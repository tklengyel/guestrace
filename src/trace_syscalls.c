#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <libvmi/libvmi_extra.h>
#include <glib.h>
#include <libxl_utils.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include "trace_syscalls.h"
#include "functions_linux.h"
#include "functions_windows.h"

/* This code relies on Xen's interface to Second Level Address Translation,
 * or SLAT. See:
 *
 * 	https://blog.xenproject.org/2016/04/13/stealthy-monitoring-with-xen-altp2m/
 *
 * guestrace maintains two page tables: The first page table (PT_1) maps the
 * kernel with no modifications. The second (PT_n/the shadow page table) adds
 * breakpoints to the kernel.
 *
 * Guestrace switches between these two page tables under the following
 * conditions:
 *
 * Guestrace activates PT_1:
 *
 * 	(1) For a single instruction after trapping a read; on Windows, such
 * 	a read is likely the result of Kernel Patch Protection. This allows
 * 	KPP to measure the expected kernel.
 *
 * 	(2) For a single instruction after trapping a guestrace-emplaced
 * 	breakpoint. This allows the kernel to execute as expected after
 * 	servicing the breakpoint.
 *
 * Guestrace activates PT_n following a single-step execution. This restores
 * guestrace's breakpoints after condition (1) or (2) above.
 */

/* Number of bits available for page offset. */
#define VF_PAGE_OFFSET_BITS 12

/* Default page size on our domain */
#define VF_PAGE_SIZE (1 << VF_PAGE_OFFSET_BITS)

/* Maximum number of VCPUs VisorFlow will support */
#define VF_MAX_VCPUS 16

/* Intel breakpoint interrupt (INT 3) instruction. */
static uint8_t VF_BREAKPOINT_INST = 0xCC;

/*
 * Handle terminating signals by setting interrupted flag. This allows
 * a graceful exit.
 */
static int vf_interrupted = 0;

static struct os_functions *os_functions;

//vf_paddr_record *sysret_trap;
addr_t sysret_addr;
addr_t trampoline_addr;

vf_paddr_record *sysret_trap;

/*
 * Set up Xen logging and initialize the vf_state object to interact with Xen.
 * Notably, we create the altp2m view here. Assuming success, Xen will activate
 * the shadow page table which will eventually contain breakpoints.
 * Returns true on success.
 */
static bool
vf_init_state(vmi_instance_t vmi, char *name, vf_state *state)
{
	int rc;
	bool status = false;

	state->vmi = vmi;

	state->xch = xc_interface_open(0, 0, 0);
	if (NULL == state->xch) {
		fprintf(stderr, "failed to create xc interface\n");
		goto done;
	}

	rc = libxl_ctx_alloc(&state->ctx, LIBXL_VERSION, 0, NULL);
	if (0 != rc) {
		fprintf(stderr, "failed to create libxl context\n");
		goto done;
	}

	state->domid = ~0u;
	rc = libxl_name_to_domid(state->ctx, name, &state->domid);
	if (0 != rc || ~0u == state->domid) {
		fprintf(stderr, "failed to translate guest name to dom. ID\n");
		goto done;
	}

	state->curr_mem_size = state->init_mem_size = vmi_get_memsize(vmi);
	if (0 == state->init_mem_size) {
		fprintf(stderr, "failed to get guest memory size\n");
		goto done;
	}

	rc = xc_altp2m_set_domain_state(state->xch, state->domid, 1);
	if (rc < 0) {
		fprintf(stderr, "failed to enable altp2m on guest\n");
		goto done;
	}

	rc = xc_altp2m_create_view(state->xch, state->domid, 0, &state->shadow_view);
	if (rc < 0) {
		fprintf(stderr, "failed to create view for shadow page\n");
		goto done;
	}

	rc = xc_altp2m_switch_to_view(state->xch, state->domid, state->shadow_view);
	if (rc < 0) {
		fprintf(stderr, "failed to enable shadow view\n");
		goto done;
	}

	status = true;

done:
	return status;
}

/* Restore any lingering stack return pointers so Kernel doesn't crash on guestrace exit */
static void
vf_restore_return_address(gpointer value, gpointer data)
{
	addr_t ret_loc = (addr_t)value;
	vf_state *state = data;

	addr_t pa = vmi_translate_kv2p(state->vmi, ret_loc);

	/* todo: error checking */
	vmi_write_64_pa(state->vmi, pa, &sysret_addr);
}

/* Tear down the Xen facilities set up by vf_init_state(). */
static void
vf_teardown_state(vf_state *state)
{
	int status;

	/*
	 * todo: overwrite our trampoline interrupt with a NOP so
	 * lingering threads don't crash after we exit guestrace
	 */

	g_hash_table_destroy(state->vf_page_record_collection);
	g_hash_table_destroy(state->vf_page_translation);

	g_ptr_array_foreach(state->vf_ret_addr_mapping, vf_restore_return_address, state);

	g_ptr_array_free(state->vf_ret_addr_mapping, false);

	status = xc_altp2m_switch_to_view(state->xch, state->domid, 0);
	if (0 > status) {
		fprintf(stderr, "failed to reset EPT to point to default table\n");
	}

	status = xc_altp2m_destroy_view(state->xch, state->domid, state->shadow_view);
	if (0 > status) {
		fprintf(stderr, "failed to destroy shadow view\n");
	}

	status = xc_altp2m_set_domain_state(state->xch, state->domid, 0);
	if (0 > status) {
		fprintf(stderr, "failed to turn off altp2m on guest\n");
	}

	/* todo: find out why this isn't decreasing main memory on next run of guestrace */
	status = xc_domain_setmaxmem(state->xch, state->domid, state->init_mem_size);
	if (0 > status) {
		fprintf(stderr, "failed to reset max memory on guest");
	}

	libxl_ctx_free(state->ctx);
	xc_interface_close(state->xch);
}

/* Allocate a new page of memory in the guest's address space. */
static addr_t
vf_allocate_shadow_page (vf_state *state)
{
	int status;
	xen_pfn_t gfn = 0;
	uint64_t proposed_mem_size = state->curr_mem_size + VF_PAGE_SIZE;

	status = xc_domain_setmaxmem(state->xch, state->domid, proposed_mem_size);
	if (0 == status) {
		state->curr_mem_size = proposed_mem_size;
	} else {
		fprintf(stderr,
		       "failed to increase memory size on guest to %lx\n",
		        proposed_mem_size);
		goto done;
	}

	status = xc_domain_increase_reservation_exact(state->xch, state->domid,
	                                              1, 0, 0, &gfn);

	if (status) {
		fprintf(stderr, "failed to increase reservation on guest");
		goto done;
	}

	status = xc_domain_populate_physmap_exact(state->xch, state->domid, 1, 0,
	                                          0, &gfn);

	if (status) {
		fprintf(stderr, "failed to populate GFN at 0x%lx\n", gfn);
		gfn = 0;
		goto done;
	}

done:
	return gfn;
}

static void
vf_destroy_paddr_record (gpointer data) {
	vf_paddr_record *paddr_record = data;

	fprintf(stderr,
	       "destroying paddr record at shadow physical address %lx\n",
	       (paddr_record->parent->shadow_page << VF_PAGE_OFFSET_BITS)
	      + paddr_record->offset);

	vf_remove_breakpoint(paddr_record);

	g_free(paddr_record);
}

static void
vf_destroy_page_record (gpointer data) {
	vf_page_record *page_record = data;

	fprintf(stderr,
	       "destroying page record on shadow page %lx\n",
	        page_record->shadow_page);

	g_hash_table_destroy(page_record->children);

	/* Stop monitoring this page. */
	vmi_set_mem_event(page_record->state->vmi,
	                  page_record->frame,
	                  VMI_MEMACCESS_N,
	                  page_record->state->shadow_view);

	xc_altp2m_change_gfn(page_record->state->xch,
	                     page_record->state->domid,
	                     page_record->state->shadow_view,
	                     page_record->shadow_page,
	                    ~0);

	xc_domain_decrease_reservation_exact(page_record->state->xch,
	                                     page_record->state->domid,
	                                     1, 0,
	                                    &page_record->shadow_page);

	g_free(page_record);
}

/*
 * Callback invoked on a R/W of a monitored page (likely kernel patch protection).
 * Switch the VCPUs SLAT to its original, step once, switch SLAT back
 */
static event_response_t
vf_mem_rw_cb (vmi_instance_t vmi, vmi_event_t *event) {
	//fprintf(stderr, "mem r/w on page %lx\n", event->mem_event.gfn);

	/* Switch back to original SLAT for one step. */
	event->slat_id = 0;

	return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP
	     | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
}

/*
 * Ensure there exists a memory trap on the shadow page containing virtual
 * address va, and create a page record if it does not yet exist. Add a
 * physical-address record corresponding to va to the page record's collection
 * of children.
 */
vf_paddr_record *
vf_setup_mem_trap (vf_state *state, addr_t va)
{
	vf_page_record  *page_record  = NULL;
	vf_paddr_record *paddr_record = NULL;

	addr_t pa = vmi_translate_kv2p(state->vmi, va);
	if (0 == pa) {
		fprintf(stderr, "virtual addr. translation failed: %lx\n", va);
		goto done;
	}

	addr_t frame = pa >> VF_PAGE_OFFSET_BITS;
	addr_t shadow = (addr_t) g_hash_table_lookup(state->vf_page_translation,
		                                     GSIZE_TO_POINTER(frame));
	addr_t shadow_offset = pa % VF_PAGE_SIZE;

	if (0 == shadow) {
		/* Record does not exist; allocate new page and create record. */
		shadow = vf_allocate_shadow_page(state);
		if (0 == shadow) {
			fprintf(stderr, "failed to allocate shadow page\n");
			goto done;
		}

		g_hash_table_insert(state->vf_page_translation,
		                    GSIZE_TO_POINTER(frame),
		                    GSIZE_TO_POINTER(shadow));

		/* Activate in shadow view. */
		int xc_status = xc_altp2m_change_gfn(state->xch,
		                                     state->domid,
		                                     state->shadow_view,
		                                     frame,
		                                     shadow);
		if (xc_status < 0) {
			fprintf(stderr, "failed to update shadow view\n");
			goto done;
		}
	}

	page_record = g_hash_table_lookup(state->vf_page_record_collection,
	                                  GSIZE_TO_POINTER(shadow));
	if (NULL == page_record) {
		/* No record for this page yet; create one. */
		fprintf(stderr, "creating new page trap on 0x%lx -> 0x%lx\n",
		        shadow, frame);

		/* Copy page to shadow. */
		uint8_t buff[VF_PAGE_SIZE] = {0};
		status_t status = vmi_read_pa(state->vmi,
		                              frame << VF_PAGE_OFFSET_BITS,
		                              buff,
		                              VF_PAGE_SIZE);
		if (0 == status) {
			fprintf(stderr, "failed to read in syscall page\n");
			goto done;
		}

		status = vmi_write_pa(state->vmi,
		                      shadow << VF_PAGE_OFFSET_BITS,
		                      buff,
		                      VF_PAGE_SIZE);
		if (0 == status) {
			fprintf(stderr, "failed to write to shadow page\n");
			goto done;
		}

		/* Initialize record of this page. */
		page_record              = g_new0(vf_page_record, 1);
		page_record->shadow_page = shadow;
		page_record->frame       = frame;
		page_record->state       = state;
		page_record->children    = g_hash_table_new_full(NULL,
		                                       NULL,
		                                       NULL,
		                                       vf_destroy_paddr_record);

		g_hash_table_insert(state->vf_page_record_collection,
		                    GSIZE_TO_POINTER(shadow),
		                    page_record);

		/* Establish callback on a R/W of this page. */
		vmi_set_mem_event(state->vmi, frame, VMI_MEMACCESS_RW,
		                  state->shadow_view);
	} else {
		/* We already have a page record for this page in collection. */
		paddr_record = g_hash_table_lookup(page_record->children,
		                                GSIZE_TO_POINTER(shadow_offset));
		if (NULL != paddr_record) {
			/* We have a paddr record too; done (no error). */
			goto done;
		}
	}

	/* Create physical-address record and add to page record. */
	paddr_record                =  g_new0(vf_paddr_record, 1);
	paddr_record->offset        =  shadow_offset;
	paddr_record->parent        =  page_record;
	paddr_record->identifier    = ~0; /* default 0xFFFF */

	/* Write interrupt to our shadow page at the correct location. */
	status_t ret = vmi_write_8_pa(state->vmi,
	                             (shadow << VF_PAGE_OFFSET_BITS) + shadow_offset,
	                             &VF_BREAKPOINT_INST);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "failed to write interrupt to shadow page\n");
		goto done;
	}

	g_hash_table_insert(page_record->children,
	                    GSIZE_TO_POINTER(shadow_offset),
	                    paddr_record);

done:
	/* TODO: Should undo state (e.g., remove from hash tables) on error */
	return paddr_record;
}

/*
 * Emplace the breakpoint associated with paddr_record.
 */
status_t
vf_emplace_breakpoint(vf_paddr_record *paddr_record) {
	addr_t shadow_page = paddr_record->parent->shadow_page;
	addr_t offset      = paddr_record->offset;

	return vmi_write_8_pa(paddr_record->parent->state->vmi,
	                     (shadow_page << VF_PAGE_OFFSET_BITS) + offset,
	                     &VF_BREAKPOINT_INST);
}

/*
 * Remove the breakpoint associated with paddr_record.
 */
status_t
vf_remove_breakpoint(vf_paddr_record *paddr_record) {
	uint8_t curr_inst;
	status_t status    = VMI_FAILURE;
	addr_t shadow_page = paddr_record->parent->shadow_page;
	addr_t frame       = paddr_record->parent->frame;
	addr_t offset      = paddr_record->offset;

	status = vmi_read_8_pa(paddr_record->parent->state->vmi,
	                      (frame << VF_PAGE_OFFSET_BITS) + offset,
	                      &curr_inst);
	if (VMI_FAILURE == status) {
		goto done;
	}

	status = vmi_write_8_pa(paddr_record->parent->state->vmi,
	                       (shadow_page << VF_PAGE_OFFSET_BITS) + offset,
	                       &curr_inst);

done:
	return status;
}

bool
vf_find_syscalls_and_setup_mem_traps(vf_state *state,
                                     const struct syscall_defs syscalls[],
                                     const char *traced_syscalls[])
{
	bool status = false;

	for (int i = 0; syscalls[i].name; i++) {
		for (int j = 0; traced_syscalls[j]; j++) {
			addr_t sysaddr;
			vf_paddr_record *syscall_trap;

			if (strcmp(syscalls[i].name, traced_syscalls[j])) {
				continue;
			}

			sysaddr = vmi_translate_ksym2v(state->vmi,
						       traced_syscalls[j]);
			if (0 == sysaddr) {
				fprintf(stderr,
				       "could not find symbol %s\n",
					traced_syscalls[j]);
				continue;
			}

			syscall_trap = vf_setup_mem_trap(state, sysaddr);
			if (NULL == syscall_trap) {
				fprintf(stderr,
				       "failed to set memory trap on %s\n",
					traced_syscalls[j]);
				goto done;
			}

			/* Set identifier to contents of RAX during syscall. */
			syscall_trap->identifier = i;

			break;
		}
	}

	status = true;

done:
	return status;
}

/*
 * Return the paddr_record associated with the given physical address.
 *
 * First obtain the page record associated with the physical address's
 * page, and then obtain the child within that record which is associated
 * with the physical address. Recall that a given page might contain
 * multiple breakpoints.
 */
static vf_paddr_record *
vf_paddr_record_from_pa(vf_state *state, addr_t pa) {
	vf_paddr_record *paddr_record = NULL;
	vf_page_record  *page_record  = NULL;

	addr_t frame  = pa >> VF_PAGE_OFFSET_BITS;
	addr_t offset = pa % VF_PAGE_SIZE;
	addr_t shadow = (addr_t)g_hash_table_lookup(state->vf_page_translation,
	                                            GSIZE_TO_POINTER(frame));
	if (0 == shadow) {
		goto done;
	}

	page_record = g_hash_table_lookup(state->vf_page_record_collection,
	                                          GSIZE_TO_POINTER(shadow));
	if (NULL == page_record) {
		goto done;
	}

	paddr_record = g_hash_table_lookup(page_record->children,
	                                   GSIZE_TO_POINTER(offset));

done:
	return paddr_record;
}

/* Return the paddr_record associated with the given virtual address. */
static vf_paddr_record *
vf_paddr_record_from_va(vf_state *state, addr_t va) {
	return vf_paddr_record_from_pa(state, vmi_translate_kv2p(state->vmi, va));
}

/*
 * Service a triggered breakpoint. Restore the original page table for one
 * single-step iteration and possibly print the system call parameters
 * or return value.
 *
 * In the case of a system call, enable the syscall return breakpoint.
 *
 * In the case of a system return, disable the syscall return breakpoint until
 * the next system call enables it.
 */
static event_response_t
vf_breakpoint_cb(vmi_instance_t vmi, vmi_event_t *event) {
	status_t status = VMI_EVENT_RESPONSE_NONE;

	vf_paddr_record *paddr_record
		= vf_paddr_record_from_va(event->data, event->interrupt_event.gla);

	/* If paddr_record is null, we assume we didn't emplace interrupt. */
	if (NULL == paddr_record) {
		event->interrupt_event.reinject = 1;
		/* TODO: Ensure this does the right thing: */
		status = VMI_EVENT_RESPONSE_EMULATE;
		goto done;
	}

	vf_state *state = event->data;
	event->interrupt_event.reinject = 0;

	if (sysret_trap == paddr_record) {
		os_functions->print_sysret(vmi, event);

		vmi_set_vcpureg(vmi, sysret_addr, RIP, event->vcpu_id);

		g_ptr_array_remove_fast(state->vf_ret_addr_mapping,
		                        GSIZE_TO_POINTER(event->x86_regs->rsp - 8));
	} else {
		addr_t ret_loc = vmi_translate_kv2p(vmi, event->x86_regs->rsp);

		addr_t ret_addr;
		vmi_read_64_pa(vmi, ret_loc, &ret_addr);

		/*
		 * If these match, we know the lstar routine called this function
		 * We may be able to remove this check and the associated read if
		 * we're confident nothing else will call a system call stub
		 */

		if (ret_addr == sysret_addr) {
			os_functions->print_syscall(vmi, event, paddr_record);
			vmi_write_64_pa(vmi, ret_loc, &trampoline_addr);
			g_ptr_array_add(state->vf_ret_addr_mapping,
		                    GSIZE_TO_POINTER(event->x86_regs->rsp));
		}

		/* Set VCPUs SLAT to use original for one step. */
		event->slat_id = 0;

		/* Turn on single-step and switch slat_id. */
		status = VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP
		       | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;

	}

done:
	return status;
}

/*
 * Setup our global interrupt to catch any interrupts on any pages.
 */
static bool
vf_set_up_generic_events (vf_state *state) {
	bool status = false;
	static vmi_event_t breakpoint_event;
	static vmi_event_t memory_event;

	SETUP_INTERRUPT_EVENT(&breakpoint_event, 0, vf_breakpoint_cb);
	breakpoint_event.data = state;

	status_t ret = vmi_register_event(state->vmi, &breakpoint_event);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "Failed to setup interrupt event\n");
		goto done;
	}

	/* TODO: support write events? */
	SETUP_MEM_EVENT(&memory_event,
	                ~0ULL,
	                 VMI_MEMACCESS_RW,
	                 vf_mem_rw_cb,
	                 1);

	memory_event.data = state;

	ret = vmi_register_event(state->vmi, &memory_event);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "Failed to setup memory event\n");
		goto done;
	}

	status = true;

done:
	return status;
}

/*
 * Callback after a step event on any VCPU.
 * Here we must reset any single-step changes we made.
 */
static event_response_t
vf_singlestep_cb(vmi_instance_t vmi, vmi_event_t *event) {
	/* Resume use of shadow SLAT. */
	vf_state *state = event->data;
	event->slat_id = state->shadow_view;

	/* Turn off single-step and switch slat_id. */
	return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP
	     | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
}

/*
 * Preemptively create the step events needed for each VCPU so we don't have to
 * create a new event each time we want to single-step.
 */
static bool
vf_set_up_step_events (vf_state *state)
{
	bool status = false;
	static vmi_event_t step_event[VF_MAX_VCPUS];

	int vcpus = vmi_get_num_vcpus(state->vmi);
	if (0 == vcpus) {
		fprintf(stderr, "failed to get number of VCPUs\n");
		goto done;
	}

	if (VF_MAX_VCPUS < vcpus) {
		fprintf(stderr, "guest has more VCPUs than supported\n");
		goto done;
	}

	for (int vcpu = 0; vcpu < vcpus; vcpu++) {
		vmi_event_t curr = step_event[vcpu];
		SETUP_SINGLESTEP_EVENT(&curr, 1u << vcpu, vf_singlestep_cb, 0);
		curr.data = state;

		if (VMI_FAILURE == vmi_register_event(state->vmi, &curr)) {
			fprintf(stderr,
			       "failed to register single-step event on VCPU %d\n",
			        vcpu);
			goto done;
		}
	}

	status = true;

done:
	return status;
}

static bool
vf_create_trampoline (vf_state *state)
{
	bool status = false;

	sysret_trap = vf_setup_mem_trap(state, trampoline_addr);
	if (NULL == sysret_trap) {
		fprintf(stderr, "failed to create sysret trap\n");
		goto done;
	}

	status = true;

done:
	return status;
}

static void
vf_close_handler (int sig)
{
	vf_interrupted = sig;
}

static bool
vf_set_up_signal_handler (struct sigaction act)
{
	int status = 0;

	act.sa_handler = vf_close_handler;
	act.sa_flags = 0;

	status = sigemptyset(&act.sa_mask);
	if (-1 == status) {
		perror("failed to initialize signal handler.\n");
		goto done;
	}

	status = sigaction(SIGHUP,  &act, NULL);
	if (-1 == status) {
		perror("failed to register SIGHUP handler.\n");
		goto done;
	}

	status = sigaction(SIGTERM, &act, NULL);
	if (-1 == status) {
		perror("failed to register SIGTERM handler.\n");
		goto done;
	}

	status = sigaction(SIGINT,  &act, NULL);
	if (-1 == status) {
		perror("failed to register SIGINT handler.\n");
		goto done;
	}

	status = sigaction(SIGALRM, &act, NULL);
	if (-1 == status) {
		perror("failed to register SIGALRM handler.\n");
		goto done;
	}

done:
	return -1 != status;
}

int
main (int argc, char **argv) {
	os_t os;
	struct sigaction act;
	status_t status = VMI_FAILURE;
	vmi_instance_t vmi;
	char *name = NULL;
	vf_state state = {0};

	if (argc < 2){
		fprintf(stderr, "Usage: guestrace <name of VM>\n");
		exit(EXIT_FAILURE);
	}

	/* Arg 1 is the VM name. */
	name = argv[1];

	if (!vf_set_up_signal_handler(act)) {
		goto done;
	}

	/* Initialize the libvmi library. */
	status = vmi_init(&vmi, VMI_XEN | VMI_INIT_COMPLETE | VMI_INIT_EVENTS, name);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to init LibVMI library.\n");
		goto done;
	} else {
		printf("LibVMI init succeeded!\n");
	}

	state.vf_page_translation = g_hash_table_new(NULL, NULL);
	state.vf_page_record_collection = g_hash_table_new_full(NULL,
	                                                  NULL,
	                                                  NULL,
	                                                  vf_destroy_page_record);
	state.vf_ret_addr_mapping = g_ptr_array_new();

	vmi_pause_vm(vmi);

	os = vmi_get_ostype(vmi);
        switch (os) {
        case VMI_OS_LINUX:
                os_functions = &os_functions_linux;
                break;
        case VMI_OS_WINDOWS:
                os_functions = &os_functions_windows;
                break;
        default:
		fprintf(stderr, "unknown guest operating system\n");
                status = VMI_FAILURE;
                goto done;
        }

	if (!vf_init_state(vmi, name, &state)) {
		vmi_resume_vm(vmi);
		goto done;
	}

	if (!vf_set_up_step_events(&state)) {
		vmi_resume_vm(vmi);
		goto done;
	}

	if (!vf_set_up_generic_events(&state)) {
		vmi_resume_vm(vmi);
		goto done;
	}

	if (!os_functions->find_syscalls_and_setup_mem_traps(&state)) {
		vmi_resume_vm(vmi);
		goto done;
	}

	if (!os_functions->find_sysret_addr(&state)) {
		vmi_resume_vm(vmi);
		goto done;
	}

	if (!os_functions->find_trampoline_addr(&state)) {
		vmi_resume_vm(vmi);
		goto done;
	}

	if (!vf_create_trampoline(&state)) {
		vmi_resume_vm(vmi);
		goto done;
	}

	vmi_resume_vm(vmi);

	printf("Waiting for events...\n");

	while(!vf_interrupted){
		status = vmi_events_listen(vmi,500);
		if (status != VMI_SUCCESS) {
			printf("Error waiting for events, quitting...\n");
			goto done;
		}
	}

done:
	printf("Shutting down guestrace\n");

	vmi_pause_vm(vmi);

	vf_teardown_state(&state);

	vmi_resume_vm(vmi);

	if (vmi != NULL) {
		vmi_destroy(vmi);
	}

	exit(VMI_SUCCESS == status ? EXIT_SUCCESS : EXIT_FAILURE);
}

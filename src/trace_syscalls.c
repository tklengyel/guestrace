#include <capstone/capstone.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <glib.h>
#include <inttypes.h>
#include <libxl_utils.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xenctrl.h>

#include "translate_syscalls.h"

/*
 * Before running, you must add
 *
 * 	GRUB_CMDLINE_XEN_DEFAULT="altp2m=1"
 *
 * to /etc/default/grub and add
 *
 * 	altp2mhvm = 1
 *
 * to the xen config file of each guest.
 */

/* Number of bits available for page offset. */
#define VF_PAGE_OFFSET_BITS 12

/* Default page size on our domain */
#define VF_PAGE_SIZE (1 << VF_PAGE_OFFSET_BITS)

/* Maximum number of VCPUs VisorFlow will support */
#define VF_MAX_VCPUS 16

/* Intel breakpoint interrupt (INT 3) instruction. */
static uint8_t VF_BREAKPOINT_INST = 0xCC;

/* Array to hold step event for each VCPU */
static vmi_event_t vf_step_event[VF_MAX_VCPUS];

/* Global interrupt event that gets triggered on any VF_BREAKPOINT_INST callback */
static vmi_event_t vf_breakpoint_event;

/* Global memory event that gets triggered on memory events */
static vmi_event_t vf_memory_event;

/* Data structure used to interact directly with Xen driver */
typedef struct vf_config {
	xc_interface *xch;
	libxl_ctx *ctx;
	xentoollog_logger *logger;
	uint32_t domid;
	uint64_t init_mem_size;
	uint64_t curr_mem_size;
	vmi_instance_t vmi;
	uint16_t shadow_view;
} vf_config;

static GHashTable *vf_page_translation;
static GHashTable *vf_page_record_collection;

/*
 * Guestrace maintains three collections:
 *
 * The first collection contains a mapping from page numbers to shadow page
 * numbers. Given a physical page, this will translate it into a shadow page
 * if one exists. NOTE: the code has changed since the original inception in my
 * mind, so we might be able to delete this without negative consquences
 *
 * The second collection contains a mapping from shadow page numbers to vf_page_record
 * structures. This serves as a record of the guest pages for which guestrace
 * installed a memory event. When the guest accesses such a page, control
 * traps into guestrace. The most notable field in vf_page_record is children.
 * The children field points to the third collection.
 *
 * The third collection contains a mapping from physical address offsets to vf_paddr_record
 * structures. This serves as a record for each breakpoint that guestrace
 * sets within a page.
 */

typedef struct vf_page_record {
	addr_t frame;
	addr_t shadow_page;
	GHashTable *children;
	vf_config *conf;
} vf_page_record;

typedef struct vf_paddr_record {
	addr_t offset;
	vf_page_record *parent;
	uint16_t identifier; /* syscall identifier because we nix RAX */
} vf_paddr_record;

/* Global paddr record for our syscall return address */
static vf_paddr_record * sysret_trap;

/*
 * Handle terminating signals by setting interrupted flag. This allows
 * a graceful exit.
 */
static int vf_interrupted = 0;

/*
 * Initilize our vf_config object to interact with Xen driver
 * Returns true if succeeded
 */
static bool
vf_init_config (vmi_instance_t vmi, char * name, vf_config * conf)
{
	bool status = false;

	conf->vmi = vmi;
	xc_interface *xch = xc_interface_open(0, 0, 0);

	if (NULL == xch) {
		fprintf(stderr, "Could not create xc interface\n");
		goto done;
	}

	conf->xch = xch;

	conf->logger = (xentoollog_logger *)xtl_createlogger_stdiostream(stderr, XTL_PROGRESS, 0);
	if (conf->logger == NULL) {
		fprintf(stderr, "Could not create libxl logger\n");
		goto done;
	}

	if (libxl_ctx_alloc(&conf->ctx, LIBXL_VERSION, 0, conf->logger)) {
		fprintf(stderr, "Could not create libxl context\n");
		goto done;
	}

	conf->domid = ~0U;

	if (libxl_name_to_domid(conf->ctx, name, &conf->domid) || ~0U == conf->domid) {
		fprintf(stderr, "Could not translate guest name to dom-id\n");
		goto done;
	}

	conf->init_mem_size = vmi_get_memsize(vmi);
	conf->curr_mem_size = conf->init_mem_size;

	if (0 == conf->init_mem_size) {
		fprintf(stderr, "Could not get guest's memory size\n");
		goto done;
	}

	fprintf(stderr, "Guest's starting memory size is %lx\n", conf->init_mem_size);

	/* here we enable xen-specific altp2m */
	int xc_status = xc_altp2m_set_domain_state(conf->xch, conf->domid, 1);
	if (0 > xc_status) {
		fprintf(stderr, "Failed to enable altp2m on guest\n");
		goto done;
	}

	xc_status = xc_altp2m_create_view(conf->xch, conf->domid, 0, &conf->shadow_view);
	if (0 > xc_status) {
		fprintf(stderr, "Failed to create view for shadow page\n");
		goto done;
	}

	xc_status = xc_altp2m_switch_to_view(conf->xch, conf->domid, conf->shadow_view);
	if (0 > xc_status) {
		fprintf(stderr, "Failed to enable shadow view\n");
		goto done;
	}

	status = true;

done:
	return status;
}

/*
 * Close our driver handlers and reset shadow memory
 */
static void
vf_close_config(vf_config * conf)
{
	int xc_status = xc_altp2m_switch_to_view(conf->xch, conf->domid, 0);
	if (0 > xc_status) {
		fprintf(stderr, "Failed to reset EPT to point to default table\n");
	}

	xc_status = xc_altp2m_destroy_view(conf->xch, conf->domid, conf->shadow_view);
	if (0 > xc_status) {
		fprintf(stderr, "Failed to destroy shadow view\n");
	}

	xc_status = xc_altp2m_set_domain_state(conf->xch, conf->domid, 0);
	if (0 > xc_status) {
		fprintf(stderr, "Failed to turn off altp2m on guest\n");
	}

	/* todo: find out why this isn't decreasing main memory on next run of guestrace */
	xc_status = xc_domain_setmaxmem(conf->xch, conf->domid, conf->init_mem_size);
	if (0 > xc_status) {
		fprintf(stderr, "Failed to reset max memory on guest");
	}

	libxl_ctx_free(conf->ctx);
	xc_interface_close(conf->xch);
}

/*
 * Allocates a new page of memory in the guest's address space
 */
static addr_t
vf_allocate_shadow_page (vf_config * conf)
{
	xen_pfn_t gfn = 0;

	int status = xc_domain_setmaxmem(conf->xch, conf->domid, conf->curr_mem_size + VF_PAGE_SIZE);

	if (0 == status) {
		conf->curr_mem_size += VF_PAGE_SIZE;
	} else {
		fprintf(stderr, "Could not increase memory size on guest to %lx\n", conf->curr_mem_size + VF_PAGE_SIZE);
		goto done;
	}

	status = xc_domain_increase_reservation_exact(conf->xch, conf->domid, 1, 0, 0, &gfn);

	if (status) {
		fprintf(stderr, "Could not increase reservation on guest");
		goto done;
	}

	status = xc_domain_populate_physmap_exact(conf->xch, conf->domid, 1, 0, 0, &gfn);

	if (status) {
		fprintf(stderr, "Could not populate GFN at 0x%lx\n", gfn);
		gfn = 0;
		goto done;
	}

done:
	return gfn;
}

static void
vf_destroy_paddr_record (gpointer data) {
	vf_paddr_record *paddr_record = data;

	fprintf(stderr, "Destroying paddr_record at shadow physical address %lx\n", (paddr_record->parent->shadow_page << VF_PAGE_OFFSET_BITS) + paddr_record->offset);

	g_free(paddr_record);
}

static void
vf_destroy_page_record (gpointer data) {
	vf_page_record *page_record = data;

	fprintf(stderr, "Destroying page_record on shadow page %lx\n", page_record->shadow_page);

	/* stop monitoring this page with our mem event */
	vmi_set_mem_event(page_record->conf->vmi,
					  page_record->frame,
					  VMI_MEMACCESS_N,
					  page_record->conf->shadow_view);

	xc_altp2m_change_gfn(page_record->conf->xch,
						 page_record->conf->domid,
						 page_record->conf->shadow_view,
						 page_record->shadow_page,
						 ~0);

	xc_domain_decrease_reservation_exact(page_record->conf->xch,
										 page_record->conf->domid,
										 1,
										 0,
										 &page_record->shadow_page);

	g_hash_table_destroy(page_record->children);

	g_free(page_record);
}

/*
 * Callback invoked on a R/W of a monitored page (likely kernel patch protection).
 * Switch the VCPU's SLAT to its original, step once, switch SLAT back
 */
static event_response_t
vf_mem_rw_cb (vmi_instance_t vmi, vmi_event_t *event) {
	fprintf(stderr, "mem r/w on page %lx\n", event->mem_event.gfn);

	/* switch back to original slat for one step */
	event->slat_id = 0;

	return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
}

static vf_paddr_record *
vf_setup_mem_trap (vf_config * conf, addr_t va)
{
	vf_page_record  *page_record  = NULL;
	vf_paddr_record *paddr_record = NULL;

	addr_t pa = vmi_translate_kv2p(conf->vmi, va);
	if (0 == pa) {
		fprintf(stderr, "virtual addr. translation failed: %lx\n", va);
		goto done;
	}

	addr_t frame = pa >> VF_PAGE_OFFSET_BITS;
	addr_t shadow = (addr_t)g_hash_table_lookup(vf_page_translation,
		                                GSIZE_TO_POINTER(frame));
	addr_t shadow_offset = pa % VF_PAGE_SIZE;

	if (0 == shadow) {
		/* we need to allocate a new page */
		shadow = vf_allocate_shadow_page(conf);

		if (0 == shadow) {
			fprintf(stderr, "Failed to allocate shadow page\n");
			goto done;
		}

		g_hash_table_insert(vf_page_translation,
							GSIZE_TO_POINTER(frame),
							GSIZE_TO_POINTER(shadow));

		/* this adds our remapping into our shadow view */
		int xc_status = xc_altp2m_change_gfn(conf->xch, conf->domid, conf->shadow_view, frame, shadow);
		if (0 > xc_status) {
			fprintf(stderr, "Failed to add paddr_record into shadow view\n");
			goto done;
		}
	}

	page_record = g_hash_table_lookup(vf_page_record_collection,
		                                			GSIZE_TO_POINTER(shadow));

	if (NULL == page_record) {
		/* we need to create our page record and fill it */
		fprintf(stderr, "creating new page trap on 0x%lx -> 0x%lx\n", shadow, frame);

		/* store current page on the stack */
		uint8_t buff[VF_PAGE_SIZE] = {0};
		status_t status = vmi_read_pa(conf->vmi, frame << VF_PAGE_OFFSET_BITS, buff, VF_PAGE_SIZE);
		if (0 == status) {
			fprintf(stderr, "Failed to read in syscall page\n");
			goto done;
		}

		status = vmi_write_pa(conf->vmi, shadow << VF_PAGE_OFFSET_BITS, buff, VF_PAGE_SIZE);
		if (0 == status) {
			fprintf(stderr, "Failed to write to shadow page\n");
			goto done;
		}

		page_record                     = g_new0(vf_page_record, 1);
		page_record->shadow_page        = shadow;
		page_record->frame              = frame;
		page_record->conf               = conf;
		page_record->children 			= g_hash_table_new_full(NULL,
					                                            NULL,
					                                            NULL,
					                                            vf_destroy_paddr_record);

		g_hash_table_insert(vf_page_record_collection,
		                    GSIZE_TO_POINTER(shadow),
		                    page_record);

		/* tells libvmi to trigger our callback on a R/W to this page */
		vmi_set_mem_event(conf->vmi, frame, VMI_MEMACCESS_RW, conf->shadow_view);
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

	/* write the interrupt to our shadow page at the correct location */
	status_t ret = vmi_write_8_pa(conf->vmi, (shadow << VF_PAGE_OFFSET_BITS) + shadow_offset, &VF_BREAKPOINT_INST);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "Failed to write interrupt to shadow page\n");
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
static status_t
vf_emplace_breakpoint(vf_paddr_record *paddr_record) {
	return vmi_write_8_pa(paddr_record->parent->conf->vmi,
	                      (paddr_record->parent->shadow_page << VF_PAGE_OFFSET_BITS) + paddr_record->offset,
	                      &VF_BREAKPOINT_INST);
}

/*
 * Remove the breakpoint associated with paddr_record.
 */
static status_t
vf_remove_breakpoint(vf_paddr_record *paddr_record) {
	uint8_t curr_inst;
	status_t status = VMI_FAILURE;

	status = vmi_read_8_pa(paddr_record->parent->conf->vmi,
						   (paddr_record->parent->frame << VF_PAGE_OFFSET_BITS) + paddr_record->offset,
						   &curr_inst);

	if (VMI_FAILURE == status) {
		goto done;
	}

	status = vmi_write_8_pa(paddr_record->parent->conf->vmi,
	                        (paddr_record->parent->shadow_page << VF_PAGE_OFFSET_BITS) + paddr_record->offset,
	                        &curr_inst);

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
vf_paddr_record_from_pa(vmi_instance_t vmi, addr_t pa) {
	vf_paddr_record *paddr_record = NULL;
	vf_page_record  *page_record  = NULL;

	addr_t frame  = pa >> VF_PAGE_OFFSET_BITS;
	addr_t offset = pa % VF_PAGE_SIZE;
	addr_t shadow = (addr_t)g_hash_table_lookup(vf_page_translation,
	                                            GSIZE_TO_POINTER(frame));
	if (0 == shadow) {
		goto done;
	}

	page_record = g_hash_table_lookup(vf_page_record_collection,
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
vf_paddr_record_from_va(vmi_instance_t vmi, addr_t va) {
	return vf_paddr_record_from_pa(vmi, vmi_translate_kv2p(vmi, va));
}

/*
 * Callback on any interrupts received from our shadow pages
 * Here we must make temporary changes and enter into single-step mode
 */
static event_response_t
vf_breakpoint_cb(vmi_instance_t vmi, vmi_event_t *event) {
	status_t status = VMI_EVENT_RESPONSE_NONE;

	vf_paddr_record *paddr_record = vf_paddr_record_from_va(vmi,
	                                                        event->interrupt_event.gla);

	/* if paddr_record is null, we assume that we didn't emplace this interrupt */
	if (NULL == paddr_record) {
		event->interrupt_event.reinject = 1;
		/* TODO: Ensure this does the right thing: */
		status = VMI_EVENT_RESPONSE_EMULATE;
		goto done;
	}

	/* set vcpu's slat to use original for one step */
	event->slat_id = 0;
	event->interrupt_event.reinject = 0;

	/* turn on single-step and switch slat_id */
	status = VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;

	if (sysret_trap != paddr_record) {
		/* syscall */
		print_syscall(vmi, event, paddr_record->identifier);
		vf_emplace_breakpoint(sysret_trap);
	} else {
		/* sysret */
		print_sysret(vmi, event);
		vf_remove_breakpoint(sysret_trap);
	}

done:
	return status;
}

/*
 * Setup our global interrupt to catch any interrupts on any pages
 */
static bool
vf_set_up_generic_events (vf_config * conf) {
	bool status = false;

	SETUP_INTERRUPT_EVENT(&vf_breakpoint_event, 0, vf_breakpoint_cb);
	vf_breakpoint_event.data = conf;

	status_t ret = vmi_register_event(conf->vmi, &vf_breakpoint_event);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "Failed to setup interrupt event\n");
		goto done;
	}

	/* todo: support write events? */
	SETUP_MEM_EVENT(&vf_memory_event,
	                ~0ULL,
	                VMI_MEMACCESS_RW,
	                vf_mem_rw_cb,
	                1);

	vf_memory_event.data = conf;

	ret = vmi_register_event(conf->vmi, &vf_memory_event);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "Failed to setup memory event\n");
		goto done;
	}

	status = true;

done:
	return status;
}

/*
 * Callback after a step event on any VCPU
 * Here we must reset any single-step changes we made
 */
static event_response_t
vf_singlestep_cb(vmi_instance_t vmi, vmi_event_t *event) {
	/* set to shadow slat */
	vf_config *conf = event->data;

	event->slat_id = conf->shadow_view;

	/* turn off single-step and switch slat_id */
	return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
}

/*
 * Creates the step events needed for each VCPU so we don't have to create
 * a new event everytime we want to step
 */
static bool
vf_set_up_step_events (vf_config * conf) {
	bool status = false;

	int vcpus = vmi_get_num_vcpus(conf->vmi);
	if (0 == vcpus) {
		fprintf(stderr, "Failed to get number of VCPUs\n");
		goto done;
	}

	if (VF_MAX_VCPUS < vcpus) {
		fprintf(stderr, "Guest has more VCPUs than supported\n");
		goto done;
	}

	for (int vcpu = 0; vcpu < vcpus; vcpu++) {
		vmi_event_t curr = vf_step_event[vcpu];
		SETUP_SINGLESTEP_EVENT(&curr, 1u << vcpu, vf_singlestep_cb, 0);
		curr.data = conf;

		if (VMI_FAILURE == vmi_register_event(conf->vmi, &curr)) {
			fprintf(stderr, "Failed to register single-step event on VCPU %d\n", vcpu);
			goto done;
		}
	}

	status = true;

done:
	return status;
}

/*
 * Disassemble the kernel and find the appropriate point for a breakpoint
 * which allows guestrace to determine a system call's return value. Return
 * the address.
 */
static addr_t
vf_get_syscall_ret_addr(vf_config * conf, addr_t syscall_start) {
	csh handle;
	cs_insn *inst;
	size_t count, call_offset = ~0;
	addr_t ret = 0;
	uint8_t code[4096]; /* Assume CALL is within first KB. */

	addr_t syscall_start_p = vmi_translate_kv2p(conf->vmi, syscall_start);
	if (0 == syscall_start_p) {
		fprintf(stderr, "failed to read instructions from 0x%"
		                 PRIx64".\n", syscall_start);
		goto done;
	}

	/* Read kernel instructions into code. */
	status_t status = vmi_read_pa(conf->vmi, syscall_start_p, code, sizeof(code));
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to read instructions from 0x%"
		                 PRIx64".\n", syscall_start_p);
		goto done;
	}

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		fprintf(stderr, "failed to open capstone\n");
		goto done;
	}

	/* Find CALL inst. and note address of inst. which follows. */
	count = cs_disasm(handle, code, sizeof(code), 0, 0, &inst);
	if (count > 0) {
		size_t i;
		for (i = 0; i < count; i++) {
			if (0 == strcmp(inst[i].mnemonic, "call")
			 && 0 == strcmp(inst[i].op_str, "r10")) {
				call_offset = inst[i + 1].address;
				break;
			}
		}
		cs_free(inst, count);
	} else {
		fprintf(stderr, "failed to disassemble system-call handler\n");
		goto done;
	}

	if (~0 == call_offset) {
		fprintf(stderr, "did not find call in system-call handler\n");
		goto done;
	}

	cs_close(&handle);

	ret = syscall_start + call_offset;

done:
	return ret;
}

static bool
vf_set_up_sysret_handler(vf_config * conf)
{
	bool status = false;
	addr_t lstar = 0;

	/* LSTAR should be the constant across all vcpus */
	status_t ret = vmi_get_vcpureg(conf->vmi, &lstar, MSR_LSTAR, 0);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "failed to get MSR_LSTAR address\n");
		goto done;
	}

	addr_t ret_addr = vf_get_syscall_ret_addr(conf, lstar);
	if (0 == ret_addr) {
		fprintf(stderr, "failed to get system return address\n");
		goto done;
	}

	sysret_trap = vf_setup_mem_trap(conf, ret_addr);
	if (NULL == sysret_trap) {
		fprintf(stderr, "Failed to create sysret memory trap\n");
		goto done;
	}

	vf_remove_breakpoint(sysret_trap);

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

#define countof(array) (sizeof(array) / sizeof((array)[0]))

/*
 * For each of the system calls libvmi is interested in, establish a memory trap
 * on the page containing the system call handler's first instruction. An
 * execute trap will cause guestrace to emplace a breakpoint. A read/write trap
 * (i.e., kernel patch protection) will cause guestrace to restore the original
 * instruction.
 */
static bool
vf_find_syscalls_and_setup_mem_trap(vf_config * conf)
{
	bool status = false;

	/* See Windows's KeServiceDescriptorTable. */
	static const char *SYSCALLS[] = {
		"NtMapUserPhysicalPagesScatter",
		"NtWaitForSingleObject",
		"NtCallbackReturn",
		"NtReadFile",
		"NtDeviceIoControlFile",
		"NtWriteFile",
		"NtRemoveIoCompletion",
		"NtReleaseSemaphore",
		"NtReplyWaitReceivePort",
		"NtReplyPort",
		"NtSetInformationThread",
		"NtSetEvent",
		"NtClose",
		"NtQueryObject",
		"NtQueryInformationFile",
		"NtOpenKey",
		"NtEnumerateValueKey",
		"NtFindAtom",
		"NtQueryDefaultLocale",
		"NtQueryKey",
		"NtQueryValueKey",
		"NtAllocateVirtualMemory",
		"NtQueryInformationProcess",
		"NtWaitForMultipleObjects32",
		"NtWriteFileGather",
		"NtSetInformationProcess",
		"NtCreateKey",
		"NtFreeVirtualMemory",
		"NtImpersonateClientOfPort",
		"NtReleaseMutant",
		"NtQueryInformationToken",
		"NtRequestWaitReplyPort",
		"NtQueryVirtualMemory",
		"NtOpenThreadToken",
		"NtQueryInformationThread",
		"NtOpenProcess",
		"NtSetInformationFile",
		"NtMapViewOfSection",
		"NtAccessCheckAndAuditAlarm",
		"NtUnmapViewOfSection",
		"NtReplyWaitReceivePortEx",
		"NtTerminateProcess",
		"NtSetEventBoostPriority",
		"NtReadFileScatter",
		"NtOpenThreadTokenEx",
		"NtOpenProcessTokenEx",
		"NtQueryPerformanceCounter",
		"NtEnumerateKey",
		"NtOpenFile",
		"NtDelayExecution",
		"NtQueryDirectoryFile",
		"NtQuerySystemInformation",
		"NtOpenSection",
		"NtQueryTimer",
		"NtFsControlFile",
		"NtWriteVirtualMemory",
		"NtCloseObjectAuditAlarm",
		"NtDuplicateObject",
		"NtQueryAttributesFile",
		"NtClearEvent",
		"NtReadVirtualMemory",
		"NtOpenEvent",
		"NtAdjustPrivilegesToken",
		"NtDuplicateToken",
		"NtContinue",
		"NtQueryDefaultUILanguage",
		"NtQueueApcThread",
		"NtYieldExecution",
		"NtAddAtom",
		"NtCreateEvent",
		"NtQueryVolumeInformationFile",
		"NtCreateSection",
		"NtFlushBuffersFile",
		"NtApphelpCacheControl",
		"NtCreateProcessEx",
		"NtCreateThread",
		"NtIsProcessInJob",
		"NtProtectVirtualMemory",
		"NtQuerySection",
		"NtResumeThread",
		"NtTerminateThread",
		"NtReadRequestData",
		"NtCreateFile",
		"NtQueryEvent",
		"NtWriteRequestData",
		"NtOpenDirectoryObject",
		"NtAccessCheckByTypeAndAuditAlarm",
		"NtQuerySystemTime",
		"NtWaitForMultipleObjects",
		"NtSetInformationObject",
		"NtCancelIoFile",
		"NtTraceEvent",
		"NtPowerInformation",
		"NtSetValueKey",
		"NtCancelTimer",
		"NtSetTimer",
		"NtAcceptConnectPort",
		"NtAccessCheck",
		"NtAccessCheckByType",
		"NtAccessCheckByTypeResultList",
		"NtAccessCheckByTypeResultListAndAuditAlarm",
		"NtAccessCheckByTypeResultListAndAuditAlarmByHandle",
		"NtAddBootEntry",
		"NtAddDriverEntry",
		"NtAdjustGroupsToken",
		"NtAlertResumeThread",
		"NtAlertThread",
		"NtAllocateLocallyUniqueId",
		"NtAllocateReserveObject",
		"NtAllocateUserPhysicalPages",
		"NtAllocateUuids",
		"NtAlpcAcceptConnectPort",
		"NtAlpcCancelMessage",
		"NtAlpcConnectPort",
		"NtAlpcCreatePort",
		"NtAlpcCreatePortSection",
		"NtAlpcCreateResourceReserve",
		"NtAlpcCreateSectionView",
		"NtAlpcCreateSecurityContext",
		"NtAlpcDeletePortSection",
		"NtAlpcDeleteResourceReserve",
		"NtAlpcDeleteSectionView",
		"NtAlpcDeleteSecurityContext",
		"NtAlpcDisconnectPort",
		"NtAlpcImpersonateClientOfPort",
		"NtAlpcOpenSenderProcess",
		"NtAlpcOpenSenderThread",
		"NtAlpcQueryInformation",
		"NtAlpcQueryInformationMessage",
		"NtAlpcRevokeSecurityContext",
		"NtAlpcSendWaitReceivePort",
		"NtAlpcSetInformation",
		"NtAreMappedFilesTheSame",
		"NtAssignProcessToJobObject",
		"NtCancelIoFileEx",
		"NtCancelSynchronousIoFile",
		"NtCommitComplete",
		"NtCommitEnlistment",
		"NtCommitTransaction",
		"NtCompactKeys",
		"NtCompareTokens",
		"NtCompleteConnectPort",
		"NtCompressKey",
		"NtConnectPort",
		"NtCreateDebugObject",
		"NtCreateDirectoryObject",
		"NtCreateEnlistment",
		"NtCreateEventPair",
		"NtCreateIoCompletion",
		"NtCreateJobObject",
		"NtCreateJobSet",
		"NtCreateKeyTransacted",
		"NtCreateKeyedEvent",
		"NtCreateMailslotFile",
		"NtCreateMutant",
		"NtCreateNamedPipeFile",
		"NtCreatePagingFile",
		"NtCreatePort",
		"NtCreatePrivateNamespace",
		"NtCreateProcess",
		"NtCreateProfile",
		"NtCreateProfileEx",
		"NtCreateResourceManager",
		"NtCreateSemaphore",
		"NtCreateSymbolicLinkObject",
		"NtCreateThreadEx",
		"NtCreateTimer",
		"NtCreateToken",
		"NtCreateTransaction",
		"NtCreateTransactionManager",
		"NtCreateUserProcess",
		"NtCreateWaitablePort",
		"NtCreateWorkerFactory",
		"NtDebugActiveProcess",
		"NtDebugContinue",
		"NtDeleteAtom",
		"NtDeleteBootEntry",
		"NtDeleteDriverEntry",
		"NtDeleteFile",
		"NtDeleteKey",
		"NtDeleteObjectAuditAlarm",
		"NtDeletePrivateNamespace",
		"NtDeleteValueKey",
		"NtDisableLastKnownGood",
		"NtDisplayString",
		"NtDrawText",
		"NtEnableLastKnownGood",
		"NtEnumerateBootEntries",
		"NtEnumerateDriverEntries",
		"NtEnumerateSystemEnvironmentValuesEx",
		"NtEnumerateTransactionObject",
		"NtExtendSection",
		"NtFilterToken",
		"NtFlushInstallUILanguage",
		"NtFlushInstructionCache",
		"NtFlushKey",
		"NtFlushProcessWriteBuffers",
		"NtFlushVirtualMemory",
		"NtFlushWriteBuffer",
		"NtFreeUserPhysicalPages",
		"NtFreezeRegistry",
		"NtFreezeTransactions",
		"NtGetContextThread",
		"NtGetCurrentProcessorNumber",
		"NtGetDevicePowerState",
		"NtGetMUIRegistryInfo",
		"NtGetNextProcess",
		"NtGetNextThread",
		"NtGetNlsSectionPtr",
		"NtGetNotificationResourceManager",
		"NtGetPlugPlayEvent",
		"NtGetWriteWatch",
		"NtImpersonateAnonymousToken",
		"NtImpersonateThread",
		"NtInitializeNlsFiles",
		"NtInitializeRegistry",
		"NtInitiatePowerAction",
		"NtIsSystemResumeAutomatic",
		"NtIsUILanguageComitted",
		"NtListenPort",
		"NtLoadDriver",
		"NtLoadKey",
		"NtLoadKey2",
		"NtLoadKeyEx",
		"NtLockFile",
		"NtLockProductActivationKeys",
		"NtLockRegistryKey",
		"NtLockVirtualMemory",
		"NtMakePermanentObject",
		"NtMakeTemporaryObject",
		"NtMapCMFModule",
		"NtMapUserPhysicalPages",
		"NtModifyBootEntry",
		"NtModifyDriverEntry",
		"NtNotifyChangeDirectoryFile",
		"NtNotifyChangeKey",
		"NtNotifyChangeMultipleKeys",
		"NtNotifyChangeSession",
		"NtOpenEnlistment",
		"NtOpenEventPair",
		"NtOpenIoCompletion",
		"NtOpenJobObject",
		"NtOpenKeyEx",
		"NtOpenKeyTransacted",
		"NtOpenKeyTransactedEx",
		"NtOpenKeyedEvent",
		"NtOpenMutant",
		"NtOpenObjectAuditAlarm",
		"NtOpenPrivateNamespace",
		"NtOpenProcessToken",
		"NtOpenResourceManager",
		"NtOpenSemaphore",
		"NtOpenSession",
		"NtOpenSymbolicLinkObject",
		"NtOpenThread",
		"NtOpenTimer",
		"NtOpenTransaction",
		"NtOpenTransactionManager",
		"NtPlugPlayControl",
		"NtPrePrepareComplete",
		"NtPrePrepareEnlistment",
		"NtPrepareComplete",
		"NtPrepareEnlistment",
		"NtPrivilegeCheck",
		"NtPrivilegeObjectAuditAlarm",
		"NtPrivilegedServiceAuditAlarm",
		"NtPropagationComplete",
		"NtPropagationFailed",
		"NtPulseEvent",
		"NtQueryBootEntryOrder",
		"NtQueryBootOptions",
		"NtQueryDebugFilterState",
		"NtQueryDirectoryObject",
		"NtQueryDriverEntryOrder",
		"NtQueryEaFile",
		"NtQueryFullAttributesFile",
		"NtQueryInformationAtom",
		"NtQueryInformationEnlistment",
		"NtQueryInformationJobObject",
		"NtQueryInformationPort",
		"NtQueryInformationResourceManager",
		"NtQueryInformationTransaction",
		"NtQueryInformationTransactionManager",
		"NtQueryInformationWorkerFactory",
		"NtQueryInstallUILanguage",
		"NtQueryIntervalProfile",
		"NtQueryIoCompletion",
		"NtQueryLicenseValue",
		"NtQueryMultipleValueKey",
		"NtQueryMutant",
		"NtQueryOpenSubKeys",
		"NtQueryOpenSubKeysEx",
		"NtQueryPortInformationProcess",
		"NtQueryQuotaInformationFile",
		"NtQuerySecurityAttributesToken",
		"NtQuerySecurityObject",
		"NtQuerySemaphore",
		"NtQuerySymbolicLinkObject",
		"NtQuerySystemEnvironmentValue",
		"NtQuerySystemEnvironmentValueEx",
		"NtQuerySystemInformationEx",
		"NtQueryTimerResolution",
		"NtQueueApcThreadEx",
		"NtRaiseException",
		"NtRaiseHardError",
		"NtReadOnlyEnlistment",
		"NtRecoverEnlistment",
		"NtRecoverResourceManager",
		"NtRecoverTransactionManager",
		"NtRegisterProtocolAddressInformation",
		"NtRegisterThreadTerminatePort",
		"NtReleaseKeyedEvent",
		"NtReleaseWorkerFactoryWorker",
		"NtRemoveIoCompletionEx",
		"NtRemoveProcessDebug",
		"NtRenameKey",
		"NtRenameTransactionManager",
		"NtReplaceKey",
		"NtReplacePartitionUnit",
		"NtReplyWaitReplyPort",
		"NtRequestPort",
		"NtResetEvent",
		"NtResetWriteWatch",
		"NtRestoreKey",
		"NtResumeProcess",
		"NtRollbackComplete",
		"NtRollbackEnlistment",
		"NtRollbackTransaction",
		"NtRollforwardTransactionManager",
		"NtSaveKey",
		"NtSaveKeyEx",
		"NtSaveMergedKeys",
		"NtSecureConnectPort",
		"NtSerializeBoot",
		"NtSetBootEntryOrder",
		"NtSetBootOptions",
		"NtSetContextThread",
		"NtSetDebugFilterState",
		"NtSetDefaultHardErrorPort",
		"NtSetDefaultLocale",
		"NtSetDefaultUILanguage",
		"NtSetDriverEntryOrder",
		"NtSetEaFile",
		"NtSetHighEventPair",
		"NtSetHighWaitLowEventPair",
		"NtSetInformationDebugObject",
		"NtSetInformationEnlistment",
		"NtSetInformationJobObject",
		"NtSetInformationKey",
		"NtSetInformationResourceManager",
		"NtSetInformationToken",
		"NtSetInformationTransaction",
		"NtSetInformationTransactionManager",
		"NtSetInformationWorkerFactory",
		"NtSetIntervalProfile",
		"NtSetIoCompletion",
		"NtSetIoCompletionEx",
		"NtSetLdtEntries",
		"NtSetLowEventPair",
		"NtSetLowWaitHighEventPair",
		"NtSetQuotaInformationFile",
		"NtSetSecurityObject",
		"NtSetSystemEnvironmentValue",
		"NtSetSystemEnvironmentValueEx",
		"NtSetSystemInformation",
		"NtSetSystemPowerState",
		"NtSetSystemTime",
		"NtSetThreadExecutionState",
		"NtSetTimerEx",
		"NtSetTimerResolution",
		"NtSetUuidSeed",
		"NtSetVolumeInformationFile",
		"NtShutdownSystem",
		"NtShutdownWorkerFactory",
		"NtSignalAndWaitForSingleObject",
		"NtSinglePhaseReject",
		"NtStartProfile",
		"NtStopProfile",
		"NtSuspendProcess",
		"NtSuspendThread",
		"NtSystemDebugControl",
		"NtTerminateJobObject",
		"NtTestAlert",
		"NtThawRegistry",
		"NtThawTransactions",
		"NtTraceControl",
		"NtTranslateFilePath",
		"NtUmsThreadYield",
		"NtUnloadDriver",
		"NtUnloadKey",
		"NtUnloadKey2",
		"NtUnloadKeyEx",
		"NtUnlockFile",
		"NtUnlockVirtualMemory",
		"NtVdmControl",
		"NtWaitForDebugEvent",
		"NtWaitForKeyedEvent",
		"NtWaitForWorkViaWorkerFactory",
		"NtWaitHighEventPair",
		"NtWaitLowEventPair",
		"NtWorkerFactoryWorkerReady"
	};

	static const char *MONITORED_SYSCALLS[] = {
		"NtCreateFile",
		"NtOpenProcess"
	};

	for (int i = 0; i < countof(SYSCALLS); i++) {
		for (int j = 0; j < countof(MONITORED_SYSCALLS); j++) {
			if (strcmp(SYSCALLS[i], MONITORED_SYSCALLS[j])) {
				continue;
			}

			addr_t sysaddr = vmi_translate_ksym2v(conf->vmi, MONITORED_SYSCALLS[j]);
			if (0 == sysaddr) {
				fprintf(stderr, "could not find symbol %s\n", MONITORED_SYSCALLS[j]);
				goto done;
			}

			vf_paddr_record *syscall_trap = vf_setup_mem_trap(conf, sysaddr);
			if (NULL == syscall_trap) {
				fprintf(stderr, "failed to set memory trap on %s\n",
						 MONITORED_SYSCALLS[j]);
				goto done;
			}

			/* set identifier to what RAX would be during syscall */
			syscall_trap->identifier = i;

			break;
		}
	}

	status = true;

done:
	return status;
}

int
main (int argc, char **argv) {
	struct sigaction act;
	status_t status = VMI_FAILURE;
	vmi_instance_t vmi;
	char *name = NULL;
	vf_config config = {0};

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

	vf_page_translation = g_hash_table_new(NULL, NULL);
	vf_page_record_collection = g_hash_table_new_full(NULL,
	                                                  NULL,
	                                                  NULL,
	                                                  vf_destroy_page_record);

	vmi_pause_vm(vmi);

	if (!vf_init_config(vmi, name, &config)) {
		vmi_resume_vm(vmi);
		goto done;
	}

	if (!vf_set_up_step_events(&config)) {
		vmi_resume_vm(vmi);
		goto done;
	}

	if (!vf_set_up_generic_events(&config)) {
		vmi_resume_vm(vmi);
		goto done;
	}

	if (!vf_find_syscalls_and_setup_mem_trap(&config)) {
		vmi_resume_vm(vmi);
		goto done;
	}

	if (!vf_set_up_sysret_handler(&config)) {
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

	g_hash_table_destroy(vf_page_record_collection);
	g_hash_table_destroy(vf_page_translation);
	vf_close_config(&config);

	vmi_resume_vm(vmi);

	if (vmi != NULL) {
		vmi_destroy(vmi);
	}

	exit(VMI_SUCCESS == status ? EXIT_SUCCESS : EXIT_FAILURE);
}

#include <capstone/capstone.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <libvmi/slat.h>
#include <libvmi/libvmi_extra.h>
#include <glib.h>
#include <libxl_utils.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include "early-boot.h"
#include "guestrace.h"
#include "guestrace-private.h"
#include "functions-linux.h"
#include "functions-windows.h"
#include "trace-syscalls.h"

/*
 * High-level design:
 *
 * This code relies on Xen's interface to Second Level Address Translation,
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
 *
 *
 *
 * Guestrace makes use of two types of breakpoints:
 *
 * Guestrace places a type-one breakpoint as the first instruction in each
 * per-system-call implementation routine. For example, Linux's sys_open,
 * which is called by the handler pointed to by LSTAR. Each type-one
 * breakpoint exists as a modification of some shadow page. Guestrace can easily
 * identify the addresses which require type-one breakpoints; it merely looks
 * up the function name using libvmi. (We do not break on the function pointed
 * to by LSTAR because a program might want to break only on select system
 * calls for performance reasons.
 *
 * Guestrace places a type-two breakpoints on the return path between each
 * per-system-call implementation routine and its caller. To avoid disassembly,
 * guestrace uses a trampoline. To avoid allocating new page in the guest
 * operating system's memory space, guestrace makes use of an existing break-
 * point instruction byte in the guest operating system's memory space. At
 * start-up time, guestrace finds the instruction. While servicing each
 * type-one breakpoint, guestrace overwrites the stack so that the return
 * executes the breakpoint instruction. After servicing a type-two breakpoing,
 * guestrace sets RIP to the original return point.
 */

/**
 * SECTION: guestrace
 * @title: libguestrace
 * @short_description: a library which allows programs to monitor the system
 * calls serviced by a kernel running as a Xen guest.
 * @include: libguestrace/guestrace.h
 *
 * A program using libguestrace registers callbacks which the guestrace event
 * loop invokes when a system call occurs in the monitored guest operating system.
 * Libguestrace builds upon libvmi, and it makes libvmi's lower-level
 * facilities available from within a callback through its
 * gt_guest_get_vmi_instance() and gt_guest_get_vmi_event() routines.
 *
 * <example>
 * 	<title>Program which uses libguestrace to print open()s and read()s which occur on a Linux guest (error handling and other details omitted)</title>
 * 	<programlisting>
 * 	GLoop *loop = gt_loop_new("xen-guest-name");
 *
 * 	gt_loop_set_cb(loop, "sys_open", open_cb, sysret_cb, NULL);
 * 	gt_loop_set_cb(loop, "sys_read", read_cb, sysret_cb, NULL);
 *
 * 	gt_loop_run(loop);
 * 	</programlisting>
 * </example>
 *
 * <example>
 * 	<title>A simple open_cb() routine which prints the system-call's parameters</title>
 * 	<programlisting>
 *void *open_cb(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
 *{
 *        gt_addr_t addr = gt_guest_get_register(state, RDI);
 *        char *path     = gt_guest_get_string(state, addr);
 *        int flags      = gt_guest_get_register(state, RSI);
 *        int mode       = gt_guest_get_register(state, RDX);
 *        printf("%u called open(\"%s\", %i, %d)\n", pid, path, flags, mode);
 *        return NULL;
 *}
 * 	</programlisting>
 * </example>
 **/

/* Intel breakpoint interrupt (INT 3) instruction. */
uint8_t GT_BREAKPOINT_INST = 0xCC;

/*
 * Handle terminating signals by unsetting gt_running flag. This allows
 * a graceful exit.
 */
static gboolean gt_running = TRUE;

/* Track whether we are in a GtSyscallFunc. */
static gboolean in_syscall_cb = FALSE;

/*
 * A record which describes a frame. The children of these records (themselves
 * of type gt_paddr_record) describe the physical addresses contained in the
 * frame which themselves contain a breakpoint. This is needed when the guest
 * operating system triggers such a breakpoint.
 *
 * Stored in gt_page_record_collection.
 * 	Key:   addr_t (shadow frame)
 * 	Value: gt_page_record
 */
typedef struct gt_page_record {
	addr_t      frame;
	addr_t      shadow_frame;
	GHashTable *children;
	GtLoop     *loop;
} gt_page_record;

/*
 * A record which describes the information associated with a physical address
 * which contains a breakpoint.
 *
 * Stored in children field of gt_page_record.
 * 	Key:   addr_t (shadow offset)
 * 	Value: gt_paddr_record
 */
typedef struct gt_paddr_record {
	addr_t          offset;
	GtSyscallFunc   syscall_cb;
	GtSysretFunc    sysret_cb;
	gt_page_record *parent;
	void           *data; /* Optional; passed to syscall_cb. */
} gt_paddr_record;

/*
 * Describes the state associated with a system call. This information is
 * stored and later made available while servicing the corresponding
 * system return.
 *
 * Stored in gt_ret_addr_mapping.
 * 	Key:   addr_t (thread_id AKA thread's stack pointer)
 * 	Value: gt_syscall_state
 */
typedef struct gt_syscall_state {
	gt_paddr_record *syscall_paddr_record;
	void            *data;
	addr_t           thread_id; /* needed for teardown */
} gt_syscall_state;

/*
 * Restore a stack return pointer; useful to ensure the kernel continues to
 * run after guestrace exit. Otherwise, guestrace's stack manipulation might
 * remain in place, since guestrace might no longer exist at the time of a
 * system-call return.
 */
static void
gt_restore_return_addr (gpointer data)
{
	status_t status;
	gt_syscall_state *sys_state = data;
	GtLoop *loop = sys_state->syscall_paddr_record->parent->loop;

	if (gt_running) {
		/*
		 * Save time: no need to restore stack if guestrace remains
		 * attached. In this case, we will return through the
		 * trampoline by setting RIP.
		 */
		goto done;
	}

	addr_t pa = vmi_translate_kv2p(loop->vmi, sys_state->thread_id);
	if (0 == pa) {
		fprintf(stderr, "error restoring stack; guest will likely fail\n");
		goto done;
	}

	status = vmi_write_64_pa(loop->vmi, pa, &loop->return_addr);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "error restoring stack; guest will likely fail\n");
		goto done;
	}

done:
	g_free(sys_state);
}

static void
gt_destroy_page_record (gpointer data) {
	status_t status;
	gt_page_record *page_record = data;

	g_hash_table_destroy(page_record->children);

	/* Stop monitoring this page. */
	vmi_set_mem_event(page_record->loop->vmi,
	                  page_record->frame,
	                  VMI_MEMACCESS_N,
	                  page_record->loop->shadow_view);

	status = vmi_slat_change_gfn(page_record->loop->vmi,
				     page_record->loop->shadow_view,
				     page_record->shadow_frame,
				    ~0);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to update shadow view\n");
	}

	xc_domain_decrease_reservation_exact(page_record->loop->xch,
	                                     page_record->loop->domid,
	                                     1, 0,
	                                    &page_record->shadow_frame);

	g_free(page_record);
}

/*
 * Callback after a step event on any VCPU.
 */
static event_response_t
gt_singlestep_cb(vmi_instance_t vmi, vmi_event_t *event) {
	GtLoop *loop = event->data;

	/* Resume use of shadow SLAT. */
	event->slat_id = loop->shadow_view;

	/* Turn off single-step and switch slat_id. */
	return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP
	     | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
}

/*
 * Preemptively create the step events needed for each VCPU so we don't have to
 * create a new event each time we want to single-step.
 */
static bool
gt_set_up_step_events (GtLoop *loop)
{
	bool ok = false;

	int vcpus = vmi_get_num_vcpus(loop->vmi);
	if (0 == vcpus) {
		fprintf(stderr, "failed to get number of VCPUs\n");
		goto done;
	}

	if (vcpus > _GT_MAX_VCPUS) {
		fprintf(stderr, "guest has more VCPUs than supported\n");
		goto done;
	}

	for (int vcpu = 0; vcpu < vcpus; vcpu++) {
		SETUP_SINGLESTEP_EVENT(&(loop->step_event[vcpu]),
		                       1u << vcpu,
		                       gt_singlestep_cb,
		                       0);
		loop->step_event[vcpu].data = loop;

		if (VMI_SUCCESS != vmi_register_event(loop->vmi,
		                                     &loop->step_event[vcpu])) {
			fprintf(stderr,
			       "register single-step event on VCPU failed %d\n",
			        vcpu);
			goto done;
		}
	}

	ok = true;

done:
	return ok;
}

/*
 * Return the paddr_record associated with the given physical address.
 *
 * First obtain the page record associated with the physical address's
 * page, and then obtain the child within that record which is associated
 * with the physical address. Recall that a given page might contain
 * multiple breakpoints.
 */
static gt_paddr_record *
gt_paddr_record_from_pa(GtLoop *loop, addr_t pa) {
	gt_paddr_record *paddr_record = NULL;
	gt_page_record  *page_record  = NULL;

	addr_t frame  = pa >> GT_PAGE_OFFSET_BITS;
	addr_t offset = pa  % GT_PAGE_SIZE;
	addr_t shadow = (addr_t)g_hash_table_lookup(loop->gt_page_translation,
	                                            GSIZE_TO_POINTER(frame));
	if (0 == shadow) {
		goto done;
	}

	page_record = g_hash_table_lookup(loop->gt_page_record_collection,
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
static gt_paddr_record *
gt_paddr_record_from_va(GtLoop *loop, addr_t va) {
	return gt_paddr_record_from_pa(loop, vmi_translate_kv2p(loop->vmi, va));
}

/**
 * gt_guest_free_syscall_state:
 * @state: a pointer to a #GtGuestState.
 * @thread_id: the thread ID associated with the syscall to free.
 *
 * Frees the object which the guestrace event loop would have allocated
 * when processing the system call associated with @thread_id. This is useful
 * for system calls that never return (unless there is an error) such as execve.
 * The application must first free the object pointed to by the @data
 * argument to the #GtSyscallFunc before calling this function. The
 * application should not call this function if the guestrace event loop
 * will call #GtSysretFunc.
 */
void
gt_guest_free_syscall_state(GtGuestState *state, gt_tid_t thread_id)
{
	g_hash_table_remove(state->loop->gt_ret_addr_mapping,
			    GSIZE_TO_POINTER(thread_id));
}

/*
 * Service a triggered breakpoint. Restore the original page table for one
 * single-step iteration and invoke the system call or return callback.
 *
 * In the case of a system call, enable the syscall return breakpoint.
 *
 * In the case of a system return, disable the syscall return breakpoint until
 * the next system call enables it.
 */
static event_response_t
gt_breakpoint_cb(vmi_instance_t vmi, vmi_event_t *event) {
	event_response_t response = VMI_EVENT_RESPONSE_NONE;

	GtLoop *loop = event->data;
	event->interrupt_event.reinject = 0;

	if (event->interrupt_event.gla != loop->trampoline_addr) {
		/* Type-one breakpoint (system call). */
		status_t status;
		addr_t thread_id, return_loc;
		gt_paddr_record *record;
		gt_syscall_state *state;

		/* Lookup record corresponding to breakpoint address. */
		record = gt_paddr_record_from_va(loop,
		                                 event->interrupt_event.gla);
		if (NULL == record) {
			/* Assume we didn't emplace interrupt. */
			event->interrupt_event.reinject = 1;
			/* TODO: Ensure this does the right thing: */
			goto done;
		}

		/* Set VCPUs SLAT to use original for one step. */
		event->slat_id = 0;

		/* Turn on single-step and switch slat_id after return. */
		response = VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP
		         | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;

		thread_id = return_loc = event->x86_regs->rsp;

		addr_t return_addr = 0;
		status = vmi_read_64_va(vmi, return_loc, 0, &return_addr);
		if (VMI_SUCCESS != status || return_addr != loop->return_addr) {
			/* Return pointer not as expected. */
			goto done;
		}

		gt_pid_t pid = vmi_dtb_to_pid(vmi, event->x86_regs->cr3);

		state                       = g_new0(gt_syscall_state, 1);
		state->syscall_paddr_record = record;
		state->thread_id            = thread_id;

		/* Invoke system-call callback in record. */
		in_syscall_cb = TRUE;
		state->data          = record->syscall_cb(&(GtGuestState) { loop, vmi, event },
		                                          pid,
		                                          thread_id,
		                                          record->data);
		in_syscall_cb = FALSE;

		/* Record system-call state. */
		g_hash_table_insert(loop->gt_ret_addr_mapping,
		                    GSIZE_TO_POINTER(thread_id),
		                    state);

		/* Overwrite stack to return to trampoline. */
		vmi_write_64_va(vmi, return_loc, 0, &loop->trampoline_addr);
	} else {
		/* Type-two breakpoint (system return). */
		gt_syscall_state *state;
		addr_t thread_id = event->x86_regs->rsp - loop->return_addr_width;

		state = g_hash_table_lookup(loop->gt_ret_addr_mapping,
		                            GSIZE_TO_POINTER(thread_id));

		if (NULL != state) {
			gt_pid_t pid = vmi_dtb_to_pid(vmi, event->x86_regs->cr3);

			state->syscall_paddr_record->sysret_cb(&(GtGuestState) { loop, vmi, event },
			                                       pid,
			                                       thread_id,
			                                       state->data);

			vmi_set_vcpureg(vmi, loop->return_addr, RIP, event->vcpu_id);

			/*
			 * This will free our gt_syscall_state object, but
			 * sysret_cb must have freed state->data.
			 */
			gt_guest_free_syscall_state(&(GtGuestState) { loop, vmi, event }, thread_id);
		}
	}

done:
	return response;
}

/*
 * Callback invoked on a R/W of a monitored page (likely Windows kernel patch
 * protection). Switch the VCPU's SLAT to its original, step once, switch SLAT
 * back.
 */
static event_response_t
gt_mem_rw_cb (vmi_instance_t vmi, vmi_event_t *event) {
	/* Switch back to original SLAT for one step. */
	event->slat_id = 0;

	return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP
	     | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
}

/* Callback invoked on CR3 change (context switch). */
static event_response_t
gt_cr3_cb(vmi_instance_t vmi, vmi_event_t *event) {
	event_response_t response = VMI_EVENT_RESPONSE_NONE;

	/* This is not the case yet, since the event precedes the CR3 update. */
	event->x86_regs->cr3 = event->reg_event.value;

	/*
	 * Testing indicated pidcache flush was necessary to get vaddr
	 * translations to consistently work in a GtSyscallFunc. DRAKVUF
	 * flushes all of the caches on a CR3 change, so we do too.
	 */
	vmi_pidcache_flush(vmi);
	vmi_v2pcache_flush(vmi, event->reg_event.previous);
	vmi_rvacache_flush(vmi);
	vmi_symcache_flush(vmi);

	return response;
}

/*
 * Setup our global interrupt to catch any interrupts on any pages.
 */
static bool
gt_set_up_generic_events (GtLoop *loop) {
	bool ok = false;
	status_t status;

	SETUP_INTERRUPT_EVENT(&loop->breakpoint_event, 0, gt_breakpoint_cb);
	loop->breakpoint_event.data = loop;

	SETUP_REG_EVENT(&loop->cr3_event, CR3, VMI_REGACCESS_W, 0, gt_cr3_cb);
	loop->cr3_event.data = loop;

	status = vmi_register_event(loop->vmi, &loop->breakpoint_event);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "Failed to setup interrupt event\n");
		goto done;
	}

	SETUP_MEM_EVENT(&loop->memory_event,
	                ~0ULL,
	                 VMI_MEMACCESS_RW,
	                 gt_mem_rw_cb,
	                 1);

	loop->memory_event.data = loop;

	status = vmi_register_event(loop->vmi, &loop->memory_event);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to setup memory event\n");
		goto done;
	}

	ok = true;

done:
	return ok;
}

/* Search the kernel code address space for an existing int 3 instruction. */
addr_t
gt_find_trampoline_addr (GtLoop *loop)
{
	addr_t trampoline_addr = 0;
	status_t status;
	addr_t lstar = 0;
	uint8_t code[GT_PAGE_SIZE] = { 0 }; /* Assume CALL is within first page. */

	/* LSTAR should be constant across all VCPUs */
	status = vmi_get_vcpureg(loop->vmi, &lstar, MSR_LSTAR, 0);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to get MSR_LSTAR address\n");
		goto done;
	}

	g_assert(loop->lstar_addr == lstar);

	addr_t lstar_p = vmi_translate_kv2p(loop->vmi, lstar);
	if (0 == lstar_p) {
		fprintf(stderr, "failed to translate virtual LSTAR to physical address");
		goto done;
	}

	/* Read kernel instructions into code. */
	status = vmi_read_pa(loop->vmi, lstar_p, code, sizeof(code));
	if (status < GT_PAGE_SIZE) {
		fprintf(stderr, "failed to read instructions from 0x%lx.\n",
		                 lstar_p);
		goto done;
	}

	/* Look for int 3. */
	for (int curr_inst = 0; curr_inst < GT_PAGE_SIZE; curr_inst++) {
		if (code[curr_inst] == GT_BREAKPOINT_INST) {
			trampoline_addr = lstar + curr_inst;
			break;
		}
	}

done:
	return trampoline_addr;
}

/**
 * gt_loop_new:
 * @guest_name: the name of a running guest virtual machine.
 *
 * Creates a new #GtLoop structure.
 *
 * Returns: a new #GtLoop.
 **/
GtLoop *gt_loop_new(const char *guest_name)
{
	int i;
	GtLoop *loop;
	int rc;
	status_t status = VMI_FAILURE;

	loop = g_new0(GtLoop, 1);

	loop->g_main_loop = g_main_loop_new(NULL, true);
	loop->guest_name = guest_name;

	/* Initialize the libvmi library. */
	for (i = 0; i < 300; i++) {
		status = vmi_init(&loop->vmi,
				   VMI_XEN | VMI_INIT_COMPLETE | VMI_INIT_EVENTS,
				   guest_name);

		if (VMI_SUCCESS == status) {
			break;
		}

		usleep(100000);
	}

	/* Did vmi_init fail too many times above? */
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to init LibVMI library.\n");
		goto done;
	}

	loop->gt_page_translation = g_hash_table_new(NULL, NULL);
	loop->gt_page_record_collection = g_hash_table_new_full(NULL,
	                                                        NULL,
	                                                        NULL,
	                                                        gt_destroy_page_record);
	loop->gt_ret_addr_mapping = g_hash_table_new_full(NULL,
	                                                  NULL,
	                                                  NULL,
	                                                  gt_restore_return_addr);

	vmi_pause_vm(loop->vmi);

	loop->os = vmi_get_ostype(loop->vmi);
	switch (loop->os) {
	case VMI_OS_LINUX:
		loop->os_functions = &os_functions_linux;
		break;
	case VMI_OS_WINDOWS:
		loop->os_functions = &os_functions_windows;
		break;
	default:
		fprintf(stderr, "unknown guest operating system\n");
		status = VMI_FAILURE;
		goto done;
	}

	loop->return_addr_width = vmi_get_address_width(loop->vmi);

	loop->xch = xc_interface_open(0, 0, 0);
	if (NULL == loop->xch) {
		fprintf(stderr, "failed to create xc interface\n");
                status = VMI_FAILURE;
		goto done;
	}

	rc = libxl_ctx_alloc(&loop->ctx, LIBXL_VERSION, 0, NULL);
	if (0 != rc) {
		fprintf(stderr, "failed to create libxl context\n");
                status = VMI_FAILURE;
		goto done;
	}

	loop->domid = ~0u;
	rc = libxl_name_to_domid(loop->ctx, guest_name, &loop->domid);
	if (0 != rc || ~0u == loop->domid) {
		fprintf(stderr, "failed to translate guest name to dom. ID\n");
                status = VMI_FAILURE;
		goto done;
	}

	loop->curr_mem_size = loop->init_mem_size = vmi_get_memsize(loop->vmi);
	if (0 == loop->init_mem_size) {
		fprintf(stderr, "failed to get guest memory size\n");
                status = VMI_FAILURE;
		goto done;
	}

	status = vmi_slat_set_domain_state(loop->vmi, TRUE);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to enable slat/altp2m on guest\n");
		goto done;
	}

	status = vmi_slat_create(loop->vmi, &loop->shadow_view);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to enable shadow view\n");
		goto done;
	}

	vmi_resume_vm(loop->vmi);

done:
	if (VMI_SUCCESS != status) {
		gt_loop_free(loop);
		loop = NULL;
	}

	return loop;
}

/**
 * gt_loop_get_ostype:
 * @loop: a #GtLoop.
 *
 * Returns: the OS type of #GtLoop.
 **/
GtOSType
gt_loop_get_ostype(GtLoop *loop)
{
	switch (loop->os) {
	case VMI_OS_LINUX:
		return GT_OS_LINUX;
	case VMI_OS_WINDOWS:
		return GT_OS_WINDOWS;
	default:
		return GT_OS_UNKNOWN;
	}
}

 /**
 * gt_loop_get_guest_name:
 * @loop: a #GtLoop.
 *
 * Returns: the name of the guest to which #GtLoop has attached. The #GtLoop
 * maintains ownership of the string. Thus the returned string must not be
 * freed by the caller.
 **/
const char *
gt_loop_get_guest_name(GtLoop *loop)
{
	return loop->guest_name;
}

/**
 * gt_loop_get_vmi_instance:
 * @loop: a pointer to a #GtLoop.
 *
 * Returns the vmi_instance_t associated with @loop. Refer to the libvmi
 * documentation for a description of vmi_instance_t.
 */
vmi_instance_t
gt_loop_get_vmi_instance(GtLoop *loop)
{
	return loop->vmi;
}

/**
 * gt_guest_get_register:
 * @state: a pointer to a #GtGuestState.
 * @name: name of register to get.
 *
 * Returns the value of the named register from the guest state.
 */
gt_reg_t
gt_guest_get_register(GtGuestState *state, gt_reg_name_t name)
{
	gt_reg_t reg = 0;

	switch (name) {
	case RAX:
		reg = state->event->x86_regs->rax;
		goto done;
	case RSP:
		reg = state->event->x86_regs->rsp;
		goto done;
	case RDI:
		reg = state->event->x86_regs->rdi;
		goto done;
	case RSI:
		reg = state->event->x86_regs->rsi;
		goto done;
	case RCX:
		reg = state->event->x86_regs->rcx;
		goto done;
	case RDX:
		reg = state->event->x86_regs->rdx;
		goto done;
	case R8:
		reg = state->event->x86_regs->r8;
		goto done;
	case R9:
		reg = state->event->x86_regs->r9;
		goto done;
	case R10:
		reg = state->event->x86_regs->r10;
		goto done;
	}

	g_assert_not_reached();

done:
	return reg;
}

/**
 * gt_guest_get_bytes:
 * @state: a pointer to a #GtGuestState.
 * @vaddr: a virtual address from the guest's address space.
 * @pid: PID of the virtual address space (0 for kernel).
 * @buf: the data read from memory.
 * @count: the number of bytes to read.
 *
 * Copies a sequence of up to @count bytes which starts at @vaddr into the
 * memory starting at @buf. Returns the number of bytes copied.
 */
size_t
gt_guest_get_bytes(GtGuestState *state, gt_addr_t vaddr, gt_pid_t pid, void *buf, size_t count)
{
	return vmi_read_va(gt_guest_get_vmi_instance(state), vaddr, pid, buf, count);
}

/**
 * gt_guest_get_string:
 * @state: a pointer to a #GtGuestState.
 * @vaddr: a virtual address from the guest's address space.
 * @pid: PID of the virtual address space (0 for kernel).
 *
 * Returns the NULL-terminated string which starts at @vaddr or NULL on error.
 * The returned string must be freed by the caller.
 */
char *
gt_guest_get_string(GtGuestState *state, gt_addr_t vaddr, gt_pid_t pid)
{
	return vmi_read_str_va(gt_guest_get_vmi_instance(state), vaddr, pid);
}

/**
 * gt_guest_get_argv:
 * @state: a pointer to a #GtGuestState.
 * @vaddr: a virtual address from the guest's address space.
 * @pid: PID of the virtual address space (0 for kernel).
 *
 * Returns the NULL-terminated argv-style array which starts at @vaddr
 * or NULL on error. Each item in the array is a string.
 * The array and each string in the array must be freed by the caller.
 */
char **
gt_guest_get_argv(GtGuestState *state, gt_addr_t vaddr, gt_pid_t pid)
{
	status_t status = VMI_SUCCESS;
	int length = 16, i = 0;
	char **argv = NULL;
	vmi_instance_t vmi = gt_guest_get_vmi_instance(state);

	if (0 == vaddr) {
		goto done;
	}

	argv = g_new0(char *, length);

	do {
		uint64_t vaddr2;
		status = vmi_read_64_va(vmi, vaddr + (i * sizeof(char *)), pid, &vaddr2);
		if (VMI_SUCCESS != status) {
			goto done;
		}
		if (vaddr2 != 0) {
			if (i == length) {
				length *= 2;
				argv = g_renew(char *, argv, length);
				memset(argv + i, 0x00, length - i);
			}
			argv[i] = vmi_read_str_va(vmi, vaddr2, pid);
		} else {
			argv[i] = NULL;
		}
	} while (argv[i++] != NULL);

done:
	if (VMI_SUCCESS != status) {
		for (i = 0; argv[i]; i++) {
			g_free(argv[i]);
		}
		g_free(argv);
		argv = NULL;
	}

	return argv;
}

/**
 * gt_guest_get_vmi_instance:
 * @state: a pointer to a #GtGuestState.
 *
 * Returns the vmi_instance_t associated with @state. Refer to the libvmi
 * documentation for a description of vmi_instance_t.
 */
vmi_instance_t
gt_guest_get_vmi_instance(GtGuestState *state)
{
	return state->vmi;
}

/**
 * gt_guest_get_vmi_event:
 * @state: a pointer to a #GtGuestState.
 *
 * Returns the vmi_event_t associated with @state. Refer to the libvmi
 * documentation for a description of vmi_event_t.
 */
vmi_event_t *
gt_guest_get_vmi_event(GtGuestState *state)
{
	return state->event;
}

char *
gt_guest_get_process_name(GtGuestState *state, gt_pid_t pid)
{
	char *process_name = NULL;

	switch (state->loop->os) {
	case VMI_OS_LINUX:
		process_name = gt_linux_get_process_name(state->vmi, pid);
		break;
	case VMI_OS_WINDOWS:
		process_name = gt_windows_get_process_name(state->vmi, pid);
		break;
	default:
		g_assert_not_reached();
	}

	return process_name;
}

static gboolean
gt_loop_listen(gpointer user_data)
{
	GtLoop *loop = user_data;

	status_t status = vmi_events_listen(loop->vmi, 500);
	if (status != VMI_SUCCESS) {
		fprintf(stderr, "error waiting for events\n");
		gt_running = FALSE;
	}

	if (!gt_running) {
		g_main_loop_quit(loop->g_main_loop);
	}

	return gt_running;
}

/**
 * gt_loop_run:
 * @loop: a #GtLoop.
 *
 * Uses libvmi to complete the preparations necessary to trace a guest's system
 * calls. Runs @loop until gt_loop_quit() is called on @loop.
 */
void gt_loop_run(GtLoop *loop)
{
	status_t status;

	status = early_boot_wait_for_os_load(loop);
	if (VMI_SUCCESS != status) {
                fprintf(stderr, "failed to wait on LSTAR.\n");
                goto done;
        }

	status = early_boot_wait_for_first_process(loop);
	if (VMI_SUCCESS != status) {
                fprintf(stderr, "failed to wait for initialization\n");
                goto done;
        }

	vmi_pause_vm(loop->vmi);

	status = vmi_slat_switch(loop->vmi, loop->shadow_view);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to enable shadow view\n");
		goto done;
	}

	if (!gt_set_up_generic_events(loop)) {
		goto done;
	}

	if (!gt_set_up_step_events(loop)) {
		goto done;
	}

	loop->return_addr = loop->os_functions->find_return_point_addr(loop);
	if (0 == loop->return_addr) {
		goto done;
	}

	loop->trampoline_addr = gt_find_trampoline_addr(loop);
	if (0 == loop->trampoline_addr) {
		fprintf(stderr, "could not find addr. of existing int 3 inst.\n");
		goto done;
	}

	vmi_resume_vm(loop->vmi);

	g_idle_add(gt_loop_listen, loop);
	g_main_loop_run(loop->g_main_loop);

	vmi_pause_vm(loop->vmi);

	/*
	 * gt_running affects freeing of gt_ret_addr_mapping elements.
	 * Must be false or return pointers on kernel stack will not be reset.
	 * Thus we check no code has been altered in an ill way here, since
	 * this requirement is not obvious.
	 */
	g_assert(!gt_running);

	g_hash_table_remove_all(loop->gt_page_translation);
	g_hash_table_remove_all(loop->gt_ret_addr_mapping);
	g_hash_table_remove_all(loop->gt_page_record_collection);

	status = vmi_slat_switch(loop->vmi, 0);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to reset EPT to point to default table\n");
	}

	vmi_resume_vm(loop->vmi);

done:
	return;
}

/**
 * gt_loop_quit:
 * @loop: a #GtLoop.
 *
 * Stops @loop from running. Any calls to gt_loop_run() for the loop will return.
 * This removes any modifications to the guest's memory and allows the guest
 * to run without instrumentation.
 */
void gt_loop_quit(GtLoop *loop)
{
	gt_running = FALSE;
}

/**
 * gt_loop_free:
 * @loop: a #GtLoop.
 *
 * Free @loop and its associated memory. If the loop is currently running, then
 * gt_loop_quit() must first terminate the loop and remove the guest
 * instrumentation.
 */
void gt_loop_free(GtLoop *loop)
{
	if (NULL == loop) {
		goto done;
	}

	vmi_pause_vm(loop->vmi);

	g_hash_table_destroy(loop->gt_page_translation);
	g_hash_table_destroy(loop->gt_ret_addr_mapping);
	g_hash_table_destroy(loop->gt_page_record_collection);

	vmi_slat_destroy(loop->vmi, loop->shadow_view);
	vmi_slat_set_domain_state(loop->vmi, FALSE);
	/* TODO: find out why this isn't decreasing main memory on next run of guestrace */
	xc_domain_setmaxmem(loop->xch, loop->domid, loop->init_mem_size);

	libxl_ctx_free(loop->ctx);
	xc_interface_close(loop->xch);

	vmi_resume_vm(loop->vmi);

	vmi_destroy(loop->vmi);

	g_main_loop_unref(loop->g_main_loop);

	g_free(loop);

done:
	return;
}

/* Allocate a new page of memory in the guest's address space. */
static addr_t
gt_allocate_shadow_frame (GtLoop *loop)
{
	int rc;
	xen_pfn_t gfn = 0;
	uint64_t proposed_mem_size = loop->curr_mem_size + GT_PAGE_SIZE;

	rc = xc_domain_setmaxmem(loop->xch, loop->domid, proposed_mem_size);
	if (rc < 0) {
		fprintf(stderr,
		       "failed to increase memory size on guest to %lx\n",
		        proposed_mem_size);
		goto done;
	}

	loop->curr_mem_size = proposed_mem_size;

	rc = xc_domain_increase_reservation_exact(loop->xch, loop->domid,
	                                              1, 0, 0, &gfn);
	if (rc < 0) {
		fprintf(stderr, "failed to increase reservation on guest");
		goto done;
	}

	rc = xc_domain_populate_physmap_exact(loop->xch, loop->domid, 1, 0,
	                                          0, &gfn);
	if (rc < 0) {
		fprintf(stderr, "failed to populate GFN at 0x%lx\n", gfn);
		gfn = 0;
		goto done;
	}

done:
	return gfn;
}

/* Remove the breakpoint associated with paddr_record.  */
static status_t
gt_remove_breakpoint(gt_paddr_record *paddr_record) {
	uint8_t curr_inst;
	status_t status     = VMI_FAILURE;
	addr_t frame        = paddr_record->parent->frame;
	addr_t shadow_frame = paddr_record->parent->shadow_frame;
	addr_t offset       = paddr_record->offset;

	status = vmi_read_8_pa(paddr_record->parent->loop->vmi,
	                      (frame << GT_PAGE_OFFSET_BITS) + offset,
	                      &curr_inst);
	if (VMI_SUCCESS != status) {
		goto done;
	}

	status = vmi_write_8_pa(paddr_record->parent->loop->vmi,
	                       (shadow_frame << GT_PAGE_OFFSET_BITS) + offset,
	                       &curr_inst);

done:
	return status;
}

static void
gt_destroy_paddr_record (gpointer data) {
	gt_paddr_record *paddr_record = data;

	gt_remove_breakpoint(paddr_record);

	g_free(paddr_record);
}

/*
 * Ensure there exists a memory trap on the shadow page containing virtual
 * address va, and create a page record if it does not yet exist. Add a
 * physical-address record corresponding to va to the page record's collection
 * of children.
 */
static gt_paddr_record *
gt_setup_mem_trap (GtLoop *loop,
                   addr_t va,
                   GtSyscallFunc syscall_cb,
                   GtSysretFunc sysret_cb,
                   void *user_data)
{
	size_t ret;
	status_t status;
	gt_page_record  *page_record  = NULL;
	gt_paddr_record *paddr_record = NULL;

	addr_t pa = vmi_translate_kv2p(loop->vmi, va);
	if (0 == pa) {
		fprintf(stderr, "virtual addr. translation failed: %lx\n", va);
		goto done;
	}

	addr_t frame = pa >> GT_PAGE_OFFSET_BITS;
	addr_t shadow = (addr_t) g_hash_table_lookup(loop->gt_page_translation,
		                                     GSIZE_TO_POINTER(frame));
	addr_t shadow_offset = pa % GT_PAGE_SIZE;

	if (0 == shadow) {
		/* Record does not exist; allocate new page and create record. */
		shadow = gt_allocate_shadow_frame(loop);
		if (0 == shadow) {
			fprintf(stderr, "failed to allocate shadow page\n");
			goto done;
		}

		g_hash_table_insert(loop->gt_page_translation,
		                    GSIZE_TO_POINTER(frame),
		                    GSIZE_TO_POINTER(shadow));

		/* Activate in shadow view. */
		status = vmi_slat_change_gfn(loop->vmi,
		                             loop->shadow_view,
		                             frame,
		                             shadow);
		if (VMI_SUCCESS != status) {
			fprintf(stderr, "failed to update shadow view\n");
			goto done;
		}
	}

	page_record = g_hash_table_lookup(loop->gt_page_record_collection,
	                                  GSIZE_TO_POINTER(shadow));
	if (NULL == page_record) {
		/* No record for this page yet; create one. */

		/* Copy page to shadow. */
		uint8_t buff[GT_PAGE_SIZE] = {0};
		ret = vmi_read_pa(loop->vmi,
		                  frame << GT_PAGE_OFFSET_BITS,
		                  buff,
		                  GT_PAGE_SIZE);
		if (GT_PAGE_SIZE != ret) {
			fprintf(stderr, "failed to read in syscall page\n");
			goto done;
		}

		ret = vmi_write_pa(loop->vmi,
		                   shadow << GT_PAGE_OFFSET_BITS,
		                   buff,
		                   GT_PAGE_SIZE);
		if (GT_PAGE_SIZE != ret) {
			fprintf(stderr, "failed to write to shadow page\n");
			goto done;
		}

		/* Initialize record of this page. */
		page_record              = g_new0(gt_page_record, 1);
		page_record->shadow_frame = shadow;
		page_record->frame       = frame;
		page_record->loop        = loop;
		page_record->children    = g_hash_table_new_full(NULL,
		                                       NULL,
		                                       NULL,
		                                       gt_destroy_paddr_record);

		g_hash_table_insert(loop->gt_page_record_collection,
		                    GSIZE_TO_POINTER(shadow),
		                    page_record);

		/* Establish callback on a R/W of this page. */
		vmi_set_mem_event(loop->vmi, frame, VMI_MEMACCESS_RW,
		                  loop->shadow_view);
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
	paddr_record             = g_new0(gt_paddr_record, 1);
	paddr_record->offset     = shadow_offset;
	paddr_record->parent     = page_record;
	paddr_record->syscall_cb = syscall_cb;
	paddr_record->sysret_cb  = sysret_cb;
	paddr_record->data       = user_data;

	/* Write interrupt to our shadow page at the correct location. */
	status = vmi_write_8_pa(loop->vmi,
	                       (shadow << GT_PAGE_OFFSET_BITS) + shadow_offset,
	                       &GT_BREAKPOINT_INST);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to write interrupt to shadow page\n");
		goto done;
	}

	g_hash_table_insert(page_record->children,
	                    GSIZE_TO_POINTER(shadow_offset),
	                    paddr_record);

done:
	/* TODO: Should undo loop (e.g., remove from hash tables) on error */
	return paddr_record;
}

/**
 * gt_loop_set_cb:
 * @loop: a #GtLoop.
 * @kernel_func: the name of a function in the traced kernel which implements
 * a system call.
 * @syscall_cb: a #GtSyscallFunc which will handle the named system call.
 * @sysret_cb: a #GtSysretFunc which will handle returns from the named
 * system call.
 * @user_data: optional data which the guestrace event loop will pass to each call of @syscall_cb
 *
 * Sets the callback functions associated with @kernel_func. Each time
 * processing a system call in the guest kernel calls @kernel_func,
 * The loop will invoke @syscall_cb with the parameters associated with the
 * call. When @kernel_func returns, the loop will invoke @sysret_cb.
 *
 * Returns: %TRUE on success, %FALSE on failure; an invalid @kernel_func
 * will cause the callback registration to fail.
 **/
gboolean gt_loop_set_cb(GtLoop *loop,
                        const char *kernel_func,
                        GtSyscallFunc syscall_cb,
                        GtSysretFunc sysret_cb,
                        void *user_data)
{
	gboolean fnval = FALSE;

	addr_t sysaddr;
	gt_paddr_record *syscall_trap;

	vmi_pause_vm(loop->vmi);

	sysaddr = vmi_translate_ksym2v(loop->vmi, kernel_func);
	if (0 == sysaddr) {
		goto done;
	}

	syscall_trap = gt_setup_mem_trap(loop, sysaddr, syscall_cb, sysret_cb, user_data);
	if (NULL == syscall_trap) {
		goto done;
	}

	fnval = TRUE;

done:
	vmi_resume_vm(loop->vmi);

	return fnval;
}

/**
 * gt_loop_set_cbs:
 * @loop: a #GtLoop.
 * @syscalls: an array of #GtCallbackRegistry values, where each contains a
 * function name and corresponding #GtSyscallFunc and #GtSysretFunc.
 *
 * A convenience function which repeatedly invoke gt_loop_set_cb for each
 * callback defined in @syscalls. The @syscalls array must be terminated with
 * an #GtCallbackRegistry with each field set to NULL.
 *
 * Returns: an integer which represents the number of callbacks
 * successfully set; an invalid function name in @syscalls will
 * cause the corresponding callback registration to fail.
 **/
int
gt_loop_set_cbs(GtLoop *loop, const GtCallbackRegistry callbacks[])
{
	int count = 0;

	for (int i = 0; callbacks[i].name; i++) {
		gboolean ok = gt_loop_set_cb(loop,
		                             callbacks[i].name,
		                             callbacks[i].syscall_cb,
		                             callbacks[i].sysret_cb,
		                             callbacks[i].user_data);
		if (ok) {
			count++;
		}
	}

	return count;
}

/**
 * gt_loop_add_watch:
 * @channel: a GIOChannel.
 * @condition: the condition to watch for.
 * @func: the function to call when the condition is satisfied.
 * @user_data: user data to pass to @func.
 *
 * Returns: the event source ID.
 **/
guint
gt_loop_add_watch(GIOChannel *channel,
                  GIOCondition condition,
                  GIOFunc func,
                  gpointer user_data)
{
	return g_io_add_watch(channel, condition, func, user_data);
}

/*
 * Disassemble a page of memory beginning at <start> until
 * finding the correct mnemonic and op_str, returning the next address.
 * Note: op_str is optional.
 */
addr_t
_gt_find_addr_after_instruction (GtLoop *loop, addr_t start_v, char *mnemonic, char *ops)
{
	csh handle = 0;
	cs_insn *inst;
	size_t count, offset = ~0;
	addr_t ret = 0;
	uint8_t code[GT_PAGE_SIZE];

	addr_t start_p = vmi_translate_kv2p(loop->vmi, start_v);
	if (0 == start_p) {
		fprintf(stderr, "failed to translate virtual start address to physical address\n");
		goto done;
	}

	/* Read kernel instructions into code. */
	status_t status = vmi_read_pa(loop->vmi, start_p, code, sizeof(code));
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to read instructions from 0x%lx\n", start_p);
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
			if (0 == strcmp(inst[i].mnemonic, mnemonic)
			 && (NULL == ops || 0 == strcmp(inst[i].op_str, ops))) {
				offset = inst[i + 1].address;
				break;
			}
		}
		cs_free(inst, count);
	} else {
		fprintf(stderr, "failed to disassemble system-call handler\n");
		goto done;
	}

	if (~0 == offset) {
		fprintf(stderr, "did not find call in system-call handler\n");
		goto done;
	}

	ret = start_v + offset;

done:
	if (0 != handle) {
		cs_close(&handle);
	}

	return ret;
}

/**
 * gt_loop_hijack_return:
 * @state: a #GtGuestState.
 * @errno: a #gint.
 * @retval: a #gint.
 *
 * This function manipulates the guest to hijack the current system call such
 * that the system call does not execute and instead immediately returns @retval.
 * This function can only be called from within a #GtSyscallFunc.
 *
 * Returns: %TRUE on success, %FALSE on failure. A failure indicates that the
 * function could not identify the portion of instructions in the system call
 * which restores registers, restores the stack, and returns. In this case, the
 * function does not change any state within the guest processor.
 **/
gboolean
gt_hijack_return(GtGuestState *state, gint retval)
{
        csh handle = 0;
        cs_insn *inst;
        size_t count, offset = ~0;
	gboolean ok = FALSE;
	status_t status;
        uint8_t code[GT_PAGE_SIZE];

	/* Assert original view, as int3 byte will break disassembly. */
	g_assert(0 == state->event->slat_id);
	g_assert(in_syscall_cb);

        addr_t start_v = state->event->x86_regs->rip;
        addr_t start_p = vmi_translate_kv2p(state->vmi, start_v);
        if (0 == start_p) {
                fprintf(stderr, "failed to translate virtual start address to physical address\n");
                goto done;
        }

        /* Read kernel instructions into code. */
        status = vmi_read_pa(state->vmi, start_p, code, sizeof(code));
        if (VMI_FAILURE == status) {
                fprintf(stderr, "failed to read instructions from 0x%lx\n", start_p);
                goto done;
        }

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
                fprintf(stderr, "failed to open capstone\n");
                goto done;
        }

        /* Find RET inst. */
        count = cs_disasm(handle, code, sizeof(code), 0, 0, &inst);
        if (count > 0) {
                size_t i;
                for (i = 0; i < count; i++) {
                        printf("%lx %s %s\n", inst[i].address, inst[i].mnemonic, inst[i].op_str);
			if (0 == strcmp(inst[i].mnemonic, "ret")) {
				offset = inst[i].address;
				break;
                        }
                }
                cs_free(inst, count);
        } else {
                fprintf(stderr, "failed to disassemble system-call handler\n");
                goto done;
        }

	if (~0 == offset) {
                fprintf(stderr, "did not find ret in system-call handler\n");
                goto done;
        }

	vmi_set_vcpureg(state->vmi, retval, RAX, state->event->vcpu_id);
	vmi_set_vcpureg(state->vmi, start_v + offset, RIP, state->event->vcpu_id);

	ok = TRUE;

done:
	if (0 != handle) {
		cs_close(&handle);
	}

        return ok;
}

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
#include "rekall.h"
#include "state-stacks.h"

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

/* Track whether we are in a GtSyscallFunc. */
static gboolean in_syscall_cb = FALSE;

/* For SIGSEGV, etc. handling. */
static const int GT_EMERGENCY = 1;

/*
 * Restore a stack return pointer; useful to ensure the kernel continues to
 * run after guestrace exit. Otherwise, guestrace's stack manipulation might
 * remain in place, since guestrace might no longer exist at the time of a
 * system-call return.
 */
static void
gt_restore_return_addr(gpointer data, gpointer user_data)
{
	status_t status;
	addr_t current_return_addr;
	gt_syscall_state *sys_state = data;
	GtLoop *loop = sys_state->syscall_paddr_record->parent->loop;

	status = vmi_read_64_va(loop->vmi,
	                        sys_state->return_loc,
	                        0,
	                       &current_return_addr);
	if (VMI_SUCCESS != status) {
		/* Couldn't get return pointer off of stack */
		fprintf(stderr, "error checking stack; guest might "
				"fail if running\n");
		goto done;
	}

	if (current_return_addr != loop->trampoline_addr) {
		/*
		 * Previous stack from seems gone. For example, perhaps an
		 * execve never returned through the kernel stack. We support
		 * return-free instrumentation, but there still seems to exist
		 * a race condition in execve. Execve is odd because it returns
		 * on error, but not otherwise. An application might leave the
		 * return instrumentation in place in the case of execve to
		 * catch * failures.
		 */
		fprintf(stderr, "not restoring return address on stack for "
		                "call state; existing address unexpected\n");
		goto done;
	}

	status = vmi_write_64_va(loop->vmi,
				 sys_state->return_loc,
				 0,
				&sys_state->return_addr);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "error restoring stack; guest will"
				"likely fail if running\n");
	}
done:
	return;
}

static void
gt_destroy_page_record (gpointer data) {
	gt_page_record *page_record = data;

	g_hash_table_destroy(page_record->children);

	/* Stop monitoring this page. */
	vmi_set_mem_event(page_record->loop->vmi,
	                  page_record->frame,
	                  VMI_MEMACCESS_N,
	                  page_record->loop->shadow_view);

	int xc_status = xc_altp2m_change_gfn(page_record->loop->xch,
	                                     page_record->loop->domid,
	                                     page_record->loop->shadow_view,
	                                     page_record->shadow_frame,
	                                    ~0);
	if (0 != xc_status) {
		fprintf(stderr, "failed to update shadow view\n");
	}

	xc_domain_decrease_reservation_exact(page_record->loop->xch,
	                                     page_record->loop->domid,
	                                     1, 0,
	                                    &page_record->shadow_frame);

	g_free(page_record);
}

void
gt_rewrite_interrupts(gpointer key, gpointer value, gpointer user_data)
{
	uint8_t *cache = user_data;
	addr_t shadow_offset = GPOINTER_TO_INT(key);
	cache[shadow_offset] = GT_BREAKPOINT_INST;
}

/*
 * Callback after a step event on any VCPU.
 */
static event_response_t
gt_singlestep_cb(vmi_instance_t vmi, vmi_event_t *event) {
	GtLoop *loop = event->data;
	uint8_t cache[GT_PAGE_SIZE] = { 0 };
	size_t ret;

	if (0 != loop->mem_watch[event->vcpu_id]) {
		fprintf(stderr, "updating cached shadow memory\n");
		
		gt_page_record *record = g_hash_table_lookup(loop->gt_page_record_collection,
	                                                 GSIZE_TO_POINTER(loop->mem_watch[event->vcpu_id]));

		if (NULL == record) {
			fprintf(stderr, "could not update shadow memory\n");
			goto done;
		}

		vmi_pause_vm(loop->vmi);

		ret = vmi_read_pa(loop->vmi,
		                  record->frame << GT_PAGE_OFFSET_BITS,
		                 &cache,
		                  GT_PAGE_SIZE);
		if (GT_PAGE_SIZE != ret) {
			fprintf(stderr, "failed to read in syscall page\n");
			vmi_resume_vm(loop->vmi);
			goto done;
		}

		g_hash_table_foreach(record->children, &gt_rewrite_interrupts, &cache);

		ret = vmi_write_pa(loop->vmi,
		                   record->shadow_frame << GT_PAGE_OFFSET_BITS,
		                  &cache,
		                   GT_PAGE_SIZE);
		if (GT_PAGE_SIZE != ret) {
			fprintf(stderr, "failed to write to shadow page\n");
			vmi_resume_vm(loop->vmi);
			goto done;
		}

		vmi_resume_vm(loop->vmi);
	} 

done:
	loop->mem_watch[event->vcpu_id] = 0;

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
		loop->mem_watch[vcpu] = 0;

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
	gt_syscall_state *sys_state;

	sys_state = state_stacks_tid_dequeue(state->loop->state_stacks, thread_id);
	g_free(sys_state);
}


/**
 * gt_guest_hijack_return:
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
gt_guest_hijack_return(GtGuestState *state, reg_t retval)
{
	state->hijack = true;
	state->hijack_return = retval;

	return TRUE;
}

gboolean
gt_guest_drop_return_breakpoint(GtGuestState *state, gt_tid_t thread_id)
{
	state->skip_return = TRUE;

	return TRUE;
}

static event_response_t
gt_original_slat_singlestep(vmi_event_t *event)
{
	/* Set VCPUs SLAT to use original for one step. */
	event->slat_id = 0;

	/* Turn on single-step and switch slat_id after return. */
	return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP
             | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
}

/*
 * Service a triggered breakpoint.
 *
 * In the case of a system call, invoke the syscall callback and replace the
 * return address on the stack with the address of an interrupt instruction
 * which serves as the sysret breakpoint. Switch to the original page (no
 * breakpoint) for one instruction to execute the original (non-interrupt)
 * instruction.
 *
 * In the case of a system return, set the RIP to the original return address
 * after invoking the sysret callback.
 */
static event_response_t
gt_breakpoint_cb(vmi_instance_t vmi, vmi_event_t *event) {
	GtGuestState sys_state;
	event_response_t response = VMI_EVENT_RESPONSE_NONE;

	GtLoop *loop = event->data;
	event->interrupt_event.reinject = 0;

	if (!loop->os_functions->is_user_call(loop, event)) {
		response = gt_original_slat_singlestep(event);
		goto done;
	}

	if (event->interrupt_event.gla != loop->trampoline_addr) {
		/* Type-one breakpoint (system call). */
		status_t status;
		addr_t thread_id, return_loc, return_addr = 0;
		gt_paddr_record *record;
		gt_syscall_state *state;

		/* Set VCPUs SLAT to use original for one step. */
		response = gt_original_slat_singlestep(event);

		/* Lookup record corresponding to breakpoint address. */
		record = gt_paddr_record_from_va(loop,
		                                 event->interrupt_event.gla);
		if (NULL == record) {
			/* Assume we didn't emplace interrupt. */
			fprintf(stderr, "missing record; "
			                "assuming not from VisorFlow\n");
			event->interrupt_event.reinject = 1;
			goto done;
		}

		return_loc = event->x86_regs->rsp;

		gt_pid_t pid = loop->os_functions->get_pid(loop, event);
		if (0 == pid) {
			fprintf(stderr, "failed to read process ID (syscall)\n");
			goto done;
		}

		thread_id  = loop->os_functions->get_tid(loop, event);
		if (0 == thread_id) {
			fprintf(stderr, "failed to read thread ID (syscall)\n");
			goto done;
		}

		status = vmi_read_64_va(vmi, return_loc, 0, &return_addr);
		if (VMI_SUCCESS != status) {
			fprintf(stderr, "count not read return pointer off stack\n");
			goto done;
		}

		state                       = g_new0(gt_syscall_state, 1);
		state->syscall_paddr_record = record;
		state->return_loc           = return_loc;
		state->return_addr          = return_addr;

		if (GT_EMERGENCY == setjmp(loop->jmpbuf[event->vcpu_id])) {
			/*
			 * Jump here on SIGSEGV to avoid re-running
			 * faulty instruction in callback. See
			 * gt_loop_jmp_past_cb().
			 */
			goto skip_syscall_cb;
		}

		/* Invoke system-call callback in record. */
		in_syscall_cb = TRUE;
		loop->count++;
		sys_state = (GtGuestState) { loop, vmi, event, FALSE, FALSE, 0 };
		state->data = record->syscall_cb(&sys_state,
		                                  pid,
		                                  thread_id,
		                                  record->data);
		in_syscall_cb = FALSE;

skip_syscall_cb:
		memset(loop->jmpbuf[event->vcpu_id], 0x00, sizeof loop->jmpbuf[event->vcpu_id]);

		if (sys_state.hijack) {
			/*
			 * Application called gt_guest_hijack_return().
			 */
			g_assert(NULL == state->data);

			vmi_set_vcpureg(vmi, sys_state.hijack_return, RAX, event->vcpu_id);
			vmi_set_vcpureg(vmi, state->return_addr, RIP, event->vcpu_id);

			/*
			 * Revert to avoid changing SLAT and setting singlestep.
			 * We are hijacking RIP, so no need to remove breakpoint
			 * for one step.
			 */
			response = VMI_EVENT_RESPONSE_NONE;

			g_free(state);
		} else if (FALSE == sys_state.skip_return
		        && NULL != record->sysret_cb) {
			/* Normal code path. */

			/* Record system-call state. */
			state_stacks_tid_push(loop->state_stacks, thread_id, state);

			/* Overwrite stack to return to trampoline. */
			vmi_write_64_va(vmi, return_loc, 0, &loop->trampoline_addr);
		} else {
			/*
			 * Sysret callback not registered or application called
			 * gt_guest_drop_return_breakpoint().
			 */
			g_assert(NULL == state->data);
			g_free(state);
		}
	} else {
		/* Type-two breakpoint (system return). */
		gt_syscall_state *state;
		addr_t thread_id = loop->os_functions->get_tid(loop, event);
		if (0 == thread_id) {
			fprintf(stderr, "failed to read thread ID (sysret)\n");
			goto done;
		}

		gt_pid_t pid = loop->os_functions->get_pid(loop, event);
		if (0 == pid) {
			fprintf(stderr, "failed to read process ID (sysret)\n");
			goto done;
		}

		state = state_stacks_tid_pop(loop->state_stacks, thread_id);
		if (NULL == state) {
			fprintf(stderr, "no state for sysret %d:%ld\n", pid, thread_id);
			goto done;
		}

		if (GT_EMERGENCY == setjmp(loop->jmpbuf[event->vcpu_id])) {
			/*
			 * Jump here on SIGSEGV to avoid re-running
			 * faulty instruction in callback. See
			 * gt_loop_jmp_past_cb().
			 */
			goto skip_sysret_cb;
		}

		sys_state = (GtGuestState) { loop, vmi, event, FALSE, FALSE, 0 };
		state->syscall_paddr_record->sysret_cb(&sys_state,
						        pid,
						        thread_id,
						        state->data);

skip_sysret_cb:
		memset(loop->jmpbuf[event->vcpu_id], 0x00, sizeof loop->jmpbuf[event->vcpu_id]);

		/* Set RIP to the original return location. */
		event->x86_regs->rip = state->return_addr;
		response = VMI_EVENT_RESPONSE_SET_REGISTERS;

		/*
		 * This will free our gt_syscall_state object, but
		 * sysret_cb must have freed state->data.
		 */
		g_free(state);
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
	GtLoop *loop = event->data;
	event_response_t response = VMI_EVENT_RESPONSE_NONE;

	if (!g_hash_table_lookup(loop->gt_page_translation, GINT_TO_POINTER(event->mem_event.gfn))) {
		fprintf(stderr, "memory event on shadow frame\n");
		if (event->mem_event.out_access & VMI_MEMACCESS_W) {
			fprintf(stderr, "w: VCPU -> %d, SLAT -> %d, RIP -> 0x%lx, GLA -> 0x%lx, GFN -> 0x%lx\n", event->vcpu_id, event->slat_id, event->x86_regs->rip, event->mem_event.gla, event->mem_event.gfn);
		}
		if (event->mem_event.out_access & VMI_MEMACCESS_R) {
			fprintf(stderr, "r: VCPU -> %d, SLAT -> %d, RIP -> 0x%lx, GLA -> 0x%lx, GFN -> 0x%lx\n", event->vcpu_id, event->slat_id, event->x86_regs->rip, event->mem_event.gla, event->mem_event.gfn);
		}
		if (event->mem_event.out_access & VMI_MEMACCESS_X) {
			fprintf(stderr, "x: VCPU -> %d, SLAT -> %d, RIP -> 0x%lx, GLA -> 0x%lx, GFN -> 0x%lx\n", event->vcpu_id, event->slat_id, event->x86_regs->rip, event->mem_event.gla, event->mem_event.gfn);
		}
		goto done;
	}
	
	if (event->mem_event.out_access & VMI_MEMACCESS_W) {
		/* tell our step event we need to copy new data to shadow frame */
		loop->mem_watch[event->vcpu_id] = event->mem_event.gfn;
	}

	event->slat_id = 0;

	response = VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP
	         | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;

done:
	return response;
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
	gboolean ok;
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
	loop->state_stacks = state_stacks_new(gt_restore_return_addr);

	vmi_pause_vm(loop->vmi);

	loop->os = vmi_get_ostype(loop->vmi);
	switch (loop->os) {
	case VMI_OS_LINUX:
		loop->os_functions = &os_functions_linux;
		break;
	case VMI_OS_WINDOWS:
		loop->os_functions = &os_functions_windows;
		vmi_init_paging(loop->vmi, (1u << 0));
		break;
	default:
		fprintf(stderr, "unknown guest operating system\n");
		status = VMI_FAILURE;
		goto done;
	}

	ok = loop->os_functions->initialize(loop);
	if (!ok) {
		fprintf(stderr, "error initializing for operating system\n");
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

	rc = xc_altp2m_set_domain_state(loop->xch, loop->domid, TRUE);
	if (0 != rc) {
		fprintf(stderr, "failed to enable slat on guest\n");
		goto done;
	}

	rc = xc_altp2m_create_view(loop->xch, loop->domid, 0, &loop->shadow_view);
	if (0 != rc) {
		fprintf(stderr, "failed to create slat\n");
		goto done;
	}

	if (!gt_set_up_generic_events(loop)) {
		goto done;
	}

	if (!gt_set_up_step_events(loop)) {
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
	default:
		g_assert_not_reached();
	}

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
	return state->loop->os_functions->get_process_name(state->vmi, pid);
}

static gboolean
gt_handle_vmi_event(GIOChannel *chan, GIOCondition condition, gpointer user_data)
{
	status_t status;
	GtLoop *loop = user_data;

	switch (condition) {
	case G_IO_IN:
		status = vmi_events_listen(loop->vmi, 0);
		if (status != VMI_SUCCESS) {
			fprintf(stderr, "error waiting for events\n");
			loop->running = FALSE;
		}
		break;
	case G_IO_ERR:
		fprintf(stderr, "error reading fd\n");
		break;
	case G_IO_HUP:
		fprintf(stderr, "fd hungup\n");
		break;
	case G_IO_NVAL:
		fprintf(stderr, "fd not valid\n");
		break;
	default:
		fprintf(stderr, "unknown error reading fd\n");
		break;
	}

	if (!loop->running) {
		g_main_loop_quit(loop->g_main_loop);
	}

	return loop->running;
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
	loop->running = FALSE;
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

	if (NULL == loop->vmi) {
		goto done;
	}

	vmi_pause_vm(loop->vmi);

	g_hash_table_destroy(loop->gt_page_translation);
	state_stacks_destroy(loop->state_stacks);
	g_hash_table_destroy(loop->gt_page_record_collection);

	if (0 != loop->shadow_view) {
		xc_altp2m_switch_to_view(loop->xch, loop->domid, 0);
		xc_altp2m_destroy_view(loop->xch, loop->domid, loop->shadow_view);
		xc_altp2m_set_domain_state(loop->xch, loop->domid, FALSE);
	}

	if (NULL != loop->ctx) {
		libxl_ctx_free(loop->ctx);
	}

	if (NULL != loop->xch) {
		xc_domain_setmaxmem(loop->xch, loop->domid, loop->init_mem_size);
		xc_interface_close(loop->xch);
	}

	vmi_resume_vm(loop->vmi);

	vmi_destroy(loop->vmi);

	if (NULL != loop->g_main_loop) {
		g_main_loop_unref(loop->g_main_loop);
	}

done:
	g_free(loop);

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

	lstar = GT_PAGE_ADDR(lstar);

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
	int curr_inst;
	for (curr_inst = 0; curr_inst < GT_PAGE_SIZE; curr_inst++) {
		if (code[curr_inst] == GT_BREAKPOINT_INST) {
			trampoline_addr = lstar + curr_inst;
			break;
		}
	}

done:
	return trampoline_addr;
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
	int vmi_fd;

	status = early_boot_wait_for_os_load(loop);
	if (VMI_SUCCESS != status) {
                fprintf(stderr, "failed to wait on LSTAR.\n");
                goto done;
        }

	status = loop->os_functions->wait_for_first_process(loop);
	if (VMI_SUCCESS != status) {
                fprintf(stderr, "failed to wait for initialization\n");
                goto done;
        }

	vmi_pause_vm(loop->vmi);

	loop->trampoline_addr = gt_find_trampoline_addr(loop);
	if (0 == loop->trampoline_addr) {
		fprintf(stderr, "could not find addr. of existing int 3 inst.\n");
		goto done;
	}

	int rc = xc_altp2m_switch_to_view(loop->xch, loop->domid, loop->shadow_view);
	if (0 != rc) {
		fprintf(stderr, "failed to switch to shadow view\n");
		goto done;
	}

	vmi_fd = vmi_event_get_fd(loop->vmi);
	loop->channel_vmi = g_io_channel_unix_new(vmi_fd);
	gt_loop_add_watch(loop->channel_vmi,
	                  G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
	                  gt_handle_vmi_event,
	                  loop);

	vmi_resume_vm(loop->vmi);

	loop->running = TRUE;
	g_main_loop_run(loop->g_main_loop);

	vmi_pause_vm(loop->vmi);

	/*
	 * loop->running affects freeing of state_stacks elements.
	 * Must be false or return pointers on kernel stack will not be reset.
	 * Thus we check no code has been altered in an ill way here, since
	 * this requirement is not obvious.
	 */
	g_assert(!loop->running);

	g_hash_table_remove_all(loop->gt_page_translation);
	state_stacks_remove_all(loop->state_stacks);
	g_hash_table_remove_all(loop->gt_page_record_collection);

	vmi_resume_vm(loop->vmi);

done:
	return;
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
                   const char *name,
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
		int xc_status = xc_altp2m_change_gfn(loop->xch,
		                                     loop->domid,
		                                     loop->shadow_view,
		                                     frame,
		                                     shadow);
		if (0 != xc_status) {
			fprintf(stderr, "failed to update shadow view\n");
			goto done;
		}

		/* Activate in shadow view. */
		xc_status = xc_altp2m_change_gfn(loop->xch,
		                                     loop->domid,
		                                     loop->shadow_view,
		                                     shadow,
		                                     0);
		if (0 != xc_status) {
			fprintf(stderr, "failed to zeroed shadow view\n");
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
		status = vmi_set_mem_event(loop->vmi,
		                           frame,
		                           VMI_MEMACCESS_RW,
		                           loop->shadow_view);
		if (VMI_SUCCESS != status) {
			fprintf(stderr, "couldn't set frame permissions for 0x%lx\n", frame);
			goto done;
		}

		status = vmi_set_mem_event(loop->vmi,
		                           shadow,
		                           VMI_MEMACCESS_RW,
		                           loop->shadow_view);
		if (VMI_SUCCESS != status) {
			fprintf(stderr, "couldn't set shadow permissions for 0x%lx\n", frame);
			goto done;
		}
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
	paddr_record->name       = name;
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
 * system call, or NULL if the system call never returns.
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

	syscall_trap = gt_setup_mem_trap(loop, sysaddr, kernel_func, syscall_cb, sysret_cb, user_data);
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
 * gt_loop_get_syscall_count:
 * @loop: a #GtLoop.
 *
 * Returns: the number of system calls observed.
 **/
unsigned long
gt_loop_get_syscall_count(GtLoop *loop)
{
	return loop->count;
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

/**
 * gt_loop_jmp_past_cb:
 * @loop: a pointer to a #GtLoop.
 *
 * Skip over the syscall/sysret handler, usually to gracefully exit after
 * SIGSEGV.
 */
void
gt_loop_jmp_past_cb(GtLoop *loop)
{
	jmp_buf zero = { 0 };
	int vcpus;

	vcpus = vmi_get_num_vcpus(loop->vmi);
	if (0 == vcpus) {
		fprintf(stderr, "failed to get number of VCPUs\n");
		goto done;
	}

	for (int i = 0; i < vcpus; i++) {
		if (memcmp(zero, loop->jmpbuf[i], sizeof loop->jmpbuf[i])) {
			longjmp(loop->jmpbuf[i], GT_EMERGENCY);
		}
	}

done:
	return;
}

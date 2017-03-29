#include <libvmi/libvmi.h>

#include "guestrace.h"
#include "guestrace-private.h"
#include "rekall.h"
#include "trace-syscalls.h"

typedef enum privilege_mode {
	KERNEL_MODE,
	USER_MODE,
	MAXIMUM_MODE,
} privilege_mode_t;

static privilege_mode_t
_gt_windows_get_privilege_mode(vmi_instance_t vmi, vmi_event_t *event, gboolean do_flush)
{
	uint8_t previous_mode = KERNEL_MODE;
	GtLoop *loop = event->data;
	status_t status;
	addr_t thread;
	const char *rekall_profile;
	static addr_t prcb;
	static addr_t currentthread;
	static addr_t previousmode;
	static gboolean initialized = FALSE;

	/*
	 * Testing indicated pidcache flush was necessary to get vaddr
	 * translations to consistently work in a GtSyscallFunc. DRAKVUF
	 * flushes all of the caches on a CR3 change, so we do too.
	 */
	if (do_flush) {
		vmi_pidcache_flush(vmi);
		vmi_v2pcache_flush(vmi, event->reg_event.previous);
		vmi_rvacache_flush(vmi);
	}

	if (!initialized) {
		rekall_profile = vmi_get_rekall_path(loop->vmi);
		if (NULL == rekall_profile) {
			goto done;
		}

		status = rekall_profile_symbol_to_rva(rekall_profile, "_KPCR", "Prcb", &prcb);
		if (VMI_SUCCESS != status) {
			goto done;
		}

		status = rekall_profile_symbol_to_rva(rekall_profile, "_KPRCB", "CurrentThread", &currentthread);
		if (VMI_SUCCESS != status) {
			goto done;
			}

		status = rekall_profile_symbol_to_rva(rekall_profile, "_KTHREAD", "PreviousMode", &previousmode);
		if (VMI_SUCCESS != status) {
			goto done;
		}

		initialized = TRUE;
	}

	status = vmi_read_addr_va(loop->vmi, event->x86_regs->gs_base + prcb + currentthread, 0, &thread);
	if (VMI_SUCCESS != status) {
		goto done;
	}

	status = vmi_read_8_va(loop->vmi, thread + previousmode, 0, &previous_mode);
	if (VMI_SUCCESS != status) {
		goto done;
	}

done:
	return previous_mode;
}

static event_response_t
_gt_windows_cr3_cb(vmi_instance_t vmi, vmi_event_t *event)
{
	GtLoop *loop = event->data;
	uint8_t previous_mode = _gt_windows_get_privilege_mode(vmi, event, TRUE);

	if (USER_MODE == previous_mode) {
		loop->initialized = TRUE;
		vmi_clear_event(loop->vmi, event, NULL);
	}

	return VMI_EVENT_RESPONSE_NONE;
}

/* Wait for first user-space process; see above. */
static status_t
_gt_windows_wait_for_first_process(GtLoop *loop)
{
	status_t status = VMI_FAILURE;

	SETUP_REG_EVENT(&loop->cr3_event, CR3, VMI_REGACCESS_W, 0, _gt_windows_cr3_cb);

	loop->cr3_event.data = loop;

	status = vmi_register_event(loop->vmi, &loop->cr3_event);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "cr3 event setup failed\n");
		goto done;
	}

	while (!loop->initialized) {
		status_t status = vmi_events_listen(loop->vmi, 100);
		if (status != VMI_SUCCESS) {
			fprintf(stderr, "error waiting for events\n");
			goto done;
		}
	}

	status = VMI_SUCCESS;

done:
	return status;
}

/*
 * Within the kernel's system-call handler function (that function pointed to
 * by the value in register LSTAR) there exists a call instruction which
 * invokes the per-system-call handler function. The function here finds
 * the address immediately following the call instruction. This is
 * necessary to later differentiate per-system-call handler functions which
 * are returning directly to the kernel's system-call handler function from
 * those that have been called in a nested manner.
 */
static addr_t
_gt_windows_find_return_point_addr(GtLoop *loop)
{
	addr_t lstar, return_point_addr = 0;

	status_t ret = vmi_get_vcpureg(loop->vmi, &lstar, MSR_LSTAR, 0);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "failed to get MSR_LSTAR address\n");
		goto done;
	}

	return_point_addr = _gt_find_addr_after_instruction(loop,
	                                                   lstar,
	                                                  "call",
	                                                  "r10");

done:
	return return_point_addr;
}

static gt_pid_t
_windows_get_pid(GtLoop *loop, vmi_event_t *event)
{
	status_t status;
	size_t count;
	addr_t self;
	access_context_t ctx;
	gt_pid_t pid = 0;
	reg_t gs = event->x86_regs->gs_base;
	const char *rekall_profile;
	static addr_t nttib;
	static addr_t clientid;
	static gboolean initialized = FALSE;

	if (!initialized) {
		rekall_profile = vmi_get_rekall_path(loop->vmi);
		if (NULL == rekall_profile) {
			goto done;
		}

		/* _NT_TIB64 is first field of _KPCR at GS register. */
		status = rekall_profile_symbol_to_rva(rekall_profile, "_NT_TIB64", "Self", &nttib);
		if (VMI_SUCCESS != status) {
			goto done;
		}

		status = rekall_profile_symbol_to_rva(rekall_profile, "_TEB", "ClientId", &clientid);
		if (VMI_SUCCESS != status) {
			goto done;
			}

		initialized = TRUE;
	}

	status = vmi_read_addr_va(loop->vmi, gs + nttib, 0, &self);
	if (VMI_SUCCESS != status) {
		pid = 0;
		goto done;
	}

	ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
	ctx.dtb = event->x86_regs->cr3;
	ctx.addr = self + clientid;
	count = vmi_read(loop->vmi, &ctx, &pid, sizeof pid);
	if (sizeof pid != count) {
		pid = 0;
		goto done;
	}

done:
	return pid;
}

static gt_tid_t
_windows_get_tid(GtLoop *loop, vmi_event_t *event)
{
	status_t status;
	size_t count;
	addr_t self;
	access_context_t ctx;
	gt_tid_t tid = 0;
	reg_t gs = event->x86_regs->gs_base;
	const char *rekall_profile;
	static addr_t nttib;
	static addr_t clientid;
	static gboolean initialized = FALSE;

	if (!initialized) {
		rekall_profile = vmi_get_rekall_path(loop->vmi);
		if (NULL == rekall_profile) {
			goto done;
		}

		/* _NT_TIB64 is first field of _KPCR at GS register. */
		status = rekall_profile_symbol_to_rva(rekall_profile, "_NT_TIB64", "Self", &nttib);
		if (VMI_SUCCESS != status) {
			goto done;
		}

		status = rekall_profile_symbol_to_rva(rekall_profile, "_TEB", "ClientId", &clientid);
		if (VMI_SUCCESS != status) {
			goto done;
			}

		initialized = TRUE;
	}

	status = vmi_read_addr_va(loop->vmi, gs + nttib, 0, &self);
	if (VMI_SUCCESS != status) {
		tid = 0;
		goto done;
	}

	ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
	ctx.dtb = event->x86_regs->cr3;
	ctx.addr = self + clientid + vmi_get_address_width(loop->vmi);
	count = vmi_read(loop->vmi, &ctx, &tid, sizeof tid);
	if (sizeof tid != count) {
		tid = 0;
		goto done;
	}

done:
	return tid;
}

/* Gets the process name of the process with the PID that is input. */
static char *
_gt_windows_get_process_name(vmi_instance_t vmi, gt_pid_t pid)
{
	/* Gets the process name of the process with the input pid */
	/* offsets from the LibVMI config file */
	unsigned long task_offset = vmi_get_offset(vmi, "win_tasks");
	unsigned long pid_offset = vmi_get_offset(vmi, "win_pid");
	unsigned long name_offset = vmi_get_offset(vmi, "win_pname");

	/* addresses for the linux process list and current process */
	addr_t list_head = 0;
	addr_t list_curr = 0;
	addr_t curr_proc = 0;

	gt_pid_t curr_pid = 0;		/* pid of the processes task struct we are examining */
	char *proc = NULL;		/* process name of the current process we are examining */

	if(VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &list_head)) {
		printf("Failed to find PsActiveProcessHead\\n");
		goto done;
	}

	list_curr = list_head;							/* set the current process to the head */

	do{
		curr_proc = list_curr - task_offset;						/* subtract the task offset to get to the start of the task_struct */
		if (VMI_FAILURE == vmi_read_32_va(vmi, curr_proc + pid_offset, 0, (uint32_t*)&curr_pid)) {		/* read the current pid using the pid offset from the start of the task struct */
			printf("Failed to get the pid of the process we are examining!\\n");
			goto done;
		}

		if (pid == curr_pid) {
			proc = vmi_read_str_va(vmi, curr_proc + name_offset, 0);		/* get the process name if the current pid is equal to the pis we are looking for */
			goto done;								/* go to done to exit */
		}

		if (VMI_FAILURE == vmi_read_addr_va(vmi, list_curr, 0, &list_curr)) {				/* read the memory from the address of list_curr which will return a pointer to the */
			printf("Failed to get the next task in the process list!\\n");
			goto done;
		}

	} while (list_curr != list_head);							/* next task_struct. Continue the loop until we get back to the beginning as the  */
/* process list is doubly linked and circular */

done:
	return proc;

}

static gboolean
_gt_windows_is_user_call(GtLoop *loop, vmi_event_t *event)
{
	gboolean ok;
	uint8_t previous_mode = _gt_windows_get_privilege_mode(loop->vmi, event, FALSE);

	if (USER_MODE == previous_mode) {
		ok = TRUE;
	} else {
		ok = FALSE;
	}

	return ok;
}

struct os_functions os_functions_windows = {
	.wait_for_first_process = _gt_windows_wait_for_first_process,
	.find_return_point_addr = _gt_windows_find_return_point_addr,
	.get_pid = _windows_get_pid,
	.get_tid = _windows_get_tid,
	.get_process_name = _gt_windows_get_process_name,
	.is_user_call = _gt_windows_is_user_call,
};

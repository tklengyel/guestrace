#include <libvmi/libvmi.h>

#include "guestrace.h"
#include "guestrace-private.h"
#include "trace-syscalls.h"

/*
 * Within the kernel's system-call handler function (that function pointed to
 * by the value in register LSTAR) there exists a call instruction which
 * invokes the per-system-call handler function. The function here finds
 * the address immediately following the call instruction. This is
 * necessary to later differentiate per-system-call handler functions which
 * are returning directly to the kernel's system-call handler function from
 * those that have been called in a nested manner.
 */
addr_t
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

struct os_functions os_functions_windows = {
	.find_return_point_addr = _gt_windows_find_return_point_addr
};

/* Gets the process name of the process with the PID that is input. */
char *
gt_windows_get_process_name(vmi_instance_t vmi, gt_pid_t pid)
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

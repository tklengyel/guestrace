#include <libvmi/libvmi.h>

#include "gt.h"
#include "gt-private.h"
#include "gt-rekall.h"
#include "gt-rekall-private.h"

typedef struct offset_definition_t {
	int   id;
	char *struct_name;
	char *field_name;
} offset_definition_t;

static offset_definition_t _offset_def[] = {
	{ GT_OFFSET_LINUX_CURRENT_TASK,     "current_task",  NULL },
	{ GT_OFFSET_LINUX_TASK_STRUCT_TGID, "task_struct",  "tgid" },
	{ GT_OFFSET_LINUX_TASK_STRUCT_PID,  "task_struct",  "pid" },
	{ GT_OFFSET_LINUX_TASK_STRUCT_COMM,  "task_struct",  "comm" },
	{ GT_OFFSET_LINUX_TASK_STRUCT_REAL_PARENT,  "task_struct",  "real_parent" },
	{ GT_OFFSET_LINUX_TASK_STRUCT_MM,  "task_struct",  "mm" },
	{ GT_OFFSET_LINUX_BAD, NULL, NULL }
};

static addr_t   _offset[GT_OFFSET_LINUX_BAD];
static gboolean _initialized = FALSE;

static gboolean
_initialize(GtLoop *loop)
{
	const char *rekall_profile;
	gboolean ok;

	g_assert(!_initialized);

	rekall_profile = vmi_get_rekall_path(loop->vmi);
	if (NULL == rekall_profile) {
		goto done;
	}

	for (int i = 0; i < GT_OFFSET_LINUX_BAD; i++) {
		ok = gt_rekall_private_symbol_to_rva(rekall_profile,
		                                    _offset_def[i].struct_name,
		                                    _offset_def[i].field_name,
		                                   &_offset[i]);
		if (!ok) {
			goto done;
		}
	}

	_initialized = TRUE;

done:
	return _initialized;
}

/*
 * The libvmi dispatcher invokes this function each time the guest writes to
 * CR3. We are interested in recognizing when the first user-space process
 * runs. In the case of Linux, the bootloader loads the kernel, but then the
 * kernel then decompresses itself. Breakpoints set too early will be
 * overwritten by this process. Thus we watch for the value in CR3 to change.
 *
 * Windows seems to be easier. Its bootloader, NTLDR, does all of the real-
 * mode work and even transitions the processor into protected (long?) mode.
 * We still want to wait for a user-space process there because Windows seems
 * to make system calls from the kernel when booting, and this confuses
 * vmi_dtb_to_pid() until a user-space process exists.
 */
static event_response_t
_detect_process_cb(vmi_instance_t vmi, vmi_event_t *event) {
        GtLoop *loop = event->data;
        static addr_t prev = 0;

	g_assert(_initialized);

        if (prev != 0 && prev != event->x86_regs->cr3) {
                loop->initialized = TRUE;
        }

        prev = event->x86_regs->cr3;

        return VMI_EVENT_RESPONSE_NONE;
}

static gt_pid_t
_get_pid(vmi_instance_t vmi, vmi_event_t *event)
{
	status_t status;
	addr_t current_task;
	uint32_t pid = 0;

	g_assert(_initialized);

	status = vmi_read_addr_va(vmi,
	                          event->x86_regs->gs_base
	                       + _offset[GT_OFFSET_LINUX_CURRENT_TASK],
	                          0,
	                         &current_task);
	if (VMI_SUCCESS != status) {
		goto done;
	}

	status = vmi_read_32_va(vmi,
	                        current_task
	                     + _offset[GT_OFFSET_LINUX_TASK_STRUCT_TGID],
	                        0,
	                       &pid);
	if (VMI_SUCCESS != status) {
		pid = 0;
		goto done;
	}

done:
	return pid;
}

static gt_tid_t
_get_tid(vmi_instance_t vmi, vmi_event_t *event)
{
	status_t status;
	addr_t current_task;
	uint32_t tid = 0;

	status = vmi_read_addr_va(vmi,
	                          event->x86_regs->gs_base
	                       + _offset[GT_OFFSET_LINUX_CURRENT_TASK],
	                          0,
	                         &current_task);
	if (VMI_SUCCESS != status) {
		goto done;
	}

	status = vmi_read_32_va(vmi,
	                        current_task
	                     + _offset[GT_OFFSET_LINUX_TASK_STRUCT_PID],
	                        0,
	                       &tid);
	if (VMI_SUCCESS != status) {
		tid = 0;
		goto done;
	}

done:
	return (gt_tid_t) tid;
}

static char *
_get_process_name(vmi_instance_t vmi, vmi_event_t *event)
{
	status_t status;
	addr_t current_task;
	char *comm = NULL;

	g_assert(_initialized);

	status = vmi_read_addr_va(vmi,
	                          event->x86_regs->gs_base
	                       + _offset[GT_OFFSET_LINUX_CURRENT_TASK],
	                          0,
	                         &current_task);
	if (VMI_SUCCESS != status) {
		goto done;
	}

	comm = vmi_read_str_va(vmi,
	                       current_task
	                    + _offset[GT_OFFSET_LINUX_TASK_STRUCT_COMM],
	                       0);
	if (VMI_SUCCESS != status) {
		goto done;
	}

done:
	return comm;
}

static gt_pid_t
_get_parent_pid(vmi_instance_t vmi, gt_pid_t pid, gboolean *is_userspace)
{
	status_t status;
	addr_t list_head = 0, list_curr = 0, current_task = 0, parent_task = 0, mm = 0;
	gt_pid_t curr_pid = 0, parent_pid = 0;
	unsigned long task_offset = vmi_get_offset(vmi, "linux_tasks");
	unsigned long pid_offset  = vmi_get_offset(vmi, "linux_pid");

	g_assert(_initialized);

	list_head = vmi_translate_ksym2v(vmi, "init_task") + task_offset;
	if (list_head == task_offset) {
		fprintf(stderr, "failed to read address for init_task\n");
		goto done;
	}

	list_curr = list_head;
	do {
		current_task = list_curr - task_offset;
		if (VMI_FAILURE == vmi_read_32_va(vmi,
		                                  current_task + pid_offset,
		                                  0,
		                                 (uint32_t *) &curr_pid)) {
			fprintf(stderr,"failed to get the pid of the process we are examining\n");
			goto done;
		}

		if (pid == curr_pid) {
			break;
		}

		if (VMI_FAILURE == vmi_read_addr_va(vmi, list_curr, 0, &list_curr)) {
			fprintf(stderr, "failed to get the next task in the process list\n");
			goto done;
		}

	} while (list_curr != list_head);

	if (list_curr == list_head) {
		fprintf(stderr, "failed to find %d\n", pid);
		goto done;
	}

	status = vmi_read_addr_va(vmi,
	                          current_task
	                       + _offset[GT_OFFSET_LINUX_TASK_STRUCT_REAL_PARENT],
	                          0,
	                         &parent_task);
	if (VMI_SUCCESS != status) {
		goto done;
	}

	status = vmi_read_32_va(vmi,
	                        parent_task
	                     + _offset[GT_OFFSET_LINUX_TASK_STRUCT_TGID],
	                        0,
	          (uint32_t *) &parent_pid);
	if (VMI_SUCCESS != status) {
		parent_pid = 0;
		goto done;
	}

	if (NULL != is_userspace) {
		status = vmi_read_addr_va(vmi,
					  parent_task
		                       + _offset[GT_OFFSET_LINUX_TASK_STRUCT_MM],
					  0,
					 &mm);
		if (VMI_SUCCESS != status) {
			parent_pid = 0;
			goto done;
		}

		*is_userspace = mm != 0;
	}

done:
	return parent_pid;
}

static gboolean
_is_user_call(GtLoop *loop, vmi_event_t *event)
{
	g_assert(_initialized);

	return TRUE;
}

static addr_t
_get_offset(int offset_id)
{
	return offset_id > GT_OFFSET_WINDOWS_BAD ? 0 : _offset[offset_id];
}

struct os_functions functions_linux = {
	.initialize = _initialize,
	.detect_process_cb = _detect_process_cb,
	.get_pid = _get_pid,
	.get_tid = _get_tid,
	.get_process_name = _get_process_name,
	.get_parent_pid = _get_parent_pid,
	.is_user_call = _is_user_call,
	.get_offset = _get_offset,
};

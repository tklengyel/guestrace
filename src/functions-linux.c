#include <libvmi/libvmi.h>

#include "guestrace.h"
#include "guestrace-private.h"
#include "rekall.h"
#include "rekall-private.h"
#include "trace-syscalls.h"

typedef struct offset_definition_t {
	int   id;
	char *struct_name;
	char *field_name;
} offset_definition_t;

static offset_definition_t offset_def[] = {
	{ GT_OFFSET_LINUX_CURRENT_TASK,     "current_task",  NULL },
	{ GT_OFFSET_LINUX_TASK_STRUCT_TGID, "task_struct",  "tgid" },
	{ GT_OFFSET_LINUX_TASK_STRUCT_PID,  "task_struct",  "pid" },
	{ GT_OFFSET_LINUX_TASK_STRUCT_COMM,  "task_struct",  "comm" },
	{ GT_OFFSET_LINUX_BAD, NULL, NULL }
};

static addr_t   offset[GT_OFFSET_LINUX_BAD];
static gboolean initialized = FALSE;

static gboolean
_gt_linux_initialize(GtLoop *loop)
{
	const char *rekall_profile;
	gboolean ok;

	g_assert(!initialized);

	rekall_profile = vmi_get_rekall_path(loop->vmi);
	if (NULL == rekall_profile) {
		goto done;
	}

	for (int i = 0; i < GT_OFFSET_LINUX_BAD; i++) {
		ok = gt_rekall_symbol_to_rva(rekall_profile,
		                             offset_def[i].struct_name,
		                             offset_def[i].field_name,
		                            &offset[i]);
		if (!ok) {
			goto done;
		}
	}

	initialized = TRUE;

done:
	return initialized;
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
_gt_linux_cr3_cb(vmi_instance_t vmi, vmi_event_t *event) {
        GtLoop *loop = event->data;
        static addr_t prev = 0;

	g_assert(initialized);

        if (prev != 0 && prev != event->x86_regs->cr3) {
                loop->initialized = TRUE;
        }

        prev = event->x86_regs->cr3;

        return VMI_EVENT_RESPONSE_NONE;
}

/* Wait for first user-space process; see above. */
static status_t
_gt_linux_wait_for_first_process(GtLoop *loop)
{
	status_t status = VMI_FAILURE;

	g_assert(initialized);

	SETUP_REG_EVENT(&loop->cr3_event, CR3, VMI_REGACCESS_W, 0, _gt_linux_cr3_cb);
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

	vmi_clear_event(loop->vmi, &loop->cr3_event, NULL);
	status = VMI_SUCCESS;

done:
	return status;
}

static gt_pid_t
_linux_get_pid(GtLoop *loop, vmi_event_t *event)
{
	status_t status;
	addr_t current_task;
	uint32_t pid = 0;

	g_assert(initialized);

	status = vmi_read_addr_va(loop->vmi,
	                          event->x86_regs->gs_base
	                        + offset[GT_OFFSET_LINUX_CURRENT_TASK],
	                          0,
	                         &current_task);
	if (VMI_SUCCESS != status) {
		goto done;
	}

	status = vmi_read_32_va(loop->vmi,
	                        current_task
	                      + offset[GT_OFFSET_LINUX_TASK_STRUCT_TGID],
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
_linux_get_tid(GtLoop *loop, vmi_event_t *event)
{
	status_t status;
	addr_t current_task;
	uint32_t tid = 0;

	status = vmi_read_addr_va(loop->vmi,
	                          event->x86_regs->gs_base
	                        + offset[GT_OFFSET_LINUX_CURRENT_TASK],
	                          0,
	                         &current_task);
	if (VMI_SUCCESS != status) {
		goto done;
	}

	status = vmi_read_32_va(loop->vmi,
	                        current_task
	                      + offset[GT_OFFSET_LINUX_TASK_STRUCT_PID],
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
_gt_linux_get_process_name(vmi_instance_t vmi, vmi_event_t *event)
{
	status_t status;
	addr_t current_task;
	char *comm = NULL;

	g_assert(initialized);

	status = vmi_read_addr_va(vmi,
	                          event->x86_regs->gs_base
	                        + offset[GT_OFFSET_LINUX_CURRENT_TASK],
	                          0,
	                         &current_task);
	if (VMI_SUCCESS != status) {
		goto done;
	}

	comm = vmi_read_str_va(vmi,
	                       current_task
	                     + offset[GT_OFFSET_LINUX_TASK_STRUCT_COMM],
	                       0);
	if (VMI_SUCCESS != status) {
		goto done;
	}

done:
	return comm;
}

static gboolean
_gt_linux_is_user_call(GtLoop *loop, vmi_event_t *event)
{
	g_assert(initialized);

	return TRUE;
}

static addr_t
_gt_linux_get_offset(int offset_id)
{
	return offset_id > GT_OFFSET_WINDOWS_BAD ? 0 : offset[offset_id];
}

struct os_functions os_functions_linux = {
	.initialize = _gt_linux_initialize,
	.wait_for_first_process = _gt_linux_wait_for_first_process,
	.get_pid = _linux_get_pid,
	.get_tid = _linux_get_tid,
	.get_process_name = _gt_linux_get_process_name,
	.is_user_call = _gt_linux_is_user_call,
	.get_offset = _gt_linux_get_offset,
};

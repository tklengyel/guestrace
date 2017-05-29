#include <libvmi/libvmi.h>

#include "guestrace.h"
#include "guestrace-private.h"
#include "rekall.h"
#include "rekall-private.h"
#include "trace-syscalls.h"

typedef enum privilege_mode {
	KERNEL_MODE,
	USER_MODE,
	MAXIMUM_MODE,
} privilege_mode_t;

typedef struct offset_definition_t {
	int   id;
	char *struct_name;
	char *field_name;
} offset_definition_t;

static offset_definition_t offset_def[] = {
	{ GT_OFFSET_WINDOWS_KPCR_PRCB,                                 "_KPCR", "Prcb" },
	{ GT_OFFSET_WINDOWS_KPRCB_CURRENTTHREAD,                       "_KPRCB",  "CurrentThread" },
	{ GT_OFFSET_WINDOWS_KTHREAD_PREVIOUSMODE,                      "_KTHREAD",  "PreviousMode" },
	{ GT_OFFSET_WINDOWS_KTHREAD_PROCESS,                           "_KTHREAD",  "Process" },
	{ GT_OFFSET_WINDOWS_NT_TIB64_SELF,                             "_NT_TIB64",  "Self" },
	{ GT_OFFSET_WINDOWS_TEB_CLIENTID,                              "_TEB",  "ClientId" },
	{ GT_OFFSET_WINDOWS_EPROCESS_UNIQUEPROCESSID,                  "_EPROCESS", "UniqueProcessId" },
	{ GT_OFFSET_WINDOWS_EPROCESS_PNAME,                            "_EPROCESS", "ImageFileName" },
	{ GT_OFFSET_WINDOWS_TEB_PROCESSENVIRONMENTBLOCK,               "_TEB", "ProcessEnvironmentBlock" },
	{ GT_OFFSET_WINDOWS_PEB_PROCESSPARAMETERS,                     "_PEB", "ProcessParameters" },
	{ GT_OFFSET_WINDOWS_RTL_USER_PROCESS_PARAMETERS_IMAGEPATHNAME, "_RTL_USER_PROCESS_PARAMETERS", "ImagePathName" },
	{ GT_OFFSET_WINDOWS_UNICODE_STRING_BUFFER,                     "_UNICODE_STRING", "Buffer" },
	{ GT_OFFSET_WINDOWS_ETHREAD_CID,                               "_ETHREAD", "Cid" },
	{ GT_OFFSET_WINDOWS_CLIENT_ID_UNIQUETHREAD,                    "_CLIENT_ID", "UniqueThread" },
	{ GT_OFFSET_WINDOWS_BAD, NULL, NULL }
};

static addr_t   offset[GT_OFFSET_WINDOWS_BAD];
static gboolean initialized = FALSE;

static gboolean
_gt_windows_initialize(GtLoop *loop)
{
	const char *rekall_profile;
	gboolean ok;

	g_assert(!initialized);

	rekall_profile = vmi_get_rekall_path(loop->vmi);
	if (NULL == rekall_profile) {
		goto done;
	}

	for (int i = 0; i < GT_OFFSET_WINDOWS_BAD; i++) {
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

static privilege_mode_t
_gt_windows_get_privilege_mode(vmi_instance_t vmi, vmi_event_t *event, gboolean do_flush)
{
	uint8_t previous_mode = KERNEL_MODE;
	GtLoop *loop = event->data;
	status_t status;
	addr_t thread;

	g_assert(initialized);

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

	status = vmi_read_addr_va(loop->vmi,
	                          event->x86_regs->gs_base
	                        + offset[GT_OFFSET_WINDOWS_KPCR_PRCB]
	                        + offset[GT_OFFSET_WINDOWS_KPRCB_CURRENTTHREAD],
	                          0,
	                         &thread);
	if (VMI_SUCCESS != status) {
		goto done;
	}

	status = vmi_read_8_va(loop->vmi,
	                       thread + offset[GT_OFFSET_WINDOWS_KTHREAD_PREVIOUSMODE],
	                       0,
	                      &previous_mode);
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
	uint8_t previous_mode;

	g_assert(initialized);

	previous_mode = _gt_windows_get_privilege_mode(vmi, event, TRUE);
	if (USER_MODE == previous_mode) {
		loop->initialized = TRUE;
	}

	return VMI_EVENT_RESPONSE_NONE;
}

/* Wait for first user-space process; see above. */
static status_t
_gt_windows_wait_for_first_process(GtLoop *loop)
{
	status_t status = VMI_FAILURE;

	g_assert(initialized);

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

	vmi_clear_event(loop->vmi, &loop->cr3_event, NULL);
	status = VMI_SUCCESS;

done:
	return status;
}

static gt_pid_t
_windows_get_pid(vmi_instance_t vmi, vmi_event_t *event)
{
	status_t status;
	addr_t thread, process;
	gt_pid_t pid = 0;

	g_assert(initialized);

	status = vmi_read_addr_va(vmi,
	                          event->x86_regs->gs_base
	                        + offset[GT_OFFSET_WINDOWS_KPCR_PRCB]
	                        + offset[GT_OFFSET_WINDOWS_KPRCB_CURRENTTHREAD],
	                          0,
	                         &thread);
	if (VMI_SUCCESS != status) {
		goto done;
	}

	status = vmi_read_addr_va(vmi,
	                          thread
	                        + offset[GT_OFFSET_WINDOWS_KTHREAD_PROCESS],
	                          0,
	                         &process);
	if (VMI_SUCCESS != status) {
		goto done;
	}

	status = vmi_read_32_va(vmi,
	                        process
	                      + offset[GT_OFFSET_WINDOWS_EPROCESS_UNIQUEPROCESSID],
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
_windows_get_tid(vmi_instance_t vmi, vmi_event_t *event)
{
	status_t status;
	addr_t thread;
	gt_tid_t tid = 0;

	g_assert(initialized);

	status = vmi_read_addr_va(vmi,
	                          event->x86_regs->gs_base
	                        + offset[GT_OFFSET_WINDOWS_KPCR_PRCB]
	                        + offset[GT_OFFSET_WINDOWS_KPRCB_CURRENTTHREAD],
	                          0,
	                         &thread);
	if (VMI_SUCCESS != status) {
		goto done;
	}

	status = vmi_read_addr_va(vmi,
	                        thread
	                      + offset[GT_OFFSET_WINDOWS_ETHREAD_CID]
	                      + offset[GT_OFFSET_WINDOWS_CLIENT_ID_UNIQUETHREAD],
	                        0,
	                       &tid);
	if (VMI_SUCCESS != status) {
		tid = 0;
		goto done;
	}

done:
	return tid;
}

/* Gets the process name of the process with the PID that is input. */
static char *
_gt_windows_get_process_name(vmi_instance_t vmi, vmi_event_t *event)
{
	status_t status;
	addr_t thread, process;
	char *proc = NULL;

	g_assert(initialized);

	status = vmi_read_addr_va(vmi,
	                          event->x86_regs->gs_base
	                        + offset[GT_OFFSET_WINDOWS_KPCR_PRCB]
	                        + offset[GT_OFFSET_WINDOWS_KPRCB_CURRENTTHREAD],
	                          0,
	                         &thread);
	if (VMI_SUCCESS != status) {
		goto done;
	}

	status = vmi_read_addr_va(vmi,
	                          thread
	                        + offset[GT_OFFSET_WINDOWS_KTHREAD_PROCESS],
	                          0,
	                         &process);
	if (VMI_SUCCESS != status) {
		goto done;
	}

	proc = vmi_read_str_va(vmi,
	                       process
	                     + offset[GT_OFFSET_WINDOWS_EPROCESS_PNAME],
	                       0);
	if (NULL == proc) {
		goto done;
	}

done:
	return proc;

}

static gt_pid_t
_gt_linux_get_parent_pid(vmi_instance_t vmi, gt_pid_t pid)
{
	g_assert_not_reached();
}

static gboolean
_gt_windows_is_user_call(GtLoop *loop, vmi_event_t *event)
{
	gboolean ok;
	uint8_t previous_mode;

	g_assert(initialized);

	previous_mode = _gt_windows_get_privilege_mode(loop->vmi, event, FALSE);
	if (USER_MODE == previous_mode) {
		ok = TRUE;
	} else {
		ok = FALSE;
	}

	return ok;
}

static addr_t
_gt_windows_get_offset(int offset_id)
{
	return offset_id > GT_OFFSET_WINDOWS_BAD ? 0 : offset[offset_id];
}

struct os_functions os_functions_windows = {
	.initialize = _gt_windows_initialize,
	.wait_for_first_process = _gt_windows_wait_for_first_process,
	.get_pid = _windows_get_pid,
	.get_tid = _windows_get_tid,
	.get_process_name = _gt_windows_get_process_name,
	.get_parent_pid = _gt_windows_get_parent_pid,
	.is_user_call = _gt_windows_is_user_call,
	.get_offset = _gt_windows_get_offset,
};

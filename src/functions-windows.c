#define XC_WANT_COMPAT_EVTCHN_API

#include <libvmi/libvmi.h>

#include "gt.h"
#include "gt-private.h"
#include "gt-rekall.h"
#include "gt-rekall-private.h"

typedef enum privilege_mode {
	KERNEL_MODE = 0,
	USER_MODE,
	MAXIMUM_MODE,
} privilege_mode_t;

/*
 * References:
 * http://www.geoffchappell.com/studies/windows/win32/ntdll/
 * Windows Internals, Part 1 by Russinovich and Solomon
 */
static offset_definition_t _offset_def[] = {
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

static addr_t   _offset[GT_OFFSET_WINDOWS_BAD];
static gboolean _initialized = FALSE;

static gboolean
_initialize(GtLoop *loop)
{
	g_assert(!_initialized);

	_initialized = gt_rekall_private_initialize(loop,
	                                           _offset,
	                                           _offset_def,
	                                            GT_OFFSET_WINDOWS_BAD);

	return _initialized;
}

static addr_t
_get_current_thread(vmi_instance_t vmi, vmi_event_t *event)
{
	status_t status;
	addr_t thread = 0;

	g_assert(_initialized);

	status = vmi_read_addr_va(vmi,
	                          event->x86_regs->gs_base
	                       + _offset[GT_OFFSET_WINDOWS_KPCR_PRCB]
	                       + _offset[GT_OFFSET_WINDOWS_KPRCB_CURRENTTHREAD],
	                          0,
	                         &thread);
	if (VMI_SUCCESS != status) {
		thread = 0;
		goto done;
	}

done:
	return thread;
}

static addr_t
_get_current_process(vmi_instance_t vmi, vmi_event_t *event)
{
	status_t status;
	addr_t thread, process = 0;

	g_assert(_initialized);

	thread = _get_current_thread(vmi, event);
	if (0 == thread) {
		goto done;
	}

	status = vmi_read_addr_va(vmi,
	                          thread
	                       + _offset[GT_OFFSET_WINDOWS_KTHREAD_PROCESS],
	                          0,
	                         &process);
	if (VMI_SUCCESS != status) {
		goto done;
	}

done:
	return process;
}

static privilege_mode_t
_get_privilege_mode(vmi_instance_t vmi, vmi_event_t *event, gboolean do_flush)
{
	uint8_t previous_mode = KERNEL_MODE;
	GtLoop *loop = event->data;
	status_t status;
	addr_t thread;

	g_assert(_initialized);

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

	thread = _get_current_thread(vmi, event);
	if (0 == thread) {
		goto done;
	}

	status = vmi_read_8_va(loop->vmi,
	                       thread + _offset[GT_OFFSET_WINDOWS_KTHREAD_PREVIOUSMODE],
	                       0,
	                      &previous_mode);
	if (VMI_SUCCESS != status) {
		goto done;
	}

done:
	return previous_mode;
}

static event_response_t
_detect_process_cb(vmi_instance_t vmi, vmi_event_t *event)
{
	GtLoop *loop = event->data;
	uint8_t previous_mode;

	g_assert(_initialized);

	previous_mode = _get_privilege_mode(vmi, event, TRUE);
	if (USER_MODE == previous_mode) {
		loop->initialized = TRUE;
	}

	return VMI_EVENT_RESPONSE_NONE;
}

static gt_pid_t
_get_pid(vmi_instance_t vmi, vmi_event_t *event)
{
	status_t status;
	addr_t process;
	gt_pid_t pid = 0;

	g_assert(_initialized);

	process = _get_current_process(vmi, event);
	if (0 == process) {
		goto done;
	}

	status = vmi_read_32_va(vmi,
	                        process
	                     + _offset[GT_OFFSET_WINDOWS_EPROCESS_UNIQUEPROCESSID],
	                        0,
	          (uint32_t *) &pid);
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
	addr_t thread;
	gt_tid_t tid = 0;

	g_assert(_initialized);

	thread = _get_current_thread(vmi, event);
	if (0 == thread) {
		goto done;
	}

	status = vmi_read_addr_va(vmi,
	                        thread
	                     + _offset[GT_OFFSET_WINDOWS_ETHREAD_CID]
	                     + _offset[GT_OFFSET_WINDOWS_CLIENT_ID_UNIQUETHREAD],
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
_get_process_name(vmi_instance_t vmi, vmi_event_t *event)
{
	addr_t process;
	char *proc = NULL;

	g_assert(_initialized);

	process = _get_current_process(vmi, event);
	if (0 == process) {
		goto done;
	}

	proc = vmi_read_str_va(vmi,
	                       process
	                    + _offset[GT_OFFSET_WINDOWS_EPROCESS_PNAME],
	                       0);
	if (NULL == proc) {
		goto done;
	}

done:
	return proc;

}

static gt_pid_t
_get_parent_pid(vmi_instance_t vmi, gt_pid_t pid, gboolean *is_userspace)
{
	g_assert_not_reached();
}

static gboolean
_is_user_call(GtLoop *loop, vmi_event_t *event)
{
	gboolean ok;
	uint8_t previous_mode;

	g_assert(_initialized);

	previous_mode = _get_privilege_mode(loop->vmi, event, FALSE);
	if (USER_MODE == previous_mode) {
		ok = TRUE;
	} else {
		ok = FALSE;
	}

	return ok;
}

static addr_t
_get_offset(int offset_id)
{
	return offset_id > GT_OFFSET_WINDOWS_BAD ? 0 : _offset[offset_id];
}

struct os_functions functions_windows = {
	.initialize = _initialize,
	.detect_process_cb = _detect_process_cb,
	.get_pid = _get_pid,
	.get_tid = _get_tid,
	.get_process_name = _get_process_name,
	.get_parent_pid = _get_parent_pid,
	.is_user_call = _is_user_call,
	.get_offset = _get_offset,
};

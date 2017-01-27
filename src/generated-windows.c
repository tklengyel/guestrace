#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <guestrace.h>

static const int RETURN_ADDR_WIDTH = sizeof(void *);

struct win64_obj_attr {
	uint32_t length; // sizeof given struct
	uint64_t root_directory; // if not null, object_name is relative to this directory
	uint64_t object_name; // pointer to unicode string
	uint32_t attributes; // see microsoft documentation
	uint64_t security_descriptor; // see microsoft documentation
	uint64_t security_quality_of_service; // see microsoft documentation
};

struct win64_client_id {
	uint64_t unique_process; /* process id */
	uint64_t unique_thread; /* thread id */
};

/*
 * Get ObjectAttributes struct from virtual address
 */
static struct win64_obj_attr *
obj_attr_from_va(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid) {
	struct win64_obj_attr * buff = NULL;

	uint32_t struct_size = 0;

	if (VMI_SUCCESS != vmi_read_32_va(vmi, vaddr, pid, &struct_size)) {
		goto done;
	}

	struct_size = struct_size <= sizeof(struct win64_obj_attr) ? struct_size : sizeof(struct win64_obj_attr); // don't wanna read too much data

	buff = calloc(1, sizeof(struct win64_obj_attr));

	if (struct_size != vmi_read_va(vmi, vaddr, pid, buff, struct_size)) {
		free(buff);
		buff = NULL;
		goto done;
	}

done:
	return buff;
}

static uint8_t *
filename_from_arg(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid) {
	struct win64_obj_attr * obj_attr = obj_attr_from_va(vmi, vaddr, pid);

	uint8_t * res = NULL;

	if (obj_attr == NULL) {
		goto done;
	}

	unicode_string_t * filename = vmi_read_unicode_str_va(vmi, obj_attr->object_name, pid);

	if (filename == NULL) {
		free(obj_attr);
		goto done;
	}

	unicode_string_t nfilename;
	if (VMI_SUCCESS != vmi_convert_str_encoding(filename, &nfilename, "UTF-8")) {
		free(obj_attr);
		vmi_free_unicode_str(filename);
		goto done;
	}

	res = nfilename.contents; /* points to malloc'd memory */
	free(obj_attr);
	vmi_free_unicode_str(filename);

done:
	return res;
}

/* Gets the process name of the process with the PID that is input. */
static char *
get_process_name(vmi_instance_t vmi, vmi_pid_t pid) 
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
	
	vmi_pid_t curr_pid = 0;		/* pid of the processes task struct we are examining */
	char *proc = NULL;		/* process name of the current process we are examining */

    if(VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &list_head)) {
        printf("Failed to find PsActiveProcessHead\n");
        goto done;
    }

	list_curr = list_head;							/* set the current process to the head */

	do{
		curr_proc = list_curr - task_offset;						/* subtract the task offset to get to the start of the task_struct */
		if (VMI_FAILURE == vmi_read_32_va(vmi, curr_proc + pid_offset, 0, (uint32_t*)&curr_pid)) {		/* read the current pid using the pid offset from the start of the task struct */
			printf("Failed to get the pid of the process we are examining!\n");
			goto done;
		}
	
		if (pid == curr_pid) {
			proc = vmi_read_str_va(vmi, curr_proc + name_offset, 0);		/* get the process name if the current pid is equal to the pis we are looking for */
			goto done;								/* go to done to exit */
		}
	
		if (VMI_FAILURE == vmi_read_addr_va(vmi, list_curr, 0, &list_curr)) {				/* read the memory from the address of list_curr which will return a pointer to the */
			printf("Failed to get the next task in the process list!\n");
			goto done;
		}

	} while (list_curr != list_head);							/* next task_struct. Continue the loop until we get back to the beginning as the  */
												/* process list is doubly linked and circular */

done:	
	return proc;

}

static void
vf_windows_print_syscall_openfile_cb(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
	char *proc_name = get_process_name(vmi, pid);
	uint8_t * filename = filename_from_arg(vmi, event->x86_regs->r8, pid);

	uint64_t handle = 0;
	vmi_read_64_va(vmi, event->x86_regs->rcx, pid, &handle);

	fprintf(stderr, "pid: %d (%s) thread: 0x%lx syscall: %s(%s)\n", pid, proc_name, event->x86_regs->rsp, "NtOpenFile", filename);
	

	/* TODO: presently omitted: handle, sysnum. */
}

static void
vf_windows_print_syscall_opensymboliclinkobject_cb(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
	char *proc_name = get_process_name(vmi, pid);
	uint8_t * filename = filename_from_arg(vmi, event->x86_regs->r8, pid);

	uint64_t handle = 0;
	vmi_read_64_va(vmi, event->x86_regs->rcx, pid, &handle);

	fprintf(stderr, "pid: %d (%s) thread: 0x%lx syscall: %s(%s)\n", pid, proc_name, event->x86_regs->rsp, "NtOpenSymbolicLinkObject", filename);
	

	/* TODO: presently omitted: handle, sysnum. */
}

static void
vf_windows_print_syscall_createfile_cb(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
	char *proc_name = get_process_name(vmi, pid);
	uint8_t * filename = filename_from_arg(vmi, event->x86_regs->r8, pid);

	uint64_t handle = 0;
	vmi_read_64_va(vmi, event->x86_regs->rcx, pid, &handle);

	fprintf(stderr, "pid: %d (%s) thread: 0x%lx syscall: %s(%s)\n", pid, proc_name, event->x86_regs->rsp, "NtCreateFile", filename);
	

	/* TODO: presently omitted: handle, sysnum. */
}

static void
vf_windows_print_syscall_opendirectoryobject_cb(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
	char *proc_name = get_process_name(vmi, pid);
	uint8_t * filename = filename_from_arg(vmi, event->x86_regs->r8, pid);

	uint64_t handle = 0;
	vmi_read_64_va(vmi, event->x86_regs->rcx, pid, &handle);

	fprintf(stderr, "pid: %d (%s) thread: 0x%lx syscall: %s(%s)\n", pid, proc_name, event->x86_regs->rsp, "NtOpenDirectoryObject", filename);
	

	/* TODO: presently omitted: handle, sysnum. */
}

static void
vf_windows_print_syscall_openprocess_cb(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
	char *proc_name = get_process_name(vmi, pid);
	struct win64_client_id client_id = {0};
	vmi_read_va(vmi, event->x86_regs->r9, pid, &client_id, sizeof(struct win64_client_id));

	uint64_t handle = 0;
	vmi_read_64_va(vmi, event->x86_regs->rcx, pid, &handle);

	fprintf(stderr, "pid: %d (%s) thread: 0x%lx syscall: %s(0x%lx)\n", pid, proc_name, event->x86_regs->rsp, "NtOpenProcess", client_id.unique_process);
	

	/* TODO: presently omitted: handle, sysnum. */
}

static void
vf_windows_print_syscall_readfile_cb(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
	char *proc_name = get_process_name(vmi, pid);
	fprintf(stderr, "pid: %d (%s) thread: 0x%lx syscall: %s(0x%lx)\n", pid, proc_name, event->x86_regs->rsp, "NtReadFile", event->x86_regs->rcx);
	

	/* TODO: presently omitted: handle, sysnum. */
}

static void
vf_windows_print_syscall_writefile_cb(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
	char *proc_name = get_process_name(vmi, pid);
	fprintf(stderr, "pid: %d (%s) thread: 0x%lx syscall: %s(0x%lx)\n", pid, proc_name, event->x86_regs->rsp, "NtWriteFile", event->x86_regs->rcx);
	

	/* TODO: presently omitted: handle, sysnum. */
}

static void
vf_windows_print_syscall_generic_cb(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
	/* No-Op. for now. */
}

static void
vf_windows_print_sysret_generic_cb(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
	if (0 == pid) { /* it can't find the PID sometimes... */
		return;
	}

	char *proc_name = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %d (%s) thread: 0x%lx return: 0x%lx\n", pid, proc_name, event->x86_regs->rsp - RETURN_ADDR_WIDTH, event->x86_regs->rax);
}

/* See Windows's KeServiceDescriptorTable. */
static const struct syscall_defs SYSCALLS[] = {
	{ "NtMapUserPhysicalPagesScatter", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtWaitForSingleObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCallbackReturn", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtReadFile", vf_windows_print_syscall_readfile_cb, vf_windows_print_sysret_generic_cb },
	{ "NtDeviceIoControlFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtWriteFile", vf_windows_print_syscall_writefile_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRemoveIoCompletion", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtReleaseSemaphore", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtReplyWaitReceivePort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtReplyPort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetInformationThread", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetEvent", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtClose", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryInformationFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtEnumerateValueKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtFindAtom", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryDefaultLocale", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryValueKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAllocateVirtualMemory", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryInformationProcess", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtWaitForMultipleObjects32", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtWriteFileGather", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetInformationProcess", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtFreeVirtualMemory", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtImpersonateClientOfPort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtReleaseMutant", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryInformationToken", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRequestWaitReplyPort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryVirtualMemory", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenThreadToken", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryInformationThread", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenProcess", vf_windows_print_syscall_openprocess_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetInformationFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtMapViewOfSection", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAccessCheckAndAuditAlarm", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtUnmapViewOfSection", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtReplyWaitReceivePortEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtTerminateProcess", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetEventBoostPriority", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtReadFileScatter", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenThreadTokenEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenProcessTokenEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryPerformanceCounter", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtEnumerateKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenFile", vf_windows_print_syscall_openfile_cb, vf_windows_print_sysret_generic_cb },
	{ "NtDelayExecution", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryDirectoryFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQuerySystemInformation", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenSection", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryTimer", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtFsControlFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtWriteVirtualMemory", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCloseObjectAuditAlarm", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtDuplicateObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryAttributesFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtClearEvent", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtReadVirtualMemory", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenEvent", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAdjustPrivilegesToken", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtDuplicateToken", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtContinue", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryDefaultUILanguage", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueueApcThread", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtYieldExecution", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAddAtom", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateEvent", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryVolumeInformationFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateSection", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtFlushBuffersFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtApphelpCacheControl", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateProcessEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateThread", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtIsProcessInJob", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtProtectVirtualMemory", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQuerySection", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtResumeThread", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtTerminateThread", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtReadRequestData", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateFile", vf_windows_print_syscall_createfile_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryEvent", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtWriteRequestData", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenDirectoryObject", vf_windows_print_syscall_opendirectoryobject_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAccessCheckByTypeAndAuditAlarm", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQuerySystemTime", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtWaitForMultipleObjects", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetInformationObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCancelIoFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtTraceEvent", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtPowerInformation", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetValueKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCancelTimer", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetTimer", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAcceptConnectPort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAccessCheck", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAccessCheckByType", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAccessCheckByTypeResultList", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAccessCheckByTypeResultListAndAuditAlarm", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAccessCheckByTypeResultListAndAuditAlarmByHandle", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAddBootEntry", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAddDriverEntry", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAdjustGroupsToken", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlertResumeThread", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlertThread", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAllocateLocallyUniqueId", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAllocateReserveObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAllocateUserPhysicalPages", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAllocateUuids", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcAcceptConnectPort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcCancelMessage", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcConnectPort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcCreatePort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcCreatePortSection", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcCreateResourceReserve", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcCreateSectionView", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcCreateSecurityContext", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcDeletePortSection", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcDeleteResourceReserve", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcDeleteSectionView", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcDeleteSecurityContext", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcDisconnectPort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcImpersonateClientOfPort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcOpenSenderProcess", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcOpenSenderThread", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcQueryInformation", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcQueryInformationMessage", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcRevokeSecurityContext", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcSendWaitReceivePort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAlpcSetInformation", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAreMappedFilesTheSame", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtAssignProcessToJobObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCancelIoFileEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCancelSynchronousIoFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCommitComplete", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCommitEnlistment", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCommitTransaction", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCompactKeys", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCompareTokens", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCompleteConnectPort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCompressKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtConnectPort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateDebugObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateDirectoryObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateEnlistment", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateEventPair", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateIoCompletion", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateJobObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateJobSet", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateKeyTransacted", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateKeyedEvent", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateMailslotFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateMutant", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateNamedPipeFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreatePagingFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreatePort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreatePrivateNamespace", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateProcess", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateProfile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateProfileEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateResourceManager", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateSemaphore", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateSymbolicLinkObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateThreadEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateTimer", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateToken", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateTransaction", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateTransactionManager", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateUserProcess", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateWaitablePort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtCreateWorkerFactory", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtDebugActiveProcess", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtDebugContinue", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtDeleteAtom", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtDeleteBootEntry", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtDeleteDriverEntry", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtDeleteFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtDeleteKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtDeleteObjectAuditAlarm", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtDeletePrivateNamespace", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtDeleteValueKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtDisableLastKnownGood", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtDisplayString", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtDrawText", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtEnableLastKnownGood", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtEnumerateBootEntries", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtEnumerateDriverEntries", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtEnumerateSystemEnvironmentValuesEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtEnumerateTransactionObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtExtendSection", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtFilterToken", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtFlushInstallUILanguage", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtFlushInstructionCache", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtFlushKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtFlushProcessWriteBuffers", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtFlushVirtualMemory", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtFlushWriteBuffer", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtFreeUserPhysicalPages", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtFreezeRegistry", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtFreezeTransactions", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtGetContextThread", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtGetCurrentProcessorNumber", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtGetDevicePowerState", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtGetMUIRegistryInfo", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtGetNextProcess", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtGetNextThread", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtGetNlsSectionPtr", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtGetNotificationResourceManager", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtGetPlugPlayEvent", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtGetWriteWatch", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtImpersonateAnonymousToken", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtImpersonateThread", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtInitializeNlsFiles", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtInitializeRegistry", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtInitiatePowerAction", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtIsSystemResumeAutomatic", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtIsUILanguageComitted", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtListenPort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtLoadDriver", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtLoadKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtLoadKey2", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtLoadKeyEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtLockFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtLockProductActivationKeys", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtLockRegistryKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtLockVirtualMemory", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtMakePermanentObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtMakeTemporaryObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtMapCMFModule", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtMapUserPhysicalPages", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtModifyBootEntry", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtModifyDriverEntry", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtNotifyChangeDirectoryFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtNotifyChangeKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtNotifyChangeMultipleKeys", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtNotifyChangeSession", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenEnlistment", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenEventPair", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenIoCompletion", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenJobObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenKeyEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenKeyTransacted", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenKeyTransactedEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenKeyedEvent", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenMutant", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenObjectAuditAlarm", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenPrivateNamespace", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenProcessToken", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenResourceManager", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenSemaphore", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenSession", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenSymbolicLinkObject", vf_windows_print_syscall_opensymboliclinkobject_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenThread", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenTimer", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenTransaction", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtOpenTransactionManager", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtPlugPlayControl", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtPrePrepareComplete", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtPrePrepareEnlistment", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtPrepareComplete", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtPrepareEnlistment", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtPrivilegeCheck", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtPrivilegeObjectAuditAlarm", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtPrivilegedServiceAuditAlarm", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtPropagationComplete", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtPropagationFailed", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtPulseEvent", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryBootEntryOrder", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryBootOptions", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryDebugFilterState", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryDirectoryObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryDriverEntryOrder", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryEaFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryFullAttributesFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryInformationAtom", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryInformationEnlistment", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryInformationJobObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryInformationPort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryInformationResourceManager", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryInformationTransaction", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryInformationTransactionManager", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryInformationWorkerFactory", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryInstallUILanguage", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryIntervalProfile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryIoCompletion", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryLicenseValue", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryMultipleValueKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryMutant", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryOpenSubKeys", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryOpenSubKeysEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryPortInformationProcess", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryQuotaInformationFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQuerySecurityAttributesToken", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQuerySecurityObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQuerySemaphore", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQuerySymbolicLinkObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQuerySystemEnvironmentValue", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQuerySystemEnvironmentValueEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQuerySystemInformationEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueryTimerResolution", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtQueueApcThreadEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRaiseException", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRaiseHardError", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtReadOnlyEnlistment", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRecoverEnlistment", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRecoverResourceManager", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRecoverTransactionManager", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRegisterProtocolAddressInformation", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRegisterThreadTerminatePort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtReleaseKeyedEvent", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtReleaseWorkerFactoryWorker", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRemoveIoCompletionEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRemoveProcessDebug", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRenameKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRenameTransactionManager", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtReplaceKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtReplacePartitionUnit", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtReplyWaitReplyPort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRequestPort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtResetEvent", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtResetWriteWatch", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRestoreKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtResumeProcess", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRollbackComplete", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRollbackEnlistment", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRollbackTransaction", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtRollforwardTransactionManager", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSaveKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSaveKeyEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSaveMergedKeys", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSecureConnectPort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSerializeBoot", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetBootEntryOrder", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetBootOptions", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetContextThread", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetDebugFilterState", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetDefaultHardErrorPort", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetDefaultLocale", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetDefaultUILanguage", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetDriverEntryOrder", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetEaFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetHighEventPair", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetHighWaitLowEventPair", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetInformationDebugObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetInformationEnlistment", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetInformationJobObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetInformationKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetInformationResourceManager", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetInformationToken", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetInformationTransaction", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetInformationTransactionManager", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetInformationWorkerFactory", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetIntervalProfile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetIoCompletion", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetIoCompletionEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetLdtEntries", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetLowEventPair", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetLowWaitHighEventPair", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetQuotaInformationFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetSecurityObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetSystemEnvironmentValue", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetSystemEnvironmentValueEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetSystemInformation", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetSystemPowerState", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetSystemTime", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetThreadExecutionState", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetTimerEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetTimerResolution", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetUuidSeed", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSetVolumeInformationFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtShutdownSystem", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtShutdownWorkerFactory", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSignalAndWaitForSingleObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSinglePhaseReject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtStartProfile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtStopProfile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSuspendProcess", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSuspendThread", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtSystemDebugControl", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtTerminateJobObject", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtTestAlert", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtThawRegistry", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtThawTransactions", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtTraceControl", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtTranslateFilePath", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtUmsThreadYield", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtUnloadDriver", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtUnloadKey", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtUnloadKey2", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtUnloadKeyEx", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtUnlockFile", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtUnlockVirtualMemory", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtVdmControl", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtWaitForDebugEvent", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtWaitForKeyedEvent", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtWaitForWorkViaWorkerFactory", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtWaitHighEventPair", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtWaitLowEventPair", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ "NtWorkerFactoryWorkerReady", vf_windows_print_syscall_generic_cb, vf_windows_print_sysret_generic_cb },
	{ NULL, NULL },
};

#define NUM_SYSCALL_ARGS 8

/*
 * Tries to return a UTF-8 string representing the filename of an ObjectAttribute
 * vaddr must point to an ObjectAttribute virtual address
 * Must free what it returns
 */

/*
 * For each of the system calls libvmi is interested in, establish a memory trap
 * on the page containing the system call handler's first instruction. An
 * execute trap will cause guestrace to emplace a breakpoint. A read/write trap
 * (i.e., kernel patch protection) will cause guestrace to restore the original
 * instruction.
 */
bool
vf_windows_find_syscalls_and_setup_mem_traps(GTLoop *loop)
{
	static const char *TRACED_SYSCALLS[] = {
		"NtCreateFile",
		"NtOpenProcess",
		NULL
	};

	return vf_find_syscalls_and_setup_mem_traps(loop,
                                                    SYSCALLS,
                                                    TRACED_SYSCALLS);
}

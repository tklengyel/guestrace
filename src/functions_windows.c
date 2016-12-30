/* Generated on Linux_4.6.7-300.fc24.x86_64 on 30 Aug 2016o 16:18:03 */

#include <capstone/capstone.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <inttypes.h>
#include <stdio.h>

#include "functions_windows.h"
#include "syscall_enum.h"

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

typedef struct visor_proc {
	vmi_pid_t pid; /* current process pid */
	char * name; /* this will be removed automatically */
	uint16_t sysnum; /* 0xFFFF if not waiting on syscall to finish, otherwise sysnum */
	uint64_t * args; /* saved arguments to use between syscall start and finish. must be freed in ret */
	struct visor_proc * next; /* todo: don't use linked list */
} visor_proc;

#define NUM_SYSCALL_ARGS 8

/* todo: use glibc */
visor_proc * PROC_HEAD = NULL;

static visor_proc *
get_process_from_pid(vmi_pid_t pid) {
	visor_proc * curr = PROC_HEAD;

	while (NULL != curr) {
		if (curr->pid == pid) {
			break;
		}
		curr = curr->next;
	}

	return curr;
}

static void
delete_process(vmi_pid_t pid) {
	if (NULL == PROC_HEAD) {
		return;
	}

	if (PROC_HEAD->pid == pid) {
		visor_proc * saved = PROC_HEAD->next;
		free(PROC_HEAD->name);
		free(PROC_HEAD);
		PROC_HEAD = saved;
	} else {
		visor_proc * curr = PROC_HEAD;

		while (NULL != curr->next) {
			if (curr->next->pid == pid) {
				visor_proc * saved = curr->next->next;
				free(curr->next->name);
				free(curr->next);
				curr->next = saved;
				return;
			}
		}
	}
}

static visor_proc *
allocate_process(vmi_pid_t pid, char * name) {
	visor_proc * result = NULL;

	/* we never delete processes, only replace them if another is allocated with same PID */
	if (NULL != get_process_from_pid(pid)) {
		delete_process(pid);
	}

	result = calloc(1, sizeof(visor_proc));

	if (NULL == result) {
		goto done;
	}

	result->pid = pid;
	result->sysnum = 0xFFFF; /* not waiting on any syscall */
	result->name = name;

	/* let's append this to the current list */
	if (NULL == PROC_HEAD) {
		PROC_HEAD = result;
	} else {
		visor_proc * tail = PROC_HEAD;

		while (tail->next != NULL) {
			tail = tail->next;
		}

		tail->next = result;
	}

done:
	return result;
}

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

//const char * symbol_from_syscall_num(uint16_t sysnum) {
//	if (sysnum >> 12 == 0) { /* normal syscalls lead with 0 */
//		if (sysnum >= NUM_SYSCALLS || sysnum < 0 || NUM_TO_SYSCALL[sysnum] == NULL) {
//			return NULL;
//		} else {
//			return NUM_TO_SYSCALL[sysnum];
//		}
//	} else if (sysnum >> 12 == 1) { /* windows graphical syscalls lead with 1 */
//		return NULL; /* ignore graphical syscalls for performance */
//	} else {
//		return NULL;
//	}
//}

/*
 * Tries to return a UTF-8 string representing the filename of an ObjectAttribute
 * vaddr must point to an ObjectAttribute virtual address
 * Must free what it returns
 */

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


void 
print_syscall(vmi_instance_t vmi, vmi_event_t *event, uint16_t syscall_num) 
{
	vmi_pid_t pid = vmi_dtb_to_pid(vmi, event->x86_regs->cr3);

	if (0 == pid) { /* it can't find the PID sometimes... */
		return;
	}

	visor_proc * curr_proc = get_process_from_pid(pid);

	if (NULL == curr_proc) {
		char * proc_name = get_process_name(vmi, pid);

		//if (strcmp(proc_name, "cmd.exe") == 0) { /* let's only track cmd.exe for now */
			curr_proc = allocate_process(pid, proc_name);

			if (NULL == curr_proc) {
				free(proc_name);
			}
		//}
	}
	
	if (NULL == curr_proc) { /* we don't want to track this PID */
		return;
	}

	if (0xFFFF != curr_proc->sysnum) {
		fprintf(stderr, "Warning: system call didn't return before new system call.  Multi-threaded process?\n");
	}

	curr_proc->sysnum = syscall_num;
	
	time_t now = time(NULL);

	char * timestamp = ctime(&now); // y u have a newline
	timestamp[strlen(timestamp)-1] = 0;

	if (NULL != curr_proc->args) {
		free(curr_proc->args);
		curr_proc->args = NULL;
	}

	curr_proc->args = calloc(NUM_SYSCALL_ARGS, sizeof(uint64_t));
	curr_proc->args[0] = event->x86_regs->rcx;
	curr_proc->args[1] = event->x86_regs->rdx;
	curr_proc->args[2] = event->x86_regs->r8;
	curr_proc->args[3] = event->x86_regs->r9;

	/* todo figure out how to get rest of arguments */
	vmi_read_va(vmi, event->x86_regs->rsp, curr_proc->pid, &curr_proc->args[4], (NUM_SYSCALL_ARGS - 4) * sizeof(uint64_t));
}

void 
print_sysret(vmi_instance_t vmi, vmi_event_t *event) 
{
	vmi_pid_t pid = vmi_dtb_to_pid(vmi, event->x86_regs->cr3);

	if (0 == pid) { /* it can't find the PID sometimes... */
		return;
	}

	visor_proc * curr_proc = get_process_from_pid(pid);

	if (NULL == curr_proc) { /* not tracking this process */
		return;
	}

	if (0xFFFF == curr_proc->sysnum) {
		fprintf(stderr, "Error: system call returned without setting valid sysnum for PID %d\n", pid);
		return;
	}

	/* Print the pid, process name and return value of a system call */
	reg_t ret_status = event->x86_regs->rax;			/* get the return value out of rax */

	time_t now = time(NULL);

	char * timestamp = ctime(&now); // y u have a newline
	timestamp[strlen(timestamp)-1] = 0;

	//const char * syscall_symbol = symbol_from_syscall_num(curr_proc->sysnum);

	//if (syscall_symbol == NULL) {
	//	syscall_symbol = "Unknown Symbol";
	//}

	switch (curr_proc->sysnum) {

		case NTOPENFILE:
		{
			uint8_t * filename = filename_from_arg(vmi, curr_proc->args[2], curr_proc->pid);

			uint64_t handle = 0;
			vmi_read_64_va(vmi, curr_proc->args[0], curr_proc->pid, &handle);

			const char * syscall_symbol = "NtOpenFile";

			fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n\targuments:\t'%s'\n\treturn status:\t0x%lx\n\thandle value:\t0x%lx\n", timestamp, curr_proc->name, curr_proc->pid, syscall_symbol, curr_proc->sysnum, filename, ret_status, handle);

			break;
		} 

		case NTOPENSYMBOLICLINKOBJECT:
		{
			uint8_t * filename = filename_from_arg(vmi, curr_proc->args[2], curr_proc->pid);

			uint64_t handle = 0;
			vmi_read_64_va(vmi, curr_proc->args[0], curr_proc->pid, &handle);

			const char * syscall_symbol = "NtOpenSymbolicLinkObject";

			fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n\targuments:\t'%s'\n\treturn status:\t0x%lx\n\thandle value:\t0x%lx\n", timestamp, curr_proc->name, curr_proc->pid, syscall_symbol, curr_proc->sysnum, filename, ret_status, handle);

			break;
		}

		case NTCREATEFILE:
		{
			uint8_t * filename = filename_from_arg(vmi, curr_proc->args[2], curr_proc->pid);

			uint64_t handle = 0;
			vmi_read_64_va(vmi, curr_proc->args[0], curr_proc->pid, &handle);

			const char * syscall_symbol = "NtCreateFile";

			fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n\targuments:\t'%s'\n\treturn status:\t0x%lx\n\thandle value:\t0x%lx\n", timestamp, curr_proc->name, curr_proc->pid, syscall_symbol, curr_proc->sysnum, filename, ret_status, handle);

			break;
		}

		case NTOPENDIRECTORYOBJECT:
		{
			uint8_t * filename = filename_from_arg(vmi, curr_proc->args[2], curr_proc->pid);

			uint64_t handle = 0;
			vmi_read_64_va(vmi, curr_proc->args[0], curr_proc->pid, &handle);

			const char * syscall_symbol = "NtOpenDirectoryObject";

			fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n\targuments:\t'%s'\n\treturn status:\t0x%lx\n\thandle value:\t0x%lx\n", timestamp, curr_proc->name, curr_proc->pid, syscall_symbol, curr_proc->sysnum, filename, ret_status, handle);

			break;
		}

		/* opens a handle with given permissions to a process given a process id */
		case NTOPENPROCESS:
		{
			struct win64_client_id client_id = {0};
			vmi_read_va(vmi, curr_proc->args[3], curr_proc->pid, &client_id, sizeof(struct win64_client_id));

			uint64_t handle = 0;
			vmi_read_64_va(vmi, curr_proc->args[0], curr_proc->pid, &handle);

			const char * syscall_symbol = "NtOpenProcess";

			fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n\targuments:\t0x%lx\n\treturn status:\t0x%lx\n\thandle value:\t0x%lx\n", timestamp, curr_proc->name, curr_proc->pid, syscall_symbol, curr_proc->sysnum, client_id.unique_process, ret_status, handle);

			break;
		}

		case NTREADFILE:
		{
			const char * syscall_symbol = "NtReadFile";

			fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n\targuments:\t0x%lx\n\treturn status:\t0x%lx\n", timestamp, curr_proc->name, curr_proc->pid, syscall_symbol, curr_proc->sysnum, curr_proc->args[0], ret_status);

			break;
		}

		case NTWRITEFILE:
		{
			const char * syscall_symbol = "NtWriteFile";

			fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n\targuments:\t0x%lx\n\treturn status:\t0x%lx\n", timestamp, curr_proc->name, curr_proc->pid, syscall_symbol, curr_proc->sysnum, curr_proc->args[0], ret_status);

			break;
		}

		default:
		{
			//fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n\treturn status:\t0x%lx\n", timestamp, curr_proc->name, curr_proc->pid, syscall_symbol, curr_proc->sysnum, ret_status);
		}
	}

	curr_proc->sysnum = 0xFFFF; /* clean out the syscall */

	if (NULL != curr_proc->args) {
		free(curr_proc->args);
		curr_proc->args = NULL;
	}
}

#define countof(array) (sizeof(array) / sizeof((array)[0]))

/*
 * For each of the system calls libvmi is interested in, establish a memory trap
 * on the page containing the system call handler's first instruction. An
 * execute trap will cause guestrace to emplace a breakpoint. A read/write trap
 * (i.e., kernel patch protection) will cause guestrace to restore the original
 * instruction.
 */
bool
vf_find_syscalls_and_setup_mem_traps(vf_config *conf)
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

	static const char *TRACED_SYSCALLS[] = {
		"NtCreateFile",
		"NtOpenProcess"
	};

	for (int i = 0; i < countof(SYSCALLS); i++) {
		for (int j = 0; j < countof(TRACED_SYSCALLS); j++) {
			addr_t sysaddr;
			vf_paddr_record *syscall_trap;

			if (strcmp(SYSCALLS[i], TRACED_SYSCALLS[j])) {
				continue;
			}

			sysaddr = vmi_translate_ksym2v(conf->vmi,
			                               TRACED_SYSCALLS[j]);
			if (0 == sysaddr) {
				fprintf(stderr,
				       "could not find symbol %s\n",
				        TRACED_SYSCALLS[j]);
				goto done;
			}

			syscall_trap = vf_setup_mem_trap(conf, sysaddr);
			if (NULL == syscall_trap) {
				fprintf(stderr,
				       "failed to set memory trap on %s\n",
				        TRACED_SYSCALLS[j]);
				goto done;
			}

			/* Set identifier to contents of RAX during syscall. */
			syscall_trap->identifier = i;

			break;
		}
	}

	status = true;

done:
	return status;
}

/*
 * Disassemble the kernel and find the appropriate spot for a breakpoint
 * which will allow guestrace to determine a system call's return value. Return
 * the address of this spot.
 */
static addr_t
vf_get_syscall_ret_addr(vf_config *conf, addr_t syscall_start) {
	csh handle;
	cs_insn *inst;
	size_t count, call_offset = ~0;
	addr_t ret = 0;
	uint8_t code[4096]; /* Assume CALL is within first page. */

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

/*
 * Find the appropriate place for a breakpoint which will enable guestrace to
 * read a system call's return value, setup the breakpoint, and setup
 * a memory trap. Leave the breakpoint disabled; guestrace will enable it
 * upon an execution of the return-value page.
 */
bool
vf_set_up_sysret_handler(vf_config *conf)
{
	bool status = false;
	addr_t lstar = 0;

	/* LSTAR should be the constant across all VCPUs */
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

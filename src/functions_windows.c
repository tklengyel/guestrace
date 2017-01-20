/* Generated on Linux_4.6.7-300.fc24.x86_64 on 30 Aug 2016o 16:18:03 */

#include <capstone/capstone.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <inttypes.h>
#include <stdio.h>

#include "functions_windows.h"

struct os_functions os_functions_windows = {
        .print_syscall          = vf_windows_print_syscall,
        .print_sysret           = vf_windows_print_sysret,
        .find_syscalls_and_setup_mem_traps \
		                = vf_windows_find_syscalls_and_setup_mem_traps,
	.find_return_point_addr = vf_windows_find_return_point_addr,
	.find_trampoline_addr   = vf_windows_find_trampoline_addr
};

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

static void
vf_windows_print_sysret_openfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, char *proc_name, char *syscall_symbol)
{
	uint8_t * filename = filename_from_arg(vmi, event->x86_regs->r8, pid);

	uint64_t handle = 0;
	vmi_read_64_va(vmi, event->x86_regs->rcx, pid, &handle);

	fprintf(stderr, "pid: %d (%s) thread: 0x%lx syscall: %s(%s)\n", pid, proc_name, event->x86_regs->rsp, syscall_symbol, filename);
	

	/* TODO: presently omitted: handle, sysnum. */
}

static void
vf_windows_print_sysret_opensymboliclinkobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, char *proc_name, char *syscall_symbol)
{
	uint8_t * filename = filename_from_arg(vmi, event->x86_regs->r8, pid);

	uint64_t handle = 0;
	vmi_read_64_va(vmi, event->x86_regs->rcx, pid, &handle);

	fprintf(stderr, "pid: %d (%s) thread: 0x%lx syscall: %s(%s)\n", pid, proc_name, event->x86_regs->rsp, syscall_symbol, filename);
	

	/* TODO: presently omitted: handle, sysnum. */
}

static void
vf_windows_print_sysret_createfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, char *proc_name, char *syscall_symbol)
{
	uint8_t * filename = filename_from_arg(vmi, event->x86_regs->r8, pid);

	uint64_t handle = 0;
	vmi_read_64_va(vmi, event->x86_regs->rcx, pid, &handle);

	fprintf(stderr, "pid: %d (%s) thread: 0x%lx syscall: %s(%s)\n", pid, proc_name, event->x86_regs->rsp, syscall_symbol, filename);
	

	/* TODO: presently omitted: handle, sysnum. */
}

static void
vf_windows_print_sysret_opendirectoryobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, char *proc_name, char *syscall_symbol)
{
	uint8_t * filename = filename_from_arg(vmi, event->x86_regs->r8, pid);

	uint64_t handle = 0;
	vmi_read_64_va(vmi, event->x86_regs->rcx, pid, &handle);

	fprintf(stderr, "pid: %d (%s) thread: 0x%lx syscall: %s(%s)\n", pid, proc_name, event->x86_regs->rsp, syscall_symbol, filename);
	

	/* TODO: presently omitted: handle, sysnum. */
}

static void
vf_windows_print_sysret_openprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, char *proc_name, char *syscall_symbol)
{
	struct win64_client_id client_id = {0};
	vmi_read_va(vmi, event->x86_regs->r9, pid, &client_id, sizeof(struct win64_client_id));

	uint64_t handle = 0;
	vmi_read_64_va(vmi, event->x86_regs->rcx, pid, &handle);

	fprintf(stderr, "pid: %d (%s) thread: 0x%lx syscall: %s(0x%lx)\n", pid, proc_name, event->x86_regs->rsp, syscall_symbol, client_id.unique_process);
	

	/* TODO: presently omitted: handle, sysnum. */
}

static void
vf_windows_print_sysret_readfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, char *proc_name, char *syscall_symbol)
{
	fprintf(stderr, "pid: %d (%s) thread: 0x%lx syscall: %s(0x%lx)\n", pid, proc_name, event->x86_regs->rsp, syscall_symbol, event->x86_regs->rcx);
	

	/* TODO: presently omitted: handle, sysnum. */
}

static void
vf_windows_print_sysret_writefile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, char *proc_name, char *syscall_symbol)
{
	fprintf(stderr, "pid: %d (%s) thread: 0x%lx syscall: %s(0x%lx)\n", pid, proc_name, event->x86_regs->rsp, syscall_symbol, event->x86_regs->rcx);
	

	/* TODO: presently omitted: handle, sysnum. */
}

static void
vf_windows_print_sysret_def(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, char *proc_name, char *syscall_symbol)
{
	/* No-Op. for now. */
}

bool
vf_windows_find_trampoline_addr(vf_state *state)
{
	csh handle;
	cs_insn *inst;
	size_t count;
	status_t status = VMI_FAILURE;
	addr_t lstar = 0;
	uint8_t code[4096]; /* Assume CALL is within first page. */

	/* LSTAR should be the constant across all VCPUs */
        status_t ret = vmi_get_vcpureg(state->vmi, &lstar, MSR_LSTAR, 0);
        if (VMI_SUCCESS != ret) {
                fprintf(stderr, "failed to get MSR_LSTAR address\n");
                goto done;
        }

	addr_t lstar_p = vmi_translate_kv2p(state->vmi, lstar);
        if (0 == lstar_p) {
                fprintf(stderr, "failed to read instructions from 0x%"
                                 PRIx64".\n", lstar);
                goto done;
        }

	/* Read kernel instructions into code. */
	status = vmi_read_pa(state->vmi, lstar_p,
	                     code, sizeof(code));
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to read instructions from 0x%"
		                 PRIx64".\n", lstar_p);
		goto done;
	}

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		fprintf(stderr, "failed to open capstone\n");
		status = VMI_FAILURE;
		goto done;
	}

	/* Find CALL inst. and note address of inst. which follows. */
	count = cs_disasm(handle, code, sizeof(code), 0, 0, &inst);
	if (count > 0) {
		size_t i, j;
		for (i = 0; i < count; i++) {
			for (j = 0; j < sizeof(inst[i].bytes); j++) {
				if (0xcc == inst[i].bytes[j]) {
					trampoline_addr = lstar + inst[i].address + j;
				}
			}
		}
		cs_free(inst, count);
	} else {
		fprintf(stderr, "failed to disassemble system-call handler\n");
		status = VMI_FAILURE;
		goto done;
	}

	if (0 == trampoline_addr) {
		fprintf(stderr, "did not find existing 0xcc in kernel code\n");
		status = VMI_FAILURE;
		goto done;
	}

	cs_close(&handle);

	status = VMI_SUCCESS;

done:
	return status == VMI_SUCCESS ? true : false;
}

#if 0
bool
vf_windows_find_trampoline_addr(vf_state *state)
{
	bool status = false;
	trampoline_addr = 0;

	status_t ret = vmi_get_vcpureg(state->vmi, &trampoline_addr, MSR_LSTAR, 0);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "failed to get MSR_LSTAR address\n");
		goto done;
	}

	/*
	 * byte before system call routine should be alignment
	 *
	 * todo: programatically find a single byte in executable
	 * memory that we can overwrite with INT 3
	 * we may just be able to search through memory for an
	 * inevitable \xCC byte
	 */
	trampoline_addr -= 1;

	status = true;

done:
	return status;
}
#endif

/* See Windows's KeServiceDescriptorTable. */
static const struct syscall_defs SYSCALLS[] = {
	{ "NtMapUserPhysicalPagesScatter", vf_windows_print_sysret_def },
	{ "NtWaitForSingleObject", vf_windows_print_sysret_def },
	{ "NtCallbackReturn", vf_windows_print_sysret_def },
	{ "NtReadFile", vf_windows_print_sysret_readfile },
	{ "NtDeviceIoControlFile", vf_windows_print_sysret_def },
	{ "NtWriteFile", vf_windows_print_sysret_writefile },
	{ "NtRemoveIoCompletion", vf_windows_print_sysret_def },
	{ "NtReleaseSemaphore", vf_windows_print_sysret_def },
	{ "NtReplyWaitReceivePort", vf_windows_print_sysret_def },
	{ "NtReplyPort", vf_windows_print_sysret_def },
	{ "NtSetInformationThread", vf_windows_print_sysret_def },
	{ "NtSetEvent", vf_windows_print_sysret_def },
	{ "NtClose", vf_windows_print_sysret_def },
	{ "NtQueryObject", vf_windows_print_sysret_def },
	{ "NtQueryInformationFile", vf_windows_print_sysret_def },
	{ "NtOpenKey", vf_windows_print_sysret_def },
	{ "NtEnumerateValueKey", vf_windows_print_sysret_def },
	{ "NtFindAtom", vf_windows_print_sysret_def },
	{ "NtQueryDefaultLocale", vf_windows_print_sysret_def },
	{ "NtQueryKey", vf_windows_print_sysret_def },
	{ "NtQueryValueKey", vf_windows_print_sysret_def },
	{ "NtAllocateVirtualMemory", vf_windows_print_sysret_def },
	{ "NtQueryInformationProcess", vf_windows_print_sysret_def },
	{ "NtWaitForMultipleObjects32", vf_windows_print_sysret_def },
	{ "NtWriteFileGather", vf_windows_print_sysret_def },
	{ "NtSetInformationProcess", vf_windows_print_sysret_def },
	{ "NtCreateKey", vf_windows_print_sysret_def },
	{ "NtFreeVirtualMemory", vf_windows_print_sysret_def },
	{ "NtImpersonateClientOfPort", vf_windows_print_sysret_def },
	{ "NtReleaseMutant", vf_windows_print_sysret_def },
	{ "NtQueryInformationToken", vf_windows_print_sysret_def },
	{ "NtRequestWaitReplyPort", vf_windows_print_sysret_def },
	{ "NtQueryVirtualMemory", vf_windows_print_sysret_def },
	{ "NtOpenThreadToken", vf_windows_print_sysret_def },
	{ "NtQueryInformationThread", vf_windows_print_sysret_def },
	{ "NtOpenProcess", vf_windows_print_sysret_openprocess },
	{ "NtSetInformationFile", vf_windows_print_sysret_def },
	{ "NtMapViewOfSection", vf_windows_print_sysret_def },
	{ "NtAccessCheckAndAuditAlarm", vf_windows_print_sysret_def },
	{ "NtUnmapViewOfSection", vf_windows_print_sysret_def },
	{ "NtReplyWaitReceivePortEx", vf_windows_print_sysret_def },
	{ "NtTerminateProcess", vf_windows_print_sysret_def },
	{ "NtSetEventBoostPriority", vf_windows_print_sysret_def },
	{ "NtReadFileScatter", vf_windows_print_sysret_def },
	{ "NtOpenThreadTokenEx", vf_windows_print_sysret_def },
	{ "NtOpenProcessTokenEx", vf_windows_print_sysret_def },
	{ "NtQueryPerformanceCounter", vf_windows_print_sysret_def },
	{ "NtEnumerateKey", vf_windows_print_sysret_def },
	{ "NtOpenFile", vf_windows_print_sysret_openfile },
	{ "NtDelayExecution", vf_windows_print_sysret_def },
	{ "NtQueryDirectoryFile", vf_windows_print_sysret_def },
	{ "NtQuerySystemInformation", vf_windows_print_sysret_def },
	{ "NtOpenSection", vf_windows_print_sysret_def },
	{ "NtQueryTimer", vf_windows_print_sysret_def },
	{ "NtFsControlFile", vf_windows_print_sysret_def },
	{ "NtWriteVirtualMemory", vf_windows_print_sysret_def },
	{ "NtCloseObjectAuditAlarm", vf_windows_print_sysret_def },
	{ "NtDuplicateObject", vf_windows_print_sysret_def },
	{ "NtQueryAttributesFile", vf_windows_print_sysret_def },
	{ "NtClearEvent", vf_windows_print_sysret_def },
	{ "NtReadVirtualMemory", vf_windows_print_sysret_def },
	{ "NtOpenEvent", vf_windows_print_sysret_def },
	{ "NtAdjustPrivilegesToken", vf_windows_print_sysret_def },
	{ "NtDuplicateToken", vf_windows_print_sysret_def },
	{ "NtContinue", vf_windows_print_sysret_def },
	{ "NtQueryDefaultUILanguage", vf_windows_print_sysret_def },
	{ "NtQueueApcThread", vf_windows_print_sysret_def },
	{ "NtYieldExecution", vf_windows_print_sysret_def },
	{ "NtAddAtom", vf_windows_print_sysret_def },
	{ "NtCreateEvent", vf_windows_print_sysret_def },
	{ "NtQueryVolumeInformationFile", vf_windows_print_sysret_def },
	{ "NtCreateSection", vf_windows_print_sysret_def },
	{ "NtFlushBuffersFile", vf_windows_print_sysret_def },
	{ "NtApphelpCacheControl", vf_windows_print_sysret_def },
	{ "NtCreateProcessEx", vf_windows_print_sysret_def },
	{ "NtCreateThread", vf_windows_print_sysret_def },
	{ "NtIsProcessInJob", vf_windows_print_sysret_def },
	{ "NtProtectVirtualMemory", vf_windows_print_sysret_def },
	{ "NtQuerySection", vf_windows_print_sysret_def },
	{ "NtResumeThread", vf_windows_print_sysret_def },
	{ "NtTerminateThread", vf_windows_print_sysret_def },
	{ "NtReadRequestData", vf_windows_print_sysret_def },
	{ "NtCreateFile", vf_windows_print_sysret_createfile },
	{ "NtQueryEvent", vf_windows_print_sysret_def },
	{ "NtWriteRequestData", vf_windows_print_sysret_def },
	{ "NtOpenDirectoryObject", vf_windows_print_sysret_opendirectoryobject },
	{ "NtAccessCheckByTypeAndAuditAlarm", vf_windows_print_sysret_def },
	{ "NtQuerySystemTime", vf_windows_print_sysret_def },
	{ "NtWaitForMultipleObjects", vf_windows_print_sysret_def },
	{ "NtSetInformationObject", vf_windows_print_sysret_def },
	{ "NtCancelIoFile", vf_windows_print_sysret_def },
	{ "NtTraceEvent", vf_windows_print_sysret_def },
	{ "NtPowerInformation", vf_windows_print_sysret_def },
	{ "NtSetValueKey", vf_windows_print_sysret_def },
	{ "NtCancelTimer", vf_windows_print_sysret_def },
	{ "NtSetTimer", vf_windows_print_sysret_def },
	{ "NtAcceptConnectPort", vf_windows_print_sysret_def },
	{ "NtAccessCheck", vf_windows_print_sysret_def },
	{ "NtAccessCheckByType", vf_windows_print_sysret_def },
	{ "NtAccessCheckByTypeResultList", vf_windows_print_sysret_def },
	{ "NtAccessCheckByTypeResultListAndAuditAlarm", vf_windows_print_sysret_def },
	{ "NtAccessCheckByTypeResultListAndAuditAlarmByHandle", vf_windows_print_sysret_def },
	{ "NtAddBootEntry", vf_windows_print_sysret_def },
	{ "NtAddDriverEntry", vf_windows_print_sysret_def },
	{ "NtAdjustGroupsToken", vf_windows_print_sysret_def },
	{ "NtAlertResumeThread", vf_windows_print_sysret_def },
	{ "NtAlertThread", vf_windows_print_sysret_def },
	{ "NtAllocateLocallyUniqueId", vf_windows_print_sysret_def },
	{ "NtAllocateReserveObject", vf_windows_print_sysret_def },
	{ "NtAllocateUserPhysicalPages", vf_windows_print_sysret_def },
	{ "NtAllocateUuids", vf_windows_print_sysret_def },
	{ "NtAlpcAcceptConnectPort", vf_windows_print_sysret_def },
	{ "NtAlpcCancelMessage", vf_windows_print_sysret_def },
	{ "NtAlpcConnectPort", vf_windows_print_sysret_def },
	{ "NtAlpcCreatePort", vf_windows_print_sysret_def },
	{ "NtAlpcCreatePortSection", vf_windows_print_sysret_def },
	{ "NtAlpcCreateResourceReserve", vf_windows_print_sysret_def },
	{ "NtAlpcCreateSectionView", vf_windows_print_sysret_def },
	{ "NtAlpcCreateSecurityContext", vf_windows_print_sysret_def },
	{ "NtAlpcDeletePortSection", vf_windows_print_sysret_def },
	{ "NtAlpcDeleteResourceReserve", vf_windows_print_sysret_def },
	{ "NtAlpcDeleteSectionView", vf_windows_print_sysret_def },
	{ "NtAlpcDeleteSecurityContext", vf_windows_print_sysret_def },
	{ "NtAlpcDisconnectPort", vf_windows_print_sysret_def },
	{ "NtAlpcImpersonateClientOfPort", vf_windows_print_sysret_def },
	{ "NtAlpcOpenSenderProcess", vf_windows_print_sysret_def },
	{ "NtAlpcOpenSenderThread", vf_windows_print_sysret_def },
	{ "NtAlpcQueryInformation", vf_windows_print_sysret_def },
	{ "NtAlpcQueryInformationMessage", vf_windows_print_sysret_def },
	{ "NtAlpcRevokeSecurityContext", vf_windows_print_sysret_def },
	{ "NtAlpcSendWaitReceivePort", vf_windows_print_sysret_def },
	{ "NtAlpcSetInformation", vf_windows_print_sysret_def },
	{ "NtAreMappedFilesTheSame", vf_windows_print_sysret_def },
	{ "NtAssignProcessToJobObject", vf_windows_print_sysret_def },
	{ "NtCancelIoFileEx", vf_windows_print_sysret_def },
	{ "NtCancelSynchronousIoFile", vf_windows_print_sysret_def },
	{ "NtCommitComplete", vf_windows_print_sysret_def },
	{ "NtCommitEnlistment", vf_windows_print_sysret_def },
	{ "NtCommitTransaction", vf_windows_print_sysret_def },
	{ "NtCompactKeys", vf_windows_print_sysret_def },
	{ "NtCompareTokens", vf_windows_print_sysret_def },
	{ "NtCompleteConnectPort", vf_windows_print_sysret_def },
	{ "NtCompressKey", vf_windows_print_sysret_def },
	{ "NtConnectPort", vf_windows_print_sysret_def },
	{ "NtCreateDebugObject", vf_windows_print_sysret_def },
	{ "NtCreateDirectoryObject", vf_windows_print_sysret_def },
	{ "NtCreateEnlistment", vf_windows_print_sysret_def },
	{ "NtCreateEventPair", vf_windows_print_sysret_def },
	{ "NtCreateIoCompletion", vf_windows_print_sysret_def },
	{ "NtCreateJobObject", vf_windows_print_sysret_def },
	{ "NtCreateJobSet", vf_windows_print_sysret_def },
	{ "NtCreateKeyTransacted", vf_windows_print_sysret_def },
	{ "NtCreateKeyedEvent", vf_windows_print_sysret_def },
	{ "NtCreateMailslotFile", vf_windows_print_sysret_def },
	{ "NtCreateMutant", vf_windows_print_sysret_def },
	{ "NtCreateNamedPipeFile", vf_windows_print_sysret_def },
	{ "NtCreatePagingFile", vf_windows_print_sysret_def },
	{ "NtCreatePort", vf_windows_print_sysret_def },
	{ "NtCreatePrivateNamespace", vf_windows_print_sysret_def },
	{ "NtCreateProcess", vf_windows_print_sysret_def },
	{ "NtCreateProfile", vf_windows_print_sysret_def },
	{ "NtCreateProfileEx", vf_windows_print_sysret_def },
	{ "NtCreateResourceManager", vf_windows_print_sysret_def },
	{ "NtCreateSemaphore", vf_windows_print_sysret_def },
	{ "NtCreateSymbolicLinkObject", vf_windows_print_sysret_def },
	{ "NtCreateThreadEx", vf_windows_print_sysret_def },
	{ "NtCreateTimer", vf_windows_print_sysret_def },
	{ "NtCreateToken", vf_windows_print_sysret_def },
	{ "NtCreateTransaction", vf_windows_print_sysret_def },
	{ "NtCreateTransactionManager", vf_windows_print_sysret_def },
	{ "NtCreateUserProcess", vf_windows_print_sysret_def },
	{ "NtCreateWaitablePort", vf_windows_print_sysret_def },
	{ "NtCreateWorkerFactory", vf_windows_print_sysret_def },
	{ "NtDebugActiveProcess", vf_windows_print_sysret_def },
	{ "NtDebugContinue", vf_windows_print_sysret_def },
	{ "NtDeleteAtom", vf_windows_print_sysret_def },
	{ "NtDeleteBootEntry", vf_windows_print_sysret_def },
	{ "NtDeleteDriverEntry", vf_windows_print_sysret_def },
	{ "NtDeleteFile", vf_windows_print_sysret_def },
	{ "NtDeleteKey", vf_windows_print_sysret_def },
	{ "NtDeleteObjectAuditAlarm", vf_windows_print_sysret_def },
	{ "NtDeletePrivateNamespace", vf_windows_print_sysret_def },
	{ "NtDeleteValueKey", vf_windows_print_sysret_def },
	{ "NtDisableLastKnownGood", vf_windows_print_sysret_def },
	{ "NtDisplayString", vf_windows_print_sysret_def },
	{ "NtDrawText", vf_windows_print_sysret_def },
	{ "NtEnableLastKnownGood", vf_windows_print_sysret_def },
	{ "NtEnumerateBootEntries", vf_windows_print_sysret_def },
	{ "NtEnumerateDriverEntries", vf_windows_print_sysret_def },
	{ "NtEnumerateSystemEnvironmentValuesEx", vf_windows_print_sysret_def },
	{ "NtEnumerateTransactionObject", vf_windows_print_sysret_def },
	{ "NtExtendSection", vf_windows_print_sysret_def },
	{ "NtFilterToken", vf_windows_print_sysret_def },
	{ "NtFlushInstallUILanguage", vf_windows_print_sysret_def },
	{ "NtFlushInstructionCache", vf_windows_print_sysret_def },
	{ "NtFlushKey", vf_windows_print_sysret_def },
	{ "NtFlushProcessWriteBuffers", vf_windows_print_sysret_def },
	{ "NtFlushVirtualMemory", vf_windows_print_sysret_def },
	{ "NtFlushWriteBuffer", vf_windows_print_sysret_def },
	{ "NtFreeUserPhysicalPages", vf_windows_print_sysret_def },
	{ "NtFreezeRegistry", vf_windows_print_sysret_def },
	{ "NtFreezeTransactions", vf_windows_print_sysret_def },
	{ "NtGetContextThread", vf_windows_print_sysret_def },
	{ "NtGetCurrentProcessorNumber", vf_windows_print_sysret_def },
	{ "NtGetDevicePowerState", vf_windows_print_sysret_def },
	{ "NtGetMUIRegistryInfo", vf_windows_print_sysret_def },
	{ "NtGetNextProcess", vf_windows_print_sysret_def },
	{ "NtGetNextThread", vf_windows_print_sysret_def },
	{ "NtGetNlsSectionPtr", vf_windows_print_sysret_def },
	{ "NtGetNotificationResourceManager", vf_windows_print_sysret_def },
	{ "NtGetPlugPlayEvent", vf_windows_print_sysret_def },
	{ "NtGetWriteWatch", vf_windows_print_sysret_def },
	{ "NtImpersonateAnonymousToken", vf_windows_print_sysret_def },
	{ "NtImpersonateThread", vf_windows_print_sysret_def },
	{ "NtInitializeNlsFiles", vf_windows_print_sysret_def },
	{ "NtInitializeRegistry", vf_windows_print_sysret_def },
	{ "NtInitiatePowerAction", vf_windows_print_sysret_def },
	{ "NtIsSystemResumeAutomatic", vf_windows_print_sysret_def },
	{ "NtIsUILanguageComitted", vf_windows_print_sysret_def },
	{ "NtListenPort", vf_windows_print_sysret_def },
	{ "NtLoadDriver", vf_windows_print_sysret_def },
	{ "NtLoadKey", vf_windows_print_sysret_def },
	{ "NtLoadKey2", vf_windows_print_sysret_def },
	{ "NtLoadKeyEx", vf_windows_print_sysret_def },
	{ "NtLockFile", vf_windows_print_sysret_def },
	{ "NtLockProductActivationKeys", vf_windows_print_sysret_def },
	{ "NtLockRegistryKey", vf_windows_print_sysret_def },
	{ "NtLockVirtualMemory", vf_windows_print_sysret_def },
	{ "NtMakePermanentObject", vf_windows_print_sysret_def },
	{ "NtMakeTemporaryObject", vf_windows_print_sysret_def },
	{ "NtMapCMFModule", vf_windows_print_sysret_def },
	{ "NtMapUserPhysicalPages", vf_windows_print_sysret_def },
	{ "NtModifyBootEntry", vf_windows_print_sysret_def },
	{ "NtModifyDriverEntry", vf_windows_print_sysret_def },
	{ "NtNotifyChangeDirectoryFile", vf_windows_print_sysret_def },
	{ "NtNotifyChangeKey", vf_windows_print_sysret_def },
	{ "NtNotifyChangeMultipleKeys", vf_windows_print_sysret_def },
	{ "NtNotifyChangeSession", vf_windows_print_sysret_def },
	{ "NtOpenEnlistment", vf_windows_print_sysret_def },
	{ "NtOpenEventPair", vf_windows_print_sysret_def },
	{ "NtOpenIoCompletion", vf_windows_print_sysret_def },
	{ "NtOpenJobObject", vf_windows_print_sysret_def },
	{ "NtOpenKeyEx", vf_windows_print_sysret_def },
	{ "NtOpenKeyTransacted", vf_windows_print_sysret_def },
	{ "NtOpenKeyTransactedEx", vf_windows_print_sysret_def },
	{ "NtOpenKeyedEvent", vf_windows_print_sysret_def },
	{ "NtOpenMutant", vf_windows_print_sysret_def },
	{ "NtOpenObjectAuditAlarm", vf_windows_print_sysret_def },
	{ "NtOpenPrivateNamespace", vf_windows_print_sysret_def },
	{ "NtOpenProcessToken", vf_windows_print_sysret_def },
	{ "NtOpenResourceManager", vf_windows_print_sysret_def },
	{ "NtOpenSemaphore", vf_windows_print_sysret_def },
	{ "NtOpenSession", vf_windows_print_sysret_def },
	{ "NtOpenSymbolicLinkObject", vf_windows_print_sysret_opensymboliclinkobject },
	{ "NtOpenThread", vf_windows_print_sysret_def },
	{ "NtOpenTimer", vf_windows_print_sysret_def },
	{ "NtOpenTransaction", vf_windows_print_sysret_def },
	{ "NtOpenTransactionManager", vf_windows_print_sysret_def },
	{ "NtPlugPlayControl", vf_windows_print_sysret_def },
	{ "NtPrePrepareComplete", vf_windows_print_sysret_def },
	{ "NtPrePrepareEnlistment", vf_windows_print_sysret_def },
	{ "NtPrepareComplete", vf_windows_print_sysret_def },
	{ "NtPrepareEnlistment", vf_windows_print_sysret_def },
	{ "NtPrivilegeCheck", vf_windows_print_sysret_def },
	{ "NtPrivilegeObjectAuditAlarm", vf_windows_print_sysret_def },
	{ "NtPrivilegedServiceAuditAlarm", vf_windows_print_sysret_def },
	{ "NtPropagationComplete", vf_windows_print_sysret_def },
	{ "NtPropagationFailed", vf_windows_print_sysret_def },
	{ "NtPulseEvent", vf_windows_print_sysret_def },
	{ "NtQueryBootEntryOrder", vf_windows_print_sysret_def },
	{ "NtQueryBootOptions", vf_windows_print_sysret_def },
	{ "NtQueryDebugFilterState", vf_windows_print_sysret_def },
	{ "NtQueryDirectoryObject", vf_windows_print_sysret_def },
	{ "NtQueryDriverEntryOrder", vf_windows_print_sysret_def },
	{ "NtQueryEaFile", vf_windows_print_sysret_def },
	{ "NtQueryFullAttributesFile", vf_windows_print_sysret_def },
	{ "NtQueryInformationAtom", vf_windows_print_sysret_def },
	{ "NtQueryInformationEnlistment", vf_windows_print_sysret_def },
	{ "NtQueryInformationJobObject", vf_windows_print_sysret_def },
	{ "NtQueryInformationPort", vf_windows_print_sysret_def },
	{ "NtQueryInformationResourceManager", vf_windows_print_sysret_def },
	{ "NtQueryInformationTransaction", vf_windows_print_sysret_def },
	{ "NtQueryInformationTransactionManager", vf_windows_print_sysret_def },
	{ "NtQueryInformationWorkerFactory", vf_windows_print_sysret_def },
	{ "NtQueryInstallUILanguage", vf_windows_print_sysret_def },
	{ "NtQueryIntervalProfile", vf_windows_print_sysret_def },
	{ "NtQueryIoCompletion", vf_windows_print_sysret_def },
	{ "NtQueryLicenseValue", vf_windows_print_sysret_def },
	{ "NtQueryMultipleValueKey", vf_windows_print_sysret_def },
	{ "NtQueryMutant", vf_windows_print_sysret_def },
	{ "NtQueryOpenSubKeys", vf_windows_print_sysret_def },
	{ "NtQueryOpenSubKeysEx", vf_windows_print_sysret_def },
	{ "NtQueryPortInformationProcess", vf_windows_print_sysret_def },
	{ "NtQueryQuotaInformationFile", vf_windows_print_sysret_def },
	{ "NtQuerySecurityAttributesToken", vf_windows_print_sysret_def },
	{ "NtQuerySecurityObject", vf_windows_print_sysret_def },
	{ "NtQuerySemaphore", vf_windows_print_sysret_def },
	{ "NtQuerySymbolicLinkObject", vf_windows_print_sysret_def },
	{ "NtQuerySystemEnvironmentValue", vf_windows_print_sysret_def },
	{ "NtQuerySystemEnvironmentValueEx", vf_windows_print_sysret_def },
	{ "NtQuerySystemInformationEx", vf_windows_print_sysret_def },
	{ "NtQueryTimerResolution", vf_windows_print_sysret_def },
	{ "NtQueueApcThreadEx", vf_windows_print_sysret_def },
	{ "NtRaiseException", vf_windows_print_sysret_def },
	{ "NtRaiseHardError", vf_windows_print_sysret_def },
	{ "NtReadOnlyEnlistment", vf_windows_print_sysret_def },
	{ "NtRecoverEnlistment", vf_windows_print_sysret_def },
	{ "NtRecoverResourceManager", vf_windows_print_sysret_def },
	{ "NtRecoverTransactionManager", vf_windows_print_sysret_def },
	{ "NtRegisterProtocolAddressInformation", vf_windows_print_sysret_def },
	{ "NtRegisterThreadTerminatePort", vf_windows_print_sysret_def },
	{ "NtReleaseKeyedEvent", vf_windows_print_sysret_def },
	{ "NtReleaseWorkerFactoryWorker", vf_windows_print_sysret_def },
	{ "NtRemoveIoCompletionEx", vf_windows_print_sysret_def },
	{ "NtRemoveProcessDebug", vf_windows_print_sysret_def },
	{ "NtRenameKey", vf_windows_print_sysret_def },
	{ "NtRenameTransactionManager", vf_windows_print_sysret_def },
	{ "NtReplaceKey", vf_windows_print_sysret_def },
	{ "NtReplacePartitionUnit", vf_windows_print_sysret_def },
	{ "NtReplyWaitReplyPort", vf_windows_print_sysret_def },
	{ "NtRequestPort", vf_windows_print_sysret_def },
	{ "NtResetEvent", vf_windows_print_sysret_def },
	{ "NtResetWriteWatch", vf_windows_print_sysret_def },
	{ "NtRestoreKey", vf_windows_print_sysret_def },
	{ "NtResumeProcess", vf_windows_print_sysret_def },
	{ "NtRollbackComplete", vf_windows_print_sysret_def },
	{ "NtRollbackEnlistment", vf_windows_print_sysret_def },
	{ "NtRollbackTransaction", vf_windows_print_sysret_def },
	{ "NtRollforwardTransactionManager", vf_windows_print_sysret_def },
	{ "NtSaveKey", vf_windows_print_sysret_def },
	{ "NtSaveKeyEx", vf_windows_print_sysret_def },
	{ "NtSaveMergedKeys", vf_windows_print_sysret_def },
	{ "NtSecureConnectPort", vf_windows_print_sysret_def },
	{ "NtSerializeBoot", vf_windows_print_sysret_def },
	{ "NtSetBootEntryOrder", vf_windows_print_sysret_def },
	{ "NtSetBootOptions", vf_windows_print_sysret_def },
	{ "NtSetContextThread", vf_windows_print_sysret_def },
	{ "NtSetDebugFilterState", vf_windows_print_sysret_def },
	{ "NtSetDefaultHardErrorPort", vf_windows_print_sysret_def },
	{ "NtSetDefaultLocale", vf_windows_print_sysret_def },
	{ "NtSetDefaultUILanguage", vf_windows_print_sysret_def },
	{ "NtSetDriverEntryOrder", vf_windows_print_sysret_def },
	{ "NtSetEaFile", vf_windows_print_sysret_def },
	{ "NtSetHighEventPair", vf_windows_print_sysret_def },
	{ "NtSetHighWaitLowEventPair", vf_windows_print_sysret_def },
	{ "NtSetInformationDebugObject", vf_windows_print_sysret_def },
	{ "NtSetInformationEnlistment", vf_windows_print_sysret_def },
	{ "NtSetInformationJobObject", vf_windows_print_sysret_def },
	{ "NtSetInformationKey", vf_windows_print_sysret_def },
	{ "NtSetInformationResourceManager", vf_windows_print_sysret_def },
	{ "NtSetInformationToken", vf_windows_print_sysret_def },
	{ "NtSetInformationTransaction", vf_windows_print_sysret_def },
	{ "NtSetInformationTransactionManager", vf_windows_print_sysret_def },
	{ "NtSetInformationWorkerFactory", vf_windows_print_sysret_def },
	{ "NtSetIntervalProfile", vf_windows_print_sysret_def },
	{ "NtSetIoCompletion", vf_windows_print_sysret_def },
	{ "NtSetIoCompletionEx", vf_windows_print_sysret_def },
	{ "NtSetLdtEntries", vf_windows_print_sysret_def },
	{ "NtSetLowEventPair", vf_windows_print_sysret_def },
	{ "NtSetLowWaitHighEventPair", vf_windows_print_sysret_def },
	{ "NtSetQuotaInformationFile", vf_windows_print_sysret_def },
	{ "NtSetSecurityObject", vf_windows_print_sysret_def },
	{ "NtSetSystemEnvironmentValue", vf_windows_print_sysret_def },
	{ "NtSetSystemEnvironmentValueEx", vf_windows_print_sysret_def },
	{ "NtSetSystemInformation", vf_windows_print_sysret_def },
	{ "NtSetSystemPowerState", vf_windows_print_sysret_def },
	{ "NtSetSystemTime", vf_windows_print_sysret_def },
	{ "NtSetThreadExecutionState", vf_windows_print_sysret_def },
	{ "NtSetTimerEx", vf_windows_print_sysret_def },
	{ "NtSetTimerResolution", vf_windows_print_sysret_def },
	{ "NtSetUuidSeed", vf_windows_print_sysret_def },
	{ "NtSetVolumeInformationFile", vf_windows_print_sysret_def },
	{ "NtShutdownSystem", vf_windows_print_sysret_def },
	{ "NtShutdownWorkerFactory", vf_windows_print_sysret_def },
	{ "NtSignalAndWaitForSingleObject", vf_windows_print_sysret_def },
	{ "NtSinglePhaseReject", vf_windows_print_sysret_def },
	{ "NtStartProfile", vf_windows_print_sysret_def },
	{ "NtStopProfile", vf_windows_print_sysret_def },
	{ "NtSuspendProcess", vf_windows_print_sysret_def },
	{ "NtSuspendThread", vf_windows_print_sysret_def },
	{ "NtSystemDebugControl", vf_windows_print_sysret_def },
	{ "NtTerminateJobObject", vf_windows_print_sysret_def },
	{ "NtTestAlert", vf_windows_print_sysret_def },
	{ "NtThawRegistry", vf_windows_print_sysret_def },
	{ "NtThawTransactions", vf_windows_print_sysret_def },
	{ "NtTraceControl", vf_windows_print_sysret_def },
	{ "NtTranslateFilePath", vf_windows_print_sysret_def },
	{ "NtUmsThreadYield", vf_windows_print_sysret_def },
	{ "NtUnloadDriver", vf_windows_print_sysret_def },
	{ "NtUnloadKey", vf_windows_print_sysret_def },
	{ "NtUnloadKey2", vf_windows_print_sysret_def },
	{ "NtUnloadKeyEx", vf_windows_print_sysret_def },
	{ "NtUnlockFile", vf_windows_print_sysret_def },
	{ "NtUnlockVirtualMemory", vf_windows_print_sysret_def },
	{ "NtVdmControl", vf_windows_print_sysret_def },
	{ "NtWaitForDebugEvent", vf_windows_print_sysret_def },
	{ "NtWaitForKeyedEvent", vf_windows_print_sysret_def },
	{ "NtWaitForWorkViaWorkerFactory", vf_windows_print_sysret_def },
	{ "NtWaitHighEventPair", vf_windows_print_sysret_def },
	{ "NtWaitLowEventPair", vf_windows_print_sysret_def },
	{ "NtWorkerFactoryWorkerReady", vf_windows_print_sysret_def },
	{ NULL, NULL },
};

#define NUM_SYSCALL_ARGS 8

/*
 * Tries to return a UTF-8 string representing the filename of an ObjectAttribute
 * vaddr must point to an ObjectAttribute virtual address
 * Must free what it returns
 */

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
vf_windows_print_syscall(vmi_instance_t vmi,
                         vmi_event_t *event,
                         vf_paddr_record *paddr_record)
{
	vmi_pid_t pid = vmi_dtb_to_pid(vmi, event->x86_regs->cr3);

	if (0 == pid) { /* it can't find the PID sometimes... */
		return;
	}

	char * proc_name = get_process_name(vmi, pid);

	SYSCALLS[paddr_record->identifier].print(vmi,
	                                         event,
	                                         pid,
	                                         proc_name,
	                                         SYSCALLS[paddr_record->identifier].name);

	free(proc_name);
}

void 
vf_windows_print_sysret(vmi_instance_t vmi,
                        vmi_event_t *event) 
{
	vmi_pid_t pid = vmi_dtb_to_pid(vmi, event->x86_regs->cr3);

	if (0 == pid) { /* it can't find the PID sometimes... */
		return;
	}

	char * proc_name = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %d (%s) thread: 0x%lx return: 0x%lx\n", pid, proc_name, event->x86_regs->rsp - 8, event->x86_regs->rax);
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
vf_windows_find_syscalls_and_setup_mem_traps(vf_state *state)
{
	static const char *TRACED_SYSCALLS[] = {
		"NtCreateFile",
		"NtOpenProcess",
		NULL
	};

	return vf_find_syscalls_and_setup_mem_traps(state,
                                                    SYSCALLS,
                                                    TRACED_SYSCALLS);
}

/*
 * Disassemble the kernel and find the appropriate spot for a breakpoint
 * which will allow guestrace to determine a system call's return value. Return
 * the address of this spot.
 */
static addr_t
vf_windows_get_return_point_addr(vf_state *state, addr_t syscall_start) {
	csh handle;
	cs_insn *inst;
	size_t count, call_offset = ~0;
	addr_t ret = 0;
	uint8_t code[4096]; /* Assume CALL is within first page. */

	addr_t syscall_start_p = vmi_translate_kv2p(state->vmi, syscall_start);
	if (0 == syscall_start_p) {
		fprintf(stderr, "failed to read instructions from 0x%"
		                 PRIx64".\n", syscall_start);
		goto done;
	}

	/* Read kernel instructions into code. */
	status_t status = vmi_read_pa(state->vmi, syscall_start_p, code, sizeof(code));
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

bool
vf_windows_find_return_point_addr(vf_state *state)
{
	bool status = false;
	addr_t lstar = 0;

	/* LSTAR should be the constant across all VCPUs */
	status_t ret = vmi_get_vcpureg(state->vmi, &lstar, MSR_LSTAR, 0);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "failed to get MSR_LSTAR address\n");
		goto done;
	}

	return_point_addr = vf_windows_get_return_point_addr(state, lstar);
	if (0 == return_point_addr) {
		fprintf(stderr, "failed to get system return address\n");
		goto done;
	}

	status = true;

done:
	return status;
}

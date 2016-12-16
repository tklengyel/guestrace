#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <glib.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <capstone/capstone.h>

#include "translate_syscalls.h"

/*
 * The Windows code follows this strategy:
 *
 * (1) Set breakpoints on individual system-call functions within the
 *     kernel instead of in the vicinity of the address in LSTAR. This
 *     improves performance because it avoids breaking on system calls
 *     which are not interesting to VisorFlow.
 *
 * (2) Trap when an instruction reads from the page containing one of our
 *     breakpoints. Such reads are likely invoked by Windows's kernel patch
 *     protection, which checks the integrity of the memory containing kernel
 *     instructions. When we trap these reads, we replace the breakpoint with
 *     the original instruction byte, restoring the proper memory contents.
 *
 * (3) Trap when an instruction executes from a page which should contain one
 *     of our breakpoints. In this case, we probably restored the original
 *     instruction due to a read. Now it is time to re-emplace the breakpoint.
 *
 * The traps described by (2) or (3) exist only if we wrote a breakpoint or
 * restored an original instruction, respectively.
 */

/* Intel breakpoint interrupt (INT 3) instruction. */
static uint8_t BREAKPOINT_INST = 0xCC;

/*
 * Handle terminating signals by setting interrupted flag. This allows
 * a graceful exit.
 */
static int interrupted = 0;

/*
 * Guestrace maintains two collections:
 *
 * The first collection contains a mapping from page numbers to vf_page_record
 * structures. This serves as a record of the guest pages for which guestrace
 * installed a memory event. When the guest accesses such a page, control
 * traps into guestrace. The most notable field in vf_page_record is children.
 * The children field points to the second collection.
 *
 * The second collection contains a mapping from physical addresses to vf_paddr_record
 * structures. This serves as a record for each breakpoint that guestrace
 * sets within a page.
 */

GHashTable *vf_page_record_collection;

typedef struct vf_page_record {
	addr_t page;
	vmi_event_t *mem_event_rw;
	vmi_event_t *mem_event_x;
	GHashTable *children;
	vmi_instance_t vmi;
} vf_page_record;

typedef struct vf_paddr_record {
	addr_t breakpoint_va;
	addr_t breakpoint_pa;
	uint8_t orig_inst;
	uint8_t curr_inst;
	vf_page_record *parent;
	gboolean disabled;
	uint16_t identifier; /* syscall identifier because we nix RAX */
} vf_paddr_record;

vmi_event_t trap_int_event;
vf_paddr_record *syscall_ret_trap;

vf_paddr_record *vf_paddr_record_from_va(vmi_instance_t vmi, addr_t va);
vf_paddr_record *vf_paddr_record_from_pa(vmi_instance_t vmi, addr_t pa);
status_t vf_enable_trap(vf_paddr_record *paddr_record);
status_t vf_disable_trap(vf_paddr_record *paddr_record);
void destroy_trap(gpointer data); /* private routine for freeing memory */

/* From KeServiceDescriptorTable: */
const char *SYSCALLS[] = {
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

const char *MONITORED_SYSCALLS[] = {
	"NtCreateFile",
	"NtOpenSymbolicLinkObject",
	"NtOpenDirectoryObject",
	"NtOpenProcess"
};

#define countof(array) (sizeof(array) / sizeof((array)[0]))

void
trap_mem_callback_x_reset(vmi_event_t *event, status_t rc) {
	vf_page_record *paddr_record = (vf_page_record *) event->data;

	vmi_register_event(paddr_record->vmi, paddr_record->mem_event_rw);
}

void
trap_mem_callback_rw_reset(vmi_event_t *event, status_t rc) {
	vf_page_record *paddr_record = (vf_page_record *) event->data;

	vmi_register_event(paddr_record->vmi, paddr_record->mem_event_x);
}

void
reset_interrupts_x(gpointer key, gpointer value, gpointer user_data) {
	vf_paddr_record *paddr_record = value;
	vmi_instance_t *vmi = user_data;

	vmi_write_8_pa(*vmi, paddr_record->breakpoint_pa, &paddr_record->curr_inst);
}

event_response_t
trap_mem_callback_x(vmi_instance_t vmi, vmi_event_t *event) {
	fprintf(stderr, "mem exe at %lx\n", event->mem_event.gla);

	vf_page_record *trapped_page_record = (vf_page_record *) event->data;

	g_hash_table_foreach(trapped_page_record->children, reset_interrupts_x, &vmi);

	vmi_clear_event(vmi, event, &trap_mem_callback_x_reset);

	return VMI_EVENT_RESPONSE_NONE;
}

void
reset_interrupts_rw(gpointer key, gpointer value, gpointer user_data) {
	vf_paddr_record *paddr_record = value;
	vmi_instance_t *vmi = user_data;

	vmi_write_8_pa(*vmi, paddr_record->breakpoint_pa, &paddr_record->orig_inst);
}

event_response_t
trap_mem_callback_rw(vmi_instance_t vmi, vmi_event_t *event) {
	fprintf(stderr, "mem r/w at %lx\n", event->mem_event.gla);

	vf_page_record *trapped_page_record = (vf_page_record *) event->data;

	g_hash_table_foreach(trapped_page_record->children, reset_interrupts_rw, &vmi);

	vmi_clear_event(vmi, event, &trap_mem_callback_rw_reset);

	return VMI_EVENT_RESPONSE_NONE;
}

event_response_t
trap_int_reset(vmi_instance_t vmi, vmi_event_t *event) {
	event_response_t status = VMI_EVENT_RESPONSE_NONE;

	vf_paddr_record *paddr_record = vf_paddr_record_from_va(vmi,
	                                                        event->interrupt_event.gla);

	if (NULL == paddr_record) {
		event->interrupt_event.reinject = 1;
		/* TODO: Ensure this does the right thing: */
		status = VMI_EVENT_RESPONSE_EMULATE;
		goto done;
	}

	paddr_record->curr_inst = BREAKPOINT_INST;

	vmi_write_8_pa(vmi, paddr_record->breakpoint_pa, &paddr_record->curr_inst);

done:
	return status;
}

event_response_t
interrupt_callback(vmi_instance_t vmi, vmi_event_t *event) {
	event_response_t status = VMI_EVENT_RESPONSE_NONE;

	vf_paddr_record *paddr_record = vf_paddr_record_from_va(vmi,
	                                                        event->interrupt_event.gla);

	if (NULL == paddr_record) {
		event->interrupt_event.reinject = 1;
		/* TODO: Ensure this does the right thing: */
		status = VMI_EVENT_RESPONSE_EMULATE;
		goto done;
	}

	event->interrupt_event.reinject = 0;

	paddr_record->curr_inst = paddr_record->orig_inst;

	vmi_write_8_pa(vmi, paddr_record->breakpoint_pa, &paddr_record->curr_inst);

	if (paddr_record->disabled) {
		goto done;
	}

	if (paddr_record != syscall_ret_trap) {
		print_syscall(vmi, event, paddr_record->identifier);
		vf_enable_trap(syscall_ret_trap);
		vmi_step_event(vmi, event, event->vcpu_id, 1, trap_int_reset);
	} else {
		print_sysret(vmi, event);
		vf_disable_trap(syscall_ret_trap);
	}

done:
	return status;
}

status_t
vf_enable_trap(vf_paddr_record *paddr_record) {
	status_t status = VMI_SUCCESS;

	if (paddr_record->disabled) {
		paddr_record->curr_inst = BREAKPOINT_INST;
		vmi_write_8_pa(paddr_record->parent->vmi,
		               paddr_record->breakpoint_pa,
		              &paddr_record->curr_inst);
		paddr_record->disabled = FALSE;
	} else {
		status = VMI_FAILURE;
	}

	return status;
}

status_t
vf_disable_trap(vf_paddr_record *paddr_record) {
	status_t status = VMI_SUCCESS;

	if (!paddr_record->disabled) {
		paddr_record->curr_inst = paddr_record->orig_inst;
		vmi_write_8_pa(paddr_record->parent->vmi,
		               paddr_record->breakpoint_pa,
		              &paddr_record->curr_inst);
		paddr_record->disabled = TRUE;
	} else {
		status = VMI_FAILURE;
	}

	return status;
}

vf_paddr_record *
vf_paddr_record_from_va(vmi_instance_t vmi, addr_t va) {
	return vf_paddr_record_from_pa(vmi, vmi_translate_kv2p(vmi, va));
}

vf_paddr_record *
vf_paddr_record_from_pa(vmi_instance_t vmi, addr_t pa) {
	vf_paddr_record *paddr_record = NULL;
	vf_page_record  *page_record  = NULL;

	addr_t page = pa >> 12;

	/* get page event */
	page_record = g_hash_table_lookup(vf_page_record_collection,
	                                          GSIZE_TO_POINTER(page));

	if (NULL == page_record) { /* make sure we own this interrupt */
		goto done;
	}

	/* get individual trap */
	paddr_record = g_hash_table_lookup(page_record->children,
	                                   GSIZE_TO_POINTER(pa));

done:
	return paddr_record;
}

/*
 * Ensure there exists a memory trap on the page containing virtual address va,
 * and create a page record if it does not yet exist. Add a physical-address record
 * corresponding to va to the page record's collection of children.
 */
vf_paddr_record *
vf_setup_paddr_trap(vmi_instance_t vmi, addr_t va) {
	status_t status = VMI_FAILURE;
	vf_page_record  *page_record  = NULL;
	vf_paddr_record *paddr_record = NULL;

	addr_t pa = vmi_translate_kv2p(vmi, va);
	if (0 == pa) {
		fprintf(stderr, "virtual addr. translation failed: %lx\n", va);
		goto done;
	}

	addr_t page = pa >> 12;

	page_record = g_hash_table_lookup(vf_page_record_collection,
	                                  GSIZE_TO_POINTER(page));
	if (NULL == page_record) {
		/* Create page record and set memory trap on page. */
		fprintf(stderr, "creating new page trap on 0x%lx\n", page);

		page_record                     = g_new0(vf_page_record, 1);
		page_record->page               = page;
		page_record->vmi                = vmi;
		page_record->mem_event_rw       = g_new0(vmi_event_t, 1);
		page_record->mem_event_x        = g_new0(vmi_event_t, 1);
		page_record->mem_event_rw->data = page_record;
		page_record->mem_event_x->data  = page_record;

		page_record->children = g_hash_table_new_full(NULL,
		                                              NULL,
		                                              NULL,
		                                              destroy_trap);

		g_hash_table_insert(vf_page_record_collection,
		                    GSIZE_TO_POINTER(page),
		                    page_record);

		SETUP_MEM_EVENT(page_record->mem_event_rw,
		                page,
		                VMI_MEMACCESS_RW,
		                trap_mem_callback_rw,
		                0);

		SETUP_MEM_EVENT(page_record->mem_event_x,
		                page, VMI_MEMACCESS_X,
		                trap_mem_callback_x,
		                0);

		status = vmi_register_event(vmi, page_record->mem_event_rw);
		if (VMI_SUCCESS != status) {
			goto done;
		}
	} else {
		/* We already have a page record for this page in collection. */
		paddr_record = g_hash_table_lookup(page_record->children,
		                                GSIZE_TO_POINTER(pa));
		if (NULL != paddr_record) {
			/* We have a paddr record too; done (no error). */
			goto done;
		}
	}

	/* Create physical-address record and add to page record. */
	paddr_record                =  g_new0(vf_paddr_record, 1);
	paddr_record->breakpoint_va =  va;
	paddr_record->breakpoint_pa =  pa;
	paddr_record->parent        =  page_record;
	paddr_record->curr_inst     =  BREAKPOINT_INST;
	paddr_record->disabled      =  FALSE;
	paddr_record->identifier    = ~0; /* default 0xFFFF */

	status = vmi_read_8_pa(vmi, pa,  &paddr_record->orig_inst);
	if (VMI_SUCCESS != status) {
		paddr_record = NULL;
		goto done;
	}

	status = vmi_write_8_pa(vmi, pa, &paddr_record->curr_inst);
	if (VMI_SUCCESS != status) {
		paddr_record = NULL;
		goto done;
	}

	g_hash_table_insert(page_record->children,
	                    GSIZE_TO_POINTER(pa),
	                    paddr_record);

done:
	/* TODO: Should undo state (e.g., remove from hash tables) on error */
	return paddr_record;
}

void
vf_destroy_page_record(vf_page_record *page_record) {
	fprintf(stderr, "destroy page trap on 0x%lx\n", page_record->page);

	g_hash_table_remove(vf_page_record_collection,
	                    GSIZE_TO_POINTER(page_record->page));
}

void
vf_destroy_trap(vf_paddr_record *paddr_record) {
	g_hash_table_remove(paddr_record->parent->children,
	                    GSIZE_TO_POINTER(paddr_record->breakpoint_pa));

	if (0 == g_hash_table_size(paddr_record->parent->children)) {
		vf_destroy_page_record(paddr_record->parent);
	}
}

void
destroy_page_record(gpointer data) {
	vf_page_record *page_record = data;

	vmi_clear_event(page_record->vmi, page_record->mem_event_rw, NULL);
	vmi_clear_event(page_record->vmi, page_record->mem_event_x, NULL);

	free(page_record->mem_event_rw);
	free(page_record->mem_event_x);

	g_hash_table_destroy(page_record->children);

	free(page_record);
}

void
destroy_trap(gpointer data) {
	vf_paddr_record *paddr_record = data;

	vmi_write_8_pa(paddr_record->parent->vmi,
	               paddr_record->breakpoint_pa,
	              &paddr_record->orig_inst);

	free(paddr_record);
}

addr_t
get_syscall_ret_addr(vmi_instance_t vmi, addr_t syscall_start) {
	csh handle;
	cs_insn *inst;
	size_t count, call_offset = ~0;
	addr_t ret = 0;
	uint8_t code[4096]; /* Assume CALL is within first KB. */

	addr_t syscall_start_p = vmi_translate_kv2p(vmi, syscall_start);
	if (0 == syscall_start_p) {
		fprintf(stderr, "failed to read instructions from 0x%"
		                 PRIx64".\n", syscall_start);
		goto done;
	}

	/* Read kernel instructions into code. */
	status_t status = vmi_read_pa(vmi, syscall_start_p, code, sizeof(code));
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

static void
close_handler (int sig)
{
	interrupted = sig;
}

static bool
set_up_signal_handler (struct sigaction act)
{
	int status = 0;

	act.sa_handler = close_handler;
	act.sa_flags = 0;

	status = sigemptyset(&act.sa_mask);
	if (-1 == status) {
		perror("failed to initialize signal handler.\n");
		goto done;
	}

	status = sigaction(SIGHUP,  &act, NULL);
	if (-1 == status) {
		perror("failed to register SIGHUP handler.\n");
		goto done;
	}

	status = sigaction(SIGTERM, &act, NULL);
	if (-1 == status) {
		perror("failed to register SIGTERM handler.\n");
		goto done;
	}

	status = sigaction(SIGINT,  &act, NULL);
	if (-1 == status) {
		perror("failed to register SIGINT handler.\n");
		goto done;
	}

	status = sigaction(SIGALRM, &act, NULL);
	if (-1 == status) {
		perror("failed to register SIGALRM handler.\n");
		goto done;
	}

done:
	return -1 != status;
}

int
main (int argc, char **argv) {
	struct sigaction act;
	status_t status = VMI_FAILURE;
	vmi_instance_t vmi;
	char *name = NULL;

	if (argc < 2){
		fprintf(stderr, "Usage: syscall_events_example <name of VM>\n");
		exit(EXIT_FAILURE);
	}

	/* Arg 1 is the VM name. */
	name = argv[1];

	if (!set_up_signal_handler(act)) {
		goto done;
	}

	vf_page_record_collection = g_hash_table_new_full(NULL,
	                                                  NULL,
	                                                  NULL,
	                                                  destroy_page_record);

	/* Initialize the libvmi library. */
	status = vmi_init(&vmi, VMI_XEN | VMI_INIT_COMPLETE | VMI_INIT_EVENTS, name);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to init LibVMI library.\n");
		goto done;
	} else {
		printf("LibVMI init succeeded!\n");
	}

	vmi_pause_vm(vmi);

	/* Call interrupt_callback in response to an interrupt event. */
	SETUP_INTERRUPT_EVENT(&trap_int_event, 0, interrupt_callback);
	status = vmi_register_event(vmi, &trap_int_event);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to setup interrupt event\n");
		goto done;
	}

	addr_t lstar = 0;
	status = vmi_get_vcpureg(vmi, &lstar, MSR_LSTAR, 0);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to setup interrupt event\n");
		goto done;
	}

	addr_t syscall_ret_addr = get_syscall_ret_addr(vmi, lstar);
	if (0 == syscall_ret_addr) {
		goto done;
	}

	syscall_ret_trap = vf_setup_paddr_trap(vmi, syscall_ret_addr);
	if (NULL == syscall_ret_trap) {
		fprintf(stderr, "failed to set memory trap on syscall return\n");
	}

	vf_disable_trap(syscall_ret_trap);

	for (int i = 0; i < countof(SYSCALLS); i++) {
		bool worked = false;
		for (int x = 0; x < countof(MONITORED_SYSCALLS); x++) {
			if (0 == strcmp(SYSCALLS[i], MONITORED_SYSCALLS[x])) {
				worked = true;
				break;
			}
		}
		if (worked) {
			addr_t sysaddr = vmi_translate_ksym2v(vmi, SYSCALLS[i]);

			if (sysaddr != 0) {
				vf_paddr_record *syscall_trap = vf_setup_paddr_trap(vmi, sysaddr);
				if (NULL == syscall_ret_trap) {
					fprintf(stderr, "failed to set memory trap on %s\n",
					                 SYSCALLS[i]);
				}
				syscall_trap->identifier = i;
			}
		}
	}

	vmi_resume_vm(vmi);

	printf("Waiting for events...\n");

	while(!interrupted){
		status = vmi_events_listen(vmi,500);
		if (status != VMI_SUCCESS) {
			printf("Error waiting for events, quitting...\n");
			goto done;
		}
	}

done:
	printf("Shutting down guestrace\n");

	g_hash_table_destroy(vf_page_record_collection);

	if (vmi != NULL) {
		vmi_destroy(vmi);
	}

	exit(VMI_SUCCESS == status ? EXIT_SUCCESS : EXIT_FAILURE);
}

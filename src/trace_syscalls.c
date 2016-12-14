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

/* The Windows code follows this strategy:
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

#define NUM_SYSCALLS 0x191
const char *NUM_TO_SYSCALL[NUM_SYSCALLS];

GHashTable *vf_page_traps; /* (pa >> 12) -> vf_page_trap */

typedef struct vf_page_trap {
	addr_t page;
	vmi_event_t *mem_event_rw;
	vmi_event_t *mem_event_x;
	GHashTable *children;
	vmi_instance_t vmi;
} vf_page_trap;

typedef struct vf_trap {
	addr_t breakpoint_va;
	addr_t breakpoint_pa;
	uint8_t orig_inst;
	uint8_t curr_inst;
	vf_page_trap *parent;
	uint8_t disabled; /* enabled if 0, disabled otherwise */
	uint16_t identifier; /* syscall identifier because we nix RAX */
} vf_trap;

vmi_event_t trap_int_event;
vf_trap *syscall_ret_trap;

vf_trap *vf_trap_from_va(vmi_instance_t vmi, addr_t va);
vf_trap *vf_trap_from_pa(vmi_instance_t vmi, addr_t pa);
status_t vf_enable_trap(vf_trap *curr_trap);
status_t vf_disable_trap(vf_trap *curr_trap);
void destroy_trap(gpointer data); /* private routine for freeing memory */

event_response_t trap_mem_callback_rw(vmi_instance_t vmi, vmi_event_t *event);
event_response_t trap_mem_callback_x(vmi_instance_t vmi, vmi_event_t *event);

void
trap_mem_callback_x_reset(vmi_event_t *event, status_t rc) {
	vf_page_trap *curr_trap = (vf_page_trap*)event->data;

	vmi_register_event(curr_trap->vmi, curr_trap->mem_event_rw);
}

void
trap_mem_callback_rw_reset(vmi_event_t *event, status_t rc) {
	vf_page_trap *curr_trap = (vf_page_trap*)event->data;

	vmi_register_event(curr_trap->vmi, curr_trap->mem_event_x);
}

void
reset_interrupts_x(gpointer key, gpointer value, gpointer user_data) {
	vf_trap *curr_trap  = value;
	vmi_instance_t *vmi = user_data;

	vmi_write_8_pa(*vmi, curr_trap->breakpoint_pa, &curr_trap->curr_inst);
}

event_response_t
trap_mem_callback_x(vmi_instance_t vmi, vmi_event_t *event) {
	fprintf(stderr, "mem exe at %lx\n", event->mem_event.gla);

	vf_page_trap *curr_page_trap = (vf_page_trap*)event->data;

	g_hash_table_foreach(curr_page_trap->children, reset_interrupts_x, &vmi);

	vmi_clear_event(vmi, event, &trap_mem_callback_x_reset);

	return VMI_EVENT_RESPONSE_NONE;
}

void
reset_interrupts_rw(gpointer key, gpointer value, gpointer user_data) {
	vf_trap *curr_trap = value;
	vmi_instance_t *vmi = user_data;

	vmi_write_8_pa(*vmi, curr_trap->breakpoint_pa, &curr_trap->orig_inst);
}

event_response_t
trap_mem_callback_rw(vmi_instance_t vmi, vmi_event_t *event) {
	fprintf(stderr, "mem r/w at %lx\n", event->mem_event.gla);

	vf_page_trap *curr_page_trap = (vf_page_trap*)event->data;

	g_hash_table_foreach(curr_page_trap->children, reset_interrupts_rw, &vmi);

	vmi_clear_event(vmi, event, &trap_mem_callback_rw_reset);

	return VMI_EVENT_RESPONSE_NONE;
}

event_response_t
trap_int_reset(vmi_instance_t vmi, vmi_event_t *event) {
	event_response_t status = VMI_EVENT_RESPONSE_NONE;

	vf_trap *curr_trap = vf_trap_from_va(vmi, event->interrupt_event.gla);

	if (curr_trap == NULL) {
		event->interrupt_event.reinject = 1;
		/* TODO: Ensure this does the right thing: */
		status = VMI_EVENT_RESPONSE_EMULATE;
		goto done;
	}

	curr_trap->curr_inst = BREAKPOINT_INST;

	vmi_write_8_pa(vmi, curr_trap->breakpoint_pa, &curr_trap->curr_inst);

done:
	return status;
}

event_response_t
trap_int_callback(vmi_instance_t vmi, vmi_event_t *event) {
	event_response_t status = VMI_EVENT_RESPONSE_NONE;

	vf_trap *curr_trap = vf_trap_from_va(vmi, event->interrupt_event.gla);

	if (curr_trap == NULL) {
		event->interrupt_event.reinject = 1;
		/* TODO: Ensure this does the right thing: */
		status = VMI_EVENT_RESPONSE_EMULATE;
		goto done;
	}

	event->interrupt_event.reinject = 0;

	curr_trap->curr_inst = curr_trap->orig_inst;

	vmi_write_8_pa(vmi, curr_trap->breakpoint_pa, &curr_trap->curr_inst);

	if (curr_trap->disabled != 0) {
		goto done;
	}

	if (curr_trap != syscall_ret_trap) {
		print_syscall(vmi, event, curr_trap->identifier);
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
vf_enable_trap(vf_trap *curr_trap) {
	status_t status = VMI_SUCCESS;

	if (curr_trap->disabled != 0) {
		curr_trap->curr_inst = BREAKPOINT_INST;
		vmi_write_8_pa(curr_trap->parent->vmi, curr_trap->breakpoint_pa, &curr_trap->curr_inst);
		curr_trap->disabled = 0;
	} else {
		status = VMI_FAILURE;
	}

	return status;
}

status_t
vf_disable_trap(vf_trap *curr_trap) {
	status_t status = VMI_SUCCESS;

	if (curr_trap->disabled == 0) {
		curr_trap->curr_inst = curr_trap->orig_inst;
		vmi_write_8_pa(curr_trap->parent->vmi, curr_trap->breakpoint_pa, &curr_trap->curr_inst);
		curr_trap->disabled = 1;
	} else {
		status = VMI_FAILURE;
	}

	return status;
}

vf_trap *
vf_trap_from_va(vmi_instance_t vmi, addr_t va) {
	return vf_trap_from_pa(vmi, vmi_translate_kv2p(vmi, va));
}

vf_trap *
vf_trap_from_pa(vmi_instance_t vmi, addr_t pa) {
	vf_trap *curr_trap = NULL;

	addr_t page = pa >> 12;

	/* get page event */
	vf_page_trap *curr_page_trap = g_hash_table_lookup(vf_page_traps, (void*)page);

	if (NULL == curr_page_trap) { /* make sure we own this interrupt */
		goto done;
	}

	/* get individual trap */
	curr_trap = g_hash_table_lookup(curr_page_trap->children, (void*)pa);

done:
	return curr_trap;
}

/* TODO: Error handling */
vf_trap *
vf_create_trap(vmi_instance_t vmi, addr_t va) {
	addr_t pa = vmi_translate_kv2p(vmi, va);
	addr_t page = pa >> 12;

	vf_page_trap *curr_page_trap = NULL;
	vf_trap *curr_trap = NULL;

	if ((curr_page_trap = g_hash_table_lookup(vf_page_traps, (void*)page)) != NULL) {
		if ((curr_trap = g_hash_table_lookup(curr_page_trap->children, (void*)pa)) != NULL) {
			goto done;
		}
	} else {
		fprintf(stderr, "Creating new page trap on 0x%lx\n", page);
		curr_page_trap = calloc(1, sizeof(vf_page_trap));
		curr_page_trap->page = page;
		curr_page_trap->vmi = vmi;
		curr_page_trap->mem_event_rw = calloc(1, sizeof(vmi_event_t));
		curr_page_trap->mem_event_x = calloc(1, sizeof(vmi_event_t));

		SETUP_MEM_EVENT(curr_page_trap->mem_event_rw, page, VMI_MEMACCESS_RW, trap_mem_callback_rw, 0);
		SETUP_MEM_EVENT(curr_page_trap->mem_event_x, page, VMI_MEMACCESS_X, trap_mem_callback_x, 0);

		curr_page_trap->mem_event_rw->data = curr_page_trap;
		curr_page_trap->mem_event_x->data = curr_page_trap;

		curr_page_trap->children = g_hash_table_new_full(NULL, NULL, NULL, destroy_trap);

		g_hash_table_insert(vf_page_traps, (void*)page, curr_page_trap);

		vmi_register_event(vmi, curr_page_trap->mem_event_rw);
	}

	curr_trap = calloc(1, sizeof(vf_trap));

	curr_trap->breakpoint_va = va;
	curr_trap->breakpoint_pa = pa;
	curr_trap->parent = curr_page_trap;
	curr_trap->curr_inst = BREAKPOINT_INST;
	curr_trap->disabled = 0; /* default enabled */
	curr_trap->identifier = ~0; /* default 0xFFFF */

	vmi_read_8_pa(vmi, pa, &curr_trap->orig_inst);
	vmi_write_8_pa(vmi, pa, &curr_trap->curr_inst);

	g_hash_table_insert(curr_page_trap->children, (void*)pa, curr_trap);

done:
	return curr_trap;
}

void
vf_destroy_page_trap(vf_page_trap *curr_page_trap) {
	fprintf(stderr, "Destroying page trap on 0x%lx\n", curr_page_trap->page);

	g_hash_table_remove(vf_page_traps, (void*)curr_page_trap->page);
}

void
vf_destroy_trap(vf_trap *curr_trap) {
	g_hash_table_remove(curr_trap->parent->children, (void*)curr_trap->breakpoint_pa);

	if (g_hash_table_size(curr_trap->parent->children) == 0) {
		vf_destroy_page_trap(curr_trap->parent);
	}
}

void
destroy_page_trap(gpointer data) {
	vf_page_trap *curr_page_trap = data;

	vmi_clear_event(curr_page_trap->vmi, curr_page_trap->mem_event_rw, NULL);
	vmi_clear_event(curr_page_trap->vmi, curr_page_trap->mem_event_x, NULL);

	free(curr_page_trap->mem_event_rw);
	free(curr_page_trap->mem_event_x);

	g_hash_table_destroy(curr_page_trap->children);

	free(curr_page_trap);
}

void
destroy_trap(gpointer data) {
	vf_trap *curr_trap = data;

	vmi_write_8_pa(curr_trap->parent->vmi, curr_trap->breakpoint_pa, &curr_trap->orig_inst);

	free(curr_trap);
}

static int interrupted = 0;
static void
close_handler(int sig){
	interrupted = sig;
}

addr_t
setup_syscall_ret(vmi_instance_t vmi, addr_t syscall_start) {
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
			if (strcmp(inst[i].mnemonic, "call") == 0) {
				if (strcmp(inst[i].op_str, "r10") == 0) {
					call_offset = inst[i + 1].address;
					break;
				}
			}
			//fprintf(stderr, "%lx: %s %s\n", inst[i].address + syscall_start, inst[i].mnemonic, inst[i].op_str);
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

int
main (int argc, char **argv) {
	status_t status = VMI_SUCCESS;
	vmi_instance_t vmi;
	struct sigaction act;
	act.sa_handler = close_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP,  &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT,  &act, NULL);
	sigaction(SIGALRM, &act, NULL);

	vf_page_traps = g_hash_table_new_full(NULL, NULL, NULL, destroy_page_trap);

	char *name = NULL;

	if(argc < 2){
		fprintf(stderr, "Usage: syscall_events_example <name of VM>\n");
		exit(1);
	}

	// Arg 1 is the VM name.
	name = argv[1];

	// Initialize the libvmi library.
	if (vmi_init(&vmi, VMI_XEN | VMI_INIT_COMPLETE | VMI_INIT_EVENTS, name) == VMI_FAILURE){
		printf("Failed to init LibVMI library.\n");
		goto done;
	} else{
		printf("LibVMI init succeeded!\n");
	}

	vmi_pause_vm(vmi);

	SETUP_INTERRUPT_EVENT(&trap_int_event, 0, trap_int_callback);
	vmi_register_event(vmi, &trap_int_event);

	addr_t lstar = 0;
	vmi_get_vcpureg(vmi, &lstar, MSR_LSTAR, 0);

	fprintf(stderr, "%lx\n", lstar);

	addr_t syscall_ret_addr = setup_syscall_ret(vmi, lstar);

	if (0 == syscall_ret_addr) {
		goto done;
	}

	syscall_ret_trap = vf_create_trap(vmi, syscall_ret_addr);
	vf_disable_trap(syscall_ret_trap);

	//const char *checkthese[] = {"NtOpenFile", "NtOpenSymbolicLinkObject", "NtCreateFile", "NtOpenDirectoryObject", "NtOpenProcess", "NtReadFile", "NtWriteFile"};

	const char *checkthese[] = {"NtCreateFile", "NtOpenSymbolicLinkObject", "NtOpenDirectoryObject", "NtOpenProcess"};

	for (int i = 0; i < NUM_SYSCALLS; i++) {
	bool worked = false;
	for (int x = 0; x < sizeof(checkthese) / sizeof(char *); x++) {
		if (strcmp(NUM_TO_SYSCALL[i], checkthese[x]) == 0) {
			worked = true;
			break;
		}
	}
		if (worked) {
			addr_t sysaddr = vmi_translate_ksym2v(vmi, NUM_TO_SYSCALL[i]);

			if (sysaddr != 0) {
				vf_trap *syscall_trap = vf_create_trap(vmi, sysaddr);
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

	g_hash_table_destroy(vf_page_traps);

	if (vmi != NULL) {
		vmi_destroy(vmi);
	}

	return 0;
}

/* KeServiceDescriptorTable */
const char *NUM_TO_SYSCALL[NUM_SYSCALLS] = {
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

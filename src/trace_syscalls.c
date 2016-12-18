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
static const uint8_t VF_BREAKPOINT_INST = 0xCC;

/*
 * Global interrupt event that gets trigged on any VF_BREAKPOINT_INST callback
 */
static vmi_event_t vf_breakpoint_event;

/*
 * Handle terminating signals by setting interrupted flag. This allows
 * a graceful exit.
 */
static int vf_interrupted = 0;

static GHashTable  *vf_page_record_collection;

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
	gboolean enabled;
	uint16_t identifier; /* syscall identifier because we nix RAX */
} vf_paddr_record;

static vf_paddr_record *vf_syscall_ret_trap;

/*
 * Emplace the breakpoint associated with paddr_record.
 */
static status_t
vf_emplace_breakpoint(vf_paddr_record *paddr_record) {
	paddr_record->curr_inst = VF_BREAKPOINT_INST;
	return vmi_write_8_pa(paddr_record->parent->vmi,
	                      paddr_record->breakpoint_pa,
	                     &paddr_record->curr_inst);
}

/*
 * Remove the breakpoint associated with paddr_record.
 */
static status_t
vf_remove_breakpoint(vf_paddr_record *paddr_record) {
	paddr_record->curr_inst = paddr_record->orig_inst;
	return vmi_write_8_pa(paddr_record->parent->vmi,
	                      paddr_record->breakpoint_pa,
	                     &paddr_record->curr_inst);
}

static void
vf_destroy_page_record(gpointer data) {
	vf_page_record *page_record = data;

	fprintf(stderr, "Destroying page_record on page %lx\n", page_record->page);

	vmi_clear_event(page_record->vmi, page_record->mem_event_rw, NULL);
	vmi_clear_event(page_record->vmi, page_record->mem_event_x, NULL);

	g_free(page_record->mem_event_rw);
	g_free(page_record->mem_event_x);

	g_hash_table_destroy(page_record->children);

	g_free(page_record);
}

static void
vf_destroy_paddr_record(gpointer data) {
	vf_paddr_record *paddr_record = data;

	fprintf(stderr, "Destroying paddr_record on va %lx\n", paddr_record->breakpoint_va);

	vf_remove_breakpoint(paddr_record);

	g_free(paddr_record);
}

static void
vf_mem_x_switch_trap_to_rw_cb(vmi_event_t *event, status_t rc) {
	vf_page_record *paddr_record = (vf_page_record *) event->data;

	vmi_register_event(paddr_record->vmi, paddr_record->mem_event_rw);
}

static void
vf_mem_rw_switch_trap_to_x_cb(vmi_event_t *event, status_t rc) {
	vf_page_record *paddr_record = (vf_page_record *) event->data;

	vmi_register_event(paddr_record->vmi, paddr_record->mem_event_x);
}

static void
vf_emplace_breakpoint_cb(gpointer key, gpointer value, gpointer user_data) {
	vf_paddr_record *paddr_record = value;

	vf_emplace_breakpoint(paddr_record);
}

/*
 * Callback invoked on an execute in a monitored page.
 * Replace the original instruction fragment/byte with a breakpoint and
 * set guest to trap on R/W of monitored page.
 */
static event_response_t
vf_mem_x_cb(vmi_instance_t vmi, vmi_event_t *event) {
	fprintf(stderr, "mem exe at %lx\n", event->mem_event.gla);

	vf_page_record *trapped_page_record = (vf_page_record *) event->data;

	g_hash_table_foreach(trapped_page_record->children, vf_emplace_breakpoint_cb, NULL);

	vmi_clear_event(vmi, event, &vf_mem_x_switch_trap_to_rw_cb);

	return VMI_EVENT_RESPONSE_NONE;
}

static void
vf_remove_breakpoint_cb(gpointer key, gpointer value, gpointer user_data) {
	vf_paddr_record *paddr_record = value;

	vf_remove_breakpoint(paddr_record);
}

/*
 * Callback invoked on a R/W of a monitored page (likely kernel patch protection).
 * Replace the related breakpoint with the original instruction fragment/byte and
 * set guest to trap on execute of monitored page.
 */
static event_response_t
vf_mem_rw_cb(vmi_instance_t vmi, vmi_event_t *event) {
	fprintf(stderr, "mem r/w at %lx\n", event->mem_event.gla);

	vf_page_record *trapped_page_record = (vf_page_record *) event->data;

	g_hash_table_foreach(trapped_page_record->children, vf_remove_breakpoint_cb, NULL);

	vmi_clear_event(vmi, event, &vf_mem_rw_switch_trap_to_x_cb);

	return VMI_EVENT_RESPONSE_NONE;
}

/*
 * Return the paddr_record associated with the given physical address.
 *
 * First obtain the page record associated with the physical address's
 * page, and then obtain the child within that record which is associated
 * with the physical address. Recall that a given page might contain
 * multiple breakpoints.
 */
static vf_paddr_record *
vf_paddr_record_from_pa(vmi_instance_t vmi, addr_t pa) {
	vf_paddr_record *paddr_record = NULL;
	vf_page_record  *page_record  = NULL;

	addr_t page = pa >> 12;

	page_record = g_hash_table_lookup(vf_page_record_collection,
	                                          GSIZE_TO_POINTER(page));
	if (NULL == page_record) {
		goto done;
	}

	paddr_record = g_hash_table_lookup(page_record->children,
	                                   GSIZE_TO_POINTER(pa));

done:
	return paddr_record;
}

/* Return the paddr_record associated with the given virtual address. */
static vf_paddr_record *
vf_paddr_record_from_va(vmi_instance_t vmi, addr_t va) {
	return vf_paddr_record_from_pa(vmi, vmi_translate_kv2p(vmi, va));
}

/*
 * Callback wrapper around vf_emplace_breakpoint. Used to emplace the breakpoint
 * after single stepping past the original instruction the breakpoint with
 * replace.
 */
static event_response_t
vf_emplace_breakpoint_vmi_cb(vmi_instance_t vmi, vmi_event_t *event) {
	event_response_t status = VMI_EVENT_RESPONSE_NONE;

	vf_paddr_record *paddr_record = vf_paddr_record_from_va(vmi,
	                                                        event->interrupt_event.gla);

	if (NULL == paddr_record) {
		event->interrupt_event.reinject = 1;
		/* TODO: Ensure this does the right thing: */
		status = VMI_EVENT_RESPONSE_EMULATE;
		goto done;
	}

	status = vf_emplace_breakpoint(paddr_record);

done:
	return status;
}

/*
 * Enable/emplace the breakpoint associated with paddr_record. The breakpoint
 * must be disabled upon calling this function.
 */
static status_t
vf_enable_breakpoint(vf_paddr_record *paddr_record) {
	status_t status = VMI_SUCCESS;

	/* assertion here breaks on multiple threads? */
	if (paddr_record->enabled) {
		goto done;
	}

	/* this check is purely for optimization, so we don't overwrite the same thing */
	if (paddr_record->curr_inst == paddr_record->orig_inst) {
		vf_emplace_breakpoint(paddr_record);
	}

	paddr_record->enabled = TRUE;

done:
	return status;
}


/*
 * Disable/remove the breakpoint associated with paddr_record. The breakpoint
 * must be enabled upon calling this function.
 */
static status_t
vf_disable_breakpoint(vf_paddr_record *paddr_record) {
	status_t status = VMI_SUCCESS;

	/* assertion here breaks on multiple threads? */
	if (!paddr_record->enabled) {
		goto done;
	}

	/* this check is purely for optimization, so we don't overwrite the same thing */
	if (paddr_record->curr_inst != paddr_record->orig_inst) {
		vf_remove_breakpoint(paddr_record);
	}

	paddr_record->enabled = FALSE;

done:
	return status;
}

/*
 * Service a triggered breakpoint. Replace the breakpoint with the original
 * instruction fragment/byte and possibly print the system call parameters
 * or return value.
 *
 * In the case of a system call, enable the syscall ret
 * breakpoint and schedule the syscall breakpoint to be emplaced after a single
 * stepping beyond the original instruction.
 *
 * In the case of a system return, disable the system return breakpoint until
 * the next system call enables it.
 */
static event_response_t
vf_breakpoint_cb(vmi_instance_t vmi, vmi_event_t *event) {
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

	if (!paddr_record->enabled) {
		goto done;
	}

	if (paddr_record != vf_syscall_ret_trap) {
		print_syscall(vmi, event, paddr_record->identifier);
		vf_enable_breakpoint(vf_syscall_ret_trap);
		vmi_step_event(vmi, event, event->vcpu_id, 1, vf_emplace_breakpoint_vmi_cb);
	} else {
		print_sysret(vmi, event);
		vf_disable_breakpoint(vf_syscall_ret_trap);
	}

done:
	return status;
}

/*
 * Ensure there exists a memory trap on the page containing virtual address va,
 * and create a page record if it does not yet exist. Add a physical-address record
 * corresponding to va to the page record's collection of children.
 */
static vf_paddr_record *
vf_setup_mem_trap(vmi_instance_t vmi, addr_t va) {
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
		                                              vf_destroy_paddr_record);

		g_hash_table_insert(vf_page_record_collection,
		                    GSIZE_TO_POINTER(page),
		                    page_record);

		SETUP_MEM_EVENT(page_record->mem_event_rw,
		                page_record->page,
		                VMI_MEMACCESS_RW,
		                vf_mem_rw_cb,
		                0);

		SETUP_MEM_EVENT(page_record->mem_event_x,
		                page_record->page,
		                VMI_MEMACCESS_X,
		                vf_mem_x_cb,
		                0);

		status = vmi_register_event(vmi, page_record->mem_event_rw);
		if (VMI_SUCCESS != status) {
			fprintf(stderr, "failed to register event\n");
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
	paddr_record->curr_inst     =  VF_BREAKPOINT_INST;
	paddr_record->enabled       =  TRUE;
	paddr_record->identifier    = ~0; /* default 0xFFFF */

	status = vmi_read_8_pa(vmi, pa, &paddr_record->orig_inst);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to read original instruction fragment %lx\n", pa);
		g_free(paddr_record);
		paddr_record = NULL;
		goto done;
	}

	status = vmi_write_8_pa(vmi, pa, &paddr_record->curr_inst);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to write breakpoint at %lx\n", pa);
		g_free(paddr_record);
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

/*
 * Disassemble the kernel and find the appropriate point for a breakpoint
 * which allows guestrace to determine a system call's return value. Return
 * the address.
 */
static addr_t
vf_get_syscall_ret_addr(vmi_instance_t vmi, addr_t syscall_start) {
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
vf_close_handler (int sig)
{
	vf_interrupted = sig;
}

static bool
vf_set_up_signal_handler (struct sigaction act)
{
	int status = 0;

	act.sa_handler = vf_close_handler;
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

/*
 * Find the appropriate place for a breakpoint which will enable guestrace to
 * read a system call's return value, setup the breakpoint, and setup
 * a memory trap. Leave the breakpoint disabled; guestrace will enable it
 * upon an execution of the return-value page.
 */
static status_t
vf_find_syscall_ret_setup_disabled_breakpoint_and_mem_trap(vmi_instance_t vmi)
{
	status_t status;

	/* Call vf_breakpoint_cb in response to an interrupt event. */
	SETUP_INTERRUPT_EVENT(&vf_breakpoint_event, 0, vf_breakpoint_cb);
	status = vmi_register_event(vmi, &vf_breakpoint_event);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to setup interrupt event\n");
		goto done;
	}

	addr_t lstar = 0;
	status = vmi_get_vcpureg(vmi, &lstar, MSR_LSTAR, 0);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to get MSR_LSTAR address\n");
		goto done;
	}

	addr_t syscall_ret_addr = vf_get_syscall_ret_addr(vmi, lstar);
	if (0 == syscall_ret_addr) {
		status = VMI_FAILURE;
		goto done;
	}

	vf_syscall_ret_trap = vf_setup_mem_trap(vmi, syscall_ret_addr);
	if (NULL == vf_syscall_ret_trap) {
		status = VMI_FAILURE;
		fprintf(stderr, "failed to set memory trap on syscall return\n");
		goto done;
	}

	status = vf_disable_breakpoint(vf_syscall_ret_trap);

done:
	return status;
}

#define countof(array) (sizeof(array) / sizeof((array)[0]))

/*
 * For each of the system calls libvmi is interested in, establish a memory trap
 * on the page containing the system call handler's first instruction. An
 * execute trap will cause guestrace to emplace a breakpoint. A read/write trap
 * (i.e., kernel patch protection) will cause guestrace to restore the original
 * instruction.
 */
static status_t
vf_find_syscalls_and_setup_mem_trap(vmi_instance_t vmi)
{
	status_t status = VMI_SUCCESS;

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

	static const char *MONITORED_SYSCALLS[] = {
		"NtCreateFile",
		"NtOpenProcess"
	};

	for (int i = 0; i < countof(SYSCALLS); i++) {
		for (int j = 0; j < countof(MONITORED_SYSCALLS); j++) {
			if (strcmp(SYSCALLS[i], MONITORED_SYSCALLS[j])) {
				continue;
			}

			addr_t sysaddr = vmi_translate_ksym2v(vmi, MONITORED_SYSCALLS[j]);
			if (0 == sysaddr) {
				fprintf(stderr, "could not find symbol %s\n", MONITORED_SYSCALLS[j]);
				status = VMI_FAILURE;
				goto done;
			}

			vf_paddr_record *syscall_trap = vf_setup_mem_trap(vmi, sysaddr);
			if (NULL == syscall_trap) {
				fprintf(stderr, "failed to set memory trap on %s\n",
						 MONITORED_SYSCALLS[j]);
				status = VMI_FAILURE;
				goto done;
			}

			/* set identifier to what RAX would be during syscall */
			syscall_trap->identifier = i;

			break;
		}
	}

done:
	return status;
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

	if (!vf_set_up_signal_handler(act)) {
		goto done;
	}

	/* Initialize the libvmi library. */
	status = vmi_init(&vmi, VMI_XEN | VMI_INIT_COMPLETE | VMI_INIT_EVENTS, name);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to init LibVMI library.\n");
		goto done;
	} else {
		printf("LibVMI init succeeded!\n");
	}

	vf_page_record_collection = g_hash_table_new_full(NULL,
	                                                  NULL,
	                                                  NULL,
	                                                  vf_destroy_page_record);

	vmi_pause_vm(vmi);

	status = vf_find_syscall_ret_setup_disabled_breakpoint_and_mem_trap(vmi);
	if (VMI_SUCCESS != status) {
		goto done;
	}

	status = vf_find_syscalls_and_setup_mem_trap(vmi);
	if (VMI_SUCCESS != status) {
		goto done;
	}

	vmi_resume_vm(vmi);

	printf("Waiting for events...\n");

	while(!vf_interrupted){
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

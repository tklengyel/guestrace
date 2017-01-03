#include <capstone/capstone.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "functions_linux.h"

struct os_functions os_functions_linux = {
	.print_syscall         = vf_linux_print_syscall,
	.print_sysret          = vf_linux_print_sysret,
	.find_syscalls_and_setup_mem_traps \
	                       = vf_linux_find_syscalls_and_setup_mem_traps,
	.set_up_sysret_handler = vf_linux_set_up_sysret_handler,
};

/* 
 * Replace the first byte of the system-call handler with INT 3. The address of
 * the system call handler is available in MSR_LSTAR.
 */
bool
vf_linux_find_syscalls_and_setup_mem_traps(vf_state *state)
{
	status_t status = false;
	addr_t sysaddr;
	vf_paddr_record *syscall_trap;

	status = vmi_get_vcpureg(state->vmi, &sysaddr, MSR_LSTAR, 0);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to read MSR_LSTAR.\n");
		goto done;
	}

	syscall_trap = vf_setup_mem_trap(state, sysaddr);
	if (NULL == syscall_trap) {
		fprintf(stderr, "failed to set syscall memory trap\n");
		goto done;
	}

done:
	return status == VMI_SUCCESS ? true : false;
}

/*
 * Replace the first byte of the instruction following the CALL instruction
 * in the kernel's system-call handler with INT 3. This is the first
 * practical point at which we have access to the system call's return value
 * We find the address of the CALL instruction by disassembling the kernel core.
 */
bool
vf_linux_set_up_sysret_handler(vf_state *state)
{
	csh handle;
	cs_insn *inst;
	size_t count, call_offset = ~0;
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
		size_t i;
		for (i = 0; i < count; i++) {
			if (!strcmp(inst[i].mnemonic, "call")) {
				call_offset = inst[i + 1].address;
				break;
			}
		}
		cs_free(inst, count);
	} else {
		fprintf(stderr, "failed to disassemble system-call handler\n");
		status = VMI_FAILURE;
		goto done;
	}

	if (~0 == call_offset) {
		fprintf(stderr, "did not find call in system-call handler\n");
		status = VMI_FAILURE;
		goto done;
	}

	cs_close(&handle);

	sysret_trap = vf_setup_mem_trap(state, lstar + call_offset);
        if (NULL == sysret_trap) {
		fprintf(stderr, "failed to create sysret memory trap\n");
		status = VMI_FAILURE;
		goto done;
        }

	vf_remove_breakpoint(sysret_trap);

	status = VMI_SUCCESS;

done:
	return status == VMI_SUCCESS ? true : false;
}

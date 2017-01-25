#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "functions_linux.h"
#include "generated_linux.h"

struct os_functions os_functions_linux = {
	.print_syscall          = vf_linux_print_syscall,
	.print_sysret           = vf_linux_print_sysret,
	.find_syscalls_and_setup_mem_traps \
	                        = vf_linux_find_syscalls_and_setup_mem_traps,
	.find_return_point_addr = vf_linux_find_return_point_addr
};

bool
vf_linux_find_syscalls_and_setup_mem_traps(vf_state *state)
{
	return vf_find_syscalls_and_setup_mem_traps(state,
	                                            VM_LINUX_SYSCALLS,
	                                            VM_LINUX_TRACED_SYSCALLS);
}


bool
vf_linux_find_return_point_addr(vf_state *state)
{
	bool status = false;
	addr_t lstar;

	status_t ret = vmi_get_vcpureg(state->vmi, &lstar, MSR_LSTAR, 0);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "failed to get MSR_LSTAR address\n");
		goto done;
	}

	return_point_addr = vf_find_addr_after_instruction(state, lstar, "call", NULL);
	if (0 == return_point_addr) {
		fprintf(stderr, "failed to get return pointer address\n");
		goto done;
	}

	status = true;

done:
	return status;
}

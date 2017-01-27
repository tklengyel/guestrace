#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "guestrace-private.h"
#include "functions-linux.h"
#include "generated-linux.h"

struct os_functions os_functions_linux = {
	.find_syscalls_and_setup_mem_traps \
	                        = vf_linux_find_syscalls_and_setup_mem_traps,
	.find_return_point_addr = vf_linux_find_return_point_addr
};

bool
vf_linux_find_syscalls_and_setup_mem_traps(GTLoop *loop)
{
	return vf_find_syscalls_and_setup_mem_traps(loop,
	                                            VM_LINUX_SYSCALLS,
	                                            VM_LINUX_TRACED_SYSCALLS);
}


bool
vf_linux_find_return_point_addr(GTLoop *loop)
{
	bool status = false;
	addr_t lstar;

	status_t ret = vmi_get_vcpureg(loop->vmi, &lstar, MSR_LSTAR, 0);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "failed to get MSR_LSTAR address\n");
		goto done;
	}

	loop->return_point_addr = vf_find_addr_after_instruction(loop, lstar, "call", NULL);
	if (0 == loop->return_point_addr) {
		fprintf(stderr, "failed to get return pointer address\n");
		goto done;
	}

	status = true;

done:
	return status;
}

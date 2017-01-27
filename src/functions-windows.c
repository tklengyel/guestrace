#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "guestrace-private.h"

bool
vf_windows_find_return_point_addr(GTLoop *loop)
{
	bool status = false;
	addr_t lstar;

	status_t ret = vmi_get_vcpureg(loop->vmi, &lstar, MSR_LSTAR, 0);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "failed to get MSR_LSTAR address\n");
		goto done;
	}

	loop->return_point_addr = vf_find_addr_after_instruction(loop, lstar, "call", "r10");
	if (0 == loop->return_point_addr) {
		fprintf(stderr, "failed to get return pointer address\n");
		goto done;
	}

	status = true;

done:
	return status;
}

struct os_functions os_functions_windows = {
	.find_return_point_addr = vf_windows_find_return_point_addr
};

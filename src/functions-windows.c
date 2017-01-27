#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "guestrace-private.h"

addr_t
vf_windows_find_return_point_addr(GTLoop *loop)
{
	addr_t lstar, return_point_addr = 0;

	status_t ret = vmi_get_vcpureg(loop->vmi, &lstar, MSR_LSTAR, 0);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "failed to get MSR_LSTAR address\n");
		goto done;
	}

	return_point_addr = vf_find_addr_after_instruction(loop, lstar, "call", "r10");

done:
	return return_point_addr;
}

struct os_functions os_functions_windows = {
	.find_return_point_addr = vf_windows_find_return_point_addr
};

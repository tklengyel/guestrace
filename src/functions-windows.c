#include <libvmi/libvmi.h>

#include "guestrace.h"
#include "guestrace-private.h"
#include "trace-syscalls.h"

/*
 * Within the kernel's system-call handler function (that function pointed to
 * by the value in register LSTAR) there exists a call instruction which
 * invokes the per-system-call handler function. The function here finds
 * the address immediately following the call instruction. This is
 * necessary to later differentiate per-system-call handler functions which
 * are returning directly to the kernel's system-call handler function from
 * those that have been called in a nested manner.
 */
addr_t
_gt_windows_find_return_point_addr(GtLoop *loop)
{
	addr_t lstar, return_point_addr = 0;

	status_t ret = vmi_get_vcpureg(loop->vmi, &lstar, MSR_LSTAR, 0);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "failed to get MSR_LSTAR address\n");
		goto done;
	}

	return_point_addr = _gt_find_addr_after_instruction(loop,
	                                                   lstar,
	                                                  "call",
	                                                  "r10");

done:
	return return_point_addr;
}

struct os_functions os_functions_windows = {
	.find_return_point_addr = _gt_windows_find_return_point_addr
};

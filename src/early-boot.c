#include <libvmi/libvmi.h>

#include "early-boot.h"
#include "trace-syscalls.h"
#include "rekall.h"

/* This code handles detecting when a kernel is ready to be instrumented.
 * For example, we do not want to instrument GRUB instead of the kernel---
 * we want to wait until GRUB loads the kernel.
 *
 * The idea is that a value other than zero in LSTAR indicates that the kernel
 * has begun to set up 64-bit mode. Once this is the case, we wait for CR3 to
 * change, as this indicates that a user-space process is running. Once this
 * happens, we remove the CR3 event and instrument the kernel for runtime.
 * More details below.
 */

status_t
early_boot_wait_for_os_load(GtLoop *loop)
{
	status_t status = VMI_FAILURE;
	addr_t lstar;

	/* Libvmi does not appear to support LSTAR write events. */
	while (TRUE) {
		status = vmi_get_vcpureg(loop->vmi, &lstar, MSR_LSTAR, 0);
		if (VMI_SUCCESS != status) {
			fprintf(stderr, "failed to get MSR_LSTAR address\n");
			goto done;
		}

		if (0 != lstar) {
			break;
		}

		usleep(100000);
	}

	loop->lstar_addr = lstar;

done:
	return status;
}

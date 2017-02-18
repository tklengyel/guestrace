#include <libvmi/libvmi.h>

#include "early-boot.h"
#include "trace-syscalls.h"

/* This code handles detecting when a kernel is ready to be instrumented.
 * For example, we do not want to instrument GRUB instead of the kernel---
 * we want to wait until GRUB loads the kernel.
 *
 * The idea is that a value other than zero in LSTAR indicates that the kernel
 * has begun to set up 64-bit mode. Once this is the case, we wait for CR3 to
 * change, as this indicates that a user-space process is running. Once this
 * happens, we remove the CR3 event and instrument the kernel for runtime.
 */

status_t
early_boot_wait_for_os_load(GtLoop *loop)
{
	status_t status = VMI_FAILURE;
	addr_t lstar;

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

static event_response_t
gt_cr3_cb(vmi_instance_t vmi, vmi_event_t *event) {
	GtLoop *loop = event->data;

	vmi_clear_event(loop->vmi, event, NULL);
	loop->initialized = TRUE;

	return VMI_EVENT_RESPONSE_NONE;
}

status_t
early_boot_wait_for_first_process(GtLoop *loop)
{
	status_t status = VMI_FAILURE;

	SETUP_REG_EVENT(&loop->cr3_event, CR3, VMI_REGACCESS_W, 0, gt_cr3_cb);

	loop->cr3_event.data = loop;

	status = vmi_register_event(loop->vmi, &loop->cr3_event);
        if (VMI_SUCCESS != status) {
                fprintf(stderr, "failed to setup memory event\n");
                goto done;
        }

	while (!loop->initialized) {
                status_t status = vmi_events_listen(loop->vmi, 1000);
                if (status != VMI_SUCCESS) {
                        fprintf(stderr, "error waiting for events\n");
			goto done;
                }
        }

	status = VMI_SUCCESS;

done:
	return status;
}

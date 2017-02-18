#include <libvmi/libvmi.h>

#include "early-boot.h"
#include "trace-syscalls.h"

/* This code handles detecting when a kernel is ready to be instrumented.
 * For example, we do not want to instrument GRUB instead of the kernel---
 * we want to wait until GRUB loads the kernel.
 *
 * The idea is that a value other than zero in LSTAR indicates that the kernel
 * has begun to set up 64-bit mode. Once this is the case, we set a breakpoint
 * at the address stored in LSTAR. The kernel will trigger this breakpoint as
 * it services the very first system call. Once this happens, we remove the
 * breakpoint and instrument the kernel for runtime.
 *
 * Both Linux and Windows seem to update instruction pages even after they set
 * LSTAR. Thus we also register a R/W event on the page holding the LSTAR
 * address. This allows us to reset the breakpoint if it had been overwritten
 * before being executed.
 */

static status_t
_early_boot_set_initialize_breakpoint(GtLoop *loop, uint8_t *inst)
{
	addr_t lstar_p;
	status_t status = VMI_FAILURE;

	lstar_p = vmi_translate_kv2p(loop->vmi, loop->lstar_addr);
	if (0 == lstar_p) {
		fprintf(stderr, "failed to translate virtual LSTAR to physical address\n");
		goto done;
	}

	status = vmi_read_8_pa(loop->vmi,
			       lstar_p,
			       inst);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to read instruction byte at MSR_LSTAR address\n");
		goto done;
	}

	status = vmi_write_8_pa(loop->vmi,
			      lstar_p,
			      &GT_BREAKPOINT_INST);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to write breakpoint at MSR_LSTAR address\n");
		goto done;
	}

	status = vmi_set_mem_event(loop->vmi, lstar_p >> GT_PAGE_OFFSET_BITS,
	                           VMI_MEMACCESS_RW,
                                   loop->shadow_view);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to set mem. event on MSR_LSTAR page\n");
		goto done;
	}

done:
	return status;
}

status_t
early_boot_set_initialize_breakpoint(GtLoop *loop)
{
	status_t status;
	uint8_t inst = 0;

	status = _early_boot_set_initialize_breakpoint(loop, &inst);

	loop->orig_inst = inst;

	return status;
}

status_t
early_boot_reset_initialize_breakpoint(GtLoop *loop)
{
	status_t status;
	uint8_t inst;

	status = _early_boot_set_initialize_breakpoint(loop, &inst);

	g_assert(GT_BREAKPOINT_INST == inst || loop->orig_inst == inst);

	return status;
}

status_t
early_boot_remove_initialize_breakpoint(GtLoop *loop)
{
	status_t status = VMI_FAILURE;
	addr_t lstar_p;
	uint8_t inst;

	vmi_pause_vm(loop->vmi);

	lstar_p = vmi_translate_kv2p(loop->vmi, loop->lstar_addr);
	if (0 == lstar_p) {
		fprintf(stderr, "translation of virt. LSTAR to phy. failed");
		goto done;
	}

	status = vmi_read_8_pa(loop->vmi,
			       lstar_p,
			      &inst);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to read instruction byte at MSR_LSTAR address\n");
		goto done;
	}

	status = vmi_write_8_pa(loop->vmi,
				lstar_p,
			       &loop->orig_inst);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "remove of initialize breakpoint failed\n");
		goto done;
	}

	status = vmi_set_mem_event(loop->vmi, lstar_p >> GT_PAGE_OFFSET_BITS,
	                           VMI_MEMACCESS_N,
			           loop->shadow_view);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to remove mem. event on MSR_LSTAR page\n");
		goto done;
	}

	vmi_resume_vm(loop->vmi);

done:
	return status;
}

status_t
early_boot_wait_for_lstar(GtLoop *loop)
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

status_t
early_boot_wait_for_initialized(GtLoop *loop)
{
	status_t status = VMI_FAILURE;

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

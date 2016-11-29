#include <libvmi/libvmi.h>
#include <libvmi/events.h>	
#include <capstone/capstone.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "translate_syscalls.h"

static event_response_t step_cb (vmi_instance_t vmi, vmi_event_t *event);
static event_response_t int3_cb (vmi_instance_t vmi, vmi_event_t *event);

struct gs_state {
	uint8_t orig_syscall_inst;	
	uint8_t orig_sysret_inst;	
	reg_t virt_syscall_addr;
	addr_t phys_syscall_addr;
	reg_t virt_sysret_addr;
	addr_t phys_sysret_addr;
};

/* Intel breakpoint interrupt (INT 3) instruction. */
static uint8_t BREAKPOINT_INST = 0xCC;

/*
 * Handle terminating signals by setting interrupted flag. This allows
 * a graceful exit.
 */

static int interrupted = 0; 

static void 
close_handler (int sig) 
{
	interrupted = sig; 	
}

static bool
set_up_signal_handler (struct sigaction act)
{
	int status = 0;

	act.sa_handler = close_handler;
	act.sa_flags = 0;

	status = sigemptyset(&act.sa_mask);	
	if (-1 == status) {
		fprintf(stderr, "sigemptyset failed to initialize handler.\n");
		goto done;
	}
 
	status = sigaction(SIGHUP,  &act, NULL);
	if (-1 == status) {	
		fprintf(stderr, "Failed to register SIGHUP handler.\n");
		goto done;
	}

	status = sigaction(SIGTERM, &act, NULL);		
	if (-1 == status) {
		fprintf(stderr, "Failed to register SIGTERM handler.\n");
		goto done;
	}

	status = sigaction(SIGINT,  &act, NULL);		
	if (-1 == status) {
		fprintf(stderr, "Failed to register SIGINT handler.\n");
		goto done;
	}
	
	status = sigaction(SIGALRM, &act, NULL);		
	if (-1 == status) {
		fprintf(stderr, "Failed to register SIGALRM handler.\n");
		goto done;
	}

done:
	return -1 != status;
}


/* 
 * Replace the first byte of the system-call handler with INT 3. The address of
 * the system call handler is available in MSR_LSTAR.
 */
static status_t
set_up_syscall_int3 (vmi_instance_t vmi, struct gs_state *vm_info)
{
	status_t status = VMI_FAILURE;

	status = vmi_get_vcpureg(vmi, &vm_info->virt_syscall_addr, SYSENTER_EIP, 0);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to read SYSENTER_EIP.\n");
		goto done;
	}

	vm_info->phys_syscall_addr = vmi_translate_kv2p(vmi,
	                                                vm_info->virt_syscall_addr);
	if (0 == vm_info->phys_syscall_addr) {
		fprintf(stderr, "failed to get phy. addr. of syscall "
		                "fn at 0x%"PRIx64".\n", vm_info->virt_syscall_addr);
		goto done;
	}

	status = vmi_read_8_pa(vmi, vm_info->phys_syscall_addr,
	                      &vm_info->orig_syscall_inst);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to read original syscall inst. from 0x%"
		                 PRIx64".\n", vm_info->phys_syscall_addr);
		goto done;
	}

	status = vmi_write_8_pa(vmi, vm_info->phys_syscall_addr, &BREAKPOINT_INST);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to write syscall breakpoint at 0x%"
		                 PRIx64".\n", vm_info->phys_syscall_addr);
		goto done;
	}

	status = VMI_SUCCESS;

done:
	return status;
}

/*
 * Restore the VM's memory before exiting: replace original instruction
 * fragments, but only if we were able to find them in the first place.
 */
static void
restore_original_instructions (vmi_instance_t vmi, struct gs_state *vm_info)
{
	status_t status = VMI_SUCCESS;
	
	if (0 != vm_info->phys_syscall_addr) {
		status = vmi_write_8_pa(vmi,
		                        vm_info->phys_syscall_addr,
		                       &vm_info->orig_syscall_inst);
		if (VMI_FAILURE == status) {
			fprintf(stderr, "failed to write original syscall "
			                "instruction; VM might crash.\n");
		}
	}
	
	if (0 != vm_info->phys_sysret_addr) {
		status = vmi_write_8_pa(vmi,
		                        vm_info->phys_sysret_addr,
		                       &vm_info->orig_sysret_inst);
		if (VMI_FAILURE == status) {
			fprintf(stderr, "failed to write original sysret "
			                "instruction; VM might crash.\n");
		}
	}
}

static bool
is_syscall(reg_t rip, struct gs_state *vm_info)
{
	return rip == vm_info->virt_syscall_addr;
}

/*
 * Single-step callback. After single step beyond restored instruction,
 * replace instruction with breakpoint again. Replace both call and return
 * breakpoint every time. (See also int3_cb.)
 */
static event_response_t 
step_cb (vmi_instance_t vmi, vmi_event_t *event) 
{
	status_t status = VMI_SUCCESS;
	struct gs_state *vm_info = (struct gs_state *) event->data;

	status = vmi_pause_vm(vmi);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to pause the VM while in step_cb.\n");
		interrupted = 1;
		return VMI_EVENT_RESPONSE_NONE;	
	}

	status = vmi_write_8_pa(vmi, vm_info->phys_syscall_addr, &BREAKPOINT_INST);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to reset syscall breakpoint at 0x%"PRIx64" "
		                "in step_cb.\n",
		                 vm_info->phys_syscall_addr);
		interrupted = 1; 		
		return VMI_EVENT_RESPONSE_NONE;	
	}

	status = vmi_resume_vm(vmi);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to resume the vm while in step_cb.\n");
		interrupted = 1;
		return VMI_EVENT_RESPONSE_NONE;
	}
	
	/* Turn off single step. */
	return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

/* 
 * INT 3 callback. Print a syscall or sysret, restore the original instuction
 * fragment which we replaced with INT 3, and turn on single stepping. We will
 * step on instruction past the restored instruction and then again replace its
 * first byte with an INT 3. (See also step_cb.)
 */
static event_response_t 
int3_cb (vmi_instance_t vmi, vmi_event_t *event) 
{
	status_t status = VMI_SUCCESS;
	addr_t  orig_inst_addr = 0;
	uint8_t orig_inst_frag = 0;
	reg_t rip = event->x86_regs->rip;
	struct gs_state *vm_info = (struct gs_state *) event->data; 

	/*
	 * Flush the PID to page table cache to ensure we are looking at the
	 * correct page for the running process.
	 */
	vmi_pidcache_flush(vmi);
	
	/*
	 * Do not re-inject the interrupt we are handling here.
	 */
	event->interrupt_event.reinject = 0;

	status = vmi_pause_vm(vmi);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to pause the vm while in int3_cb.\n");
		interrupted = 1;
		goto done;
	}

	/* Restore original instruction fragment. */
	if (is_syscall(rip, vm_info)) {
		orig_inst_addr = vm_info->phys_syscall_addr;
		orig_inst_frag = vm_info->orig_syscall_inst;

		status = vmi_write_8_pa(vmi, orig_inst_addr, &orig_inst_frag);
		if (VMI_FAILURE == status) {
			fprintf(stderr, "failed to rewrite original instruction at 0x%"
			                 PRIx64" in int3_cb.\n", orig_inst_addr);
			interrupted = 1;
			goto done;
		}

		print_syscall(vmi, event);
	}

	/* NOTE: would not get this far in any other case. */

done:
	status = vmi_resume_vm(vmi);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to resume the VM in int3_cb.\n");
		interrupted = 1;
	}

	if (VMI_SUCCESS == status) {
		/* Turn on single step. */
		return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
	} else {
		return VMI_EVENT_RESPONSE_NONE;
	}
}

static status_t
set_up_int3_event (vmi_instance_t vmi,
                   vmi_event_t int3_event,
                   struct gs_state *vm_info)
{
	memset(&int3_event, 0, sizeof(vmi_event_t));
	SETUP_INTERRUPT_EVENT(&int3_event, 0, int3_cb);
	int3_event.data = vm_info;

	return vmi_register_event(vmi, &int3_event);
}

static status_t
set_up_single_step_event (vmi_instance_t vmi,
                          vmi_event_t step_event,
                          struct gs_state *vm_info)
{
	memset(&step_event, 0, sizeof(vmi_event_t));
	SETUP_SINGLESTEP_EVENT(&step_event, 1, step_cb, 0);
	step_event.data = vm_info;

	return vmi_register_event(vmi, &step_event);
}

int 
main (int argc, char *argv[]) 
{
	char *guest_name;		
	struct sigaction act;
	vmi_event_t int3_event;
	vmi_event_t step_event;
	int exitcode = EXIT_FAILURE;	
	int status = VMI_FAILURE;
	vmi_instance_t vmi = NULL; 		
	struct gs_state vm_info;

	memset(&vm_info, 0x00, sizeof(vm_info));

	if (argc < 2) {
		fprintf(stderr, "usage: %s <VM name>\n", argv[0]);
		goto done;
	}
	
	guest_name = argv[1];

	if (!set_up_signal_handler(act)) {
		fprintf(stderr, "error setting up signal handlers\n");
		goto done;
	}

	status = vmi_init(&vmi,
	                   VMI_XEN | VMI_INIT_COMPLETE | VMI_INIT_EVENTS,
	                   guest_name);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to initialize LibVMI library.\n");
		goto done;
	}

	status = vmi_pause_vm(vmi);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to pause VM.\n");
		goto done;
	}

	status = set_up_syscall_int3(vmi, &vm_info);
	if (VMI_FAILURE == status) {
		goto done;
	}

	status = set_up_int3_event(vmi, int3_event, &vm_info);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to setup the int3 event.");
		goto done;
	}

	status = set_up_single_step_event(vmi, step_event, &vm_info);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to setup the single-step event.");
		goto done;
	}		


	status = vmi_resume_vm(vmi);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to resume the VM.\n");
		goto done;
	}

	while(!interrupted) {
		status = vmi_events_listen(vmi, 500);
		if (VMI_FAILURE == status) {
			fprintf(stderr, "error waiting for event.\n");	
			goto done;				
		}
	}

	exitcode = EXIT_SUCCESS;
	
done:
	if (NULL != vmi) {
		restore_original_instructions(vmi, &vm_info);
		vmi_resume_vm(vmi);
		vmi_destroy(vmi);
	} 

	exit(exitcode);
}
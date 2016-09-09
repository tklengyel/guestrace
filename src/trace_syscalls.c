#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <inttypes.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>	
#include "translate_syscalls.h"

/*			
 *			STATIC VARIABLE DEFINITIONS
 * 		      -------------------------------
 *  Static variables used in different functions throughout guestrace.
 *  Making them static reduces the number of memory and register
 *  look ups required on each system call.
 */
static uint8_t breakpoint_inst = 0xcc;		
static uint8_t orig_syscall_inst;	
static uint8_t orig_sysret_inst;	
static reg_t virt_system_call_entry_addr;	
static addr_t phys_system_call_entry_addr; 
static reg_t virt_sysret_addr;
static addr_t phys_sysret_addr;

/* 
 * 			SIGNAL HANDLER DECLARATIONS
 * 		      -------------------------------
 *  Signal handler declarations used by the signal handle in main
 */
static int interrupted = 0; 

static void 
close_handler (int sig) 
{
	interrupted = sig; 	
}

/*			EVENT CALLBACK FUNCTIONS
 *		      ----------------------------
 *  Functions to handle a registered  vmi_events on occurrence of the event.
 */
event_response_t 
step_cb (vmi_instance_t vmi, vmi_event_t *event) 
{
	/* 
 	 *  This function writes the break point instruction to system_call()
 	 *  and ret_from_sys_call() on a single step event. 
	 */
	status_t status = VMI_SUCCESS;

	status = vmi_pause_vm(vmi);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "Failed to pause the vm while in step_cb!\n");
		interrupted = 1;						/* kills the main loop */
		return VMI_EVENT_RESPONSE_NONE;	
	}

	status = vmi_write_8_pa(vmi, phys_system_call_entry_addr, &breakpoint_inst);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "Failed to write the break point to syscall at 0x%"PRIx64" in step_cb!\n", phys_system_call_entry_addr);
		interrupted = 1; 		
		return VMI_EVENT_RESPONSE_NONE;	
	}
	
	status = vmi_write_8_pa(vmi, phys_sysret_addr, &breakpoint_inst);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "Failed to write the break point to ret_from_sys_call at 0x%"PRIx64" in step_cb!\n", phys_sysret_addr);
		interrupted = 1;
		return VMI_EVENT_RESPONSE_NONE;
	}

	status = vmi_resume_vm(vmi);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "Failed to resume the vm while in step_cb!\n");
		interrupted = 1;
		return VMI_EVENT_RESPONSE_NONE;
	}
	
	return 1u << VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;	/* turns single stepping off */
}

event_response_t 
int3_cb (vmi_instance_t vmi, vmi_event_t *event) 
{
	/* 
 	 *  Prints out information on system calls and return values an restores the
 	 *  original instruction to whichever function was called (system_call or ret_from_sys_call.
 	 */
	status_t status = VMI_SUCCESS;
	reg_t rip = event->regs.x86->rip; 
	vmi_pidcache_flush(vmi);	/* flush the pid to page table cache to ensure we are looking at the correct page for the running process */
	
	event->interrupt_event.reinject = 0;	/* don't re-inject the interrupt as we placed it in memory */

	status = vmi_pause_vm(vmi);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "Failed to pause the vm while in int3_cb!\n");
		interrupted = 1;
		return VMI_EVENT_RESPONSE_NONE;
	}

	if (rip == virt_system_call_entry_addr) {
		
		status = vmi_write_8_pa(vmi, phys_system_call_entry_addr, &orig_syscall_inst);		/* restore the original instruction for system_call */
		if (VMI_FAILURE == status) {						
			fprintf(stderr, "Failed to rewrite original syscall instruction at 0x%"PRIx64" in int3_cb!\n", phys_system_call_entry_addr);
			interrupted = 1;								
			return VMI_EVENT_RESPONSE_NONE;
		}
		
		print_syscall_info(vmi, event);
	}

	else if (rip == virt_sysret_addr) {
		
		status = vmi_write_8_pa(vmi, phys_sysret_addr, &orig_sysret_inst);	/* restore the original instruction for ret_from_sys_call */
		if (VMI_FAILURE == status) {					
			fprintf(stderr, "Failed to write the original sysret instruction at 0x%"PRIx64" in int3_cb!\n", phys_sysret_addr);
			interrupted = 1;
			return VMI_EVENT_RESPONSE_NONE;	
		}
		
		print_sysret_info(vmi, event);	
	}

	else {		
		status = vmi_resume_vm(vmi);
		if (VMI_FAILURE == status) {
			fprintf(stderr, "Failed to resume the vm in int3_cb!\n");
			interrupted = 1;
		}	
		return VMI_EVENT_RESPONSE_NONE;
	}
	
	status = vmi_resume_vm(vmi);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "Failed to resume the vm in int3_cb!\n");
		interrupted = 1;
		return VMI_EVENT_RESPONSE_NONE;
	}

	return 1u << VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;				/* enables single stepping allowing us to move one instruction */
}

/* 
 * 			SETUP FUNCTIONS
 *  		      -------------------
 *  Functions used in the setting up the events and memory
 *  in the guest needed to trace all system calls.
 */

status_t
set_up_exit_handler (struct sigaction act)
{
	/*  
	 *  Creates a signal handler in order to allow for us to clean up memory and
 	 *  gracefully exit when a signal occurs.
 	 */
	int status = 0;
	act.sa_handler = close_handler;		/* sets the sigaction handler to close_handler */
	act.sa_flags = 0;			/* clears out the sigaction flags */

	status = sigemptyset(&act.sa_mask);	
	if (-1 == status) {
		fprintf(stderr, "sigempty set failed while setting up the exit handler!\n");
		goto done;
	}
 
	status = sigaction(SIGHUP,  &act, NULL);	/* sets the handler for the signal to our handler */		
	if (-1 == status) {	
		fprintf(stderr, "Failed to register act as the handler for the signal SIGHUP!\n");
		goto done;
	}

	status = sigaction(SIGTERM, &act, NULL);		
	if (-1 == status) {
		fprintf(stderr, "Failed to register act as the handler for the signal SIGTERM!\n");
		goto done;
	}

	status = sigaction(SIGINT,  &act, NULL);		
	if (-1 == status) {
		fprintf(stderr, "Failed to register act as the handler for the signal SIGINT!\n");
		goto done;
	}
	
	status = sigaction(SIGALRM, &act, NULL);		
	if (-1 == status) {
		fprintf(stderr, "Failed to register act as the handler for the signal SIGALRM!\n");
		goto done;
	}

done:
	if (-1 == status) {
		return VMI_FAILURE;
	}

	else {
		return VMI_SUCCESS;
	}
}

status_t
set_up_int3_event (vmi_instance_t vmi, vmi_event_t int3_event)
{
	memset(&int3_event, 0, sizeof(vmi_event_t));			
	SETUP_INTERRUPT_EVENT(&int3_event, 0, int3_cb);	
	
	return vmi_register_event(vmi, &int3_event);
}

status_t
set_up_single_step_event (vmi_instance_t vmi, vmi_event_t step_event)
{
	memset(&step_event, 0, sizeof(vmi_event_t));								
	SETUP_SINGLESTEP_EVENT(&step_event, 1, step_cb, 0);		

	return vmi_register_event(vmi, &step_event);
}

status_t
set_up_system_call_entry_int3 (vmi_instance_t vmi)
{
	/*
 	 *  Gets all necessary addresses and writes the break point instruction
 	 *  to the system_call function.
 	 */
	status_t status = VMI_SUCCESS;

	status = vmi_get_vcpureg(vmi, &virt_system_call_entry_addr, MSR_LSTAR, 0);	/* get and store the virtual address for the system_call function which is stored in MSR_LSTAR */
	if (VMI_FAILURE == status) {	
		fprintf(stderr, "Failed to get the system_call() function entry address from MSR_LSTAR!\n");
		goto done;
	}

	phys_system_call_entry_addr = vmi_translate_kv2p(vmi, virt_system_call_entry_addr);	/* get and store the physical address of the system_call function form the virtual address*/	
	if (0 == phys_system_call_entry_addr) {
		fprintf(stderr, "Failed to get the physical address of the system_call() function\n");
		status = VMI_FAILURE;
		goto done;
	}

	status = vmi_read_8_pa(vmi, phys_system_call_entry_addr, &orig_syscall_inst);	/* get and store the original first 8 bits of the system_call function */
	if (VMI_FAILURE == status) {		
		fprintf(stderr, "Failed to read original instruction from 0x%"PRIx64"!\n", phys_system_call_entry_addr);
		goto done;
	}

	status = vmi_write_8_pa(vmi, phys_system_call_entry_addr, &breakpoint_inst);	/* write the break point instruction to the first byte of the system_call function */
	if (VMI_FAILURE == status) {				
		fprintf(stderr, "Failed to write the break point to syscall at 0x%"PRIx64"!\n", phys_system_call_entry_addr);
		goto done;
	}

done:
	return status;
}

status_t
set_up_sysret_entry_int3 (vmi_instance_t vmi)
{
	/*
 	 *  Gets all necessary addresses and writes the break point instruction
 	 *  to the ret_from_sys_call function.
 	 */
	status_t status = VMI_SUCCESS;

	virt_sysret_addr = vmi_translate_ksym2v(vmi, "ret_from_sys_call");	/* get and store the virtual address of the ret_from_sys_call function */
	if (0 == virt_sysret_addr) {
		fprintf(stderr, "Failed to get the virtual address of ret_from_sys_call\n");
		status = VMI_FAILURE;
		goto done;
	}

	phys_sysret_addr = vmi_translate_kv2p(vmi, virt_sysret_addr);		/* get and store the physical address of ret_from_syscall */
	if (0 == phys_sysret_addr) {
		fprintf(stderr, "Failed to get the physical address of ret_from_sys_call\n");
		status = VMI_FAILURE;
		goto done;
	}

	status = vmi_read_8_pa(vmi, phys_sysret_addr, &orig_sysret_inst);	/* get and store the first byte of ret_from_sys_call */
	if (VMI_FAILURE == status) {   	
		fprintf(stderr, "Failed to read original instruction from 0x%"PRIx64"!\n", phys_sysret_addr);
		goto done;
	}

	status = vmi_write_8_pa(vmi, phys_sysret_addr, &breakpoint_inst);
	if (VMI_FAILURE == status) {				/* write the break point to the firt byte of ret_from_sys_call */
		fprintf(stderr, "Failed to write the break point to sysret at 0x%"PRIx64"!\n", phys_sysret_addr);
		goto done;
	}

done:
	return status;
}

/*
 * 			CLEANUP FUNCTIONS
 * 		      ---------------------
 *  Functions used to clean up memory before exiting the program.
 */
void
restore_original_instructions (vmi_instance_t vmi)
{
	/*
 	 *  Restores the original instructions for system_call and ret_from_sys_call.
 	 */
	status_t status = VMI_SUCCESS;
	
	status = vmi_write_8_pa(vmi, phys_system_call_entry_addr, &orig_syscall_inst);	/* restore the original byte of system_call */
	if (VMI_FAILURE == status) {
		fprintf(stderr, "Failed to write original syscall instruction back to memory, your VM may need to be restarted!\n");
	}
	
	status = vmi_write_8_pa(vmi, phys_sysret_addr, &orig_sysret_inst);	/* restore the original byte of ret_from_sys_call */
	if (VMI_FAILURE == status) {
		fprintf(stderr, "Failed to write the original sysret instruction back to memory, your VM may need to be restarted!\n");
	}
}

/* 			
 *  			MAIN FUNCTION 
 *  		      -----------------
 *  The main function sets up all events and memory and runs the main loop
 *  listening for events until VMI_FAILURE or the loop is interrupted by
 *  a signal.
 */

int 
main (int argc, char *argv[]) 
{
	vmi_instance_t vmi = NULL; 		
	char *guest_name;		
	struct sigaction act;	
	int status = VMI_SUCCESS;	
	vmi_event_t int3_event;		/* event to register waiting for int3 events to occur */
	vmi_event_t step_event;		/* event to register waiting for single-step events to occur */

	if (argc < 2) {
		printf("Not enough arguments\nUsage: %s <vm name>\n", argv[0]);
		return 1;
	}
	
	guest_name = argv[1];

	status = set_up_exit_handler(act);
	if (VMI_FAILURE == status) {
		goto done;
	}

	/* initialize the vmi instance with the given flags and exit cleanly on failure */
	status = vmi_init(&vmi, VMI_XEN | VMI_INIT_COMPLETE | VMI_INIT_EVENTS, guest_name);
	if (VMI_FAILURE == status) {	
		fprintf(stderr, "Failed to initialize LibVMI library!\n");			
		goto done;
	}

	status = set_up_int3_event(vmi, int3_event);
	if (VMI_FAILURE == status) {	
		fprintf(stderr, "Failed to setup the int3 event!");
		goto done;
	}	

	status = set_up_single_step_event(vmi, step_event);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "Failed to setup the single step event!");
		goto done;
	}	
	
	status = vmi_pause_vm(vmi);
	if (VMI_FAILURE == status) {						/* pause the vm for writing memory */
		fprintf(stderr, "Failed to pause the VM!\n");
		goto done;
	}

	status = set_up_system_call_entry_int3(vmi);
	if (VMI_FAILURE == status) {
		goto done;
	}

	status = set_up_sysret_entry_int3(vmi);
	if (VMI_FAILURE == status) {
		goto done;
	}	

	status = vmi_resume_vm(vmi);
	if (VMI_FAILURE == status) {						/* resume the vm */
		fprintf(stderr, "Failed to resume the VM!\n");
		goto done;
	}

	while(!interrupted) {						/* loop while interrupted is 0 */
		status = vmi_events_listen(vmi, 500);			/* listen for vmi events with a 500ms timeout */
		if (VMI_FAILURE == status) {				/* check for errors waiting on events */
			fprintf(stderr, "Error waiting for events!\n");	
			goto done;				
		}
	}
	
done:
	if (NULL != vmi) {
		restore_original_instructions(vmi);
		status = vmi_destroy(vmi);
	} 

	exit(status);				/* return the status*/
}

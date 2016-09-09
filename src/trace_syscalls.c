#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <inttypes.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>	
#include "translate_syscalls.h"

/* 			
 *  			EVENT DECLARATIONS
 *		      ----------------------
 *  Pre-defines the events that we use throughout the VMI
 *  program. In this instance we define a vmi_event named
 *  int3_event that causes a VM_EXIT on all
 *  int 3 instructions.
 */
vmi_event_t int3_event;		/* event to trap on interrupt 3 events */
vmi_event_t step_event;		/* event to trap on single-step events */

/*			
 *			STATIC VARIABLE DEFINITIONS
 * 		      -------------------------------
 *  Static variables we use throughout the program which stay constant once
 *  set in main. The following variables reduce the number of memory and register
 *  look ups required on each system call
 */
static uint8_t bp = 0xcc;		/* set the break point instruction value (0xCC) */
static uint8_t orig_syscall_inst;	/* stores the original instruction for the syscall handler that we replace with bp */
static uint8_t orig_sysret_inst;	/* stores the original instruction for ret_from_sys_call that we replace with bp */

static reg_t virt_system_call_entry_addr;	/* stores the virtual address of the entry to the system_call() function which is found in MSR_LSTAR */
static addr_t phys_system_call_entry_addr; 	/* stores the physical address that is derived from the virtual address p fthe system_call() function */

static reg_t virt_sysret_addr;		/* stores the virtual address found at the kernel symbol ret_from_sys_call */
static addr_t phys_sysret_addr;		/* stores the physical address of ret_from_sys_call */

/* 
 * 			SIGNAL HANDLER DECLARATIONS
 * 		      -------------------------------
 *  The signal handler uses the following declarations in order for us to catch signals to 
 *  terminate the program and destroy the vmi instance for a clean exit and keeping the 
 *  guest machine in a usable state
 */
static int interrupted = 0; 	/* tracks interrupts from signals and error handling*/

static void 
close_handler (int sig) 
{
	interrupted = sig; 	/* set interrupted to the signal value (sig) on receipt of a signal */
}

/*			EVENT CALLBACK FUNCTIONS
 *		      ----------------------------
 *  The call back functions handle a vmi_event, that is registered, once
 *  it occurs. Each function has a description of what it is doing.
 */
event_response_t 
step_cb (vmi_instance_t vmi, vmi_event_t *event) 
{
	/* 
 	 *  This function is called on single_step events. We use this function
 	 *  to place the break point instruction back at the syscall handler 
 	 *  location (physical address from lstar), and to turn off single stepping.
	 */	

	vmi_pause_vm(vmi);

	if (VMI_FAILURE == vmi_write_8_pa(vmi, phys_system_call_entry_addr, &bp)) {
		fprintf(stderr, "Failed to write the break point to syscall at 0x%"PRIx64" in step_cb!\n", phys_system_call_entry_addr);
		interrupted = 1; 			/* This will kill the event listen loop */
		return VMI_EVENT_RESPONSE_NONE;		/* return no response to the event response handler */
	}
	
	if (VMI_FAILURE == vmi_write_8_pa(vmi, phys_sysret_addr, &bp)) {
		fprintf(stderr, "Failed to write the break point to ret_from_sys_call at 0x%"PRIx64" in step_cb!\n", phys_sysret_addr);
		interrupted = 1;
		return VMI_EVENT_RESPONSE_NONE;
	}

	vmi_resume_vm(vmi);
	
	/* The follow turns single stepping off */
	return 1u << VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

event_response_t 
int3_cb (vmi_instance_t vmi, vmi_event_t *event) 
{
	/* 
 	 *  Anytime an int3_event occurs we call this function.
 	 *  It determines whether the event was triggered by a syscall
 	 *  or by a return from a syscall by examining the value of 
 	 *  the RIP register and comparing it to the virtual addresses
 	 *  of the two instructions. It then, depending on which type of
 	 *  call was made, calls the correct function to print pertinent
 	 *  information about the call, for syscalls we print the pid, name
 	 *  and all arguments, and for returns we print the pid and the return
 	 *  value.
 	 */
	reg_t rip = event->regs.x86->rip; 					/* get the instruction pointer to determine if we are initiating or returning from syscall */

	vmi_pidcache_flush(vmi);						/* flush the pid to page table cache to ensure we are looking at the correct page for the running process */
	/* 
         *  We do not want to re-inject the event because we want the program to continue
 	 *  and not actually process the software break point, therefore we set the
 	 *  re-inject value to 0.
 	 */	
	event->interrupt_event.reinject = 0;

	vmi_pause_vm(vmi);

	if (rip == virt_system_call_entry_addr) {
		
		if (VMI_FAILURE == vmi_write_8_pa(vmi, phys_system_call_entry_addr, &orig_syscall_inst)) {		/* restore the entry to system_call()  to its original instruction */
			fprintf(stderr, "Failed to rewrite original syscall instruction at 0x%"PRIx64" in int3_cb!\n", phys_system_call_entry_addr);
			interrupted = 1;								/* This will kill the event listen loop */
			return VMI_EVENT_RESPONSE_NONE;
		}
		
		print_syscall_info(vmi, event);					/* function found in translate_syscalls.c */
	}

	else if (rip == virt_sysret_addr) {
		
		if (VMI_FAILURE == vmi_write_8_pa(vmi, phys_sysret_addr, &orig_sysret_inst)) {	/* restore the entry to the ret_from_sys_call() to its original instruction */ 
			fprintf(stderr, "Failed to write the original sysret instruction at 0x%"PRIx64" in int3_cb!\n", phys_sysret_addr);
			interrupted = 1;
			return VMI_EVENT_RESPONSE_NONE;	
		}
		
		print_sysret_info(vmi, event);					/* function found in translate_syscalls.c */
	}

	else {		
		vmi_resume_vm(vmi);							/* if neither of the previous is true, we have an INT3 event that did not occur from a syscall or return */
		return VMI_EVENT_RESPONSE_NONE;
	}
	
	vmi_resume_vm(vmi);

	/* 
 	 *  The following turns single stepping on allowing us
 	 *  to move one instruction past the syscall handler
 	 *  entry point and triggering our single step event
 	 */
	return 1u << VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;		
}

status_t
set_up_exit_handler (struct sigaction act)
{
	int status = 0;
	/* creates the signal handler that allows us to cleanly exit*/
	act.sa_handler = close_handler;		/* sets the sigaction handler to close_handler */
	act.sa_flags = 0;			/* clears out the sigaction flags */

	status = sigemptyset(&act.sa_mask);		/* initializes the sa_mask man sigaction(2) */
	if (-1 == status) {
		fprintf(stderr, "sigempty set failed while setting up the exit handler!\n");
		goto done;
	}
 
	status = sigaction(SIGHUP,  &act, NULL);		/* calls act signal handler on SIGHUP */
	if (-1 == status) {	
		fprintf(stderr, "Failed to register act as the handler for the signal SIGHUP!\n");
		goto done;
	}

	status = sigaction(SIGTERM, &act, NULL);		/* calls act signal handler on SIGTERM */
	if (-1 == status) {
		fprintf(stderr, "Failed to register act as the handler for the signal SIGTERM!\n");
		goto done;
	}

	status = sigaction(SIGINT,  &act, NULL);		/* calls act signal handler on SIGINT */
	if (-1 == status) {
		fprintf(stderr, "Failed to register act as the handler for the signal SIGINT!\n");
		goto done;
	}
	
	status = sigaction(SIGALRM, &act, NULL);		/* calls act signal handler on SIGALRM */	
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
set_up_int3_event (vmi_instance_t vmi)
{
	memset(&int3_event, 0, sizeof(vmi_event_t));			/* set memory to 0 at &int3_syscall_event for sizeof(vmi_event_t) bytes */
	SETUP_INTERRUPT_EVENT(&int3_event, 0, int3_cb);			/* setup the int3_syscall interrupt event */
	
	return vmi_register_event(vmi, &int3_event);
}

status_t
set_up_single_step_event (vmi_instance_t vmi)
{
	memset(&step_event, 0, sizeof(vmi_event_t));			/* set memory to 0 at &step_event for sizeof(vmi_event_t) bytes	*/								
	SETUP_SINGLESTEP_EVENT(&step_event, 1, step_cb, 0);		/* setup the single step event */

	return vmi_register_event(vmi, &step_event);
}

status_t
set_up_system_call_entry_int3 (vmi_instance_t vmi)
{
	status_t status = VMI_SUCCESS;

	status = vmi_get_vcpureg(vmi, &virt_system_call_entry_addr, MSR_LSTAR, 0);
	if (VMI_FAILURE == status) {		/* get the lstar value */
		fprintf(stderr, "Failed to get the system_call() function entry address from MSR_LSTAR!\n");
		goto done;
	}

	phys_system_call_entry_addr = vmi_translate_kv2p(vmi, virt_system_call_entry_addr);		/* get the physical address of lstar */	
	if (0 == phys_system_call_entry_addr) {
		fprintf(stderr, "Failed to get the physical address of the system_call() function\n");
		status = VMI_FAILURE;
		goto done;
	}

	status = vmi_read_8_pa(vmi, phys_system_call_entry_addr, &orig_syscall_inst);
	if (VMI_FAILURE == status) {		/* get the original instruction for the syscall handler */
		fprintf(stderr, "Failed to read original instruction from 0x%"PRIx64"!\n", phys_system_call_entry_addr);
		goto done;
	}

	status = vmi_write_8_pa(vmi, phys_system_call_entry_addr, &bp);
	if (VMI_FAILURE == status) {				/* write the break point at the syscall handler */
		fprintf(stderr, "Failed to write the break point to syscall at 0x%"PRIx64"!\n", phys_system_call_entry_addr);
		goto done;
	}

done:
	return status;
}

status_t
set_up_sysret_entry_int3 (vmi_instance_t vmi)
{
	status_t status = VMI_SUCCESS;

	virt_sysret_addr = vmi_translate_ksym2v(vmi, "ret_from_sys_call");	/* get the virtual address of the ret_from_sys_call kernel symbol */
	if (0 == virt_sysret_addr) {
		fprintf(stderr, "Failed to get the virtual address of ret_from_sys_call\n");
		status = VMI_FAILURE;
		goto done;
	}

	phys_sysret_addr = vmi_translate_kv2p(vmi, virt_sysret_addr);		/* get the physical address of the kernel symbol */
	if (0 == phys_sysret_addr) {
		fprintf(stderr, "Failed to get the physical address of ret_from_sys_call\n");
		status = VMI_FAILURE;
		goto done;
	}

	status = vmi_read_8_pa(vmi, phys_sysret_addr, &orig_sysret_inst);
	if (VMI_FAILURE == status) {    	/* get the original instruction for ret_from_sys_call */
		fprintf(stderr, "Failed to read original instruction from 0x%"PRIx64"!\n", phys_sysret_addr);
		goto done;
	}

	status = vmi_write_8_pa(vmi, phys_sysret_addr, &bp);
	if (VMI_FAILURE == status) {				/* write the break point at ret_from_sys_call */
		fprintf(stderr, "Failed to write the break point to sysret at 0x%"PRIx64"!\n", phys_sysret_addr);
		goto done;
	}

done:
	return status;
}

void
restore_original_instructions (vmi_instance_t vmi)
{
	status_t status = VMI_SUCCESS;
	
	status = vmi_write_8_pa(vmi, phys_system_call_entry_addr, &orig_syscall_inst);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "Failed to write original syscall instruction back to memory, your VM may need to be restarted!\n");
	}
	
	status = vmi_write_8_pa(vmi, phys_sysret_addr, &orig_sysret_inst);
	if (VMI_FAILURE == status) {	/* write the original instructions back to memory */
		fprintf(stderr, "Failed to write the original sysret instruction back to memory, your VM may need to be restarted!\n");
	}
}

/* 			
 *  			MAIN FUNCTION 
 *  		      -----------------
 *  The main function modifies the signal handler allowing for a clean
 *  exit, creates our VMI instance allowing us to introspect into the guest,
 *  sets up our vmi_events that we wish to trap on, runs the main loop
 *  to listen for vmi_events and handles them with callback functions and
 *  cleanly exit our program
 */

int 
main (int argc, char *argv[]) 
{
	
	vmi_instance_t vmi = NULL; 	/* will store the vmi instance instance information */	
	char *guest_name;		/* will stores the name of the vm to introspect which is argv[1] */
	struct sigaction act;		/* initializes sigaction struct to handle signals */
	int status = VMI_SUCCESS;	/* status for vmi_events_listen in loop */

	/* get the input arguments for the function */
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

	status = set_up_int3_event(vmi);
	if (VMI_FAILURE == status) {	
		fprintf(stderr, "Failed to setup the int3 event!");
		goto done;
	}	

	status = set_up_single_step_event(vmi);
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
	
	/*  
 	 *  we need to clean up memory before exiting by ensuring that the
 	 *  original instruction for the syscall handler is in place and
 	 *  we don't destroy our guest machine
 	 */
done:
	if (NULL != vmi) {
		restore_original_instructions(vmi);
		status = vmi_destroy(vmi);
	} 

	exit(status);				/* return the status*/
}

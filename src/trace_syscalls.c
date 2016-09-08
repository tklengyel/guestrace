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

static reg_t virt_lstar;		/* stores the virtual address found in MSR_LSTAR */
static addr_t phys_lstar; 		/* stores the physical address that is derived from the virtual address in lstar */

static reg_t virt_sysret;		/* stores the virtual address found at the kernel symbol ret_from_sys_call */
static addr_t phys_sysret;		/* stores the physical address on ret_from_sys_call */

/* 
 * 			SIGNAL HANDLER DECLARATIONS
 * 		      -------------------------------
 *  The signal handler uses the following declarations in order for us to catch signals to 
 *  terminate the program and destroy the vmi instance for a clean exit and keeping the 
 *  guest machine in a usable state
 */
static int interrupted = 0; 	/* tracks interrupts from signals and error handling*/

static void 
close_handler(int sig) 
{
	interrupted = sig; 	/* set interrupted to the signal value (sig) on receipt of a signal */
}

/*			EVENT CALLBACK FUNCTIONS
 *		      ----------------------------
 *  The call back functions handle a vmi_event, that is registered, once
 *  it occurs. Each function has a description of what it is doing.
 */
event_response_t 
step_cb(vmi_instance_t vmi, vmi_event_t *event) 
{
	/* 
 	 *  This function is called on single_step events. We use this function
 	 *  to place the break point instruction back at the syscall handler 
 	 *  location (physical address from lstar), and to turn off single stepping.
	 */	

	vmi_pause_vm(vmi);

	if (VMI_FAILURE == vmi_write_8_pa(vmi, phys_lstar, &bp)) {
		fprintf(stderr, "Failed to write the break point to syscall at 0x%"PRIx64" in step_cb!\n", phys_lstar);
		interrupted = 1; 			/* This will kill the event listen loop */
		return VMI_EVENT_RESPONSE_NONE;		/* return no response to the event response handler */
	}
	
	if (VMI_FAILURE == vmi_write_8_pa(vmi, phys_sysret, &bp)) {
		fprintf(stderr, "Failed to write the break point to ret_from_sys_call at 0x%"PRIx64" in step_cb!\n", phys_sysret);
		interrupted = 1;
		return VMI_EVENT_RESPONSE_NONE;
	}

	vmi_resume_vm(vmi);
	
	/* The follow turns single stepping off */
	return (1u << VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP);
}

event_response_t 
int3_cb(vmi_instance_t vmi, vmi_event_t *event) 
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

	if (rip == virt_lstar) {
		
		if (VMI_FAILURE == vmi_write_8_pa(vmi, phys_lstar, &orig_syscall_inst)) {		/* set the entry to syscall handler  to its original instruction */
			fprintf(stderr, "Failed to rewrite original syscall instruction at 0x%"PRIx64" in int3_cb!\n", phys_lstar);
			interrupted = 1;								/* This will kill the event listen loop */
			return VMI_EVENT_RESPONSE_NONE;
		}
		
		print_syscall_info(vmi, event);					/* function found in translate_syscalls.c */
	}

	else if (rip == virt_sysret) {
		
		if (VMI_FAILURE == vmi_write_8_pa(vmi, phys_sysret, &orig_sysret_inst)) {	/* set the entry to the ret_from_sys_call instruction to its original instruction */ 
			fprintf(stderr, "Failed to write the original sysret instruction at 0x%"PRIx64" in int3_cb!\n", phys_sysret);
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
	return (1u << VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP);		
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
	char *name;			/* will stores the name of the vm to introspect which is argv[1] */
	struct sigaction act;		/* initializes sigaction struct to handle signals */
	int status = VMI_FAILURE;	/* status for vmi_events_listen in loop */

	/* get the input arguments for the function */
	if (argc < 2) {
		printf("Not enough arguments\nUsage: %s <vm name>\n", argv[0]);
		return 1;
	}
	
	name = argv[1];

	/* creates the signal handler that allows us to cleanly exit*/
	act.sa_handler = close_handler;		/* sets the sigaction handler to close_handler */
	act.sa_flags = 0;			/* clears out the sigaction flags */
	sigemptyset(&act.sa_mask);		/* initializes the sa_mask man sigaction(2) */
	sigaction(SIGHUP,  &act, NULL);		/* calls act signal handler on SIGHUP */
	sigaction(SIGTERM, &act, NULL);		/* calls act signal handler on SIGTERM */
	sigaction(SIGINT,  &act, NULL);		/* calls act signal handler on SIGINT */
	sigaction(SIGALRM, &act, NULL);		/* calls act signal handler on SIGALRM */

	/* initialize the vmi instance with the given flags and exit cleanly on failure */
	if (VMI_FAILURE == vmi_init(&vmi, VMI_XEN | VMI_INIT_COMPLETE | VMI_INIT_EVENTS, name)) {	/* call vmi_init on the vm and store in vmi */
		fprintf(stderr, "Failed to initialize LibVMI library!\n");						/* check to see if it fails */
		goto init_fail;
	}

	memset(&int3_event, 0, sizeof(vmi_event_t));			/* set memory to 0 at &int3_syscall_event for sizeof(vmi_event_t) bytes */
	memset(&step_event, 0, sizeof(vmi_event_t));			/* set memory to 0 at &step_event for sizeof(vmi_event_t) bytes	*/

	SETUP_INTERRUPT_EVENT(&int3_event, 0, int3_cb);			/* setup the int3_syscall interrupt event */
	
	if (VMI_FAILURE == vmi_register_event(vmi, &int3_event)) {	/* register the int3 event */
		fprintf(stderr, "Failed to register the int 3 event!\n");
		goto done;
	}								 

	SETUP_SINGLESTEP_EVENT(&step_event, 1, step_cb, 0);		/* setup the single step event */

	if (VMI_FAILURE == vmi_register_event(vmi, &step_event)) {	/* register the single step event */
		fprintf(stderr, "Failed to register the single step event!\n");
		goto done;
	}	

	if (VMI_FAILURE == vmi_get_vcpureg(vmi, &virt_lstar, MSR_LSTAR, 0)) {		/* get the lstar value */
		fprintf(stderr, "Failed to get the lstar register value!\n");
		goto done;
	}

	phys_lstar = vmi_translate_kv2p(vmi, virt_lstar);		/* get the physical address of lstar */
	
	if (0 == phys_lstar) {
		fprintf(stderr, "Failed to get the physical address of syscall()\n");
		goto done;
	}

	virt_sysret = vmi_translate_ksym2v(vmi, "ret_from_sys_call");	/* get the virtual address of the ret_from_sys_call kernel symbol */

	if (0 == virt_sysret) {
		fprintf(stderr, "Failed to get the virtual address of ret_from_sys_call\n");
		goto done;
	}

	phys_sysret = vmi_translate_kv2p(vmi, virt_sysret);		/* get the physical address of the kernel symbol */

	if (0 == phys_sysret) {
		fprintf(stderr, "Failed to get the physical address of ret_from_sys_call\n");
		goto done;
	}

	if (VMI_FAILURE == vmi_pause_vm(vmi)) {						/* pause the vm for writing memory */
		fprintf(stderr, "Failed to pause the VM!\n");
		goto done;
	}

	if (VMI_FAILURE == vmi_read_8_pa(vmi, phys_lstar, &orig_syscall_inst)) {		/* get the original instruction for the syscall handler */
		fprintf(stderr, "Failed to read original instruction from 0x%"PRIx64"!\n", phys_lstar);
		goto done;
	}

	if (VMI_FAILURE == vmi_write_8_pa(vmi, phys_lstar, &bp)) {				/* write the break point at the syscall handler */
		fprintf(stderr, "Failed to write the break point to syscall at 0x%"PRIx64"!\n", phys_lstar);
		goto done;
	}

	if (VMI_FAILURE == vmi_read_8_pa(vmi, phys_sysret, &orig_sysret_inst)) {    	/* get the original instruction for ret_from_sys_call */
		fprintf(stderr, "Failed to read original instruction from 0x%"PRIx64"!\n", phys_sysret);
		goto done;
	}


	if (VMI_FAILURE == vmi_write_8_pa(vmi, phys_sysret, &bp)) {				/* write the break point at ret_from_sys_call */
		fprintf(stderr, "Failed to write the break point to sysret at 0x%"PRIx64"!\n", phys_sysret);
		goto done;
	}


	if (VMI_FAILURE == vmi_resume_vm(vmi)) {						/* resume the vm */
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
	/*  
 	 *  we need to clean up memory before exiting by ensuring that the
 	 *  original instruction for the syscall handler is in place and
 	 *  we don't destroy our guest machine
 	 */
	if (VMI_FAILURE == vmi_write_8_pa(vmi, phys_lstar, &orig_syscall_inst)) {
		fprintf(stderr, "Failed to write original syscall instruction back to memory, your VM may need to be restarted!\n");
		status = VMI_FAILURE;
	}
	
	if (VMI_FAILURE == vmi_write_8_pa(vmi, phys_sysret, &orig_sysret_inst)) {	/* write the original instructions back to memory */
		fprintf(stderr, "Failed to write the original sysret instruction back to memory, your VM may need to be restarted!\n");
		status = VMI_FAILURE;
	}

init_fail:	
	if (NULL != vmi && VMI_FAILURE == vmi_destroy(vmi)) { 		/* destroy the vmi instance */							
		printf("Failed to destroy the VMI instance!\n");
		status = VMI_FAILURE;
	}

	return status;				/* return the status*/
}

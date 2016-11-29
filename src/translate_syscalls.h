#ifndef TRANSLATE_SYSCALLS_H
#define TRANSLATE_STSCALLS_H

char * get_process_name(vmi_instance_t vmi, vmi_pid_t pid);			/* gets the process name of the process with the pid that is input */
void print_syscall(vmi_instance_t vmi, vmi_event_t *event);	/* translates and prints syscall information */
void print_sysret(vmi_instance_t vmi, vmi_event_t *event);		/* translates and prints return information */
const char * symbol_from_syscall_num(uint16_t sysnum); 		/* translate syscall number into symbol */

#endif

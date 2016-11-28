#ifndef TRANSLATE_SYSCALLS_H
#define TRANSLATE_STSCALLS_H

char *get_proc_name(vmi_instance_t vmi, vmi_pid_t pid);			/* gets the process name of the process with the pid that is input */
void print_syscall_info(vmi_instance_t vmi, vmi_event_t *event);	/* translates and prints syscall information */
void print_sysret_info(vmi_instance_t vmi, vmi_event_t *event);		/* translates and prints return information */
const char * symbol_from_syscall_num(unsigned int sysnum); 		/* translate syscall number into symbol */

#endif

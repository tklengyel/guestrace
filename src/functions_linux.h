#ifndef FUNCTIONS_LINUX_H
#define FUNCTIONS_LINUX_H

#include "trace_syscalls.h"

extern struct os_functions os_functions_linux;

void vf_linux_print_syscall(vmi_instance_t vmi, vmi_event_t *event, uint16_t syscall_num);
void vf_linux_print_sysret(vmi_instance_t vmi, vmi_event_t *event);
bool vf_linux_find_syscalls_and_setup_mem_traps(vf_config *conf);
bool vf_linux_set_up_sysret_handler(vf_config *conf);

#endif

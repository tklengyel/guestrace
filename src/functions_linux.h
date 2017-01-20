#ifndef FUNCTIONS_LINUX_H
#define FUNCTIONS_LINUX_H

#include "trace_syscalls.h"

extern struct os_functions os_functions_linux;

void vf_linux_print_syscall(vmi_instance_t vmi, vmi_event_t *event, vf_paddr_record *unused);
void vf_linux_print_sysret(vmi_instance_t vmi, vmi_event_t *event);
bool vf_linux_find_syscalls_and_setup_mem_traps(vf_state *state);
bool vf_linux_find_return_point_addr(vf_state *state);
bool vf_linux_find_trampoline_addr(vf_state *state);

#endif

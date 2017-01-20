#ifndef FUNCTIONS_WINDOWS_H
#define FUNCTIONS_WINDOWS_H

#include "trace_syscalls.h"

extern struct os_functions os_functions_windows;

void vf_windows_print_syscall(vmi_instance_t vmi, vmi_event_t *event, vf_paddr_record *paddr_record);
void vf_windows_print_sysret(vmi_instance_t vmi, vmi_event_t *event);
bool vf_windows_find_syscalls_and_setup_mem_traps(vf_state *state);
bool vf_windows_find_return_point_addr(vf_state *state);
bool vf_windows_find_trampoline_addr(vf_state *state);

#endif

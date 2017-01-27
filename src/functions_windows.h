#ifndef FUNCTIONS_WINDOWS_H
#define FUNCTIONS_WINDOWS_H

#include "trace_syscalls.h"

extern struct os_functions os_functions_windows;

bool vf_windows_find_syscalls_and_setup_mem_traps(GTLoop *loop);
bool vf_windows_find_return_point_addr(GTLoop *loop);

#endif

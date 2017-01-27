#ifndef FUNCTIONS_LINUX_H
#define FUNCTIONS_LINUX_H

#include "guestrace.h"

extern struct os_functions os_functions_linux;

bool vf_linux_find_syscalls_and_setup_mem_traps(GTLoop *loop);
bool vf_linux_find_return_point_addr(GTLoop *loop);

#endif

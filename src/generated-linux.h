/* Generated on Linux_4.9.3-200.fc25.x86_64 on 27 Jan 2017 01:42:51*/

#ifndef GENERATED_LINUX_H
#define GENERATED_LINUX_H

#include "guestrace.h"

bool vf_linux_find_syscalls_and_setup_mem_traps(GTLoop *loop);

extern const char *VM_LINUX_TRACED_SYSCALLS[];
extern const struct syscall_defs VM_LINUX_SYSCALLS[];

#endif

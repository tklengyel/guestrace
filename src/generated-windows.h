/* Generated on Linux_4.9.3-200.fc25.x86_64 on 27 Jan 2017 01:20:20*/

#ifndef GENERATED_WINDOWS_H
#define GENERATED_WINDOWS_H

#include "guestrace.h"
#include "trace-syscalls.h"

int _gt_windows_find_syscalls_and_setup_mem_traps(GTLoop *loop);

extern const char *VM_LINUX_TRACED_SYSCALLS[];
extern const GTSyscallCallback VM_WINDOWS_SYSCALLS[];

#endif

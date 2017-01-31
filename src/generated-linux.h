/* Generated on Linux_4.9.3-200.fc25.x86_64 on 30 Jan 2017 20:25:38*/

#ifndef GENERATED_LINUX_H
#define GENERATED_LINUX_H

#include "guestrace.h"
#include "trace-syscalls.h"

int _gt_linux_find_syscalls_and_setup_mem_traps(GTLoop *loop);

extern const GTSyscallCallback VM_LINUX_SYSCALLS[];

#endif

/* Generated on Linux_4.9.3-200.fc25.x86_64 on 29 Jan 2017 16:13:09*/

#ifndef GENERATED_LINUX_H
#define GENERATED_LINUX_H

#include "guestrace.h"
#include "trace-syscalls.h"

bool _gt_linux_find_syscalls_and_setup_mem_traps(GTLoop *loop);

extern const char *VM_LINUX_TRACED_SYSCALLS[];
extern const struct syscall_defs VM_LINUX_SYSCALLS[];

#endif

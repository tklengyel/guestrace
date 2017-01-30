#ifndef TRACE_SYSCALLS_H
#define TRACE_SYSCALLS_H

struct syscall_defs {
	/* <private> */
        char         *name;
        GTSyscallFunc syscall_cb;
        GTSysretFunc  sysret_cb;
};

/* Operating-system-specific operations. */
struct os_functions {
	/* <private> */
        addr_t (*find_return_point_addr) (GTLoop *loop);
};

bool _gt_find_syscalls_and_setup_mem_traps(GTLoop *loop,
                                           const struct syscall_defs syscalls[]);

addr_t _gt_find_addr_after_instruction(GTLoop *loop,
                                      addr_t start_v,
                                      char *mnemonic,
                                      char *ops);

#endif

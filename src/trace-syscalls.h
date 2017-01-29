#ifndef TRACE_SYSCALLS_H
#define TRACE_SYSCALLS_H

struct vf_paddr_record {
        addr_t offset;
        GTSyscallFunc syscall_cb;
        GTSysretFunc  sysret_cb;
        vf_page_record *parent;
};

struct syscall_defs {
        char         *name;
        GTSyscallFunc syscall_cb;
        GTSysretFunc  sysret_cb;
};

/* Operating-system-specific operations. */
struct os_functions {
        addr_t (*find_return_point_addr) (GTLoop *loop);
};

struct vf_paddr_record *vf_setup_mem_trap (GTLoop *loop,
                                           addr_t va,
                                           GTSyscallFunc syscall_cb,
                                           GTSysretFunc sysret_cb);
bool vf_find_syscalls_and_setup_mem_traps(GTLoop *loop,
                                          const struct syscall_defs syscalls[],
                                          const char *traced_syscalls[]);
addr_t vf_find_addr_after_instruction(GTLoop *loop,
                                      addr_t start_v,
                                      char *mnemonic,
                                      char *ops);

#endif

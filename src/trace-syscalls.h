#ifndef TRACE_SYSCALLS_H
#define TRACE_SYSCALLS_H

/* Operating-system-specific operations. */
struct os_functions {
	/* <private> */
        addr_t (*find_return_point_addr) (GTLoop *loop);
};

addr_t _gt_find_addr_after_instruction(GTLoop *loop,
                                      addr_t start_v,
                                      char *mnemonic,
                                      char *ops);

#endif

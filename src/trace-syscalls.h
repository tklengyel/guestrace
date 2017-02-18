#ifndef TRACE_SYSCALLS_H
#define TRACE_SYSCALLS_H

/* Operating-system-specific operations. */
struct os_functions {
	/* <private> */
        addr_t (*find_return_point_addr) (GtLoop *loop);
};

/* Maximum number of VCPUs VisorFlow will support. */
#define _GT_MAX_VCPUS 16

/* Number of bits available for page offset. */
#define GT_PAGE_OFFSET_BITS 12

/* Default page size on our domain. */
#define GT_PAGE_SIZE (1 << GT_PAGE_OFFSET_BITS)

/* Intel breakpoint interrupt (INT 3) instruction. */
extern uint8_t GT_BREAKPOINT_INST;

addr_t _gt_find_addr_after_instruction(GtLoop *loop,
                                      addr_t start_v,
                                      char *mnemonic,
                                      char *ops);

#endif

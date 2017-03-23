#ifndef TRACE_SYSCALLS_H
#define TRACE_SYSCALLS_H

/* Operating-system-specific operations. */
struct os_functions {
	/* <private> */
	status_t (*wait_for_first_process) (GtLoop *loop);
        addr_t (*find_return_point_addr) (GtLoop *loop);
	gt_pid_t (*get_pid) (vmi_instance_t vmi, vmi_event_t *event);
	char *(*get_process_name) (vmi_instance_t vmi, gt_pid_t pid);
	gboolean (*is_user_call) (GtLoop *loop, vmi_event_t *event);
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

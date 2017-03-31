#ifndef STATE_STACKS_H
#define STATE_STACKS_H

#include <glib.h>

#include "guestrace.h"

/*
 * A record which describes a frame. The children of these records (themselves
 * of type gt_paddr_record) describe the physical addresses contained in the
 * frame which themselves contain a breakpoint. This is needed when the guest
 * operating system triggers such a breakpoint.
 *
 * Stored in gt_page_record_collection.
 *      Key:   addr_t (shadow frame)
 *      Value: gt_page_record
 */
typedef struct gt_page_record {
	/* <private> */
	addr_t      frame;
	addr_t      shadow_frame;
	GHashTable *children;
	GtLoop     *loop;
} gt_page_record;

/*
 * A record which describes the information associated with a physical address
 * which contains a breakpoint.
 *
 * Stored in children field of gt_page_record.
 *      Key:   addr_t (shadow offset)
 *      Value: gt_paddr_record
 */
typedef struct gt_paddr_record {
	/* <private> */
	addr_t          offset;
	GtSyscallFunc   syscall_cb;
	GtSysretFunc    sysret_cb;
	gt_page_record *parent;
	void           *data;       /* Optional; passed to syscall_cb. */
} gt_paddr_record;

/*
 * Describes the state associated with a system call. This information is
 * stored and later made available while servicing the corresponding
 * system return.
 *
 * Stored in gt_ret_addr_mapping.
 *      Key:   addr_t (return_loc AKA thread's stack pointer)
 *      Value: gt_syscall_state
 */
typedef struct gt_syscall_state {
	/* <private> */
	gt_paddr_record *syscall_paddr_record;
	void            *data;
	addr_t           return_loc; /* needed for teardown */
	addr_t           return_addr;
} gt_syscall_state;

typedef struct state_stacks_t state_stacks_t;

state_stacks_t   *state_stacks_new(GFunc func);
void              state_stacks_destroy(state_stacks_t *collection);
void              state_stacks_remove_all(state_stacks_t *collection);
void              state_stacks_tid_free(state_stacks_t *collection, gt_tid_t tid);
void              state_stacks_tid_push(state_stacks_t *collection, gt_tid_t tid, gt_syscall_state *state);
gt_syscall_state *state_stacks_tid_pop(state_stacks_t *collection, gt_tid_t tid);

#endif

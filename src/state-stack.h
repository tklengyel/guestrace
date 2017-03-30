#ifndef STATE_STACK_H
#define STATE_STACK_H

#include <glib.h>

#include "guestrace.h"
#include "guestrace-private.h"

typedef GQueue state_stack_t;

void              state_stack_free(state_stack_t *stack, GDestroyNotify free_func);
void              state_stack_free_tid(GtLoop *loop, gt_tid_t tid);
void              state_stack_push_tid(GtLoop *loop, gt_tid_t tid, gt_syscall_state *state);
gt_syscall_state *state_stack_pop_tid(GtLoop *loop, gt_tid_t tid);

#endif

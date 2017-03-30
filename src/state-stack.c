#include "state-stack.h"

typedef GQueue state_stack_t;

void
state_stack_free(state_stack_t *stack, GDestroyNotify free_func)
{
	g_queue_free_full(stack, free_func);
}

void
state_stack_free_tid(GtLoop *loop, gt_tid_t tid)
{
	state_stack_t *stack;
	GHashTable *map = loop->gt_ret_addr_mapping;

	stack = g_hash_table_lookup(map, GSIZE_TO_POINTER(tid));
	if (NULL == stack) {
		goto done;
	}

	g_queue_pop_head(stack);

	if (g_queue_is_empty(stack)) {
		g_hash_table_remove(map, GSIZE_TO_POINTER(tid));
	}

done:
	return;
}

void
state_stack_push_tid(GtLoop *loop, gt_tid_t tid, gt_syscall_state *state)
{
	state_stack_t *stack;
	GHashTable *map = loop->gt_ret_addr_mapping;

	stack = g_hash_table_lookup(map, GSIZE_TO_POINTER(tid));
	if (NULL == stack) {
		stack = g_queue_new();
		g_hash_table_insert(map, GSIZE_TO_POINTER(tid), stack);
	}

	g_queue_push_head(stack, state);
}

gt_syscall_state *
state_stack_pop_tid(GtLoop *loop, gt_tid_t tid)
{
	state_stack_t *stack;
	void *state = NULL;
	GHashTable *map = loop->gt_ret_addr_mapping;

	stack = g_hash_table_lookup(map, GSIZE_TO_POINTER(tid));
	if (NULL == stack) {
		goto done;
	}

	state = g_queue_pop_head(stack);

	if (g_queue_is_empty(stack)) {
		g_hash_table_remove(map, GSIZE_TO_POINTER(tid));
	}

done:
	return state;
}

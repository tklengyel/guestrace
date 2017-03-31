#include "state-stacks.h"

typedef struct state_stacks_t {
	GHashTable *map;
	GFunc stack_elem_func;
} state_stacks_t;

typedef struct state_stack_t {
	GQueue *stack;
	GFunc func;
} state_stack_t;

static void
_state_stack_free(gpointer data)
{
	state_stack_t *stack = data;

	g_queue_foreach(stack->stack, stack->func, NULL);

	g_queue_free_full(stack->stack, g_free);
}

state_stacks_t *
state_stacks_new(GFunc func)
{
	state_stacks_t *stacks = g_new(state_stacks_t, 1);

	stacks->map = g_hash_table_new_full(NULL, NULL, NULL, _state_stack_free);
	stacks->stack_elem_func = func;

	return stacks;
}

void
state_stacks_destroy(state_stacks_t *collection)
{
	g_hash_table_destroy(collection->map);
}

void
state_stacks_remove_all(state_stacks_t *collection)
{
	g_hash_table_remove_all(collection->map);
}

void
state_stacks_tid_free(state_stacks_t *collection, gt_tid_t tid)
{
	state_stack_t *stack;

	stack = g_hash_table_lookup(collection->map, GSIZE_TO_POINTER(tid));
	if (NULL == stack) {
		goto done;
	}

	g_hash_table_remove(collection->map, GSIZE_TO_POINTER(tid));

done:
	return;
}

void
state_stacks_tid_push(state_stacks_t *collection, gt_tid_t tid, gt_syscall_state *state)
{
	state_stack_t *stack;

	stack = g_hash_table_lookup(collection->map, GSIZE_TO_POINTER(tid));
	if (NULL == stack) {
		stack = g_new(state_stack_t, 1);

		stack->stack = g_queue_new();
		stack->func  = collection->stack_elem_func;

		g_hash_table_insert(collection->map, GSIZE_TO_POINTER(tid), stack);
	}

	g_queue_push_head(stack->stack, state);
}

gt_syscall_state *
state_stacks_tid_pop(state_stacks_t *collection, gt_tid_t tid)
{
	state_stack_t *stack;
	void *state = NULL;

	stack = g_hash_table_lookup(collection->map, GSIZE_TO_POINTER(tid));
	if (NULL == stack) {
		goto done;
	}

	state = g_queue_pop_head(stack->stack);

	if (g_queue_is_empty(stack->stack)) {
		g_hash_table_remove(collection->map, GSIZE_TO_POINTER(tid));
	}

done:
	return state;
}

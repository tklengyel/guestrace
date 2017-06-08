/* This code comes from libvmi. Should they export this function? */

#include <json-c/json.h>

#include "gt-private.h"
#include "gt-rekall.h"

addr_t
gt_rekall_offset(GtGuestState *state, int offset_id)
{
	return state->loop->os_functions->get_offset(offset_id);
}

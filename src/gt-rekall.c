/* This code comes from libvmi. Should they export this function? */

#define XC_WANT_COMPAT_EVTCHN_API

#include <json-c/json.h>

#include "gt-private.h"
#include "gt-rekall.h"

/**
 * SECTION: gt-rekall
 * @title: libguestrace-rekall
 * @short_description: libguestrace Rekall integration.
 * @include: libguestrace/gt-rekall.h
 *
 * This interface allows a program using libguestrace to obtain kernel-data-structure
 * offsets as found by Rekall.
 **/

/**
 * gt_rekall_offset:
 * @state: a #GtGuestState.
 * @offset_id: a #gint.
 *
 * Returns: offset of field corresponding to @offset_id as calculated by Rekall.
 **/
addr_t
gt_rekall_offset(GtGuestState *state, int offset_id)
{
	return state->loop->os_functions->get_offset(offset_id);
}

#ifndef GUESTRACE_PRIVATE_H
#define GUESTRACE_PRIVATE_H

#include <glib.h>
#include <libxl.h>
#include <xenctrl.h>

#include "guestrace.h"
#include "trace-syscalls.h"

/* Includes collection of global state for callbacks.
 *
 * Guestrace maintains three collections:
 *
 * The first collection (gt_page_translation) contains a mapping from
 * frame numbers to shadow page numbers. Given a frame, this will translate
 * it into a shadow page if one exists. TODO: the code has changed since
 * the original inception in my mind, so we might be able to delete this
 * without negative consequences
 *
 * The second collection (gt_page_record_collection) contains a
 * mapping from shadow page numbers to gt_page_record structures. This
 * serves as a record of the guest pages for which guestrace installed a
 * memory event. When the guest accesses such a page, control traps into
 * guestrace. The most notable field in gt_page_record is children; this
 * field points to the third collection.
 *
 * The third collection (each gt_page_record's children field) contains a
 * mapping from physical address offsets to gt_paddr_record structures.
 * This serves as a record for each breakpoint that guestrace sets within a
 * page.
 */
struct _GtLoop {
	/* <private> */
	GMainLoop *g_main_loop;

	unsigned long count;

	vmi_instance_t vmi;
	const char *guest_name;

	gboolean initialized;
	gboolean running;
	addr_t lstar_addr;

	/* For SIGSEGV, etc. handling. */
	sigjmp_buf jmpbuf[_GT_MAX_VCPUS];

	os_t os;
	uint8_t return_addr_width;

	/*
	 * Function pointers which allow for polymorphism; cleanly support both
	 * Linux and Windows.
	 */
	struct os_functions *os_functions;

	/* Fields used with libvmi. */
	GHashTable *gt_page_translation;
	GHashTable *gt_page_record_collection;

	/* Contains the current mapping between a thread return ptr and gt_paddr_record */
	GHashTable *gt_ret_addr_mapping;

	/* Fields used to interact directly with Xen driver. */
	xc_interface *xch;
	libxl_ctx *ctx;
	uint32_t domid;
	uint64_t init_mem_size;
	uint64_t curr_mem_size;
	uint16_t shadow_view;
	vmi_event_t breakpoint_event;
	vmi_event_t memory_event;
	vmi_event_t cr3_event;
	vmi_event_t step_event[_GT_MAX_VCPUS];

	/*
	 * trampoline_addr is the address of the type-two breakpoint.
	 */
	addr_t trampoline_addr;
};

struct _GtGuestState {
	/* <private> */
	GtLoop         *loop;
	vmi_instance_t  vmi;
	vmi_event_t    *event;
	gboolean        hijack;
	reg_t           hijack_return;
};

#endif

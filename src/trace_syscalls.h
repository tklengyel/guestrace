#ifndef TRACE_SYSCALLS_H
#define TRACE_SYSCALLS_H

#include <glib.h>
#include <libxl.h>
#include <xenctrl.h>

/* Collection of global state for callbacks.
 *
 * Guestrace maintains three collections:
 *
 * The first collection (vf_page_translation) contains a mapping from
 * frame numbers to shadow page numbers. Given a frame, this will translate
 * it into a shadow page if one exists. TODO: the code has changed since
 * the original inception in my mind, so we might be able to delete this
 * without negative consequences
 *
 * The second collection (vf_page_record_collection) contains a
 * mapping from shadow page numbers to vf_page_record structures. This
 * serves as a record of the guest pages for which guestrace installed a
 * memory event. When the guest accesses such a page, control traps into
 * guestrace. The most notable field in vf_page_record is children; this
 * field points to the third collection.
 *
 * The third collection (each vf_page_record's children field) contains a
 * mapping from physical address offsets to vf_paddr_record structures.
 * This serves as a record for each breakpoint that guestrace sets within a
 * page.
 */
typedef struct vf_state {
	/* Fields used with libvmi. */
	GHashTable *vf_page_translation;
	GHashTable *vf_page_record_collection;

	/* Fields used to interact directly with Xen driver. */
	xc_interface *xch;
	libxl_ctx *ctx;
	uint32_t domid;
	uint64_t init_mem_size;
	uint64_t curr_mem_size;
	vmi_instance_t vmi;
	uint16_t shadow_view;
} vf_state;

typedef struct vf_page_record {
	addr_t frame;
	addr_t shadow_page;
	GHashTable *children;
	vf_state *state;
} vf_page_record;

typedef struct vf_paddr_record {
	addr_t offset;
	vf_page_record *parent;
	uint16_t identifier; /* Syscall identifier because we nix RAX. */
} vf_paddr_record;

/* Operating-system-specific operations. */
struct os_functions {
        void (*print_syscall) (vmi_instance_t vmi, vmi_event_t *event, vf_paddr_record *record);
        void (*print_sysret) (vmi_instance_t vmi, vmi_event_t *event);
        bool (*find_syscalls_and_setup_mem_traps) (vf_state *state);
        bool (*find_sysret_addr) (vf_state *state);
        bool (*find_trampoline_addr) (vf_state *state);
};

/* Global paddr record for our syscall return address */
//extern vf_paddr_record *sysret_trap;

extern addr_t sysret_addr;
extern addr_t trampoline_addr;

vf_paddr_record *vf_setup_mem_trap (vf_state *state, addr_t va);
status_t vf_emplace_breakpoint(vf_paddr_record *paddr_record);
status_t vf_remove_breakpoint(vf_paddr_record *paddr_record);

#endif

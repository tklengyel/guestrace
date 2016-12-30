#ifndef TRACE_SYSCALLS_H
#define TRACE_SYSCALLS_H

#include <glib.h>
#include <libxl.h>
#include <xenctrl.h>
#include <xentoollog.h>

/* Data structure used to interact directly with Xen driver */
typedef struct vf_config {
	xc_interface *xch;
	libxl_ctx *ctx;
	xentoollog_logger *logger;
	uint32_t domid;
	uint64_t init_mem_size;
	uint64_t curr_mem_size;
	vmi_instance_t vmi;
	uint16_t shadow_view;
} vf_config;

typedef struct vf_page_record {
	addr_t frame;
	addr_t shadow_page;
	GHashTable *children;
	vf_config *conf;
} vf_page_record;

typedef struct vf_paddr_record {
	addr_t offset;
	vf_page_record *parent;
	uint16_t identifier; /* Syscall identifier because we nix RAX. */
} vf_paddr_record;

/* Global paddr record for our syscall return address */
static vf_paddr_record *sysret_trap;

vf_paddr_record *vf_setup_mem_trap (vf_config *conf, addr_t va);
status_t vf_emplace_breakpoint(vf_paddr_record *paddr_record);
status_t vf_remove_breakpoint(vf_paddr_record *paddr_record);

#endif

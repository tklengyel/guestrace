#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <glib.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <capstone/capstone.h>
#include <xenctrl.h>
#include <libxl_utils.h>

#include "translate_syscalls.h"

/*
 * Before running, you must add
 * GRUB_CMDLINE_XEN_DEFAULT="altp2m=1"
 * to /etc/default/grub and add
 * altp2mhvm = 1
 * to the xen config file of a guest
 */

/* Default page size on our domain */
#define VF_PAGE_SIZE 0x1000

/* Maximum # of VCPUS we want visorflow to support */
#define VF_MAX_VCPUS 16

/* Intel breakpoint interrupt (INT 3) instruction. */
static uint8_t VF_BREAKPOINT_INST = 0xCC;

static vmi_event_t vf_step_events[VF_MAX_VCPUS];

addr_t phys_lstar;
uint8_t orig_inst;

/*
 * Global interrupt event that gets trigged on any VF_BREAKPOINT_INST callback
 */
static vmi_event_t vf_breakpoint_event;

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

/* contains the translation from guest address to newly allocated pages */
static GHashTable *vf_page_translation;

static GHashTable *vf_page_record_collection;

typedef struct vf_page_record {
	addr_t page;
	vmi_event_t *mem_event_rw;
	GHashTable *children;
	vf_config *conf;
} vf_page_record;

typedef struct vf_paddr_record {
	addr_t offset;
	vf_page_record *parent;
	gboolean enabled;
	uint16_t identifier; /* syscall identifier because we nix RAX */
} vf_paddr_record;

/*
 * Handle terminating signals by setting interrupted flag. This allows
 * a graceful exit.
 */
static int vf_interrupted = 0;

/*
 * Initilize our vf_config object to interact with Xen driver
 * Returns true if succeeded
 */
static bool
vf_init_config (vmi_instance_t vmi, char * name, vf_config * conf)
{
	bool status = false;

	conf->vmi = vmi;
	xc_interface *xch = xc_interface_open(0, 0, 0);

	if (NULL == xch) {
		fprintf(stderr, "Could not create xc interface\n");
		goto done;
	}

	conf->xch = xch;

	conf->logger = (xentoollog_logger *)xtl_createlogger_stdiostream(stderr, XTL_PROGRESS, 0);
	if (conf->logger == NULL) {
		fprintf(stderr, "Could not create libxl logger\n");
		goto done;
	}

	if (libxl_ctx_alloc(&conf->ctx, LIBXL_VERSION, 0, conf->logger)) {
		fprintf(stderr, "Could not create libxl context\n");
		goto done;
	}

	conf->domid = ~0U;

	if (libxl_name_to_domid(conf->ctx, name, &conf->domid) || ~0U == conf->domid) {
		fprintf(stderr, "Could not translate guest name to dom-id\n");
		goto done;
	}

	conf->init_mem_size = conf->curr_mem_size = vmi_get_memsize(vmi);

	if (0 == conf->init_mem_size) {
		fprintf(stderr, "Could not get guest's memory size\n");
		goto done;
	}

	fprintf(stderr, "Guest's starting memory size is %lx\n", conf->init_mem_size);

	/* here we enable xen-specific altp2m */
	int xc_status = xc_altp2m_set_domain_state(conf->xch, conf->domid, 1);
	if (0 > xc_status) {
		fprintf(stderr, "Failed to enable altp2m on guest\n");
		goto done;
	}

	xc_status = xc_altp2m_create_view(conf->xch, conf->domid, 0, &conf->shadow_view);
	if (0 > xc_status) {
		fprintf(stderr, "Failed to create view for shadow page\n");
		goto done;
	}

	xc_status = xc_altp2m_switch_to_view(conf->xch, conf->domid, conf->shadow_view);
	if (0 > xc_status) {
		fprintf(stderr, "Failed to enable shadow view\n");
		goto done;
	}

	status = true;

done:
	return status;
}

/*
 * Close our driver handlers and reset shadow memory
 */
static void
vf_close_config(vf_config * conf)
{
	int xc_status = xc_altp2m_switch_to_view(conf->xch, conf->domid, 0);
	if (0 > xc_status) {
		fprintf(stderr, "Failed to reset EPT to point to default table\n");
	}

	xc_status = xc_altp2m_destroy_view(conf->xch, conf->domid, conf->shadow_view);
	if (0 > xc_status) {
		fprintf(stderr, "Failed to destroy shadow view\n");
	}

	xc_status = xc_altp2m_set_domain_state(conf->xch, conf->domid, 0);
	if (0 > xc_status) {
		fprintf(stderr, "Failed to turn off altp2m on guest\n");
	}

	xc_status = xc_domain_setmaxmem(conf->xch, conf->domid, conf->init_mem_size);
	if (0 > xc_status) {
		fprintf(stderr, "Failed to reset max memory on guest");
	}

	libxl_ctx_free(conf->ctx);
	xc_interface_close(conf->xch);
}

/*
 * Allocates a new page of memory in the guest's address space
 */
static addr_t
vf_allocate_shadow_page (vf_config * conf)
{
	xen_pfn_t gfn = 0;

	int status = xc_domain_setmaxmem(conf->xch, conf->domid, conf->curr_mem_size + VF_PAGE_SIZE);

	if (0 == status) {
		conf->curr_mem_size += VF_PAGE_SIZE;
	} else {
		fprintf(stderr, "Could not increase memory size on guest to %lx\n", conf->curr_mem_size + VF_PAGE_SIZE);
		goto done;
	}

	status = xc_domain_increase_reservation_exact(conf->xch, conf->domid, 1, 0, 0, &gfn);

	if (status) {
		fprintf(stderr, "Could not increase reservation on guest");
		goto done;
	}

	status = xc_domain_populate_physmap_exact(conf->xch, conf->domid, 1, 0, 0, &gfn);

	if (status) {
		fprintf(stderr, "Could not populate GFN at 0x%lx\n", gfn);
		gfn = 0;
		goto done;
	}

done:
	return gfn;
}

static void
vf_destroy_paddr_record (gpointer data) {
	vf_paddr_record *paddr_record = data;

	fprintf(stderr, "Destroying paddr_record at shadow pa %lx\n", paddr_record->parent->page + paddr_record->offset);

	g_free(paddr_record);
}

static void
vf_destroy_page_record (gpointer data) {
	vf_page_record *page_record = data;

	fprintf(stderr, "Destroying page_record on page %lx\n", page_record->page);

	xc_altp2m_change_gfn(page_record->conf->xch, page_record->conf->domid, page_record->conf->shadow_view, page_record->page, ~0);
	xc_domain_decrease_reservation_exact(page_record->conf->xch, page_record->conf->domid, 1, 0, &page_record->page);

	vmi_clear_event(page_record->conf->vmi, page_record->mem_event_rw, NULL);

	g_free(page_record->mem_event_rw);

	g_hash_table_destroy(page_record->children);

	g_free(page_record);
}

/*
 * Callback invoked on a R/W of a monitored page (likely kernel patch protection).
 * Switch the VCPU's SLAT to its original, step once, switch SLAT back
 */
static event_response_t
vf_mem_rw_cb (vmi_instance_t vmi, vmi_event_t *event) {
	fprintf(stderr, "mem r/w at %lx\n", event->mem_event.gla);

	/* switch back to original slat for one step */
	event->slat_id = 0;

	return VMI_EVENT_RESPONSE_NONE;
}

static vf_paddr_record *
vf_setup_mem_trap (vf_config * conf, addr_t va)
{
	vf_page_record  *page_record  = NULL;
	vf_paddr_record *paddr_record = NULL;

	addr_t pa = vmi_translate_kv2p(conf->vmi, va);
	if (0 == pa) {
		fprintf(stderr, "virtual addr. translation failed: %lx\n", va);
		goto done;
	}

	addr_t page = pa >> 12;
	addr_t shadow = (addr_t)g_hash_table_lookup(vf_page_translation,
		                                GSIZE_TO_POINTER(page));
	addr_t shadow_offset = pa - (page << 12); /* probably a fancy bitwise way to do this */

	if (0 == shadow) {
		/* we need to allocate a new page */
		shadow = vf_allocate_shadow_page(conf);

		if (0 == shadow) {
			fprintf(stderr, "Failed to allocate shadow page\n");
			goto done;
		}

		g_hash_table_insert(vf_page_translation,
							GSIZE_TO_POINTER(page),
							GSIZE_TO_POINTER(shadow));

		/* this adds our remapping into our shadow view */
		int xc_status = xc_altp2m_change_gfn(conf->xch, conf->domid, conf->shadow_view, page, shadow);
		if (0 > xc_status) {
			fprintf(stderr, "Failed to add paddr_record into shadow view\n");
			goto done;
		}
	}

	page_record = g_hash_table_lookup(vf_page_record_collection,
		                                			GSIZE_TO_POINTER(shadow));

	if (NULL == page_record) {
		/* we need to create our page record and fill it */
		fprintf(stderr, "creating new page trap on 0x%lx -> 0x%lx\n", shadow, page);

		/* store current page on the stack */
		uint8_t buff[VF_PAGE_SIZE] = {0};
		status_t status = vmi_read_pa(conf->vmi, page << 12, buff, VF_PAGE_SIZE);
		if (0 == status) {
			fprintf(stderr, "Failed to read in syscall page\n");
			goto done;
		}

		status = vmi_write_pa(conf->vmi, shadow << 12, buff, VF_PAGE_SIZE);
		if (0 == status) {
			fprintf(stderr, "Failed to write to shadow page\n");
			goto done;
		}

		page_record                     = g_new0(vf_page_record, 1);
		page_record->page               = shadow;
		page_record->conf               = conf;
		page_record->mem_event_rw       = g_new0(vmi_event_t, 1);
		page_record->mem_event_rw->data = page_record;

		page_record->children = g_hash_table_new_full(NULL,
		                                              NULL,
		                                              NULL,
		                                              vf_destroy_paddr_record);

		g_hash_table_insert(vf_page_record_collection,
		                    GSIZE_TO_POINTER(shadow),
		                    page_record);

		/* todo: support write events? */
		SETUP_MEM_EVENT(page_record->mem_event_rw,
		                page_record->page,
		                VMI_MEMACCESS_RW,
		                vf_mem_rw_cb,
		                0);

		status = vmi_register_event(conf->vmi, page_record->mem_event_rw);
		if (VMI_SUCCESS != status) {
			fprintf(stderr, "failed to register event\n");
			goto done;
		}
	} else {
		/* We already have a page record for this page in collection. */
		paddr_record = g_hash_table_lookup(page_record->children,
		                                GSIZE_TO_POINTER(shadow_offset));
		if (NULL != paddr_record) {
			/* We have a paddr record too; done (no error). */
			goto done;
		}
	}

	/* Create physical-address record and add to page record. */
	paddr_record                =  g_new0(vf_paddr_record, 1);
	paddr_record->offset        =  shadow_offset;
	paddr_record->parent        =  page_record;
	paddr_record->enabled       =  TRUE;
	paddr_record->identifier    = ~0; /* default 0xFFFF */

	/* write the interrupt to our shadow page at the correct location */
	status_t ret = vmi_write_8_pa(conf->vmi, (shadow << 12) + shadow_offset, &VF_BREAKPOINT_INST);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "Failed to write interrupt to shadow page\n");
		goto done;
	}

done:
	/* TODO: Should undo state (e.g., remove from hash tables) on error */
	return paddr_record;
}

/*
 * Callback on any interrupts received from our shadow pages
 * Here we must make temporary changes and enter into single-step mode
 */
static event_response_t
vf_breakpoint_cb(vmi_instance_t vmi, vmi_event_t *event) {
	//fprintf(stderr, "!!! Syscall on VCPU %d\n", event->vcpu_id);

	/* set vcpu's slat to use original for one step */
	event->slat_id = 0;
	event->interrupt_event.reinject = 0;

	/* turn on single-step and switch slat_id */
	return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
}

/*
 * Setup our global interrupt to catch any interrupts on any pages
 */
static bool
vf_set_up_interrupt_event (vf_config * conf) {
	bool status = false;

	SETUP_INTERRUPT_EVENT(&vf_breakpoint_event, 0, vf_breakpoint_cb);
	vf_breakpoint_event.data = conf;

	status_t ret = vmi_register_event(conf->vmi, &vf_breakpoint_event);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "Failed to setup interrupt event\n");
		goto done;
	}

	status = true;

done:
	return status;
}

/*
 * Callback after a step event on any VCPU
 * Here we must reset any single-step changes we made
 */
static event_response_t
vf_singlestep_cb(vmi_instance_t vmi, vmi_event_t *event) {
	/* set to shadow slat */
	vf_config *conf = event->data;

	event->slat_id = conf->shadow_view;

	/* turn off single-step and switch slat_id */
	return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP | VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;
}

/*
 * Creates the step events needed for each VCPU so we don't have to create
 * a new event everytime we want to step
 */
static bool
vf_set_up_step_events (vf_config * conf) {
	bool status = false;

	int vcpus = vmi_get_num_vcpus(conf->vmi);
	if (0 == vcpus) {
		fprintf(stderr, "Failed to get number of VCPUs\n");
		goto done;
	}

	if (VF_MAX_VCPUS < vcpus) {
		fprintf(stderr, "Guest has more VCPUs than supported\n");
		goto done;
	}

	for (int vcpu = 0; vcpu < vcpus; vcpu++) {
		vmi_event_t curr = vf_step_events[vcpu];
		SETUP_SINGLESTEP_EVENT(&curr, 1u << vcpu, vf_singlestep_cb, 0);
		curr.data = conf;

		if (VMI_FAILURE == vmi_register_event(conf->vmi, &curr)) {
			fprintf(stderr, "Failed to register single-step event on VCPU %d\n", vcpu);
			goto done;
		}
	}

	status = true;

done:
	return status;
}

static bool
vf_set_up_syscall_handler(vf_config * conf)
{
	bool status = false;
	addr_t lstar = 0;

	/* LSTAR should be the constant across all vcpus */
	status_t ret = vmi_get_vcpureg(conf->vmi, &lstar, MSR_LSTAR, 0);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "failed to get MSR_LSTAR address\n");
		goto done;
	}

	vf_paddr_record * lstar_trap = vf_setup_mem_trap(conf, lstar);
	if (NULL == lstar_trap) {
		fprintf(stderr, "Failed to create memory trap\n");
		goto done;
	}

	status = true;

done:
	return status;
}

static void
vf_close_handler (int sig)
{
	vf_interrupted = sig;
}

static bool
vf_set_up_signal_handler (struct sigaction act)
{
	int status = 0;

	act.sa_handler = vf_close_handler;
	act.sa_flags = 0;

	status = sigemptyset(&act.sa_mask);
	if (-1 == status) {
		perror("failed to initialize signal handler.\n");
		goto done;
	}

	status = sigaction(SIGHUP,  &act, NULL);
	if (-1 == status) {
		perror("failed to register SIGHUP handler.\n");
		goto done;
	}

	status = sigaction(SIGTERM, &act, NULL);
	if (-1 == status) {
		perror("failed to register SIGTERM handler.\n");
		goto done;
	}

	status = sigaction(SIGINT,  &act, NULL);
	if (-1 == status) {
		perror("failed to register SIGINT handler.\n");
		goto done;
	}

	status = sigaction(SIGALRM, &act, NULL);
	if (-1 == status) {
		perror("failed to register SIGALRM handler.\n");
		goto done;
	}

done:
	return -1 != status;
}

int
main (int argc, char **argv) {
	struct sigaction act;
	status_t status = VMI_FAILURE;
	vmi_instance_t vmi;
	char *name = NULL;
	vf_config config = {0};

	if (argc < 2){
		fprintf(stderr, "Usage: guestrace <name of VM>\n");
		exit(EXIT_FAILURE);
	}

	/* Arg 1 is the VM name. */
	name = argv[1];

	if (!vf_set_up_signal_handler(act)) {
		goto done;
	}

	/* Initialize the libvmi library. */
	status = vmi_init(&vmi, VMI_XEN | VMI_INIT_COMPLETE | VMI_INIT_EVENTS, name);
	if (VMI_SUCCESS != status) {
		fprintf(stderr, "failed to init LibVMI library.\n");
		goto done;
	} else {
		printf("LibVMI init succeeded!\n");
	}

	vf_page_translation = g_hash_table_new(NULL, NULL);
	vf_page_record_collection = g_hash_table_new_full(NULL,
	                                                  NULL,
	                                                  NULL,
	                                                  vf_destroy_page_record);

	vmi_pause_vm(vmi);

	if (!vf_init_config(vmi, name, &config)) {
		vmi_resume_vm(vmi);
		goto done;
	}

	if (!vf_set_up_step_events(&config)) {
		vmi_resume_vm(vmi);
		goto done;
	}

	if (!vf_set_up_interrupt_event(&config)) {
		vmi_resume_vm(vmi);
		goto done;
	}

	if (!vf_set_up_syscall_handler(&config)) {
		vmi_resume_vm(vmi);
		goto done;
	}

	vmi_resume_vm(vmi);

	printf("Waiting for events...\n");

	while(!vf_interrupted){
		status = vmi_events_listen(vmi,500);
		if (status != VMI_SUCCESS) {
			printf("Error waiting for events, quitting...\n");
			goto done;
		}
	}

done:
	printf("Shutting down guestrace\n");

	vmi_pause_vm(vmi);

	g_hash_table_destroy(vf_page_record_collection);
	vf_close_config(&config);

	vmi_resume_vm(vmi);

	if (vmi != NULL) {
		vmi_destroy(vmi);
	}

	exit(VMI_SUCCESS == status ? EXIT_SUCCESS : EXIT_FAILURE);
}

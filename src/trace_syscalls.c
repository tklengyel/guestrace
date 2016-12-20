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

/* Intel breakpoint interrupt (INT 3) instruction. */
static uint8_t VF_BREAKPOINT_INST = 0xCC;

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

/*
 * List that stores our allocated pages for destruction on guestrace exit
 */
GSList * vf_allocated_pages;

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

	conf->init_mem_size = vmi_get_memsize(vmi);
	conf->curr_mem_size = conf->init_mem_size;

	if (0 == conf->init_mem_size) {
		fprintf(stderr, "Could not get guest's memory size\n");
		goto done;
	}

	status = true;

done:
	return status;
}

static void
vf_close_config(vf_config * conf)
{
	libxl_ctx_free(conf->ctx);
	xc_altp2m_switch_to_view(conf->xch, conf->domid, 0);
	xc_altp2m_set_domain_state(conf->xch, conf->domid, 0);
	xc_interface_close(conf->xch);
}

/*
 * Allocates a new page of memory in the guest's address space
 */
static xen_pfn_t
vf_allocate_page (vf_config * conf)
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

	vf_allocated_pages = g_slist_prepend(vf_allocated_pages, (void*)gfn);

done:
	return gfn;
}

/*
 * Removes any extra pages we added to the guest
 */
static void
vf_destroy_pages (vf_config * conf)
{
	GSList * elem;

	for(elem = vf_allocated_pages; elem; elem = elem->next) {
		xen_pfn_t curr = (xen_pfn_t)elem->data;

		if (xc_domain_decrease_reservation_exact(conf->xch, conf->domid, 1, 0, &curr)) {
			fprintf(stderr, "Could not destroy GFN at 0x%lx\n", curr);
		}
	}

	if (xc_domain_setmaxmem(conf->xch, conf->domid, conf->init_mem_size)) {
		fprintf(stderr, "Could not reset max memory on guest");
	}

	g_slist_free(vf_allocated_pages);
}

/*
 * Service an INT CC breakpoint
 */
static event_response_t
vf_breakpoint_cb(vmi_instance_t vmi, vmi_event_t *event) {
	event_response_t status = VMI_EVENT_RESPONSE_NONE;
	event->interrupt_event.reinject = 0;

	vf_config *conf = (vf_config*)event->data;

	fprintf(stderr, "Syscall!!\n");

	event->slat_id = conf->shadow_view;
	status = VMI_EVENT_RESPONSE_VMM_PAGETABLE_ID;

	return status;
}

/*
 * Create a shadow copy of our syscall routine into a newly
 * allocated page, then modify the original to have interrupts
 * Returns true if successful
 */
static bool
vf_set_up_syscall_handler (vf_config * conf)
{
	bool status = false;

	xen_pfn_t shadow = vf_allocate_page(conf);

	if (0 == shadow) {
		fprintf(stderr, "Failed to allocate shadow page\n");
		goto done;
	}

	addr_t lstar = 0;
	/* LSTAR should be the constant across all vcpus */
	status_t ret = vmi_get_vcpureg(conf->vmi, &lstar, MSR_LSTAR, 0);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "failed to get MSR_LSTAR address\n");
		goto done;
	}

	addr_t phys_lstar = vmi_translate_kv2p(conf->vmi, lstar);
	if (0 == phys_lstar) {
		fprintf(stderr, "failed to translate MSR_LSTAR into physical address\n");
		goto done;
	}

	addr_t syscall_page = phys_lstar >> 12;

	/* store current page on the stack */
	uint8_t buff[VF_PAGE_SIZE] = {0};
	ret = vmi_read_pa(conf->vmi, syscall_page << 12, buff, VF_PAGE_SIZE);
	if (0 == ret) {
		fprintf(stderr, "Failed to read in syscall page\n");
		goto done;
	}

	ret = vmi_write_pa(conf->vmi, shadow << 12, buff, VF_PAGE_SIZE);
	if (0 == ret) {
		fprintf(stderr, "Failed to write to shadow page\n");
		goto done;
	}

	/*
	 * At this point, we have a new page that has an exact copy of our syscall page.
	 * We can now write interrupts to our syscall page, and then switch to our shadow
	 * page whenever we get interrupt callbacks.  Since this is vcpu-specific, we no
	 * longer have a race-condition in single-step mode between different vcpus
	 */

	int xc_status = xc_altp2m_set_domain_state(conf->xch, conf->domid, 1);
	if (xc_status < 0) {
		fprintf(stderr, "Failed to enable altp2m on guest\n");
		goto done;
	}

	xc_status = xc_altp2m_create_view(conf->xch, conf->domid, 0, &conf->shadow_view);
	if (xc_status < 0) {
		fprintf(stderr, "Failed to create view for shadow page\n");
		goto done;
	}

	/* this adds our remapping into our shadow view */
	xc_status = xc_altp2m_change_gfn(conf->xch, conf->domid, conf->shadow_view, syscall_page, shadow);
	if (xc_status < 0) {
		fprintf(stderr, "Failed to change GFN to shadow\n");
		goto done;
	}

	SETUP_INTERRUPT_EVENT(&vf_breakpoint_event, 0, vf_breakpoint_cb);
	vf_breakpoint_event.data = conf;
	ret = vmi_register_event(conf->vmi, &vf_breakpoint_event);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "Failed to setup interrupt event\n");
		goto done;
	}

	ret = vmi_write_8_pa(conf->vmi, phys_lstar, &VF_BREAKPOINT_INST);
	if (VMI_SUCCESS != ret) {
		fprintf(stderr, "Failed to write interrupt to syscall page\n");
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

	vmi_pause_vm(vmi);

	if (!vf_init_config(vmi, name, &config)) {
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

	vf_destroy_pages(&config);
	vf_close_config(&config);

	if (vmi != NULL) {
		vmi_destroy(vmi);
	}

	exit(VMI_SUCCESS == status ? EXIT_SUCCESS : EXIT_FAILURE);
}

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "guestrace.h"
#include "generated-windows.h"
#include "generated-linux.h"

GtLoop *loop = NULL;

static void
gt_close_handler (int sig)
{
	gt_loop_quit(loop);
}

static int
gt_set_up_signal_handler (struct sigaction act)
{
	int rc = 0;

	act.sa_handler = gt_close_handler;
	act.sa_flags = 0;

	rc = sigemptyset(&act.sa_mask);
	if (-1 == rc) {
		goto done;
	}

	rc = sigaction(SIGHUP,  &act, NULL);
	if (-1 == rc ) {
		goto done;
	}

	rc = sigaction(SIGTERM, &act, NULL);
	if (-1 == rc) {
		goto done;
	}

	rc = sigaction(SIGINT,  &act, NULL);
	if (-1 == rc) {
		goto done;
	}

	rc = sigaction(SIGALRM, &act, NULL);
	if (-1 == rc) {
		goto done;
	}

done:
	return rc;
}

void
usage()
{
	fprintf(stderr, "usage: guestrace [-s] -n <VM name>\n");
}

int
main (int argc, char **argv) {
	int opt;
	gboolean silent = FALSE;
	char *name = NULL;
	struct sigaction act;
	const GtCallbackRegistry *registry;
	status_t status = VMI_FAILURE;

	while ((opt = getopt(argc, argv, "sn:")) != -1) {
		switch (opt) {
		case 's':
			silent = TRUE;
			break;
		case 'n':
			name = optarg;
			break;
		default:
			usage();
			goto done;
		}
	}

	if (NULL == name) {
		usage();
		goto done;
	}

	if (-1 == gt_set_up_signal_handler(act)) {
		perror("failed to setup signal handler.\n");
		goto done;
	}

	loop = gt_loop_new(name);
	if (NULL == loop) {
		fprintf(stderr, "could not initialize guestrace\n");
		goto done;
	}

	GtOSType os = gt_loop_get_ostype(loop);
	if (silent && os != GT_OS_LINUX) {
		fprintf(stderr, "only Linux supports silent mode\n");
		goto done;
	}

	switch (os) {
	case GT_OS_LINUX:
		registry = silent ? GT_LINUX_SILENT_SYSCALLS : GT_LINUX_SYSCALLS;
		break;
	case GT_OS_WINDOWS:
		registry = GT_WINDOWS_SYSCALLS;
		break;
	default:
		fprintf(stderr, "unknown guest operating system\n");
		goto done;
	}

	if (0 == gt_loop_set_cbs(loop, registry)) {
		fprintf(stderr, "unable to instrument any system calls\n");
		goto done;
	}

	status = VMI_SUCCESS;
	gt_loop_run(loop);

done:
	gt_loop_free(loop);

	exit(VMI_SUCCESS == status ? EXIT_SUCCESS : EXIT_FAILURE);
}

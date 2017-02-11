#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "guestrace.h"
#include "generated-windows.h"
#include "generated-linux.h"

GtLoop *loop = NULL;

/* Variables to hold command-line options and arguments. */
char *name       = NULL;
gboolean silent  = FALSE;
gboolean verbose = FALSE;

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

static void
usage()
{
	fprintf(stderr, "usage: guestrace [-s] [-v] -n <VM name>\n");
}

static int
message(const char *format, ...)
{
	int rc = 0;
	va_list ap;

	if (verbose) {
		va_start(ap, format);

		rc = vfprintf(stderr, format, ap);

		va_end(ap);
	}

	return rc;
}

int
main (int argc, char **argv) {
	int opt;
	struct sigaction act;
	const GtCallbackRegistry *registry;
	status_t status = VMI_FAILURE;

	while ((opt = getopt(argc, argv, "n:sv")) != -1) {
		switch (opt) {
		case 'n':
			name = optarg;
			break;
		case 's':
			silent = TRUE;
			break;
		case 'v':
			verbose = TRUE;
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

	message("setting up signal handlers\n");

	if (-1 == gt_set_up_signal_handler(act)) {
		perror("failed to setup signal handler.\n");
		goto done;
	}

	message("creating event loop\n");

	loop = gt_loop_new(name);
	if (NULL == loop) {
		fprintf(stderr, "could not initialize guestrace\n");
		goto done;
	}

	message("identifying OS type ... ");

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

	message("%s\n", GT_OS_LINUX ? "linux" : "windows");
	message("establishing callbacks (might take a few seconds)\n");

	if (0 == gt_loop_set_cbs(loop, registry)) {
		fprintf(stderr, "unable to instrument any system calls\n");
		goto done;
	}

	message("starting event loop");

	status = VMI_SUCCESS;
	gt_loop_run(loop);

done:
	message("freeing event loop");

	gt_loop_free(loop);

	exit(VMI_SUCCESS == status ? EXIT_SUCCESS : EXIT_FAILURE);
}

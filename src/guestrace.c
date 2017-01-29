#include <stdio.h>
#include <signal.h>
#include <stdlib.h>

#include "guestrace.h"
#include "generated-windows.h"
#include "generated-linux.h"

GTLoop *loop = NULL;

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

int
main (int argc, char **argv) {
	struct sigaction act;
	status_t status = VMI_FAILURE;

	if (argc < 2) {
		fprintf(stderr, "usage: guestrace <VM name>\n");
		goto done;
	}

	if (-1 == gt_set_up_signal_handler(act)) {
		perror("failed to setup signal handler.\n");
		goto done;
	}

	loop = gt_loop_new(argv[1]);
	if (NULL == loop) {
		fprintf(stderr, "could not initialize guestrace\n");
		goto done;
	}

	GTOSType os = gt_loop_get_ostype(loop);
	switch (os) {
	case GT_OS_LINUX:
		if (!_gt_linux_find_syscalls_and_setup_mem_traps(loop)) {
			fprintf(stderr, "could not setup memory traps\n");
			goto done;
		}
		break;
	case GT_OS_WINDOWS:
		if (!_gt_windows_find_syscalls_and_setup_mem_traps(loop)) {
			fprintf(stderr, "could not setup memory traps\n");
			goto done;
		}
		break;
	default:
		fprintf(stderr, "unknown guest operating system\n");
		goto done;
	}

	printf("Waiting for events.\n");

	status = VMI_SUCCESS;
	gt_loop_run(loop);

done:
	printf("Shutting down guestrace.\n");

	gt_loop_free(loop);

	exit(VMI_SUCCESS == status ? EXIT_SUCCESS : EXIT_FAILURE);
}

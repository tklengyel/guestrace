#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <trace_syscalls.h>

#include "functions_windows.h"
#include "functions_linux.h"

GTLoop *loop = NULL;

static void
vf_close_handler (int sig)
{
	gt_loop_quit(loop);
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

	if (argc < 2){
		fprintf(stderr, "Usage: guestrace <name of VM>\n");
		exit(EXIT_FAILURE);
	}

	if (!vf_set_up_signal_handler(act)) {
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
		if (!vf_linux_find_syscalls_and_setup_mem_traps(loop)) {
			fprintf(stderr, "could not setup memory traps\n");
			goto done;
		}
		break;
	case GT_OS_WINDOWS:
		if (!vf_windows_find_syscalls_and_setup_mem_traps(loop)) {
			fprintf(stderr, "could not setup memory traps\n");
			goto done;
		}
		break;
	default:
		fprintf(stderr, "unknown guest operating system\n");
		goto done;
	}

	printf("Waiting for events...\n");

	gt_loop_run(loop);

done:
	printf("Shutting down guestrace\n");

	gt_loop_quit(loop);

	exit(VMI_SUCCESS == status ? EXIT_SUCCESS : EXIT_FAILURE);
}

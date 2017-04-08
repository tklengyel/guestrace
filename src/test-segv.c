#include <setjmp.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "guestrace.h"
#include "generated-linux.h"

GtLoop *loop         = NULL;
char *name           = NULL;
gboolean test_return = FALSE;

struct args_open {
	addr_t pathaddr;
	int    flags;
	int    mode;
};

struct args_execve {
	addr_t fileaddr;
	/* Not done. */
};

static void
gt_close_handler (int sig)
{
	gt_loop_quit(loop);
}

static void
gt_close_handler_emergency (int sig)
{
	fprintf(stderr, "received emergency signal %d\n", sig);

	gt_loop_quit(loop);

	gt_loop_jmp_past_cb(loop);
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

	/*
	 * Some runtime error would otherwise crash VisorFlow, leaving the
	 * guest in a corrupt state. Handle these to attempt a graceful exit.
	 */
	act.sa_handler = gt_close_handler_emergency;
	act.sa_flags = 0;

	rc = sigaction(SIGSEGV, &act, NULL);
	if (-1 == rc) {
		goto done;
	}

done:
	return rc;
}

static void
usage()
{
	fprintf(stderr, "usage: guestrace -n <VM name> [-r]\n"
	                "\n"
	                "-n  name of guest to instrument\n");
}

void *handle_open_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	if (!test_return) {
		kill(0, SIGSEGV);
		g_assert_not_reached();
	}

	return NULL;
}

void handle_open_return(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data) {
	if (test_return) {
		kill(0, SIGSEGV);
		g_assert_not_reached();
	}
}

int
main (int argc, char **argv) {
	int opt, count;
	struct sigaction act;
	status_t status = VMI_FAILURE;

	const GtCallbackRegistry registry[] = {
		{ "sys_open", handle_open_args, handle_open_return },
		{ NULL, NULL, NULL },
	};

	while ((opt = getopt(argc, argv, "hn:r")) != -1) {
		switch (opt) {
		case 'n':
			name = optarg;
			break;
		case 'r':
			test_return = TRUE;
			break;
		case 'h':
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

	fprintf(stderr, "set up callbacks\n");

	count = gt_loop_set_cbs(loop, registry);
	if (0 == count) {
		fprintf(stderr, "unable to instrument any system calls\n");
		goto done;
	}

	fprintf(stderr, "run loop\n");

	status = VMI_SUCCESS;

	gt_loop_run(loop);

done:
	fprintf(stderr, "done\n");

	gt_loop_free(loop);

	fprintf(stderr, "exiting\n");

	exit(VMI_SUCCESS == status ? EXIT_SUCCESS : EXIT_FAILURE);
}

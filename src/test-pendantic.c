#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "guestrace.h"
#include "generated-windows.h"
#include "generated-linux.h"

GtLoop *loop = NULL;

/* Variables to hold command-line options and arguments. */
char *name            = NULL;

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
	fprintf(stderr, "usage: guestrace [-i syscall1,syscall2] [-s] [-v] "
	                "-n <VM name>\n"
	                "\n"
	                "-n  name of guest to instrument\n");
}

void *handle_open_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	vmi_event_t *event = gt_guest_get_vmi_event(state);

	char *arg0 = gt_guest_get_string(state, event->x86_regs->rdi, pid);

	if (!g_utf8_validate(arg0, -1, NULL)) {
		fprintf(stderr, "Bad string in argument to open.\n");
		fprintf(stderr, "Open %s\n", arg0);
		g_assert_not_reached();
	} else {
		fprintf(stderr, "Open %s\n", arg0);
	}

	return NULL;
}

void handle_open_return(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data) {
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

	while ((opt = getopt(argc, argv, "hn:")) != -1) {
		switch (opt) {
		case 'n':
			name = optarg;
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
	gt_loop_free(loop);

	exit(VMI_SUCCESS == status ? EXIT_SUCCESS : EXIT_FAILURE);
}

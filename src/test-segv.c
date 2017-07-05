#define XC_WANT_COMPAT_EVTCHN_API

#include <setjmp.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "gt.h"
#include "generated-linux.h"

static GtLoop *_loop         = NULL;
static char *_name           = NULL;
static gboolean _test_return = FALSE;

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
_close_handler (int sig)
{
	gt_loop_quit(_loop);
}

static void
_close_handler_emergency (int sig)
{
	fprintf(stderr, "received emergency signal %d\n", sig);

	gt_loop_quit(_loop);

	gt_loop_jmp_past_cb(_loop);
}

static int
_set_up_signal_handler (struct sigaction act)
{
	int rc = 0;

	act.sa_handler = _close_handler;
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
	act.sa_handler = _close_handler_emergency;
	act.sa_flags = 0;

	rc = sigaction(SIGSEGV, &act, NULL);
	if (-1 == rc) {
		goto done;
	}

done:
	return rc;
}

static void
_usage()
{
	fprintf(stderr, "usage: guestrace -n <VM name> [-r]\n"
	                "\n"
	                "-n  name of guest to instrument\n");
}

static void *
_handle_open_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	if (!_test_return) {
		kill(0, SIGSEGV);
		g_assert_not_reached();
	}

	return NULL;
}

static void
_handle_open_return(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data) {
	if (_test_return) {
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
		{ "sys_open", _handle_open_args, _handle_open_return },
		{ NULL, NULL, NULL },
	};

	while ((opt = getopt(argc, argv, "hn:r")) != -1) {
		switch (opt) {
		case 'n':
			_name = optarg;
			break;
		case 'r':
			_test_return = TRUE;
			break;
		case 'h':
		default:
			_usage();
			goto done;
		}
	}

	if (NULL == _name) {
		_usage();
		goto done;
	}

	if (-1 == _set_up_signal_handler(act)) {
		perror("failed to setup signal handler.\n");
		goto done;
	}

	_loop = gt_loop_new(_name);
	if (NULL == _loop) {
		fprintf(stderr, "could not initialize guestrace\n");
		goto done;
	}

	fprintf(stderr, "set up callbacks\n");

	count = gt_loop_set_cbs(_loop, registry);
	if (0 == count) {
		fprintf(stderr, "unable to instrument any system calls\n");
		goto done;
	}

	fprintf(stderr, "run loop\n");

	status = VMI_SUCCESS;

	gt_loop_run(_loop);

done:
	fprintf(stderr, "done\n");

	gt_loop_free(_loop);

	fprintf(stderr, "exiting\n");

	exit(VMI_SUCCESS == status ? EXIT_SUCCESS : EXIT_FAILURE);
}

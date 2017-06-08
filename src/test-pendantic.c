#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "gt.h"
#include "generated-linux.h"

static GtLoop *_loop = NULL;
static char *_name   = NULL;

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

done:
	return rc;
}

static void
_usage()
{
	fprintf(stderr, "usage: guestrace -n <VM name>\n"
	                "\n"
	                "-n  name of guest to instrument\n");
}

static void *
_handle_open_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct args_open *args;

	args           = g_new0(struct args_open, 1);
	args->pathaddr = gt_guest_get_register(state, RDI);
	args->flags    = gt_guest_get_register(state, RSI);
	args->mode     = gt_guest_get_register(state, RDX);

	return args;
}

static void
_handle_open_return(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data) {
	struct args_open *args = user_data;
	int ret                = gt_guest_get_register(state, RAX);
	char *proc             = gt_guest_get_process_name(state);
	char *pathname         = gt_guest_get_string(state, args->pathaddr, pid);

	g_assert(NULL != proc);

	if (!g_utf8_validate(proc, -1, NULL)) {
		fprintf(stderr, "Bad process name (open): %d/%s.\n", pid, proc);
	}

	if (ret < 0) {
		goto done;
	}

	if (NULL == pathname || !g_utf8_validate(pathname, -1, NULL)) {
		fprintf(stderr, "%s open(%s [%lx], %d, %d) = %d\n",
		                 proc,
		                 pathname,
		                 args->pathaddr,
		                 args->flags,
		                 args->mode,
	                         ret);
	}

done:
	g_free(args);
}

static void *
_handle_clone_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	return NULL;
}

static void
_handle_clone_return(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data) {
	char *proc = gt_guest_get_process_name(state);

	if (!g_utf8_validate(proc, -1, NULL)) {
		fprintf(stderr, "Bad process name (clone): %d/%s.\n", pid, proc);
	}
}

static void *
_handle_execve_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct args_execve *args;
	char *proc = gt_guest_get_process_name(state);

	if (!g_utf8_validate(proc, -1, NULL)) {
		fprintf(stderr, "Bad process name (execve): %d/%s.\n", pid, proc);
	}

	args           = g_new0(struct args_execve, 1);
	args->fileaddr = gt_guest_get_register(state, RDI);

	return args;
}

static void
_handle_execve_return(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data) {
	int ret = gt_guest_get_register(state, RAX);
	char *proc = gt_guest_get_process_name(state);

	g_assert(NULL != proc);

	if (!g_utf8_validate(proc, -1, NULL)) {
		fprintf(stderr, "Bad process name (execve): %d/%s.\n", pid, proc);
	}

	fprintf(stderr, "%s call to execve returned %d\n", proc, ret);

	g_free(user_data);
}

int
main (int argc, char **argv) {
	int opt, count;
	struct sigaction act;
	status_t status = VMI_FAILURE;

	const GtCallbackRegistry registry[] = {
		{ "sys_open", _handle_open_args, _handle_open_return },
		{ "sys_clone", _handle_clone_args, _handle_clone_return },
		{ "stub_execve", _handle_execve_args, _handle_execve_return },
		{ NULL, NULL, NULL },
	};

	while ((opt = getopt(argc, argv, "hn:")) != -1) {
		switch (opt) {
		case 'n':
			_name = optarg;
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
	gt_loop_free(_loop);

	exit(VMI_SUCCESS == status ? EXIT_SUCCESS : EXIT_FAILURE);
}

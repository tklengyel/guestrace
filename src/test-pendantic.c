#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "gt.h"
#include "generated-linux.h"

GtLoop *loop = NULL;
char *name   = NULL;

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
	fprintf(stderr, "usage: guestrace -n <VM name>\n"
	                "\n"
	                "-n  name of guest to instrument\n");
}

void *
handle_open_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct args_open *args;

	args           = g_new0(struct args_open, 1);
	args->pathaddr = gt_guest_get_register(state, RDI);
	args->flags    = gt_guest_get_register(state, RSI);
	args->mode     = gt_guest_get_register(state, RDX);

	return args;
}

void
handle_open_return(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data) {
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

void *
handle_clone_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	return NULL;
}

void
handle_clone_return(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data) {
	char *proc = gt_guest_get_process_name(state);

	if (!g_utf8_validate(proc, -1, NULL)) {
		fprintf(stderr, "Bad process name (clone): %d/%s.\n", pid, proc);
	}
}

void *
handle_execve_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
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

void
handle_execve_return(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data) {
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
		{ "sys_open", handle_open_args, handle_open_return },
		{ "sys_clone", handle_clone_args, handle_clone_return },
		{ "stub_execve", handle_execve_args, handle_execve_return },
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

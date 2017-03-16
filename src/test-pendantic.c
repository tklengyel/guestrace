#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "guestrace.h"
#include "generated-linux.h"

GtLoop *loop = NULL;
char *name   = NULL;

struct args_open {
	addr_t pathaddr;
	char  *pathname;
	int    flags;
	int    mode;
};

struct args_execve {
	addr_t fileaddr;
	char  *filename;
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
	fprintf(stderr, "usage: guestrace [-i syscall1,syscall2] [-s] [-v] "
	                "-n <VM name>\n"
	                "\n"
	                "-n  name of guest to instrument\n");
}

void *handle_open_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct args_open *args;

	args           = g_new0(struct args_open, 1);
	args->pathaddr = gt_guest_get_register(state, RDI);
	args->pathname = gt_guest_get_string(state, args->pathaddr, pid);
	args->flags    = gt_guest_get_register(state, RSI);
	args->mode     = gt_guest_get_register(state, RDX);

	g_assert(NULL != args->pathname);

	return args;
}

void handle_open_return(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data) {
	struct args_open *args = user_data;
	int ret                = gt_guest_get_register(state, RAX);
	char *proc             = gt_guest_get_process_name(state, pid);

	g_assert(NULL != proc);

	if (!g_utf8_validate(proc, -1, NULL)) {
		fprintf(stderr, "Bad string in process name.\n");
		fprintf(stderr, "Process %d/%s\n", pid, proc);
		g_assert_not_reached();
	} else {
		fprintf(stderr, "Process %d/%s; ", pid, proc);
	}

	fprintf(stderr, "return %d; ", ret);

	if (!g_utf8_validate(args->pathname, -1, NULL)) {
		fprintf(stderr, "bad argument to open [%lx].\n", args->pathaddr);
		fprintf(stderr, "open(%s [%lx], %d, %d)\n",
		                 args->pathname,
		                 args->pathaddr,
		                 args->flags,
		                 args->mode);
		g_assert_not_reached();
	} else {
		fprintf(stderr, "open(%s [%lx], %d, %d)\n",
		                 args->pathname,
		                 args->pathaddr,
		                 args->flags,
		                 args->mode);
	}

	g_free(args);
}

void *handle_clone_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	return NULL;
}

void handle_clone_return(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data) {
	char *proc = gt_guest_get_process_name(state, pid);

	if (!g_utf8_validate(proc, -1, NULL)) {
		fprintf(stderr, "Bad string in process name.\n");
		fprintf(stderr, "Process %d/%s\n", pid, proc);
		g_assert_not_reached();
	} else {
		fprintf(stderr, "Process %d/%s; ", pid, proc);
	}

	fprintf(stderr, "clone returned\n");
}

void *handle_execve_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct args_execve *args;
	char *proc = gt_guest_get_process_name(state, pid);

	if (!g_utf8_validate(proc, -1, NULL)) {
		fprintf(stderr, "Bad string in process name.\n");
		fprintf(stderr, "Process %d/%s\n", pid, proc);
		g_assert_not_reached();
	} else {
		fprintf(stderr, "Process %d/%s; ", pid, proc);
	}

	args           = g_new0(struct args_execve, 1);
	args->fileaddr = gt_guest_get_register(state, RDI);
	args->filename = gt_guest_get_string(state, args->fileaddr, pid);

	g_assert(NULL != args->filename);

	if (!g_utf8_validate(args->filename, -1, NULL)) {
		fprintf(stderr, "bad argument to execve [%lx].\n", args->fileaddr);
		fprintf(stderr, "execve(%s [%lx], ...)\n",
		                 args->filename,
		                 args->fileaddr);
		g_assert_not_reached();
	} else {
		fprintf(stderr, "execve(%s [%lx], ...)\n",
		                 args->filename,
		                 args->fileaddr);
	}

	return args;
}

void handle_execve_return(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data) {
	int ret = gt_guest_get_register(state, RAX);
	char *proc = gt_guest_get_process_name(state, pid);

	g_assert(NULL != proc);

	if (!g_utf8_validate(proc, -1, NULL)) {
		fprintf(stderr, "Bad string in process name.\n");
		fprintf(stderr, "Process %d/%s\n", pid, proc);
		g_assert_not_reached();
	} else {
		fprintf(stderr, "Process %d/%s; ", pid, proc);
	}

	fprintf(stderr, "WARNING: execve returned %d\n", ret);

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

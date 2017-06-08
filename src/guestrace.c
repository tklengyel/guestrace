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
char *instrument_list = NULL;
gboolean silent       = FALSE;
gboolean verbose      = FALSE;

static void
_close_handler (int sig)
{
	gt_loop_quit(loop);
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
	fprintf(stderr, "usage: guestrace [-i syscall1,syscall2] [-s] [-v] "
	                "-n <VM name>\n"
	                "\n"
	                "-i  specify subset of system calls to instrument\n"
	                "-s  operate in silent mode (no output on call/ret)\n"
	                "-v  verbose\n"
	                "-n  name of guest to instrument\n");
}

static int
_message(const char *format, ...)
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

void *silent_syscall(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{

	static long count = 1;

	if (0 == count % 1000) {
		fprintf(stderr, "%ld system calls invoked\n", count);
	}

	count++;

	return NULL;
}

void silent_sysret(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data) {
}

static GtCallbackRegistry *
_registry_dup(const GtCallbackRegistry *registry)
{
	GtCallbackRegistry *copy;
	int count = 0;

	while (NULL != registry[count].name) {
		count++;
	}

	copy = g_new0(GtCallbackRegistry, count + 1);

	for (int i = 0; i < count; i++) {
		copy[i] = registry[i];
	}

	copy[count] = (GtCallbackRegistry) { NULL };

	return copy;
}

static GtCallbackRegistry *
_registry_build(const GtCallbackRegistry *registry, char *instrument_list)
{
	int i;
	GtCallbackRegistry *new = NULL;

	if (NULL == instrument_list) {
		new = _registry_dup(registry);
	} else if (0 == strlen(instrument_list)) {
		new = g_new0(GtCallbackRegistry, 1);
		new[0] = (GtCallbackRegistry) { NULL };
	} else {
		int size, j;
		char *ptr, *token;

		size = 2; /* At least one syscall + NULL record. */

		ptr = strchr(instrument_list, ',');
		while (NULL != ptr) {
			size++;
			ptr = strchr(ptr + 1, ',');
		}

		new = g_new0(GtCallbackRegistry, size);

		new[size - 1] = (GtCallbackRegistry) { NULL };

		token = strtok_r(instrument_list, ",", &ptr);
		for (i = 0; i < size - 1; i++) {
			for (j = 0; NULL != registry[j].name; j++) {
				if (0 == strcmp(registry[j].name, token)) {
					new[i] = registry[j];
					break;
				}
			}

			if (NULL == new[i].name) {
				g_free(new);
				new = NULL;
				goto done;
			}

			token = strtok_r(NULL, ",", &ptr);
		}
	}

	if (silent) {
		for (i = 0; NULL != new[i].name; i++) {
			new[i].syscall_cb = silent_syscall;
			new[i].sysret_cb  = silent_sysret;
		}
	}

done:
	return new;
}

int
main (int argc, char **argv) {
	int opt, count;
	struct sigaction act;
	const GtCallbackRegistry *orig_registry;
	GtCallbackRegistry *registry = NULL;
	status_t status = VMI_FAILURE;

	while ((opt = getopt(argc, argv, "hi:n:sv")) != -1) {
		switch (opt) {
		case 'i':
			instrument_list = optarg;
			break;
		case 'n':
			name = optarg;
			break;
		case 's':
			silent = TRUE;
			break;
		case 'v':
			verbose = TRUE;
			break;
		case 'h':
		default:
			_usage();
			goto done;
		}
	}

	if (NULL == name) {
		_usage();
		goto done;
	}

	if (NULL != instrument_list && 0 == strlen(instrument_list)) {
		_usage();
		goto done;
	}

	_message("setting up signal handlers\n");

	if (-1 == _set_up_signal_handler(act)) {
		perror("failed to setup signal handler.\n");
		goto done;
	}

	_message("creating event loop\n");

	loop = gt_loop_new(name);
	if (NULL == loop) {
		fprintf(stderr, "could not initialize guestrace\n");
		goto done;
	}

	_message("identifying OS type ... ");

	GtOSType os = gt_loop_get_ostype(loop);

	switch (os) {
	case GT_OS_LINUX:
		orig_registry = GENERATED_LINUX_SYSCALLS;
		break;
	case GT_OS_WINDOWS:
		orig_registry = GENERATED_WINDOWS_SYSCALLS;
		break;
	default:
		fprintf(stderr, "unknown guest operating system\n");
		goto done;
	}

	_message("%s\n", GT_OS_LINUX == os ? "linux" : "windows");

	registry = _registry_build(orig_registry, instrument_list);
	if (NULL == registry) {
		fprintf(stderr, "error building system call registry\n");
		goto done;
	}

	_message("establishing callbacks (might take a few seconds) ... ");

	count = gt_loop_set_cbs(loop, registry);
	if (0 == count) {
		fprintf(stderr, "unable to instrument any system calls\n");
		goto done;
	}

	_message("%d system calls instrumented\n", count);

	_message("running event loop ...\n");

	status = VMI_SUCCESS;
	gt_loop_run(loop);

done:
	_message("freeing event loop\n");

	gt_loop_free(loop);
	g_free(registry);

	exit(VMI_SUCCESS == status ? EXIT_SUCCESS : EXIT_FAILURE);
}

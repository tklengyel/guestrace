#ifndef GUESTRACE_H
#define GUESTRACE_H

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <glib.h>
#include <libxl.h>
#include <xenctrl.h>

/**
 * GTLoop
 *
 * The `GTLoop` struct is an opaque data type
 * representing the main event loop of a guestrace application.
 */
typedef struct _GTLoop GTLoop;

/**
 * GTSyscallFunc:
 * 
 * Specifies one of the two types of functions passed to gt_loop_set_cb().
 * Returns a pointer that gets passed to the sysret function
 */
typedef void *(*GTSyscallFunc) (vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid);

/**
 * GTSysretFunc:
 * 
 * Specifies one of the two types of functions passed to gt_loop_set_cb().
 */
typedef void (*GTSysretFunc) (vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, void * data);

enum {
	GT_OS_UNKNOWN,
	GT_OS_WINDOWS,
	GT_OS_LINUX,
};

typedef int GTOSType;

GTLoop  *gt_loop_new(const char *guest_name);
GTOSType gt_loop_get_ostype(GTLoop *loop);
void     gt_loop_set_cb(GTLoop *loop,
                        const char *kernel_func,
                        GTSyscallFunc syscall_cb,
                        GTSysretFunc sysret_cb);
void     gt_loop_run(GTLoop *loop);
void     gt_loop_quit(GTLoop *loop);
void     gt_loop_free(GTLoop *loop);

#endif

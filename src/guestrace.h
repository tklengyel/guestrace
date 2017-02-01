#ifndef GUESTRACE_H
#define GUESTRACE_H

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <glib.h>
#include <libxl.h>
#include <xenctrl.h>

/**
 * GtLoop
 *
 * The `GtLoop` struct is an opaque data type
 * representing the main event loop of a guestrace application.
 */
typedef struct _GtLoop GtLoop;

typedef addr_t    gt_addr_t;
typedef addr_t    gt_tid_t;
typedef vmi_pid_t gt_pid_t;
typedef reg_t     gt_reg_t;
typedef registers_t gt_reg_name_t;

/**
 * GtGuestState
 *
 * The `GtGuestState` struct is an opaque data type representing the state of
 * the instrumented guest.
 */
typedef struct _GtGuestState GtGuestState;

/**
 * GtSyscallFunc:
 * @vmi: the libvmi instance which abstracts the guest.
 * @event: the event which abstracts the system call which caused the guestrace
 * event loop to invoke this function.
 * @pid: the ID of the process running when the event occurred.
 * @tid: the unique ID of the thread running within the current process.
 * @user_data: optional data which might have been passed to the
 * corresponding gt_loop_set_cb(); if set, the guestrace event loop will pass it
 * here.
 * 
 * Specifies one of the two types of functions passed to gt_loop_set_cb().
 * The guestrace event loop invokes this callback each time a program running
 * on the guest invokes the corresponding system call. Implementations can
 * optionally return a pointer which the guestrace event loop will later pass
 * to the corresponding #GtSysretFunc after the system call returns.
 */
typedef void *(*GtSyscallFunc) (GtGuestState *state,
                                gt_pid_t pid,
                                gt_tid_t tid,
                                void *user_data);

/**
 * GtSysretFunc:
 * @vmi: the libvmi instance which abstracts the guest.
 * @event: the event which abstracts the system return which caused the guestrace event loop to invoke this function.
 * @pid: the ID of the process running when the event occurred.
 * @tid: the unique ID of the thread running within the current process.
 * @user_data: the return value from #GtSyscallFunc which the guestrace event loop passes to #GtSysretFunc.
 * 
 * Specifies one of the two types of functions passed to gt_loop_set_cb().
 * The guestrace event loop invokes this callback each time a system call on
 * the guest returns control to a program. It is the responsibility of each
 * #GtSysretFunc implementation to free @user_data if the corresponding
 * #GtSyscallFunc returned a pointer to a dynamically-allocated object.
 */
typedef void (*GtSysretFunc) (GtGuestState *state,
                              gt_pid_t pid,
                              gt_tid_t tid,
                              void *user_data);

/**
 * GtCallbackRegistry
 * @name: the name of the kernel function to instrument.
 * @syscall_cb: the #GtSyscallFunc which the guestrace event loop will invoke upon @name being called.
 * @sysret_cb: the #GtSysretFunc which the guestrace event loop will invoke when @name returns.
 *
 * Full callback definition for use with gt_loop_set_cbs().
 */
typedef struct GtCallbackRegistry {
        /* <private> */
        char         *name;
        GtSyscallFunc syscall_cb;
        GtSysretFunc  sysret_cb;
        void         *user_data;
} GtCallbackRegistry;

/**
 * GtOSType:
 * @GT_OS_UNKNOWN: an unknown operating system.
 * @GT_OS_LINUX: a Linux operating system.
 * @GT_OS_WINDOWS: a Windows operating system.
 *
 * Enum values which specify the operating system running on the guest.
 */
typedef enum GtOSType {
	GT_OS_UNKNOWN,
	GT_OS_WINDOWS,
	GT_OS_LINUX,
	/* <private> */
	GT_OS_COUNT,
} GtOSType;

GtLoop        *gt_loop_new(const char *guest_name);
GtOSType       gt_loop_get_ostype(GtLoop *loop);
gboolean       gt_loop_set_cb(GtLoop *loop,
                              const char *kernel_func,
                              GtSyscallFunc syscall_cb,
                              GtSysretFunc sysret_cb,
                              void *user_data);
int            gt_loop_set_cbs(GtLoop *loop,
                               const GtCallbackRegistry callbacks[]);
gt_reg_t       gt_guest_get_register(GtGuestState *state, gt_reg_name_t name);
char          *gt_guest_get_string(GtGuestState *state, gt_addr_t vaddr, gt_pid_t pid);
vmi_instance_t gt_guest_get_vmi_instance(GtGuestState *state);
vmi_event_t   *gt_guest_get_vmi_event(GtGuestState *state);
void           gt_loop_run(GtLoop *loop);
void           gt_loop_quit(GtLoop *loop);
void           gt_loop_free(GtLoop *loop);

#endif

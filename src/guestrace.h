#ifndef GUESTRACE_H
#define GUESTRACE_H

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <glib.h>
#include <libxl.h>
#include <setjmp.h>
#include <xenctrl.h>

/**
 * GtLoop
 *
 * The `GtLoop` struct is an opaque data type
 * representing the main event loop of a guestrace application.
 */
typedef struct _GtLoop GtLoop;

/**
 * GtGuestState
 *
 * The `GtGuestState` struct is an opaque data type representing the state of
 * the instrumented guest.
 */
typedef struct _GtGuestState GtGuestState;

/**
 * gt_reg_name_t
 *
 * The `gt_reg_name_t` enum contains the valid names
 * of the registers found on the guest.
 */
typedef int gt_reg_name_t;

/**
 * gt_addr_t:
 *
 * A guest virtual memory address.
 */
typedef addr_t    gt_addr_t;

/**
 * gt_pid_t:
 *
 * The unique identifier for a guest process.
 */
typedef vmi_pid_t gt_pid_t;

/**
 * gt_tid_t:
 *
 * An identifier which serves to correlate between calls and returns
 * at thread granularity. Generally the value of the stack pointer
 * upon invoking a system call.
 */
typedef addr_t    gt_tid_t;

/**
 * gt_reg_t:
 *
 * The value of some guest register.
 */
typedef reg_t     gt_reg_t;

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
const char    *gt_loop_get_guest_name(GtLoop *loop);
vmi_instance_t gt_loop_get_vmi_instance(GtLoop *loop);
gboolean       gt_loop_set_cb(GtLoop *loop,
                              const char *kernel_func,
                              GtSyscallFunc syscall_cb,
                              GtSysretFunc sysret_cb,
                              void *user_data);
int            gt_loop_set_cbs(GtLoop *loop,
                               const GtCallbackRegistry callbacks[]);
unsigned long  gt_loop_get_syscall_count(GtLoop *loop);
guint          gt_loop_add_watch(GIOChannel *channel,
                                 GIOCondition condition,
                                 GIOFunc func,
                                 gpointer user_data);
gt_reg_t       gt_guest_get_register(GtGuestState *state, gt_reg_name_t name);
size_t         gt_guest_get_bytes(GtGuestState *state, gt_addr_t vaddr, gt_pid_t pid, void *buf, size_t count);
char          *gt_guest_get_string(GtGuestState *state, gt_addr_t vaddr, gt_pid_t pid);
char         **gt_guest_get_argv(GtGuestState *state, gt_addr_t vaddr, gt_pid_t pid);
vmi_instance_t gt_guest_get_vmi_instance(GtGuestState *state);
vmi_event_t   *gt_guest_get_vmi_event(GtGuestState *state);
char          *gt_guest_get_process_name(GtGuestState *state, gt_pid_t pid);
void           gt_guest_free_syscall_state(GtGuestState *state, gt_tid_t thread_id);
gboolean       gt_guest_hijack_return(GtGuestState *state, reg_t retval);
gboolean       gt_guest_drop_return_breakpoint(GtGuestState *state, gt_tid_t thread_id);
void           gt_loop_run(GtLoop *loop);
void           gt_loop_quit(GtLoop *loop);
void           gt_loop_free(GtLoop *loop);
void           gt_loop_jmp_past_cb(GtLoop *loop);

#endif

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

typedef struct vf_page_record {
	addr_t frame;
	addr_t shadow_page;
	GHashTable *children;
	GTLoop *loop;
} vf_page_record;

typedef struct vf_paddr_record vf_paddr_record;

typedef struct GTSyscallState {
	vf_paddr_record   *syscall_trap;
	void              *data;
} GTSyscallState;

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

struct vf_paddr_record {
	addr_t offset;
	GTSyscallFunc syscall_cb;
        GTSysretFunc  sysret_cb;
	vf_page_record *parent;
};

struct syscall_defs {
	char         *name;
	GTSyscallFunc syscall_cb;
	GTSysretFunc  sysret_cb;
};

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

/* Operating-system-specific operations. */
struct os_functions {
        addr_t (*find_return_point_addr) (GTLoop *loop);
};

struct vf_paddr_record *vf_setup_mem_trap (GTLoop *loop,
                                           addr_t va,
                                           GTSyscallFunc syscall_cb,
                                           GTSysretFunc sysret_cb);
bool vf_find_syscalls_and_setup_mem_traps(GTLoop *loop,
                                          const struct syscall_defs syscalls[],
                                          const char *traced_syscalls[]);
addr_t vf_find_addr_after_instruction(GTLoop *loop,
                                      addr_t start_v,
                                      char *mnemonic,
                                      char *ops);

#endif

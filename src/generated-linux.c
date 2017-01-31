/* Generated on Linux_4.9.3-200.fc25.x86_64 on 30 Jan 2017 17:39:14*/

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "generated-linux.h"

static const int RETURN_ADDR_WIDTH = sizeof(void *);

void
_gt_linux_find_syscalls_and_setup_mem_traps(GTLoop *loop)
{
        gt_loop_set_cbs(loop, VM_LINUX_SYSCALLS);
}

static char *
get_process_name(vmi_instance_t vmi, vmi_pid_t pid) 
{
	/* Gets the process name of the process with the input pid */
	/* offsets from the LibVMI config file */	
	unsigned long task_offset = vmi_get_offset(vmi, "linux_tasks");
	unsigned long pid_offset = vmi_get_offset(vmi, "linux_pid");
	unsigned long name_offset = vmi_get_offset(vmi, "linux_name");
	
	/* addresses for the linux process list and current process */
	addr_t list_head = 0;
	addr_t list_curr = 0;
	addr_t curr_proc = 0;
	
	vmi_pid_t curr_pid = 0;		/* pid of the processes task struct we are examining */
	char *proc = NULL;		/* process name of the current process we are examining */

	list_head = vmi_translate_ksym2v(vmi, "init_task") + task_offset; 	/* get the address to the head of the process list */

	if (list_head == task_offset) {
		fprintf(stderr, "failed to read address for init_task\n");
		goto done;
	}
	
	list_curr = list_head;							/* set the current process to the head */

	do{
		curr_proc = list_curr - task_offset;						/* subtract the task offset to get to the start of the task_struct */
		if (VMI_FAILURE == vmi_read_32_va(vmi, curr_proc + pid_offset, 0, (uint32_t*)&curr_pid)) {		/* read the current pid using the pid offset from the start of the task struct */
			fprintf(stderr, "failed to get the pid of the process we are examining\n");
			goto done;
		}
	
		if (pid == curr_pid) {
			proc = vmi_read_str_va(vmi, curr_proc + name_offset, 0);		/* get the process name if the current pid is equal to the pis we are looking for */
			goto done;								/* go to done to exit */
		}
	
		if (VMI_FAILURE == vmi_read_addr_va(vmi, list_curr, 0, &list_curr)) {				/* read the memory from the address of list_curr which will return a pointer to the */
			fprintf(stderr, "failed to get the next task in the process list\n");
			goto done;
		}

	} while (list_curr != list_head);							/* next task_struct. Continue the loop until we get back to the beginning as the  */
												/* process list is doubly linked and circular */

done:
	if (NULL == proc) {		/* if proc is NULL we don't know the process name */
		return "unknown";
	}
	
	return proc;

}

void *gt_linux_print_syscall_sys_read(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_read", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_write(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_write", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_open(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	char *arg0 = vmi_read_str_va(vmi, event->x86_regs->rdi, pid);
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(\"%s\", %i, %lu)\n", pid, rsp, proc, "sys_open", (char *) arg0, (int) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_close(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_close", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_stat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_stat", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_fstat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_fstat", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_lstat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_lstat", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_poll(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %i)\n", pid, rsp, proc, "sys_poll", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_lseek(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_lseek", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_mmap(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_mmap");
	return NULL;
}

void *gt_linux_print_syscall_sys_mprotect(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu)\n", pid, rsp, proc, "sys_mprotect", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_munmap(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_munmap", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_brk(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_brk", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_rt_sigaction(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_rt_sigaction", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_rt_sigprocmask(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_rt_sigprocmask", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_rt_sigreturn(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_rt_sigreturn");
	return NULL;
}

void *gt_linux_print_syscall_sys_ioctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu)\n", pid, rsp, proc, "sys_ioctl", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_pread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %li)\n", pid, rsp, proc, "sys_pread", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (long int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_pwrite(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %li)\n", pid, rsp, proc, "sys_pwrite", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (long int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_readv(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_readv", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_writev(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_writev", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_access(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_access", (unsigned long) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_pipe(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_pipe", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_select(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_select", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_yield(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_sched_yield");
	return NULL;
}

void *gt_linux_print_syscall_sys_mremap(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu, %lu, %lu)\n", pid, rsp, proc, "sys_mremap", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_msync(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i)\n", pid, rsp, proc, "sys_msync", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_mincore(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_mincore", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_madvise(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i)\n", pid, rsp, proc, "sys_madvise", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_shmget(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %i)\n", pid, rsp, proc, "sys_shmget", (int) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_shmat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_shmat", (int) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_shmctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_shmctl", (int) arg0, (int) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_dup(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_dup", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_dup2(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_dup2", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_pause(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_pause");
	return NULL;
}

void *gt_linux_print_syscall_sys_nanosleep(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_nanosleep", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_getitimer(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_getitimer", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_alarm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_alarm", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_setitimer(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_setitimer", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_getpid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_getpid");
	return NULL;
}

void *gt_linux_print_syscall_sys_sendfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_sendfile", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_socket(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i)\n", pid, rsp, proc, "sys_socket", (int) arg0, (int) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_connect(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_connect", (int) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_accept(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_accept", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_sendto(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_sendto", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (int) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_recvfrom(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_recvfrom", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_sendmsg(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_sendmsg", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_recvmsg(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_recvmsg", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_shutdown(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_shutdown", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_bind(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_bind", (int) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_listen(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_listen", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_getsockname(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_getsockname", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_getpeername(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_getpeername", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_socketpair(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_socketpair", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_setsockopt(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_setsockopt", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_getsockopt(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_getsockopt", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_clone(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, 0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_clone", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_fork(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_fork");
	return NULL;
}

void *gt_linux_print_syscall_sys_vfork(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_vfork");
	return NULL;
}

void *gt_linux_print_syscall_sys_execve(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_execve", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_exit(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_exit", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_wait4(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_wait4", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_kill(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_kill", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_uname(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_uname", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_semget(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i)\n", pid, rsp, proc, "sys_semget", (int) arg0, (int) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_semop(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_semop", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_semctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, %lu)\n", pid, rsp, proc, "sys_semctl", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_shmdt(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_shmdt", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_msgget(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_msgget", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_msgsnd(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %i)\n", pid, rsp, proc, "sys_msgsnd", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_msgrcv(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %li, %i)\n", pid, rsp, proc, "sys_msgrcv", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (long int) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_msgctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_msgctl", (int) arg0, (int) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_fcntl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu)\n", pid, rsp, proc, "sys_fcntl", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_flock(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_flock", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_fsync(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_fsync", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_fdatasync(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_fdatasync", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_truncate(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %li)\n", pid, rsp, proc, "sys_truncate", (unsigned long) arg0, (long int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_ftruncate(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_ftruncate", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_getdents(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_getdents", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_getcwd(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_getcwd", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_chdir(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_chdir", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_fchdir(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_fchdir", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_rename(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_rename", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_mkdir(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_mkdir", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_rmdir(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_rmdir", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_creat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_creat", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_link(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_link", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_unlink(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_unlink", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_symlink(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_symlink", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_readlink(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_readlink", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_chmod(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_chmod", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_fchmod(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_fchmod", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_chown(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_chown", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_fchown(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu)\n", pid, rsp, proc, "sys_fchown", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_lchown(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_lchown", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_umask(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_umask", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_gettimeofday(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_gettimeofday", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_getrlimit(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_getrlimit", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_getrusage(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_getrusage", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_sysinfo(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_sysinfo", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_times(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_times", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_ptrace(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%li, %li, %lu, %lu)\n", pid, rsp, proc, "sys_ptrace", (long int) arg0, (long int) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_getuid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_getuid");
	return NULL;
}

void *gt_linux_print_syscall_sys_syslog(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_syslog", (int) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_getgid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_getgid");
	return NULL;
}

void *gt_linux_print_syscall_sys_setuid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_setuid", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_setgid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_setgid", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_geteuid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_geteuid");
	return NULL;
}

void *gt_linux_print_syscall_sys_getegid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_getegid");
	return NULL;
}

void *gt_linux_print_syscall_sys_setpgid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_setpgid", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_getppid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_getppid");
	return NULL;
}

void *gt_linux_print_syscall_sys_getpgrp(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_getpgrp");
	return NULL;
}

void *gt_linux_print_syscall_sys_setsid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_setsid");
	return NULL;
}

void *gt_linux_print_syscall_sys_setreuid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_setreuid", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_setregid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_setregid", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_getgroups(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_getgroups", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_setgroups(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_setgroups", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_setresuid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu)\n", pid, rsp, proc, "sys_setresuid", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_getresuid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_getresuid", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_setresgid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu)\n", pid, rsp, proc, "sys_setresgid", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_getresgid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_getresgid", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_getpgid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_getpgid", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_setfsuid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_setfsuid", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_setfsgid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_setfsgid", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_getsid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_getsid", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_capget(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_capget", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_capset(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_capset", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_rt_sigpending(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_rt_sigpending", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_rt_sigtimedwait(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_rt_sigtimedwait", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_rt_sigqueueinfo(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_rt_sigqueueinfo", (int) arg0, (int) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_rt_sigsuspend(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_rt_sigsuspend", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_sigaltstack(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_sigaltstack", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_utime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_utime", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_mknod(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_mknod", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_uselib(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_uselib", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_personality(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_personality", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_ustat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_ustat", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_statfs(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_statfs", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_fstatfs(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_fstatfs", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_sysfs(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %lu)\n", pid, rsp, proc, "sys_sysfs", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_getpriority(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_getpriority", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_setpriority(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i)\n", pid, rsp, proc, "sys_setpriority", (int) arg0, (int) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_setparam(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_sched_setparam", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_getparam(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_sched_getparam", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_setscheduler(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_sched_setscheduler", (int) arg0, (int) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_getscheduler(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_sched_getscheduler", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_get_priority_max(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_sched_get_priority_max", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_get_priority_min(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_sched_get_priority_min", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_rr_get_interval(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_sched_rr_get_interval", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_mlock(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_mlock", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_munlock(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_munlock", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_mlockall(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_mlockall", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_munlockall(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_munlockall");
	return NULL;
}

void *gt_linux_print_syscall_sys_vhangup(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_vhangup");
	return NULL;
}

void *gt_linux_print_syscall_sys_modify_ldt(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_modify_ldt");
	return NULL;
}

void *gt_linux_print_syscall_sys_pivot_root(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_pivot_root", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_sysctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_sysctl", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_prctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %lu, %lu, %lu)\n", pid, rsp, proc, "sys_prctl", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_arch_prctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_arch_prctl");
	return NULL;
}

void *gt_linux_print_syscall_sys_adjtimex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_adjtimex", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_setrlimit(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_setrlimit", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_chroot(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_chroot", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_sync(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_sync");
	return NULL;
}

void *gt_linux_print_syscall_sys_acct(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_acct", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_settimeofday(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_settimeofday", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_mount(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_mount", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_umount2(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_umount2");
	return NULL;
}

void *gt_linux_print_syscall_sys_swapon(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_swapon", (unsigned long) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_swapoff(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_swapoff", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_reboot(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_reboot", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_sethostname(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_sethostname", (unsigned long) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_setdomainname(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_setdomainname", (unsigned long) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_iopl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_iopl");
	return NULL;
}

void *gt_linux_print_syscall_sys_ioperm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i)\n", pid, rsp, proc, "sys_ioperm", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_create_module(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_create_module");
	return NULL;
}

void *gt_linux_print_syscall_sys_init_module(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_init_module", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_delete_module(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_delete_module", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_get_kernel_syms(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_get_kernel_syms");
	return NULL;
}

void *gt_linux_print_syscall_sys_query_module(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_query_module");
	return NULL;
}

void *gt_linux_print_syscall_sys_quotactl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_quotactl", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_nfsservctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_nfsservctl");
	return NULL;
}

void *gt_linux_print_syscall_sys_getpmsg(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_getpmsg");
	return NULL;
}

void *gt_linux_print_syscall_sys_putpmsg(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_putpmsg");
	return NULL;
}

void *gt_linux_print_syscall_sys_afs_syscall(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_afs_syscall");
	return NULL;
}

void *gt_linux_print_syscall_sys_tuxcall(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_tuxcall");
	return NULL;
}

void *gt_linux_print_syscall_sys_security(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_security");
	return NULL;
}

void *gt_linux_print_syscall_sys_gettid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_gettid");
	return NULL;
}

void *gt_linux_print_syscall_sys_readahead(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %li, %lu)\n", pid, rsp, proc, "sys_readahead", (int) arg0, (long int) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_setxattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n", pid, rsp, proc, "sys_setxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_lsetxattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n", pid, rsp, proc, "sys_lsetxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_fsetxattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n", pid, rsp, proc, "sys_fsetxattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_getxattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_getxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_lgetxattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_lgetxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_fgetxattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_fgetxattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_listxattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_listxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_llistxattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_llistxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_flistxattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_flistxattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_removexattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_removexattr", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_lremovexattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_lremovexattr", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_fremovexattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_fremovexattr", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_tkill(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_tkill", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_time(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_time", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_futex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_futex", (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_setaffinity(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_sched_setaffinity", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_getaffinity(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_sched_getaffinity", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_set_thread_area(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_set_thread_area");
	return NULL;
}

void *gt_linux_print_syscall_sys_io_setup(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_io_setup", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_io_destroy(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_io_destroy", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_io_getevents(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %li, %li, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_io_getevents", (unsigned long) arg0, (long int) arg1, (long int) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_io_submit(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %li, 0x%"PRIx64")\n", pid, rsp, proc, "sys_io_submit", (unsigned long) arg0, (long int) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_io_cancel(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_io_cancel", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_get_thread_area(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_get_thread_area");
	return NULL;
}

void *gt_linux_print_syscall_sys_lookup_dcookie(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_lookup_dcookie", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_epoll_create(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_epoll_create", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_epoll_ctl_old(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_epoll_ctl_old");
	return NULL;
}

void *gt_linux_print_syscall_sys_epoll_wait_old(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_epoll_wait_old");
	return NULL;
}

void *gt_linux_print_syscall_sys_remap_file_pages(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu, %lu, %lu)\n", pid, rsp, proc, "sys_remap_file_pages", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_getdents64(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_getdents64", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_set_tid_address(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_set_tid_address", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_restart_syscall(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_restart_syscall");
	return NULL;
}

void *gt_linux_print_syscall_sys_semtimedop(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_semtimedop", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_fadvise64(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %li, %lu, %i)\n", pid, rsp, proc, "sys_fadvise64", (int) arg0, (long int) arg1, (unsigned long) arg2, (int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_timer_create(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_timer_create", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_timer_settime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_timer_settime", (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_timer_gettime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_timer_gettime", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_timer_getoverrun(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_timer_getoverrun", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_timer_delete(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_timer_delete", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_clock_settime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_clock_settime", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_clock_gettime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_clock_gettime", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_clock_getres(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_clock_getres", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_clock_nanosleep(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_clock_nanosleep", (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_exit_group(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_exit_group", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_epoll_wait(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, %i)\n", pid, rsp, proc, "sys_epoll_wait", (int) arg0, (unsigned long) arg1, (int) arg2, (int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_epoll_ctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_epoll_ctl", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_tgkill(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i)\n", pid, rsp, proc, "sys_tgkill", (int) arg0, (int) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_utimes(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_utimes", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_vserver(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_vserver");
	return NULL;
}

void *gt_linux_print_syscall_sys_mbind(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu, 0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_mbind", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_set_mempolicy(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_set_mempolicy", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_get_mempolicy(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu, %lu, %lu)\n", pid, rsp, proc, "sys_get_mempolicy", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_mq_open(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i, %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_mq_open", (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_mq_unlink(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_mq_unlink", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_mq_timedsend(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_mq_timedsend", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_mq_timedreceive(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_mq_timedreceive", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_mq_notify(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_mq_notify", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_mq_getsetattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_mq_getsetattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_kexec_load(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_kexec_load", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_waitid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64", %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_waitid", (int) arg0, (int) arg1, (unsigned long) arg2, (int) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_add_key(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n", pid, rsp, proc, "sys_add_key", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_request_key(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_request_key", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_keyctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %lu, %lu, %lu)\n", pid, rsp, proc, "sys_keyctl", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_ioprio_set(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i)\n", pid, rsp, proc, "sys_ioprio_set", (int) arg0, (int) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_ioprio_get(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_ioprio_get", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_inotify_init(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_inotify_init");
	return NULL;
}

void *gt_linux_print_syscall_sys_inotify_add_watch(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_inotify_add_watch", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_inotify_rm_watch(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_inotify_rm_watch", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_migrate_pages(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_migrate_pages", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_openat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, %lu)\n", pid, rsp, proc, "sys_openat", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_mkdirat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_mkdirat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_mknodat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_mknodat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_fchownat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, %i)\n", pid, rsp, proc, "sys_fchownat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_futimesat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_futimesat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_newfstatat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_newfstatat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_unlinkat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_unlinkat", (int) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_renameat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_renameat", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_linkat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_linkat", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_symlinkat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_symlinkat", (unsigned long) arg0, (int) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_readlinkat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_readlinkat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_fchmodat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_fchmodat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_faccessat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_faccessat", (int) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_pselect6(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_pselect6", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_ppoll(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_ppoll", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_unshare(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_unshare", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_set_robust_list(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_set_robust_list", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_get_robust_list(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_get_robust_list", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_splice(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_splice", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_tee(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %lu, %lu)\n", pid, rsp, proc, "sys_tee", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_sync_file_range(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %li, %li, %lu)\n", pid, rsp, proc, "sys_sync_file_range", (int) arg0, (long int) arg1, (long int) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_vmsplice(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_vmsplice", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_move_pages(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_move_pages", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (int) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_utimensat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_utimensat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_epoll_pwait(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, %i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_epoll_pwait", (int) arg0, (unsigned long) arg1, (int) arg2, (int) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_signalfd(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_signalfd", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_timerfd(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_timerfd");
	return NULL;
}

void *gt_linux_print_syscall_sys_eventfd(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_eventfd", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_fallocate(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %li, %li)\n", pid, rsp, proc, "sys_fallocate", (int) arg0, (int) arg1, (long int) arg2, (long int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_timerfd_settime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_timerfd_settime", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_timerfd_gettime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_timerfd_gettime", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_accept4(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_accept4", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_signalfd4(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %i)\n", pid, rsp, proc, "sys_signalfd4", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_eventfd2(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %i)\n", pid, rsp, proc, "sys_eventfd2", (unsigned long) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_epoll_create1(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_epoll_create1", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_dup3(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i)\n", pid, rsp, proc, "sys_dup3", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_pipe2(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_pipe2", (unsigned long) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_inotify_init1(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_inotify_init1", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_preadv(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %lu, %lu)\n", pid, rsp, proc, "sys_preadv", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_pwritev(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %lu, %lu)\n", pid, rsp, proc, "sys_pwritev", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_rt_tgsigqueueinfo(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_rt_tgsigqueueinfo", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_perf_event_open(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i, %i, %i, %lu)\n", pid, rsp, proc, "sys_perf_event_open", (unsigned long) arg0, (int) arg1, (int) arg2, (int) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_recvmmsg(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_recvmmsg", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_fanotify_init(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_fanotify_init", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_fanotify_mark(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %lu, %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_fanotify_mark", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_prlimit64(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_prlimit64", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_name_to_handle_at(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_name_to_handle_at", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_open_by_handle_at(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_open_by_handle_at", (int) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_clock_adjtime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_clock_adjtime", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_syncfs(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_syncfs", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_sendmmsg(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_sendmmsg", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_setns(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_setns", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_getcpu(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_getcpu", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_process_vm_readv(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_process_vm_readv", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_process_vm_writev(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_process_vm_writev", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_kcmp(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, %lu, %lu)\n", pid, rsp, proc, "sys_kcmp", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_finit_module(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_finit_module", (int) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_setattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_sched_setattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_getattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_sched_getattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_renameat2(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_renameat2", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_seccomp(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_seccomp", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_getrandom(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_getrandom", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_memfd_create(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_memfd_create", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_kexec_file_load(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_kexec_file_load", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_bpf(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_bpf", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_execveat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_execveat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_userfaultfd(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_userfaultfd", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_membarrier(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_membarrier", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_mlock2(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i)\n", pid, rsp, proc, "sys_mlock2", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_copy_file_range(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_copy_file_range", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void gt_linux_print_sysret(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data) {
	reg_t syscall_return = event->x86_regs->rax;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) return: 0x%"PRIx64"\n", pid, rsp - RETURN_ADDR_WIDTH, get_process_name(vmi, pid), syscall_return);
}

const GTSyscallCallback VM_LINUX_SYSCALLS[] = {
	{ "sys_read", gt_linux_print_syscall_sys_read, gt_linux_print_sysret, NULL },
	{ "sys_write", gt_linux_print_syscall_sys_write, gt_linux_print_sysret, NULL },
	{ "sys_open", gt_linux_print_syscall_sys_open, gt_linux_print_sysret, NULL },
	{ "sys_close", gt_linux_print_syscall_sys_close, gt_linux_print_sysret, NULL },
	{ "sys_stat", gt_linux_print_syscall_sys_stat, gt_linux_print_sysret, NULL },
	{ "sys_fstat", gt_linux_print_syscall_sys_fstat, gt_linux_print_sysret, NULL },
	{ "sys_lstat", gt_linux_print_syscall_sys_lstat, gt_linux_print_sysret, NULL },
	{ "sys_poll", gt_linux_print_syscall_sys_poll, gt_linux_print_sysret, NULL },
	{ "sys_lseek", gt_linux_print_syscall_sys_lseek, gt_linux_print_sysret, NULL },
	{ "sys_mmap", gt_linux_print_syscall_sys_mmap, gt_linux_print_sysret, NULL },
	{ "sys_mprotect", gt_linux_print_syscall_sys_mprotect, gt_linux_print_sysret, NULL },
	{ "sys_munmap", gt_linux_print_syscall_sys_munmap, gt_linux_print_sysret, NULL },
	{ "sys_brk", gt_linux_print_syscall_sys_brk, gt_linux_print_sysret, NULL },
	{ "sys_rt_sigaction", gt_linux_print_syscall_sys_rt_sigaction, gt_linux_print_sysret, NULL },
	{ "sys_rt_sigprocmask", gt_linux_print_syscall_sys_rt_sigprocmask, gt_linux_print_sysret, NULL },
	{ "sys_rt_sigreturn", gt_linux_print_syscall_sys_rt_sigreturn, gt_linux_print_sysret, NULL },
	{ "sys_ioctl", gt_linux_print_syscall_sys_ioctl, gt_linux_print_sysret, NULL },
	{ "sys_pread", gt_linux_print_syscall_sys_pread, gt_linux_print_sysret, NULL },
	{ "sys_pwrite", gt_linux_print_syscall_sys_pwrite, gt_linux_print_sysret, NULL },
	{ "sys_readv", gt_linux_print_syscall_sys_readv, gt_linux_print_sysret, NULL },
	{ "sys_writev", gt_linux_print_syscall_sys_writev, gt_linux_print_sysret, NULL },
	{ "sys_access", gt_linux_print_syscall_sys_access, gt_linux_print_sysret, NULL },
	{ "sys_pipe", gt_linux_print_syscall_sys_pipe, gt_linux_print_sysret, NULL },
	{ "sys_select", gt_linux_print_syscall_sys_select, gt_linux_print_sysret, NULL },
	{ "sys_sched_yield", gt_linux_print_syscall_sys_sched_yield, gt_linux_print_sysret, NULL },
	{ "sys_mremap", gt_linux_print_syscall_sys_mremap, gt_linux_print_sysret, NULL },
	{ "sys_msync", gt_linux_print_syscall_sys_msync, gt_linux_print_sysret, NULL },
	{ "sys_mincore", gt_linux_print_syscall_sys_mincore, gt_linux_print_sysret, NULL },
	{ "sys_madvise", gt_linux_print_syscall_sys_madvise, gt_linux_print_sysret, NULL },
	{ "sys_shmget", gt_linux_print_syscall_sys_shmget, gt_linux_print_sysret, NULL },
	{ "sys_shmat", gt_linux_print_syscall_sys_shmat, gt_linux_print_sysret, NULL },
	{ "sys_shmctl", gt_linux_print_syscall_sys_shmctl, gt_linux_print_sysret, NULL },
	{ "sys_dup", gt_linux_print_syscall_sys_dup, gt_linux_print_sysret, NULL },
	{ "sys_dup2", gt_linux_print_syscall_sys_dup2, gt_linux_print_sysret, NULL },
	{ "sys_pause", gt_linux_print_syscall_sys_pause, gt_linux_print_sysret, NULL },
	{ "sys_nanosleep", gt_linux_print_syscall_sys_nanosleep, gt_linux_print_sysret, NULL },
	{ "sys_getitimer", gt_linux_print_syscall_sys_getitimer, gt_linux_print_sysret, NULL },
	{ "sys_alarm", gt_linux_print_syscall_sys_alarm, gt_linux_print_sysret, NULL },
	{ "sys_setitimer", gt_linux_print_syscall_sys_setitimer, gt_linux_print_sysret, NULL },
	{ "sys_getpid", gt_linux_print_syscall_sys_getpid, gt_linux_print_sysret, NULL },
	{ "sys_sendfile", gt_linux_print_syscall_sys_sendfile, gt_linux_print_sysret, NULL },
	{ "sys_socket", gt_linux_print_syscall_sys_socket, gt_linux_print_sysret, NULL },
	{ "sys_connect", gt_linux_print_syscall_sys_connect, gt_linux_print_sysret, NULL },
	{ "sys_accept", gt_linux_print_syscall_sys_accept, gt_linux_print_sysret, NULL },
	{ "sys_sendto", gt_linux_print_syscall_sys_sendto, gt_linux_print_sysret, NULL },
	{ "sys_recvfrom", gt_linux_print_syscall_sys_recvfrom, gt_linux_print_sysret, NULL },
	{ "sys_sendmsg", gt_linux_print_syscall_sys_sendmsg, gt_linux_print_sysret, NULL },
	{ "sys_recvmsg", gt_linux_print_syscall_sys_recvmsg, gt_linux_print_sysret, NULL },
	{ "sys_shutdown", gt_linux_print_syscall_sys_shutdown, gt_linux_print_sysret, NULL },
	{ "sys_bind", gt_linux_print_syscall_sys_bind, gt_linux_print_sysret, NULL },
	{ "sys_listen", gt_linux_print_syscall_sys_listen, gt_linux_print_sysret, NULL },
	{ "sys_getsockname", gt_linux_print_syscall_sys_getsockname, gt_linux_print_sysret, NULL },
	{ "sys_getpeername", gt_linux_print_syscall_sys_getpeername, gt_linux_print_sysret, NULL },
	{ "sys_socketpair", gt_linux_print_syscall_sys_socketpair, gt_linux_print_sysret, NULL },
	{ "sys_setsockopt", gt_linux_print_syscall_sys_setsockopt, gt_linux_print_sysret, NULL },
	{ "sys_getsockopt", gt_linux_print_syscall_sys_getsockopt, gt_linux_print_sysret, NULL },
	{ "sys_clone", gt_linux_print_syscall_sys_clone, gt_linux_print_sysret, NULL },
	{ "sys_fork", gt_linux_print_syscall_sys_fork, gt_linux_print_sysret, NULL },
	{ "sys_vfork", gt_linux_print_syscall_sys_vfork, gt_linux_print_sysret, NULL },
	{ "sys_execve", gt_linux_print_syscall_sys_execve, gt_linux_print_sysret, NULL },
	{ "sys_exit", gt_linux_print_syscall_sys_exit, gt_linux_print_sysret, NULL },
	{ "sys_wait4", gt_linux_print_syscall_sys_wait4, gt_linux_print_sysret, NULL },
	{ "sys_kill", gt_linux_print_syscall_sys_kill, gt_linux_print_sysret, NULL },
	{ "sys_uname", gt_linux_print_syscall_sys_uname, gt_linux_print_sysret, NULL },
	{ "sys_semget", gt_linux_print_syscall_sys_semget, gt_linux_print_sysret, NULL },
	{ "sys_semop", gt_linux_print_syscall_sys_semop, gt_linux_print_sysret, NULL },
	{ "sys_semctl", gt_linux_print_syscall_sys_semctl, gt_linux_print_sysret, NULL },
	{ "sys_shmdt", gt_linux_print_syscall_sys_shmdt, gt_linux_print_sysret, NULL },
	{ "sys_msgget", gt_linux_print_syscall_sys_msgget, gt_linux_print_sysret, NULL },
	{ "sys_msgsnd", gt_linux_print_syscall_sys_msgsnd, gt_linux_print_sysret, NULL },
	{ "sys_msgrcv", gt_linux_print_syscall_sys_msgrcv, gt_linux_print_sysret, NULL },
	{ "sys_msgctl", gt_linux_print_syscall_sys_msgctl, gt_linux_print_sysret, NULL },
	{ "sys_fcntl", gt_linux_print_syscall_sys_fcntl, gt_linux_print_sysret, NULL },
	{ "sys_flock", gt_linux_print_syscall_sys_flock, gt_linux_print_sysret, NULL },
	{ "sys_fsync", gt_linux_print_syscall_sys_fsync, gt_linux_print_sysret, NULL },
	{ "sys_fdatasync", gt_linux_print_syscall_sys_fdatasync, gt_linux_print_sysret, NULL },
	{ "sys_truncate", gt_linux_print_syscall_sys_truncate, gt_linux_print_sysret, NULL },
	{ "sys_ftruncate", gt_linux_print_syscall_sys_ftruncate, gt_linux_print_sysret, NULL },
	{ "sys_getdents", gt_linux_print_syscall_sys_getdents, gt_linux_print_sysret, NULL },
	{ "sys_getcwd", gt_linux_print_syscall_sys_getcwd, gt_linux_print_sysret, NULL },
	{ "sys_chdir", gt_linux_print_syscall_sys_chdir, gt_linux_print_sysret, NULL },
	{ "sys_fchdir", gt_linux_print_syscall_sys_fchdir, gt_linux_print_sysret, NULL },
	{ "sys_rename", gt_linux_print_syscall_sys_rename, gt_linux_print_sysret, NULL },
	{ "sys_mkdir", gt_linux_print_syscall_sys_mkdir, gt_linux_print_sysret, NULL },
	{ "sys_rmdir", gt_linux_print_syscall_sys_rmdir, gt_linux_print_sysret, NULL },
	{ "sys_creat", gt_linux_print_syscall_sys_creat, gt_linux_print_sysret, NULL },
	{ "sys_link", gt_linux_print_syscall_sys_link, gt_linux_print_sysret, NULL },
	{ "sys_unlink", gt_linux_print_syscall_sys_unlink, gt_linux_print_sysret, NULL },
	{ "sys_symlink", gt_linux_print_syscall_sys_symlink, gt_linux_print_sysret, NULL },
	{ "sys_readlink", gt_linux_print_syscall_sys_readlink, gt_linux_print_sysret, NULL },
	{ "sys_chmod", gt_linux_print_syscall_sys_chmod, gt_linux_print_sysret, NULL },
	{ "sys_fchmod", gt_linux_print_syscall_sys_fchmod, gt_linux_print_sysret, NULL },
	{ "sys_chown", gt_linux_print_syscall_sys_chown, gt_linux_print_sysret, NULL },
	{ "sys_fchown", gt_linux_print_syscall_sys_fchown, gt_linux_print_sysret, NULL },
	{ "sys_lchown", gt_linux_print_syscall_sys_lchown, gt_linux_print_sysret, NULL },
	{ "sys_umask", gt_linux_print_syscall_sys_umask, gt_linux_print_sysret, NULL },
	{ "sys_gettimeofday", gt_linux_print_syscall_sys_gettimeofday, gt_linux_print_sysret, NULL },
	{ "sys_getrlimit", gt_linux_print_syscall_sys_getrlimit, gt_linux_print_sysret, NULL },
	{ "sys_getrusage", gt_linux_print_syscall_sys_getrusage, gt_linux_print_sysret, NULL },
	{ "sys_sysinfo", gt_linux_print_syscall_sys_sysinfo, gt_linux_print_sysret, NULL },
	{ "sys_times", gt_linux_print_syscall_sys_times, gt_linux_print_sysret, NULL },
	{ "sys_ptrace", gt_linux_print_syscall_sys_ptrace, gt_linux_print_sysret, NULL },
	{ "sys_getuid", gt_linux_print_syscall_sys_getuid, gt_linux_print_sysret, NULL },
	{ "sys_syslog", gt_linux_print_syscall_sys_syslog, gt_linux_print_sysret, NULL },
	{ "sys_getgid", gt_linux_print_syscall_sys_getgid, gt_linux_print_sysret, NULL },
	{ "sys_setuid", gt_linux_print_syscall_sys_setuid, gt_linux_print_sysret, NULL },
	{ "sys_setgid", gt_linux_print_syscall_sys_setgid, gt_linux_print_sysret, NULL },
	{ "sys_geteuid", gt_linux_print_syscall_sys_geteuid, gt_linux_print_sysret, NULL },
	{ "sys_getegid", gt_linux_print_syscall_sys_getegid, gt_linux_print_sysret, NULL },
	{ "sys_setpgid", gt_linux_print_syscall_sys_setpgid, gt_linux_print_sysret, NULL },
	{ "sys_getppid", gt_linux_print_syscall_sys_getppid, gt_linux_print_sysret, NULL },
	{ "sys_getpgrp", gt_linux_print_syscall_sys_getpgrp, gt_linux_print_sysret, NULL },
	{ "sys_setsid", gt_linux_print_syscall_sys_setsid, gt_linux_print_sysret, NULL },
	{ "sys_setreuid", gt_linux_print_syscall_sys_setreuid, gt_linux_print_sysret, NULL },
	{ "sys_setregid", gt_linux_print_syscall_sys_setregid, gt_linux_print_sysret, NULL },
	{ "sys_getgroups", gt_linux_print_syscall_sys_getgroups, gt_linux_print_sysret, NULL },
	{ "sys_setgroups", gt_linux_print_syscall_sys_setgroups, gt_linux_print_sysret, NULL },
	{ "sys_setresuid", gt_linux_print_syscall_sys_setresuid, gt_linux_print_sysret, NULL },
	{ "sys_getresuid", gt_linux_print_syscall_sys_getresuid, gt_linux_print_sysret, NULL },
	{ "sys_setresgid", gt_linux_print_syscall_sys_setresgid, gt_linux_print_sysret, NULL },
	{ "sys_getresgid", gt_linux_print_syscall_sys_getresgid, gt_linux_print_sysret, NULL },
	{ "sys_getpgid", gt_linux_print_syscall_sys_getpgid, gt_linux_print_sysret, NULL },
	{ "sys_setfsuid", gt_linux_print_syscall_sys_setfsuid, gt_linux_print_sysret, NULL },
	{ "sys_setfsgid", gt_linux_print_syscall_sys_setfsgid, gt_linux_print_sysret, NULL },
	{ "sys_getsid", gt_linux_print_syscall_sys_getsid, gt_linux_print_sysret, NULL },
	{ "sys_capget", gt_linux_print_syscall_sys_capget, gt_linux_print_sysret, NULL },
	{ "sys_capset", gt_linux_print_syscall_sys_capset, gt_linux_print_sysret, NULL },
	{ "sys_rt_sigpending", gt_linux_print_syscall_sys_rt_sigpending, gt_linux_print_sysret, NULL },
	{ "sys_rt_sigtimedwait", gt_linux_print_syscall_sys_rt_sigtimedwait, gt_linux_print_sysret, NULL },
	{ "sys_rt_sigqueueinfo", gt_linux_print_syscall_sys_rt_sigqueueinfo, gt_linux_print_sysret, NULL },
	{ "sys_rt_sigsuspend", gt_linux_print_syscall_sys_rt_sigsuspend, gt_linux_print_sysret, NULL },
	{ "sys_sigaltstack", gt_linux_print_syscall_sys_sigaltstack, gt_linux_print_sysret, NULL },
	{ "sys_utime", gt_linux_print_syscall_sys_utime, gt_linux_print_sysret, NULL },
	{ "sys_mknod", gt_linux_print_syscall_sys_mknod, gt_linux_print_sysret, NULL },
	{ "sys_uselib", gt_linux_print_syscall_sys_uselib, gt_linux_print_sysret, NULL },
	{ "sys_personality", gt_linux_print_syscall_sys_personality, gt_linux_print_sysret, NULL },
	{ "sys_ustat", gt_linux_print_syscall_sys_ustat, gt_linux_print_sysret, NULL },
	{ "sys_statfs", gt_linux_print_syscall_sys_statfs, gt_linux_print_sysret, NULL },
	{ "sys_fstatfs", gt_linux_print_syscall_sys_fstatfs, gt_linux_print_sysret, NULL },
	{ "sys_sysfs", gt_linux_print_syscall_sys_sysfs, gt_linux_print_sysret, NULL },
	{ "sys_getpriority", gt_linux_print_syscall_sys_getpriority, gt_linux_print_sysret, NULL },
	{ "sys_setpriority", gt_linux_print_syscall_sys_setpriority, gt_linux_print_sysret, NULL },
	{ "sys_sched_setparam", gt_linux_print_syscall_sys_sched_setparam, gt_linux_print_sysret, NULL },
	{ "sys_sched_getparam", gt_linux_print_syscall_sys_sched_getparam, gt_linux_print_sysret, NULL },
	{ "sys_sched_setscheduler", gt_linux_print_syscall_sys_sched_setscheduler, gt_linux_print_sysret, NULL },
	{ "sys_sched_getscheduler", gt_linux_print_syscall_sys_sched_getscheduler, gt_linux_print_sysret, NULL },
	{ "sys_sched_get_priority_max", gt_linux_print_syscall_sys_sched_get_priority_max, gt_linux_print_sysret, NULL },
	{ "sys_sched_get_priority_min", gt_linux_print_syscall_sys_sched_get_priority_min, gt_linux_print_sysret, NULL },
	{ "sys_sched_rr_get_interval", gt_linux_print_syscall_sys_sched_rr_get_interval, gt_linux_print_sysret, NULL },
	{ "sys_mlock", gt_linux_print_syscall_sys_mlock, gt_linux_print_sysret, NULL },
	{ "sys_munlock", gt_linux_print_syscall_sys_munlock, gt_linux_print_sysret, NULL },
	{ "sys_mlockall", gt_linux_print_syscall_sys_mlockall, gt_linux_print_sysret, NULL },
	{ "sys_munlockall", gt_linux_print_syscall_sys_munlockall, gt_linux_print_sysret, NULL },
	{ "sys_vhangup", gt_linux_print_syscall_sys_vhangup, gt_linux_print_sysret, NULL },
	{ "sys_modify_ldt", gt_linux_print_syscall_sys_modify_ldt, gt_linux_print_sysret, NULL },
	{ "sys_pivot_root", gt_linux_print_syscall_sys_pivot_root, gt_linux_print_sysret, NULL },
	{ "sys_sysctl", gt_linux_print_syscall_sys_sysctl, gt_linux_print_sysret, NULL },
	{ "sys_prctl", gt_linux_print_syscall_sys_prctl, gt_linux_print_sysret, NULL },
	{ "sys_arch_prctl", gt_linux_print_syscall_sys_arch_prctl, gt_linux_print_sysret, NULL },
	{ "sys_adjtimex", gt_linux_print_syscall_sys_adjtimex, gt_linux_print_sysret, NULL },
	{ "sys_setrlimit", gt_linux_print_syscall_sys_setrlimit, gt_linux_print_sysret, NULL },
	{ "sys_chroot", gt_linux_print_syscall_sys_chroot, gt_linux_print_sysret, NULL },
	{ "sys_sync", gt_linux_print_syscall_sys_sync, gt_linux_print_sysret, NULL },
	{ "sys_acct", gt_linux_print_syscall_sys_acct, gt_linux_print_sysret, NULL },
	{ "sys_settimeofday", gt_linux_print_syscall_sys_settimeofday, gt_linux_print_sysret, NULL },
	{ "sys_mount", gt_linux_print_syscall_sys_mount, gt_linux_print_sysret, NULL },
	{ "sys_umount2", gt_linux_print_syscall_sys_umount2, gt_linux_print_sysret, NULL },
	{ "sys_swapon", gt_linux_print_syscall_sys_swapon, gt_linux_print_sysret, NULL },
	{ "sys_swapoff", gt_linux_print_syscall_sys_swapoff, gt_linux_print_sysret, NULL },
	{ "sys_reboot", gt_linux_print_syscall_sys_reboot, gt_linux_print_sysret, NULL },
	{ "sys_sethostname", gt_linux_print_syscall_sys_sethostname, gt_linux_print_sysret, NULL },
	{ "sys_setdomainname", gt_linux_print_syscall_sys_setdomainname, gt_linux_print_sysret, NULL },
	{ "sys_iopl", gt_linux_print_syscall_sys_iopl, gt_linux_print_sysret, NULL },
	{ "sys_ioperm", gt_linux_print_syscall_sys_ioperm, gt_linux_print_sysret, NULL },
	{ "sys_create_module", gt_linux_print_syscall_sys_create_module, gt_linux_print_sysret, NULL },
	{ "sys_init_module", gt_linux_print_syscall_sys_init_module, gt_linux_print_sysret, NULL },
	{ "sys_delete_module", gt_linux_print_syscall_sys_delete_module, gt_linux_print_sysret, NULL },
	{ "sys_get_kernel_syms", gt_linux_print_syscall_sys_get_kernel_syms, gt_linux_print_sysret, NULL },
	{ "sys_query_module", gt_linux_print_syscall_sys_query_module, gt_linux_print_sysret, NULL },
	{ "sys_quotactl", gt_linux_print_syscall_sys_quotactl, gt_linux_print_sysret, NULL },
	{ "sys_nfsservctl", gt_linux_print_syscall_sys_nfsservctl, gt_linux_print_sysret, NULL },
	{ "sys_getpmsg", gt_linux_print_syscall_sys_getpmsg, gt_linux_print_sysret, NULL },
	{ "sys_putpmsg", gt_linux_print_syscall_sys_putpmsg, gt_linux_print_sysret, NULL },
	{ "sys_afs_syscall", gt_linux_print_syscall_sys_afs_syscall, gt_linux_print_sysret, NULL },
	{ "sys_tuxcall", gt_linux_print_syscall_sys_tuxcall, gt_linux_print_sysret, NULL },
	{ "sys_security", gt_linux_print_syscall_sys_security, gt_linux_print_sysret, NULL },
	{ "sys_gettid", gt_linux_print_syscall_sys_gettid, gt_linux_print_sysret, NULL },
	{ "sys_readahead", gt_linux_print_syscall_sys_readahead, gt_linux_print_sysret, NULL },
	{ "sys_setxattr", gt_linux_print_syscall_sys_setxattr, gt_linux_print_sysret, NULL },
	{ "sys_lsetxattr", gt_linux_print_syscall_sys_lsetxattr, gt_linux_print_sysret, NULL },
	{ "sys_fsetxattr", gt_linux_print_syscall_sys_fsetxattr, gt_linux_print_sysret, NULL },
	{ "sys_getxattr", gt_linux_print_syscall_sys_getxattr, gt_linux_print_sysret, NULL },
	{ "sys_lgetxattr", gt_linux_print_syscall_sys_lgetxattr, gt_linux_print_sysret, NULL },
	{ "sys_fgetxattr", gt_linux_print_syscall_sys_fgetxattr, gt_linux_print_sysret, NULL },
	{ "sys_listxattr", gt_linux_print_syscall_sys_listxattr, gt_linux_print_sysret, NULL },
	{ "sys_llistxattr", gt_linux_print_syscall_sys_llistxattr, gt_linux_print_sysret, NULL },
	{ "sys_flistxattr", gt_linux_print_syscall_sys_flistxattr, gt_linux_print_sysret, NULL },
	{ "sys_removexattr", gt_linux_print_syscall_sys_removexattr, gt_linux_print_sysret, NULL },
	{ "sys_lremovexattr", gt_linux_print_syscall_sys_lremovexattr, gt_linux_print_sysret, NULL },
	{ "sys_fremovexattr", gt_linux_print_syscall_sys_fremovexattr, gt_linux_print_sysret, NULL },
	{ "sys_tkill", gt_linux_print_syscall_sys_tkill, gt_linux_print_sysret, NULL },
	{ "sys_time", gt_linux_print_syscall_sys_time, gt_linux_print_sysret, NULL },
	{ "sys_futex", gt_linux_print_syscall_sys_futex, gt_linux_print_sysret, NULL },
	{ "sys_sched_setaffinity", gt_linux_print_syscall_sys_sched_setaffinity, gt_linux_print_sysret, NULL },
	{ "sys_sched_getaffinity", gt_linux_print_syscall_sys_sched_getaffinity, gt_linux_print_sysret, NULL },
	{ "sys_set_thread_area", gt_linux_print_syscall_sys_set_thread_area, gt_linux_print_sysret, NULL },
	{ "sys_io_setup", gt_linux_print_syscall_sys_io_setup, gt_linux_print_sysret, NULL },
	{ "sys_io_destroy", gt_linux_print_syscall_sys_io_destroy, gt_linux_print_sysret, NULL },
	{ "sys_io_getevents", gt_linux_print_syscall_sys_io_getevents, gt_linux_print_sysret, NULL },
	{ "sys_io_submit", gt_linux_print_syscall_sys_io_submit, gt_linux_print_sysret, NULL },
	{ "sys_io_cancel", gt_linux_print_syscall_sys_io_cancel, gt_linux_print_sysret, NULL },
	{ "sys_get_thread_area", gt_linux_print_syscall_sys_get_thread_area, gt_linux_print_sysret, NULL },
	{ "sys_lookup_dcookie", gt_linux_print_syscall_sys_lookup_dcookie, gt_linux_print_sysret, NULL },
	{ "sys_epoll_create", gt_linux_print_syscall_sys_epoll_create, gt_linux_print_sysret, NULL },
	{ "sys_epoll_ctl_old", gt_linux_print_syscall_sys_epoll_ctl_old, gt_linux_print_sysret, NULL },
	{ "sys_epoll_wait_old", gt_linux_print_syscall_sys_epoll_wait_old, gt_linux_print_sysret, NULL },
	{ "sys_remap_file_pages", gt_linux_print_syscall_sys_remap_file_pages, gt_linux_print_sysret, NULL },
	{ "sys_getdents64", gt_linux_print_syscall_sys_getdents64, gt_linux_print_sysret, NULL },
	{ "sys_set_tid_address", gt_linux_print_syscall_sys_set_tid_address, gt_linux_print_sysret, NULL },
	{ "sys_restart_syscall", gt_linux_print_syscall_sys_restart_syscall, gt_linux_print_sysret, NULL },
	{ "sys_semtimedop", gt_linux_print_syscall_sys_semtimedop, gt_linux_print_sysret, NULL },
	{ "sys_fadvise64", gt_linux_print_syscall_sys_fadvise64, gt_linux_print_sysret, NULL },
	{ "sys_timer_create", gt_linux_print_syscall_sys_timer_create, gt_linux_print_sysret, NULL },
	{ "sys_timer_settime", gt_linux_print_syscall_sys_timer_settime, gt_linux_print_sysret, NULL },
	{ "sys_timer_gettime", gt_linux_print_syscall_sys_timer_gettime, gt_linux_print_sysret, NULL },
	{ "sys_timer_getoverrun", gt_linux_print_syscall_sys_timer_getoverrun, gt_linux_print_sysret, NULL },
	{ "sys_timer_delete", gt_linux_print_syscall_sys_timer_delete, gt_linux_print_sysret, NULL },
	{ "sys_clock_settime", gt_linux_print_syscall_sys_clock_settime, gt_linux_print_sysret, NULL },
	{ "sys_clock_gettime", gt_linux_print_syscall_sys_clock_gettime, gt_linux_print_sysret, NULL },
	{ "sys_clock_getres", gt_linux_print_syscall_sys_clock_getres, gt_linux_print_sysret, NULL },
	{ "sys_clock_nanosleep", gt_linux_print_syscall_sys_clock_nanosleep, gt_linux_print_sysret, NULL },
	{ "sys_exit_group", gt_linux_print_syscall_sys_exit_group, gt_linux_print_sysret, NULL },
	{ "sys_epoll_wait", gt_linux_print_syscall_sys_epoll_wait, gt_linux_print_sysret, NULL },
	{ "sys_epoll_ctl", gt_linux_print_syscall_sys_epoll_ctl, gt_linux_print_sysret, NULL },
	{ "sys_tgkill", gt_linux_print_syscall_sys_tgkill, gt_linux_print_sysret, NULL },
	{ "sys_utimes", gt_linux_print_syscall_sys_utimes, gt_linux_print_sysret, NULL },
	{ "sys_vserver", gt_linux_print_syscall_sys_vserver, gt_linux_print_sysret, NULL },
	{ "sys_mbind", gt_linux_print_syscall_sys_mbind, gt_linux_print_sysret, NULL },
	{ "sys_set_mempolicy", gt_linux_print_syscall_sys_set_mempolicy, gt_linux_print_sysret, NULL },
	{ "sys_get_mempolicy", gt_linux_print_syscall_sys_get_mempolicy, gt_linux_print_sysret, NULL },
	{ "sys_mq_open", gt_linux_print_syscall_sys_mq_open, gt_linux_print_sysret, NULL },
	{ "sys_mq_unlink", gt_linux_print_syscall_sys_mq_unlink, gt_linux_print_sysret, NULL },
	{ "sys_mq_timedsend", gt_linux_print_syscall_sys_mq_timedsend, gt_linux_print_sysret, NULL },
	{ "sys_mq_timedreceive", gt_linux_print_syscall_sys_mq_timedreceive, gt_linux_print_sysret, NULL },
	{ "sys_mq_notify", gt_linux_print_syscall_sys_mq_notify, gt_linux_print_sysret, NULL },
	{ "sys_mq_getsetattr", gt_linux_print_syscall_sys_mq_getsetattr, gt_linux_print_sysret, NULL },
	{ "sys_kexec_load", gt_linux_print_syscall_sys_kexec_load, gt_linux_print_sysret, NULL },
	{ "sys_waitid", gt_linux_print_syscall_sys_waitid, gt_linux_print_sysret, NULL },
	{ "sys_add_key", gt_linux_print_syscall_sys_add_key, gt_linux_print_sysret, NULL },
	{ "sys_request_key", gt_linux_print_syscall_sys_request_key, gt_linux_print_sysret, NULL },
	{ "sys_keyctl", gt_linux_print_syscall_sys_keyctl, gt_linux_print_sysret, NULL },
	{ "sys_ioprio_set", gt_linux_print_syscall_sys_ioprio_set, gt_linux_print_sysret, NULL },
	{ "sys_ioprio_get", gt_linux_print_syscall_sys_ioprio_get, gt_linux_print_sysret, NULL },
	{ "sys_inotify_init", gt_linux_print_syscall_sys_inotify_init, gt_linux_print_sysret, NULL },
	{ "sys_inotify_add_watch", gt_linux_print_syscall_sys_inotify_add_watch, gt_linux_print_sysret, NULL },
	{ "sys_inotify_rm_watch", gt_linux_print_syscall_sys_inotify_rm_watch, gt_linux_print_sysret, NULL },
	{ "sys_migrate_pages", gt_linux_print_syscall_sys_migrate_pages, gt_linux_print_sysret, NULL },
	{ "sys_openat", gt_linux_print_syscall_sys_openat, gt_linux_print_sysret, NULL },
	{ "sys_mkdirat", gt_linux_print_syscall_sys_mkdirat, gt_linux_print_sysret, NULL },
	{ "sys_mknodat", gt_linux_print_syscall_sys_mknodat, gt_linux_print_sysret, NULL },
	{ "sys_fchownat", gt_linux_print_syscall_sys_fchownat, gt_linux_print_sysret, NULL },
	{ "sys_futimesat", gt_linux_print_syscall_sys_futimesat, gt_linux_print_sysret, NULL },
	{ "sys_newfstatat", gt_linux_print_syscall_sys_newfstatat, gt_linux_print_sysret, NULL },
	{ "sys_unlinkat", gt_linux_print_syscall_sys_unlinkat, gt_linux_print_sysret, NULL },
	{ "sys_renameat", gt_linux_print_syscall_sys_renameat, gt_linux_print_sysret, NULL },
	{ "sys_linkat", gt_linux_print_syscall_sys_linkat, gt_linux_print_sysret, NULL },
	{ "sys_symlinkat", gt_linux_print_syscall_sys_symlinkat, gt_linux_print_sysret, NULL },
	{ "sys_readlinkat", gt_linux_print_syscall_sys_readlinkat, gt_linux_print_sysret, NULL },
	{ "sys_fchmodat", gt_linux_print_syscall_sys_fchmodat, gt_linux_print_sysret, NULL },
	{ "sys_faccessat", gt_linux_print_syscall_sys_faccessat, gt_linux_print_sysret, NULL },
	{ "sys_pselect6", gt_linux_print_syscall_sys_pselect6, gt_linux_print_sysret, NULL },
	{ "sys_ppoll", gt_linux_print_syscall_sys_ppoll, gt_linux_print_sysret, NULL },
	{ "sys_unshare", gt_linux_print_syscall_sys_unshare, gt_linux_print_sysret, NULL },
	{ "sys_set_robust_list", gt_linux_print_syscall_sys_set_robust_list, gt_linux_print_sysret, NULL },
	{ "sys_get_robust_list", gt_linux_print_syscall_sys_get_robust_list, gt_linux_print_sysret, NULL },
	{ "sys_splice", gt_linux_print_syscall_sys_splice, gt_linux_print_sysret, NULL },
	{ "sys_tee", gt_linux_print_syscall_sys_tee, gt_linux_print_sysret, NULL },
	{ "sys_sync_file_range", gt_linux_print_syscall_sys_sync_file_range, gt_linux_print_sysret, NULL },
	{ "sys_vmsplice", gt_linux_print_syscall_sys_vmsplice, gt_linux_print_sysret, NULL },
	{ "sys_move_pages", gt_linux_print_syscall_sys_move_pages, gt_linux_print_sysret, NULL },
	{ "sys_utimensat", gt_linux_print_syscall_sys_utimensat, gt_linux_print_sysret, NULL },
	{ "sys_epoll_pwait", gt_linux_print_syscall_sys_epoll_pwait, gt_linux_print_sysret, NULL },
	{ "sys_signalfd", gt_linux_print_syscall_sys_signalfd, gt_linux_print_sysret, NULL },
	{ "sys_timerfd", gt_linux_print_syscall_sys_timerfd, gt_linux_print_sysret, NULL },
	{ "sys_eventfd", gt_linux_print_syscall_sys_eventfd, gt_linux_print_sysret, NULL },
	{ "sys_fallocate", gt_linux_print_syscall_sys_fallocate, gt_linux_print_sysret, NULL },
	{ "sys_timerfd_settime", gt_linux_print_syscall_sys_timerfd_settime, gt_linux_print_sysret, NULL },
	{ "sys_timerfd_gettime", gt_linux_print_syscall_sys_timerfd_gettime, gt_linux_print_sysret, NULL },
	{ "sys_accept4", gt_linux_print_syscall_sys_accept4, gt_linux_print_sysret, NULL },
	{ "sys_signalfd4", gt_linux_print_syscall_sys_signalfd4, gt_linux_print_sysret, NULL },
	{ "sys_eventfd2", gt_linux_print_syscall_sys_eventfd2, gt_linux_print_sysret, NULL },
	{ "sys_epoll_create1", gt_linux_print_syscall_sys_epoll_create1, gt_linux_print_sysret, NULL },
	{ "sys_dup3", gt_linux_print_syscall_sys_dup3, gt_linux_print_sysret, NULL },
	{ "sys_pipe2", gt_linux_print_syscall_sys_pipe2, gt_linux_print_sysret, NULL },
	{ "sys_inotify_init1", gt_linux_print_syscall_sys_inotify_init1, gt_linux_print_sysret, NULL },
	{ "sys_preadv", gt_linux_print_syscall_sys_preadv, gt_linux_print_sysret, NULL },
	{ "sys_pwritev", gt_linux_print_syscall_sys_pwritev, gt_linux_print_sysret, NULL },
	{ "sys_rt_tgsigqueueinfo", gt_linux_print_syscall_sys_rt_tgsigqueueinfo, gt_linux_print_sysret, NULL },
	{ "sys_perf_event_open", gt_linux_print_syscall_sys_perf_event_open, gt_linux_print_sysret, NULL },
	{ "sys_recvmmsg", gt_linux_print_syscall_sys_recvmmsg, gt_linux_print_sysret, NULL },
	{ "sys_fanotify_init", gt_linux_print_syscall_sys_fanotify_init, gt_linux_print_sysret, NULL },
	{ "sys_fanotify_mark", gt_linux_print_syscall_sys_fanotify_mark, gt_linux_print_sysret, NULL },
	{ "sys_prlimit64", gt_linux_print_syscall_sys_prlimit64, gt_linux_print_sysret, NULL },
	{ "sys_name_to_handle_at", gt_linux_print_syscall_sys_name_to_handle_at, gt_linux_print_sysret, NULL },
	{ "sys_open_by_handle_at", gt_linux_print_syscall_sys_open_by_handle_at, gt_linux_print_sysret, NULL },
	{ "sys_clock_adjtime", gt_linux_print_syscall_sys_clock_adjtime, gt_linux_print_sysret, NULL },
	{ "sys_syncfs", gt_linux_print_syscall_sys_syncfs, gt_linux_print_sysret, NULL },
	{ "sys_sendmmsg", gt_linux_print_syscall_sys_sendmmsg, gt_linux_print_sysret, NULL },
	{ "sys_setns", gt_linux_print_syscall_sys_setns, gt_linux_print_sysret, NULL },
	{ "sys_getcpu", gt_linux_print_syscall_sys_getcpu, gt_linux_print_sysret, NULL },
	{ "sys_process_vm_readv", gt_linux_print_syscall_sys_process_vm_readv, gt_linux_print_sysret, NULL },
	{ "sys_process_vm_writev", gt_linux_print_syscall_sys_process_vm_writev, gt_linux_print_sysret, NULL },
	{ "sys_kcmp", gt_linux_print_syscall_sys_kcmp, gt_linux_print_sysret, NULL },
	{ "sys_finit_module", gt_linux_print_syscall_sys_finit_module, gt_linux_print_sysret, NULL },
	{ "sys_sched_setattr", gt_linux_print_syscall_sys_sched_setattr, gt_linux_print_sysret, NULL },
	{ "sys_sched_getattr", gt_linux_print_syscall_sys_sched_getattr, gt_linux_print_sysret, NULL },
	{ "sys_renameat2", gt_linux_print_syscall_sys_renameat2, gt_linux_print_sysret, NULL },
	{ "sys_seccomp", gt_linux_print_syscall_sys_seccomp, gt_linux_print_sysret, NULL },
	{ "sys_getrandom", gt_linux_print_syscall_sys_getrandom, gt_linux_print_sysret, NULL },
	{ "sys_memfd_create", gt_linux_print_syscall_sys_memfd_create, gt_linux_print_sysret, NULL },
	{ "sys_kexec_file_load", gt_linux_print_syscall_sys_kexec_file_load, gt_linux_print_sysret, NULL },
	{ "sys_bpf", gt_linux_print_syscall_sys_bpf, gt_linux_print_sysret, NULL },
	{ "sys_execveat", gt_linux_print_syscall_sys_execveat, gt_linux_print_sysret, NULL },
	{ "sys_userfaultfd", gt_linux_print_syscall_sys_userfaultfd, gt_linux_print_sysret, NULL },
	{ "sys_membarrier", gt_linux_print_syscall_sys_membarrier, gt_linux_print_sysret, NULL },
	{ "sys_mlock2", gt_linux_print_syscall_sys_mlock2, gt_linux_print_sysret, NULL },
	{ "sys_copy_file_range", gt_linux_print_syscall_sys_copy_file_range, gt_linux_print_sysret, NULL },
	{ NULL, NULL, NULL, NULL }
};

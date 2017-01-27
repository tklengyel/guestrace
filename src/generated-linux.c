/* Generated on Linux_4.9.3-200.fc25.x86_64 on 27 Jan 2017 01:42:51*/

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "generated-linux.h"

static const int RETURN_ADDR_WIDTH = sizeof(void *);

bool
vf_linux_find_syscalls_and_setup_mem_traps(GTLoop *loop)
{
        return vf_find_syscalls_and_setup_mem_traps(loop,
                                                    VM_LINUX_SYSCALLS,
                                                    VM_LINUX_TRACED_SYSCALLS);
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

void vf_linux_print_syscall_sys_read(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_read", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_write(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_write", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_open(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	char *arg0 = vmi_read_str_va(vmi, event->x86_regs->rdi, pid);
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(\"%s\", %i, %lu)\n", pid, rsp, proc, "sys_open", (char *) arg0, (int) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_close(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_close", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_stat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_stat", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_fstat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_fstat", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_lstat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_lstat", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_poll(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %i)\n", pid, rsp, proc, "sys_poll", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_lseek(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_lseek", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_mmap(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_mmap");
}

void vf_linux_print_syscall_sys_mprotect(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu)\n", pid, rsp, proc, "sys_mprotect", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_munmap(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_munmap", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_brk(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_brk", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_rt_sigaction(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_rt_sigaction", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_rt_sigprocmask(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_rt_sigprocmask", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_rt_sigreturn(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_rt_sigreturn");
}

void vf_linux_print_syscall_sys_ioctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu)\n", pid, rsp, proc, "sys_ioctl", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_pread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %li)\n", pid, rsp, proc, "sys_pread", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (long int) arg3);
}

void vf_linux_print_syscall_sys_pwrite(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %li)\n", pid, rsp, proc, "sys_pwrite", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (long int) arg3);
}

void vf_linux_print_syscall_sys_readv(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_readv", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_writev(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_writev", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_access(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_access", (unsigned long) arg0, (int) arg1);
}

void vf_linux_print_syscall_sys_pipe(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_pipe", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_select(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_select", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_sched_yield(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_sched_yield");
}

void vf_linux_print_syscall_sys_mremap(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu, %lu, %lu)\n", pid, rsp, proc, "sys_mremap", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_msync(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i)\n", pid, rsp, proc, "sys_msync", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_mincore(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_mincore", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_madvise(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i)\n", pid, rsp, proc, "sys_madvise", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_shmget(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %i)\n", pid, rsp, proc, "sys_shmget", (int) arg0, (unsigned long) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_shmat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_shmat", (int) arg0, (unsigned long) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_shmctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_shmctl", (int) arg0, (int) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_dup(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_dup", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_dup2(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_dup2", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_pause(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_pause");
}

void vf_linux_print_syscall_sys_nanosleep(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_nanosleep", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_getitimer(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_getitimer", (int) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_alarm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_alarm", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_setitimer(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_setitimer", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_getpid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_getpid");
}

void vf_linux_print_syscall_sys_sendfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_sendfile", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_socket(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i)\n", pid, rsp, proc, "sys_socket", (int) arg0, (int) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_connect(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_connect", (int) arg0, (unsigned long) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_accept(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_accept", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_sendto(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
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
}

void vf_linux_print_syscall_sys_recvfrom(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
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
}

void vf_linux_print_syscall_sys_sendmsg(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_sendmsg", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_recvmsg(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_recvmsg", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_shutdown(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_shutdown", (int) arg0, (int) arg1);
}

void vf_linux_print_syscall_sys_bind(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_bind", (int) arg0, (unsigned long) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_listen(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_listen", (int) arg0, (int) arg1);
}

void vf_linux_print_syscall_sys_getsockname(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_getsockname", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_getpeername(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_getpeername", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_socketpair(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_socketpair", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_setsockopt(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_setsockopt", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, (int) arg4);
}

void vf_linux_print_syscall_sys_getsockopt(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_getsockopt", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_clone(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, 0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_clone", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_fork(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_fork");
}

void vf_linux_print_syscall_sys_vfork(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_vfork");
}

void vf_linux_print_syscall_sys_execve(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_execve", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_exit(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_exit", (int) arg0);
}

void vf_linux_print_syscall_sys_wait4(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_wait4", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_kill(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_kill", (int) arg0, (int) arg1);
}

void vf_linux_print_syscall_sys_uname(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_uname", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_semget(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i)\n", pid, rsp, proc, "sys_semget", (int) arg0, (int) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_semop(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_semop", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_semctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, %lu)\n", pid, rsp, proc, "sys_semctl", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_shmdt(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_shmdt", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_msgget(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_msgget", (int) arg0, (int) arg1);
}

void vf_linux_print_syscall_sys_msgsnd(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %i)\n", pid, rsp, proc, "sys_msgsnd", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
}

void vf_linux_print_syscall_sys_msgrcv(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %li, %i)\n", pid, rsp, proc, "sys_msgrcv", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (long int) arg3, (int) arg4);
}

void vf_linux_print_syscall_sys_msgctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_msgctl", (int) arg0, (int) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_fcntl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu)\n", pid, rsp, proc, "sys_fcntl", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_flock(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_flock", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_fsync(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_fsync", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_fdatasync(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_fdatasync", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_truncate(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %li)\n", pid, rsp, proc, "sys_truncate", (unsigned long) arg0, (long int) arg1);
}

void vf_linux_print_syscall_sys_ftruncate(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_ftruncate", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_getdents(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_getdents", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_getcwd(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_getcwd", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_chdir(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_chdir", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_fchdir(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_fchdir", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_rename(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_rename", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_mkdir(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_mkdir", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_rmdir(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_rmdir", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_creat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_creat", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_link(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_link", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_unlink(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_unlink", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_symlink(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_symlink", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_readlink(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_readlink", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_chmod(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_chmod", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_fchmod(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_fchmod", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_chown(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_chown", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_fchown(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu)\n", pid, rsp, proc, "sys_fchown", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_lchown(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_lchown", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_umask(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_umask", (int) arg0);
}

void vf_linux_print_syscall_sys_gettimeofday(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_gettimeofday", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_getrlimit(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_getrlimit", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_getrusage(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_getrusage", (int) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_sysinfo(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_sysinfo", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_times(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_times", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_ptrace(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%li, %li, %lu, %lu)\n", pid, rsp, proc, "sys_ptrace", (long int) arg0, (long int) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_getuid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_getuid");
}

void vf_linux_print_syscall_sys_syslog(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_syslog", (int) arg0, (unsigned long) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_getgid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_getgid");
}

void vf_linux_print_syscall_sys_setuid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_setuid", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_setgid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_setgid", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_geteuid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_geteuid");
}

void vf_linux_print_syscall_sys_getegid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_getegid");
}

void vf_linux_print_syscall_sys_setpgid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_setpgid", (int) arg0, (int) arg1);
}

void vf_linux_print_syscall_sys_getppid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_getppid");
}

void vf_linux_print_syscall_sys_getpgrp(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_getpgrp");
}

void vf_linux_print_syscall_sys_setsid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_setsid");
}

void vf_linux_print_syscall_sys_setreuid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_setreuid", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_setregid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_setregid", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_getgroups(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_getgroups", (int) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_setgroups(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_setgroups", (int) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_setresuid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu)\n", pid, rsp, proc, "sys_setresuid", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_getresuid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_getresuid", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_setresgid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu)\n", pid, rsp, proc, "sys_setresgid", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_getresgid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_getresgid", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_getpgid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_getpgid", (int) arg0);
}

void vf_linux_print_syscall_sys_setfsuid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_setfsuid", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_setfsgid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_setfsgid", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_getsid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_getsid", (int) arg0);
}

void vf_linux_print_syscall_sys_capget(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_capget", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_capset(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_capset", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_rt_sigpending(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_rt_sigpending", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_rt_sigtimedwait(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_rt_sigtimedwait", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_rt_sigqueueinfo(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_rt_sigqueueinfo", (int) arg0, (int) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_rt_sigsuspend(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_rt_sigsuspend", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_sigaltstack(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_sigaltstack", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_utime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_utime", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_mknod(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_mknod", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_uselib(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_uselib", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_personality(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_personality", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_ustat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_ustat", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_statfs(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_statfs", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_fstatfs(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_fstatfs", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_sysfs(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %lu)\n", pid, rsp, proc, "sys_sysfs", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_getpriority(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_getpriority", (int) arg0, (int) arg1);
}

void vf_linux_print_syscall_sys_setpriority(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i)\n", pid, rsp, proc, "sys_setpriority", (int) arg0, (int) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_sched_setparam(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_sched_setparam", (int) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_sched_getparam(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_sched_getparam", (int) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_sched_setscheduler(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_sched_setscheduler", (int) arg0, (int) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_sched_getscheduler(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_sched_getscheduler", (int) arg0);
}

void vf_linux_print_syscall_sys_sched_get_priority_max(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_sched_get_priority_max", (int) arg0);
}

void vf_linux_print_syscall_sys_sched_get_priority_min(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_sched_get_priority_min", (int) arg0);
}

void vf_linux_print_syscall_sys_sched_rr_get_interval(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_sched_rr_get_interval", (int) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_mlock(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_mlock", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_munlock(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_munlock", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_mlockall(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_mlockall", (int) arg0);
}

void vf_linux_print_syscall_sys_munlockall(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_munlockall");
}

void vf_linux_print_syscall_sys_vhangup(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_vhangup");
}

void vf_linux_print_syscall_sys_modify_ldt(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_modify_ldt");
}

void vf_linux_print_syscall_sys_pivot_root(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_pivot_root", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_sysctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_sysctl", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_prctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %lu, %lu, %lu)\n", pid, rsp, proc, "sys_prctl", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_arch_prctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_arch_prctl");
}

void vf_linux_print_syscall_sys_adjtimex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_adjtimex", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_setrlimit(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_setrlimit", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_chroot(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_chroot", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_sync(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_sync");
}

void vf_linux_print_syscall_sys_acct(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_acct", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_settimeofday(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_settimeofday", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_mount(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_mount", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_umount2(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_umount2");
}

void vf_linux_print_syscall_sys_swapon(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_swapon", (unsigned long) arg0, (int) arg1);
}

void vf_linux_print_syscall_sys_swapoff(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_swapoff", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_reboot(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_reboot", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_sethostname(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_sethostname", (unsigned long) arg0, (int) arg1);
}

void vf_linux_print_syscall_sys_setdomainname(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_setdomainname", (unsigned long) arg0, (int) arg1);
}

void vf_linux_print_syscall_sys_iopl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_iopl");
}

void vf_linux_print_syscall_sys_ioperm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i)\n", pid, rsp, proc, "sys_ioperm", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_create_module(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_create_module");
}

void vf_linux_print_syscall_sys_init_module(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_init_module", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_delete_module(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_delete_module", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_get_kernel_syms(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_get_kernel_syms");
}

void vf_linux_print_syscall_sys_query_module(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_query_module");
}

void vf_linux_print_syscall_sys_quotactl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_quotactl", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_nfsservctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_nfsservctl");
}

void vf_linux_print_syscall_sys_getpmsg(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_getpmsg");
}

void vf_linux_print_syscall_sys_putpmsg(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_putpmsg");
}

void vf_linux_print_syscall_sys_afs_syscall(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_afs_syscall");
}

void vf_linux_print_syscall_sys_tuxcall(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_tuxcall");
}

void vf_linux_print_syscall_sys_security(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_security");
}

void vf_linux_print_syscall_sys_gettid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_gettid");
}

void vf_linux_print_syscall_sys_readahead(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %li, %lu)\n", pid, rsp, proc, "sys_readahead", (int) arg0, (long int) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_setxattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n", pid, rsp, proc, "sys_setxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
}

void vf_linux_print_syscall_sys_lsetxattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n", pid, rsp, proc, "sys_lsetxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
}

void vf_linux_print_syscall_sys_fsetxattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n", pid, rsp, proc, "sys_fsetxattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
}

void vf_linux_print_syscall_sys_getxattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_getxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_lgetxattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_lgetxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_fgetxattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_fgetxattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_listxattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_listxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_llistxattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_llistxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_flistxattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_flistxattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_removexattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_removexattr", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_lremovexattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_lremovexattr", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_fremovexattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_fremovexattr", (int) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_tkill(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_tkill", (int) arg0, (int) arg1);
}

void vf_linux_print_syscall_sys_time(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_time", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_futex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
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
}

void vf_linux_print_syscall_sys_sched_setaffinity(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_sched_setaffinity", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_sched_getaffinity(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_sched_getaffinity", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_set_thread_area(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_set_thread_area");
}

void vf_linux_print_syscall_sys_io_setup(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_io_setup", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_io_destroy(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_io_destroy", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_io_getevents(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %li, %li, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_io_getevents", (unsigned long) arg0, (long int) arg1, (long int) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_io_submit(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %li, 0x%"PRIx64")\n", pid, rsp, proc, "sys_io_submit", (unsigned long) arg0, (long int) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_io_cancel(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_io_cancel", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_get_thread_area(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_get_thread_area");
}

void vf_linux_print_syscall_sys_lookup_dcookie(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_lookup_dcookie", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_epoll_create(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_epoll_create", (int) arg0);
}

void vf_linux_print_syscall_sys_epoll_ctl_old(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_epoll_ctl_old");
}

void vf_linux_print_syscall_sys_epoll_wait_old(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_epoll_wait_old");
}

void vf_linux_print_syscall_sys_remap_file_pages(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu, %lu, %lu)\n", pid, rsp, proc, "sys_remap_file_pages", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_getdents64(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_getdents64", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_set_tid_address(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_set_tid_address", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_restart_syscall(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_restart_syscall");
}

void vf_linux_print_syscall_sys_semtimedop(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_semtimedop", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_fadvise64(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %li, %lu, %i)\n", pid, rsp, proc, "sys_fadvise64", (int) arg0, (long int) arg1, (unsigned long) arg2, (int) arg3);
}

void vf_linux_print_syscall_sys_timer_create(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_timer_create", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_timer_settime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_timer_settime", (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_timer_gettime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_timer_gettime", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_timer_getoverrun(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_timer_getoverrun", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_timer_delete(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_timer_delete", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_clock_settime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_clock_settime", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_clock_gettime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_clock_gettime", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_clock_getres(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_clock_getres", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_clock_nanosleep(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_clock_nanosleep", (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_exit_group(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_exit_group", (int) arg0);
}

void vf_linux_print_syscall_sys_epoll_wait(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, %i)\n", pid, rsp, proc, "sys_epoll_wait", (int) arg0, (unsigned long) arg1, (int) arg2, (int) arg3);
}

void vf_linux_print_syscall_sys_epoll_ctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_epoll_ctl", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_tgkill(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i)\n", pid, rsp, proc, "sys_tgkill", (int) arg0, (int) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_utimes(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_utimes", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_vserver(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_vserver");
}

void vf_linux_print_syscall_sys_mbind(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
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
}

void vf_linux_print_syscall_sys_set_mempolicy(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_set_mempolicy", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_get_mempolicy(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu, %lu, %lu)\n", pid, rsp, proc, "sys_get_mempolicy", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_mq_open(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i, %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_mq_open", (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_mq_unlink(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, rsp, proc, "sys_mq_unlink", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_mq_timedsend(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_mq_timedsend", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_mq_timedreceive(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_mq_timedreceive", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_mq_notify(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_mq_notify", (int) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_mq_getsetattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_mq_getsetattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_kexec_load(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_kexec_load", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_waitid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64", %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_waitid", (int) arg0, (int) arg1, (unsigned long) arg2, (int) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_add_key(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n", pid, rsp, proc, "sys_add_key", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
}

void vf_linux_print_syscall_sys_request_key(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_request_key", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
}

void vf_linux_print_syscall_sys_keyctl(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %lu, %lu, %lu)\n", pid, rsp, proc, "sys_keyctl", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_ioprio_set(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i)\n", pid, rsp, proc, "sys_ioprio_set", (int) arg0, (int) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_ioprio_get(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_ioprio_get", (int) arg0, (int) arg1);
}

void vf_linux_print_syscall_sys_inotify_init(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_inotify_init");
}

void vf_linux_print_syscall_sys_inotify_add_watch(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_inotify_add_watch", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_inotify_rm_watch(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_inotify_rm_watch", (int) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_migrate_pages(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_migrate_pages", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_openat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, %lu)\n", pid, rsp, proc, "sys_openat", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_mkdirat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_mkdirat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_mknodat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_mknodat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_fchownat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, %i)\n", pid, rsp, proc, "sys_fchownat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
}

void vf_linux_print_syscall_sys_futimesat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_futimesat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_newfstatat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_newfstatat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
}

void vf_linux_print_syscall_sys_unlinkat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_unlinkat", (int) arg0, (unsigned long) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_renameat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_renameat", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_linkat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_linkat", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (int) arg4);
}

void vf_linux_print_syscall_sys_symlinkat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_symlinkat", (unsigned long) arg0, (int) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_readlinkat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_readlinkat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
}

void vf_linux_print_syscall_sys_fchmodat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_fchmodat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_faccessat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_faccessat", (int) arg0, (unsigned long) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_pselect6(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
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
}

void vf_linux_print_syscall_sys_ppoll(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_ppoll", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_unshare(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_unshare", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_set_robust_list(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_set_robust_list", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_get_robust_list(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_get_robust_list", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_splice(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
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
}

void vf_linux_print_syscall_sys_tee(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %lu, %lu)\n", pid, rsp, proc, "sys_tee", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_sync_file_range(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %li, %li, %lu)\n", pid, rsp, proc, "sys_sync_file_range", (int) arg0, (long int) arg1, (long int) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_vmsplice(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_vmsplice", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_move_pages(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
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
}

void vf_linux_print_syscall_sys_utimensat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_utimensat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
}

void vf_linux_print_syscall_sys_epoll_pwait(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
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
}

void vf_linux_print_syscall_sys_signalfd(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_signalfd", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_timerfd(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, rsp, proc, "sys_timerfd");
}

void vf_linux_print_syscall_sys_eventfd(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, rsp, proc, "sys_eventfd", (unsigned long) arg0);
}

void vf_linux_print_syscall_sys_fallocate(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %li, %li)\n", pid, rsp, proc, "sys_fallocate", (int) arg0, (int) arg1, (long int) arg2, (long int) arg3);
}

void vf_linux_print_syscall_sys_timerfd_settime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_timerfd_settime", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_timerfd_gettime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_timerfd_gettime", (int) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_accept4(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_accept4", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
}

void vf_linux_print_syscall_sys_signalfd4(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %i)\n", pid, rsp, proc, "sys_signalfd4", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
}

void vf_linux_print_syscall_sys_eventfd2(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %i)\n", pid, rsp, proc, "sys_eventfd2", (unsigned long) arg0, (int) arg1);
}

void vf_linux_print_syscall_sys_epoll_create1(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_epoll_create1", (int) arg0);
}

void vf_linux_print_syscall_sys_dup3(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i)\n", pid, rsp, proc, "sys_dup3", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_pipe2(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_pipe2", (unsigned long) arg0, (int) arg1);
}

void vf_linux_print_syscall_sys_inotify_init1(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_inotify_init1", (int) arg0);
}

void vf_linux_print_syscall_sys_preadv(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %lu, %lu)\n", pid, rsp, proc, "sys_preadv", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_pwritev(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %lu, %lu)\n", pid, rsp, proc, "sys_pwritev", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_rt_tgsigqueueinfo(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_rt_tgsigqueueinfo", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_perf_event_open(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i, %i, %i, %lu)\n", pid, rsp, proc, "sys_perf_event_open", (unsigned long) arg0, (int) arg1, (int) arg2, (int) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_recvmmsg(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_recvmmsg", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_fanotify_init(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, rsp, proc, "sys_fanotify_init", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_fanotify_mark(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %lu, %i, 0x%"PRIx64")\n", pid, rsp, proc, "sys_fanotify_mark", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_prlimit64(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_prlimit64", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_name_to_handle_at(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_name_to_handle_at", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
}

void vf_linux_print_syscall_sys_open_by_handle_at(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_open_by_handle_at", (int) arg0, (unsigned long) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_clock_adjtime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_clock_adjtime", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_syncfs(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_syncfs", (int) arg0);
}

void vf_linux_print_syscall_sys_sendmmsg(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_sendmmsg", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_setns(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_setns", (int) arg0, (int) arg1);
}

void vf_linux_print_syscall_sys_getcpu(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, rsp, proc, "sys_getcpu", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_process_vm_readv(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
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
}

void vf_linux_print_syscall_sys_process_vm_writev(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
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
}

void vf_linux_print_syscall_sys_kcmp(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, %lu, %lu)\n", pid, rsp, proc, "sys_kcmp", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_finit_module(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_finit_module", (int) arg0, (unsigned long) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_sched_setattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_sched_setattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_sched_getattr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_sched_getattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

void vf_linux_print_syscall_sys_renameat2(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_renameat2", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_seccomp(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, 0x%"PRIx64")\n", pid, rsp, proc, "sys_seccomp", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_getrandom(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %lu)\n", pid, rsp, proc, "sys_getrandom", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_memfd_create(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_memfd_create", (unsigned long) arg0, (unsigned long) arg1);
}

void vf_linux_print_syscall_sys_kexec_file_load(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %lu, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_kexec_file_load", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

void vf_linux_print_syscall_sys_bpf(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, rsp, proc, "sys_bpf", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

void vf_linux_print_syscall_sys_execveat(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, rsp, proc, "sys_execveat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
}

void vf_linux_print_syscall_sys_userfaultfd(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, rsp, proc, "sys_userfaultfd", (int) arg0);
}

void vf_linux_print_syscall_sys_membarrier(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, rsp, proc, "sys_membarrier", (int) arg0, (int) arg1);
}

void vf_linux_print_syscall_sys_mlock2(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
{
    char *proc = get_process_name(vmi, pid);
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i)\n", pid, rsp, proc, "sys_mlock2", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
}

void vf_linux_print_syscall_sys_copy_file_range(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid)
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
}

void vf_linux_print_sysret(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid) {
	reg_t syscall_return = event->x86_regs->rax;
	reg_t rsp = event->x86_regs->rsp;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) return: 0x%"PRIx64"\n", pid, rsp - RETURN_ADDR_WIDTH, get_process_name(vmi, pid), syscall_return);
}

const char *VM_LINUX_TRACED_SYSCALLS[] = {
	"sys_read",
	"sys_write",
	"sys_open",
	"sys_close",
	"sys_stat",
	"sys_fstat",
	"sys_lstat",
	"sys_poll",
	"sys_lseek",
	"sys_mmap",
	"sys_mprotect",
	"sys_munmap",
	"sys_brk",
	"sys_rt_sigaction",
	"sys_rt_sigprocmask",
	"sys_rt_sigreturn",
	"sys_ioctl",
	"sys_pread",
	"sys_pwrite",
	"sys_readv",
	"sys_writev",
	"sys_access",
	"sys_pipe",
	"sys_select",
	"sys_sched_yield",
	"sys_mremap",
	"sys_msync",
	"sys_mincore",
	"sys_madvise",
	"sys_shmget",
	"sys_shmat",
	"sys_shmctl",
	"sys_dup",
	"sys_dup2",
	"sys_pause",
	"sys_nanosleep",
	"sys_getitimer",
	"sys_alarm",
	"sys_setitimer",
	"sys_getpid",
	"sys_sendfile",
	"sys_socket",
	"sys_connect",
	"sys_accept",
	"sys_sendto",
	"sys_recvfrom",
	"sys_sendmsg",
	"sys_recvmsg",
	"sys_shutdown",
	"sys_bind",
	"sys_listen",
	"sys_getsockname",
	"sys_getpeername",
	"sys_socketpair",
	"sys_setsockopt",
	"sys_getsockopt",
	"sys_clone",
	"sys_fork",
	"sys_vfork",
	"sys_execve",
	"sys_exit",
	"sys_wait4",
	"sys_kill",
	"sys_uname",
	"sys_semget",
	"sys_semop",
	"sys_semctl",
	"sys_shmdt",
	"sys_msgget",
	"sys_msgsnd",
	"sys_msgrcv",
	"sys_msgctl",
	"sys_fcntl",
	"sys_flock",
	"sys_fsync",
	"sys_fdatasync",
	"sys_truncate",
	"sys_ftruncate",
	"sys_getdents",
	"sys_getcwd",
	"sys_chdir",
	"sys_fchdir",
	"sys_rename",
	"sys_mkdir",
	"sys_rmdir",
	"sys_creat",
	"sys_link",
	"sys_unlink",
	"sys_symlink",
	"sys_readlink",
	"sys_chmod",
	"sys_fchmod",
	"sys_chown",
	"sys_fchown",
	"sys_lchown",
	"sys_umask",
	"sys_gettimeofday",
	"sys_getrlimit",
	"sys_getrusage",
	"sys_sysinfo",
	"sys_times",
	"sys_ptrace",
	"sys_getuid",
	"sys_syslog",
	"sys_getgid",
	"sys_setuid",
	"sys_setgid",
	"sys_geteuid",
	"sys_getegid",
	"sys_setpgid",
	"sys_getppid",
	"sys_getpgrp",
	"sys_setsid",
	"sys_setreuid",
	"sys_setregid",
	"sys_getgroups",
	"sys_setgroups",
	"sys_setresuid",
	"sys_getresuid",
	"sys_setresgid",
	"sys_getresgid",
	"sys_getpgid",
	"sys_setfsuid",
	"sys_setfsgid",
	"sys_getsid",
	"sys_capget",
	"sys_capset",
	"sys_rt_sigpending",
	"sys_rt_sigtimedwait",
	"sys_rt_sigqueueinfo",
	"sys_rt_sigsuspend",
	"sys_sigaltstack",
	"sys_utime",
	"sys_mknod",
	"sys_uselib",
	"sys_personality",
	"sys_ustat",
	"sys_statfs",
	"sys_fstatfs",
	"sys_sysfs",
	"sys_getpriority",
	"sys_setpriority",
	"sys_sched_setparam",
	"sys_sched_getparam",
	"sys_sched_setscheduler",
	"sys_sched_getscheduler",
	"sys_sched_get_priority_max",
	"sys_sched_get_priority_min",
	"sys_sched_rr_get_interval",
	"sys_mlock",
	"sys_munlock",
	"sys_mlockall",
	"sys_munlockall",
	"sys_vhangup",
	"sys_modify_ldt",
	"sys_pivot_root",
	"sys_sysctl",
	"sys_prctl",
	"sys_arch_prctl",
	"sys_adjtimex",
	"sys_setrlimit",
	"sys_chroot",
	"sys_sync",
	"sys_acct",
	"sys_settimeofday",
	"sys_mount",
	"sys_umount2",
	"sys_swapon",
	"sys_swapoff",
	"sys_reboot",
	"sys_sethostname",
	"sys_setdomainname",
	"sys_iopl",
	"sys_ioperm",
	"sys_create_module",
	"sys_init_module",
	"sys_delete_module",
	"sys_get_kernel_syms",
	"sys_query_module",
	"sys_quotactl",
	"sys_nfsservctl",
	"sys_getpmsg",
	"sys_putpmsg",
	"sys_afs_syscall",
	"sys_tuxcall",
	"sys_security",
	"sys_gettid",
	"sys_readahead",
	"sys_setxattr",
	"sys_lsetxattr",
	"sys_fsetxattr",
	"sys_getxattr",
	"sys_lgetxattr",
	"sys_fgetxattr",
	"sys_listxattr",
	"sys_llistxattr",
	"sys_flistxattr",
	"sys_removexattr",
	"sys_lremovexattr",
	"sys_fremovexattr",
	"sys_tkill",
	"sys_time",
	"sys_futex",
	"sys_sched_setaffinity",
	"sys_sched_getaffinity",
	"sys_set_thread_area",
	"sys_io_setup",
	"sys_io_destroy",
	"sys_io_getevents",
	"sys_io_submit",
	"sys_io_cancel",
	"sys_get_thread_area",
	"sys_lookup_dcookie",
	"sys_epoll_create",
	"sys_epoll_ctl_old",
	"sys_epoll_wait_old",
	"sys_remap_file_pages",
	"sys_getdents64",
	"sys_set_tid_address",
	"sys_restart_syscall",
	"sys_semtimedop",
	"sys_fadvise64",
	"sys_timer_create",
	"sys_timer_settime",
	"sys_timer_gettime",
	"sys_timer_getoverrun",
	"sys_timer_delete",
	"sys_clock_settime",
	"sys_clock_gettime",
	"sys_clock_getres",
	"sys_clock_nanosleep",
	"sys_exit_group",
	"sys_epoll_wait",
	"sys_epoll_ctl",
	"sys_tgkill",
	"sys_utimes",
	"sys_vserver",
	"sys_mbind",
	"sys_set_mempolicy",
	"sys_get_mempolicy",
	"sys_mq_open",
	"sys_mq_unlink",
	"sys_mq_timedsend",
	"sys_mq_timedreceive",
	"sys_mq_notify",
	"sys_mq_getsetattr",
	"sys_kexec_load",
	"sys_waitid",
	"sys_add_key",
	"sys_request_key",
	"sys_keyctl",
	"sys_ioprio_set",
	"sys_ioprio_get",
	"sys_inotify_init",
	"sys_inotify_add_watch",
	"sys_inotify_rm_watch",
	"sys_migrate_pages",
	"sys_openat",
	"sys_mkdirat",
	"sys_mknodat",
	"sys_fchownat",
	"sys_futimesat",
	"sys_newfstatat",
	"sys_unlinkat",
	"sys_renameat",
	"sys_linkat",
	"sys_symlinkat",
	"sys_readlinkat",
	"sys_fchmodat",
	"sys_faccessat",
	"sys_pselect6",
	"sys_ppoll",
	"sys_unshare",
	"sys_set_robust_list",
	"sys_get_robust_list",
	"sys_splice",
	"sys_tee",
	"sys_sync_file_range",
	"sys_vmsplice",
	"sys_move_pages",
	"sys_utimensat",
	"sys_epoll_pwait",
	"sys_signalfd",
	"sys_timerfd",
	"sys_eventfd",
	"sys_fallocate",
	"sys_timerfd_settime",
	"sys_timerfd_gettime",
	"sys_accept4",
	"sys_signalfd4",
	"sys_eventfd2",
	"sys_epoll_create1",
	"sys_dup3",
	"sys_pipe2",
	"sys_inotify_init1",
	"sys_preadv",
	"sys_pwritev",
	"sys_rt_tgsigqueueinfo",
	"sys_perf_event_open",
	"sys_recvmmsg",
	"sys_fanotify_init",
	"sys_fanotify_mark",
	"sys_prlimit64",
	"sys_name_to_handle_at",
	"sys_open_by_handle_at",
	"sys_clock_adjtime",
	"sys_syncfs",
	"sys_sendmmsg",
	"sys_setns",
	"sys_getcpu",
	"sys_process_vm_readv",
	"sys_process_vm_writev",
	"sys_kcmp",
	"sys_finit_module",
	"sys_sched_setattr",
	"sys_sched_getattr",
	"sys_renameat2",
	"sys_seccomp",
	"sys_getrandom",
	"sys_memfd_create",
	"sys_kexec_file_load",
	"sys_bpf",
	"sys_execveat",
	"sys_userfaultfd",
	"sys_membarrier",
	"sys_mlock2",
	"sys_copy_file_range",
	NULL,
};

const struct syscall_defs VM_LINUX_SYSCALLS[] = {
	{ "sys_read", vf_linux_print_syscall_sys_read, vf_linux_print_sysret },
	{ "sys_write", vf_linux_print_syscall_sys_write, vf_linux_print_sysret },
	{ "sys_open", vf_linux_print_syscall_sys_open, vf_linux_print_sysret },
	{ "sys_close", vf_linux_print_syscall_sys_close, vf_linux_print_sysret },
	{ "sys_stat", vf_linux_print_syscall_sys_stat, vf_linux_print_sysret },
	{ "sys_fstat", vf_linux_print_syscall_sys_fstat, vf_linux_print_sysret },
	{ "sys_lstat", vf_linux_print_syscall_sys_lstat, vf_linux_print_sysret },
	{ "sys_poll", vf_linux_print_syscall_sys_poll, vf_linux_print_sysret },
	{ "sys_lseek", vf_linux_print_syscall_sys_lseek, vf_linux_print_sysret },
	{ "sys_mmap", vf_linux_print_syscall_sys_mmap, vf_linux_print_sysret },
	{ "sys_mprotect", vf_linux_print_syscall_sys_mprotect, vf_linux_print_sysret },
	{ "sys_munmap", vf_linux_print_syscall_sys_munmap, vf_linux_print_sysret },
	{ "sys_brk", vf_linux_print_syscall_sys_brk, vf_linux_print_sysret },
	{ "sys_rt_sigaction", vf_linux_print_syscall_sys_rt_sigaction, vf_linux_print_sysret },
	{ "sys_rt_sigprocmask", vf_linux_print_syscall_sys_rt_sigprocmask, vf_linux_print_sysret },
	{ "sys_rt_sigreturn", vf_linux_print_syscall_sys_rt_sigreturn, vf_linux_print_sysret },
	{ "sys_ioctl", vf_linux_print_syscall_sys_ioctl, vf_linux_print_sysret },
	{ "sys_pread", vf_linux_print_syscall_sys_pread, vf_linux_print_sysret },
	{ "sys_pwrite", vf_linux_print_syscall_sys_pwrite, vf_linux_print_sysret },
	{ "sys_readv", vf_linux_print_syscall_sys_readv, vf_linux_print_sysret },
	{ "sys_writev", vf_linux_print_syscall_sys_writev, vf_linux_print_sysret },
	{ "sys_access", vf_linux_print_syscall_sys_access, vf_linux_print_sysret },
	{ "sys_pipe", vf_linux_print_syscall_sys_pipe, vf_linux_print_sysret },
	{ "sys_select", vf_linux_print_syscall_sys_select, vf_linux_print_sysret },
	{ "sys_sched_yield", vf_linux_print_syscall_sys_sched_yield, vf_linux_print_sysret },
	{ "sys_mremap", vf_linux_print_syscall_sys_mremap, vf_linux_print_sysret },
	{ "sys_msync", vf_linux_print_syscall_sys_msync, vf_linux_print_sysret },
	{ "sys_mincore", vf_linux_print_syscall_sys_mincore, vf_linux_print_sysret },
	{ "sys_madvise", vf_linux_print_syscall_sys_madvise, vf_linux_print_sysret },
	{ "sys_shmget", vf_linux_print_syscall_sys_shmget, vf_linux_print_sysret },
	{ "sys_shmat", vf_linux_print_syscall_sys_shmat, vf_linux_print_sysret },
	{ "sys_shmctl", vf_linux_print_syscall_sys_shmctl, vf_linux_print_sysret },
	{ "sys_dup", vf_linux_print_syscall_sys_dup, vf_linux_print_sysret },
	{ "sys_dup2", vf_linux_print_syscall_sys_dup2, vf_linux_print_sysret },
	{ "sys_pause", vf_linux_print_syscall_sys_pause, vf_linux_print_sysret },
	{ "sys_nanosleep", vf_linux_print_syscall_sys_nanosleep, vf_linux_print_sysret },
	{ "sys_getitimer", vf_linux_print_syscall_sys_getitimer, vf_linux_print_sysret },
	{ "sys_alarm", vf_linux_print_syscall_sys_alarm, vf_linux_print_sysret },
	{ "sys_setitimer", vf_linux_print_syscall_sys_setitimer, vf_linux_print_sysret },
	{ "sys_getpid", vf_linux_print_syscall_sys_getpid, vf_linux_print_sysret },
	{ "sys_sendfile", vf_linux_print_syscall_sys_sendfile, vf_linux_print_sysret },
	{ "sys_socket", vf_linux_print_syscall_sys_socket, vf_linux_print_sysret },
	{ "sys_connect", vf_linux_print_syscall_sys_connect, vf_linux_print_sysret },
	{ "sys_accept", vf_linux_print_syscall_sys_accept, vf_linux_print_sysret },
	{ "sys_sendto", vf_linux_print_syscall_sys_sendto, vf_linux_print_sysret },
	{ "sys_recvfrom", vf_linux_print_syscall_sys_recvfrom, vf_linux_print_sysret },
	{ "sys_sendmsg", vf_linux_print_syscall_sys_sendmsg, vf_linux_print_sysret },
	{ "sys_recvmsg", vf_linux_print_syscall_sys_recvmsg, vf_linux_print_sysret },
	{ "sys_shutdown", vf_linux_print_syscall_sys_shutdown, vf_linux_print_sysret },
	{ "sys_bind", vf_linux_print_syscall_sys_bind, vf_linux_print_sysret },
	{ "sys_listen", vf_linux_print_syscall_sys_listen, vf_linux_print_sysret },
	{ "sys_getsockname", vf_linux_print_syscall_sys_getsockname, vf_linux_print_sysret },
	{ "sys_getpeername", vf_linux_print_syscall_sys_getpeername, vf_linux_print_sysret },
	{ "sys_socketpair", vf_linux_print_syscall_sys_socketpair, vf_linux_print_sysret },
	{ "sys_setsockopt", vf_linux_print_syscall_sys_setsockopt, vf_linux_print_sysret },
	{ "sys_getsockopt", vf_linux_print_syscall_sys_getsockopt, vf_linux_print_sysret },
	{ "sys_clone", vf_linux_print_syscall_sys_clone, vf_linux_print_sysret },
	{ "sys_fork", vf_linux_print_syscall_sys_fork, vf_linux_print_sysret },
	{ "sys_vfork", vf_linux_print_syscall_sys_vfork, vf_linux_print_sysret },
	{ "sys_execve", vf_linux_print_syscall_sys_execve, vf_linux_print_sysret },
	{ "sys_exit", vf_linux_print_syscall_sys_exit, vf_linux_print_sysret },
	{ "sys_wait4", vf_linux_print_syscall_sys_wait4, vf_linux_print_sysret },
	{ "sys_kill", vf_linux_print_syscall_sys_kill, vf_linux_print_sysret },
	{ "sys_uname", vf_linux_print_syscall_sys_uname, vf_linux_print_sysret },
	{ "sys_semget", vf_linux_print_syscall_sys_semget, vf_linux_print_sysret },
	{ "sys_semop", vf_linux_print_syscall_sys_semop, vf_linux_print_sysret },
	{ "sys_semctl", vf_linux_print_syscall_sys_semctl, vf_linux_print_sysret },
	{ "sys_shmdt", vf_linux_print_syscall_sys_shmdt, vf_linux_print_sysret },
	{ "sys_msgget", vf_linux_print_syscall_sys_msgget, vf_linux_print_sysret },
	{ "sys_msgsnd", vf_linux_print_syscall_sys_msgsnd, vf_linux_print_sysret },
	{ "sys_msgrcv", vf_linux_print_syscall_sys_msgrcv, vf_linux_print_sysret },
	{ "sys_msgctl", vf_linux_print_syscall_sys_msgctl, vf_linux_print_sysret },
	{ "sys_fcntl", vf_linux_print_syscall_sys_fcntl, vf_linux_print_sysret },
	{ "sys_flock", vf_linux_print_syscall_sys_flock, vf_linux_print_sysret },
	{ "sys_fsync", vf_linux_print_syscall_sys_fsync, vf_linux_print_sysret },
	{ "sys_fdatasync", vf_linux_print_syscall_sys_fdatasync, vf_linux_print_sysret },
	{ "sys_truncate", vf_linux_print_syscall_sys_truncate, vf_linux_print_sysret },
	{ "sys_ftruncate", vf_linux_print_syscall_sys_ftruncate, vf_linux_print_sysret },
	{ "sys_getdents", vf_linux_print_syscall_sys_getdents, vf_linux_print_sysret },
	{ "sys_getcwd", vf_linux_print_syscall_sys_getcwd, vf_linux_print_sysret },
	{ "sys_chdir", vf_linux_print_syscall_sys_chdir, vf_linux_print_sysret },
	{ "sys_fchdir", vf_linux_print_syscall_sys_fchdir, vf_linux_print_sysret },
	{ "sys_rename", vf_linux_print_syscall_sys_rename, vf_linux_print_sysret },
	{ "sys_mkdir", vf_linux_print_syscall_sys_mkdir, vf_linux_print_sysret },
	{ "sys_rmdir", vf_linux_print_syscall_sys_rmdir, vf_linux_print_sysret },
	{ "sys_creat", vf_linux_print_syscall_sys_creat, vf_linux_print_sysret },
	{ "sys_link", vf_linux_print_syscall_sys_link, vf_linux_print_sysret },
	{ "sys_unlink", vf_linux_print_syscall_sys_unlink, vf_linux_print_sysret },
	{ "sys_symlink", vf_linux_print_syscall_sys_symlink, vf_linux_print_sysret },
	{ "sys_readlink", vf_linux_print_syscall_sys_readlink, vf_linux_print_sysret },
	{ "sys_chmod", vf_linux_print_syscall_sys_chmod, vf_linux_print_sysret },
	{ "sys_fchmod", vf_linux_print_syscall_sys_fchmod, vf_linux_print_sysret },
	{ "sys_chown", vf_linux_print_syscall_sys_chown, vf_linux_print_sysret },
	{ "sys_fchown", vf_linux_print_syscall_sys_fchown, vf_linux_print_sysret },
	{ "sys_lchown", vf_linux_print_syscall_sys_lchown, vf_linux_print_sysret },
	{ "sys_umask", vf_linux_print_syscall_sys_umask, vf_linux_print_sysret },
	{ "sys_gettimeofday", vf_linux_print_syscall_sys_gettimeofday, vf_linux_print_sysret },
	{ "sys_getrlimit", vf_linux_print_syscall_sys_getrlimit, vf_linux_print_sysret },
	{ "sys_getrusage", vf_linux_print_syscall_sys_getrusage, vf_linux_print_sysret },
	{ "sys_sysinfo", vf_linux_print_syscall_sys_sysinfo, vf_linux_print_sysret },
	{ "sys_times", vf_linux_print_syscall_sys_times, vf_linux_print_sysret },
	{ "sys_ptrace", vf_linux_print_syscall_sys_ptrace, vf_linux_print_sysret },
	{ "sys_getuid", vf_linux_print_syscall_sys_getuid, vf_linux_print_sysret },
	{ "sys_syslog", vf_linux_print_syscall_sys_syslog, vf_linux_print_sysret },
	{ "sys_getgid", vf_linux_print_syscall_sys_getgid, vf_linux_print_sysret },
	{ "sys_setuid", vf_linux_print_syscall_sys_setuid, vf_linux_print_sysret },
	{ "sys_setgid", vf_linux_print_syscall_sys_setgid, vf_linux_print_sysret },
	{ "sys_geteuid", vf_linux_print_syscall_sys_geteuid, vf_linux_print_sysret },
	{ "sys_getegid", vf_linux_print_syscall_sys_getegid, vf_linux_print_sysret },
	{ "sys_setpgid", vf_linux_print_syscall_sys_setpgid, vf_linux_print_sysret },
	{ "sys_getppid", vf_linux_print_syscall_sys_getppid, vf_linux_print_sysret },
	{ "sys_getpgrp", vf_linux_print_syscall_sys_getpgrp, vf_linux_print_sysret },
	{ "sys_setsid", vf_linux_print_syscall_sys_setsid, vf_linux_print_sysret },
	{ "sys_setreuid", vf_linux_print_syscall_sys_setreuid, vf_linux_print_sysret },
	{ "sys_setregid", vf_linux_print_syscall_sys_setregid, vf_linux_print_sysret },
	{ "sys_getgroups", vf_linux_print_syscall_sys_getgroups, vf_linux_print_sysret },
	{ "sys_setgroups", vf_linux_print_syscall_sys_setgroups, vf_linux_print_sysret },
	{ "sys_setresuid", vf_linux_print_syscall_sys_setresuid, vf_linux_print_sysret },
	{ "sys_getresuid", vf_linux_print_syscall_sys_getresuid, vf_linux_print_sysret },
	{ "sys_setresgid", vf_linux_print_syscall_sys_setresgid, vf_linux_print_sysret },
	{ "sys_getresgid", vf_linux_print_syscall_sys_getresgid, vf_linux_print_sysret },
	{ "sys_getpgid", vf_linux_print_syscall_sys_getpgid, vf_linux_print_sysret },
	{ "sys_setfsuid", vf_linux_print_syscall_sys_setfsuid, vf_linux_print_sysret },
	{ "sys_setfsgid", vf_linux_print_syscall_sys_setfsgid, vf_linux_print_sysret },
	{ "sys_getsid", vf_linux_print_syscall_sys_getsid, vf_linux_print_sysret },
	{ "sys_capget", vf_linux_print_syscall_sys_capget, vf_linux_print_sysret },
	{ "sys_capset", vf_linux_print_syscall_sys_capset, vf_linux_print_sysret },
	{ "sys_rt_sigpending", vf_linux_print_syscall_sys_rt_sigpending, vf_linux_print_sysret },
	{ "sys_rt_sigtimedwait", vf_linux_print_syscall_sys_rt_sigtimedwait, vf_linux_print_sysret },
	{ "sys_rt_sigqueueinfo", vf_linux_print_syscall_sys_rt_sigqueueinfo, vf_linux_print_sysret },
	{ "sys_rt_sigsuspend", vf_linux_print_syscall_sys_rt_sigsuspend, vf_linux_print_sysret },
	{ "sys_sigaltstack", vf_linux_print_syscall_sys_sigaltstack, vf_linux_print_sysret },
	{ "sys_utime", vf_linux_print_syscall_sys_utime, vf_linux_print_sysret },
	{ "sys_mknod", vf_linux_print_syscall_sys_mknod, vf_linux_print_sysret },
	{ "sys_uselib", vf_linux_print_syscall_sys_uselib, vf_linux_print_sysret },
	{ "sys_personality", vf_linux_print_syscall_sys_personality, vf_linux_print_sysret },
	{ "sys_ustat", vf_linux_print_syscall_sys_ustat, vf_linux_print_sysret },
	{ "sys_statfs", vf_linux_print_syscall_sys_statfs, vf_linux_print_sysret },
	{ "sys_fstatfs", vf_linux_print_syscall_sys_fstatfs, vf_linux_print_sysret },
	{ "sys_sysfs", vf_linux_print_syscall_sys_sysfs, vf_linux_print_sysret },
	{ "sys_getpriority", vf_linux_print_syscall_sys_getpriority, vf_linux_print_sysret },
	{ "sys_setpriority", vf_linux_print_syscall_sys_setpriority, vf_linux_print_sysret },
	{ "sys_sched_setparam", vf_linux_print_syscall_sys_sched_setparam, vf_linux_print_sysret },
	{ "sys_sched_getparam", vf_linux_print_syscall_sys_sched_getparam, vf_linux_print_sysret },
	{ "sys_sched_setscheduler", vf_linux_print_syscall_sys_sched_setscheduler, vf_linux_print_sysret },
	{ "sys_sched_getscheduler", vf_linux_print_syscall_sys_sched_getscheduler, vf_linux_print_sysret },
	{ "sys_sched_get_priority_max", vf_linux_print_syscall_sys_sched_get_priority_max, vf_linux_print_sysret },
	{ "sys_sched_get_priority_min", vf_linux_print_syscall_sys_sched_get_priority_min, vf_linux_print_sysret },
	{ "sys_sched_rr_get_interval", vf_linux_print_syscall_sys_sched_rr_get_interval, vf_linux_print_sysret },
	{ "sys_mlock", vf_linux_print_syscall_sys_mlock, vf_linux_print_sysret },
	{ "sys_munlock", vf_linux_print_syscall_sys_munlock, vf_linux_print_sysret },
	{ "sys_mlockall", vf_linux_print_syscall_sys_mlockall, vf_linux_print_sysret },
	{ "sys_munlockall", vf_linux_print_syscall_sys_munlockall, vf_linux_print_sysret },
	{ "sys_vhangup", vf_linux_print_syscall_sys_vhangup, vf_linux_print_sysret },
	{ "sys_modify_ldt", vf_linux_print_syscall_sys_modify_ldt, vf_linux_print_sysret },
	{ "sys_pivot_root", vf_linux_print_syscall_sys_pivot_root, vf_linux_print_sysret },
	{ "sys_sysctl", vf_linux_print_syscall_sys_sysctl, vf_linux_print_sysret },
	{ "sys_prctl", vf_linux_print_syscall_sys_prctl, vf_linux_print_sysret },
	{ "sys_arch_prctl", vf_linux_print_syscall_sys_arch_prctl, vf_linux_print_sysret },
	{ "sys_adjtimex", vf_linux_print_syscall_sys_adjtimex, vf_linux_print_sysret },
	{ "sys_setrlimit", vf_linux_print_syscall_sys_setrlimit, vf_linux_print_sysret },
	{ "sys_chroot", vf_linux_print_syscall_sys_chroot, vf_linux_print_sysret },
	{ "sys_sync", vf_linux_print_syscall_sys_sync, vf_linux_print_sysret },
	{ "sys_acct", vf_linux_print_syscall_sys_acct, vf_linux_print_sysret },
	{ "sys_settimeofday", vf_linux_print_syscall_sys_settimeofday, vf_linux_print_sysret },
	{ "sys_mount", vf_linux_print_syscall_sys_mount, vf_linux_print_sysret },
	{ "sys_umount2", vf_linux_print_syscall_sys_umount2, vf_linux_print_sysret },
	{ "sys_swapon", vf_linux_print_syscall_sys_swapon, vf_linux_print_sysret },
	{ "sys_swapoff", vf_linux_print_syscall_sys_swapoff, vf_linux_print_sysret },
	{ "sys_reboot", vf_linux_print_syscall_sys_reboot, vf_linux_print_sysret },
	{ "sys_sethostname", vf_linux_print_syscall_sys_sethostname, vf_linux_print_sysret },
	{ "sys_setdomainname", vf_linux_print_syscall_sys_setdomainname, vf_linux_print_sysret },
	{ "sys_iopl", vf_linux_print_syscall_sys_iopl, vf_linux_print_sysret },
	{ "sys_ioperm", vf_linux_print_syscall_sys_ioperm, vf_linux_print_sysret },
	{ "sys_create_module", vf_linux_print_syscall_sys_create_module, vf_linux_print_sysret },
	{ "sys_init_module", vf_linux_print_syscall_sys_init_module, vf_linux_print_sysret },
	{ "sys_delete_module", vf_linux_print_syscall_sys_delete_module, vf_linux_print_sysret },
	{ "sys_get_kernel_syms", vf_linux_print_syscall_sys_get_kernel_syms, vf_linux_print_sysret },
	{ "sys_query_module", vf_linux_print_syscall_sys_query_module, vf_linux_print_sysret },
	{ "sys_quotactl", vf_linux_print_syscall_sys_quotactl, vf_linux_print_sysret },
	{ "sys_nfsservctl", vf_linux_print_syscall_sys_nfsservctl, vf_linux_print_sysret },
	{ "sys_getpmsg", vf_linux_print_syscall_sys_getpmsg, vf_linux_print_sysret },
	{ "sys_putpmsg", vf_linux_print_syscall_sys_putpmsg, vf_linux_print_sysret },
	{ "sys_afs_syscall", vf_linux_print_syscall_sys_afs_syscall, vf_linux_print_sysret },
	{ "sys_tuxcall", vf_linux_print_syscall_sys_tuxcall, vf_linux_print_sysret },
	{ "sys_security", vf_linux_print_syscall_sys_security, vf_linux_print_sysret },
	{ "sys_gettid", vf_linux_print_syscall_sys_gettid, vf_linux_print_sysret },
	{ "sys_readahead", vf_linux_print_syscall_sys_readahead, vf_linux_print_sysret },
	{ "sys_setxattr", vf_linux_print_syscall_sys_setxattr, vf_linux_print_sysret },
	{ "sys_lsetxattr", vf_linux_print_syscall_sys_lsetxattr, vf_linux_print_sysret },
	{ "sys_fsetxattr", vf_linux_print_syscall_sys_fsetxattr, vf_linux_print_sysret },
	{ "sys_getxattr", vf_linux_print_syscall_sys_getxattr, vf_linux_print_sysret },
	{ "sys_lgetxattr", vf_linux_print_syscall_sys_lgetxattr, vf_linux_print_sysret },
	{ "sys_fgetxattr", vf_linux_print_syscall_sys_fgetxattr, vf_linux_print_sysret },
	{ "sys_listxattr", vf_linux_print_syscall_sys_listxattr, vf_linux_print_sysret },
	{ "sys_llistxattr", vf_linux_print_syscall_sys_llistxattr, vf_linux_print_sysret },
	{ "sys_flistxattr", vf_linux_print_syscall_sys_flistxattr, vf_linux_print_sysret },
	{ "sys_removexattr", vf_linux_print_syscall_sys_removexattr, vf_linux_print_sysret },
	{ "sys_lremovexattr", vf_linux_print_syscall_sys_lremovexattr, vf_linux_print_sysret },
	{ "sys_fremovexattr", vf_linux_print_syscall_sys_fremovexattr, vf_linux_print_sysret },
	{ "sys_tkill", vf_linux_print_syscall_sys_tkill, vf_linux_print_sysret },
	{ "sys_time", vf_linux_print_syscall_sys_time, vf_linux_print_sysret },
	{ "sys_futex", vf_linux_print_syscall_sys_futex, vf_linux_print_sysret },
	{ "sys_sched_setaffinity", vf_linux_print_syscall_sys_sched_setaffinity, vf_linux_print_sysret },
	{ "sys_sched_getaffinity", vf_linux_print_syscall_sys_sched_getaffinity, vf_linux_print_sysret },
	{ "sys_set_thread_area", vf_linux_print_syscall_sys_set_thread_area, vf_linux_print_sysret },
	{ "sys_io_setup", vf_linux_print_syscall_sys_io_setup, vf_linux_print_sysret },
	{ "sys_io_destroy", vf_linux_print_syscall_sys_io_destroy, vf_linux_print_sysret },
	{ "sys_io_getevents", vf_linux_print_syscall_sys_io_getevents, vf_linux_print_sysret },
	{ "sys_io_submit", vf_linux_print_syscall_sys_io_submit, vf_linux_print_sysret },
	{ "sys_io_cancel", vf_linux_print_syscall_sys_io_cancel, vf_linux_print_sysret },
	{ "sys_get_thread_area", vf_linux_print_syscall_sys_get_thread_area, vf_linux_print_sysret },
	{ "sys_lookup_dcookie", vf_linux_print_syscall_sys_lookup_dcookie, vf_linux_print_sysret },
	{ "sys_epoll_create", vf_linux_print_syscall_sys_epoll_create, vf_linux_print_sysret },
	{ "sys_epoll_ctl_old", vf_linux_print_syscall_sys_epoll_ctl_old, vf_linux_print_sysret },
	{ "sys_epoll_wait_old", vf_linux_print_syscall_sys_epoll_wait_old, vf_linux_print_sysret },
	{ "sys_remap_file_pages", vf_linux_print_syscall_sys_remap_file_pages, vf_linux_print_sysret },
	{ "sys_getdents64", vf_linux_print_syscall_sys_getdents64, vf_linux_print_sysret },
	{ "sys_set_tid_address", vf_linux_print_syscall_sys_set_tid_address, vf_linux_print_sysret },
	{ "sys_restart_syscall", vf_linux_print_syscall_sys_restart_syscall, vf_linux_print_sysret },
	{ "sys_semtimedop", vf_linux_print_syscall_sys_semtimedop, vf_linux_print_sysret },
	{ "sys_fadvise64", vf_linux_print_syscall_sys_fadvise64, vf_linux_print_sysret },
	{ "sys_timer_create", vf_linux_print_syscall_sys_timer_create, vf_linux_print_sysret },
	{ "sys_timer_settime", vf_linux_print_syscall_sys_timer_settime, vf_linux_print_sysret },
	{ "sys_timer_gettime", vf_linux_print_syscall_sys_timer_gettime, vf_linux_print_sysret },
	{ "sys_timer_getoverrun", vf_linux_print_syscall_sys_timer_getoverrun, vf_linux_print_sysret },
	{ "sys_timer_delete", vf_linux_print_syscall_sys_timer_delete, vf_linux_print_sysret },
	{ "sys_clock_settime", vf_linux_print_syscall_sys_clock_settime, vf_linux_print_sysret },
	{ "sys_clock_gettime", vf_linux_print_syscall_sys_clock_gettime, vf_linux_print_sysret },
	{ "sys_clock_getres", vf_linux_print_syscall_sys_clock_getres, vf_linux_print_sysret },
	{ "sys_clock_nanosleep", vf_linux_print_syscall_sys_clock_nanosleep, vf_linux_print_sysret },
	{ "sys_exit_group", vf_linux_print_syscall_sys_exit_group, vf_linux_print_sysret },
	{ "sys_epoll_wait", vf_linux_print_syscall_sys_epoll_wait, vf_linux_print_sysret },
	{ "sys_epoll_ctl", vf_linux_print_syscall_sys_epoll_ctl, vf_linux_print_sysret },
	{ "sys_tgkill", vf_linux_print_syscall_sys_tgkill, vf_linux_print_sysret },
	{ "sys_utimes", vf_linux_print_syscall_sys_utimes, vf_linux_print_sysret },
	{ "sys_vserver", vf_linux_print_syscall_sys_vserver, vf_linux_print_sysret },
	{ "sys_mbind", vf_linux_print_syscall_sys_mbind, vf_linux_print_sysret },
	{ "sys_set_mempolicy", vf_linux_print_syscall_sys_set_mempolicy, vf_linux_print_sysret },
	{ "sys_get_mempolicy", vf_linux_print_syscall_sys_get_mempolicy, vf_linux_print_sysret },
	{ "sys_mq_open", vf_linux_print_syscall_sys_mq_open, vf_linux_print_sysret },
	{ "sys_mq_unlink", vf_linux_print_syscall_sys_mq_unlink, vf_linux_print_sysret },
	{ "sys_mq_timedsend", vf_linux_print_syscall_sys_mq_timedsend, vf_linux_print_sysret },
	{ "sys_mq_timedreceive", vf_linux_print_syscall_sys_mq_timedreceive, vf_linux_print_sysret },
	{ "sys_mq_notify", vf_linux_print_syscall_sys_mq_notify, vf_linux_print_sysret },
	{ "sys_mq_getsetattr", vf_linux_print_syscall_sys_mq_getsetattr, vf_linux_print_sysret },
	{ "sys_kexec_load", vf_linux_print_syscall_sys_kexec_load, vf_linux_print_sysret },
	{ "sys_waitid", vf_linux_print_syscall_sys_waitid, vf_linux_print_sysret },
	{ "sys_add_key", vf_linux_print_syscall_sys_add_key, vf_linux_print_sysret },
	{ "sys_request_key", vf_linux_print_syscall_sys_request_key, vf_linux_print_sysret },
	{ "sys_keyctl", vf_linux_print_syscall_sys_keyctl, vf_linux_print_sysret },
	{ "sys_ioprio_set", vf_linux_print_syscall_sys_ioprio_set, vf_linux_print_sysret },
	{ "sys_ioprio_get", vf_linux_print_syscall_sys_ioprio_get, vf_linux_print_sysret },
	{ "sys_inotify_init", vf_linux_print_syscall_sys_inotify_init, vf_linux_print_sysret },
	{ "sys_inotify_add_watch", vf_linux_print_syscall_sys_inotify_add_watch, vf_linux_print_sysret },
	{ "sys_inotify_rm_watch", vf_linux_print_syscall_sys_inotify_rm_watch, vf_linux_print_sysret },
	{ "sys_migrate_pages", vf_linux_print_syscall_sys_migrate_pages, vf_linux_print_sysret },
	{ "sys_openat", vf_linux_print_syscall_sys_openat, vf_linux_print_sysret },
	{ "sys_mkdirat", vf_linux_print_syscall_sys_mkdirat, vf_linux_print_sysret },
	{ "sys_mknodat", vf_linux_print_syscall_sys_mknodat, vf_linux_print_sysret },
	{ "sys_fchownat", vf_linux_print_syscall_sys_fchownat, vf_linux_print_sysret },
	{ "sys_futimesat", vf_linux_print_syscall_sys_futimesat, vf_linux_print_sysret },
	{ "sys_newfstatat", vf_linux_print_syscall_sys_newfstatat, vf_linux_print_sysret },
	{ "sys_unlinkat", vf_linux_print_syscall_sys_unlinkat, vf_linux_print_sysret },
	{ "sys_renameat", vf_linux_print_syscall_sys_renameat, vf_linux_print_sysret },
	{ "sys_linkat", vf_linux_print_syscall_sys_linkat, vf_linux_print_sysret },
	{ "sys_symlinkat", vf_linux_print_syscall_sys_symlinkat, vf_linux_print_sysret },
	{ "sys_readlinkat", vf_linux_print_syscall_sys_readlinkat, vf_linux_print_sysret },
	{ "sys_fchmodat", vf_linux_print_syscall_sys_fchmodat, vf_linux_print_sysret },
	{ "sys_faccessat", vf_linux_print_syscall_sys_faccessat, vf_linux_print_sysret },
	{ "sys_pselect6", vf_linux_print_syscall_sys_pselect6, vf_linux_print_sysret },
	{ "sys_ppoll", vf_linux_print_syscall_sys_ppoll, vf_linux_print_sysret },
	{ "sys_unshare", vf_linux_print_syscall_sys_unshare, vf_linux_print_sysret },
	{ "sys_set_robust_list", vf_linux_print_syscall_sys_set_robust_list, vf_linux_print_sysret },
	{ "sys_get_robust_list", vf_linux_print_syscall_sys_get_robust_list, vf_linux_print_sysret },
	{ "sys_splice", vf_linux_print_syscall_sys_splice, vf_linux_print_sysret },
	{ "sys_tee", vf_linux_print_syscall_sys_tee, vf_linux_print_sysret },
	{ "sys_sync_file_range", vf_linux_print_syscall_sys_sync_file_range, vf_linux_print_sysret },
	{ "sys_vmsplice", vf_linux_print_syscall_sys_vmsplice, vf_linux_print_sysret },
	{ "sys_move_pages", vf_linux_print_syscall_sys_move_pages, vf_linux_print_sysret },
	{ "sys_utimensat", vf_linux_print_syscall_sys_utimensat, vf_linux_print_sysret },
	{ "sys_epoll_pwait", vf_linux_print_syscall_sys_epoll_pwait, vf_linux_print_sysret },
	{ "sys_signalfd", vf_linux_print_syscall_sys_signalfd, vf_linux_print_sysret },
	{ "sys_timerfd", vf_linux_print_syscall_sys_timerfd, vf_linux_print_sysret },
	{ "sys_eventfd", vf_linux_print_syscall_sys_eventfd, vf_linux_print_sysret },
	{ "sys_fallocate", vf_linux_print_syscall_sys_fallocate, vf_linux_print_sysret },
	{ "sys_timerfd_settime", vf_linux_print_syscall_sys_timerfd_settime, vf_linux_print_sysret },
	{ "sys_timerfd_gettime", vf_linux_print_syscall_sys_timerfd_gettime, vf_linux_print_sysret },
	{ "sys_accept4", vf_linux_print_syscall_sys_accept4, vf_linux_print_sysret },
	{ "sys_signalfd4", vf_linux_print_syscall_sys_signalfd4, vf_linux_print_sysret },
	{ "sys_eventfd2", vf_linux_print_syscall_sys_eventfd2, vf_linux_print_sysret },
	{ "sys_epoll_create1", vf_linux_print_syscall_sys_epoll_create1, vf_linux_print_sysret },
	{ "sys_dup3", vf_linux_print_syscall_sys_dup3, vf_linux_print_sysret },
	{ "sys_pipe2", vf_linux_print_syscall_sys_pipe2, vf_linux_print_sysret },
	{ "sys_inotify_init1", vf_linux_print_syscall_sys_inotify_init1, vf_linux_print_sysret },
	{ "sys_preadv", vf_linux_print_syscall_sys_preadv, vf_linux_print_sysret },
	{ "sys_pwritev", vf_linux_print_syscall_sys_pwritev, vf_linux_print_sysret },
	{ "sys_rt_tgsigqueueinfo", vf_linux_print_syscall_sys_rt_tgsigqueueinfo, vf_linux_print_sysret },
	{ "sys_perf_event_open", vf_linux_print_syscall_sys_perf_event_open, vf_linux_print_sysret },
	{ "sys_recvmmsg", vf_linux_print_syscall_sys_recvmmsg, vf_linux_print_sysret },
	{ "sys_fanotify_init", vf_linux_print_syscall_sys_fanotify_init, vf_linux_print_sysret },
	{ "sys_fanotify_mark", vf_linux_print_syscall_sys_fanotify_mark, vf_linux_print_sysret },
	{ "sys_prlimit64", vf_linux_print_syscall_sys_prlimit64, vf_linux_print_sysret },
	{ "sys_name_to_handle_at", vf_linux_print_syscall_sys_name_to_handle_at, vf_linux_print_sysret },
	{ "sys_open_by_handle_at", vf_linux_print_syscall_sys_open_by_handle_at, vf_linux_print_sysret },
	{ "sys_clock_adjtime", vf_linux_print_syscall_sys_clock_adjtime, vf_linux_print_sysret },
	{ "sys_syncfs", vf_linux_print_syscall_sys_syncfs, vf_linux_print_sysret },
	{ "sys_sendmmsg", vf_linux_print_syscall_sys_sendmmsg, vf_linux_print_sysret },
	{ "sys_setns", vf_linux_print_syscall_sys_setns, vf_linux_print_sysret },
	{ "sys_getcpu", vf_linux_print_syscall_sys_getcpu, vf_linux_print_sysret },
	{ "sys_process_vm_readv", vf_linux_print_syscall_sys_process_vm_readv, vf_linux_print_sysret },
	{ "sys_process_vm_writev", vf_linux_print_syscall_sys_process_vm_writev, vf_linux_print_sysret },
	{ "sys_kcmp", vf_linux_print_syscall_sys_kcmp, vf_linux_print_sysret },
	{ "sys_finit_module", vf_linux_print_syscall_sys_finit_module, vf_linux_print_sysret },
	{ "sys_sched_setattr", vf_linux_print_syscall_sys_sched_setattr, vf_linux_print_sysret },
	{ "sys_sched_getattr", vf_linux_print_syscall_sys_sched_getattr, vf_linux_print_sysret },
	{ "sys_renameat2", vf_linux_print_syscall_sys_renameat2, vf_linux_print_sysret },
	{ "sys_seccomp", vf_linux_print_syscall_sys_seccomp, vf_linux_print_sysret },
	{ "sys_getrandom", vf_linux_print_syscall_sys_getrandom, vf_linux_print_sysret },
	{ "sys_memfd_create", vf_linux_print_syscall_sys_memfd_create, vf_linux_print_sysret },
	{ "sys_kexec_file_load", vf_linux_print_syscall_sys_kexec_file_load, vf_linux_print_sysret },
	{ "sys_bpf", vf_linux_print_syscall_sys_bpf, vf_linux_print_sysret },
	{ "sys_execveat", vf_linux_print_syscall_sys_execveat, vf_linux_print_sysret },
	{ "sys_userfaultfd", vf_linux_print_syscall_sys_userfaultfd, vf_linux_print_sysret },
	{ "sys_membarrier", vf_linux_print_syscall_sys_membarrier, vf_linux_print_sysret },
	{ "sys_mlock2", vf_linux_print_syscall_sys_mlock2, vf_linux_print_sysret },
	{ "sys_copy_file_range", vf_linux_print_syscall_sys_copy_file_range, vf_linux_print_sysret },
	{ NULL, NULL, NULL }
};

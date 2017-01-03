/* Generated on Linux_4.8.15-300.fc25.x86_64 on 03 Jan 2017 15:57:44*/

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

struct syscall_defs {
    char *name;
    void (*print) (vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event);
};

static char *
get_proc_name(vmi_instance_t vmi, vmi_pid_t pid) 
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
		printf("Failed to read address for init_task!\n");
		goto done;
	}
	
	list_curr = list_head;							/* set the current process to the head */

	do{
		curr_proc = list_curr - task_offset;						/* subtract the task offset to get to the start of the task_struct */
		if (VMI_FAILURE == vmi_read_32_va(vmi, curr_proc + pid_offset, 0, (uint32_t*)&curr_pid)) {		/* read the current pid using the pid offset from the start of the task struct */
			printf("Failed to get the pid of the process we are examining!\n");
			goto done;
		}
	
		if (pid == curr_pid) {
			proc = vmi_read_str_va(vmi, curr_proc + name_offset, 0);		/* get the process name if the current pid is equal to the pis we are looking for */
			goto done;								/* go to done to exit */
		}
	
		if (VMI_FAILURE == vmi_read_addr_va(vmi, list_curr, 0, &list_curr)) {				/* read the memory from the address of list_curr which will return a pointer to the */
			printf("Failed to get the next task in the process list!\n");
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

static void vf_linux_print_syscall_sys_read(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_write(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_open(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	char *arg0 = vmi_read_str_va(vmi, event->x86_regs->rdi, pid);
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(\"%s\", %i, %lu)\n", pid, proc, syscall, (char *) arg0, (int) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_close(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%lu)\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_stat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_fstat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_lstat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_poll(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %lu, %i)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_lseek(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_mmap(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	printf("pid: %u (%s) syscall: %s(%lu, %lu, %lu, %lu, %lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
}

static void vf_linux_print_syscall_sys_mprotect(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, %lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_munmap(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_brk(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%lu)\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_rt_sigaction(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_rt_sigprocmask(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_rt_sigreturn(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_ioctl(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, %lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_pread(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %li)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (long int) arg3);
}

static void vf_linux_print_syscall_sys_pwrite(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %li)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (long int) arg3);
}

static void vf_linux_print_syscall_sys_readv(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_writev(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_access(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, proc, syscall, (unsigned long) arg0, (int) arg1);
}

static void vf_linux_print_syscall_sys_pipe(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_select(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_sched_yield(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_mremap(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%lu, %lu, %lu, %lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_msync(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, %lu, %i)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_mincore(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, %lu, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_madvise(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, %lu, %i)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_shmget(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, %lu, %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_shmat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_shmctl(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, %i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (int) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_dup(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%lu)\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_dup2(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_pause(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_nanosleep(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_getitimer(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_alarm(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%lu)\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_setitimer(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_getpid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_sendfile(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, %i, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_socket(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, %i, %i)\n", pid, proc, syscall, (int) arg0, (int) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_connect(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_accept(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_sendto(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (int) arg5);
}

static void vf_linux_print_syscall_sys_recvfrom(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
}

static void vf_linux_print_syscall_sys_sendmsg(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_recvmsg(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_shutdown(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, %i)\n", pid, proc, syscall, (int) arg0, (int) arg1);
}

static void vf_linux_print_syscall_sys_bind(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_listen(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, %i)\n", pid, proc, syscall, (int) arg0, (int) arg1);
}

static void vf_linux_print_syscall_sys_getsockname(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_getpeername(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_socketpair(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_setsockopt(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64", %i)\n", pid, proc, syscall, (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, (int) arg4);
}

static void vf_linux_print_syscall_sys_getsockopt(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_clone(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_fork(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_vfork(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_execve(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_exit(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%i)\n", pid, proc, syscall, (int) arg0);
}

static void vf_linux_print_syscall_sys_wait4(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_kill(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, %i)\n", pid, proc, syscall, (int) arg0, (int) arg1);
}

static void vf_linux_print_syscall_sys_uname(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_semget(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, %i, %i)\n", pid, proc, syscall, (int) arg0, (int) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_semop(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_semctl(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, %i, %i, %lu)\n", pid, proc, syscall, (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_shmdt(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_msgget(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, %i)\n", pid, proc, syscall, (int) arg0, (int) arg1);
}

static void vf_linux_print_syscall_sys_msgsnd(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
}

static void vf_linux_print_syscall_sys_msgrcv(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %li, %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (long int) arg3, (int) arg4);
}

static void vf_linux_print_syscall_sys_msgctl(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, %i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (int) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_fcntl(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, %lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_flock(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_fsync(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%lu)\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_fdatasync(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%lu)\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_truncate(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %li)\n", pid, proc, syscall, (unsigned long) arg0, (long int) arg1);
}

static void vf_linux_print_syscall_sys_ftruncate(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_getdents(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_getcwd(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_chdir(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_fchdir(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%lu)\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_rename(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_mkdir(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_rmdir(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_creat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_link(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_unlink(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_symlink(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_readlink(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_chmod(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_fchmod(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_chown(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_fchown(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, %lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_lchown(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_umask(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%i)\n", pid, proc, syscall, (int) arg0);
}

static void vf_linux_print_syscall_sys_gettimeofday(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_getrlimit(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_getrusage(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_sysinfo(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_times(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_ptrace(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%li, %li, %lu, %lu)\n", pid, proc, syscall, (long int) arg0, (long int) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_getuid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_syslog(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_getgid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_setuid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%lu)\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_setgid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%lu)\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_geteuid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_getegid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_setpgid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, %i)\n", pid, proc, syscall, (int) arg0, (int) arg1);
}

static void vf_linux_print_syscall_sys_getppid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_getpgrp(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_setsid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_setreuid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_setregid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_getgroups(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_setgroups(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_setresuid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, %lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_getresuid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_setresgid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, %lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_getresgid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_getpgid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%i)\n", pid, proc, syscall, (int) arg0);
}

static void vf_linux_print_syscall_sys_setfsuid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%lu)\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_setfsgid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%lu)\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_getsid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%i)\n", pid, proc, syscall, (int) arg0);
}

static void vf_linux_print_syscall_sys_capget(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_capset(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_rt_sigpending(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_rt_sigtimedwait(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_rt_sigqueueinfo(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, %i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (int) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_rt_sigsuspend(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_sigaltstack(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_utime(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_mknod(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_uselib(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_personality(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%lu)\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_ustat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_statfs(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_fstatfs(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_sysfs(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, %lu, %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_getpriority(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, %i)\n", pid, proc, syscall, (int) arg0, (int) arg1);
}

static void vf_linux_print_syscall_sys_setpriority(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, %i, %i)\n", pid, proc, syscall, (int) arg0, (int) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_sched_setparam(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_sched_getparam(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_sched_setscheduler(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, %i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (int) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_sched_getscheduler(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%i)\n", pid, proc, syscall, (int) arg0);
}

static void vf_linux_print_syscall_sys_sched_get_priority_max(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%i)\n", pid, proc, syscall, (int) arg0);
}

static void vf_linux_print_syscall_sys_sched_get_priority_min(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%i)\n", pid, proc, syscall, (int) arg0);
}

static void vf_linux_print_syscall_sys_sched_rr_get_interval(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_mlock(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_munlock(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_mlockall(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%i)\n", pid, proc, syscall, (int) arg0);
}

static void vf_linux_print_syscall_sys_munlockall(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_vhangup(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_modify_ldt(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_pivot_root(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_sysctl(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_prctl(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, %lu, %lu, %lu, %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_arch_prctl(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_adjtimex(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_setrlimit(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_chroot(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_sync(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_acct(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_settimeofday(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_mount(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_umount2(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_swapon(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, proc, syscall, (unsigned long) arg0, (int) arg1);
}

static void vf_linux_print_syscall_sys_swapoff(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_reboot(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, %i, %lu, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_sethostname(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, proc, syscall, (unsigned long) arg0, (int) arg1);
}

static void vf_linux_print_syscall_sys_setdomainname(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, proc, syscall, (unsigned long) arg0, (int) arg1);
}

static void vf_linux_print_syscall_sys_iopl(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%lu)\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_ioperm(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	printf("pid: %u (%s) syscall: %s(%lu, %lu, %i, %lu, %lu, %i)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4, (int) arg5);
}

static void vf_linux_print_syscall_sys_create_module(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_init_module(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_delete_module(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_get_kernel_syms(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_query_module(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_quotactl(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_nfsservctl(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_getpmsg(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_putpmsg(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_afs_syscall(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_tuxcall(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_security(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_gettid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_readahead(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, %li, %lu)\n", pid, proc, syscall, (int) arg0, (long int) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_setxattr(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
}

static void vf_linux_print_syscall_sys_lsetxattr(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
}

static void vf_linux_print_syscall_sys_fsetxattr(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
}

static void vf_linux_print_syscall_sys_getxattr(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_lgetxattr(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_fgetxattr(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_listxattr(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_llistxattr(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_flistxattr(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_removexattr(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_lremovexattr(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_fremovexattr(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_tkill(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, %i)\n", pid, proc, syscall, (int) arg0, (int) arg1);
}

static void vf_linux_print_syscall_sys_time(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_futex(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
}

static void vf_linux_print_syscall_sys_sched_setaffinity(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, %lu, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_sched_getaffinity(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, %lu, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_set_thread_area(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_io_setup(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_io_destroy(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_io_getevents(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %li, %li, 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (long int) arg1, (long int) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_io_submit(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %li, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (long int) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_io_cancel(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_get_thread_area(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_lookup_dcookie(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_epoll_create(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%i)\n", pid, proc, syscall, (int) arg0);
}

static void vf_linux_print_syscall_sys_epoll_ctl_old(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_epoll_wait_old(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_remap_file_pages(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%lu, %lu, %lu, %lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_getdents64(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_set_tid_address(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_restart_syscall(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_semtimedop(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_fadvise64(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, %li, %lu, %i)\n", pid, proc, syscall, (int) arg0, (long int) arg1, (unsigned long) arg2, (int) arg3);
}

static void vf_linux_print_syscall_sys_timer_create(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_timer_settime(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%lu, %i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_timer_gettime(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_timer_getoverrun(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%lu)\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_timer_delete(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%lu)\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_clock_settime(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_clock_gettime(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_clock_getres(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_clock_nanosleep(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%lu, %i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_exit_group(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%i)\n", pid, proc, syscall, (int) arg0);
}

static void vf_linux_print_syscall_sys_epoll_wait(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %i, %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (int) arg2, (int) arg3);
}

static void vf_linux_print_syscall_sys_epoll_ctl(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_tgkill(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, %i, %i)\n", pid, proc, syscall, (int) arg0, (int) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_utimes(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_vserver(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_mbind(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	printf("pid: %u (%s) syscall: %s(%lu, %lu, %lu, 0x%"PRIx64", %lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
}

static void vf_linux_print_syscall_sys_set_mempolicy(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_get_mempolicy(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu, %lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_mq_open(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %i, %lu, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_mq_unlink(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_mq_timedsend(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_mq_timedreceive(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_mq_notify(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_mq_getsetattr(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_kexec_load(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%lu, %lu, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_waitid(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, %i, 0x%"PRIx64", %i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (int) arg1, (unsigned long) arg2, (int) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_add_key(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
}

static void vf_linux_print_syscall_sys_request_key(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
}

static void vf_linux_print_syscall_sys_keyctl(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, %lu, %lu, %lu, %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_ioprio_set(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, %i, %i)\n", pid, proc, syscall, (int) arg0, (int) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_ioprio_get(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, %i)\n", pid, proc, syscall, (int) arg0, (int) arg1);
}

static void vf_linux_print_syscall_sys_inotify_init(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_inotify_add_watch(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_inotify_rm_watch(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_migrate_pages(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_openat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %i, %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_mkdirat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_mknodat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_fchownat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
}

static void vf_linux_print_syscall_sys_futimesat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_newfstatat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
}

static void vf_linux_print_syscall_sys_unlinkat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_renameat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_linkat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (int) arg4);
}

static void vf_linux_print_syscall_sys_symlinkat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %i, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (int) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_readlinkat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
}

static void vf_linux_print_syscall_sys_fchmodat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_faccessat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_pselect6(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
}

static void vf_linux_print_syscall_sys_ppoll(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %lu, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_unshare(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%lu)\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_set_robust_list(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_get_robust_list(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_splice(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %lu, %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
}

static void vf_linux_print_syscall_sys_tee(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, %i, %lu, %lu)\n", pid, proc, syscall, (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_sync_file_range(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, %li, %li, %lu)\n", pid, proc, syscall, (int) arg0, (long int) arg1, (long int) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_vmsplice(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_move_pages(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	printf("pid: %u (%s) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (int) arg5);
}

static void vf_linux_print_syscall_sys_utimensat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
}

static void vf_linux_print_syscall_sys_epoll_pwait(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %i, %i, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (int) arg2, (int) arg3, (unsigned long) arg4, (unsigned long) arg5);
}

static void vf_linux_print_syscall_sys_signalfd(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_timerfd(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	printf("pid: %u (%s) syscall: %s()\n", pid, proc, syscall);
}

static void vf_linux_print_syscall_sys_eventfd(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%lu)\n", pid, proc, syscall, (unsigned long) arg0);
}

static void vf_linux_print_syscall_sys_fallocate(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, %i, %li, %li)\n", pid, proc, syscall, (int) arg0, (int) arg1, (long int) arg2, (long int) arg3);
}

static void vf_linux_print_syscall_sys_timerfd_settime(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, %i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_timerfd_gettime(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_accept4(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
}

static void vf_linux_print_syscall_sys_signalfd4(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
}

static void vf_linux_print_syscall_sys_eventfd2(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, %i)\n", pid, proc, syscall, (unsigned long) arg0, (int) arg1);
}

static void vf_linux_print_syscall_sys_epoll_create1(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%i)\n", pid, proc, syscall, (int) arg0);
}

static void vf_linux_print_syscall_sys_dup3(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, %lu, %i)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_pipe2(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, proc, syscall, (unsigned long) arg0, (int) arg1);
}

static void vf_linux_print_syscall_sys_inotify_init1(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%i)\n", pid, proc, syscall, (int) arg0);
}

static void vf_linux_print_syscall_sys_preadv(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_pwritev(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_rt_tgsigqueueinfo(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_perf_event_open(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %i, %i, %i, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (int) arg1, (int) arg2, (int) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_recvmmsg(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_fanotify_init(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_fanotify_mark(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, %lu, %lu, %i, 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_prlimit64(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_name_to_handle_at(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
}

static void vf_linux_print_syscall_sys_open_by_handle_at(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_clock_adjtime(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_syncfs(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%i)\n", pid, proc, syscall, (int) arg0);
}

static void vf_linux_print_syscall_sys_sendmmsg(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_setns(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, %i)\n", pid, proc, syscall, (int) arg0, (int) arg1);
}

static void vf_linux_print_syscall_sys_getcpu(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_process_vm_readv(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", %lu, %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
}

static void vf_linux_print_syscall_sys_process_vm_writev(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", %lu, %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
}

static void vf_linux_print_syscall_sys_kcmp(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, %i, %i, %lu, %lu)\n", pid, proc, syscall, (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_finit_module(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_sched_setattr(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_sched_getattr(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
}

static void vf_linux_print_syscall_sys_renameat2(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_seccomp(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, %lu, 0x%"PRIx64")\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_getrandom(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %lu, %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_memfd_create(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1);
}

static void vf_linux_print_syscall_sys_kexec_file_load(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, %i, %lu, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
}

static void vf_linux_print_syscall_sys_bpf(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
}

static void vf_linux_print_syscall_sys_execveat(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
}

static void vf_linux_print_syscall_sys_userfaultfd(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	printf("pid: %u (%s) syscall: %s(%i)\n", pid, proc, syscall, (int) arg0);
}

static void vf_linux_print_syscall_sys_membarrier(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	printf("pid: %u (%s) syscall: %s(%i, %i)\n", pid, proc, syscall, (int) arg0, (int) arg1);
}

static void vf_linux_print_syscall_sys_mlock2(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	printf("pid: %u (%s) syscall: %s(%lu, %lu, %i)\n", pid, proc, syscall, (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
}

static void vf_linux_print_syscall_sys_copy_file_range(vmi_instance_t vmi, vmi_pid_t pid, char *proc, char *syscall, vmi_event_t *event)
{
	reg_t arg0 = event->x86_regs->rdi;
	reg_t arg1 = event->x86_regs->rsi;
	reg_t arg2 = event->x86_regs->rdx;
	reg_t arg3 = event->x86_regs->r10;
	reg_t arg4 = event->x86_regs->r8;
	reg_t arg5 = event->x86_regs->r9;
	printf("pid: %u (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %lu, %lu)\n", pid, proc, syscall, (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
}


static const struct syscall_defs SYSCALLS[] = {
	{ "sys_read", vf_linux_print_syscall_sys_read },
	{ "sys_write", vf_linux_print_syscall_sys_write },
	{ "sys_open", vf_linux_print_syscall_sys_open },
	{ "sys_close", vf_linux_print_syscall_sys_close },
	{ "sys_stat", vf_linux_print_syscall_sys_stat },
	{ "sys_fstat", vf_linux_print_syscall_sys_fstat },
	{ "sys_lstat", vf_linux_print_syscall_sys_lstat },
	{ "sys_poll", vf_linux_print_syscall_sys_poll },
	{ "sys_lseek", vf_linux_print_syscall_sys_lseek },
	{ "sys_mmap", vf_linux_print_syscall_sys_mmap },
	{ "sys_mprotect", vf_linux_print_syscall_sys_mprotect },
	{ "sys_munmap", vf_linux_print_syscall_sys_munmap },
	{ "sys_brk", vf_linux_print_syscall_sys_brk },
	{ "sys_rt_sigaction", vf_linux_print_syscall_sys_rt_sigaction },
	{ "sys_rt_sigprocmask", vf_linux_print_syscall_sys_rt_sigprocmask },
	{ "sys_rt_sigreturn", vf_linux_print_syscall_sys_rt_sigreturn },
	{ "sys_ioctl", vf_linux_print_syscall_sys_ioctl },
	{ "sys_pread", vf_linux_print_syscall_sys_pread },
	{ "sys_pwrite", vf_linux_print_syscall_sys_pwrite },
	{ "sys_readv", vf_linux_print_syscall_sys_readv },
	{ "sys_writev", vf_linux_print_syscall_sys_writev },
	{ "sys_access", vf_linux_print_syscall_sys_access },
	{ "sys_pipe", vf_linux_print_syscall_sys_pipe },
	{ "sys_select", vf_linux_print_syscall_sys_select },
	{ "sys_sched_yield", vf_linux_print_syscall_sys_sched_yield },
	{ "sys_mremap", vf_linux_print_syscall_sys_mremap },
	{ "sys_msync", vf_linux_print_syscall_sys_msync },
	{ "sys_mincore", vf_linux_print_syscall_sys_mincore },
	{ "sys_madvise", vf_linux_print_syscall_sys_madvise },
	{ "sys_shmget", vf_linux_print_syscall_sys_shmget },
	{ "sys_shmat", vf_linux_print_syscall_sys_shmat },
	{ "sys_shmctl", vf_linux_print_syscall_sys_shmctl },
	{ "sys_dup", vf_linux_print_syscall_sys_dup },
	{ "sys_dup2", vf_linux_print_syscall_sys_dup2 },
	{ "sys_pause", vf_linux_print_syscall_sys_pause },
	{ "sys_nanosleep", vf_linux_print_syscall_sys_nanosleep },
	{ "sys_getitimer", vf_linux_print_syscall_sys_getitimer },
	{ "sys_alarm", vf_linux_print_syscall_sys_alarm },
	{ "sys_setitimer", vf_linux_print_syscall_sys_setitimer },
	{ "sys_getpid", vf_linux_print_syscall_sys_getpid },
	{ "sys_sendfile", vf_linux_print_syscall_sys_sendfile },
	{ "sys_socket", vf_linux_print_syscall_sys_socket },
	{ "sys_connect", vf_linux_print_syscall_sys_connect },
	{ "sys_accept", vf_linux_print_syscall_sys_accept },
	{ "sys_sendto", vf_linux_print_syscall_sys_sendto },
	{ "sys_recvfrom", vf_linux_print_syscall_sys_recvfrom },
	{ "sys_sendmsg", vf_linux_print_syscall_sys_sendmsg },
	{ "sys_recvmsg", vf_linux_print_syscall_sys_recvmsg },
	{ "sys_shutdown", vf_linux_print_syscall_sys_shutdown },
	{ "sys_bind", vf_linux_print_syscall_sys_bind },
	{ "sys_listen", vf_linux_print_syscall_sys_listen },
	{ "sys_getsockname", vf_linux_print_syscall_sys_getsockname },
	{ "sys_getpeername", vf_linux_print_syscall_sys_getpeername },
	{ "sys_socketpair", vf_linux_print_syscall_sys_socketpair },
	{ "sys_setsockopt", vf_linux_print_syscall_sys_setsockopt },
	{ "sys_getsockopt", vf_linux_print_syscall_sys_getsockopt },
	{ "sys_clone", vf_linux_print_syscall_sys_clone },
	{ "sys_fork", vf_linux_print_syscall_sys_fork },
	{ "sys_vfork", vf_linux_print_syscall_sys_vfork },
	{ "sys_execve", vf_linux_print_syscall_sys_execve },
	{ "sys_exit", vf_linux_print_syscall_sys_exit },
	{ "sys_wait4", vf_linux_print_syscall_sys_wait4 },
	{ "sys_kill", vf_linux_print_syscall_sys_kill },
	{ "sys_uname", vf_linux_print_syscall_sys_uname },
	{ "sys_semget", vf_linux_print_syscall_sys_semget },
	{ "sys_semop", vf_linux_print_syscall_sys_semop },
	{ "sys_semctl", vf_linux_print_syscall_sys_semctl },
	{ "sys_shmdt", vf_linux_print_syscall_sys_shmdt },
	{ "sys_msgget", vf_linux_print_syscall_sys_msgget },
	{ "sys_msgsnd", vf_linux_print_syscall_sys_msgsnd },
	{ "sys_msgrcv", vf_linux_print_syscall_sys_msgrcv },
	{ "sys_msgctl", vf_linux_print_syscall_sys_msgctl },
	{ "sys_fcntl", vf_linux_print_syscall_sys_fcntl },
	{ "sys_flock", vf_linux_print_syscall_sys_flock },
	{ "sys_fsync", vf_linux_print_syscall_sys_fsync },
	{ "sys_fdatasync", vf_linux_print_syscall_sys_fdatasync },
	{ "sys_truncate", vf_linux_print_syscall_sys_truncate },
	{ "sys_ftruncate", vf_linux_print_syscall_sys_ftruncate },
	{ "sys_getdents", vf_linux_print_syscall_sys_getdents },
	{ "sys_getcwd", vf_linux_print_syscall_sys_getcwd },
	{ "sys_chdir", vf_linux_print_syscall_sys_chdir },
	{ "sys_fchdir", vf_linux_print_syscall_sys_fchdir },
	{ "sys_rename", vf_linux_print_syscall_sys_rename },
	{ "sys_mkdir", vf_linux_print_syscall_sys_mkdir },
	{ "sys_rmdir", vf_linux_print_syscall_sys_rmdir },
	{ "sys_creat", vf_linux_print_syscall_sys_creat },
	{ "sys_link", vf_linux_print_syscall_sys_link },
	{ "sys_unlink", vf_linux_print_syscall_sys_unlink },
	{ "sys_symlink", vf_linux_print_syscall_sys_symlink },
	{ "sys_readlink", vf_linux_print_syscall_sys_readlink },
	{ "sys_chmod", vf_linux_print_syscall_sys_chmod },
	{ "sys_fchmod", vf_linux_print_syscall_sys_fchmod },
	{ "sys_chown", vf_linux_print_syscall_sys_chown },
	{ "sys_fchown", vf_linux_print_syscall_sys_fchown },
	{ "sys_lchown", vf_linux_print_syscall_sys_lchown },
	{ "sys_umask", vf_linux_print_syscall_sys_umask },
	{ "sys_gettimeofday", vf_linux_print_syscall_sys_gettimeofday },
	{ "sys_getrlimit", vf_linux_print_syscall_sys_getrlimit },
	{ "sys_getrusage", vf_linux_print_syscall_sys_getrusage },
	{ "sys_sysinfo", vf_linux_print_syscall_sys_sysinfo },
	{ "sys_times", vf_linux_print_syscall_sys_times },
	{ "sys_ptrace", vf_linux_print_syscall_sys_ptrace },
	{ "sys_getuid", vf_linux_print_syscall_sys_getuid },
	{ "sys_syslog", vf_linux_print_syscall_sys_syslog },
	{ "sys_getgid", vf_linux_print_syscall_sys_getgid },
	{ "sys_setuid", vf_linux_print_syscall_sys_setuid },
	{ "sys_setgid", vf_linux_print_syscall_sys_setgid },
	{ "sys_geteuid", vf_linux_print_syscall_sys_geteuid },
	{ "sys_getegid", vf_linux_print_syscall_sys_getegid },
	{ "sys_setpgid", vf_linux_print_syscall_sys_setpgid },
	{ "sys_getppid", vf_linux_print_syscall_sys_getppid },
	{ "sys_getpgrp", vf_linux_print_syscall_sys_getpgrp },
	{ "sys_setsid", vf_linux_print_syscall_sys_setsid },
	{ "sys_setreuid", vf_linux_print_syscall_sys_setreuid },
	{ "sys_setregid", vf_linux_print_syscall_sys_setregid },
	{ "sys_getgroups", vf_linux_print_syscall_sys_getgroups },
	{ "sys_setgroups", vf_linux_print_syscall_sys_setgroups },
	{ "sys_setresuid", vf_linux_print_syscall_sys_setresuid },
	{ "sys_getresuid", vf_linux_print_syscall_sys_getresuid },
	{ "sys_setresgid", vf_linux_print_syscall_sys_setresgid },
	{ "sys_getresgid", vf_linux_print_syscall_sys_getresgid },
	{ "sys_getpgid", vf_linux_print_syscall_sys_getpgid },
	{ "sys_setfsuid", vf_linux_print_syscall_sys_setfsuid },
	{ "sys_setfsgid", vf_linux_print_syscall_sys_setfsgid },
	{ "sys_getsid", vf_linux_print_syscall_sys_getsid },
	{ "sys_capget", vf_linux_print_syscall_sys_capget },
	{ "sys_capset", vf_linux_print_syscall_sys_capset },
	{ "sys_rt_sigpending", vf_linux_print_syscall_sys_rt_sigpending },
	{ "sys_rt_sigtimedwait", vf_linux_print_syscall_sys_rt_sigtimedwait },
	{ "sys_rt_sigqueueinfo", vf_linux_print_syscall_sys_rt_sigqueueinfo },
	{ "sys_rt_sigsuspend", vf_linux_print_syscall_sys_rt_sigsuspend },
	{ "sys_sigaltstack", vf_linux_print_syscall_sys_sigaltstack },
	{ "sys_utime", vf_linux_print_syscall_sys_utime },
	{ "sys_mknod", vf_linux_print_syscall_sys_mknod },
	{ "sys_uselib", vf_linux_print_syscall_sys_uselib },
	{ "sys_personality", vf_linux_print_syscall_sys_personality },
	{ "sys_ustat", vf_linux_print_syscall_sys_ustat },
	{ "sys_statfs", vf_linux_print_syscall_sys_statfs },
	{ "sys_fstatfs", vf_linux_print_syscall_sys_fstatfs },
	{ "sys_sysfs", vf_linux_print_syscall_sys_sysfs },
	{ "sys_getpriority", vf_linux_print_syscall_sys_getpriority },
	{ "sys_setpriority", vf_linux_print_syscall_sys_setpriority },
	{ "sys_sched_setparam", vf_linux_print_syscall_sys_sched_setparam },
	{ "sys_sched_getparam", vf_linux_print_syscall_sys_sched_getparam },
	{ "sys_sched_setscheduler", vf_linux_print_syscall_sys_sched_setscheduler },
	{ "sys_sched_getscheduler", vf_linux_print_syscall_sys_sched_getscheduler },
	{ "sys_sched_get_priority_max", vf_linux_print_syscall_sys_sched_get_priority_max },
	{ "sys_sched_get_priority_min", vf_linux_print_syscall_sys_sched_get_priority_min },
	{ "sys_sched_rr_get_interval", vf_linux_print_syscall_sys_sched_rr_get_interval },
	{ "sys_mlock", vf_linux_print_syscall_sys_mlock },
	{ "sys_munlock", vf_linux_print_syscall_sys_munlock },
	{ "sys_mlockall", vf_linux_print_syscall_sys_mlockall },
	{ "sys_munlockall", vf_linux_print_syscall_sys_munlockall },
	{ "sys_vhangup", vf_linux_print_syscall_sys_vhangup },
	{ "sys_modify_ldt", vf_linux_print_syscall_sys_modify_ldt },
	{ "sys_pivot_root", vf_linux_print_syscall_sys_pivot_root },
	{ "sys_sysctl", vf_linux_print_syscall_sys_sysctl },
	{ "sys_prctl", vf_linux_print_syscall_sys_prctl },
	{ "sys_arch_prctl", vf_linux_print_syscall_sys_arch_prctl },
	{ "sys_adjtimex", vf_linux_print_syscall_sys_adjtimex },
	{ "sys_setrlimit", vf_linux_print_syscall_sys_setrlimit },
	{ "sys_chroot", vf_linux_print_syscall_sys_chroot },
	{ "sys_sync", vf_linux_print_syscall_sys_sync },
	{ "sys_acct", vf_linux_print_syscall_sys_acct },
	{ "sys_settimeofday", vf_linux_print_syscall_sys_settimeofday },
	{ "sys_mount", vf_linux_print_syscall_sys_mount },
	{ "sys_umount2", vf_linux_print_syscall_sys_umount2 },
	{ "sys_swapon", vf_linux_print_syscall_sys_swapon },
	{ "sys_swapoff", vf_linux_print_syscall_sys_swapoff },
	{ "sys_reboot", vf_linux_print_syscall_sys_reboot },
	{ "sys_sethostname", vf_linux_print_syscall_sys_sethostname },
	{ "sys_setdomainname", vf_linux_print_syscall_sys_setdomainname },
	{ "sys_iopl", vf_linux_print_syscall_sys_iopl },
	{ "sys_ioperm", vf_linux_print_syscall_sys_ioperm },
	{ "sys_create_module", vf_linux_print_syscall_sys_create_module },
	{ "sys_init_module", vf_linux_print_syscall_sys_init_module },
	{ "sys_delete_module", vf_linux_print_syscall_sys_delete_module },
	{ "sys_get_kernel_syms", vf_linux_print_syscall_sys_get_kernel_syms },
	{ "sys_query_module", vf_linux_print_syscall_sys_query_module },
	{ "sys_quotactl", vf_linux_print_syscall_sys_quotactl },
	{ "sys_nfsservctl", vf_linux_print_syscall_sys_nfsservctl },
	{ "sys_getpmsg", vf_linux_print_syscall_sys_getpmsg },
	{ "sys_putpmsg", vf_linux_print_syscall_sys_putpmsg },
	{ "sys_afs_syscall", vf_linux_print_syscall_sys_afs_syscall },
	{ "sys_tuxcall", vf_linux_print_syscall_sys_tuxcall },
	{ "sys_security", vf_linux_print_syscall_sys_security },
	{ "sys_gettid", vf_linux_print_syscall_sys_gettid },
	{ "sys_readahead", vf_linux_print_syscall_sys_readahead },
	{ "sys_setxattr", vf_linux_print_syscall_sys_setxattr },
	{ "sys_lsetxattr", vf_linux_print_syscall_sys_lsetxattr },
	{ "sys_fsetxattr", vf_linux_print_syscall_sys_fsetxattr },
	{ "sys_getxattr", vf_linux_print_syscall_sys_getxattr },
	{ "sys_lgetxattr", vf_linux_print_syscall_sys_lgetxattr },
	{ "sys_fgetxattr", vf_linux_print_syscall_sys_fgetxattr },
	{ "sys_listxattr", vf_linux_print_syscall_sys_listxattr },
	{ "sys_llistxattr", vf_linux_print_syscall_sys_llistxattr },
	{ "sys_flistxattr", vf_linux_print_syscall_sys_flistxattr },
	{ "sys_removexattr", vf_linux_print_syscall_sys_removexattr },
	{ "sys_lremovexattr", vf_linux_print_syscall_sys_lremovexattr },
	{ "sys_fremovexattr", vf_linux_print_syscall_sys_fremovexattr },
	{ "sys_tkill", vf_linux_print_syscall_sys_tkill },
	{ "sys_time", vf_linux_print_syscall_sys_time },
	{ "sys_futex", vf_linux_print_syscall_sys_futex },
	{ "sys_sched_setaffinity", vf_linux_print_syscall_sys_sched_setaffinity },
	{ "sys_sched_getaffinity", vf_linux_print_syscall_sys_sched_getaffinity },
	{ "sys_set_thread_area", vf_linux_print_syscall_sys_set_thread_area },
	{ "sys_io_setup", vf_linux_print_syscall_sys_io_setup },
	{ "sys_io_destroy", vf_linux_print_syscall_sys_io_destroy },
	{ "sys_io_getevents", vf_linux_print_syscall_sys_io_getevents },
	{ "sys_io_submit", vf_linux_print_syscall_sys_io_submit },
	{ "sys_io_cancel", vf_linux_print_syscall_sys_io_cancel },
	{ "sys_get_thread_area", vf_linux_print_syscall_sys_get_thread_area },
	{ "sys_lookup_dcookie", vf_linux_print_syscall_sys_lookup_dcookie },
	{ "sys_epoll_create", vf_linux_print_syscall_sys_epoll_create },
	{ "sys_epoll_ctl_old", vf_linux_print_syscall_sys_epoll_ctl_old },
	{ "sys_epoll_wait_old", vf_linux_print_syscall_sys_epoll_wait_old },
	{ "sys_remap_file_pages", vf_linux_print_syscall_sys_remap_file_pages },
	{ "sys_getdents64", vf_linux_print_syscall_sys_getdents64 },
	{ "sys_set_tid_address", vf_linux_print_syscall_sys_set_tid_address },
	{ "sys_restart_syscall", vf_linux_print_syscall_sys_restart_syscall },
	{ "sys_semtimedop", vf_linux_print_syscall_sys_semtimedop },
	{ "sys_fadvise64", vf_linux_print_syscall_sys_fadvise64 },
	{ "sys_timer_create", vf_linux_print_syscall_sys_timer_create },
	{ "sys_timer_settime", vf_linux_print_syscall_sys_timer_settime },
	{ "sys_timer_gettime", vf_linux_print_syscall_sys_timer_gettime },
	{ "sys_timer_getoverrun", vf_linux_print_syscall_sys_timer_getoverrun },
	{ "sys_timer_delete", vf_linux_print_syscall_sys_timer_delete },
	{ "sys_clock_settime", vf_linux_print_syscall_sys_clock_settime },
	{ "sys_clock_gettime", vf_linux_print_syscall_sys_clock_gettime },
	{ "sys_clock_getres", vf_linux_print_syscall_sys_clock_getres },
	{ "sys_clock_nanosleep", vf_linux_print_syscall_sys_clock_nanosleep },
	{ "sys_exit_group", vf_linux_print_syscall_sys_exit_group },
	{ "sys_epoll_wait", vf_linux_print_syscall_sys_epoll_wait },
	{ "sys_epoll_ctl", vf_linux_print_syscall_sys_epoll_ctl },
	{ "sys_tgkill", vf_linux_print_syscall_sys_tgkill },
	{ "sys_utimes", vf_linux_print_syscall_sys_utimes },
	{ "sys_vserver", vf_linux_print_syscall_sys_vserver },
	{ "sys_mbind", vf_linux_print_syscall_sys_mbind },
	{ "sys_set_mempolicy", vf_linux_print_syscall_sys_set_mempolicy },
	{ "sys_get_mempolicy", vf_linux_print_syscall_sys_get_mempolicy },
	{ "sys_mq_open", vf_linux_print_syscall_sys_mq_open },
	{ "sys_mq_unlink", vf_linux_print_syscall_sys_mq_unlink },
	{ "sys_mq_timedsend", vf_linux_print_syscall_sys_mq_timedsend },
	{ "sys_mq_timedreceive", vf_linux_print_syscall_sys_mq_timedreceive },
	{ "sys_mq_notify", vf_linux_print_syscall_sys_mq_notify },
	{ "sys_mq_getsetattr", vf_linux_print_syscall_sys_mq_getsetattr },
	{ "sys_kexec_load", vf_linux_print_syscall_sys_kexec_load },
	{ "sys_waitid", vf_linux_print_syscall_sys_waitid },
	{ "sys_add_key", vf_linux_print_syscall_sys_add_key },
	{ "sys_request_key", vf_linux_print_syscall_sys_request_key },
	{ "sys_keyctl", vf_linux_print_syscall_sys_keyctl },
	{ "sys_ioprio_set", vf_linux_print_syscall_sys_ioprio_set },
	{ "sys_ioprio_get", vf_linux_print_syscall_sys_ioprio_get },
	{ "sys_inotify_init", vf_linux_print_syscall_sys_inotify_init },
	{ "sys_inotify_add_watch", vf_linux_print_syscall_sys_inotify_add_watch },
	{ "sys_inotify_rm_watch", vf_linux_print_syscall_sys_inotify_rm_watch },
	{ "sys_migrate_pages", vf_linux_print_syscall_sys_migrate_pages },
	{ "sys_openat", vf_linux_print_syscall_sys_openat },
	{ "sys_mkdirat", vf_linux_print_syscall_sys_mkdirat },
	{ "sys_mknodat", vf_linux_print_syscall_sys_mknodat },
	{ "sys_fchownat", vf_linux_print_syscall_sys_fchownat },
	{ "sys_futimesat", vf_linux_print_syscall_sys_futimesat },
	{ "sys_newfstatat", vf_linux_print_syscall_sys_newfstatat },
	{ "sys_unlinkat", vf_linux_print_syscall_sys_unlinkat },
	{ "sys_renameat", vf_linux_print_syscall_sys_renameat },
	{ "sys_linkat", vf_linux_print_syscall_sys_linkat },
	{ "sys_symlinkat", vf_linux_print_syscall_sys_symlinkat },
	{ "sys_readlinkat", vf_linux_print_syscall_sys_readlinkat },
	{ "sys_fchmodat", vf_linux_print_syscall_sys_fchmodat },
	{ "sys_faccessat", vf_linux_print_syscall_sys_faccessat },
	{ "sys_pselect6", vf_linux_print_syscall_sys_pselect6 },
	{ "sys_ppoll", vf_linux_print_syscall_sys_ppoll },
	{ "sys_unshare", vf_linux_print_syscall_sys_unshare },
	{ "sys_set_robust_list", vf_linux_print_syscall_sys_set_robust_list },
	{ "sys_get_robust_list", vf_linux_print_syscall_sys_get_robust_list },
	{ "sys_splice", vf_linux_print_syscall_sys_splice },
	{ "sys_tee", vf_linux_print_syscall_sys_tee },
	{ "sys_sync_file_range", vf_linux_print_syscall_sys_sync_file_range },
	{ "sys_vmsplice", vf_linux_print_syscall_sys_vmsplice },
	{ "sys_move_pages", vf_linux_print_syscall_sys_move_pages },
	{ "sys_utimensat", vf_linux_print_syscall_sys_utimensat },
	{ "sys_epoll_pwait", vf_linux_print_syscall_sys_epoll_pwait },
	{ "sys_signalfd", vf_linux_print_syscall_sys_signalfd },
	{ "sys_timerfd", vf_linux_print_syscall_sys_timerfd },
	{ "sys_eventfd", vf_linux_print_syscall_sys_eventfd },
	{ "sys_fallocate", vf_linux_print_syscall_sys_fallocate },
	{ "sys_timerfd_settime", vf_linux_print_syscall_sys_timerfd_settime },
	{ "sys_timerfd_gettime", vf_linux_print_syscall_sys_timerfd_gettime },
	{ "sys_accept4", vf_linux_print_syscall_sys_accept4 },
	{ "sys_signalfd4", vf_linux_print_syscall_sys_signalfd4 },
	{ "sys_eventfd2", vf_linux_print_syscall_sys_eventfd2 },
	{ "sys_epoll_create1", vf_linux_print_syscall_sys_epoll_create1 },
	{ "sys_dup3", vf_linux_print_syscall_sys_dup3 },
	{ "sys_pipe2", vf_linux_print_syscall_sys_pipe2 },
	{ "sys_inotify_init1", vf_linux_print_syscall_sys_inotify_init1 },
	{ "sys_preadv", vf_linux_print_syscall_sys_preadv },
	{ "sys_pwritev", vf_linux_print_syscall_sys_pwritev },
	{ "sys_rt_tgsigqueueinfo", vf_linux_print_syscall_sys_rt_tgsigqueueinfo },
	{ "sys_perf_event_open", vf_linux_print_syscall_sys_perf_event_open },
	{ "sys_recvmmsg", vf_linux_print_syscall_sys_recvmmsg },
	{ "sys_fanotify_init", vf_linux_print_syscall_sys_fanotify_init },
	{ "sys_fanotify_mark", vf_linux_print_syscall_sys_fanotify_mark },
	{ "sys_prlimit64", vf_linux_print_syscall_sys_prlimit64 },
	{ "sys_name_to_handle_at", vf_linux_print_syscall_sys_name_to_handle_at },
	{ "sys_open_by_handle_at", vf_linux_print_syscall_sys_open_by_handle_at },
	{ "sys_clock_adjtime", vf_linux_print_syscall_sys_clock_adjtime },
	{ "sys_syncfs", vf_linux_print_syscall_sys_syncfs },
	{ "sys_sendmmsg", vf_linux_print_syscall_sys_sendmmsg },
	{ "sys_setns", vf_linux_print_syscall_sys_setns },
	{ "sys_getcpu", vf_linux_print_syscall_sys_getcpu },
	{ "sys_process_vm_readv", vf_linux_print_syscall_sys_process_vm_readv },
	{ "sys_process_vm_writev", vf_linux_print_syscall_sys_process_vm_writev },
	{ "sys_kcmp", vf_linux_print_syscall_sys_kcmp },
	{ "sys_finit_module", vf_linux_print_syscall_sys_finit_module },
	{ "sys_sched_setattr", vf_linux_print_syscall_sys_sched_setattr },
	{ "sys_sched_getattr", vf_linux_print_syscall_sys_sched_getattr },
	{ "sys_renameat2", vf_linux_print_syscall_sys_renameat2 },
	{ "sys_seccomp", vf_linux_print_syscall_sys_seccomp },
	{ "sys_getrandom", vf_linux_print_syscall_sys_getrandom },
	{ "sys_memfd_create", vf_linux_print_syscall_sys_memfd_create },
	{ "sys_kexec_file_load", vf_linux_print_syscall_sys_kexec_file_load },
	{ "sys_bpf", vf_linux_print_syscall_sys_bpf },
	{ "sys_execveat", vf_linux_print_syscall_sys_execveat },
	{ "sys_userfaultfd", vf_linux_print_syscall_sys_userfaultfd },
	{ "sys_membarrier", vf_linux_print_syscall_sys_membarrier },
	{ "sys_mlock2", vf_linux_print_syscall_sys_mlock2 },
	{ "sys_copy_file_range", vf_linux_print_syscall_sys_copy_file_range },
};

void vf_linux_print_syscall(vmi_instance_t vmi, vmi_event_t *event) {
	reg_t syscall_id = event->x86_regs->rax;
	vmi_pid_t pid = vmi_dtb_to_pid(vmi, event->x86_regs->cr3);
	char *proc = get_proc_name(vmi, pid);
	SYSCALLS[syscall_id].print(vmi, pid, proc, SYSCALLS[syscall_id].name, event);
}
void vf_linux_print_sysret(vmi_instance_t vmi, vmi_event_t *event) {
	reg_t syscall_return = event->x86_regs->rax;
	vmi_pid_t pid = vmi_dtb_to_pid(vmi, event->x86_regs->cr3);
	printf("pid: %u (%s) return: 0x%"PRIx64"\n", pid, get_proc_name(vmi, pid), syscall_return);
	}

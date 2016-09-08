/* Generated on Linux_4.6.7-300.fc24.x86_64 on 30 Aug 2016o 16:18:03 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include "syscall_enum.h"

char *get_proc_name(vmi_instance_t vmi, vmi_pid_t pid) {
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


void print_syscall_info(vmi_instance_t vmi, vmi_event_t *event) {
	/* 
 	 *  This function is used to translate the 
 	 *  raw values found in registers on a syscall to a readable string
 	 *  that is printed to stdout. It displays the PID, Process name,
 	 *  and the syscall name with all of its arguments formatted to 
 	 *  show as an integer, hex value or string if possible.
 	 */

	/* Every case will make use of the following values */
	char *name;							/* stores the syscall name */
	reg_t syscall_number = event->regs.x86->rax;			/* stores the syscall number from rax */
	vmi_pid_t pid = vmi_dtb_to_pid(vmi, event->regs.x86->cr3);	/* stores the PID of the process making a syscall */
	char *proc = get_proc_name(vmi, pid);				/* stores the process name */

	/* 
 	 *  The switch statement uses the syscall number and the syscalls enum to 
 	 *  match on the syscall and gather specific values for each different syscall
 	 *  and format them to print nicely.
 	 *
 	 *  The registers for syscall arguments from 1 to 6 are rdi, rsi, 
 	 *  rdx, r10, r8 and r9 respectively
 	 */
	switch (syscall_number) {

		case SYS_READ:
		{
			name = "sys_read";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			reg_t rsi = event->regs.x86->rsi;		/* char __user * buf */
			reg_t rdx = event->regs.x86->rdx;		/* size_t count */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_WRITE:
		{
			name = "sys_write";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * buf */
			reg_t rdx = event->regs.x86->rdx;		/* size_t count */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_OPEN:
		{
			name = "sys_open";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * filename */	
			reg_t rsi = event->regs.x86->rsi;		/* int flags */
			reg_t rdx = event->regs.x86->rdx;		/* umode_t mode */

			/* this is the first example of getting a string value from the register value. This format shows up many more times below */
			char *fname = vmi_read_str_va(vmi, rdi, pid);	/* get the actual filename by reading the string starting at the address in RDI in this instance */
			
			if (NULL == fname) {		/* if we read the filename and get NULL then we return the address of the filename */
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %i, %lu)\n",  pid, proc, name, (unsigned long)rdi, (int)rsi, (unsigned long)rdx);
			}
			else {				/* otherwise we print the string that vmi_read_str_va returned */
				printf("pid: %u ( %s ) syscall: %s(\"%s\", %i, %lu)\n",  pid, proc, name, fname, (int)rsi, (unsigned long)rdx);
				free(fname);	/* free the memory allocated using realloc in vmi_read_str_va */
			}				
			break;
		}

		case SYS_CLOSE:
		{
			name = "sys_close";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_STAT:
		{
			name = "sys_stat";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * filename */
			reg_t rsi = event->regs.x86->rsi;		/* struct __old_kernel_stat __user * statbuf */

			char *fname = vmi_read_str_va(vmi, rdi, pid);	/* get the actual filename */
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", 0x%"PRIx64")\n",  pid, proc, name, fname, (unsigned long)rsi);	
				free(fname);	/* free the memory allocated in vmi_read_str_va */
			}			
			break;
		}

		case SYS_FSTAT:
		{
			name = "sys_fstat";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			reg_t rsi = event->regs.x86->rsi;		/* struct __old_kernel_stat __user * statbuf */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_LSTAT:
		{
			name = "sys_lstat";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * filename */
			reg_t rsi = event->regs.x86->rsi;		/* struct __old_kernel_stat __user * statbuf */

			char *fname = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", 0x%"PRIx64")\n",  pid, proc, name, fname, (unsigned long)rsi);	
				free(fname);
			}
			break;
		}

		case SYS_POLL:
		{
			name = "sys_poll";
			reg_t rdi = event->regs.x86->rdi;		/* struct pollfd __user * ufds */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned int nfds */
			reg_t rdx = event->regs.x86->rdx;		/* int timeout */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu, %i)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_LSEEK:
		{
			name = "sys_lseek";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			reg_t rsi = event->regs.x86->rsi;		/* off_t offset */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned int whence */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_MMAP:
		{
			name = "sys_mmap";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long arg1 */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned long arg2 */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long arg3 */
			reg_t r10 = event->regs.x86->r10;		/* unsigned long arg4 */
			reg_t r8 = event->regs.x86->r8;		/* unsigned long arg5 */
			reg_t r9 = event->regs.x86->r9;		/* unsigned long arg6 */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu, %i, %i, %i, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (int)rdx, (int)r10, (int)r8, (unsigned long)r9);
			break;
		}

		case SYS_MPROTECT:
		{
			name = "sys_mprotect";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long start */
			reg_t rsi = event->regs.x86->rsi;		/* size_t len */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long prot */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_MUNMAP:
		{
			name = "sys_munmap";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long addr */
			reg_t rsi = event->regs.x86->rsi;		/* size_t len */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_BRK:
		{
			name = "sys_brk";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long brk */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_RT_SIGACTION:
		{
			name = "sys_rt_sigaction";
			reg_t rdi = event->regs.x86->rdi;		/*  int arg1 */
			reg_t rsi = event->regs.x86->rsi;		/* const struct sigaction __user * arg2 */
			reg_t rdx = event->regs.x86->rdx;		/* struct sigaction __user * arg3 */
			reg_t r10 = event->regs.x86->r10;		/*  size_t */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_RT_SIGPROCMASK:
		{
			name = "sys_rt_sigprocmask";
			reg_t rdi = event->regs.x86->rdi;		/* int how */
			reg_t rsi = event->regs.x86->rsi;		/* sigset_t __user * set */
			reg_t rdx = event->regs.x86->rdx;		/* sigset_t __user * oset */
			reg_t r10 = event->regs.x86->r10;		/* size_t sigsetsize */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_RT_SIGRETURN:
		{
			name = "sys_rt_sigreturn";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_IOCTL:
		{
			name = "sys_ioctl";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned int cmd */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long arg */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_PREAD:
		{
			name = "sys_pread";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			reg_t rsi = event->regs.x86->rsi;		/* char __user * buf */
			reg_t rdx = event->regs.x86->rdx;		/* size_t count */
			reg_t r10 = event->regs.x86->r10;		/* loff_t pos */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu, %li)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (long int)r10);
			break;
		}

		case SYS_PWRITE:
		{
			name = "sys_pwrite";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * buf */
			reg_t rdx = event->regs.x86->rdx;		/* size_t count */
			reg_t r10 = event->regs.x86->r10;		/* loff_t pos */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu, %li)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (long int)r10);
			break;
		}

		case SYS_READV:
		{
			name = "sys_readv";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long fd */
			reg_t rsi = event->regs.x86->rsi;		/* const struct iovec __user * vec */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long vlen */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_WRITEV:
		{
			name = "sys_writev";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long fd */
			reg_t rsi = event->regs.x86->rsi;		/* const struct iovec __user * vec */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long vlen */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_ACCESS:
		{
			name = "sys_access";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * filename */
			reg_t rsi = event->regs.x86->rsi;		/* int mode */

			char *fname = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %i)\n",  pid, proc, name, (unsigned long)rdi, (int)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", %i)\n",  pid, proc, name, fname, (int)rsi);	
				free(fname);
			}
			break;
		}

		case SYS_PIPE:
		{
			name = "sys_pipe";
			reg_t rdi = event->regs.x86->rdi;		/* int __user * fildes */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_SELECT:
		{
			name = "sys_select";
			reg_t rdi = event->regs.x86->rdi;		/* int n */
			reg_t rsi = event->regs.x86->rsi;		/* fd_set __user * inp */
			reg_t rdx = event->regs.x86->rdx;		/* fd_set __user * outp */
			reg_t r10 = event->regs.x86->r10;		/* fd_set __user * exp */
			reg_t r8 = event->regs.x86->r8;		/* struct timeval __user * tvp */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_SCHED_YIELD:
		{
			name = "sys_sched_yield";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_MREMAP:
		{
			name = "sys_mremap";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long addr */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned long old_len */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long new_len */
			reg_t r10 = event->regs.x86->r10;		/* unsigned long flags */
			reg_t r8 = event->regs.x86->r8;		/* unsigned long new_addr */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_MSYNC:
		{
			name = "sys_msync";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long start */
			reg_t rsi = event->regs.x86->rsi;		/* size_t len */
			reg_t rdx = event->regs.x86->rdx;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %i)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_MINCORE:
		{
			name = "sys_mincore";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long start */
			reg_t rsi = event->regs.x86->rsi;		/* size_t len */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned char __user * vec */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_MADVISE:
		{
			name = "sys_madvise";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long start */
			reg_t rsi = event->regs.x86->rsi;		/* size_t len */
			reg_t rdx = event->regs.x86->rdx;		/* int behavior */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %i)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_SHMGET:
		{
			name = "sys_shmget";
			reg_t rdi = event->regs.x86->rdi;		/* key_t key */
			reg_t rsi = event->regs.x86->rsi;		/* size_t size */
			reg_t rdx = event->regs.x86->rdx;		/* int flag */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_SHMAT:
		{
			name = "sys_shmat";
			reg_t rdi = event->regs.x86->rdi;		/* int shmid */
			reg_t rsi = event->regs.x86->rsi;		/* char __user * shmaddr */
			reg_t rdx = event->regs.x86->rdx;		/* int shmflg */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_SHMCTL:
		{
			name = "sys_shmctl";
			reg_t rdi = event->regs.x86->rdi;		/* int shmid */
			reg_t rsi = event->regs.x86->rsi;		/* int cmd */
			reg_t rdx = event->regs.x86->rdx;		/* struct shmid_ds __user * buf */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_DUP:
		{
			name = "sys_dup";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fildes */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_DUP2:
		{
			name = "sys_dup2";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int oldfd */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned int newfd */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_PAUSE:
		{
			name = "sys_pause";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_NANOSLEEP:
		{
			name = "sys_nanosleep";
			reg_t rdi = event->regs.x86->rdi;		/* struct timespec __user * rqtp */
			reg_t rsi = event->regs.x86->rsi;		/* struct timespec __user * rmtp */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_GETITIMER:
		{
			name = "sys_getitimer";
			reg_t rdi = event->regs.x86->rdi;		/* int which */
			reg_t rsi = event->regs.x86->rsi;		/* struct itimerval __user * value */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_ALARM:
		{
			name = "sys_alarm";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int seconds */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_SETITIMER:
		{
			name = "sys_setitimer";
			reg_t rdi = event->regs.x86->rdi;		/* int which */
			reg_t rsi = event->regs.x86->rsi;		/* struct itimerval __user * value */
			reg_t rdx = event->regs.x86->rdx;		/* struct itimerval __user * ovalue */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GETPID:
		{
			name = "sys_getpid";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_SENDFILE:
		{
			name = "sys_sendfile";
			reg_t rdi = event->regs.x86->rdi;		/* int out_fd */
			reg_t rsi = event->regs.x86->rsi;		/* int in_fd */
			reg_t rdx = event->regs.x86->rdx;		/* off_t __user * offset */
			reg_t r10 = event->regs.x86->r10;		/* size_t count */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_SOCKET:
		{
			name = "sys_socket";
			reg_t rdi = event->regs.x86->rdi;		/*  int arg1 */
			reg_t rsi = event->regs.x86->rsi;		/*  int arg2 */
			reg_t rdx = event->regs.x86->rdx;		/*  int arg3 */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx);
			break;
		}

		case SYS_CONNECT:
		{
			name = "sys_connect";
			reg_t rdi = event->regs.x86->rdi;		/*  int arg1 */
			reg_t rsi = event->regs.x86->rsi;		/* struct sockaddr __user * arg2 */
			reg_t rdx = event->regs.x86->rdx;		/*  int arg3 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_ACCEPT:
		{
			name = "sys_accept";
			reg_t rdi = event->regs.x86->rdi;		/*  int arg1 */
			reg_t rsi = event->regs.x86->rsi;		/* struct sockaddr __user * arg2 */
			reg_t rdx = event->regs.x86->rdx;		/* int __user * arg3 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SENDTO:
		{
			name = "sys_sendto";
			reg_t rdi = event->regs.x86->rdi;		/*  int arg1 */
			reg_t rsi = event->regs.x86->rsi;		/* void __user * arg2 */
			reg_t rdx = event->regs.x86->rdx;		/*  size_t */
			reg_t r10 = event->regs.x86->r10;		/*  unsigned */
			reg_t r8 = event->regs.x86->r8;		/* struct sockaddr __user * arg5 */
			reg_t r9 = event->regs.x86->r9;		/*  int arg6 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8, (int)r9);
			break;
		}

		case SYS_RECVFROM:
		{
			name = "sys_recvfrom";
			reg_t rdi = event->regs.x86->rdi;		/*  int arg1 */
			reg_t rsi = event->regs.x86->rsi;		/* void __user * arg2 */
			reg_t rdx = event->regs.x86->rdx;		/*  size_t */
			reg_t r10 = event->regs.x86->r10;		/*  unsigned */
			reg_t r8 = event->regs.x86->r8;		/* struct sockaddr __user * arg5 */
			reg_t r9 = event->regs.x86->r9;		/* int __user * arg6 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8, (unsigned long)r9);
			break;
		}

		case SYS_SENDMSG:
		{
			name = "sys_sendmsg";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* struct user_msghdr __user * msg */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_RECVMSG:
		{
			name = "sys_recvmsg";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* struct user_msghdr __user * msg */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SHUTDOWN:
		{
			name = "sys_shutdown";
			reg_t rdi = event->regs.x86->rdi;		/*  int arg1 */
			reg_t rsi = event->regs.x86->rsi;		/*  int arg2 */
			printf("pid: %u ( %s ) syscall: %s(%i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi);
			break;
		}

		case SYS_BIND:
		{
			name = "sys_bind";
			reg_t rdi = event->regs.x86->rdi;		/*  int arg1 */
			reg_t rsi = event->regs.x86->rsi;		/* struct sockaddr __user * arg2 */
			reg_t rdx = event->regs.x86->rdx;		/*  int arg3 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_LISTEN:
		{
			name = "sys_listen";
			reg_t rdi = event->regs.x86->rdi;		/*  int arg1 */
			reg_t rsi = event->regs.x86->rsi;		/*  int arg2 */
			printf("pid: %u ( %s ) syscall: %s(%i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi);
			break;
		}

		case SYS_GETSOCKNAME:
		{
			name = "sys_getsockname";
			reg_t rdi = event->regs.x86->rdi;		/*  int arg1 */
			reg_t rsi = event->regs.x86->rsi;		/* struct sockaddr __user * arg2 */
			reg_t rdx = event->regs.x86->rdx;		/* int __user * arg3 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GETPEERNAME:
		{
			name = "sys_getpeername";
			reg_t rdi = event->regs.x86->rdi;		/*  int arg1 */
			reg_t rsi = event->regs.x86->rsi;		/* struct sockaddr __user * arg2 */
			reg_t rdx = event->regs.x86->rdx;		/* int __user * arg3 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SOCKETPAIR:
		{
			name = "sys_socketpair";
			reg_t rdi = event->regs.x86->rdi;		/*  int arg1 */
			reg_t rsi = event->regs.x86->rsi;		/*  int arg2 */
			reg_t rdx = event->regs.x86->rdx;		/*  int arg3 */
			reg_t r10 = event->regs.x86->r10;		/* int __user * arg4 */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx, (unsigned long)r10);
			break;
		}

		case SYS_SETSOCKOPT:
		{
			name = "sys_setsockopt";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* int level */
			reg_t rdx = event->regs.x86->rdx;		/* int optname */
			reg_t r10 = event->regs.x86->r10;		/* char __user * optval */
			reg_t r8 = event->regs.x86->r8;		/* int optlen */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i, 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx, (unsigned long)r10, (int)r8);
			break;
		}

		case SYS_GETSOCKOPT:
		{
			name = "sys_getsockopt";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* int level */
			reg_t rdx = event->regs.x86->rdx;		/* int optname */
			reg_t r10 = event->regs.x86->r10;		/* char __user * optval */
			reg_t r8 = event->regs.x86->r8;		/* int __user * optlen */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_CLONE:
		{
			name = "sys_clone";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long flags */
			reg_t rsi = event->regs.x86->rsi;		/* void *child_stack */
			reg_t rdx = event->regs.x86->rdx;		/* void *ptid */
			reg_t r10 = event->regs.x86->r10;		/* void *ctid */
			reg_t r8 = event->regs.x86->r8;		/* struct pt_retgs *regs */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_FORK:
		{
			name = "sys_fork";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_VFORK:
		{
			name = "sys_vfork";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_EXECVE:
		{
			name = "sys_execve";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * filename */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user *const __user * argv */
			reg_t rdx = event->regs.x86->rdx;		/* const char __user *const __user * envp */
			
			char *fname = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, fname, (unsigned long)rsi, (unsigned long)rdx);
				free(fname);
			}
			break;
		}

		case SYS_EXIT:
		{
			name = "sys_exit";
			reg_t rdi = event->regs.x86->rdi;		/* int error_code */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_WAIT4:
		{
			name = "sys_wait4";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid */
			reg_t rsi = event->regs.x86->rsi;		/* int __user * stat_addr */
			reg_t rdx = event->regs.x86->rdx;		/* int options */
			reg_t r10 = event->regs.x86->r10;		/* struct rusage __user * ru */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx, (unsigned long)r10);
			break;
		}

		case SYS_KILL:
		{
			name = "sys_kill";
			reg_t rdi = event->regs.x86->rdi;		/* int pid */
			reg_t rsi = event->regs.x86->rsi;		/* int sig */
			printf("pid: %u ( %s ) syscall: %s(%i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi);
			break;
		}

		case SYS_UNAME:
		{
			name = "sys_uname";
			reg_t rdi = event->regs.x86->rdi;		/* struct old_utsname __user * arg1 */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_SEMGET:
		{
			name = "sys_semget";
			reg_t rdi = event->regs.x86->rdi;		/* key_t key */
			reg_t rsi = event->regs.x86->rsi;		/* int nsems */
			reg_t rdx = event->regs.x86->rdx;		/* int semflg */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx);
			break;
		}

		case SYS_SEMOP:
		{
			name = "sys_semop";
			reg_t rdi = event->regs.x86->rdi;		/* int semid */
			reg_t rsi = event->regs.x86->rsi;		/* struct sembuf __user * sops */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned nsops */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SEMCTL:
		{
			name = "sys_semctl";
			reg_t rdi = event->regs.x86->rdi;		/* int semid */
			reg_t rsi = event->regs.x86->rsi;		/* int semnum */
			reg_t rdx = event->regs.x86->rdx;		/* int cmd */
			reg_t r10 = event->regs.x86->r10;		/* unsigned long arg */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i, %lu)\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx, (unsigned long)r10);
			break;
		}

		case SYS_SHMDT:
		{
			name = "sys_shmdt";
			reg_t rdi = event->regs.x86->rdi;		/* char __user * shmaddr */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_MSGGET:
		{
			name = "sys_msgget";
			reg_t rdi = event->regs.x86->rdi;		/* key_t key */
			reg_t rsi = event->regs.x86->rsi;		/* int msgflg */
			printf("pid: %u ( %s ) syscall: %s(%i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi);
			break;
		}

		case SYS_MSGSND:
		{
			name = "sys_msgsnd";
			reg_t rdi = event->regs.x86->rdi;		/* int msqid */
			reg_t rsi = event->regs.x86->rsi;		/* struct msgbuf __user * msgp */
			reg_t rdx = event->regs.x86->rdx;		/* size_t msgsz */
			reg_t r10 = event->regs.x86->r10;		/* int msgflg */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (int)r10);
			break;
		}

		case SYS_MSGRCV:
		{
			name = "sys_msgrcv";
			reg_t rdi = event->regs.x86->rdi;		/* int msqid */
			reg_t rsi = event->regs.x86->rsi;		/* struct msgbuf __user * msgp */
			reg_t rdx = event->regs.x86->rdx;		/* size_t msgsz */
			reg_t r10 = event->regs.x86->r10;		/* long msgtyp */
			reg_t r8 = event->regs.x86->r8;		/* int msgflg */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, %li, %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (long int)r10, (int)r8);
			break;
		}

		case SYS_MSGCTL:
		{
			name = "sys_msgctl";
			reg_t rdi = event->regs.x86->rdi;		/* int msqid */
			reg_t rsi = event->regs.x86->rsi;		/* int cmd */
			reg_t rdx = event->regs.x86->rdx;		/* struct msqid_ds __user * buf */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_FCNTL:
		{
			name = "sys_fcntl";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned int cmd */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long arg */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_FLOCK:
		{
			name = "sys_flock";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned int cmd */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_FSYNC:
		{
			name = "sys_fsync";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_FDATASYNC:
		{
			name = "sys_fdatasync";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_TRUNCATE:
		{
			name = "sys_truncate";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * path */
			reg_t rsi = event->regs.x86->rsi;		/* long length */

			char *path = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == path) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %li)\n",  pid, proc, name, (unsigned long)rdi, (long int)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", %li)\n",  pid, proc, name, path, (long int)rsi);	
				free(path);
			}
			break;
		}

		case SYS_FTRUNCATE:
		{
			name = "sys_ftruncate";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned long length */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_GETDENTS:
		{
			name = "sys_getdents";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			reg_t rsi = event->regs.x86->rsi;		/* struct linux_dirent __user * dirent */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned int count */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GETCWD:
		{
			name = "sys_getcwd";
			reg_t rdi = event->regs.x86->rdi;		/* char __user * buf */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned long size */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_CHDIR:
		{
			name = "sys_chdir";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * filename */

			char *path = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == path) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\")\n",  pid, proc, name, path);
				free(path);
			}
			break;
		}

		case SYS_FCHDIR:
		{
			name = "sys_fchdir";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_RENAME:
		{
			name = "sys_rename";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * oldname */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * newname */

			char * oldname = vmi_read_str_va(vmi, rdi, pid);
			char * newname = vmi_read_str_va(vmi, rsi, pid);

			if (NULL == oldname || NULL == newname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", \"%s\")\n",  pid, proc, name, oldname, newname);
				free(oldname);
				free(newname);
			}
			break;
		}

		case SYS_MKDIR:
		{
			name = "sys_mkdir";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * pathname */
			reg_t rsi = event->regs.x86->rsi;		/* umode_t mode */
			
			char *path = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == path) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", %lu)\n",  pid, proc, name, path, (unsigned long)rsi);
				free(path);
			}
			break;
		}

		case SYS_RMDIR:
		{
			name = "sys_rmdir";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * pathname */

			char *path = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == path) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\")\n",  pid, proc, name, path);
				free(path);
			}
			break;
		}

		case SYS_CREAT:
		{
			name = "sys_creat";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * pathname */
			reg_t rsi = event->regs.x86->rsi;		/* umode_t mode */

			char *path = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == path) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", %lu)\n",  pid, proc, name, path, (unsigned long)rsi);	
				free(path);
			}
			break;
		}

		case SYS_LINK:
		{
			name = "sys_link";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * oldname */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * newname */
			
			char *oldname = vmi_read_str_va(vmi, rdi, pid);
			char *newname = vmi_read_str_va(vmi, rsi, pid);

			if (NULL == oldname || NULL == newname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", \"%s\")\n",  pid, proc, name, oldname, newname);
				free(oldname);
				free(newname);
			}
			break;
		}

		case SYS_UNLINK:
		{
			name = "sys_unlink";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * pathname */
			
			char *path = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == path) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\")\n",  pid, proc, name, path);
				free(path);
			}
			break;
		}

		case SYS_SYMLINK:
		{
			name = "sys_symlink";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * old */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * new */
			
			char *oldname = vmi_read_str_va(vmi, rdi, pid);
			char *newname = vmi_read_str_va(vmi, rsi, pid);

			if (NULL == oldname || NULL == newname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", \"%s\")\n",  pid, proc, name, oldname, newname);
				free(oldname);
				free(newname);
			}
			break;
		}

		case SYS_READLINK:
		{
			name = "sys_readlink";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * path */
			reg_t rsi = event->regs.x86->rsi;		/* char __user * buf */
			reg_t rdx = event->regs.x86->rdx;		/* int bufsiz */

			char *path = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == path) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %i)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (int)rdx);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", 0x%"PRIx64", %i)\n",  pid, proc, name, path, (unsigned long)rsi, (int)rdx);
				free(path);
			}
			break;
		}

		case SYS_CHMOD:
		{
			name = "sys_chmod";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * filename */
			reg_t rsi = event->regs.x86->rsi;		/* umode_t mode */

			char *fname = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", %lu)\n",  pid, proc, name, fname, (unsigned long)rsi);
				free(fname);
			}
			break;
		}

		case SYS_FCHMOD:
		{
			name = "sys_fchmod";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			reg_t rsi = event->regs.x86->rsi;		/* umode_t mode */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_CHOWN:
		{
			name = "sys_chown";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * filename */
			reg_t rsi = event->regs.x86->rsi;		/* uid_t user */
			reg_t rdx = event->regs.x86->rdx;		/* gid_t group */

			char *fname = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			}	
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", %lu, %lu)\n",  pid, proc, name, fname, (unsigned long)rsi, (unsigned long)rdx);
				free(fname);
			}
			break;
		}

		case SYS_FCHOWN:
		{
			name = "sys_fchown";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			reg_t rsi = event->regs.x86->rsi;		/* uid_t user */
			reg_t rdx = event->regs.x86->rdx;		/* gid_t group */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_LCHOWN:
		{
			name = "sys_lchown";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * filename */
			reg_t rsi = event->regs.x86->rsi;		/* uid_t user */
			reg_t rdx = event->regs.x86->rdx;		/* gid_t group */
			
			char *fname = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			}	
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", %lu, %lu)\n",  pid, proc, name, fname, (unsigned long)rsi, (unsigned long)rdx);
				free(fname);
			}
			break;
		}

		case SYS_UMASK:
		{
			name = "sys_umask";
			reg_t rdi = event->regs.x86->rdi;		/* int mask */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_GETTIMEOFDAY:
		{
			name = "sys_gettimeofday";
			reg_t rdi = event->regs.x86->rdi;		/* struct timeval __user * tv */
			reg_t rsi = event->regs.x86->rsi;		/* struct timezone __user * tz */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_GETRLIMIT:
		{
			name = "sys_getrlimit";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int resource */
			reg_t rsi = event->regs.x86->rsi;		/* struct rlimit __user * rlim */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_GETRUSAGE:
		{
			name = "sys_getrusage";
			reg_t rdi = event->regs.x86->rdi;		/* int who */
			reg_t rsi = event->regs.x86->rsi;		/* struct rusage __user * ru */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_SYSINFO:
		{
			name = "sys_sysinfo";
			reg_t rdi = event->regs.x86->rdi;		/* struct sysinfo __user * info */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_TIMES:
		{
			name = "sys_times";
			reg_t rdi = event->regs.x86->rdi;		/* struct tms __user * tbuf */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_PTRACE:
		{
			name = "sys_ptrace";
			reg_t rdi = event->regs.x86->rdi;		/* long request */
			reg_t rsi = event->regs.x86->rsi;		/* long pid */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long addr */
			reg_t r10 = event->regs.x86->r10;		/* unsigned long data */
			printf("pid: %u ( %s ) syscall: %s(%li, %li, %lu, %lu)\n",  pid, proc, name, (long int)rdi, (long int)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_GETUID:
		{
			name = "sys_getuid";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_SYSLOG:
		{
			name = "sys_syslog";
			reg_t rdi = event->regs.x86->rdi;		/* int type */
			reg_t rsi = event->regs.x86->rsi;		/* char __user * buf */
			reg_t rdx = event->regs.x86->rdx;		/* int len */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_GETGID:
		{
			name = "sys_getgid";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_SETUID:
		{
			name = "sys_setuid";
			reg_t rdi = event->regs.x86->rdi;		/* uid_t uid */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_SETGID:
		{
			name = "sys_setgid";
			reg_t rdi = event->regs.x86->rdi;		/* gid_t gid */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_GETEUID:
		{
			name = "sys_geteuid";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_GETEGID:
		{
			name = "sys_getegid";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_SETPGID:
		{
			name = "sys_setpgid";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid */
			reg_t rsi = event->regs.x86->rsi;		/* pid_t pgid */
			printf("pid: %u ( %s ) syscall: %s(%i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi);
			break;
		}

		case SYS_GETPPID:
		{
			name = "sys_getppid";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_GETPGRP:
		{
			name = "sys_getpgrp";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_SETSID:
		{
			name = "sys_setsid";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_SETREUID:
		{
			name = "sys_setreuid";
			reg_t rdi = event->regs.x86->rdi;		/* uid_t ruid */
			reg_t rsi = event->regs.x86->rsi;		/* uid_t euid */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_SETREGID:
		{
			name = "sys_setregid";
			reg_t rdi = event->regs.x86->rdi;		/* gid_t rgid */
			reg_t rsi = event->regs.x86->rsi;		/* gid_t egid */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_GETGROUPS:
		{
			name = "sys_getgroups";
			reg_t rdi = event->regs.x86->rdi;		/* int gidsetsize */
			reg_t rsi = event->regs.x86->rsi;		/* gid_t __user * grouplist */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_SETGROUPS:
		{
			name = "sys_setgroups";
			reg_t rdi = event->regs.x86->rdi;		/* int gidsetsize */
			reg_t rsi = event->regs.x86->rsi;		/* gid_t __user * grouplist */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_SETRESUID:
		{
			name = "sys_setresuid";
			reg_t rdi = event->regs.x86->rdi;		/* uid_t ruid */
			reg_t rsi = event->regs.x86->rsi;		/* uid_t euid */
			reg_t rdx = event->regs.x86->rdx;		/* uid_t suid */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GETRESUID:
		{
			name = "sys_getresuid";
			reg_t rdi = event->regs.x86->rdi;		/* uid_t __user * ruid */
			reg_t rsi = event->regs.x86->rsi;		/* uid_t __user * euid */
			reg_t rdx = event->regs.x86->rdx;		/* uid_t __user * suid */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SETRESGID:
		{
			name = "sys_setresgid";
			reg_t rdi = event->regs.x86->rdi;		/* gid_t rgid */
			reg_t rsi = event->regs.x86->rsi;		/* gid_t egid */
			reg_t rdx = event->regs.x86->rdx;		/* gid_t sgid */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GETRESGID:
		{
			name = "sys_getresgid";
			reg_t rdi = event->regs.x86->rdi;		/* gid_t __user * rgid */
			reg_t rsi = event->regs.x86->rsi;		/* gid_t __user * egid */
			reg_t rdx = event->regs.x86->rdx;		/* gid_t __user * sgid */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GETPGID:
		{
			name = "sys_getpgid";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_SETFSUID:
		{
			name = "sys_setfsuid";
			reg_t rdi = event->regs.x86->rdi;		/* uid_t uid */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_SETFSGID:
		{
			name = "sys_setfsgid";
			reg_t rdi = event->regs.x86->rdi;		/* gid_t gid */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_GETSID:
		{
			name = "sys_getsid";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_CAPGET:
		{
			name = "sys_capget";
			reg_t rdi = event->regs.x86->rdi;		/* cap_user_header_t header */
			reg_t rsi = event->regs.x86->rsi;		/* cap_user_data_t dataptr */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_CAPSET:
		{
			name = "sys_capset";
			reg_t rdi = event->regs.x86->rdi;		/* cap_user_header_t header */
			reg_t rsi = event->regs.x86->rsi;		/* const cap_user_data_t data */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_RT_SIGPENDING:
		{
			name = "sys_rt_sigpending";
			reg_t rdi = event->regs.x86->rdi;		/* sigset_t __user * set */
			reg_t rsi = event->regs.x86->rsi;		/* size_t sigsetsize */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_RT_SIGTIMEDWAIT:
		{
			name = "sys_rt_sigtimedwait";
			reg_t rdi = event->regs.x86->rdi;		/* const sigset_t __user * uthese */
			reg_t rsi = event->regs.x86->rsi;		/* siginfo_t __user * uinfo */
			reg_t rdx = event->regs.x86->rdx;		/* const struct timespec __user * uts */
			reg_t r10 = event->regs.x86->r10;		/* size_t sigsetsize */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_RT_SIGQUEUEINFO:
		{
			name = "sys_rt_sigqueueinfo";
			reg_t rdi = event->regs.x86->rdi;		/* int pid */
			reg_t rsi = event->regs.x86->rsi;		/* int sig */
			reg_t rdx = event->regs.x86->rdx;		/* siginfo_t __user * uinfo */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_RT_SIGSUSPEND:
		{
			name = "sys_rt_sigsuspend";
			reg_t rdi = event->regs.x86->rdi;		/* sigset_t __user * unewset */
			reg_t rsi = event->regs.x86->rsi;		/* size_t sigsetsize */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_SIGALTSTACK:
		{
			name = "sys_sigaltstack";
			reg_t rdi = event->regs.x86->rdi;		/* const struct sigaltstack __user * uss */
			reg_t rsi = event->regs.x86->rsi;		/* struct sigaltstack __user * uoss */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_UTIME:
		{
			name = "sys_utime";
			reg_t rdi = event->regs.x86->rdi;		/* char __user * filename */
			reg_t rsi = event->regs.x86->rsi;		/* struct utimbuf __user * times */
			
			char *fname = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", 0x%"PRIx64")\n",  pid, proc, name, fname, (unsigned long)rsi);
				free(fname);
			}
			break;
		}

		case SYS_MKNOD:
		{
			name = "sys_mknod";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * filename */
			reg_t rsi = event->regs.x86->rsi;		/* umode_t mode */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned dev */

			char *fname = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", %lu, %lu)\n",  pid, proc, name, fname, (unsigned long)rsi, (unsigned long)rdx);	
				free(fname);
			}
			break;
		}

		case SYS_USELIB:
		{
			name = "sys_uselib";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * library */
			
			char *lib = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == lib) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\")\n",  pid, proc, name, lib);
				free(lib);
			}
			break;
		}

		case SYS_PERSONALITY:
		{
			name = "sys_personality";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int personality */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_USTAT:
		{
			name = "sys_ustat";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned dev */
			reg_t rsi = event->regs.x86->rsi;		/* struct ustat __user * ubuf */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_STATFS:
		{
			name = "sys_statfs";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * path */
			reg_t rsi = event->regs.x86->rsi;		/* struct statfs __user * buf */
			
			char *path = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == path) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", 0x%"PRIx64")\n",  pid, proc, name, path, (unsigned long)rsi);
				free(path);
			}
			break;
		}

		case SYS_FSTATFS:
		{
			name = "sys_fstatfs";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			reg_t rsi = event->regs.x86->rsi;		/* struct statfs __user * buf */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_SYSFS:
		{
			name = "sys_sysfs";
			reg_t rdi = event->regs.x86->rdi;		/* int option */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned long arg1 */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long arg2 */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GETPRIORITY:
		{
			name = "sys_getpriority";
			reg_t rdi = event->regs.x86->rdi;		/* int which */
			reg_t rsi = event->regs.x86->rsi;		/* int who */
			printf("pid: %u ( %s ) syscall: %s(%i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi);
			break;
		}

		case SYS_SETPRIORITY:
		{
			name = "sys_setpriority";
			reg_t rdi = event->regs.x86->rdi;		/* int which */
			reg_t rsi = event->regs.x86->rsi;		/* int who */
			reg_t rdx = event->regs.x86->rdx;		/* int niceval */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx);
			break;
		}

		case SYS_SCHED_SETPARAM:
		{
			name = "sys_sched_setparam";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid */
			reg_t rsi = event->regs.x86->rsi;		/* struct sched_param __user * param */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_SCHED_GETPARAM:
		{
			name = "sys_sched_getparam";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid */
			reg_t rsi = event->regs.x86->rsi;		/* struct sched_param __user * param */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_SCHED_SETSCHEDULER:
		{
			name = "sys_sched_setscheduler";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid */
			reg_t rsi = event->regs.x86->rsi;		/* int policy */
			reg_t rdx = event->regs.x86->rdx;		/* struct sched_param __user * param */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SCHED_GETSCHEDULER:
		{
			name = "sys_sched_getscheduler";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_SCHED_GET_PRIORITY_MAX:
		{
			name = "sys_sched_get_priority_max";
			reg_t rdi = event->regs.x86->rdi;		/* int policy */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_SCHED_GET_PRIORITY_MIN:
		{
			name = "sys_sched_get_priority_min";
			reg_t rdi = event->regs.x86->rdi;		/* int policy */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_SCHED_RR_GET_INTERVAL:
		{
			name = "sys_sched_rr_get_interval";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid */
			reg_t rsi = event->regs.x86->rsi;		/* struct timespec __user * interval */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_MLOCK:
		{
			name = "sys_mlock";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long start */
			reg_t rsi = event->regs.x86->rsi;		/* size_t len */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_MUNLOCK:
		{
			name = "sys_munlock";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long start */
			reg_t rsi = event->regs.x86->rsi;		/* size_t len */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_MLOCKALL:
		{
			name = "sys_mlockall";
			reg_t rdi = event->regs.x86->rdi;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_MUNLOCKALL:
		{
			name = "sys_munlockall";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_VHANGUP:
		{
			name = "sys_vhangup";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_MODIFY_LDT:
		{
			name = "sys_modify_ldt";
			reg_t rdi = event->regs.x86->rdi;		/*  int arg1 */
			reg_t rsi = event->regs.x86->rsi;		/* void __user * arg2 */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long arg3 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_PIVOT_ROOT:
		{
			name = "sys_pivot_root";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * new_root */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * put_old */

			char *new = vmi_read_str_va(vmi, rdi, pid);
			char *old = vmi_read_str_va(vmi, rsi, pid);

			if (NULL == new || NULL == old) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			}
			else {	
				printf("pid: %u ( %s ) syscall: %s(\"%s\", \"%s\")\n",  pid, proc, name, new, old);
				free(new);
				free(old);
			}
			break;
		}

		case SYS_SYSCTL:
		{
			name = "sys_sysctl";
			reg_t rdi = event->regs.x86->rdi;		/* struct __sysctl_args __user * args */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_PRCTL:
		{
			name = "sys_prctl";
			reg_t rdi = event->regs.x86->rdi;		/* int option */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned long arg2 */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long arg3 */
			reg_t r10 = event->regs.x86->r10;		/* unsigned long arg4 */
			reg_t r8 = event->regs.x86->r8;		/* unsigned long arg5 */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, %lu, %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_ARCH_PRCTL:
		{
			name = "sys_arch_prctl";
			reg_t rdi = event->regs.x86->rdi;		/*  int arg1 */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned long arg2 */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_ADJTIMEX:
		{
			name = "sys_adjtimex";
			reg_t rdi = event->regs.x86->rdi;		/* struct timex __user * txc_p */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_SETRLIMIT:
		{
			name = "sys_setrlimit";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int resource */
			reg_t rsi = event->regs.x86->rsi;		/* struct rlimit __user * rlim */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_CHROOT:
		{
			name = "sys_chroot";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * filename */

			char *fname = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\")\n",  pid, proc, name, fname);
				free(fname);
			}
			break;
		}

		case SYS_SYNC:
		{
			name = "sys_sync";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_ACCT:
		{
			name = "sys_acct";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * name */

			char *fname = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\")\n",  pid, proc, name, fname);
				free(fname);
			}
			break;
		}

		case SYS_SETTIMEOFDAY:
		{
			name = "sys_settimeofday";
			reg_t rdi = event->regs.x86->rdi;		/* struct timeval __user * tv */
			reg_t rsi = event->regs.x86->rsi;		/* struct timezone __user * tz */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_MOUNT:
		{
			name = "sys_mount";
			reg_t rdi = event->regs.x86->rdi;		/* char __user * dev_name */
			reg_t rsi = event->regs.x86->rsi;		/* char __user * dir_name */
			reg_t rdx = event->regs.x86->rdx;		/* char __user * type */
			reg_t r10 = event->regs.x86->r10;		/* unsigned long flags */
			reg_t r8 = event->regs.x86->r8;		/* void __user * data */

			char *dev = vmi_read_str_va(vmi, rdi, pid);
			char *dir = vmi_read_str_va(vmi, rsi, pid);
			char *type = vmi_read_str_va(vmi, rdx, pid);

			if (NULL == dev || NULL == dir || NULL == type) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", \"%s\", %s, %lu, 0x%"PRIx64")\n",  pid, proc, name, dev, dir, type, (unsigned long)r10, (unsigned long)r8);
				free(dev);
				free(dir);
				free(type);
			}
			break;
		}

		case SYS_UMOUNT2:
		{
			name = "sys_umount2";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_SWAPON:
		{
			name = "sys_swapon";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * specialfile */
			reg_t rsi = event->regs.x86->rsi;		/* int swap_flags */

			char *path = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == path) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %i)\n",  pid, proc, name, (unsigned long)rdi, (int)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", %i)\n",  pid, proc, name, path, (int)rsi);
				free(path);
			}
			break;
		}

		case SYS_SWAPOFF:
		{
			name = "sys_swapoff";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * specialfile */
			
			char *path = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == path) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\")\n",  pid, proc, name, path);
				free(path);
			}
			break;
		}

		case SYS_REBOOT:
		{
			name = "sys_reboot";
			reg_t rdi = event->regs.x86->rdi;		/* int magic1 */
			reg_t rsi = event->regs.x86->rsi;		/* int magic2 */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned int cmd */
			reg_t r10 = event->regs.x86->r10;		/* void __user * arg */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %lu, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_SETHOSTNAME:
		{
			name = "sys_sethostname";
			reg_t rdi = event->regs.x86->rdi;		/* char __user * name */
			reg_t rsi = event->regs.x86->rsi;		/* int len */

			char *newname = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == name) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %i)\n",  pid, proc, name, (unsigned long)rdi, (int)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", %i)\n",  pid, proc, name, newname, (int)rsi);
				free(newname);
			}
			break;
		}

		case SYS_SETDOMAINNAME:
		{
			name = "sys_setdomainname";
			reg_t rdi = event->regs.x86->rdi;		/* char __user * name */
			reg_t rsi = event->regs.x86->rsi;		/* int len */

			char *newname = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == newname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %i)\n",  pid, proc, name, (unsigned long)rdi, (int)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", %i)\n",  pid, proc, name, newname, (int)rsi);
				free(newname);
			}
			break;
		}

		case SYS_IOPL:
		{
			name = "sys_iopl";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int arg1 */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_IOPERM:
		{
			name = "sys_ioperm";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long from */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned long num */
			reg_t rdx = event->regs.x86->rdx;		/* int on */
			reg_t r10 = event->regs.x86->r10;		/* unsigned long arg4 */
			reg_t r8 = event->regs.x86->r8;		/* unsigned long arg5 */
			reg_t r9 = event->regs.x86->r9;		/*  int arg6 */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %i, %lu, %lu, %i)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (int)rdx, (unsigned long)r10, (unsigned long)r8, (int)r9);
			break;
		}

		case SYS_CREATE_MODULE:
		{
			name = "sys_create_module";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_INIT_MODULE:
		{
			name = "sys_init_module";
			reg_t rdi = event->regs.x86->rdi;		/* void __user * umod */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned long len */
			reg_t rdx = event->regs.x86->rdx;		/* const char __user * uargs */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_DELETE_MODULE:
		{
			name = "sys_delete_module";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * name_user */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned int flags */
			
			char *path = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == path) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %u\n",  pid, proc, name, (unsigned long)rdi, (unsigned int)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", %u)\n",  pid, proc, name, path, (unsigned int)rsi);
				free(path);
			}
			break;
		}

		case SYS_GET_KERNEL_SYMS:
		{
			name = "sys_get_kernel_syms";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_QUERY_MODULE:
		{
			name = "sys_query_module";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_QUOTACTL:
		{
			name = "sys_quotactl";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int cmd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * special */
			reg_t rdx = event->regs.x86->rdx;		/* qid_t id */
			reg_t r10 = event->regs.x86->r10;		/* void __user * addr */

			char *special = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == special) {
				printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%lu, \"%s\", %lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, special, (unsigned long)rdx, (unsigned long)r10);
				free(special);
			}
			break;
		}

		case SYS_NFSSERVCTL:
		{
			name = "sys_nfsservctl";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_GETPMSG:
		{
			name = "sys_getpmsg";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_PUTPMSG:
		{
			name = "sys_putpmsg";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_AFS_SYSCALL:
		{
			name = "sys_afs_syscall";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_TUXCALL:
		{
			name = "sys_tuxcall";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_SECURITY:
		{
			name = "sys_security";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_GETTID:
		{
			name = "sys_gettid";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_READAHEAD:
		{
			name = "sys_readahead";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* loff_t offset */
			reg_t rdx = event->regs.x86->rdx;		/* size_t count */
			printf("pid: %u ( %s ) syscall: %s(%i, %li, %lu)\n",  pid, proc, name, (int)rdi, (long int)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SETXATTR:
		{
			name = "sys_setxattr";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * path */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * name */
			reg_t rdx = event->regs.x86->rdx;		/* const void __user * value */
			reg_t r10 = event->regs.x86->r10;		/* size_t size */
			reg_t r8 = event->regs.x86->r8;		/* int flags */

			char *path = vmi_read_str_va(vmi, rdi, pid);
			char *xattrname = vmi_read_str_va(vmi, rsi, pid);

			if (NULL == path || NULL == xattrname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (int)r8);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", \"%s\", 0x%"PRIx64", %lu, %i)\n",  pid, proc, name, path, xattrname, (unsigned long)rdx, (unsigned long)r10, (int)r8);
				free(path);
				free(xattrname);
			}
			break;
		}

		case SYS_LSETXATTR:
		{
			name = "sys_lsetxattr";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * path */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * name */
			reg_t rdx = event->regs.x86->rdx;		/* const void __user * value */
			reg_t r10 = event->regs.x86->r10;		/* size_t size */
			reg_t r8 = event->regs.x86->r8;		/* int flags */
			
			char *path = vmi_read_str_va(vmi, rdi, pid);
			char *xattrname = vmi_read_str_va(vmi, rsi, pid);

			if (NULL == path || NULL == xattrname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (int)r8);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", \"%s\", 0x%"PRIx64", %lu, %i)\n",  pid, proc, name, path, xattrname, (unsigned long)rdx, (unsigned long)r10, (int)r8);
				free(path);
				free(xattrname);
			}
			break;
		}

		case SYS_FSETXATTR:
		{
			name = "sys_fsetxattr";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * name */
			reg_t rdx = event->regs.x86->rdx;		/* const void __user * value */
			reg_t r10 = event->regs.x86->r10;		/* size_t size */
			reg_t r8 = event->regs.x86->r8;		/* int flags */


			char *xattrname = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == xattrname) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (int)r8);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", 0x%"PRIx64", %lu, %i)\n",  pid, proc, name, (int)rdi, xattrname, (unsigned long)rdx, (unsigned long)r10, (int)r8);	
				free(xattrname);
			}
			break;
		}

		case SYS_GETXATTR:
		{
			name = "sys_getxattr";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * path */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * name */
			reg_t rdx = event->regs.x86->rdx;		/* void __user * value */
			reg_t r10 = event->regs.x86->r10;		/* size_t size */

			char *path = vmi_read_str_va(vmi, rdi, pid);
			char * xattrname = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == path || NULL == xattrname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", \"%s\", 0x%"PRIx64", %lu)\n",  pid, proc, name, path, xattrname, (unsigned long)rdx, (unsigned long)r10);	
				free(path);
				free(xattrname);
			}
			break;
		}

		case SYS_LGETXATTR:
		{
			name = "sys_lgetxattr";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * path */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * name */
			reg_t rdx = event->regs.x86->rdx;		/* void __user * value */
			reg_t r10 = event->regs.x86->r10;		/* size_t size */
			
			char *path = vmi_read_str_va(vmi, rdi, pid);
			char * xattrname = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == path || NULL == xattrname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", \"%s\", 0x%"PRIx64", %lu)\n",  pid, proc, name, path, xattrname, (unsigned long)rdx, (unsigned long)r10);	
				free(path);
				free(xattrname);
			}			
			break;
		}

		case SYS_FGETXATTR:
		{
			name = "sys_fgetxattr";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * name */
			reg_t rdx = event->regs.x86->rdx;		/* void __user * value */
			reg_t r10 = event->regs.x86->r10;		/* size_t size */
		
			char *xattrname = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == xattrname) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, xattrname, (unsigned long)rdx, (unsigned long)r10);
				free(xattrname);
			}
			break;
		}

		case SYS_LISTXATTR:
		{
			name = "sys_listxattr";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * path */
			reg_t rsi = event->regs.x86->rsi;		/* char __user * list */
			reg_t rdx = event->regs.x86->rdx;		/* size_t size */

			char *path = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == path) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", 0x%"PRIx64", %lu)\n",  pid, proc, name, path, (unsigned long)rsi, (unsigned long)rdx);
				free(path);
			}
			break;
		}

		case SYS_LLISTXATTR:
		{
			name = "sys_llistxattr";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * path */
			reg_t rsi = event->regs.x86->rsi;		/* char __user * list */
			reg_t rdx = event->regs.x86->rdx;		/* size_t size */
			
			char *path = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == path) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", 0x%"PRIx64", %lu)\n",  pid, proc, name, path, (unsigned long)rsi, (unsigned long)rdx);
				free(path);
			}
			break;
		}

		case SYS_FLISTXATTR:
		{
			name = "sys_flistxattr";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* char __user * list */
			reg_t rdx = event->regs.x86->rdx;		/* size_t size */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_REMOVEXATTR:
		{
			name = "sys_removexattr";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * path */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * name */

			char *path = vmi_read_str_va(vmi, rdi, pid);
			char *xattrname = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == path || NULL == xattrname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", \"%s\")\n",  pid, proc, name, path, xattrname);
				free(path);
				free(xattrname);
			}
			break;
		}

		case SYS_LREMOVEXATTR:
		{
			name = "sys_lremovexattr";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * path */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * name */

			char *path = vmi_read_str_va(vmi, rdi, pid);
			char *xattrname = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == path || NULL == xattrname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", \"%s\")\n",  pid, proc, name, path, xattrname);
				free(path);
				free(xattrname);
			}
			break;
		}

		case SYS_FREMOVEXATTR:
		{
			name = "sys_fremovexattr";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * name */

			char *xattrname = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == xattrname) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\")\n",  pid, proc, name, (int)rdi, xattrname);	
				free(xattrname);
			}
			break;
		}

		case SYS_TKILL:
		{
			name = "sys_tkill";
			reg_t rdi = event->regs.x86->rdi;		/* int pid */
			reg_t rsi = event->regs.x86->rsi;		/* int sig */
			printf("pid: %u ( %s ) syscall: %s(%i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi);
			break;
		}

		case SYS_TIME:
		{
			name = "sys_time";
			reg_t rdi = event->regs.x86->rdi;		/* time_t __user * tloc */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_FUTEX:
		{
			name = "sys_futex";
			reg_t rdi = event->regs.x86->rdi;		/* u32 __user * uaddr */
			reg_t rsi = event->regs.x86->rsi;		/* int op */
			reg_t rdx = event->regs.x86->rdx;		/* u32 val */
			reg_t r10 = event->regs.x86->r10;		/* struct timespec __user * utime */
			reg_t r8 = event->regs.x86->r8;		/* u32 __user * uaddr2 */
			reg_t r9 = event->regs.x86->r9;		/* u32 val3 */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (int)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8, (unsigned long)r9);
			break;
		}

		case SYS_SCHED_SETAFFINITY:
		{
			name = "sys_sched_setaffinity";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned int len */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long __user * user_mask_ptr */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SCHED_GETAFFINITY:
		{
			name = "sys_sched_getaffinity";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned int len */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long __user * user_mask_ptr */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SET_THREAD_AREA:
		{
			name = "sys_set_thread_area";
			reg_t rdi = event->regs.x86->rdi;		/* struct user_desc __user * arg1 */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_IO_SETUP:
		{
			name = "sys_io_setup";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned nr_reqs */
			reg_t rsi = event->regs.x86->rsi;		/* aio_context_t __user * ctx */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_IO_DESTROY:
		{
			name = "sys_io_destroy";
			reg_t rdi = event->regs.x86->rdi;		/* aio_context_t ctx */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_IO_GETEVENTS:
		{
			name = "sys_io_getevents";
			reg_t rdi = event->regs.x86->rdi;		/* aio_context_t ctx_id */
			reg_t rsi = event->regs.x86->rsi;		/* long min_nr */
			reg_t rdx = event->regs.x86->rdx;		/* long nr */
			reg_t r10 = event->regs.x86->r10;		/* struct io_event __user * events */
			reg_t r8 = event->regs.x86->r8;		/* struct timespec __user * timeout */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %li, %li, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (long int)rsi, (long int)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_IO_SUBMIT:
		{
			name = "sys_io_submit";
			reg_t rdi = event->regs.x86->rdi;		/*  aio_context_t */
			reg_t rsi = event->regs.x86->rsi;		/*  long arg2 */
			reg_t rdx = event->regs.x86->rdx;		/* struct iocb __user * __user * arg3 */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %li, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (long int)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_IO_CANCEL:
		{
			name = "sys_io_cancel";
			reg_t rdi = event->regs.x86->rdi;		/* aio_context_t ctx_id */
			reg_t rsi = event->regs.x86->rsi;		/* struct iocb __user * iocb */
			reg_t rdx = event->regs.x86->rdx;		/* struct io_event __user * result */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GET_THREAD_AREA:
		{
			name = "sys_get_thread_area";
			reg_t rdi = event->regs.x86->rdi;		/* struct user_desc __user * arg1 */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_LOOKUP_DCOOKIE:
		{
			name = "sys_lookup_dcookie";
			reg_t rdi = event->regs.x86->rdi;		/* u64 cookie64 */
			reg_t rsi = event->regs.x86->rsi;		/* char __user * buf */
			reg_t rdx = event->regs.x86->rdx;		/* size_t len */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_EPOLL_CREATE:
		{
			name = "sys_epoll_create";
			reg_t rdi = event->regs.x86->rdi;		/* int size */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_EPOLL_CTL_OLD:
		{
			name = "sys_epoll_ctl_old";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_EPOLL_WAIT_OLD:
		{
			name = "sys_epoll_wait_old";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_REMAP_FILE_PAGES:
		{
			name = "sys_remap_file_pages";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long start */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned long size */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long prot */
			reg_t r10 = event->regs.x86->r10;		/* unsigned long pgoff */
			reg_t r8 = event->regs.x86->r8;		/* unsigned long flags */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_GETDENTS64:
		{
			name = "sys_getdents64";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int fd */
			reg_t rsi = event->regs.x86->rsi;		/* struct linux_dirent64 __user * dirent */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned int count */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SET_TID_ADDRESS:
		{
			name = "sys_set_tid_address";
			reg_t rdi = event->regs.x86->rdi;		/* int __user * tidptr */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_RESTART_SYSCALL:
		{
			name = "sys_restart_syscall";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_SEMTIMEDOP:
		{
			name = "sys_semtimedop";
			reg_t rdi = event->regs.x86->rdi;		/* int semid */
			reg_t rsi = event->regs.x86->rsi;		/* struct sembuf __user * sops */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned nsops */
			reg_t r10 = event->regs.x86->r10;		/* const struct timespec __user * timeout */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_FADVISE64:
		{
			name = "sys_fadvise64";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* loff_t offset */
			reg_t rdx = event->regs.x86->rdx;		/* size_t len */
			reg_t r10 = event->regs.x86->r10;		/* int advice */
			printf("pid: %u ( %s ) syscall: %s(%i, %li, %lu, %i)\n",  pid, proc, name, (int)rdi, (long int)rsi, (unsigned long)rdx, (int)r10);
			break;
		}

		case SYS_TIMER_CREATE:
		{
			name = "sys_timer_create";
			reg_t rdi = event->regs.x86->rdi;		/* clockid_t which_clock */
			reg_t rsi = event->regs.x86->rsi;		/* struct sigevent __user * timer_event_spec */
			reg_t rdx = event->regs.x86->rdx;		/* timer_t __user * created_timer_id */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_TIMER_SETTIME:
		{
			name = "sys_timer_settime";
			reg_t rdi = event->regs.x86->rdi;		/* timer_t timer_id */
			reg_t rsi = event->regs.x86->rsi;		/* int flags */
			reg_t rdx = event->regs.x86->rdx;		/* const struct itimerspec __user * new_setting */
			reg_t r10 = event->regs.x86->r10;		/* struct itimerspec __user * old_setting */
			printf("pid: %u ( %s ) syscall: %s(%lu, %i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (int)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_TIMER_GETTIME:
		{
			name = "sys_timer_gettime";
			reg_t rdi = event->regs.x86->rdi;		/* timer_t timer_id */
			reg_t rsi = event->regs.x86->rsi;		/* struct itimerspec __user * setting */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_TIMER_GETOVERRUN:
		{
			name = "sys_timer_getoverrun";
			reg_t rdi = event->regs.x86->rdi;		/* timer_t timer_id */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_TIMER_DELETE:
		{
			name = "sys_timer_delete";
			reg_t rdi = event->regs.x86->rdi;		/* timer_t timer_id */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_CLOCK_SETTIME:
		{
			name = "sys_clock_settime";
			reg_t rdi = event->regs.x86->rdi;		/* clockid_t which_clock */
			reg_t rsi = event->regs.x86->rsi;		/* const struct timespec __user * tp */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_CLOCK_GETTIME:
		{
			name = "sys_clock_gettime";
			reg_t rdi = event->regs.x86->rdi;		/* clockid_t which_clock */
			reg_t rsi = event->regs.x86->rsi;		/* struct timespec __user * tp */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_CLOCK_GETRES:
		{
			name = "sys_clock_getres";
			reg_t rdi = event->regs.x86->rdi;		/* clockid_t which_clock */
			reg_t rsi = event->regs.x86->rsi;		/* struct timespec __user * tp */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_CLOCK_NANOSLEEP:
		{
			name = "sys_clock_nanosleep";
			reg_t rdi = event->regs.x86->rdi;		/* clockid_t which_clock */
			reg_t rsi = event->regs.x86->rsi;		/* int flags */
			reg_t rdx = event->regs.x86->rdx;		/* const struct timespec __user * rqtp */
			reg_t r10 = event->regs.x86->r10;		/* struct timespec __user * rmtp */
			printf("pid: %u ( %s ) syscall: %s(%lu, %i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (int)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_EXIT_GROUP:
		{
			name = "sys_exit_group";
			reg_t rdi = event->regs.x86->rdi;		/* int error_code */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_EPOLL_WAIT:
		{
			name = "sys_epoll_wait";
			reg_t rdi = event->regs.x86->rdi;		/* int epfd */
			reg_t rsi = event->regs.x86->rsi;		/* struct epoll_event __user * events */
			reg_t rdx = event->regs.x86->rdx;		/* int maxevents */
			reg_t r10 = event->regs.x86->r10;		/* int timeout */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i, %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx, (int)r10);
			break;
		}

		case SYS_EPOLL_CTL:
		{
			name = "sys_epoll_ctl";
			reg_t rdi = event->regs.x86->rdi;		/* int epfd */
			reg_t rsi = event->regs.x86->rsi;		/* int op */
			reg_t rdx = event->regs.x86->rdx;		/* int fd */
			reg_t r10 = event->regs.x86->r10;		/* struct epoll_event __user * event */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx, (unsigned long)r10);
			break;
		}

		case SYS_TGKILL:
		{
			name = "sys_tgkill";
			reg_t rdi = event->regs.x86->rdi;		/* int tgid */
			reg_t rsi = event->regs.x86->rsi;		/* int pid */
			reg_t rdx = event->regs.x86->rdx;		/* int sig */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx);
			break;
		}

		case SYS_UTIMES:
		{
			name = "sys_utimes";
			reg_t rdi = event->regs.x86->rdi;		/* char __user * filename */
			reg_t rsi = event->regs.x86->rsi;		/* struct timeval __user * utimes */

			char *fname = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", 0x%"PRIx64")\n",  pid, proc, name, fname, (unsigned long)rsi);
				free(fname);
			}
			break;
		}

		case SYS_VSERVER:
		{
			name = "sys_vserver";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_MBIND:
		{
			name = "sys_mbind";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long start */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned long len */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long mode */
			reg_t r10 = event->regs.x86->r10;		/* const unsigned long __user * nmask */
			reg_t r8 = event->regs.x86->r8;		/* unsigned long maxnode */
			reg_t r9 = event->regs.x86->r9;		/* unsigned flags */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %lu, 0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8, (unsigned long)r9);
			break;
		}

		case SYS_SET_MEMPOLICY:
		{
			name = "sys_set_mempolicy";
			reg_t rdi = event->regs.x86->rdi;		/* int mode */
			reg_t rsi = event->regs.x86->rsi;		/* const unsigned long __user * nmask */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long maxnode */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GET_MEMPOLICY:
		{
			name = "sys_get_mempolicy";
			reg_t rdi = event->regs.x86->rdi;		/* int __user * policy */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned long __user * nmask */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long maxnode */
			reg_t r10 = event->regs.x86->r10;		/* unsigned long addr */
			reg_t r8 = event->regs.x86->r8;		/* unsigned long flags */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_MQ_OPEN:
		{
			name = "sys_mq_open";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * name */
			reg_t rsi = event->regs.x86->rsi;		/* int oflag */
			reg_t rdx = event->regs.x86->rdx;		/* umode_t mode */
			reg_t r10 = event->regs.x86->r10;		/* struct mq_attr __user * attr */

			char *qname = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == qname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %i, %lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (int)rsi, (unsigned long)rdx, (unsigned long)r10);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", %i, %lu, 0x%"PRIx64")\n",  pid, proc, name, qname, (int)rsi, (unsigned long)rdx, (unsigned long)r10);
				free(qname);
			}
			break;
		}

		case SYS_MQ_UNLINK:
		{
			name = "sys_mq_unlink";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * name */

			char *qname = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == qname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\")\n",  pid, proc, name, qname);
				free(qname);
			}
			break;
		}

		case SYS_MQ_TIMEDSEND:
		{
			name = "sys_mq_timedsend";
			reg_t rdi = event->regs.x86->rdi;		/* mqd_t mqdes */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * msg_ptr */
			reg_t rdx = event->regs.x86->rdx;		/* size_t msg_len */
			reg_t r10 = event->regs.x86->r10;		/* unsigned int msg_prio */
			reg_t r8 = event->regs.x86->r8;		/* const struct timespec __user * abs_timeout */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_MQ_TIMEDRECEIVE:
		{
			name = "sys_mq_timedreceive";
			reg_t rdi = event->regs.x86->rdi;		/* mqd_t mqdes */
			reg_t rsi = event->regs.x86->rsi;		/* char __user * msg_ptr */
			reg_t rdx = event->regs.x86->rdx;		/* size_t msg_len */
			reg_t r10 = event->regs.x86->r10;		/* unsigned int __user * msg_prio */
			reg_t r8 = event->regs.x86->r8;		/* const struct timespec __user * abs_timeout */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_MQ_NOTIFY:
		{
			name = "sys_mq_notify";
			reg_t rdi = event->regs.x86->rdi;		/* mqd_t mqdes */
			reg_t rsi = event->regs.x86->rsi;		/* const struct sigevent __user * notification */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_MQ_GETSETATTR:
		{
			name = "sys_mq_getsetattr";
			reg_t rdi = event->regs.x86->rdi;		/* mqd_t mqdes */
			reg_t rsi = event->regs.x86->rsi;		/* const struct mq_attr __user * mqstat */
			reg_t rdx = event->regs.x86->rdx;		/* struct mq_attr __user * omqstat */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_KEXEC_LOAD:
		{
			name = "sys_kexec_load";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long entry */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned long nr_segments */
			reg_t rdx = event->regs.x86->rdx;		/* struct kexec_segment __user * segments */
			reg_t r10 = event->regs.x86->r10;		/* unsigned long flags */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_WAITID:
		{
			name = "sys_waitid";
			reg_t rdi = event->regs.x86->rdi;		/* int which */
			reg_t rsi = event->regs.x86->rsi;		/* pid_t pid */
			reg_t rdx = event->regs.x86->rdx;		/* struct siginfo __user * infop */
			reg_t r10 = event->regs.x86->r10;		/* int options */
			reg_t r8 = event->regs.x86->r8;		/* struct rusage __user * ru */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, 0x%"PRIx64", %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx, (int)r10, (unsigned long)r8);
			break;
		}

		case SYS_ADD_KEY:
		{
			name = "sys_add_key";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * _type */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * _description */
			reg_t rdx = event->regs.x86->rdx;		/* const void __user * _payload */
			reg_t r10 = event->regs.x86->r10;		/* size_t plen */
			reg_t r8 = event->regs.x86->r8;		/* key_serial_t destringid */
			char *type = vmi_read_str_va(vmi, rdi, pid);
			char *desc = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == type || NULL == desc) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (int)r8);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", \"%s\", 0x%"PRIx64", %lu, %i)\n",  pid, proc, name, type, desc, (unsigned long)rdx, (unsigned long)r10, (int)r8);
				free(type);
				free(desc);
			}
			break;
		}

		case SYS_REQUEST_KEY:
		{
			name = "sys_request_key";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * _type */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * _description */
			reg_t rdx = event->regs.x86->rdx;		/* const char __user * _callout_info */
			reg_t r10 = event->regs.x86->r10;		/* key_serial_t destringid */
			char *type = vmi_read_str_va(vmi, rdi, pid);
			char *desc = vmi_read_str_va(vmi, rsi, pid);
			char *callout = vmi_read_str_va(vmi, rdx, pid);
			if (NULL == type || NULL == desc) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", \"%s\", \"%s\", %lu)\n",  pid, proc, name, type, desc, callout, (unsigned long)r10);
				free(type);
				free(desc);
			}
			break;
		}

		case SYS_KEYCTL:
		{
			name = "sys_keyctl";
			reg_t rdi = event->regs.x86->rdi;		/* int cmd */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned long arg2 */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long arg3 */
			reg_t r10 = event->regs.x86->r10;		/* unsigned long arg4 */
			reg_t r8 = event->regs.x86->r8;		/* unsigned long arg5 */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, %lu, %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_IOPRIO_SET:
		{
			name = "sys_ioprio_set";
			reg_t rdi = event->regs.x86->rdi;		/* int which */
			reg_t rsi = event->regs.x86->rsi;		/* int who */
			reg_t rdx = event->regs.x86->rdx;		/* int ioprio */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx);
			break;
		}

		case SYS_IOPRIO_GET:
		{
			name = "sys_ioprio_get";
			reg_t rdi = event->regs.x86->rdi;		/* int which */
			reg_t rsi = event->regs.x86->rsi;		/* int who */
			printf("pid: %u ( %s ) syscall: %s(%i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi);
			break;
		}

		case SYS_INOTIFY_INIT:
		{
			name = "sys_inotify_init";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_INOTIFY_ADD_WATCH:
		{
			name = "sys_inotify_add_watch";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * path */
			reg_t rdx = event->regs.x86->rdx;		/* u32 mask */

			char *path = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == path) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, path, (unsigned long)rdx);
				free(path);
			}
			break;
		}

		case SYS_INOTIFY_RM_WATCH:
		{
			name = "sys_inotify_rm_watch";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* __s32 wd */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_MIGRATE_PAGES:
		{
			name = "sys_migrate_pages";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned long maxnode */
			reg_t rdx = event->regs.x86->rdx;		/* const unsigned long __user * from */
			reg_t r10 = event->regs.x86->r10;		/* const unsigned long __user * to */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_OPENAT:
		{
			name = "sys_openat";
			reg_t rdi = event->regs.x86->rdi;		/* int dfd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * filename */
			reg_t rdx = event->regs.x86->rdx;		/* int flags */
			reg_t r10 = event->regs.x86->r10;		/* umode_t mode */

			char *fname = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx, (unsigned long)r10);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", %i, %lu)\n",  pid, proc, name, (int)rdi, fname, (int)rdx, (unsigned long)r10);
				free(fname);
			}
			break;
		}

		case SYS_MKDIRAT:
		{
			name = "sys_mkdirat";
			reg_t rdi = event->regs.x86->rdi;		/* int dfd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * pathname */
			reg_t rdx = event->regs.x86->rdx;		/* umode_t mode */

			char *fname = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", %lu)\n",  pid, proc, name, (int)rdi, fname, (unsigned long)rdx);
				free(fname);
			}
			break;
		}

		case SYS_MKNODAT:
		{
			name = "sys_mknodat";
			reg_t rdi = event->regs.x86->rdi;		/* int dfd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * filename */
			reg_t rdx = event->regs.x86->rdx;		/* umode_t mode */
			reg_t r10 = event->regs.x86->r10;		/* unsigned dev */

			char *fname = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", %lu, %lu)\n",  pid, proc, name, (int)rdi, fname, (unsigned long)rdx, (unsigned long)r10);
				free(fname);
			}
			break;
		}

		case SYS_FCHOWNAT:
		{
			name = "sys_fchownat";
			reg_t rdi = event->regs.x86->rdi;		/* int dfd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * filename */
			reg_t rdx = event->regs.x86->rdx;		/* uid_t user */
			reg_t r10 = event->regs.x86->r10;		/* gid_t group */
			reg_t r8 = event->regs.x86->r8;		/* int flag */

			char *fname = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (int)r8);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", %lu, %lu, %i)\n",  pid, proc, name, (int)rdi, fname, (unsigned long)rdx, (unsigned long)r10, (int)r8);
				free(fname);
			}
			break;
		}

		case SYS_FUTIMESAT:
		{
			name = "sys_futimesat";
			reg_t rdi = event->regs.x86->rdi;		/* int dfd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * filename */
			reg_t rdx = event->regs.x86->rdx;		/* struct timeval __user * utimes */

			char *fname = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, fname, (unsigned long)rdx);
				free(fname);
			}
			break;
		}

		case SYS_NEWFSTATAT:
		{
			name = "sys_newfstatat";
			reg_t rdi = event->regs.x86->rdi;		/* int dfd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * filename */
			reg_t rdx = event->regs.x86->rdx;		/* struct stat __user * statbuf */
			reg_t r10 = event->regs.x86->r10;		/* int flag */

			char *fname = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (int)r10);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, fname, (unsigned long)rdx, (int)r10);
				free(fname);
			}
			break;
		}

		case SYS_UNLINKAT:
		{
			name = "sys_unlinkat";
			reg_t rdi = event->regs.x86->rdi;		/* int dfd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * pathname */
			reg_t rdx = event->regs.x86->rdx;		/* int flag */

			char *path = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == path) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", %i)\n",  pid, proc, name, (int)rdi, path, (int)rdx);
				free(path);
			}
			break;
		}

		case SYS_RENAMEAT:
		{
			name = "sys_renameat";
			reg_t rdi = event->regs.x86->rdi;		/* int olddfd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * oldname */
			reg_t rdx = event->regs.x86->rdx;		/* int newdfd */
			reg_t r10 = event->regs.x86->r10;		/* const char __user * newname */
			
			char *oldname = vmi_read_str_va(vmi, rsi, pid);
			char *newname = vmi_read_str_va(vmi, r10, pid);
			if (NULL == oldname || NULL == newname) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx, (unsigned long)r10);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", %i, %s)\n",  pid, proc, name, (int)rdi, oldname, (int)rdx, newname);
				free(oldname);
				free(newname);
			}
			break;
		}

		case SYS_LINKAT:
		{
			name = "sys_linkat";
			reg_t rdi = event->regs.x86->rdi;		/* int olddfd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * oldname */
			reg_t rdx = event->regs.x86->rdx;		/* int newdfd */
			reg_t r10 = event->regs.x86->r10;		/* const char __user * newname */
			reg_t r8 = event->regs.x86->r8;		/* int flags */

			char *oldname = vmi_read_str_va(vmi, rsi, pid);
			char *newname = vmi_read_str_va(vmi, r10, pid);
			if (NULL == oldname || NULL == newname) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx, (unsigned long)r10, (int)r8);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", %i, \"%s\", %i)\n",  pid, proc, name, (int)rdi, oldname, (int)rdx, newname, (int)r8);
				free(oldname);
				free(newname);
			}
			break;
		}

		case SYS_SYMLINKAT:
		{
			name = "sys_symlinkat";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * oldname */
			reg_t rsi = event->regs.x86->rsi;		/* int newdfd */
			reg_t rdx = event->regs.x86->rdx;		/* const char __user * newname */
			
			char *oldname = vmi_read_str_va(vmi, rdi, pid);
			char *newname = vmi_read_str_va(vmi, rdx, pid);
			if (NULL == oldname || NULL == newname) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (int)rsi, (unsigned long)rdx);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", %i, %s)\n",  pid, proc, name, oldname, (int)rsi, newname);
				free(oldname);
				free(newname);
			}
			break;
		}

		case SYS_READLINKAT:
		{
			name = "sys_readlinkat";
			reg_t rdi = event->regs.x86->rdi;		/* int dfd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * path */
			reg_t rdx = event->regs.x86->rdx;		/* char __user * buf */
			reg_t r10 = event->regs.x86->r10;		/* int bufsiz */

			char *path = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == path) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (int)r10);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, path, (unsigned long)rdx, (int)r10);
				free(path);
			}
			break;
		}

		case SYS_FCHMODAT:
		{
			name = "sys_fchmodat";
			reg_t rdi = event->regs.x86->rdi;		/* int dfd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * filename */
			reg_t rdx = event->regs.x86->rdx;		/* umode_t mode */

			char *fname = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", %lu)\n",  pid, proc, name, (int)rdi, fname, (unsigned long)rdx);
				free(fname);
			}	
			break;
		}

		case SYS_FACCESSAT:
		{
			name = "sys_faccessat";
			reg_t rdi = event->regs.x86->rdi;		/* int dfd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * filename */
			reg_t rdx = event->regs.x86->rdx;		/* int mode */

			char *fname = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", %i)\n",  pid, proc, name, (int)rdi, fname, (int)rdx);	
				free(fname);
			}
			break;
		}

		case SYS_PSELECT6:
		{
			name = "sys_pselect6";
			reg_t rdi = event->regs.x86->rdi;		/*  int arg1 */
			reg_t rsi = event->regs.x86->rsi;		/* fd_set __user * arg2 */
			reg_t rdx = event->regs.x86->rdx;		/* fd_set __user * arg3 */
			reg_t r10 = event->regs.x86->r10;		/* fd_set __user * arg4 */
			reg_t r8 = event->regs.x86->r8;		/* struct timespec __user * arg5 */
			reg_t r9 = event->regs.x86->r9;		/* void __user * arg6 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8, (unsigned long)r9);
			break;
		}

		case SYS_PPOLL:
		{
			name = "sys_ppoll";
			reg_t rdi = event->regs.x86->rdi;		/* struct pollfd __user * arg1 */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned int arg2 */
			reg_t rdx = event->regs.x86->rdx;		/* struct timespec __user * arg3 */
			reg_t r10 = event->regs.x86->r10;		/* const sigset_t __user * arg4 */
			reg_t r8 = event->regs.x86->r8;		/*  size_t */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_UNSHARE:
		{
			name = "sys_unshare";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long unshare_flags */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_SET_ROBUST_LIST:
		{
			name = "sys_set_robust_list";
			reg_t rdi = event->regs.x86->rdi;		/* struct robust_list_head __user * head */
			reg_t rsi = event->regs.x86->rsi;		/* size_t len */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_GET_ROBUST_LIST:
		{
			name = "sys_get_robust_list";
			reg_t rdi = event->regs.x86->rdi;		/* int pid */
			reg_t rsi = event->regs.x86->rsi;		/* struct robust_list_head __user * __user * head_ptr */
			reg_t rdx = event->regs.x86->rdx;		/* size_t __user * len_ptr */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SPLICE:
		{
			name = "sys_splice";
			reg_t rdi = event->regs.x86->rdi;		/* int fd_in */
			reg_t rsi = event->regs.x86->rsi;		/* loff_t __user * off_in */
			reg_t rdx = event->regs.x86->rdx;		/* int fd_out */
			reg_t r10 = event->regs.x86->r10;		/* loff_t __user * off_out */
			reg_t r8 = event->regs.x86->r8;		/* size_t len */
			reg_t r9 = event->regs.x86->r9;		/* unsigned int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx, (unsigned long)r10, (unsigned long)r8, (unsigned long)r9);
			break;
		}

		case SYS_TEE:
		{
			name = "sys_tee";
			reg_t rdi = event->regs.x86->rdi;		/* int fdin */
			reg_t rsi = event->regs.x86->rsi;		/* int fdout */
			reg_t rdx = event->regs.x86->rdx;		/* size_t len */
			reg_t r10 = event->regs.x86->r10;		/* unsigned int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %lu, %lu)\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_SYNC_FILE_RANGE:
		{
			name = "sys_sync_file_range";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* loff_t offset */
			reg_t rdx = event->regs.x86->rdx;		/* loff_t nbytes */
			reg_t r10 = event->regs.x86->r10;		/* unsigned int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, %li, %li, %lu)\n",  pid, proc, name, (int)rdi, (long int)rsi, (long int)rdx, (unsigned long)r10);
			break;
		}

		case SYS_VMSPLICE:
		{
			name = "sys_vmsplice";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* const struct iovec __user * iov */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long nr_segs */
			reg_t r10 = event->regs.x86->r10;		/* unsigned int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_MOVE_PAGES:
		{
			name = "sys_move_pages";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned long nr_pages */
			reg_t rdx = event->regs.x86->rdx;		/* const void __user * __user * pages */
			reg_t r10 = event->regs.x86->r10;		/* const int __user * nodes */
			reg_t r8 = event->regs.x86->r8;		/* int __user * status */
			reg_t r9 = event->regs.x86->r9;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8, (int)r9);
			break;
		}

		case SYS_UTIMENSAT:
		{
			name = "sys_utimensat";
			reg_t rdi = event->regs.x86->rdi;		/* int dfd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * filename */
			reg_t rdx = event->regs.x86->rdx;		/* struct timespec __user * utimes */
			reg_t r10 = event->regs.x86->r10;		/* int flags */
		
			char *fname = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (int)r10);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, fname, (unsigned long)rdx, (int)r10);
				free(fname);
			}
			break;
		}

		case SYS_EPOLL_PWAIT:
		{
			name = "sys_epoll_pwait";
			reg_t rdi = event->regs.x86->rdi;		/* int epfd */
			reg_t rsi = event->regs.x86->rsi;		/* struct epoll_event __user * events */
			reg_t rdx = event->regs.x86->rdx;		/* int maxevents */
			reg_t r10 = event->regs.x86->r10;		/* int timeout */
			reg_t r8 = event->regs.x86->r8;		/* const sigset_t __user * sigmask */
			reg_t r9 = event->regs.x86->r9;		/* size_t sigsetsize */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i, %i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx, (int)r10, (unsigned long)r8, (unsigned long)r9);
			break;
		}

		case SYS_SIGNALFD:
		{
			name = "sys_signalfd";
			reg_t rdi = event->regs.x86->rdi;		/* int ufd */
			reg_t rsi = event->regs.x86->rsi;		/* sigset_t __user * user_mask */
			reg_t rdx = event->regs.x86->rdx;		/* size_t sizemask */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_TIMERFD:
		{
			name = "sys_timerfd";
			printf("pid: %u ( %s ) syscall: %s()\n",  pid, proc, name);
			break;
		}

		case SYS_EVENTFD:
		{
			name = "sys_eventfd";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int count */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_FALLOCATE:
		{
			name = "sys_fallocate";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* int mode */
			reg_t rdx = event->regs.x86->rdx;		/* loff_t offset */
			reg_t r10 = event->regs.x86->r10;		/* loff_t len */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %li, %li)\n",  pid, proc, name, (int)rdi, (int)rsi, (long int)rdx, (long int)r10);
			break;
		}

		case SYS_TIMERFD_SETTIME:
		{
			name = "sys_timerfd_settime";
			reg_t rdi = event->regs.x86->rdi;		/* int ufd */
			reg_t rsi = event->regs.x86->rsi;		/* int flags */
			reg_t rdx = event->regs.x86->rdx;		/* const struct itimerspec __user * utmr */
			reg_t r10 = event->regs.x86->r10;		/* struct itimerspec __user * otmr */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_TIMERFD_GETTIME:
		{
			name = "sys_timerfd_gettime";
			reg_t rdi = event->regs.x86->rdi;		/* int ufd */
			reg_t rsi = event->regs.x86->rsi;		/* struct itimerspec __user * otmr */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_ACCEPT4:
		{
			name = "sys_accept4";
			reg_t rdi = event->regs.x86->rdi;		/*  int arg1 */
			reg_t rsi = event->regs.x86->rsi;		/* struct sockaddr __user * arg2 */
			reg_t rdx = event->regs.x86->rdx;		/* int __user * arg3 */
			reg_t r10 = event->regs.x86->r10;		/*  int arg4 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (int)r10);
			break;
		}

		case SYS_SIGNALFD4:
		{
			name = "sys_signalfd4";
			reg_t rdi = event->regs.x86->rdi;		/* int ufd */
			reg_t rsi = event->regs.x86->rsi;		/* sigset_t __user * user_mask */
			reg_t rdx = event->regs.x86->rdx;		/* size_t sizemask */
			reg_t r10 = event->regs.x86->r10;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (int)r10);
			break;
		}

		case SYS_EVENTFD2:
		{
			name = "sys_eventfd2";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int count */
			reg_t rsi = event->regs.x86->rsi;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%lu, %i)\n",  pid, proc, name, (unsigned long)rdi, (int)rsi);
			break;
		}

		case SYS_EPOLL_CREATE1:
		{
			name = "sys_epoll_create1";
			reg_t rdi = event->regs.x86->rdi;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_DUP3:
		{
			name = "sys_dup3";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int oldfd */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned int newfd */
			reg_t rdx = event->regs.x86->rdx;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %i)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_PIPE2:
		{
			name = "sys_pipe2";
			reg_t rdi = event->regs.x86->rdi;		/* int __user * fildes */
			reg_t rsi = event->regs.x86->rsi;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %i)\n",  pid, proc, name, (unsigned long)rdi, (int)rsi);
			break;
		}

		case SYS_INOTIFY_INIT1:
		{
			name = "sys_inotify_init1";
			reg_t rdi = event->regs.x86->rdi;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_PREADV:
		{
			name = "sys_preadv";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long fd */
			reg_t rsi = event->regs.x86->rsi;		/* const struct iovec __user * vec */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long vlen */
			reg_t r10 = event->regs.x86->r10;		/* unsigned long pos_l */
			reg_t r8 = event->regs.x86->r8;		/* unsigned long pos_h */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_PWRITEV:
		{
			name = "sys_pwritev";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long fd */
			reg_t rsi = event->regs.x86->rsi;		/* const struct iovec __user * vec */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long vlen */
			reg_t r10 = event->regs.x86->r10;		/* unsigned long pos_l */
			reg_t r8 = event->regs.x86->r8;		/* unsigned long pos_h */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_RT_TGSIGQUEUEINFO:
		{
			name = "sys_rt_tgsigqueueinfo";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t tgid */
			reg_t rsi = event->regs.x86->rsi;		/* pid_t  pid */
			reg_t rdx = event->regs.x86->rdx;		/* int sig */
			reg_t r10 = event->regs.x86->r10;		/* siginfo_t __user * uinfo */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx, (unsigned long)r10);
			break;
		}

		case SYS_PERF_EVENT_OPEN:
		{
			name = "sys_perf_event_open";
			reg_t rdi = event->regs.x86->rdi;		/*  struct perf_event_attr __user * attr_uptr */
			reg_t rsi = event->regs.x86->rsi;		/* pid_t pid */
			reg_t rdx = event->regs.x86->rdx;		/* int cpu */
			reg_t r10 = event->regs.x86->r10;		/* int group_fd */
			reg_t r8 = event->regs.x86->r8;		/* unsigned long flags */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %i, %i, %i, %lu)\n",  pid, proc, name, (unsigned long)rdi, (int)rsi, (int)rdx, (int)r10, (unsigned long)r8);
			break;
		}

		case SYS_RECVMMSG:
		{
			name = "sys_recvmmsg";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* struct mmsghdr __user * msg */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned int vlen */
			reg_t r10 = event->regs.x86->r10;		/* unsigned flags */
			reg_t r8 = event->regs.x86->r8;		/* struct timespec __user * timeout */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_FANOTIFY_INIT:
		{
			name = "sys_fanotify_init";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int flags */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned int event_f_flags */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_FANOTIFY_MARK:
		{
			name = "sys_fanotify_mark";
			reg_t rdi = event->regs.x86->rdi;		/* int fanotify_fd */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned int flags */
			reg_t rdx = event->regs.x86->rdx;		/* u64 mask */
			reg_t r10 = event->regs.x86->r10;		/* int fd */
			reg_t r8 = event->regs.x86->r8;		/* const char  __user * pathname */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, %lu, %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (int)r10, (unsigned long)r8);
			break;
		}

		case SYS_PRLIMIT64:
		{
			name = "sys_prlimit64";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned int resource */
			reg_t rdx = event->regs.x86->rdx;		/* const struct rlimit64 __user * new_rlim */
			reg_t r10 = event->regs.x86->r10;		/* struct rlimit64 __user * old_rlim */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_NAME_TO_HANDLE_AT:
		{
			name = "sys_name_to_handle_at";
			reg_t rdi = event->regs.x86->rdi;		/* int dfd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * name */
			reg_t rdx = event->regs.x86->rdx;		/* struct file_handle __user * handle */
			reg_t r10 = event->regs.x86->r10;		/* int __user * mnt_id */
			reg_t r8 = event->regs.x86->r8;		/* int flag */

			char *path = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == path) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (int)r8);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", 0x%"PRIx64", 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, path, (unsigned long)rdx, (unsigned long)r10, (int)r8);
				free(path);
			}
			break;
		}

		case SYS_OPEN_BY_HANDLE_AT:
		{
			name = "sys_open_by_handle_at";
			reg_t rdi = event->regs.x86->rdi;		/* int mountdirfd */
			reg_t rsi = event->regs.x86->rsi;		/* struct file_handle __user * handle */
			reg_t rdx = event->regs.x86->rdx;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_CLOCK_ADJTIME:
		{
			name = "sys_clock_adjtime";
			reg_t rdi = event->regs.x86->rdi;		/* clockid_t which_clock */
			reg_t rsi = event->regs.x86->rsi;		/* struct timex __user * tx */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_SYNCFS:
		{
			name = "sys_syncfs";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_SENDMMSG:
		{
			name = "sys_sendmmsg";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* struct mmsghdr __user * msg */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned int vlen */
			reg_t r10 = event->regs.x86->r10;		/* unsigned flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_SETNS:
		{
			name = "sys_setns";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* int nstype */
			printf("pid: %u ( %s ) syscall: %s(%i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi);
			break;
		}

		case SYS_GETCPU:
		{
			name = "sys_getcpu";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned __user * cpu */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned __user * node */
			reg_t rdx = event->regs.x86->rdx;		/* struct getcpu_cache __user * cache */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_PROCESS_VM_READV:
		{
			name = "sys_process_vm_readv";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid */
			reg_t rsi = event->regs.x86->rsi;		/* const struct iovec __user * lvec */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long liovcnt */
			reg_t r10 = event->regs.x86->r10;		/* const struct iovec __user * rvec */
			reg_t r8 = event->regs.x86->r8;		/* unsigned long riovcnt */
			reg_t r9 = event->regs.x86->r9;		/* unsigned long flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8, (unsigned long)r9);
			break;
		}

		case SYS_PROCESS_VM_WRITEV:
		{
			name = "sys_process_vm_writev";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid */
			reg_t rsi = event->regs.x86->rsi;		/* const struct iovec __user * lvec */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long liovcnt */
			reg_t r10 = event->regs.x86->r10;		/* const struct iovec __user * rvec */
			reg_t r8 = event->regs.x86->r8;		/* unsigned long riovcnt */
			reg_t r9 = event->regs.x86->r9;		/* unsigned long flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8, (unsigned long)r9);
			break;
		}

		case SYS_KCMP:
		{
			name = "sys_kcmp";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid1 */
			reg_t rsi = event->regs.x86->rsi;		/* pid_t pid2 */
			reg_t rdx = event->regs.x86->rdx;		/* int type */
			reg_t r10 = event->regs.x86->r10;		/* unsigned long idx1 */
			reg_t r8 = event->regs.x86->r8;		/* unsigned long idx2 */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i, %lu, %lu)\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_FINIT_MODULE:
		{
			name = "sys_finit_module";
			reg_t rdi = event->regs.x86->rdi;		/* int fd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * uargs */
			reg_t rdx = event->regs.x86->rdx;		/* int flags */
		
			char *uargs = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == uargs) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", %i)\n",  pid, proc, name, (int)rdi, uargs, (int)rdx);
				free(uargs);
			}
			break;
		}

		case SYS_SCHED_SETATTR:
		{
			name = "sys_sched_setattr";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid */
			reg_t rsi = event->regs.x86->rsi;		/* struct sched_attr __user * attr */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SCHED_GETATTR:
		{
			name = "sys_sched_getattr";
			reg_t rdi = event->regs.x86->rdi;		/* pid_t pid */
			reg_t rsi = event->regs.x86->rsi;		/* struct sched_attr __user * attr */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned int size */
			reg_t r10 = event->regs.x86->r10;		/* unsigned int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_RENAMEAT2:
		{
			name = "sys_renameat2";
			reg_t rdi = event->regs.x86->rdi;		/* int olddfd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * oldname */
			reg_t rdx = event->regs.x86->rdx;		/* int newdfd */
			reg_t r10 = event->regs.x86->r10;		/* const char __user * newname */
			reg_t r8 = event->regs.x86->r8;		/* unsigned int flags */	

			char *oldname = vmi_read_str_va(vmi, rsi, pid);
			char *newname = vmi_read_str_va(vmi, r10, pid);
			if (NULL == oldname || NULL == newname) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx, (unsigned long)r10, (unsigned long)r8);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", %i, %s, %lu)\n",  pid, proc, name, (int)rdi, oldname, (int)rdx, newname, (unsigned long)r8);
				free(oldname);
				free(newname);
			}
			break;
		}

		case SYS_SECCOMP:
		{
			name = "sys_seccomp";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned int op */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned int flags */
			reg_t rdx = event->regs.x86->rdx;		/* const char __user * uargs */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GETRANDOM:
		{
			name = "sys_getrandom";
			reg_t rdi = event->regs.x86->rdi;		/* char __user * buf */
			reg_t rsi = event->regs.x86->rsi;		/* size_t count */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned int flags */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_MEMFD_CREATE:
		{
			name = "sys_memfd_create";
			reg_t rdi = event->regs.x86->rdi;		/* const char __user * uname_ptr */
			reg_t rsi = event->regs.x86->rsi;		/* unsigned int flags */
	
			char *fname = vmi_read_str_va(vmi, rdi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", %lu)\n",  pid, proc, name, fname, (unsigned long)rsi);
				free(fname);
			}
			break;
		}

		case SYS_KEXEC_FILE_LOAD:
		{
			name = "sys_kexec_file_load";
			reg_t rdi = event->regs.x86->rdi;		/* int kernel_fd */
			reg_t rsi = event->regs.x86->rsi;		/* int initrd_fd */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned long cmdline_len */
			reg_t r10 = event->regs.x86->r10;		/* const char __user * cmdline_ptr */
			reg_t r8 = event->regs.x86->r8;		/* unsigned long flags */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_BPF:
		{
			name = "sys_bpf";
			reg_t rdi = event->regs.x86->rdi;		/* int cmd */
			reg_t rsi = event->regs.x86->rsi;		/* union bpf_attr * attr */
			reg_t rdx = event->regs.x86->rdx;		/* unsigned int size */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_EXECVEAT:
		{
			name = "sys_execveat";
			reg_t rdi = event->regs.x86->rdi;		/* int dfd */
			reg_t rsi = event->regs.x86->rsi;		/* const char __user * filename */
			reg_t rdx = event->regs.x86->rdx;		/* const char __user *const __user * argv */
			reg_t r10 = event->regs.x86->r10;		/* const char __user *const __user * envp */
			reg_t r8 = event->regs.x86->r8;		/* int flags */

			char *fname = vmi_read_str_va(vmi, rsi, pid);
			if (NULL == fname) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (int)r8);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", 0x%"PRIx64", 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, fname, (unsigned long)rdx, (unsigned long)r10, (int)r8);
				free(fname);
			}
			break;
		}

		case SYS_USERFAULTFD:
		{
			name = "sys_userfaultfd";
			reg_t rdi = event->regs.x86->rdi;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_MEMBARRIER:
		{
			name = "sys_membarrier";
			reg_t rdi = event->regs.x86->rdi;		/* int cmd */
			reg_t rsi = event->regs.x86->rsi;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi);
			break;
		}

		case SYS_MLOCK2:
		{
			name = "sys_mlock2";
			reg_t rdi = event->regs.x86->rdi;		/* unsigned long start */
			reg_t rsi = event->regs.x86->rsi;		/* size_t len */
			reg_t rdx = event->regs.x86->rdx;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %i)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_COPY_FILE_RANGE:
		{
			name = "sys_copy_file_range";
			reg_t rdi = event->regs.x86->rdi;		/* int fd_in */
			reg_t rsi = event->regs.x86->rsi;		/* loff_t __user * off_in */
			reg_t rdx = event->regs.x86->rdx;		/* int fd_out */
			reg_t r10 = event->regs.x86->r10;		/* loff_t __user * off_out */
			reg_t r8 = event->regs.x86->r8;		/* size_t len */
			reg_t r9 = event->regs.x86->r9;		/* unsigned int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx, (unsigned long)r10, (unsigned long)r8, (unsigned long)r9);
			break;
		}

		default:
		{
			printf("pid: %u ( %s ) syscall: unmapped syscall number: %lu\n",  pid, proc, (unsigned long)syscall_number);
		}
	}
	free(proc);	/* free the memory stored by proc as it was allocated using realloc from a call to vmi_read_str_va */
}

void print_sysret_info(vmi_instance_t vmi, vmi_event_t *event) {
	/* Print the pid, process name and return value of a system call */
	reg_t syscall_return = event->regs.x86->rax;			/* get the return value out of rax */
	vmi_pid_t pid = vmi_dtb_to_pid(vmi, event->regs.x86->cr3);	/* get the pid of the process */
	char *proc = get_proc_name(vmi, pid);				/* get the process name */

	printf("pid: %u ( %s ) return: 0x%"PRIx64"\n",  pid, proc, syscall_return);
}

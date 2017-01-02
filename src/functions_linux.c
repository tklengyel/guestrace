#include <capstone/capstone.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "functions_linux.h"

struct os_functions os_functions_linux = {
	.print_syscall         = vf_linux_print_syscall,
	.print_sysret          = vf_linux_print_sysret,
	.find_syscalls_and_setup_mem_traps \
	                       = vf_linux_find_syscalls_and_setup_mem_traps,
	.set_up_sysret_handler = vf_linux_set_up_sysret_handler,
};

/*
 * The syscalls enum places all system calls in order by syscall number
 * such that we may compare syscall number stored in RAX to the enum value
 * and get a correct match.
 */
enum syscalls_linux {
	SYS_READ,			/* 0 */
	SYS_WRITE,			/* 1 */
	SYS_OPEN,			/* 2 */
	SYS_CLOSE,			/* 3 */
	SYS_STAT,			/* 4 */
	SYS_FSTAT,			/* 5 */
	SYS_LSTAT,			/* 6 */
	SYS_POLL,			/* 7 */
	SYS_LSEEK,			/* 8 */
	SYS_MMAP,			/* 9 */
	SYS_MPROTECT,			/* 10 */
	SYS_MUNMAP,			/* 11 */
	SYS_BRK,			/* 12 */
	SYS_RT_SIGACTION,		/* 13 */
	SYS_RT_SIGPROCMASK,		/* 14 */
	SYS_RT_SIGRETURN,		/* 15 */
	SYS_IOCTL,			/* 16 */
	SYS_PREAD,			/* 17 */
	SYS_PWRITE,			/* 18 */
	SYS_READV,			/* 19 */
	SYS_WRITEV,			/* 20 */
	SYS_ACCESS,			/* 21 */
	SYS_PIPE,			/* 22 */
	SYS_SELECT,			/* 23 */
	SYS_SCHED_YIELD,		/* 24 */
	SYS_MREMAP,			/* 25 */
	SYS_MSYNC,			/* 26 */
	SYS_MINCORE,			/* 27 */
	SYS_MADVISE,			/* 28 */
	SYS_SHMGET,			/* 29 */
	SYS_SHMAT,			/* 30 */
	SYS_SHMCTL,			/* 31 */
	SYS_DUP,			/* 32 */
	SYS_DUP2,			/* 33 */
	SYS_PAUSE,			/* 34 */
	SYS_NANOSLEEP,			/* 35 */
	SYS_GETITIMER,			/* 36 */
	SYS_ALARM,			/* 37 */
	SYS_SETITIMER,			/* 38 */
	SYS_GETPID,			/* 39 */
	SYS_SENDFILE,			/* 40 */
	SYS_SOCKET,			/* 41 */
	SYS_CONNECT,			/* 42 */
	SYS_ACCEPT,			/* 43 */
	SYS_SENDTO,			/* 44 */
	SYS_RECVFROM,			/* 45 */
	SYS_SENDMSG,			/* 46 */
	SYS_RECVMSG,			/* 47 */
	SYS_SHUTDOWN,			/* 48 */
	SYS_BIND,			/* 49 */
	SYS_LISTEN,			/* 50 */
	SYS_GETSOCKNAME,		/* 51 */
	SYS_GETPEERNAME,		/* 52 */
	SYS_SOCKETPAIR,			/* 53 */
	SYS_SETSOCKOPT,			/* 54 */
	SYS_GETSOCKOPT,			/* 55 */
	SYS_CLONE,			/* 56 */
	SYS_FORK,			/* 57 */
	SYS_VFORK,			/* 58 */
	SYS_EXECVE,			/* 59 */
	SYS_EXIT,			/* 60 */
	SYS_WAIT4,			/* 61 */
	SYS_KILL,			/* 62 */
	SYS_UNAME,			/* 63 */
	SYS_SEMGET,			/* 64 */
	SYS_SEMOP,			/* 65 */
	SYS_SEMCTL,			/* 66 */
	SYS_SHMDT,			/* 67 */
	SYS_MSGGET,			/* 68 */
	SYS_MSGSND,			/* 69 */
	SYS_MSGRCV,			/* 70 */
	SYS_MSGCTL,			/* 71 */
	SYS_FCNTL,			/* 72 */
	SYS_FLOCK,			/* 73 */
	SYS_FSYNC,			/* 74 */
	SYS_FDATASYNC,			/* 75 */
	SYS_TRUNCATE,			/* 76 */
	SYS_FTRUNCATE,			/* 77 */
	SYS_GETDENTS,			/* 78 */
	SYS_GETCWD,			/* 79 */
	SYS_CHDIR,			/* 80 */
	SYS_FCHDIR,			/* 81 */
	SYS_RENAME,			/* 82 */
	SYS_MKDIR,			/* 83 */
	SYS_RMDIR,			/* 84 */
	SYS_CREAT,			/* 85 */
	SYS_LINK,			/* 86 */
	SYS_UNLINK,			/* 87 */
	SYS_SYMLINK,			/* 88 */
	SYS_READLINK,			/* 89 */
	SYS_CHMOD,			/* 90 */
	SYS_FCHMOD,			/* 91 */
	SYS_CHOWN,			/* 92 */
	SYS_FCHOWN,			/* 93 */
	SYS_LCHOWN,			/* 94 */
	SYS_UMASK,			/* 95 */
	SYS_GETTIMEOFDAY,		/* 96 */
	SYS_GETRLIMIT,			/* 97 */
	SYS_GETRUSAGE,			/* 98 */
	SYS_SYSINFO,			/* 99 */
	SYS_TIMES,			/* 100 */
	SYS_PTRACE,			/* 101 */
	SYS_GETUID,			/* 102 */
	SYS_SYSLOG,			/* 103 */
	SYS_GETGID,			/* 104 */
	SYS_SETUID,			/* 105 */
	SYS_SETGID,			/* 106 */
	SYS_GETEUID,			/* 107 */
	SYS_GETEGID,			/* 108 */
	SYS_SETPGID,			/* 109 */
	SYS_GETPPID,			/* 110 */
	SYS_GETPGRP,			/* 111 */
	SYS_SETSID,			/* 112 */
	SYS_SETREUID,			/* 113 */
	SYS_SETREGID,			/* 114 */
	SYS_GETGROUPS,			/* 115 */
	SYS_SETGROUPS,			/* 116 */
	SYS_SETRESUID,			/* 117 */
	SYS_GETRESUID,			/* 118 */
	SYS_SETRESGID,			/* 119 */
	SYS_GETRESGID,			/* 120 */
	SYS_GETPGID,			/* 121 */
	SYS_SETFSUID,			/* 122 */
	SYS_SETFSGID,			/* 123 */
	SYS_GETSID,			/* 124 */
	SYS_CAPGET,			/* 125 */
	SYS_CAPSET,			/* 126 */
	SYS_RT_SIGPENDING,		/* 127 */
	SYS_RT_SIGTIMEDWAIT,		/* 128 */
	SYS_RT_SIGQUEUEINFO,		/* 129 */
	SYS_RT_SIGSUSPEND,		/* 130 */
	SYS_SIGALTSTACK,		/* 131 */
	SYS_UTIME,			/* 132 */
	SYS_MKNOD,			/* 133 */
	SYS_USELIB,			/* 134 */
	SYS_PERSONALITY,		/* 135 */
	SYS_USTAT,			/* 136 */
	SYS_STATFS,			/* 137 */
	SYS_FSTATFS,			/* 138 */
	SYS_SYSFS,			/* 139 */
	SYS_GETPRIORITY,		/* 140 */
	SYS_SETPRIORITY,		/* 141 */
	SYS_SCHED_SETPARAM,		/* 142 */
	SYS_SCHED_GETPARAM,		/* 143 */
	SYS_SCHED_SETSCHEDULER,		/* 144 */
	SYS_SCHED_GETSCHEDULER,		/* 145 */
	SYS_SCHED_GET_PRIORITY_MAX,	/* 146 */
	SYS_SCHED_GET_PRIORITY_MIN,	/* 147 */
	SYS_SCHED_RR_GET_INTERVAL,	/* 148 */
	SYS_MLOCK,			/* 149 */
	SYS_MUNLOCK,			/* 150 */
	SYS_MLOCKALL,			/* 151 */
	SYS_MUNLOCKALL,			/* 152 */
	SYS_VHANGUP,			/* 153 */
	SYS_MODIFY_LDT,			/* 154 */
	SYS_PIVOT_ROOT,			/* 155 */
	SYS_SYSCTL,			/* 156 */
	SYS_PRCTL,			/* 157 */
	SYS_ARCH_PRCTL,			/* 158 */
	SYS_ADJTIMEX,			/* 159 */
	SYS_SETRLIMIT,			/* 160 */
	SYS_CHROOT,			/* 161 */
	SYS_SYNC,			/* 162 */
	SYS_ACCT,			/* 163 */
	SYS_SETTIMEOFDAY,		/* 164 */
	SYS_MOUNT,			/* 165 */
	SYS_UMOUNT2,			/* 166 */
	SYS_SWAPON,			/* 167 */
	SYS_SWAPOFF,			/* 168 */
	SYS_REBOOT,			/* 169 */
	SYS_SETHOSTNAME,		/* 170 */
	SYS_SETDOMAINNAME,		/* 171 */
	SYS_IOPL,			/* 172 */
	SYS_IOPERM,			/* 173 */
	SYS_CREATE_MODULE,		/* 174 */
	SYS_INIT_MODULE,		/* 175 */
	SYS_DELETE_MODULE,		/* 176 */
	SYS_GET_KERNEL_SYMS,		/* 177 */
	SYS_QUERY_MODULE,		/* 178 */
	SYS_QUOTACTL,			/* 179 */
	SYS_NFSSERVCTL,			/* 180 */
	SYS_GETPMSG,			/* 181 */
	SYS_PUTPMSG,			/* 182 */
	SYS_AFS_SYSCALL,		/* 183 */
	SYS_TUXCALL,			/* 184 */
	SYS_SECURITY,			/* 185 */
	SYS_GETTID,			/* 186 */
	SYS_READAHEAD,			/* 187 */
	SYS_SETXATTR,			/* 188 */
	SYS_LSETXATTR,			/* 189 */
	SYS_FSETXATTR,			/* 190 */
	SYS_GETXATTR,			/* 191 */
	SYS_LGETXATTR,			/* 192 */
	SYS_FGETXATTR,			/* 193 */
	SYS_LISTXATTR,			/* 194 */
	SYS_LLISTXATTR,			/* 195 */
	SYS_FLISTXATTR,			/* 196 */
	SYS_REMOVEXATTR,		/* 197 */
	SYS_LREMOVEXATTR,		/* 198 */
	SYS_FREMOVEXATTR,		/* 199 */
	SYS_TKILL,			/* 200 */
	SYS_TIME,			/* 201 */
	SYS_FUTEX,			/* 202 */
	SYS_SCHED_SETAFFINITY,		/* 203 */
	SYS_SCHED_GETAFFINITY,		/* 204 */
	SYS_SET_THREAD_AREA,		/* 205 */
	SYS_IO_SETUP,			/* 206 */
	SYS_IO_DESTROY,			/* 207 */
	SYS_IO_GETEVENTS,		/* 208 */
	SYS_IO_SUBMIT,			/* 209 */
	SYS_IO_CANCEL,			/* 210 */
	SYS_GET_THREAD_AREA,		/* 211 */
	SYS_LOOKUP_DCOOKIE,		/* 212 */
	SYS_EPOLL_CREATE,		/* 213 */
	SYS_EPOLL_CTL_OLD,		/* 214 */
	SYS_EPOLL_WAIT_OLD,		/* 215 */
	SYS_REMAP_FILE_PAGES,		/* 216 */
	SYS_GETDENTS64,			/* 217 */
	SYS_SET_TID_ADDRESS,		/* 218 */
	SYS_RESTART_SYSCALL,		/* 219 */
	SYS_SEMTIMEDOP,			/* 220 */
	SYS_FADVISE64,			/* 221 */
	SYS_TIMER_CREATE,		/* 222 */
	SYS_TIMER_SETTIME,		/* 223 */
	SYS_TIMER_GETTIME,		/* 224 */
	SYS_TIMER_GETOVERRUN,		/* 225 */
	SYS_TIMER_DELETE,		/* 226 */
	SYS_CLOCK_SETTIME,		/* 227 */
	SYS_CLOCK_GETTIME,		/* 228 */
	SYS_CLOCK_GETRES,		/* 229 */
	SYS_CLOCK_NANOSLEEP,		/* 230 */
	SYS_EXIT_GROUP,			/* 231 */
	SYS_EPOLL_WAIT,			/* 232 */
	SYS_EPOLL_CTL,			/* 233 */
	SYS_TGKILL,			/* 234 */
	SYS_UTIMES,			/* 235 */
	SYS_VSERVER,			/* 236 */
	SYS_MBIND,			/* 237 */
	SYS_SET_MEMPOLICY,		/* 238 */
	SYS_GET_MEMPOLICY,		/* 239 */
	SYS_MQ_OPEN,			/* 240 */
	SYS_MQ_UNLINK,			/* 241 */
	SYS_MQ_TIMEDSEND,		/* 242 */
	SYS_MQ_TIMEDRECEIVE,		/* 243 */
	SYS_MQ_NOTIFY,			/* 244 */
	SYS_MQ_GETSETATTR,		/* 245 */
	SYS_KEXEC_LOAD,			/* 246 */
	SYS_WAITID,			/* 247 */
	SYS_ADD_KEY,			/* 248 */
	SYS_REQUEST_KEY,		/* 249 */
	SYS_KEYCTL,			/* 250 */
	SYS_IOPRIO_SET,			/* 251 */
	SYS_IOPRIO_GET,			/* 252 */
	SYS_INOTIFY_INIT,		/* 253 */
	SYS_INOTIFY_ADD_WATCH,		/* 254 */
	SYS_INOTIFY_RM_WATCH,		/* 255 */
	SYS_MIGRATE_PAGES,		/* 256 */
	SYS_OPENAT,			/* 257 */
	SYS_MKDIRAT,			/* 258 */
	SYS_MKNODAT,			/* 259 */
	SYS_FCHOWNAT,			/* 260 */
	SYS_FUTIMESAT,			/* 261 */
	SYS_NEWFSTATAT,			/* 262 */
	SYS_UNLINKAT,			/* 263 */
	SYS_RENAMEAT,			/* 264 */
	SYS_LINKAT,			/* 265 */
	SYS_SYMLINKAT,			/* 266 */
	SYS_READLINKAT,			/* 267 */
	SYS_FCHMODAT,			/* 268 */
	SYS_FACCESSAT,			/* 269 */
	SYS_PSELECT6,			/* 270 */
	SYS_PPOLL,			/* 271 */
	SYS_UNSHARE,			/* 272 */
	SYS_SET_ROBUST_LIST,		/* 273 */
	SYS_GET_ROBUST_LIST,		/* 274 */
	SYS_SPLICE,			/* 275 */
	SYS_TEE,			/* 276 */
	SYS_SYNC_FILE_RANGE,		/* 277 */
	SYS_VMSPLICE,			/* 278 */
	SYS_MOVE_PAGES,			/* 279 */
	SYS_UTIMENSAT,			/* 280 */
	SYS_EPOLL_PWAIT,		/* 281 */
	SYS_SIGNALFD,			/* 282 */
	SYS_TIMERFD,			/* 283 */
	SYS_EVENTFD,			/* 284 */
	SYS_FALLOCATE,			/* 285 */
	SYS_TIMERFD_SETTIME,		/* 286 */
	SYS_TIMERFD_GETTIME,		/* 287 */
	SYS_ACCEPT4,			/* 288 */
	SYS_SIGNALFD4,			/* 289 */
	SYS_EVENTFD2,			/* 290 */
	SYS_EPOLL_CREATE1,		/* 291 */
	SYS_DUP3,			/* 292 */
	SYS_PIPE2,			/* 293 */
	SYS_INOTIFY_INIT1,		/* 294 */
	SYS_PREADV,			/* 295 */
	SYS_PWRITEV,			/* 296 */
	SYS_RT_TGSIGQUEUEINFO,		/* 297 */
	SYS_PERF_EVENT_OPEN,		/* 298 */
	SYS_RECVMMSG,			/* 299 */
	SYS_FANOTIFY_INIT,		/* 300 */
	SYS_FANOTIFY_MARK,		/* 301 */
	SYS_PRLIMIT64,			/* 302 */
	SYS_NAME_TO_HANDLE_AT,		/* 303 */
	SYS_OPEN_BY_HANDLE_AT,		/* 304 */
	SYS_CLOCK_ADJTIME,		/* 305 */
	SYS_SYNCFS,			/* 306 */
	SYS_SENDMMSG,			/* 307 */
	SYS_SETNS,			/* 308 */
	SYS_GETCPU,			/* 309 */
	SYS_PROCESS_VM_READV,		/* 310 */
	SYS_PROCESS_VM_WRITEV,		/* 311 */
	SYS_KCMP,			/* 312 */
	SYS_FINIT_MODULE,		/* 313 */
	SYS_SCHED_SETATTR,		/* 314 */
	SYS_SCHED_GETATTR,		/* 315 */
	SYS_RENAMEAT2,			/* 316 */
	SYS_SECCOMP,			/* 317 */
	SYS_GETRANDOM,			/* 318 */
	SYS_MEMFD_CREATE,		/* 319 */
	SYS_KEXEC_FILE_LOAD,		/* 320 */
	SYS_BPF,			/* 321 */
	SYS_EXECVEAT,			/* 322 */
	SYS_USERFAULTFD,		/* 323 */
	SYS_MEMBARRIER,			/* 324 */
	SYS_MLOCK2,			/* 325 */
	SYS_COPY_FILE_RANGE,		/* 326 */
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

void 
vf_linux_print_syscall(vmi_instance_t vmi, vmi_event_t *event, uint16_t syscall_num) 
{
	/* 
 	 *  This function is used to translate the 
 	 *  raw values found in registers on a syscall to a readable string
 	 *  that is printed to stdout. It displays the PID, Process name,
 	 *  and the syscall name with all of its arguments formatted to 
 	 *  show as an integer, hex value or string if possible.
 	 */

	/* Every case will make use of the following values */
	char *name;							/* stores the syscall name */
	reg_t syscall_number = event->x86_regs->rax;			/* stores the syscall number from rax */
	vmi_pid_t pid = vmi_dtb_to_pid(vmi, event->x86_regs->cr3);	/* stores the PID of the process making a syscall */
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
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			reg_t rsi = event->x86_regs->rsi;		/* char __user * buf */
			reg_t rdx = event->x86_regs->rdx;		/* size_t count */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_WRITE:
		{
			name = "sys_write";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * buf */
			reg_t rdx = event->x86_regs->rdx;		/* size_t count */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_OPEN:
		{
			name = "sys_open";
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * filename */	
			reg_t rsi = event->x86_regs->rsi;		/* int flags */
			reg_t rdx = event->x86_regs->rdx;		/* umode_t mode */

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
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_STAT:
		{
			name = "sys_stat";
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * filename */
			reg_t rsi = event->x86_regs->rsi;		/* struct __old_kernel_stat __user * statbuf */

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
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			reg_t rsi = event->x86_regs->rsi;		/* struct __old_kernel_stat __user * statbuf */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_LSTAT:
		{
			name = "sys_lstat";
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * filename */
			reg_t rsi = event->x86_regs->rsi;		/* struct __old_kernel_stat __user * statbuf */

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
			reg_t rdi = event->x86_regs->rdi;		/* struct pollfd __user * ufds */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned int nfds */
			reg_t rdx = event->x86_regs->rdx;		/* int timeout */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu, %i)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_LSEEK:
		{
			name = "sys_lseek";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			reg_t rsi = event->x86_regs->rsi;		/* off_t offset */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned int whence */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_MMAP:
		{
			name = "sys_mmap";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long arg1 */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned long arg2 */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long arg3 */
			reg_t r10 = event->x86_regs->r10;		/* unsigned long arg4 */
			reg_t r8 = event->x86_regs->r8;		/* unsigned long arg5 */
			reg_t r9 = event->x86_regs->r9;		/* unsigned long arg6 */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu, %i, %i, %i, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (int)rdx, (int)r10, (int)r8, (unsigned long)r9);
			break;
		}

		case SYS_MPROTECT:
		{
			name = "sys_mprotect";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long start */
			reg_t rsi = event->x86_regs->rsi;		/* size_t len */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long prot */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_MUNMAP:
		{
			name = "sys_munmap";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long addr */
			reg_t rsi = event->x86_regs->rsi;		/* size_t len */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_BRK:
		{
			name = "sys_brk";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long brk */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_RT_SIGACTION:
		{
			name = "sys_rt_sigaction";
			reg_t rdi = event->x86_regs->rdi;		/*  int arg1 */
			reg_t rsi = event->x86_regs->rsi;		/* const struct sigaction __user * arg2 */
			reg_t rdx = event->x86_regs->rdx;		/* struct sigaction __user * arg3 */
			reg_t r10 = event->x86_regs->r10;		/*  size_t */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_RT_SIGPROCMASK:
		{
			name = "sys_rt_sigprocmask";
			reg_t rdi = event->x86_regs->rdi;		/* int how */
			reg_t rsi = event->x86_regs->rsi;		/* sigset_t __user * set */
			reg_t rdx = event->x86_regs->rdx;		/* sigset_t __user * oset */
			reg_t r10 = event->x86_regs->r10;		/* size_t sigsetsize */
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
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned int cmd */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long arg */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_PREAD:
		{
			name = "sys_pread";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			reg_t rsi = event->x86_regs->rsi;		/* char __user * buf */
			reg_t rdx = event->x86_regs->rdx;		/* size_t count */
			reg_t r10 = event->x86_regs->r10;		/* loff_t pos */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu, %li)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (long int)r10);
			break;
		}

		case SYS_PWRITE:
		{
			name = "sys_pwrite";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * buf */
			reg_t rdx = event->x86_regs->rdx;		/* size_t count */
			reg_t r10 = event->x86_regs->r10;		/* loff_t pos */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu, %li)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (long int)r10);
			break;
		}

		case SYS_READV:
		{
			name = "sys_readv";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long fd */
			reg_t rsi = event->x86_regs->rsi;		/* const struct iovec __user * vec */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long vlen */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_WRITEV:
		{
			name = "sys_writev";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long fd */
			reg_t rsi = event->x86_regs->rsi;		/* const struct iovec __user * vec */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long vlen */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_ACCESS:
		{
			name = "sys_access";
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * filename */
			reg_t rsi = event->x86_regs->rsi;		/* int mode */

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
			reg_t rdi = event->x86_regs->rdi;		/* int __user * fildes */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_SELECT:
		{
			name = "sys_select";
			reg_t rdi = event->x86_regs->rdi;		/* int n */
			reg_t rsi = event->x86_regs->rsi;		/* fd_set __user * inp */
			reg_t rdx = event->x86_regs->rdx;		/* fd_set __user * outp */
			reg_t r10 = event->x86_regs->r10;		/* fd_set __user * exp */
			reg_t r8 = event->x86_regs->r8;		/* struct timeval __user * tvp */
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
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long addr */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned long old_len */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long new_len */
			reg_t r10 = event->x86_regs->r10;		/* unsigned long flags */
			reg_t r8 = event->x86_regs->r8;		/* unsigned long new_addr */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_MSYNC:
		{
			name = "sys_msync";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long start */
			reg_t rsi = event->x86_regs->rsi;		/* size_t len */
			reg_t rdx = event->x86_regs->rdx;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %i)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_MINCORE:
		{
			name = "sys_mincore";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long start */
			reg_t rsi = event->x86_regs->rsi;		/* size_t len */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned char __user * vec */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_MADVISE:
		{
			name = "sys_madvise";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long start */
			reg_t rsi = event->x86_regs->rsi;		/* size_t len */
			reg_t rdx = event->x86_regs->rdx;		/* int behavior */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %i)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_SHMGET:
		{
			name = "sys_shmget";
			reg_t rdi = event->x86_regs->rdi;		/* key_t key */
			reg_t rsi = event->x86_regs->rsi;		/* size_t size */
			reg_t rdx = event->x86_regs->rdx;		/* int flag */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_SHMAT:
		{
			name = "sys_shmat";
			reg_t rdi = event->x86_regs->rdi;		/* int shmid */
			reg_t rsi = event->x86_regs->rsi;		/* char __user * shmaddr */
			reg_t rdx = event->x86_regs->rdx;		/* int shmflg */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_SHMCTL:
		{
			name = "sys_shmctl";
			reg_t rdi = event->x86_regs->rdi;		/* int shmid */
			reg_t rsi = event->x86_regs->rsi;		/* int cmd */
			reg_t rdx = event->x86_regs->rdx;		/* struct shmid_ds __user * buf */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_DUP:
		{
			name = "sys_dup";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fildes */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_DUP2:
		{
			name = "sys_dup2";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int oldfd */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned int newfd */
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
			reg_t rdi = event->x86_regs->rdi;		/* struct timespec __user * rqtp */
			reg_t rsi = event->x86_regs->rsi;		/* struct timespec __user * rmtp */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_GETITIMER:
		{
			name = "sys_getitimer";
			reg_t rdi = event->x86_regs->rdi;		/* int which */
			reg_t rsi = event->x86_regs->rsi;		/* struct itimerval __user * value */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_ALARM:
		{
			name = "sys_alarm";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int seconds */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_SETITIMER:
		{
			name = "sys_setitimer";
			reg_t rdi = event->x86_regs->rdi;		/* int which */
			reg_t rsi = event->x86_regs->rsi;		/* struct itimerval __user * value */
			reg_t rdx = event->x86_regs->rdx;		/* struct itimerval __user * ovalue */
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
			reg_t rdi = event->x86_regs->rdi;		/* int out_fd */
			reg_t rsi = event->x86_regs->rsi;		/* int in_fd */
			reg_t rdx = event->x86_regs->rdx;		/* off_t __user * offset */
			reg_t r10 = event->x86_regs->r10;		/* size_t count */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_SOCKET:
		{
			name = "sys_socket";
			reg_t rdi = event->x86_regs->rdi;		/*  int arg1 */
			reg_t rsi = event->x86_regs->rsi;		/*  int arg2 */
			reg_t rdx = event->x86_regs->rdx;		/*  int arg3 */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx);
			break;
		}

		case SYS_CONNECT:
		{
			name = "sys_connect";
			reg_t rdi = event->x86_regs->rdi;		/*  int arg1 */
			reg_t rsi = event->x86_regs->rsi;		/* struct sockaddr __user * arg2 */
			reg_t rdx = event->x86_regs->rdx;		/*  int arg3 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_ACCEPT:
		{
			name = "sys_accept";
			reg_t rdi = event->x86_regs->rdi;		/*  int arg1 */
			reg_t rsi = event->x86_regs->rsi;		/* struct sockaddr __user * arg2 */
			reg_t rdx = event->x86_regs->rdx;		/* int __user * arg3 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SENDTO:
		{
			name = "sys_sendto";
			reg_t rdi = event->x86_regs->rdi;		/*  int arg1 */
			reg_t rsi = event->x86_regs->rsi;		/* void __user * arg2 */
			reg_t rdx = event->x86_regs->rdx;		/*  size_t */
			reg_t r10 = event->x86_regs->r10;		/*  unsigned */
			reg_t r8 = event->x86_regs->r8;		/* struct sockaddr __user * arg5 */
			reg_t r9 = event->x86_regs->r9;		/*  int arg6 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8, (int)r9);
			break;
		}

		case SYS_RECVFROM:
		{
			name = "sys_recvfrom";
			reg_t rdi = event->x86_regs->rdi;		/*  int arg1 */
			reg_t rsi = event->x86_regs->rsi;		/* void __user * arg2 */
			reg_t rdx = event->x86_regs->rdx;		/*  size_t */
			reg_t r10 = event->x86_regs->r10;		/*  unsigned */
			reg_t r8 = event->x86_regs->r8;		/* struct sockaddr __user * arg5 */
			reg_t r9 = event->x86_regs->r9;		/* int __user * arg6 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8, (unsigned long)r9);
			break;
		}

		case SYS_SENDMSG:
		{
			name = "sys_sendmsg";
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* struct user_msghdr __user * msg */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_RECVMSG:
		{
			name = "sys_recvmsg";
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* struct user_msghdr __user * msg */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SHUTDOWN:
		{
			name = "sys_shutdown";
			reg_t rdi = event->x86_regs->rdi;		/*  int arg1 */
			reg_t rsi = event->x86_regs->rsi;		/*  int arg2 */
			printf("pid: %u ( %s ) syscall: %s(%i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi);
			break;
		}

		case SYS_BIND:
		{
			name = "sys_bind";
			reg_t rdi = event->x86_regs->rdi;		/*  int arg1 */
			reg_t rsi = event->x86_regs->rsi;		/* struct sockaddr __user * arg2 */
			reg_t rdx = event->x86_regs->rdx;		/*  int arg3 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_LISTEN:
		{
			name = "sys_listen";
			reg_t rdi = event->x86_regs->rdi;		/*  int arg1 */
			reg_t rsi = event->x86_regs->rsi;		/*  int arg2 */
			printf("pid: %u ( %s ) syscall: %s(%i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi);
			break;
		}

		case SYS_GETSOCKNAME:
		{
			name = "sys_getsockname";
			reg_t rdi = event->x86_regs->rdi;		/*  int arg1 */
			reg_t rsi = event->x86_regs->rsi;		/* struct sockaddr __user * arg2 */
			reg_t rdx = event->x86_regs->rdx;		/* int __user * arg3 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GETPEERNAME:
		{
			name = "sys_getpeername";
			reg_t rdi = event->x86_regs->rdi;		/*  int arg1 */
			reg_t rsi = event->x86_regs->rsi;		/* struct sockaddr __user * arg2 */
			reg_t rdx = event->x86_regs->rdx;		/* int __user * arg3 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SOCKETPAIR:
		{
			name = "sys_socketpair";
			reg_t rdi = event->x86_regs->rdi;		/*  int arg1 */
			reg_t rsi = event->x86_regs->rsi;		/*  int arg2 */
			reg_t rdx = event->x86_regs->rdx;		/*  int arg3 */
			reg_t r10 = event->x86_regs->r10;		/* int __user * arg4 */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx, (unsigned long)r10);
			break;
		}

		case SYS_SETSOCKOPT:
		{
			name = "sys_setsockopt";
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* int level */
			reg_t rdx = event->x86_regs->rdx;		/* int optname */
			reg_t r10 = event->x86_regs->r10;		/* char __user * optval */
			reg_t r8 = event->x86_regs->r8;		/* int optlen */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i, 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx, (unsigned long)r10, (int)r8);
			break;
		}

		case SYS_GETSOCKOPT:
		{
			name = "sys_getsockopt";
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* int level */
			reg_t rdx = event->x86_regs->rdx;		/* int optname */
			reg_t r10 = event->x86_regs->r10;		/* char __user * optval */
			reg_t r8 = event->x86_regs->r8;		/* int __user * optlen */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_CLONE:
		{
			name = "sys_clone";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long flags */
			reg_t rsi = event->x86_regs->rsi;		/* void *child_stack */
			reg_t rdx = event->x86_regs->rdx;		/* void *ptid */
			reg_t r10 = event->x86_regs->r10;		/* void *ctid */
			reg_t r8 = event->x86_regs->r8;		/* struct pt_retgs *regs */
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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * filename */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user *const __user * argv */
			reg_t rdx = event->x86_regs->rdx;		/* const char __user *const __user * envp */
			
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
			reg_t rdi = event->x86_regs->rdi;		/* int error_code */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_WAIT4:
		{
			name = "sys_wait4";
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid */
			reg_t rsi = event->x86_regs->rsi;		/* int __user * stat_addr */
			reg_t rdx = event->x86_regs->rdx;		/* int options */
			reg_t r10 = event->x86_regs->r10;		/* struct rusage __user * ru */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx, (unsigned long)r10);
			break;
		}

		case SYS_KILL:
		{
			name = "sys_kill";
			reg_t rdi = event->x86_regs->rdi;		/* int pid */
			reg_t rsi = event->x86_regs->rsi;		/* int sig */
			printf("pid: %u ( %s ) syscall: %s(%i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi);
			break;
		}

		case SYS_UNAME:
		{
			name = "sys_uname";
			reg_t rdi = event->x86_regs->rdi;		/* struct old_utsname __user * arg1 */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_SEMGET:
		{
			name = "sys_semget";
			reg_t rdi = event->x86_regs->rdi;		/* key_t key */
			reg_t rsi = event->x86_regs->rsi;		/* int nsems */
			reg_t rdx = event->x86_regs->rdx;		/* int semflg */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx);
			break;
		}

		case SYS_SEMOP:
		{
			name = "sys_semop";
			reg_t rdi = event->x86_regs->rdi;		/* int semid */
			reg_t rsi = event->x86_regs->rsi;		/* struct sembuf __user * sops */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned nsops */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SEMCTL:
		{
			name = "sys_semctl";
			reg_t rdi = event->x86_regs->rdi;		/* int semid */
			reg_t rsi = event->x86_regs->rsi;		/* int semnum */
			reg_t rdx = event->x86_regs->rdx;		/* int cmd */
			reg_t r10 = event->x86_regs->r10;		/* unsigned long arg */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i, %lu)\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx, (unsigned long)r10);
			break;
		}

		case SYS_SHMDT:
		{
			name = "sys_shmdt";
			reg_t rdi = event->x86_regs->rdi;		/* char __user * shmaddr */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_MSGGET:
		{
			name = "sys_msgget";
			reg_t rdi = event->x86_regs->rdi;		/* key_t key */
			reg_t rsi = event->x86_regs->rsi;		/* int msgflg */
			printf("pid: %u ( %s ) syscall: %s(%i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi);
			break;
		}

		case SYS_MSGSND:
		{
			name = "sys_msgsnd";
			reg_t rdi = event->x86_regs->rdi;		/* int msqid */
			reg_t rsi = event->x86_regs->rsi;		/* struct msgbuf __user * msgp */
			reg_t rdx = event->x86_regs->rdx;		/* size_t msgsz */
			reg_t r10 = event->x86_regs->r10;		/* int msgflg */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (int)r10);
			break;
		}

		case SYS_MSGRCV:
		{
			name = "sys_msgrcv";
			reg_t rdi = event->x86_regs->rdi;		/* int msqid */
			reg_t rsi = event->x86_regs->rsi;		/* struct msgbuf __user * msgp */
			reg_t rdx = event->x86_regs->rdx;		/* size_t msgsz */
			reg_t r10 = event->x86_regs->r10;		/* long msgtyp */
			reg_t r8 = event->x86_regs->r8;		/* int msgflg */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, %li, %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (long int)r10, (int)r8);
			break;
		}

		case SYS_MSGCTL:
		{
			name = "sys_msgctl";
			reg_t rdi = event->x86_regs->rdi;		/* int msqid */
			reg_t rsi = event->x86_regs->rsi;		/* int cmd */
			reg_t rdx = event->x86_regs->rdx;		/* struct msqid_ds __user * buf */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_FCNTL:
		{
			name = "sys_fcntl";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned int cmd */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long arg */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_FLOCK:
		{
			name = "sys_flock";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned int cmd */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_FSYNC:
		{
			name = "sys_fsync";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_FDATASYNC:
		{
			name = "sys_fdatasync";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_TRUNCATE:
		{
			name = "sys_truncate";
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * path */
			reg_t rsi = event->x86_regs->rsi;		/* long length */

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
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned long length */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_GETDENTS:
		{
			name = "sys_getdents";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			reg_t rsi = event->x86_regs->rsi;		/* struct linux_dirent __user * dirent */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned int count */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GETCWD:
		{
			name = "sys_getcwd";
			reg_t rdi = event->x86_regs->rdi;		/* char __user * buf */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned long size */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_CHDIR:
		{
			name = "sys_chdir";
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * filename */

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
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_RENAME:
		{
			name = "sys_rename";
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * oldname */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * newname */

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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * pathname */
			reg_t rsi = event->x86_regs->rsi;		/* umode_t mode */
			
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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * pathname */

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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * pathname */
			reg_t rsi = event->x86_regs->rsi;		/* umode_t mode */

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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * oldname */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * newname */
			
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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * pathname */
			
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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * old */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * new */
			
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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * path */
			reg_t rsi = event->x86_regs->rsi;		/* char __user * buf */
			reg_t rdx = event->x86_regs->rdx;		/* int bufsiz */

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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * filename */
			reg_t rsi = event->x86_regs->rsi;		/* umode_t mode */

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
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			reg_t rsi = event->x86_regs->rsi;		/* umode_t mode */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_CHOWN:
		{
			name = "sys_chown";
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * filename */
			reg_t rsi = event->x86_regs->rsi;		/* uid_t user */
			reg_t rdx = event->x86_regs->rdx;		/* gid_t group */

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
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			reg_t rsi = event->x86_regs->rsi;		/* uid_t user */
			reg_t rdx = event->x86_regs->rdx;		/* gid_t group */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_LCHOWN:
		{
			name = "sys_lchown";
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * filename */
			reg_t rsi = event->x86_regs->rsi;		/* uid_t user */
			reg_t rdx = event->x86_regs->rdx;		/* gid_t group */
			
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
			reg_t rdi = event->x86_regs->rdi;		/* int mask */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_GETTIMEOFDAY:
		{
			name = "sys_gettimeofday";
			reg_t rdi = event->x86_regs->rdi;		/* struct timeval __user * tv */
			reg_t rsi = event->x86_regs->rsi;		/* struct timezone __user * tz */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_GETRLIMIT:
		{
			name = "sys_getrlimit";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int resource */
			reg_t rsi = event->x86_regs->rsi;		/* struct rlimit __user * rlim */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_GETRUSAGE:
		{
			name = "sys_getrusage";
			reg_t rdi = event->x86_regs->rdi;		/* int who */
			reg_t rsi = event->x86_regs->rsi;		/* struct rusage __user * ru */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_SYSINFO:
		{
			name = "sys_sysinfo";
			reg_t rdi = event->x86_regs->rdi;		/* struct sysinfo __user * info */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_TIMES:
		{
			name = "sys_times";
			reg_t rdi = event->x86_regs->rdi;		/* struct tms __user * tbuf */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_PTRACE:
		{
			name = "sys_ptrace";
			reg_t rdi = event->x86_regs->rdi;		/* long request */
			reg_t rsi = event->x86_regs->rsi;		/* long pid */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long addr */
			reg_t r10 = event->x86_regs->r10;		/* unsigned long data */
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
			reg_t rdi = event->x86_regs->rdi;		/* int type */
			reg_t rsi = event->x86_regs->rsi;		/* char __user * buf */
			reg_t rdx = event->x86_regs->rdx;		/* int len */
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
			reg_t rdi = event->x86_regs->rdi;		/* uid_t uid */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_SETGID:
		{
			name = "sys_setgid";
			reg_t rdi = event->x86_regs->rdi;		/* gid_t gid */
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
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid */
			reg_t rsi = event->x86_regs->rsi;		/* pid_t pgid */
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
			reg_t rdi = event->x86_regs->rdi;		/* uid_t ruid */
			reg_t rsi = event->x86_regs->rsi;		/* uid_t euid */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_SETREGID:
		{
			name = "sys_setregid";
			reg_t rdi = event->x86_regs->rdi;		/* gid_t rgid */
			reg_t rsi = event->x86_regs->rsi;		/* gid_t egid */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_GETGROUPS:
		{
			name = "sys_getgroups";
			reg_t rdi = event->x86_regs->rdi;		/* int gidsetsize */
			reg_t rsi = event->x86_regs->rsi;		/* gid_t __user * grouplist */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_SETGROUPS:
		{
			name = "sys_setgroups";
			reg_t rdi = event->x86_regs->rdi;		/* int gidsetsize */
			reg_t rsi = event->x86_regs->rsi;		/* gid_t __user * grouplist */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_SETRESUID:
		{
			name = "sys_setresuid";
			reg_t rdi = event->x86_regs->rdi;		/* uid_t ruid */
			reg_t rsi = event->x86_regs->rsi;		/* uid_t euid */
			reg_t rdx = event->x86_regs->rdx;		/* uid_t suid */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GETRESUID:
		{
			name = "sys_getresuid";
			reg_t rdi = event->x86_regs->rdi;		/* uid_t __user * ruid */
			reg_t rsi = event->x86_regs->rsi;		/* uid_t __user * euid */
			reg_t rdx = event->x86_regs->rdx;		/* uid_t __user * suid */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SETRESGID:
		{
			name = "sys_setresgid";
			reg_t rdi = event->x86_regs->rdi;		/* gid_t rgid */
			reg_t rsi = event->x86_regs->rsi;		/* gid_t egid */
			reg_t rdx = event->x86_regs->rdx;		/* gid_t sgid */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GETRESGID:
		{
			name = "sys_getresgid";
			reg_t rdi = event->x86_regs->rdi;		/* gid_t __user * rgid */
			reg_t rsi = event->x86_regs->rsi;		/* gid_t __user * egid */
			reg_t rdx = event->x86_regs->rdx;		/* gid_t __user * sgid */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GETPGID:
		{
			name = "sys_getpgid";
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_SETFSUID:
		{
			name = "sys_setfsuid";
			reg_t rdi = event->x86_regs->rdi;		/* uid_t uid */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_SETFSGID:
		{
			name = "sys_setfsgid";
			reg_t rdi = event->x86_regs->rdi;		/* gid_t gid */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_GETSID:
		{
			name = "sys_getsid";
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_CAPGET:
		{
			name = "sys_capget";
			reg_t rdi = event->x86_regs->rdi;		/* cap_user_header_t header */
			reg_t rsi = event->x86_regs->rsi;		/* cap_user_data_t dataptr */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_CAPSET:
		{
			name = "sys_capset";
			reg_t rdi = event->x86_regs->rdi;		/* cap_user_header_t header */
			reg_t rsi = event->x86_regs->rsi;		/* const cap_user_data_t data */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_RT_SIGPENDING:
		{
			name = "sys_rt_sigpending";
			reg_t rdi = event->x86_regs->rdi;		/* sigset_t __user * set */
			reg_t rsi = event->x86_regs->rsi;		/* size_t sigsetsize */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_RT_SIGTIMEDWAIT:
		{
			name = "sys_rt_sigtimedwait";
			reg_t rdi = event->x86_regs->rdi;		/* const sigset_t __user * uthese */
			reg_t rsi = event->x86_regs->rsi;		/* siginfo_t __user * uinfo */
			reg_t rdx = event->x86_regs->rdx;		/* const struct timespec __user * uts */
			reg_t r10 = event->x86_regs->r10;		/* size_t sigsetsize */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_RT_SIGQUEUEINFO:
		{
			name = "sys_rt_sigqueueinfo";
			reg_t rdi = event->x86_regs->rdi;		/* int pid */
			reg_t rsi = event->x86_regs->rsi;		/* int sig */
			reg_t rdx = event->x86_regs->rdx;		/* siginfo_t __user * uinfo */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_RT_SIGSUSPEND:
		{
			name = "sys_rt_sigsuspend";
			reg_t rdi = event->x86_regs->rdi;		/* sigset_t __user * unewset */
			reg_t rsi = event->x86_regs->rsi;		/* size_t sigsetsize */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_SIGALTSTACK:
		{
			name = "sys_sigaltstack";
			reg_t rdi = event->x86_regs->rdi;		/* const struct sigaltstack __user * uss */
			reg_t rsi = event->x86_regs->rsi;		/* struct sigaltstack __user * uoss */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_UTIME:
		{
			name = "sys_utime";
			reg_t rdi = event->x86_regs->rdi;		/* char __user * filename */
			reg_t rsi = event->x86_regs->rsi;		/* struct utimbuf __user * times */
			
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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * filename */
			reg_t rsi = event->x86_regs->rsi;		/* umode_t mode */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned dev */

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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * library */
			
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
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int personality */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_USTAT:
		{
			name = "sys_ustat";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned dev */
			reg_t rsi = event->x86_regs->rsi;		/* struct ustat __user * ubuf */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_STATFS:
		{
			name = "sys_statfs";
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * path */
			reg_t rsi = event->x86_regs->rsi;		/* struct statfs __user * buf */
			
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
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			reg_t rsi = event->x86_regs->rsi;		/* struct statfs __user * buf */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_SYSFS:
		{
			name = "sys_sysfs";
			reg_t rdi = event->x86_regs->rdi;		/* int option */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned long arg1 */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long arg2 */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GETPRIORITY:
		{
			name = "sys_getpriority";
			reg_t rdi = event->x86_regs->rdi;		/* int which */
			reg_t rsi = event->x86_regs->rsi;		/* int who */
			printf("pid: %u ( %s ) syscall: %s(%i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi);
			break;
		}

		case SYS_SETPRIORITY:
		{
			name = "sys_setpriority";
			reg_t rdi = event->x86_regs->rdi;		/* int which */
			reg_t rsi = event->x86_regs->rsi;		/* int who */
			reg_t rdx = event->x86_regs->rdx;		/* int niceval */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx);
			break;
		}

		case SYS_SCHED_SETPARAM:
		{
			name = "sys_sched_setparam";
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid */
			reg_t rsi = event->x86_regs->rsi;		/* struct sched_param __user * param */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_SCHED_GETPARAM:
		{
			name = "sys_sched_getparam";
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid */
			reg_t rsi = event->x86_regs->rsi;		/* struct sched_param __user * param */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_SCHED_SETSCHEDULER:
		{
			name = "sys_sched_setscheduler";
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid */
			reg_t rsi = event->x86_regs->rsi;		/* int policy */
			reg_t rdx = event->x86_regs->rdx;		/* struct sched_param __user * param */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SCHED_GETSCHEDULER:
		{
			name = "sys_sched_getscheduler";
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_SCHED_GET_PRIORITY_MAX:
		{
			name = "sys_sched_get_priority_max";
			reg_t rdi = event->x86_regs->rdi;		/* int policy */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_SCHED_GET_PRIORITY_MIN:
		{
			name = "sys_sched_get_priority_min";
			reg_t rdi = event->x86_regs->rdi;		/* int policy */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_SCHED_RR_GET_INTERVAL:
		{
			name = "sys_sched_rr_get_interval";
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid */
			reg_t rsi = event->x86_regs->rsi;		/* struct timespec __user * interval */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_MLOCK:
		{
			name = "sys_mlock";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long start */
			reg_t rsi = event->x86_regs->rsi;		/* size_t len */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_MUNLOCK:
		{
			name = "sys_munlock";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long start */
			reg_t rsi = event->x86_regs->rsi;		/* size_t len */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_MLOCKALL:
		{
			name = "sys_mlockall";
			reg_t rdi = event->x86_regs->rdi;		/* int flags */
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
			reg_t rdi = event->x86_regs->rdi;		/*  int arg1 */
			reg_t rsi = event->x86_regs->rsi;		/* void __user * arg2 */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long arg3 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_PIVOT_ROOT:
		{
			name = "sys_pivot_root";
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * new_root */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * put_old */

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
			reg_t rdi = event->x86_regs->rdi;		/* struct __sysctl_args __user * args */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_PRCTL:
		{
			name = "sys_prctl";
			reg_t rdi = event->x86_regs->rdi;		/* int option */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned long arg2 */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long arg3 */
			reg_t r10 = event->x86_regs->r10;		/* unsigned long arg4 */
			reg_t r8 = event->x86_regs->r8;		/* unsigned long arg5 */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, %lu, %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_ARCH_PRCTL:
		{
			name = "sys_arch_prctl";
			reg_t rdi = event->x86_regs->rdi;		/*  int arg1 */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned long arg2 */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_ADJTIMEX:
		{
			name = "sys_adjtimex";
			reg_t rdi = event->x86_regs->rdi;		/* struct timex __user * txc_p */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_SETRLIMIT:
		{
			name = "sys_setrlimit";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int resource */
			reg_t rsi = event->x86_regs->rsi;		/* struct rlimit __user * rlim */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_CHROOT:
		{
			name = "sys_chroot";
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * filename */

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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * name */

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
			reg_t rdi = event->x86_regs->rdi;		/* struct timeval __user * tv */
			reg_t rsi = event->x86_regs->rsi;		/* struct timezone __user * tz */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_MOUNT:
		{
			name = "sys_mount";
			reg_t rdi = event->x86_regs->rdi;		/* char __user * dev_name */
			reg_t rsi = event->x86_regs->rsi;		/* char __user * dir_name */
			reg_t rdx = event->x86_regs->rdx;		/* char __user * type */
			reg_t r10 = event->x86_regs->r10;		/* unsigned long flags */
			reg_t r8 = event->x86_regs->r8;		/* void __user * data */

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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * specialfile */
			reg_t rsi = event->x86_regs->rsi;		/* int swap_flags */

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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * specialfile */
			
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
			reg_t rdi = event->x86_regs->rdi;		/* int magic1 */
			reg_t rsi = event->x86_regs->rsi;		/* int magic2 */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned int cmd */
			reg_t r10 = event->x86_regs->r10;		/* void __user * arg */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %lu, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_SETHOSTNAME:
		{
			name = "sys_sethostname";
			reg_t rdi = event->x86_regs->rdi;		/* char __user * name */
			reg_t rsi = event->x86_regs->rsi;		/* int len */

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
			reg_t rdi = event->x86_regs->rdi;		/* char __user * name */
			reg_t rsi = event->x86_regs->rsi;		/* int len */

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
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int arg1 */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_IOPERM:
		{
			name = "sys_ioperm";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long from */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned long num */
			reg_t rdx = event->x86_regs->rdx;		/* int on */
			reg_t r10 = event->x86_regs->r10;		/* unsigned long arg4 */
			reg_t r8 = event->x86_regs->r8;		/* unsigned long arg5 */
			reg_t r9 = event->x86_regs->r9;		/*  int arg6 */
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
			reg_t rdi = event->x86_regs->rdi;		/* void __user * umod */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned long len */
			reg_t rdx = event->x86_regs->rdx;		/* const char __user * uargs */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_DELETE_MODULE:
		{
			name = "sys_delete_module";
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * name_user */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned int flags */
			
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
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int cmd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * special */
			reg_t rdx = event->x86_regs->rdx;		/* qid_t id */
			reg_t r10 = event->x86_regs->r10;		/* void __user * addr */

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
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* loff_t offset */
			reg_t rdx = event->x86_regs->rdx;		/* size_t count */
			printf("pid: %u ( %s ) syscall: %s(%i, %li, %lu)\n",  pid, proc, name, (int)rdi, (long int)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SETXATTR:
		{
			name = "sys_setxattr";
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * path */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * name */
			reg_t rdx = event->x86_regs->rdx;		/* const void __user * value */
			reg_t r10 = event->x86_regs->r10;		/* size_t size */
			reg_t r8 = event->x86_regs->r8;		/* int flags */

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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * path */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * name */
			reg_t rdx = event->x86_regs->rdx;		/* const void __user * value */
			reg_t r10 = event->x86_regs->r10;		/* size_t size */
			reg_t r8 = event->x86_regs->r8;		/* int flags */
			
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
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * name */
			reg_t rdx = event->x86_regs->rdx;		/* const void __user * value */
			reg_t r10 = event->x86_regs->r10;		/* size_t size */
			reg_t r8 = event->x86_regs->r8;		/* int flags */


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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * path */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * name */
			reg_t rdx = event->x86_regs->rdx;		/* void __user * value */
			reg_t r10 = event->x86_regs->r10;		/* size_t size */

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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * path */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * name */
			reg_t rdx = event->x86_regs->rdx;		/* void __user * value */
			reg_t r10 = event->x86_regs->r10;		/* size_t size */
			
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
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * name */
			reg_t rdx = event->x86_regs->rdx;		/* void __user * value */
			reg_t r10 = event->x86_regs->r10;		/* size_t size */
		
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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * path */
			reg_t rsi = event->x86_regs->rsi;		/* char __user * list */
			reg_t rdx = event->x86_regs->rdx;		/* size_t size */

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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * path */
			reg_t rsi = event->x86_regs->rsi;		/* char __user * list */
			reg_t rdx = event->x86_regs->rdx;		/* size_t size */
			
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
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* char __user * list */
			reg_t rdx = event->x86_regs->rdx;		/* size_t size */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_REMOVEXATTR:
		{
			name = "sys_removexattr";
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * path */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * name */

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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * path */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * name */

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
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * name */

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
			reg_t rdi = event->x86_regs->rdi;		/* int pid */
			reg_t rsi = event->x86_regs->rsi;		/* int sig */
			printf("pid: %u ( %s ) syscall: %s(%i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi);
			break;
		}

		case SYS_TIME:
		{
			name = "sys_time";
			reg_t rdi = event->x86_regs->rdi;		/* time_t __user * tloc */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_FUTEX:
		{
			name = "sys_futex";
			reg_t rdi = event->x86_regs->rdi;		/* u32 __user * uaddr */
			reg_t rsi = event->x86_regs->rsi;		/* int op */
			reg_t rdx = event->x86_regs->rdx;		/* u32 val */
			reg_t r10 = event->x86_regs->r10;		/* struct timespec __user * utime */
			reg_t r8 = event->x86_regs->r8;		/* u32 __user * uaddr2 */
			reg_t r9 = event->x86_regs->r9;		/* u32 val3 */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (int)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8, (unsigned long)r9);
			break;
		}

		case SYS_SCHED_SETAFFINITY:
		{
			name = "sys_sched_setaffinity";
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned int len */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long __user * user_mask_ptr */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SCHED_GETAFFINITY:
		{
			name = "sys_sched_getaffinity";
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned int len */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long __user * user_mask_ptr */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SET_THREAD_AREA:
		{
			name = "sys_set_thread_area";
			reg_t rdi = event->x86_regs->rdi;		/* struct user_desc __user * arg1 */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_IO_SETUP:
		{
			name = "sys_io_setup";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned nr_reqs */
			reg_t rsi = event->x86_regs->rsi;		/* aio_context_t __user * ctx */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_IO_DESTROY:
		{
			name = "sys_io_destroy";
			reg_t rdi = event->x86_regs->rdi;		/* aio_context_t ctx */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_IO_GETEVENTS:
		{
			name = "sys_io_getevents";
			reg_t rdi = event->x86_regs->rdi;		/* aio_context_t ctx_id */
			reg_t rsi = event->x86_regs->rsi;		/* long min_nr */
			reg_t rdx = event->x86_regs->rdx;		/* long nr */
			reg_t r10 = event->x86_regs->r10;		/* struct io_event __user * events */
			reg_t r8 = event->x86_regs->r8;		/* struct timespec __user * timeout */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %li, %li, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (long int)rsi, (long int)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_IO_SUBMIT:
		{
			name = "sys_io_submit";
			reg_t rdi = event->x86_regs->rdi;		/*  aio_context_t */
			reg_t rsi = event->x86_regs->rsi;		/*  long arg2 */
			reg_t rdx = event->x86_regs->rdx;		/* struct iocb __user * __user * arg3 */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %li, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (long int)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_IO_CANCEL:
		{
			name = "sys_io_cancel";
			reg_t rdi = event->x86_regs->rdi;		/* aio_context_t ctx_id */
			reg_t rsi = event->x86_regs->rsi;		/* struct iocb __user * iocb */
			reg_t rdx = event->x86_regs->rdx;		/* struct io_event __user * result */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GET_THREAD_AREA:
		{
			name = "sys_get_thread_area";
			reg_t rdi = event->x86_regs->rdi;		/* struct user_desc __user * arg1 */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_LOOKUP_DCOOKIE:
		{
			name = "sys_lookup_dcookie";
			reg_t rdi = event->x86_regs->rdi;		/* u64 cookie64 */
			reg_t rsi = event->x86_regs->rsi;		/* char __user * buf */
			reg_t rdx = event->x86_regs->rdx;		/* size_t len */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_EPOLL_CREATE:
		{
			name = "sys_epoll_create";
			reg_t rdi = event->x86_regs->rdi;		/* int size */
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
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long start */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned long size */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long prot */
			reg_t r10 = event->x86_regs->r10;		/* unsigned long pgoff */
			reg_t r8 = event->x86_regs->r8;		/* unsigned long flags */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_GETDENTS64:
		{
			name = "sys_getdents64";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int fd */
			reg_t rsi = event->x86_regs->rsi;		/* struct linux_dirent64 __user * dirent */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned int count */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SET_TID_ADDRESS:
		{
			name = "sys_set_tid_address";
			reg_t rdi = event->x86_regs->rdi;		/* int __user * tidptr */
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
			reg_t rdi = event->x86_regs->rdi;		/* int semid */
			reg_t rsi = event->x86_regs->rsi;		/* struct sembuf __user * sops */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned nsops */
			reg_t r10 = event->x86_regs->r10;		/* const struct timespec __user * timeout */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_FADVISE64:
		{
			name = "sys_fadvise64";
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* loff_t offset */
			reg_t rdx = event->x86_regs->rdx;		/* size_t len */
			reg_t r10 = event->x86_regs->r10;		/* int advice */
			printf("pid: %u ( %s ) syscall: %s(%i, %li, %lu, %i)\n",  pid, proc, name, (int)rdi, (long int)rsi, (unsigned long)rdx, (int)r10);
			break;
		}

		case SYS_TIMER_CREATE:
		{
			name = "sys_timer_create";
			reg_t rdi = event->x86_regs->rdi;		/* clockid_t which_clock */
			reg_t rsi = event->x86_regs->rsi;		/* struct sigevent __user * timer_event_spec */
			reg_t rdx = event->x86_regs->rdx;		/* timer_t __user * created_timer_id */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_TIMER_SETTIME:
		{
			name = "sys_timer_settime";
			reg_t rdi = event->x86_regs->rdi;		/* timer_t timer_id */
			reg_t rsi = event->x86_regs->rsi;		/* int flags */
			reg_t rdx = event->x86_regs->rdx;		/* const struct itimerspec __user * new_setting */
			reg_t r10 = event->x86_regs->r10;		/* struct itimerspec __user * old_setting */
			printf("pid: %u ( %s ) syscall: %s(%lu, %i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (int)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_TIMER_GETTIME:
		{
			name = "sys_timer_gettime";
			reg_t rdi = event->x86_regs->rdi;		/* timer_t timer_id */
			reg_t rsi = event->x86_regs->rsi;		/* struct itimerspec __user * setting */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_TIMER_GETOVERRUN:
		{
			name = "sys_timer_getoverrun";
			reg_t rdi = event->x86_regs->rdi;		/* timer_t timer_id */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_TIMER_DELETE:
		{
			name = "sys_timer_delete";
			reg_t rdi = event->x86_regs->rdi;		/* timer_t timer_id */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_CLOCK_SETTIME:
		{
			name = "sys_clock_settime";
			reg_t rdi = event->x86_regs->rdi;		/* clockid_t which_clock */
			reg_t rsi = event->x86_regs->rsi;		/* const struct timespec __user * tp */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_CLOCK_GETTIME:
		{
			name = "sys_clock_gettime";
			reg_t rdi = event->x86_regs->rdi;		/* clockid_t which_clock */
			reg_t rsi = event->x86_regs->rsi;		/* struct timespec __user * tp */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_CLOCK_GETRES:
		{
			name = "sys_clock_getres";
			reg_t rdi = event->x86_regs->rdi;		/* clockid_t which_clock */
			reg_t rsi = event->x86_regs->rsi;		/* struct timespec __user * tp */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_CLOCK_NANOSLEEP:
		{
			name = "sys_clock_nanosleep";
			reg_t rdi = event->x86_regs->rdi;		/* clockid_t which_clock */
			reg_t rsi = event->x86_regs->rsi;		/* int flags */
			reg_t rdx = event->x86_regs->rdx;		/* const struct timespec __user * rqtp */
			reg_t r10 = event->x86_regs->r10;		/* struct timespec __user * rmtp */
			printf("pid: %u ( %s ) syscall: %s(%lu, %i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (int)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_EXIT_GROUP:
		{
			name = "sys_exit_group";
			reg_t rdi = event->x86_regs->rdi;		/* int error_code */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_EPOLL_WAIT:
		{
			name = "sys_epoll_wait";
			reg_t rdi = event->x86_regs->rdi;		/* int epfd */
			reg_t rsi = event->x86_regs->rsi;		/* struct epoll_event __user * events */
			reg_t rdx = event->x86_regs->rdx;		/* int maxevents */
			reg_t r10 = event->x86_regs->r10;		/* int timeout */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i, %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx, (int)r10);
			break;
		}

		case SYS_EPOLL_CTL:
		{
			name = "sys_epoll_ctl";
			reg_t rdi = event->x86_regs->rdi;		/* int epfd */
			reg_t rsi = event->x86_regs->rsi;		/* int op */
			reg_t rdx = event->x86_regs->rdx;		/* int fd */
			reg_t r10 = event->x86_regs->r10;		/* struct epoll_event __user * event */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx, (unsigned long)r10);
			break;
		}

		case SYS_TGKILL:
		{
			name = "sys_tgkill";
			reg_t rdi = event->x86_regs->rdi;		/* int tgid */
			reg_t rsi = event->x86_regs->rsi;		/* int pid */
			reg_t rdx = event->x86_regs->rdx;		/* int sig */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx);
			break;
		}

		case SYS_UTIMES:
		{
			name = "sys_utimes";
			reg_t rdi = event->x86_regs->rdi;		/* char __user * filename */
			reg_t rsi = event->x86_regs->rsi;		/* struct timeval __user * utimes */

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
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long start */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned long len */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long mode */
			reg_t r10 = event->x86_regs->r10;		/* const unsigned long __user * nmask */
			reg_t r8 = event->x86_regs->r8;		/* unsigned long maxnode */
			reg_t r9 = event->x86_regs->r9;		/* unsigned flags */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %lu, 0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8, (unsigned long)r9);
			break;
		}

		case SYS_SET_MEMPOLICY:
		{
			name = "sys_set_mempolicy";
			reg_t rdi = event->x86_regs->rdi;		/* int mode */
			reg_t rsi = event->x86_regs->rsi;		/* const unsigned long __user * nmask */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long maxnode */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GET_MEMPOLICY:
		{
			name = "sys_get_mempolicy";
			reg_t rdi = event->x86_regs->rdi;		/* int __user * policy */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned long __user * nmask */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long maxnode */
			reg_t r10 = event->x86_regs->r10;		/* unsigned long addr */
			reg_t r8 = event->x86_regs->r8;		/* unsigned long flags */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_MQ_OPEN:
		{
			name = "sys_mq_open";
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * name */
			reg_t rsi = event->x86_regs->rsi;		/* int oflag */
			reg_t rdx = event->x86_regs->rdx;		/* umode_t mode */
			reg_t r10 = event->x86_regs->r10;		/* struct mq_attr __user * attr */

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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * name */

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
			reg_t rdi = event->x86_regs->rdi;		/* mqd_t mqdes */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * msg_ptr */
			reg_t rdx = event->x86_regs->rdx;		/* size_t msg_len */
			reg_t r10 = event->x86_regs->r10;		/* unsigned int msg_prio */
			reg_t r8 = event->x86_regs->r8;		/* const struct timespec __user * abs_timeout */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_MQ_TIMEDRECEIVE:
		{
			name = "sys_mq_timedreceive";
			reg_t rdi = event->x86_regs->rdi;		/* mqd_t mqdes */
			reg_t rsi = event->x86_regs->rsi;		/* char __user * msg_ptr */
			reg_t rdx = event->x86_regs->rdx;		/* size_t msg_len */
			reg_t r10 = event->x86_regs->r10;		/* unsigned int __user * msg_prio */
			reg_t r8 = event->x86_regs->r8;		/* const struct timespec __user * abs_timeout */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_MQ_NOTIFY:
		{
			name = "sys_mq_notify";
			reg_t rdi = event->x86_regs->rdi;		/* mqd_t mqdes */
			reg_t rsi = event->x86_regs->rsi;		/* const struct sigevent __user * notification */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_MQ_GETSETATTR:
		{
			name = "sys_mq_getsetattr";
			reg_t rdi = event->x86_regs->rdi;		/* mqd_t mqdes */
			reg_t rsi = event->x86_regs->rsi;		/* const struct mq_attr __user * mqstat */
			reg_t rdx = event->x86_regs->rdx;		/* struct mq_attr __user * omqstat */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_KEXEC_LOAD:
		{
			name = "sys_kexec_load";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long entry */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned long nr_segments */
			reg_t rdx = event->x86_regs->rdx;		/* struct kexec_segment __user * segments */
			reg_t r10 = event->x86_regs->r10;		/* unsigned long flags */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_WAITID:
		{
			name = "sys_waitid";
			reg_t rdi = event->x86_regs->rdi;		/* int which */
			reg_t rsi = event->x86_regs->rsi;		/* pid_t pid */
			reg_t rdx = event->x86_regs->rdx;		/* struct siginfo __user * infop */
			reg_t r10 = event->x86_regs->r10;		/* int options */
			reg_t r8 = event->x86_regs->r8;		/* struct rusage __user * ru */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, 0x%"PRIx64", %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx, (int)r10, (unsigned long)r8);
			break;
		}

		case SYS_ADD_KEY:
		{
			name = "sys_add_key";
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * _type */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * _description */
			reg_t rdx = event->x86_regs->rdx;		/* const void __user * _payload */
			reg_t r10 = event->x86_regs->r10;		/* size_t plen */
			reg_t r8 = event->x86_regs->r8;		/* key_serial_t destringid */
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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * _type */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * _description */
			reg_t rdx = event->x86_regs->rdx;		/* const char __user * _callout_info */
			reg_t r10 = event->x86_regs->r10;		/* key_serial_t destringid */
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
			reg_t rdi = event->x86_regs->rdi;		/* int cmd */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned long arg2 */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long arg3 */
			reg_t r10 = event->x86_regs->r10;		/* unsigned long arg4 */
			reg_t r8 = event->x86_regs->r8;		/* unsigned long arg5 */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, %lu, %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_IOPRIO_SET:
		{
			name = "sys_ioprio_set";
			reg_t rdi = event->x86_regs->rdi;		/* int which */
			reg_t rsi = event->x86_regs->rsi;		/* int who */
			reg_t rdx = event->x86_regs->rdx;		/* int ioprio */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx);
			break;
		}

		case SYS_IOPRIO_GET:
		{
			name = "sys_ioprio_get";
			reg_t rdi = event->x86_regs->rdi;		/* int which */
			reg_t rsi = event->x86_regs->rsi;		/* int who */
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
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * path */
			reg_t rdx = event->x86_regs->rdx;		/* u32 mask */

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
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* __s32 wd */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_MIGRATE_PAGES:
		{
			name = "sys_migrate_pages";
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned long maxnode */
			reg_t rdx = event->x86_regs->rdx;		/* const unsigned long __user * from */
			reg_t r10 = event->x86_regs->r10;		/* const unsigned long __user * to */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_OPENAT:
		{
			name = "sys_openat";
			reg_t rdi = event->x86_regs->rdi;		/* int dfd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * filename */
			reg_t rdx = event->x86_regs->rdx;		/* int flags */
			reg_t r10 = event->x86_regs->r10;		/* umode_t mode */

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
			reg_t rdi = event->x86_regs->rdi;		/* int dfd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * pathname */
			reg_t rdx = event->x86_regs->rdx;		/* umode_t mode */

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
			reg_t rdi = event->x86_regs->rdi;		/* int dfd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * filename */
			reg_t rdx = event->x86_regs->rdx;		/* umode_t mode */
			reg_t r10 = event->x86_regs->r10;		/* unsigned dev */

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
			reg_t rdi = event->x86_regs->rdi;		/* int dfd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * filename */
			reg_t rdx = event->x86_regs->rdx;		/* uid_t user */
			reg_t r10 = event->x86_regs->r10;		/* gid_t group */
			reg_t r8 = event->x86_regs->r8;		/* int flag */

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
			reg_t rdi = event->x86_regs->rdi;		/* int dfd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * filename */
			reg_t rdx = event->x86_regs->rdx;		/* struct timeval __user * utimes */

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
			reg_t rdi = event->x86_regs->rdi;		/* int dfd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * filename */
			reg_t rdx = event->x86_regs->rdx;		/* struct stat __user * statbuf */
			reg_t r10 = event->x86_regs->r10;		/* int flag */

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
			reg_t rdi = event->x86_regs->rdi;		/* int dfd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * pathname */
			reg_t rdx = event->x86_regs->rdx;		/* int flag */

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
			reg_t rdi = event->x86_regs->rdi;		/* int olddfd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * oldname */
			reg_t rdx = event->x86_regs->rdx;		/* int newdfd */
			reg_t r10 = event->x86_regs->r10;		/* const char __user * newname */
			
			char *oldname = vmi_read_str_va(vmi, rsi, pid);
			char *newname = vmi_read_str_va(vmi, r10, pid);
			if (NULL == oldname || NULL == newname) {
				printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx, (unsigned long)r10);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(%i, \"%s\", %i, \"%s\")\n",  pid, proc, name, (int)rdi, oldname, (int)rdx, newname);
				free(oldname);
				free(newname);
			}
			break;
		}

		case SYS_LINKAT:
		{
			name = "sys_linkat";
			reg_t rdi = event->x86_regs->rdi;		/* int olddfd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * oldname */
			reg_t rdx = event->x86_regs->rdx;		/* int newdfd */
			reg_t r10 = event->x86_regs->r10;		/* const char __user * newname */
			reg_t r8 = event->x86_regs->r8;		/* int flags */

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
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * oldname */
			reg_t rsi = event->x86_regs->rsi;		/* int newdfd */
			reg_t rdx = event->x86_regs->rdx;		/* const char __user * newname */
			
			char *oldname = vmi_read_str_va(vmi, rdi, pid);
			char *newname = vmi_read_str_va(vmi, rdx, pid);
			if (NULL == oldname || NULL == newname) {
				printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %i, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (int)rsi, (unsigned long)rdx);
			}
			else {
				printf("pid: %u ( %s ) syscall: %s(\"%s\", %i, \"%s\")\n",  pid, proc, name, oldname, (int)rsi, newname);
				free(oldname);
				free(newname);
			}
			break;
		}

		case SYS_READLINKAT:
		{
			name = "sys_readlinkat";
			reg_t rdi = event->x86_regs->rdi;		/* int dfd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * path */
			reg_t rdx = event->x86_regs->rdx;		/* char __user * buf */
			reg_t r10 = event->x86_regs->r10;		/* int bufsiz */

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
			reg_t rdi = event->x86_regs->rdi;		/* int dfd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * filename */
			reg_t rdx = event->x86_regs->rdx;		/* umode_t mode */

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
			reg_t rdi = event->x86_regs->rdi;		/* int dfd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * filename */
			reg_t rdx = event->x86_regs->rdx;		/* int mode */

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
			reg_t rdi = event->x86_regs->rdi;		/*  int arg1 */
			reg_t rsi = event->x86_regs->rsi;		/* fd_set __user * arg2 */
			reg_t rdx = event->x86_regs->rdx;		/* fd_set __user * arg3 */
			reg_t r10 = event->x86_regs->r10;		/* fd_set __user * arg4 */
			reg_t r8 = event->x86_regs->r8;		/* struct timespec __user * arg5 */
			reg_t r9 = event->x86_regs->r9;		/* void __user * arg6 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8, (unsigned long)r9);
			break;
		}

		case SYS_PPOLL:
		{
			name = "sys_ppoll";
			reg_t rdi = event->x86_regs->rdi;		/* struct pollfd __user * arg1 */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned int arg2 */
			reg_t rdx = event->x86_regs->rdx;		/* struct timespec __user * arg3 */
			reg_t r10 = event->x86_regs->r10;		/* const sigset_t __user * arg4 */
			reg_t r8 = event->x86_regs->r8;		/*  size_t */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_UNSHARE:
		{
			name = "sys_unshare";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long unshare_flags */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_SET_ROBUST_LIST:
		{
			name = "sys_set_robust_list";
			reg_t rdi = event->x86_regs->rdi;		/* struct robust_list_head __user * head */
			reg_t rsi = event->x86_regs->rsi;		/* size_t len */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_GET_ROBUST_LIST:
		{
			name = "sys_get_robust_list";
			reg_t rdi = event->x86_regs->rdi;		/* int pid */
			reg_t rsi = event->x86_regs->rsi;		/* struct robust_list_head __user * __user * head_ptr */
			reg_t rdx = event->x86_regs->rdx;		/* size_t __user * len_ptr */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SPLICE:
		{
			name = "sys_splice";
			reg_t rdi = event->x86_regs->rdi;		/* int fd_in */
			reg_t rsi = event->x86_regs->rsi;		/* loff_t __user * off_in */
			reg_t rdx = event->x86_regs->rdx;		/* int fd_out */
			reg_t r10 = event->x86_regs->r10;		/* loff_t __user * off_out */
			reg_t r8 = event->x86_regs->r8;		/* size_t len */
			reg_t r9 = event->x86_regs->r9;		/* unsigned int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx, (unsigned long)r10, (unsigned long)r8, (unsigned long)r9);
			break;
		}

		case SYS_TEE:
		{
			name = "sys_tee";
			reg_t rdi = event->x86_regs->rdi;		/* int fdin */
			reg_t rsi = event->x86_regs->rsi;		/* int fdout */
			reg_t rdx = event->x86_regs->rdx;		/* size_t len */
			reg_t r10 = event->x86_regs->r10;		/* unsigned int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %lu, %lu)\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_SYNC_FILE_RANGE:
		{
			name = "sys_sync_file_range";
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* loff_t offset */
			reg_t rdx = event->x86_regs->rdx;		/* loff_t nbytes */
			reg_t r10 = event->x86_regs->r10;		/* unsigned int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, %li, %li, %lu)\n",  pid, proc, name, (int)rdi, (long int)rsi, (long int)rdx, (unsigned long)r10);
			break;
		}

		case SYS_VMSPLICE:
		{
			name = "sys_vmsplice";
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* const struct iovec __user * iov */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long nr_segs */
			reg_t r10 = event->x86_regs->r10;		/* unsigned int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_MOVE_PAGES:
		{
			name = "sys_move_pages";
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned long nr_pages */
			reg_t rdx = event->x86_regs->rdx;		/* const void __user * __user * pages */
			reg_t r10 = event->x86_regs->r10;		/* const int __user * nodes */
			reg_t r8 = event->x86_regs->r8;		/* int __user * status */
			reg_t r9 = event->x86_regs->r9;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8, (int)r9);
			break;
		}

		case SYS_UTIMENSAT:
		{
			name = "sys_utimensat";
			reg_t rdi = event->x86_regs->rdi;		/* int dfd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * filename */
			reg_t rdx = event->x86_regs->rdx;		/* struct timespec __user * utimes */
			reg_t r10 = event->x86_regs->r10;		/* int flags */
		
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
			reg_t rdi = event->x86_regs->rdi;		/* int epfd */
			reg_t rsi = event->x86_regs->rsi;		/* struct epoll_event __user * events */
			reg_t rdx = event->x86_regs->rdx;		/* int maxevents */
			reg_t r10 = event->x86_regs->r10;		/* int timeout */
			reg_t r8 = event->x86_regs->r8;		/* const sigset_t __user * sigmask */
			reg_t r9 = event->x86_regs->r9;		/* size_t sigsetsize */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i, %i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx, (int)r10, (unsigned long)r8, (unsigned long)r9);
			break;
		}

		case SYS_SIGNALFD:
		{
			name = "sys_signalfd";
			reg_t rdi = event->x86_regs->rdi;		/* int ufd */
			reg_t rsi = event->x86_regs->rsi;		/* sigset_t __user * user_mask */
			reg_t rdx = event->x86_regs->rdx;		/* size_t sizemask */
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
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int count */
			printf("pid: %u ( %s ) syscall: %s(%lu)\n",  pid, proc, name, (unsigned long)rdi);
			break;
		}

		case SYS_FALLOCATE:
		{
			name = "sys_fallocate";
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* int mode */
			reg_t rdx = event->x86_regs->rdx;		/* loff_t offset */
			reg_t r10 = event->x86_regs->r10;		/* loff_t len */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %li, %li)\n",  pid, proc, name, (int)rdi, (int)rsi, (long int)rdx, (long int)r10);
			break;
		}

		case SYS_TIMERFD_SETTIME:
		{
			name = "sys_timerfd_settime";
			reg_t rdi = event->x86_regs->rdi;		/* int ufd */
			reg_t rsi = event->x86_regs->rsi;		/* int flags */
			reg_t rdx = event->x86_regs->rdx;		/* const struct itimerspec __user * utmr */
			reg_t r10 = event->x86_regs->r10;		/* struct itimerspec __user * otmr */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_TIMERFD_GETTIME:
		{
			name = "sys_timerfd_gettime";
			reg_t rdi = event->x86_regs->rdi;		/* int ufd */
			reg_t rsi = event->x86_regs->rsi;		/* struct itimerspec __user * otmr */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_ACCEPT4:
		{
			name = "sys_accept4";
			reg_t rdi = event->x86_regs->rdi;		/*  int arg1 */
			reg_t rsi = event->x86_regs->rsi;		/* struct sockaddr __user * arg2 */
			reg_t rdx = event->x86_regs->rdx;		/* int __user * arg3 */
			reg_t r10 = event->x86_regs->r10;		/*  int arg4 */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (int)r10);
			break;
		}

		case SYS_SIGNALFD4:
		{
			name = "sys_signalfd4";
			reg_t rdi = event->x86_regs->rdi;		/* int ufd */
			reg_t rsi = event->x86_regs->rsi;		/* sigset_t __user * user_mask */
			reg_t rdx = event->x86_regs->rdx;		/* size_t sizemask */
			reg_t r10 = event->x86_regs->r10;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (int)r10);
			break;
		}

		case SYS_EVENTFD2:
		{
			name = "sys_eventfd2";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int count */
			reg_t rsi = event->x86_regs->rsi;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%lu, %i)\n",  pid, proc, name, (unsigned long)rdi, (int)rsi);
			break;
		}

		case SYS_EPOLL_CREATE1:
		{
			name = "sys_epoll_create1";
			reg_t rdi = event->x86_regs->rdi;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_DUP3:
		{
			name = "sys_dup3";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int oldfd */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned int newfd */
			reg_t rdx = event->x86_regs->rdx;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %i)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_PIPE2:
		{
			name = "sys_pipe2";
			reg_t rdi = event->x86_regs->rdi;		/* int __user * fildes */
			reg_t rsi = event->x86_regs->rsi;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %i)\n",  pid, proc, name, (unsigned long)rdi, (int)rsi);
			break;
		}

		case SYS_INOTIFY_INIT1:
		{
			name = "sys_inotify_init1";
			reg_t rdi = event->x86_regs->rdi;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_PREADV:
		{
			name = "sys_preadv";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long fd */
			reg_t rsi = event->x86_regs->rsi;		/* const struct iovec __user * vec */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long vlen */
			reg_t r10 = event->x86_regs->r10;		/* unsigned long pos_l */
			reg_t r8 = event->x86_regs->r8;		/* unsigned long pos_h */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_PWRITEV:
		{
			name = "sys_pwritev";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long fd */
			reg_t rsi = event->x86_regs->rsi;		/* const struct iovec __user * vec */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long vlen */
			reg_t r10 = event->x86_regs->r10;		/* unsigned long pos_l */
			reg_t r8 = event->x86_regs->r8;		/* unsigned long pos_h */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64", %lu, %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_RT_TGSIGQUEUEINFO:
		{
			name = "sys_rt_tgsigqueueinfo";
			reg_t rdi = event->x86_regs->rdi;		/* pid_t tgid */
			reg_t rsi = event->x86_regs->rsi;		/* pid_t  pid */
			reg_t rdx = event->x86_regs->rdx;		/* int sig */
			reg_t r10 = event->x86_regs->r10;		/* siginfo_t __user * uinfo */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx, (unsigned long)r10);
			break;
		}

		case SYS_PERF_EVENT_OPEN:
		{
			name = "sys_perf_event_open";
			reg_t rdi = event->x86_regs->rdi;		/*  struct perf_event_attr __user * attr_uptr */
			reg_t rsi = event->x86_regs->rsi;		/* pid_t pid */
			reg_t rdx = event->x86_regs->rdx;		/* int cpu */
			reg_t r10 = event->x86_regs->r10;		/* int group_fd */
			reg_t r8 = event->x86_regs->r8;		/* unsigned long flags */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %i, %i, %i, %lu)\n",  pid, proc, name, (unsigned long)rdi, (int)rsi, (int)rdx, (int)r10, (unsigned long)r8);
			break;
		}

		case SYS_RECVMMSG:
		{
			name = "sys_recvmmsg";
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* struct mmsghdr __user * msg */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned int vlen */
			reg_t r10 = event->x86_regs->r10;		/* unsigned flags */
			reg_t r8 = event->x86_regs->r8;		/* struct timespec __user * timeout */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_FANOTIFY_INIT:
		{
			name = "sys_fanotify_init";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int flags */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned int event_f_flags */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_FANOTIFY_MARK:
		{
			name = "sys_fanotify_mark";
			reg_t rdi = event->x86_regs->rdi;		/* int fanotify_fd */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned int flags */
			reg_t rdx = event->x86_regs->rdx;		/* u64 mask */
			reg_t r10 = event->x86_regs->r10;		/* int fd */
			reg_t r8 = event->x86_regs->r8;		/* const char  __user * pathname */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, %lu, %i, 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (int)r10, (unsigned long)r8);
			break;
		}

		case SYS_PRLIMIT64:
		{
			name = "sys_prlimit64";
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned int resource */
			reg_t rdx = event->x86_regs->rdx;		/* const struct rlimit64 __user * new_rlim */
			reg_t r10 = event->x86_regs->r10;		/* struct rlimit64 __user * old_rlim */
			printf("pid: %u ( %s ) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_NAME_TO_HANDLE_AT:
		{
			name = "sys_name_to_handle_at";
			reg_t rdi = event->x86_regs->rdi;		/* int dfd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * name */
			reg_t rdx = event->x86_regs->rdx;		/* struct file_handle __user * handle */
			reg_t r10 = event->x86_regs->r10;		/* int __user * mnt_id */
			reg_t r8 = event->x86_regs->r8;		/* int flag */

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
			reg_t rdi = event->x86_regs->rdi;		/* int mountdirfd */
			reg_t rsi = event->x86_regs->rsi;		/* struct file_handle __user * handle */
			reg_t rdx = event->x86_regs->rdx;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %i)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_CLOCK_ADJTIME:
		{
			name = "sys_clock_adjtime";
			reg_t rdi = event->x86_regs->rdi;		/* clockid_t which_clock */
			reg_t rsi = event->x86_regs->rsi;		/* struct timex __user * tx */
			printf("pid: %u ( %s ) syscall: %s(%lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi);
			break;
		}

		case SYS_SYNCFS:
		{
			name = "sys_syncfs";
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_SENDMMSG:
		{
			name = "sys_sendmmsg";
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* struct mmsghdr __user * msg */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned int vlen */
			reg_t r10 = event->x86_regs->r10;		/* unsigned flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_SETNS:
		{
			name = "sys_setns";
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* int nstype */
			printf("pid: %u ( %s ) syscall: %s(%i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi);
			break;
		}

		case SYS_GETCPU:
		{
			name = "sys_getcpu";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned __user * cpu */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned __user * node */
			reg_t rdx = event->x86_regs->rdx;		/* struct getcpu_cache __user * cache */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_PROCESS_VM_READV:
		{
			name = "sys_process_vm_readv";
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid */
			reg_t rsi = event->x86_regs->rsi;		/* const struct iovec __user * lvec */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long liovcnt */
			reg_t r10 = event->x86_regs->r10;		/* const struct iovec __user * rvec */
			reg_t r8 = event->x86_regs->r8;		/* unsigned long riovcnt */
			reg_t r9 = event->x86_regs->r9;		/* unsigned long flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8, (unsigned long)r9);
			break;
		}

		case SYS_PROCESS_VM_WRITEV:
		{
			name = "sys_process_vm_writev";
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid */
			reg_t rsi = event->x86_regs->rsi;		/* const struct iovec __user * lvec */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long liovcnt */
			reg_t r10 = event->x86_regs->r10;		/* const struct iovec __user * rvec */
			reg_t r8 = event->x86_regs->r8;		/* unsigned long riovcnt */
			reg_t r9 = event->x86_regs->r9;		/* unsigned long flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8, (unsigned long)r9);
			break;
		}

		case SYS_KCMP:
		{
			name = "sys_kcmp";
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid1 */
			reg_t rsi = event->x86_regs->rsi;		/* pid_t pid2 */
			reg_t rdx = event->x86_regs->rdx;		/* int type */
			reg_t r10 = event->x86_regs->r10;		/* unsigned long idx1 */
			reg_t r8 = event->x86_regs->r8;		/* unsigned long idx2 */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %i, %lu, %lu)\n",  pid, proc, name, (int)rdi, (int)rsi, (int)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_FINIT_MODULE:
		{
			name = "sys_finit_module";
			reg_t rdi = event->x86_regs->rdi;		/* int fd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * uargs */
			reg_t rdx = event->x86_regs->rdx;		/* int flags */
		
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
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid */
			reg_t rsi = event->x86_regs->rsi;		/* struct sched_attr __user * attr */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_SCHED_GETATTR:
		{
			name = "sys_sched_getattr";
			reg_t rdi = event->x86_regs->rdi;		/* pid_t pid */
			reg_t rsi = event->x86_regs->rsi;		/* struct sched_attr __user * attr */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned int size */
			reg_t r10 = event->x86_regs->r10;		/* unsigned int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx, (unsigned long)r10);
			break;
		}

		case SYS_RENAMEAT2:
		{
			name = "sys_renameat2";
			reg_t rdi = event->x86_regs->rdi;		/* int olddfd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * oldname */
			reg_t rdx = event->x86_regs->rdx;		/* int newdfd */
			reg_t r10 = event->x86_regs->r10;		/* const char __user * newname */
			reg_t r8 = event->x86_regs->r8;		/* unsigned int flags */	

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
			reg_t rdi = event->x86_regs->rdi;		/* unsigned int op */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned int flags */
			reg_t rdx = event->x86_regs->rdx;		/* const char __user * uargs */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, 0x%"PRIx64")\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_GETRANDOM:
		{
			name = "sys_getrandom";
			reg_t rdi = event->x86_regs->rdi;		/* char __user * buf */
			reg_t rsi = event->x86_regs->rsi;		/* size_t count */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned int flags */
			printf("pid: %u ( %s ) syscall: %s(0x%"PRIx64", %lu, %lu)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_MEMFD_CREATE:
		{
			name = "sys_memfd_create";
			reg_t rdi = event->x86_regs->rdi;		/* const char __user * uname_ptr */
			reg_t rsi = event->x86_regs->rsi;		/* unsigned int flags */
	
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
			reg_t rdi = event->x86_regs->rdi;		/* int kernel_fd */
			reg_t rsi = event->x86_regs->rsi;		/* int initrd_fd */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned long cmdline_len */
			reg_t r10 = event->x86_regs->r10;		/* const char __user * cmdline_ptr */
			reg_t r8 = event->x86_regs->r8;		/* unsigned long flags */
			printf("pid: %u ( %s ) syscall: %s(%i, %i, %lu, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (int)rsi, (unsigned long)rdx, (unsigned long)r10, (unsigned long)r8);
			break;
		}

		case SYS_BPF:
		{
			name = "sys_bpf";
			reg_t rdi = event->x86_regs->rdi;		/* int cmd */
			reg_t rsi = event->x86_regs->rsi;		/* union bpf_attr * attr */
			reg_t rdx = event->x86_regs->rdx;		/* unsigned int size */
			printf("pid: %u ( %s ) syscall: %s(%i, 0x%"PRIx64", %lu)\n",  pid, proc, name, (int)rdi, (unsigned long)rsi, (unsigned long)rdx);
			break;
		}

		case SYS_EXECVEAT:
		{
			name = "sys_execveat";
			reg_t rdi = event->x86_regs->rdi;		/* int dfd */
			reg_t rsi = event->x86_regs->rsi;		/* const char __user * filename */
			reg_t rdx = event->x86_regs->rdx;		/* const char __user *const __user * argv */
			reg_t r10 = event->x86_regs->r10;		/* const char __user *const __user * envp */
			reg_t r8 = event->x86_regs->r8;		/* int flags */

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
			reg_t rdi = event->x86_regs->rdi;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%i)\n",  pid, proc, name, (int)rdi);
			break;
		}

		case SYS_MEMBARRIER:
		{
			name = "sys_membarrier";
			reg_t rdi = event->x86_regs->rdi;		/* int cmd */
			reg_t rsi = event->x86_regs->rsi;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%i, %i)\n",  pid, proc, name, (int)rdi, (int)rsi);
			break;
		}

		case SYS_MLOCK2:
		{
			name = "sys_mlock2";
			reg_t rdi = event->x86_regs->rdi;		/* unsigned long start */
			reg_t rsi = event->x86_regs->rsi;		/* size_t len */
			reg_t rdx = event->x86_regs->rdx;		/* int flags */
			printf("pid: %u ( %s ) syscall: %s(%lu, %lu, %i)\n",  pid, proc, name, (unsigned long)rdi, (unsigned long)rsi, (int)rdx);
			break;
		}

		case SYS_COPY_FILE_RANGE:
		{
			name = "sys_copy_file_range";
			reg_t rdi = event->x86_regs->rdi;		/* int fd_in */
			reg_t rsi = event->x86_regs->rsi;		/* loff_t __user * off_in */
			reg_t rdx = event->x86_regs->rdx;		/* int fd_out */
			reg_t r10 = event->x86_regs->r10;		/* loff_t __user * off_out */
			reg_t r8 = event->x86_regs->r8;		/* size_t len */
			reg_t r9 = event->x86_regs->r9;		/* unsigned int flags */
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

void 
vf_linux_print_sysret(vmi_instance_t vmi, vmi_event_t *event) 
{
	/* Print the pid, process name and return value of a system call */
	reg_t syscall_return = event->x86_regs->rax;			/* get the return value out of rax */
	vmi_pid_t pid = vmi_dtb_to_pid(vmi, event->x86_regs->cr3);	/* get the pid of the process */
	char *proc = get_proc_name(vmi, pid);				/* get the process name */

	printf("pid: %u ( %s ) return: 0x%"PRIx64"\n",  pid, proc, syscall_return);
}

/* 
 * Replace the first byte of the system-call handler with INT 3. The address of
 * the system call handler is available in MSR_LSTAR.
 */
bool
vf_linux_find_syscalls_and_setup_mem_traps(vf_state *state)
{
	status_t status = false;
	addr_t sysaddr;
	vf_paddr_record *syscall_trap;

	status = vmi_get_vcpureg(state->vmi, &sysaddr, MSR_LSTAR, 0);
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to read MSR_LSTAR.\n");
		goto done;
	}

	syscall_trap = vf_setup_mem_trap(state, sysaddr);
	if (NULL == syscall_trap) {
		fprintf(stderr, "failed to set syscall memory trap\n");
		goto done;
	}

done:
	return status == VMI_SUCCESS ? true : false;
}

/*
 * Replace the first byte of the instruction following the CALL instruction
 * in the kernel's system-call handler with INT 3. This is the first
 * practical point at which we have access to the system call's return value
 * We find the address of the CALL instruction by disassembling the kernel core.
 */
bool
vf_linux_set_up_sysret_handler(vf_state *state)
{
	csh handle;
	cs_insn *inst;
	size_t count, call_offset = ~0;
	status_t status = VMI_FAILURE;
	addr_t lstar = 0;
	uint8_t code[4096]; /* Assume CALL is within first page. */

	/* LSTAR should be the constant across all VCPUs */
        status_t ret = vmi_get_vcpureg(state->vmi, &lstar, MSR_LSTAR, 0);
        if (VMI_SUCCESS != ret) {
                fprintf(stderr, "failed to get MSR_LSTAR address\n");
                goto done;
        }

	addr_t lstar_p = vmi_translate_kv2p(state->vmi, lstar);
        if (0 == lstar_p) {
                fprintf(stderr, "failed to read instructions from 0x%"
                                 PRIx64".\n", lstar);
                goto done;
        }

	/* Read kernel instructions into code. */
	status = vmi_read_pa(state->vmi, lstar_p,
	                     code, sizeof(code));
	if (VMI_FAILURE == status) {
		fprintf(stderr, "failed to read instructions from 0x%"
		                 PRIx64".\n", lstar_p);
		goto done;
	}

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		fprintf(stderr, "failed to open capstone\n");
		status = VMI_FAILURE;
		goto done;
	}

	/* Find CALL inst. and note address of inst. which follows. */
	count = cs_disasm(handle, code, sizeof(code), 0, 0, &inst);
	if (count > 0) {
		size_t i;
		for (i = 0; i < count; i++) {
			if (!strcmp(inst[i].mnemonic, "call")) {
				call_offset = inst[i + 1].address;
				break;
			}
		}
		cs_free(inst, count);
	} else {
		fprintf(stderr, "failed to disassemble system-call handler\n");
		status = VMI_FAILURE;
		goto done;
	}

	if (~0 == call_offset) {
		fprintf(stderr, "did not find call in system-call handler\n");
		status = VMI_FAILURE;
		goto done;
	}

	cs_close(&handle);

	sysret_trap = vf_setup_mem_trap(state, lstar + call_offset);
        if (NULL == sysret_trap) {
		fprintf(stderr, "failed to create sysret memory trap\n");
		status = VMI_FAILURE;
		goto done;
        }

	vf_remove_breakpoint(sysret_trap);

	status = VMI_SUCCESS;

done:
	return status == VMI_SUCCESS ? true : false;
}

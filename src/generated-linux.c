/* Generated on Linux_4.9.13-201.fc25.x86_64 on 15 Mar 2017 11:32:28*/

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "functions-linux.h"
#include "generated-linux.h"

void *gt_linux_print_syscall_sys_read(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_read", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_write(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_write", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_open(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	char *arg0 = gt_guest_get_string(state, gt_guest_get_vmi_event(state)->x86_regs->rdi, pid);
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(\"%s\", %i, %lu)\n", pid, tid, proc, "sys_open", (char *) arg0, (int) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_close(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, tid, proc, "sys_close", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_stat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_stat", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_fstat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_fstat", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_lstat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_lstat", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_poll(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %i)\n", pid, tid, proc, "sys_poll", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_lseek(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_lseek", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_mmap(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	reg_t arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu, %lu, %lu, %lu)\n", pid, tid, proc, "sys_mmap", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_mprotect(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu)\n", pid, tid, proc, "sys_mprotect", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_munmap(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, tid, proc, "sys_munmap", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_brk(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, tid, proc, "sys_brk", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_rt_sigaction(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_rt_sigaction", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_rt_sigprocmask(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_rt_sigprocmask", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_rt_sigreturn(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_rt_sigreturn");
	return NULL;
}

void *gt_linux_print_syscall_sys_ioctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu)\n", pid, tid, proc, "sys_ioctl", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_pread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %li)\n", pid, tid, proc, "sys_pread", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (long int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_pwrite(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %li)\n", pid, tid, proc, "sys_pwrite", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (long int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_readv(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_readv", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_writev(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_writev", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_access(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, tid, proc, "sys_access", (unsigned long) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_pipe(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_pipe", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_select(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_select", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_yield(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_sched_yield");
	return NULL;
}

void *gt_linux_print_syscall_sys_mremap(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu, %lu, %lu)\n", pid, tid, proc, "sys_mremap", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_msync(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i)\n", pid, tid, proc, "sys_msync", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_mincore(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_mincore", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_madvise(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i)\n", pid, tid, proc, "sys_madvise", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_shmget(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %i)\n", pid, tid, proc, "sys_shmget", (int) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_shmat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_shmat", (int) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_shmctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64")\n", pid, tid, proc, "sys_shmctl", (int) arg0, (int) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_dup(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, tid, proc, "sys_dup", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_dup2(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, tid, proc, "sys_dup2", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_pause(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_pause");
	return NULL;
}

void *gt_linux_print_syscall_sys_nanosleep(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_nanosleep", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_getitimer(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, tid, proc, "sys_getitimer", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_alarm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, tid, proc, "sys_alarm", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_setitimer(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_setitimer", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_getpid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_getpid");
	return NULL;
}

void *gt_linux_print_syscall_sys_sendfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_sendfile", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_socket(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i)\n", pid, tid, proc, "sys_socket", (int) arg0, (int) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_connect(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_connect", (int) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_accept(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_accept", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_sendto(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	reg_t arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_sendto", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (int) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_recvfrom(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	reg_t arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_recvfrom", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_sendmsg(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_sendmsg", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_recvmsg(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_recvmsg", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_shutdown(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, tid, proc, "sys_shutdown", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_bind(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_bind", (int) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_listen(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, tid, proc, "sys_listen", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_getsockname(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_getsockname", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_getpeername(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_getpeername", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_socketpair(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64")\n", pid, tid, proc, "sys_socketpair", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_setsockopt(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_setsockopt", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_getsockopt(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_getsockopt", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_clone(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, 0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_clone", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_fork(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_fork");
	return NULL;
}

void *gt_linux_print_syscall_sys_vfork(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_vfork");
	return NULL;
}

void *gt_linux_print_syscall_sys_execve(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	char *arg0 = gt_guest_get_string(state, gt_guest_get_vmi_event(state)->x86_regs->rdi, pid);
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(\"%s\", %lu, %lu)\n", pid, tid, proc, "sys_execve", (char *) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_exit(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, tid, proc, "sys_exit", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_wait4(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64")\n", pid, tid, proc, "sys_wait4", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_kill(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, tid, proc, "sys_kill", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_uname(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_uname", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_semget(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i)\n", pid, tid, proc, "sys_semget", (int) arg0, (int) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_semop(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_semop", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_semctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, %lu)\n", pid, tid, proc, "sys_semctl", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_shmdt(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_shmdt", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_msgget(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, tid, proc, "sys_msgget", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_msgsnd(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %i)\n", pid, tid, proc, "sys_msgsnd", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_msgrcv(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %li, %i)\n", pid, tid, proc, "sys_msgrcv", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (long int) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_msgctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64")\n", pid, tid, proc, "sys_msgctl", (int) arg0, (int) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_fcntl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu)\n", pid, tid, proc, "sys_fcntl", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_flock(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, tid, proc, "sys_flock", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_fsync(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, tid, proc, "sys_fsync", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_fdatasync(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, tid, proc, "sys_fdatasync", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_truncate(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %li)\n", pid, tid, proc, "sys_truncate", (unsigned long) arg0, (long int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_ftruncate(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, tid, proc, "sys_ftruncate", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_getdents(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_getdents", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_getcwd(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_getcwd", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_chdir(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_chdir", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_fchdir(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, tid, proc, "sys_fchdir", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_rename(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_rename", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_mkdir(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_mkdir", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_rmdir(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_rmdir", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_creat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_creat", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_link(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_link", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_unlink(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_unlink", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_symlink(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_symlink", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_readlink(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_readlink", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_chmod(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_chmod", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_fchmod(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, tid, proc, "sys_fchmod", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_chown(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %lu)\n", pid, tid, proc, "sys_chown", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_fchown(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu)\n", pid, tid, proc, "sys_fchown", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_lchown(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %lu)\n", pid, tid, proc, "sys_lchown", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_umask(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, tid, proc, "sys_umask", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_gettimeofday(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_gettimeofday", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_getrlimit(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_getrlimit", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_getrusage(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, tid, proc, "sys_getrusage", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_sysinfo(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_sysinfo", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_times(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_times", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_ptrace(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%li, %li, %lu, %lu)\n", pid, tid, proc, "sys_ptrace", (long int) arg0, (long int) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_getuid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_getuid");
	return NULL;
}

void *gt_linux_print_syscall_sys_syslog(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_syslog", (int) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_getgid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_getgid");
	return NULL;
}

void *gt_linux_print_syscall_sys_setuid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, tid, proc, "sys_setuid", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_setgid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, tid, proc, "sys_setgid", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_geteuid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_geteuid");
	return NULL;
}

void *gt_linux_print_syscall_sys_getegid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_getegid");
	return NULL;
}

void *gt_linux_print_syscall_sys_setpgid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, tid, proc, "sys_setpgid", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_getppid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_getppid");
	return NULL;
}

void *gt_linux_print_syscall_sys_getpgrp(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_getpgrp");
	return NULL;
}

void *gt_linux_print_syscall_sys_setsid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_setsid");
	return NULL;
}

void *gt_linux_print_syscall_sys_setreuid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, tid, proc, "sys_setreuid", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_setregid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, tid, proc, "sys_setregid", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_getgroups(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, tid, proc, "sys_getgroups", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_setgroups(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, tid, proc, "sys_setgroups", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_setresuid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu)\n", pid, tid, proc, "sys_setresuid", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_getresuid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_getresuid", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_setresgid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu)\n", pid, tid, proc, "sys_setresgid", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_getresgid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_getresgid", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_getpgid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, tid, proc, "sys_getpgid", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_setfsuid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, tid, proc, "sys_setfsuid", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_setfsgid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, tid, proc, "sys_setfsgid", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_getsid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, tid, proc, "sys_getsid", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_capget(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_capget", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_capset(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_capset", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_rt_sigpending(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_rt_sigpending", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_rt_sigtimedwait(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_rt_sigtimedwait", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_rt_sigqueueinfo(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64")\n", pid, tid, proc, "sys_rt_sigqueueinfo", (int) arg0, (int) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_rt_sigsuspend(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_rt_sigsuspend", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_sigaltstack(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_sigaltstack", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_utime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_utime", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_mknod(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %lu)\n", pid, tid, proc, "sys_mknod", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_uselib(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_uselib", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_personality(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, tid, proc, "sys_personality", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_ustat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_ustat", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_statfs(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_statfs", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_fstatfs(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_fstatfs", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_sysfs(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %lu)\n", pid, tid, proc, "sys_sysfs", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_getpriority(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, tid, proc, "sys_getpriority", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_setpriority(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i)\n", pid, tid, proc, "sys_setpriority", (int) arg0, (int) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_setparam(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, tid, proc, "sys_sched_setparam", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_getparam(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, tid, proc, "sys_sched_getparam", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_setscheduler(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64")\n", pid, tid, proc, "sys_sched_setscheduler", (int) arg0, (int) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_getscheduler(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, tid, proc, "sys_sched_getscheduler", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_get_priority_max(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, tid, proc, "sys_sched_get_priority_max", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_get_priority_min(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, tid, proc, "sys_sched_get_priority_min", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_rr_get_interval(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, tid, proc, "sys_sched_rr_get_interval", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_mlock(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, tid, proc, "sys_mlock", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_munlock(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, tid, proc, "sys_munlock", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_mlockall(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, tid, proc, "sys_mlockall", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_munlockall(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_munlockall");
	return NULL;
}

void *gt_linux_print_syscall_sys_vhangup(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_vhangup");
	return NULL;
}

void *gt_linux_print_syscall_sys_modify_ldt(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_modify_ldt", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_pivot_root(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_pivot_root", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_sysctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_sysctl", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_prctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %lu, %lu, %lu)\n", pid, tid, proc, "sys_prctl", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_arch_prctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu)\n", pid, tid, proc, "sys_arch_prctl", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_adjtimex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_adjtimex", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_setrlimit(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_setrlimit", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_chroot(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_chroot", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_sync(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_sync");
	return NULL;
}

void *gt_linux_print_syscall_sys_acct(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_acct", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_settimeofday(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_settimeofday", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_mount(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_mount", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_umount2(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_umount2");
	return NULL;
}

void *gt_linux_print_syscall_sys_swapon(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, tid, proc, "sys_swapon", (unsigned long) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_swapoff(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_swapoff", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_reboot(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_reboot", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_sethostname(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, tid, proc, "sys_sethostname", (unsigned long) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_setdomainname(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, tid, proc, "sys_setdomainname", (unsigned long) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_iopl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, tid, proc, "sys_iopl", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_ioperm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i)\n", pid, tid, proc, "sys_ioperm", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_create_module(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_create_module");
	return NULL;
}

void *gt_linux_print_syscall_sys_init_module(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_init_module", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_delete_module(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_delete_module", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_get_kernel_syms(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_get_kernel_syms");
	return NULL;
}

void *gt_linux_print_syscall_sys_query_module(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_query_module");
	return NULL;
}

void *gt_linux_print_syscall_sys_quotactl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_quotactl", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_nfsservctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_nfsservctl");
	return NULL;
}

void *gt_linux_print_syscall_sys_getpmsg(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_getpmsg");
	return NULL;
}

void *gt_linux_print_syscall_sys_putpmsg(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_putpmsg");
	return NULL;
}

void *gt_linux_print_syscall_sys_afs_syscall(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_afs_syscall");
	return NULL;
}

void *gt_linux_print_syscall_sys_tuxcall(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_tuxcall");
	return NULL;
}

void *gt_linux_print_syscall_sys_security(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_security");
	return NULL;
}

void *gt_linux_print_syscall_sys_gettid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_gettid");
	return NULL;
}

void *gt_linux_print_syscall_sys_readahead(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %li, %lu)\n", pid, tid, proc, "sys_readahead", (int) arg0, (long int) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_setxattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n", pid, tid, proc, "sys_setxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_lsetxattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n", pid, tid, proc, "sys_lsetxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_fsetxattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n", pid, tid, proc, "sys_fsetxattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_getxattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_getxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_lgetxattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_lgetxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_fgetxattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_fgetxattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_listxattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_listxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_llistxattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_llistxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_flistxattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_flistxattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_removexattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_removexattr", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_lremovexattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_lremovexattr", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_fremovexattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, tid, proc, "sys_fremovexattr", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_tkill(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, tid, proc, "sys_tkill", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_time(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_time", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_futex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	reg_t arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_futex", (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_setaffinity(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_sched_setaffinity", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_getaffinity(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_sched_getaffinity", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_set_thread_area(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_set_thread_area", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_io_setup(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_io_setup", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_io_destroy(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_io_destroy", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_io_getevents(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %li, %li, 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_io_getevents", (unsigned long) arg0, (long int) arg1, (long int) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_io_submit(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %li, 0x%"PRIx64")\n", pid, tid, proc, "sys_io_submit", (unsigned long) arg0, (long int) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_io_cancel(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_io_cancel", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_get_thread_area(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_get_thread_area", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_lookup_dcookie(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_lookup_dcookie", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_epoll_create(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, tid, proc, "sys_epoll_create", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_epoll_ctl_old(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_epoll_ctl_old");
	return NULL;
}

void *gt_linux_print_syscall_sys_epoll_wait_old(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_epoll_wait_old");
	return NULL;
}

void *gt_linux_print_syscall_sys_remap_file_pages(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu, %lu, %lu)\n", pid, tid, proc, "sys_remap_file_pages", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_getdents64(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_getdents64", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_set_tid_address(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_set_tid_address", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_restart_syscall(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_restart_syscall");
	return NULL;
}

void *gt_linux_print_syscall_sys_semtimedop(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_semtimedop", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_fadvise64(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %li, %lu, %i)\n", pid, tid, proc, "sys_fadvise64", (int) arg0, (long int) arg1, (unsigned long) arg2, (int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_timer_create(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_timer_create", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_timer_settime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_timer_settime", (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_timer_gettime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_timer_gettime", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_timer_getoverrun(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, tid, proc, "sys_timer_getoverrun", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_timer_delete(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, tid, proc, "sys_timer_delete", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_clock_settime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_clock_settime", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_clock_gettime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_clock_gettime", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_clock_getres(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_clock_getres", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_clock_nanosleep(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_clock_nanosleep", (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_exit_group(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, tid, proc, "sys_exit_group", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_epoll_wait(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, %i)\n", pid, tid, proc, "sys_epoll_wait", (int) arg0, (unsigned long) arg1, (int) arg2, (int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_epoll_ctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64")\n", pid, tid, proc, "sys_epoll_ctl", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_tgkill(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i)\n", pid, tid, proc, "sys_tgkill", (int) arg0, (int) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_utimes(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_utimes", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_vserver(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_vserver");
	return NULL;
}

void *gt_linux_print_syscall_sys_mbind(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	reg_t arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu, 0x%"PRIx64", %lu, %lu)\n", pid, tid, proc, "sys_mbind", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_set_mempolicy(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_set_mempolicy", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_get_mempolicy(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu, %lu, %lu)\n", pid, tid, proc, "sys_get_mempolicy", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_mq_open(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i, %lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_mq_open", (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_mq_unlink(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64")\n", pid, tid, proc, "sys_mq_unlink", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_mq_timedsend(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_mq_timedsend", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_mq_timedreceive(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_mq_timedreceive", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_mq_notify(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, tid, proc, "sys_mq_notify", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_mq_getsetattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_mq_getsetattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_kexec_load(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_kexec_load", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_waitid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64", %i, 0x%"PRIx64")\n", pid, tid, proc, "sys_waitid", (int) arg0, (int) arg1, (unsigned long) arg2, (int) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_add_key(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, %i)\n", pid, tid, proc, "sys_add_key", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_request_key(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_request_key", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_keyctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %lu, %lu, %lu)\n", pid, tid, proc, "sys_keyctl", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_ioprio_set(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i)\n", pid, tid, proc, "sys_ioprio_set", (int) arg0, (int) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_ioprio_get(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, tid, proc, "sys_ioprio_get", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_inotify_init(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_inotify_init");
	return NULL;
}

void *gt_linux_print_syscall_sys_inotify_add_watch(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_inotify_add_watch", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_inotify_rm_watch(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, tid, proc, "sys_inotify_rm_watch", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_migrate_pages(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_migrate_pages", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_openat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, %lu)\n", pid, tid, proc, "sys_openat", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_mkdirat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_mkdirat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_mknodat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n", pid, tid, proc, "sys_mknodat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_fchownat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, %i)\n", pid, tid, proc, "sys_fchownat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_futimesat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_futimesat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_newfstatat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_newfstatat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_unlinkat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_unlinkat", (int) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_renameat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64")\n", pid, tid, proc, "sys_renameat", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_linkat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_linkat", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_symlinkat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i, 0x%"PRIx64")\n", pid, tid, proc, "sys_symlinkat", (unsigned long) arg0, (int) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_readlinkat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_readlinkat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_fchmodat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_fchmodat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_faccessat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_faccessat", (int) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_pselect6(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	reg_t arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_pselect6", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_ppoll(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_ppoll", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_unshare(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, tid, proc, "sys_unshare", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_set_robust_list(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_set_robust_list", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_get_robust_list(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_get_robust_list", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_splice(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	reg_t arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %lu, %lu)\n", pid, tid, proc, "sys_splice", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_tee(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %lu, %lu)\n", pid, tid, proc, "sys_tee", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_sync_file_range(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %li, %li, %lu)\n", pid, tid, proc, "sys_sync_file_range", (int) arg0, (long int) arg1, (long int) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_vmsplice(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n", pid, tid, proc, "sys_vmsplice", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_move_pages(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	reg_t arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_move_pages", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (int) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_utimensat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_utimensat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_epoll_pwait(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	reg_t arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, %i, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_epoll_pwait", (int) arg0, (unsigned long) arg1, (int) arg2, (int) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_signalfd(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_signalfd", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_timerfd(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s()\n", pid, tid, proc, "sys_timerfd");
	return NULL;
}

void *gt_linux_print_syscall_sys_eventfd(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu)\n", pid, tid, proc, "sys_eventfd", (unsigned long) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_fallocate(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %li, %li)\n", pid, tid, proc, "sys_fallocate", (int) arg0, (int) arg1, (long int) arg2, (long int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_timerfd_settime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_timerfd_settime", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_timerfd_gettime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64")\n", pid, tid, proc, "sys_timerfd_gettime", (int) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_accept4(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_accept4", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_signalfd4(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %i)\n", pid, tid, proc, "sys_signalfd4", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_eventfd2(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %i)\n", pid, tid, proc, "sys_eventfd2", (unsigned long) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_epoll_create1(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, tid, proc, "sys_epoll_create1", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_dup3(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i)\n", pid, tid, proc, "sys_dup3", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_pipe2(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i)\n", pid, tid, proc, "sys_pipe2", (unsigned long) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_inotify_init1(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, tid, proc, "sys_inotify_init1", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_preadv(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %lu, %lu)\n", pid, tid, proc, "sys_preadv", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_pwritev(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %lu, %lu)\n", pid, tid, proc, "sys_pwritev", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_rt_tgsigqueueinfo(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64")\n", pid, tid, proc, "sys_rt_tgsigqueueinfo", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_perf_event_open(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i, %i, %i, %lu)\n", pid, tid, proc, "sys_perf_event_open", (unsigned long) arg0, (int) arg1, (int) arg2, (int) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_recvmmsg(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_recvmmsg", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_fanotify_init(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu)\n", pid, tid, proc, "sys_fanotify_init", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_fanotify_mark(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %lu, %i, 0x%"PRIx64")\n", pid, tid, proc, "sys_fanotify_mark", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_prlimit64(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_prlimit64", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_name_to_handle_at(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_name_to_handle_at", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_open_by_handle_at(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_open_by_handle_at", (int) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_clock_adjtime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_clock_adjtime", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_syncfs(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, tid, proc, "sys_syncfs", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_sendmmsg(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n", pid, tid, proc, "sys_sendmmsg", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_setns(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, tid, proc, "sys_setns", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_getcpu(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64")\n", pid, tid, proc, "sys_getcpu", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_process_vm_readv(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	reg_t arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", %lu, %lu)\n", pid, tid, proc, "sys_process_vm_readv", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_process_vm_writev(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	reg_t arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", %lu, %lu)\n", pid, tid, proc, "sys_process_vm_writev", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void *gt_linux_print_syscall_sys_kcmp(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, %lu, %lu)\n", pid, tid, proc, "sys_kcmp", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_finit_module(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_finit_module", (int) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_setattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_sched_setattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_sched_getattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu)\n", pid, tid, proc, "sys_sched_getattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	return NULL;
}

void *gt_linux_print_syscall_sys_renameat2(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_renameat2", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_seccomp(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, 0x%"PRIx64")\n", pid, tid, proc, "sys_seccomp", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_getrandom(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %lu)\n", pid, tid, proc, "sys_getrandom", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_memfd_create(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_memfd_create", (unsigned long) arg0, (unsigned long) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_kexec_file_load(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %lu, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_kexec_file_load", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_bpf(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu)\n", pid, tid, proc, "sys_bpf", (int) arg0, (unsigned long) arg1, (unsigned long) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_execveat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i)\n", pid, tid, proc, "sys_execveat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4);
	return NULL;
}

void *gt_linux_print_syscall_sys_userfaultfd(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i)\n", pid, tid, proc, "sys_userfaultfd", (int) arg0);
	return NULL;
}

void *gt_linux_print_syscall_sys_membarrier(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i)\n", pid, tid, proc, "sys_membarrier", (int) arg0, (int) arg1);
	return NULL;
}

void *gt_linux_print_syscall_sys_mlock2(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i)\n", pid, tid, proc, "sys_mlock2", (unsigned long) arg0, (unsigned long) arg1, (int) arg2);
	return NULL;
}

void *gt_linux_print_syscall_sys_copy_file_range(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	char *proc = gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid);
	reg_t arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	reg_t arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	reg_t arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	reg_t arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	reg_t arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	reg_t arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %lu, %lu)\n", pid, tid, proc, "sys_copy_file_range", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5);
	return NULL;
}

void gt_linux_print_sysret(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data) {
	reg_t syscall_return = gt_guest_get_register(state, RAX);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) return: 0x%"PRIx64"\n", pid, tid, gt_linux_get_process_name(gt_guest_get_vmi_instance(state), pid), syscall_return);
}

const GtCallbackRegistry GT_LINUX_SYSCALLS[] = {
	{ "sys_read", gt_linux_print_syscall_sys_read, gt_linux_print_sysret },
	{ "sys_write", gt_linux_print_syscall_sys_write, gt_linux_print_sysret },
	{ "sys_open", gt_linux_print_syscall_sys_open, gt_linux_print_sysret },
	{ "sys_close", gt_linux_print_syscall_sys_close, gt_linux_print_sysret },
	{ "sys_stat", gt_linux_print_syscall_sys_stat, gt_linux_print_sysret },
	{ "sys_fstat", gt_linux_print_syscall_sys_fstat, gt_linux_print_sysret },
	{ "sys_lstat", gt_linux_print_syscall_sys_lstat, gt_linux_print_sysret },
	{ "sys_poll", gt_linux_print_syscall_sys_poll, gt_linux_print_sysret },
	{ "sys_lseek", gt_linux_print_syscall_sys_lseek, gt_linux_print_sysret },
	{ "sys_mmap", gt_linux_print_syscall_sys_mmap, gt_linux_print_sysret },
	{ "sys_mprotect", gt_linux_print_syscall_sys_mprotect, gt_linux_print_sysret },
	{ "sys_munmap", gt_linux_print_syscall_sys_munmap, gt_linux_print_sysret },
	{ "sys_brk", gt_linux_print_syscall_sys_brk, gt_linux_print_sysret },
	{ "sys_rt_sigaction", gt_linux_print_syscall_sys_rt_sigaction, gt_linux_print_sysret },
	{ "sys_rt_sigprocmask", gt_linux_print_syscall_sys_rt_sigprocmask, gt_linux_print_sysret },
	{ "sys_rt_sigreturn", gt_linux_print_syscall_sys_rt_sigreturn, gt_linux_print_sysret },
	{ "sys_ioctl", gt_linux_print_syscall_sys_ioctl, gt_linux_print_sysret },
	{ "sys_pread", gt_linux_print_syscall_sys_pread, gt_linux_print_sysret },
	{ "sys_pwrite", gt_linux_print_syscall_sys_pwrite, gt_linux_print_sysret },
	{ "sys_readv", gt_linux_print_syscall_sys_readv, gt_linux_print_sysret },
	{ "sys_writev", gt_linux_print_syscall_sys_writev, gt_linux_print_sysret },
	{ "sys_access", gt_linux_print_syscall_sys_access, gt_linux_print_sysret },
	{ "sys_pipe", gt_linux_print_syscall_sys_pipe, gt_linux_print_sysret },
	{ "sys_select", gt_linux_print_syscall_sys_select, gt_linux_print_sysret },
	{ "sys_sched_yield", gt_linux_print_syscall_sys_sched_yield, gt_linux_print_sysret },
	{ "sys_mremap", gt_linux_print_syscall_sys_mremap, gt_linux_print_sysret },
	{ "sys_msync", gt_linux_print_syscall_sys_msync, gt_linux_print_sysret },
	{ "sys_mincore", gt_linux_print_syscall_sys_mincore, gt_linux_print_sysret },
	{ "sys_madvise", gt_linux_print_syscall_sys_madvise, gt_linux_print_sysret },
	{ "sys_shmget", gt_linux_print_syscall_sys_shmget, gt_linux_print_sysret },
	{ "sys_shmat", gt_linux_print_syscall_sys_shmat, gt_linux_print_sysret },
	{ "sys_shmctl", gt_linux_print_syscall_sys_shmctl, gt_linux_print_sysret },
	{ "sys_dup", gt_linux_print_syscall_sys_dup, gt_linux_print_sysret },
	{ "sys_dup2", gt_linux_print_syscall_sys_dup2, gt_linux_print_sysret },
	{ "sys_pause", gt_linux_print_syscall_sys_pause, gt_linux_print_sysret },
	{ "sys_nanosleep", gt_linux_print_syscall_sys_nanosleep, gt_linux_print_sysret },
	{ "sys_getitimer", gt_linux_print_syscall_sys_getitimer, gt_linux_print_sysret },
	{ "sys_alarm", gt_linux_print_syscall_sys_alarm, gt_linux_print_sysret },
	{ "sys_setitimer", gt_linux_print_syscall_sys_setitimer, gt_linux_print_sysret },
	{ "sys_getpid", gt_linux_print_syscall_sys_getpid, gt_linux_print_sysret },
	{ "sys_sendfile", gt_linux_print_syscall_sys_sendfile, gt_linux_print_sysret },
	{ "sys_socket", gt_linux_print_syscall_sys_socket, gt_linux_print_sysret },
	{ "sys_connect", gt_linux_print_syscall_sys_connect, gt_linux_print_sysret },
	{ "sys_accept", gt_linux_print_syscall_sys_accept, gt_linux_print_sysret },
	{ "sys_sendto", gt_linux_print_syscall_sys_sendto, gt_linux_print_sysret },
	{ "sys_recvfrom", gt_linux_print_syscall_sys_recvfrom, gt_linux_print_sysret },
	{ "sys_sendmsg", gt_linux_print_syscall_sys_sendmsg, gt_linux_print_sysret },
	{ "sys_recvmsg", gt_linux_print_syscall_sys_recvmsg, gt_linux_print_sysret },
	{ "sys_shutdown", gt_linux_print_syscall_sys_shutdown, gt_linux_print_sysret },
	{ "sys_bind", gt_linux_print_syscall_sys_bind, gt_linux_print_sysret },
	{ "sys_listen", gt_linux_print_syscall_sys_listen, gt_linux_print_sysret },
	{ "sys_getsockname", gt_linux_print_syscall_sys_getsockname, gt_linux_print_sysret },
	{ "sys_getpeername", gt_linux_print_syscall_sys_getpeername, gt_linux_print_sysret },
	{ "sys_socketpair", gt_linux_print_syscall_sys_socketpair, gt_linux_print_sysret },
	{ "sys_setsockopt", gt_linux_print_syscall_sys_setsockopt, gt_linux_print_sysret },
	{ "sys_getsockopt", gt_linux_print_syscall_sys_getsockopt, gt_linux_print_sysret },
	{ "sys_clone", gt_linux_print_syscall_sys_clone, gt_linux_print_sysret },
	{ "sys_fork", gt_linux_print_syscall_sys_fork, gt_linux_print_sysret },
	{ "sys_vfork", gt_linux_print_syscall_sys_vfork, gt_linux_print_sysret },
	{ "stub_execve", gt_linux_print_syscall_sys_execve, gt_linux_print_sysret },
	{ "sys_exit", gt_linux_print_syscall_sys_exit, gt_linux_print_sysret },
	{ "sys_wait4", gt_linux_print_syscall_sys_wait4, gt_linux_print_sysret },
	{ "sys_kill", gt_linux_print_syscall_sys_kill, gt_linux_print_sysret },
	{ "sys_uname", gt_linux_print_syscall_sys_uname, gt_linux_print_sysret },
	{ "sys_semget", gt_linux_print_syscall_sys_semget, gt_linux_print_sysret },
	{ "sys_semop", gt_linux_print_syscall_sys_semop, gt_linux_print_sysret },
	{ "sys_semctl", gt_linux_print_syscall_sys_semctl, gt_linux_print_sysret },
	{ "sys_shmdt", gt_linux_print_syscall_sys_shmdt, gt_linux_print_sysret },
	{ "sys_msgget", gt_linux_print_syscall_sys_msgget, gt_linux_print_sysret },
	{ "sys_msgsnd", gt_linux_print_syscall_sys_msgsnd, gt_linux_print_sysret },
	{ "sys_msgrcv", gt_linux_print_syscall_sys_msgrcv, gt_linux_print_sysret },
	{ "sys_msgctl", gt_linux_print_syscall_sys_msgctl, gt_linux_print_sysret },
	{ "sys_fcntl", gt_linux_print_syscall_sys_fcntl, gt_linux_print_sysret },
	{ "sys_flock", gt_linux_print_syscall_sys_flock, gt_linux_print_sysret },
	{ "sys_fsync", gt_linux_print_syscall_sys_fsync, gt_linux_print_sysret },
	{ "sys_fdatasync", gt_linux_print_syscall_sys_fdatasync, gt_linux_print_sysret },
	{ "sys_truncate", gt_linux_print_syscall_sys_truncate, gt_linux_print_sysret },
	{ "sys_ftruncate", gt_linux_print_syscall_sys_ftruncate, gt_linux_print_sysret },
	{ "sys_getdents", gt_linux_print_syscall_sys_getdents, gt_linux_print_sysret },
	{ "sys_getcwd", gt_linux_print_syscall_sys_getcwd, gt_linux_print_sysret },
	{ "sys_chdir", gt_linux_print_syscall_sys_chdir, gt_linux_print_sysret },
	{ "sys_fchdir", gt_linux_print_syscall_sys_fchdir, gt_linux_print_sysret },
	{ "sys_rename", gt_linux_print_syscall_sys_rename, gt_linux_print_sysret },
	{ "sys_mkdir", gt_linux_print_syscall_sys_mkdir, gt_linux_print_sysret },
	{ "sys_rmdir", gt_linux_print_syscall_sys_rmdir, gt_linux_print_sysret },
	{ "sys_creat", gt_linux_print_syscall_sys_creat, gt_linux_print_sysret },
	{ "sys_link", gt_linux_print_syscall_sys_link, gt_linux_print_sysret },
	{ "sys_unlink", gt_linux_print_syscall_sys_unlink, gt_linux_print_sysret },
	{ "sys_symlink", gt_linux_print_syscall_sys_symlink, gt_linux_print_sysret },
	{ "sys_readlink", gt_linux_print_syscall_sys_readlink, gt_linux_print_sysret },
	{ "sys_chmod", gt_linux_print_syscall_sys_chmod, gt_linux_print_sysret },
	{ "sys_fchmod", gt_linux_print_syscall_sys_fchmod, gt_linux_print_sysret },
	{ "sys_chown", gt_linux_print_syscall_sys_chown, gt_linux_print_sysret },
	{ "sys_fchown", gt_linux_print_syscall_sys_fchown, gt_linux_print_sysret },
	{ "sys_lchown", gt_linux_print_syscall_sys_lchown, gt_linux_print_sysret },
	{ "sys_umask", gt_linux_print_syscall_sys_umask, gt_linux_print_sysret },
	{ "sys_gettimeofday", gt_linux_print_syscall_sys_gettimeofday, gt_linux_print_sysret },
	{ "sys_getrlimit", gt_linux_print_syscall_sys_getrlimit, gt_linux_print_sysret },
	{ "sys_getrusage", gt_linux_print_syscall_sys_getrusage, gt_linux_print_sysret },
	{ "sys_sysinfo", gt_linux_print_syscall_sys_sysinfo, gt_linux_print_sysret },
	{ "sys_times", gt_linux_print_syscall_sys_times, gt_linux_print_sysret },
	{ "sys_ptrace", gt_linux_print_syscall_sys_ptrace, gt_linux_print_sysret },
	{ "sys_getuid", gt_linux_print_syscall_sys_getuid, gt_linux_print_sysret },
	{ "sys_syslog", gt_linux_print_syscall_sys_syslog, gt_linux_print_sysret },
	{ "sys_getgid", gt_linux_print_syscall_sys_getgid, gt_linux_print_sysret },
	{ "sys_setuid", gt_linux_print_syscall_sys_setuid, gt_linux_print_sysret },
	{ "sys_setgid", gt_linux_print_syscall_sys_setgid, gt_linux_print_sysret },
	{ "sys_geteuid", gt_linux_print_syscall_sys_geteuid, gt_linux_print_sysret },
	{ "sys_getegid", gt_linux_print_syscall_sys_getegid, gt_linux_print_sysret },
	{ "sys_setpgid", gt_linux_print_syscall_sys_setpgid, gt_linux_print_sysret },
	{ "sys_getppid", gt_linux_print_syscall_sys_getppid, gt_linux_print_sysret },
	{ "sys_getpgrp", gt_linux_print_syscall_sys_getpgrp, gt_linux_print_sysret },
	{ "sys_setsid", gt_linux_print_syscall_sys_setsid, gt_linux_print_sysret },
	{ "sys_setreuid", gt_linux_print_syscall_sys_setreuid, gt_linux_print_sysret },
	{ "sys_setregid", gt_linux_print_syscall_sys_setregid, gt_linux_print_sysret },
	{ "sys_getgroups", gt_linux_print_syscall_sys_getgroups, gt_linux_print_sysret },
	{ "sys_setgroups", gt_linux_print_syscall_sys_setgroups, gt_linux_print_sysret },
	{ "sys_setresuid", gt_linux_print_syscall_sys_setresuid, gt_linux_print_sysret },
	{ "sys_getresuid", gt_linux_print_syscall_sys_getresuid, gt_linux_print_sysret },
	{ "sys_setresgid", gt_linux_print_syscall_sys_setresgid, gt_linux_print_sysret },
	{ "sys_getresgid", gt_linux_print_syscall_sys_getresgid, gt_linux_print_sysret },
	{ "sys_getpgid", gt_linux_print_syscall_sys_getpgid, gt_linux_print_sysret },
	{ "sys_setfsuid", gt_linux_print_syscall_sys_setfsuid, gt_linux_print_sysret },
	{ "sys_setfsgid", gt_linux_print_syscall_sys_setfsgid, gt_linux_print_sysret },
	{ "sys_getsid", gt_linux_print_syscall_sys_getsid, gt_linux_print_sysret },
	{ "sys_capget", gt_linux_print_syscall_sys_capget, gt_linux_print_sysret },
	{ "sys_capset", gt_linux_print_syscall_sys_capset, gt_linux_print_sysret },
	{ "sys_rt_sigpending", gt_linux_print_syscall_sys_rt_sigpending, gt_linux_print_sysret },
	{ "sys_rt_sigtimedwait", gt_linux_print_syscall_sys_rt_sigtimedwait, gt_linux_print_sysret },
	{ "sys_rt_sigqueueinfo", gt_linux_print_syscall_sys_rt_sigqueueinfo, gt_linux_print_sysret },
	{ "sys_rt_sigsuspend", gt_linux_print_syscall_sys_rt_sigsuspend, gt_linux_print_sysret },
	{ "sys_sigaltstack", gt_linux_print_syscall_sys_sigaltstack, gt_linux_print_sysret },
	{ "sys_utime", gt_linux_print_syscall_sys_utime, gt_linux_print_sysret },
	{ "sys_mknod", gt_linux_print_syscall_sys_mknod, gt_linux_print_sysret },
	{ "sys_uselib", gt_linux_print_syscall_sys_uselib, gt_linux_print_sysret },
	{ "sys_personality", gt_linux_print_syscall_sys_personality, gt_linux_print_sysret },
	{ "sys_ustat", gt_linux_print_syscall_sys_ustat, gt_linux_print_sysret },
	{ "sys_statfs", gt_linux_print_syscall_sys_statfs, gt_linux_print_sysret },
	{ "sys_fstatfs", gt_linux_print_syscall_sys_fstatfs, gt_linux_print_sysret },
	{ "sys_sysfs", gt_linux_print_syscall_sys_sysfs, gt_linux_print_sysret },
	{ "sys_getpriority", gt_linux_print_syscall_sys_getpriority, gt_linux_print_sysret },
	{ "sys_setpriority", gt_linux_print_syscall_sys_setpriority, gt_linux_print_sysret },
	{ "sys_sched_setparam", gt_linux_print_syscall_sys_sched_setparam, gt_linux_print_sysret },
	{ "sys_sched_getparam", gt_linux_print_syscall_sys_sched_getparam, gt_linux_print_sysret },
	{ "sys_sched_setscheduler", gt_linux_print_syscall_sys_sched_setscheduler, gt_linux_print_sysret },
	{ "sys_sched_getscheduler", gt_linux_print_syscall_sys_sched_getscheduler, gt_linux_print_sysret },
	{ "sys_sched_get_priority_max", gt_linux_print_syscall_sys_sched_get_priority_max, gt_linux_print_sysret },
	{ "sys_sched_get_priority_min", gt_linux_print_syscall_sys_sched_get_priority_min, gt_linux_print_sysret },
	{ "sys_sched_rr_get_interval", gt_linux_print_syscall_sys_sched_rr_get_interval, gt_linux_print_sysret },
	{ "sys_mlock", gt_linux_print_syscall_sys_mlock, gt_linux_print_sysret },
	{ "sys_munlock", gt_linux_print_syscall_sys_munlock, gt_linux_print_sysret },
	{ "sys_mlockall", gt_linux_print_syscall_sys_mlockall, gt_linux_print_sysret },
	{ "sys_munlockall", gt_linux_print_syscall_sys_munlockall, gt_linux_print_sysret },
	{ "sys_vhangup", gt_linux_print_syscall_sys_vhangup, gt_linux_print_sysret },
	{ "sys_modify_ldt", gt_linux_print_syscall_sys_modify_ldt, gt_linux_print_sysret },
	{ "sys_pivot_root", gt_linux_print_syscall_sys_pivot_root, gt_linux_print_sysret },
	{ "sys_sysctl", gt_linux_print_syscall_sys_sysctl, gt_linux_print_sysret },
	{ "sys_prctl", gt_linux_print_syscall_sys_prctl, gt_linux_print_sysret },
	{ "sys_arch_prctl", gt_linux_print_syscall_sys_arch_prctl, gt_linux_print_sysret },
	{ "sys_adjtimex", gt_linux_print_syscall_sys_adjtimex, gt_linux_print_sysret },
	{ "sys_setrlimit", gt_linux_print_syscall_sys_setrlimit, gt_linux_print_sysret },
	{ "sys_chroot", gt_linux_print_syscall_sys_chroot, gt_linux_print_sysret },
	{ "sys_sync", gt_linux_print_syscall_sys_sync, gt_linux_print_sysret },
	{ "sys_acct", gt_linux_print_syscall_sys_acct, gt_linux_print_sysret },
	{ "sys_settimeofday", gt_linux_print_syscall_sys_settimeofday, gt_linux_print_sysret },
	{ "sys_mount", gt_linux_print_syscall_sys_mount, gt_linux_print_sysret },
	{ "sys_umount2", gt_linux_print_syscall_sys_umount2, gt_linux_print_sysret },
	{ "sys_swapon", gt_linux_print_syscall_sys_swapon, gt_linux_print_sysret },
	{ "sys_swapoff", gt_linux_print_syscall_sys_swapoff, gt_linux_print_sysret },
	{ "sys_reboot", gt_linux_print_syscall_sys_reboot, gt_linux_print_sysret },
	{ "sys_sethostname", gt_linux_print_syscall_sys_sethostname, gt_linux_print_sysret },
	{ "sys_setdomainname", gt_linux_print_syscall_sys_setdomainname, gt_linux_print_sysret },
	{ "sys_iopl", gt_linux_print_syscall_sys_iopl, gt_linux_print_sysret },
	{ "sys_ioperm", gt_linux_print_syscall_sys_ioperm, gt_linux_print_sysret },
	{ "sys_create_module", gt_linux_print_syscall_sys_create_module, gt_linux_print_sysret },
	{ "sys_init_module", gt_linux_print_syscall_sys_init_module, gt_linux_print_sysret },
	{ "sys_delete_module", gt_linux_print_syscall_sys_delete_module, gt_linux_print_sysret },
	{ "sys_get_kernel_syms", gt_linux_print_syscall_sys_get_kernel_syms, gt_linux_print_sysret },
	{ "sys_query_module", gt_linux_print_syscall_sys_query_module, gt_linux_print_sysret },
	{ "sys_quotactl", gt_linux_print_syscall_sys_quotactl, gt_linux_print_sysret },
	{ "sys_nfsservctl", gt_linux_print_syscall_sys_nfsservctl, gt_linux_print_sysret },
	{ "sys_getpmsg", gt_linux_print_syscall_sys_getpmsg, gt_linux_print_sysret },
	{ "sys_putpmsg", gt_linux_print_syscall_sys_putpmsg, gt_linux_print_sysret },
	{ "sys_afs_syscall", gt_linux_print_syscall_sys_afs_syscall, gt_linux_print_sysret },
	{ "sys_tuxcall", gt_linux_print_syscall_sys_tuxcall, gt_linux_print_sysret },
	{ "sys_security", gt_linux_print_syscall_sys_security, gt_linux_print_sysret },
	{ "sys_gettid", gt_linux_print_syscall_sys_gettid, gt_linux_print_sysret },
	{ "sys_readahead", gt_linux_print_syscall_sys_readahead, gt_linux_print_sysret },
	{ "sys_setxattr", gt_linux_print_syscall_sys_setxattr, gt_linux_print_sysret },
	{ "sys_lsetxattr", gt_linux_print_syscall_sys_lsetxattr, gt_linux_print_sysret },
	{ "sys_fsetxattr", gt_linux_print_syscall_sys_fsetxattr, gt_linux_print_sysret },
	{ "sys_getxattr", gt_linux_print_syscall_sys_getxattr, gt_linux_print_sysret },
	{ "sys_lgetxattr", gt_linux_print_syscall_sys_lgetxattr, gt_linux_print_sysret },
	{ "sys_fgetxattr", gt_linux_print_syscall_sys_fgetxattr, gt_linux_print_sysret },
	{ "sys_listxattr", gt_linux_print_syscall_sys_listxattr, gt_linux_print_sysret },
	{ "sys_llistxattr", gt_linux_print_syscall_sys_llistxattr, gt_linux_print_sysret },
	{ "sys_flistxattr", gt_linux_print_syscall_sys_flistxattr, gt_linux_print_sysret },
	{ "sys_removexattr", gt_linux_print_syscall_sys_removexattr, gt_linux_print_sysret },
	{ "sys_lremovexattr", gt_linux_print_syscall_sys_lremovexattr, gt_linux_print_sysret },
	{ "sys_fremovexattr", gt_linux_print_syscall_sys_fremovexattr, gt_linux_print_sysret },
	{ "sys_tkill", gt_linux_print_syscall_sys_tkill, gt_linux_print_sysret },
	{ "sys_time", gt_linux_print_syscall_sys_time, gt_linux_print_sysret },
	{ "sys_futex", gt_linux_print_syscall_sys_futex, gt_linux_print_sysret },
	{ "sys_sched_setaffinity", gt_linux_print_syscall_sys_sched_setaffinity, gt_linux_print_sysret },
	{ "sys_sched_getaffinity", gt_linux_print_syscall_sys_sched_getaffinity, gt_linux_print_sysret },
	{ "sys_set_thread_area", gt_linux_print_syscall_sys_set_thread_area, gt_linux_print_sysret },
	{ "sys_io_setup", gt_linux_print_syscall_sys_io_setup, gt_linux_print_sysret },
	{ "sys_io_destroy", gt_linux_print_syscall_sys_io_destroy, gt_linux_print_sysret },
	{ "sys_io_getevents", gt_linux_print_syscall_sys_io_getevents, gt_linux_print_sysret },
	{ "sys_io_submit", gt_linux_print_syscall_sys_io_submit, gt_linux_print_sysret },
	{ "sys_io_cancel", gt_linux_print_syscall_sys_io_cancel, gt_linux_print_sysret },
	{ "sys_get_thread_area", gt_linux_print_syscall_sys_get_thread_area, gt_linux_print_sysret },
	{ "sys_lookup_dcookie", gt_linux_print_syscall_sys_lookup_dcookie, gt_linux_print_sysret },
	{ "sys_epoll_create", gt_linux_print_syscall_sys_epoll_create, gt_linux_print_sysret },
	{ "sys_epoll_ctl_old", gt_linux_print_syscall_sys_epoll_ctl_old, gt_linux_print_sysret },
	{ "sys_epoll_wait_old", gt_linux_print_syscall_sys_epoll_wait_old, gt_linux_print_sysret },
	{ "sys_remap_file_pages", gt_linux_print_syscall_sys_remap_file_pages, gt_linux_print_sysret },
	{ "sys_getdents64", gt_linux_print_syscall_sys_getdents64, gt_linux_print_sysret },
	{ "sys_set_tid_address", gt_linux_print_syscall_sys_set_tid_address, gt_linux_print_sysret },
	{ "sys_restart_syscall", gt_linux_print_syscall_sys_restart_syscall, gt_linux_print_sysret },
	{ "sys_semtimedop", gt_linux_print_syscall_sys_semtimedop, gt_linux_print_sysret },
	{ "sys_fadvise64", gt_linux_print_syscall_sys_fadvise64, gt_linux_print_sysret },
	{ "sys_timer_create", gt_linux_print_syscall_sys_timer_create, gt_linux_print_sysret },
	{ "sys_timer_settime", gt_linux_print_syscall_sys_timer_settime, gt_linux_print_sysret },
	{ "sys_timer_gettime", gt_linux_print_syscall_sys_timer_gettime, gt_linux_print_sysret },
	{ "sys_timer_getoverrun", gt_linux_print_syscall_sys_timer_getoverrun, gt_linux_print_sysret },
	{ "sys_timer_delete", gt_linux_print_syscall_sys_timer_delete, gt_linux_print_sysret },
	{ "sys_clock_settime", gt_linux_print_syscall_sys_clock_settime, gt_linux_print_sysret },
	{ "sys_clock_gettime", gt_linux_print_syscall_sys_clock_gettime, gt_linux_print_sysret },
	{ "sys_clock_getres", gt_linux_print_syscall_sys_clock_getres, gt_linux_print_sysret },
	{ "sys_clock_nanosleep", gt_linux_print_syscall_sys_clock_nanosleep, gt_linux_print_sysret },
	{ "sys_exit_group", gt_linux_print_syscall_sys_exit_group, gt_linux_print_sysret },
	{ "sys_epoll_wait", gt_linux_print_syscall_sys_epoll_wait, gt_linux_print_sysret },
	{ "sys_epoll_ctl", gt_linux_print_syscall_sys_epoll_ctl, gt_linux_print_sysret },
	{ "sys_tgkill", gt_linux_print_syscall_sys_tgkill, gt_linux_print_sysret },
	{ "sys_utimes", gt_linux_print_syscall_sys_utimes, gt_linux_print_sysret },
	{ "sys_vserver", gt_linux_print_syscall_sys_vserver, gt_linux_print_sysret },
	{ "sys_mbind", gt_linux_print_syscall_sys_mbind, gt_linux_print_sysret },
	{ "sys_set_mempolicy", gt_linux_print_syscall_sys_set_mempolicy, gt_linux_print_sysret },
	{ "sys_get_mempolicy", gt_linux_print_syscall_sys_get_mempolicy, gt_linux_print_sysret },
	{ "sys_mq_open", gt_linux_print_syscall_sys_mq_open, gt_linux_print_sysret },
	{ "sys_mq_unlink", gt_linux_print_syscall_sys_mq_unlink, gt_linux_print_sysret },
	{ "sys_mq_timedsend", gt_linux_print_syscall_sys_mq_timedsend, gt_linux_print_sysret },
	{ "sys_mq_timedreceive", gt_linux_print_syscall_sys_mq_timedreceive, gt_linux_print_sysret },
	{ "sys_mq_notify", gt_linux_print_syscall_sys_mq_notify, gt_linux_print_sysret },
	{ "sys_mq_getsetattr", gt_linux_print_syscall_sys_mq_getsetattr, gt_linux_print_sysret },
	{ "sys_kexec_load", gt_linux_print_syscall_sys_kexec_load, gt_linux_print_sysret },
	{ "sys_waitid", gt_linux_print_syscall_sys_waitid, gt_linux_print_sysret },
	{ "sys_add_key", gt_linux_print_syscall_sys_add_key, gt_linux_print_sysret },
	{ "sys_request_key", gt_linux_print_syscall_sys_request_key, gt_linux_print_sysret },
	{ "sys_keyctl", gt_linux_print_syscall_sys_keyctl, gt_linux_print_sysret },
	{ "sys_ioprio_set", gt_linux_print_syscall_sys_ioprio_set, gt_linux_print_sysret },
	{ "sys_ioprio_get", gt_linux_print_syscall_sys_ioprio_get, gt_linux_print_sysret },
	{ "sys_inotify_init", gt_linux_print_syscall_sys_inotify_init, gt_linux_print_sysret },
	{ "sys_inotify_add_watch", gt_linux_print_syscall_sys_inotify_add_watch, gt_linux_print_sysret },
	{ "sys_inotify_rm_watch", gt_linux_print_syscall_sys_inotify_rm_watch, gt_linux_print_sysret },
	{ "sys_migrate_pages", gt_linux_print_syscall_sys_migrate_pages, gt_linux_print_sysret },
	{ "sys_openat", gt_linux_print_syscall_sys_openat, gt_linux_print_sysret },
	{ "sys_mkdirat", gt_linux_print_syscall_sys_mkdirat, gt_linux_print_sysret },
	{ "sys_mknodat", gt_linux_print_syscall_sys_mknodat, gt_linux_print_sysret },
	{ "sys_fchownat", gt_linux_print_syscall_sys_fchownat, gt_linux_print_sysret },
	{ "sys_futimesat", gt_linux_print_syscall_sys_futimesat, gt_linux_print_sysret },
	{ "sys_newfstatat", gt_linux_print_syscall_sys_newfstatat, gt_linux_print_sysret },
	{ "sys_unlinkat", gt_linux_print_syscall_sys_unlinkat, gt_linux_print_sysret },
	{ "sys_renameat", gt_linux_print_syscall_sys_renameat, gt_linux_print_sysret },
	{ "sys_linkat", gt_linux_print_syscall_sys_linkat, gt_linux_print_sysret },
	{ "sys_symlinkat", gt_linux_print_syscall_sys_symlinkat, gt_linux_print_sysret },
	{ "sys_readlinkat", gt_linux_print_syscall_sys_readlinkat, gt_linux_print_sysret },
	{ "sys_fchmodat", gt_linux_print_syscall_sys_fchmodat, gt_linux_print_sysret },
	{ "sys_faccessat", gt_linux_print_syscall_sys_faccessat, gt_linux_print_sysret },
	{ "sys_pselect6", gt_linux_print_syscall_sys_pselect6, gt_linux_print_sysret },
	{ "sys_ppoll", gt_linux_print_syscall_sys_ppoll, gt_linux_print_sysret },
	{ "sys_unshare", gt_linux_print_syscall_sys_unshare, gt_linux_print_sysret },
	{ "sys_set_robust_list", gt_linux_print_syscall_sys_set_robust_list, gt_linux_print_sysret },
	{ "sys_get_robust_list", gt_linux_print_syscall_sys_get_robust_list, gt_linux_print_sysret },
	{ "sys_splice", gt_linux_print_syscall_sys_splice, gt_linux_print_sysret },
	{ "sys_tee", gt_linux_print_syscall_sys_tee, gt_linux_print_sysret },
	{ "sys_sync_file_range", gt_linux_print_syscall_sys_sync_file_range, gt_linux_print_sysret },
	{ "sys_vmsplice", gt_linux_print_syscall_sys_vmsplice, gt_linux_print_sysret },
	{ "sys_move_pages", gt_linux_print_syscall_sys_move_pages, gt_linux_print_sysret },
	{ "sys_utimensat", gt_linux_print_syscall_sys_utimensat, gt_linux_print_sysret },
	{ "sys_epoll_pwait", gt_linux_print_syscall_sys_epoll_pwait, gt_linux_print_sysret },
	{ "sys_signalfd", gt_linux_print_syscall_sys_signalfd, gt_linux_print_sysret },
	{ "sys_timerfd", gt_linux_print_syscall_sys_timerfd, gt_linux_print_sysret },
	{ "sys_eventfd", gt_linux_print_syscall_sys_eventfd, gt_linux_print_sysret },
	{ "sys_fallocate", gt_linux_print_syscall_sys_fallocate, gt_linux_print_sysret },
	{ "sys_timerfd_settime", gt_linux_print_syscall_sys_timerfd_settime, gt_linux_print_sysret },
	{ "sys_timerfd_gettime", gt_linux_print_syscall_sys_timerfd_gettime, gt_linux_print_sysret },
	{ "sys_accept4", gt_linux_print_syscall_sys_accept4, gt_linux_print_sysret },
	{ "sys_signalfd4", gt_linux_print_syscall_sys_signalfd4, gt_linux_print_sysret },
	{ "sys_eventfd2", gt_linux_print_syscall_sys_eventfd2, gt_linux_print_sysret },
	{ "sys_epoll_create1", gt_linux_print_syscall_sys_epoll_create1, gt_linux_print_sysret },
	{ "sys_dup3", gt_linux_print_syscall_sys_dup3, gt_linux_print_sysret },
	{ "sys_pipe2", gt_linux_print_syscall_sys_pipe2, gt_linux_print_sysret },
	{ "sys_inotify_init1", gt_linux_print_syscall_sys_inotify_init1, gt_linux_print_sysret },
	{ "sys_preadv", gt_linux_print_syscall_sys_preadv, gt_linux_print_sysret },
	{ "sys_pwritev", gt_linux_print_syscall_sys_pwritev, gt_linux_print_sysret },
	{ "sys_rt_tgsigqueueinfo", gt_linux_print_syscall_sys_rt_tgsigqueueinfo, gt_linux_print_sysret },
	{ "sys_perf_event_open", gt_linux_print_syscall_sys_perf_event_open, gt_linux_print_sysret },
	{ "sys_recvmmsg", gt_linux_print_syscall_sys_recvmmsg, gt_linux_print_sysret },
	{ "sys_fanotify_init", gt_linux_print_syscall_sys_fanotify_init, gt_linux_print_sysret },
	{ "sys_fanotify_mark", gt_linux_print_syscall_sys_fanotify_mark, gt_linux_print_sysret },
	{ "sys_prlimit64", gt_linux_print_syscall_sys_prlimit64, gt_linux_print_sysret },
	{ "sys_name_to_handle_at", gt_linux_print_syscall_sys_name_to_handle_at, gt_linux_print_sysret },
	{ "sys_open_by_handle_at", gt_linux_print_syscall_sys_open_by_handle_at, gt_linux_print_sysret },
	{ "sys_clock_adjtime", gt_linux_print_syscall_sys_clock_adjtime, gt_linux_print_sysret },
	{ "sys_syncfs", gt_linux_print_syscall_sys_syncfs, gt_linux_print_sysret },
	{ "sys_sendmmsg", gt_linux_print_syscall_sys_sendmmsg, gt_linux_print_sysret },
	{ "sys_setns", gt_linux_print_syscall_sys_setns, gt_linux_print_sysret },
	{ "sys_getcpu", gt_linux_print_syscall_sys_getcpu, gt_linux_print_sysret },
	{ "sys_process_vm_readv", gt_linux_print_syscall_sys_process_vm_readv, gt_linux_print_sysret },
	{ "sys_process_vm_writev", gt_linux_print_syscall_sys_process_vm_writev, gt_linux_print_sysret },
	{ "sys_kcmp", gt_linux_print_syscall_sys_kcmp, gt_linux_print_sysret },
	{ "sys_finit_module", gt_linux_print_syscall_sys_finit_module, gt_linux_print_sysret },
	{ "sys_sched_setattr", gt_linux_print_syscall_sys_sched_setattr, gt_linux_print_sysret },
	{ "sys_sched_getattr", gt_linux_print_syscall_sys_sched_getattr, gt_linux_print_sysret },
	{ "sys_renameat2", gt_linux_print_syscall_sys_renameat2, gt_linux_print_sysret },
	{ "sys_seccomp", gt_linux_print_syscall_sys_seccomp, gt_linux_print_sysret },
	{ "sys_getrandom", gt_linux_print_syscall_sys_getrandom, gt_linux_print_sysret },
	{ "sys_memfd_create", gt_linux_print_syscall_sys_memfd_create, gt_linux_print_sysret },
	{ "sys_kexec_file_load", gt_linux_print_syscall_sys_kexec_file_load, gt_linux_print_sysret },
	{ "sys_bpf", gt_linux_print_syscall_sys_bpf, gt_linux_print_sysret },
	{ "sys_execveat", gt_linux_print_syscall_sys_execveat, gt_linux_print_sysret },
	{ "sys_userfaultfd", gt_linux_print_syscall_sys_userfaultfd, gt_linux_print_sysret },
	{ "sys_membarrier", gt_linux_print_syscall_sys_membarrier, gt_linux_print_sysret },
	{ "sys_mlock2", gt_linux_print_syscall_sys_mlock2, gt_linux_print_sysret },
	{ "sys_copy_file_range", gt_linux_print_syscall_sys_copy_file_range, gt_linux_print_sysret },
	{ NULL, NULL, NULL }
};


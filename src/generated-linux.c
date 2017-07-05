/* Generated on Linux_4.11.8-200.fc25.x86_64 on 05 Jul 2017 13:38:15*/

#define XC_WANT_COMPAT_EVTCHN_API

#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "functions-linux.h"
#include "generated-linux.h"

struct sys_read_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_read_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_read_args *args = g_new(struct sys_read_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_read(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_read_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_read", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_write_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_write_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_write_args *args = g_new(struct sys_write_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_write(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_write_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_write", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_open_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_open_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_open_args *args = g_new(struct sys_open_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_open(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_open_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	char *arg0 = gt_guest_get_string(state, args->arg0, pid);
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(\"%s\", %i, %lu) = %ld\n", pid, tid, proc, "sys_open", (char *) arg0, (int) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_close_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_close_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_close_args *args = g_new(struct sys_close_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_close(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_close_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu) = %ld\n", pid, tid, proc, "sys_close", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_stat_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_stat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_stat_args *args = g_new(struct sys_stat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_stat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_stat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_stat", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_fstat_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_fstat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fstat_args *args = g_new(struct sys_fstat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_fstat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fstat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_fstat", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_lstat_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_lstat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_lstat_args *args = g_new(struct sys_lstat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_lstat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_lstat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_lstat", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_poll_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_poll_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_poll_args *args = g_new(struct sys_poll_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_poll(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_poll_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %i) = %ld\n", pid, tid, proc, "sys_poll", (unsigned long) arg0, (unsigned long) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_lseek_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_lseek_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_lseek_args *args = g_new(struct sys_lseek_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_lseek(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_lseek_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_lseek", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_mmap_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
	reg_t arg5;
};

void *
generated_linux_record_syscall_sys_mmap_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mmap_args *args = g_new(struct sys_mmap_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	args->arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	return args;
}

void
generated_linux_print_syscall_sys_mmap(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mmap_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	reg_t arg5 = args->arg5;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu, %lu, %lu, %lu) = %ld\n", pid, tid, proc, "sys_mmap", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5, ret);
	g_free(args);
}

struct sys_mprotect_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_mprotect_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mprotect_args *args = g_new(struct sys_mprotect_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_mprotect(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mprotect_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu) = %ld\n", pid, tid, proc, "sys_mprotect", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_munmap_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_munmap_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_munmap_args *args = g_new(struct sys_munmap_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_munmap(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_munmap_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu) = %ld\n", pid, tid, proc, "sys_munmap", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_brk_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_brk_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_brk_args *args = g_new(struct sys_brk_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_brk(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_brk_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu) = %ld\n", pid, tid, proc, "sys_brk", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_rt_sigaction_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_rt_sigaction_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rt_sigaction_args *args = g_new(struct sys_rt_sigaction_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_rt_sigaction(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rt_sigaction_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_rt_sigaction", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_rt_sigprocmask_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_rt_sigprocmask_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rt_sigprocmask_args *args = g_new(struct sys_rt_sigprocmask_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_rt_sigprocmask(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rt_sigprocmask_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_rt_sigprocmask", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_rt_sigreturn_args {
};

void *
generated_linux_record_syscall_sys_rt_sigreturn_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rt_sigreturn_args *args = g_new(struct sys_rt_sigreturn_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_rt_sigreturn(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rt_sigreturn_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_rt_sigreturn", ret);
	g_free(args);
}

struct sys_ioctl_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_ioctl_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_ioctl_args *args = g_new(struct sys_ioctl_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_ioctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_ioctl_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu) = %ld\n", pid, tid, proc, "sys_ioctl", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_pread_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_pread_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pread_args *args = g_new(struct sys_pread_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_pread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pread_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %li) = %ld\n", pid, tid, proc, "sys_pread", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (long int) arg3, ret);
	g_free(args);
}

struct sys_pwrite_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_pwrite_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pwrite_args *args = g_new(struct sys_pwrite_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_pwrite(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pwrite_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %li) = %ld\n", pid, tid, proc, "sys_pwrite", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (long int) arg3, ret);
	g_free(args);
}

struct sys_readv_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_readv_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_readv_args *args = g_new(struct sys_readv_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_readv(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_readv_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_readv", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_writev_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_writev_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_writev_args *args = g_new(struct sys_writev_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_writev(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_writev_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_writev", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_access_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_access_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_access_args *args = g_new(struct sys_access_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_access(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_access_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_access", (unsigned long) arg0, (int) arg1, ret);
	g_free(args);
}

struct sys_pipe_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_pipe_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pipe_args *args = g_new(struct sys_pipe_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_pipe(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pipe_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_pipe", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_select_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_select_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_select_args *args = g_new(struct sys_select_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_select(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_select_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_select", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_sched_yield_args {
};

void *
generated_linux_record_syscall_sys_sched_yield_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_yield_args *args = g_new(struct sys_sched_yield_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_sched_yield(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_yield_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_sched_yield", ret);
	g_free(args);
}

struct sys_mremap_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_mremap_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mremap_args *args = g_new(struct sys_mremap_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_mremap(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mremap_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu, %lu, %lu) = %ld\n", pid, tid, proc, "sys_mremap", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_msync_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_msync_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_msync_args *args = g_new(struct sys_msync_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_msync(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_msync_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i) = %ld\n", pid, tid, proc, "sys_msync", (unsigned long) arg0, (unsigned long) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_mincore_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_mincore_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mincore_args *args = g_new(struct sys_mincore_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_mincore(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mincore_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_mincore", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_madvise_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_madvise_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_madvise_args *args = g_new(struct sys_madvise_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_madvise(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_madvise_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i) = %ld\n", pid, tid, proc, "sys_madvise", (unsigned long) arg0, (unsigned long) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_shmget_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_shmget_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_shmget_args *args = g_new(struct sys_shmget_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_shmget(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_shmget_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %i) = %ld\n", pid, tid, proc, "sys_shmget", (int) arg0, (unsigned long) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_shmat_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_shmat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_shmat_args *args = g_new(struct sys_shmat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_shmat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_shmat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_shmat", (int) arg0, (unsigned long) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_shmctl_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_shmctl_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_shmctl_args *args = g_new(struct sys_shmctl_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_shmctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_shmctl_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_shmctl", (int) arg0, (int) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_dup_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_dup_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_dup_args *args = g_new(struct sys_dup_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_dup(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_dup_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu) = %ld\n", pid, tid, proc, "sys_dup", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_dup2_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_dup2_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_dup2_args *args = g_new(struct sys_dup2_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_dup2(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_dup2_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu) = %ld\n", pid, tid, proc, "sys_dup2", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_pause_args {
};

void *
generated_linux_record_syscall_sys_pause_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pause_args *args = g_new(struct sys_pause_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_pause(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pause_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_pause", ret);
	g_free(args);
}

struct sys_nanosleep_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_nanosleep_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_nanosleep_args *args = g_new(struct sys_nanosleep_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_nanosleep(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_nanosleep_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_nanosleep", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_getitimer_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_getitimer_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getitimer_args *args = g_new(struct sys_getitimer_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_getitimer(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getitimer_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_getitimer", (int) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_alarm_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_alarm_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_alarm_args *args = g_new(struct sys_alarm_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_alarm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_alarm_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu) = %ld\n", pid, tid, proc, "sys_alarm", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_setitimer_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_setitimer_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setitimer_args *args = g_new(struct sys_setitimer_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_setitimer(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setitimer_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_setitimer", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_getpid_args {
};

void *
generated_linux_record_syscall_sys_getpid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getpid_args *args = g_new(struct sys_getpid_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_getpid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getpid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_getpid", ret);
	g_free(args);
}

struct sys_sendfile_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_sendfile_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sendfile_args *args = g_new(struct sys_sendfile_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_sendfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sendfile_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_sendfile", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_socket_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_socket_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_socket_args *args = g_new(struct sys_socket_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_socket(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_socket_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i) = %ld\n", pid, tid, proc, "sys_socket", (int) arg0, (int) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_connect_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_connect_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_connect_args *args = g_new(struct sys_connect_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_connect(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_connect_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_connect", (int) arg0, (unsigned long) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_accept_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_accept_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_accept_args *args = g_new(struct sys_accept_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_accept(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_accept_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_accept", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_sendto_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
	reg_t arg5;
};

void *
generated_linux_record_syscall_sys_sendto_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sendto_args *args = g_new(struct sys_sendto_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	args->arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	return args;
}

void
generated_linux_print_syscall_sys_sendto(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sendto_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	reg_t arg5 = args->arg5;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_sendto", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (int) arg5, ret);
	g_free(args);
}

struct sys_recvfrom_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
	reg_t arg5;
};

void *
generated_linux_record_syscall_sys_recvfrom_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_recvfrom_args *args = g_new(struct sys_recvfrom_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	args->arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	return args;
}

void
generated_linux_print_syscall_sys_recvfrom(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_recvfrom_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	reg_t arg5 = args->arg5;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_recvfrom", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5, ret);
	g_free(args);
}

struct sys_sendmsg_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_sendmsg_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sendmsg_args *args = g_new(struct sys_sendmsg_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_sendmsg(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sendmsg_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_sendmsg", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_recvmsg_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_recvmsg_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_recvmsg_args *args = g_new(struct sys_recvmsg_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_recvmsg(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_recvmsg_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_recvmsg", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_shutdown_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_shutdown_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_shutdown_args *args = g_new(struct sys_shutdown_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_shutdown(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_shutdown_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i) = %ld\n", pid, tid, proc, "sys_shutdown", (int) arg0, (int) arg1, ret);
	g_free(args);
}

struct sys_bind_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_bind_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_bind_args *args = g_new(struct sys_bind_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_bind(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_bind_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_bind", (int) arg0, (unsigned long) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_listen_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_listen_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_listen_args *args = g_new(struct sys_listen_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_listen(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_listen_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i) = %ld\n", pid, tid, proc, "sys_listen", (int) arg0, (int) arg1, ret);
	g_free(args);
}

struct sys_getsockname_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_getsockname_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getsockname_args *args = g_new(struct sys_getsockname_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_getsockname(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getsockname_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_getsockname", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_getpeername_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_getpeername_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getpeername_args *args = g_new(struct sys_getpeername_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_getpeername(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getpeername_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_getpeername", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_socketpair_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_socketpair_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_socketpair_args *args = g_new(struct sys_socketpair_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_socketpair(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_socketpair_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_socketpair", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_setsockopt_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_setsockopt_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setsockopt_args *args = g_new(struct sys_setsockopt_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_setsockopt(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setsockopt_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_setsockopt", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, (int) arg4, ret);
	g_free(args);
}

struct sys_getsockopt_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_getsockopt_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getsockopt_args *args = g_new(struct sys_getsockopt_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_getsockopt(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getsockopt_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_getsockopt", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_clone_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_clone_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_clone_args *args = g_new(struct sys_clone_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_clone(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_clone_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, 0x%"PRIx64", %lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_clone", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_fork_args {
};

void *
generated_linux_record_syscall_sys_fork_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fork_args *args = g_new(struct sys_fork_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_fork(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fork_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_fork", ret);
	g_free(args);
}

struct sys_vfork_args {
};

void *
generated_linux_record_syscall_sys_vfork_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_vfork_args *args = g_new(struct sys_vfork_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_vfork(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_vfork_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_vfork", ret);
	g_free(args);
}


struct sys_execve_args {
	char *path;
	char **argv;
	char **env;
	char *oldpath;
};

void *
generated_linux_record_syscall_sys_execve_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_execve_args *args = g_new(struct sys_execve_args, 1);
	args->path = gt_guest_get_string(state, gt_guest_get_vmi_event(state)->x86_regs->rdi, pid);
	args->argv = gt_guest_get_argv  (state, gt_guest_get_vmi_event(state)->x86_regs->rsi, pid);
	args->env  = gt_guest_get_argv  (state, gt_guest_get_vmi_event(state)->x86_regs->rdx, pid);
	args->oldpath = gt_guest_get_process_name(state);
	return args;
}

void
generated_linux_print_argv(char **argv)
{
	fprintf(stderr, "[");
	for (int i = 0; argv && argv[i]; i++) {
		fprintf(stderr, "\"%s\"", argv[i]);
		if (argv[i + 1]) {
			fprintf(stderr, ", ");
		}
	}
	fprintf(stderr, "]");
}

void
generated_linux_print_syscall_sys_execve(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_execve_args *args = user_data;
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	args->path = args->path ? args->path : gt_guest_get_process_name(state);
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(\"%s\", ", pid, tid, args->oldpath, "sys_execve", (char *) args->path);
	generated_linux_print_argv(args->argv);
	fprintf(stderr, ", ");
	generated_linux_print_argv(args->env);
	fprintf(stderr, ") = %ld\n", ret);
	g_free(args);
}
struct sys_exit_args {
	reg_t arg0;
};

void
generated_linux_print_syscall_sys_exit(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_exit_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i) = %ld\n", pid, tid, proc, "sys_exit", (int) arg0, ret);
	g_free(args);
}

void *
generated_linux_record_syscall_sys_exit_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_exit_args *args = g_new(struct sys_exit_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	generated_linux_print_syscall_sys_exit(state, pid, tid, args);
    return NULL;
}

struct sys_wait4_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_wait4_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_wait4_args *args = g_new(struct sys_wait4_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_wait4(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_wait4_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_wait4", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_kill_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_kill_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_kill_args *args = g_new(struct sys_kill_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_kill(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_kill_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i) = %ld\n", pid, tid, proc, "sys_kill", (int) arg0, (int) arg1, ret);
	g_free(args);
}

struct sys_uname_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_uname_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_uname_args *args = g_new(struct sys_uname_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_uname(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_uname_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_uname", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_semget_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_semget_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_semget_args *args = g_new(struct sys_semget_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_semget(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_semget_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i) = %ld\n", pid, tid, proc, "sys_semget", (int) arg0, (int) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_semop_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_semop_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_semop_args *args = g_new(struct sys_semop_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_semop(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_semop_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_semop", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_semctl_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_semctl_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_semctl_args *args = g_new(struct sys_semctl_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_semctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_semctl_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, %lu) = %ld\n", pid, tid, proc, "sys_semctl", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_shmdt_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_shmdt_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_shmdt_args *args = g_new(struct sys_shmdt_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_shmdt(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_shmdt_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_shmdt", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_msgget_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_msgget_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_msgget_args *args = g_new(struct sys_msgget_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_msgget(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_msgget_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i) = %ld\n", pid, tid, proc, "sys_msgget", (int) arg0, (int) arg1, ret);
	g_free(args);
}

struct sys_msgsnd_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_msgsnd_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_msgsnd_args *args = g_new(struct sys_msgsnd_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_msgsnd(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_msgsnd_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %i) = %ld\n", pid, tid, proc, "sys_msgsnd", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3, ret);
	g_free(args);
}

struct sys_msgrcv_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_msgrcv_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_msgrcv_args *args = g_new(struct sys_msgrcv_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_msgrcv(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_msgrcv_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %li, %i) = %ld\n", pid, tid, proc, "sys_msgrcv", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (long int) arg3, (int) arg4, ret);
	g_free(args);
}

struct sys_msgctl_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_msgctl_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_msgctl_args *args = g_new(struct sys_msgctl_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_msgctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_msgctl_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_msgctl", (int) arg0, (int) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_fcntl_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_fcntl_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fcntl_args *args = g_new(struct sys_fcntl_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_fcntl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fcntl_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu) = %ld\n", pid, tid, proc, "sys_fcntl", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_flock_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_flock_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_flock_args *args = g_new(struct sys_flock_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_flock(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_flock_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu) = %ld\n", pid, tid, proc, "sys_flock", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_fsync_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_fsync_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fsync_args *args = g_new(struct sys_fsync_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_fsync(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fsync_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu) = %ld\n", pid, tid, proc, "sys_fsync", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_fdatasync_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_fdatasync_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fdatasync_args *args = g_new(struct sys_fdatasync_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_fdatasync(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fdatasync_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu) = %ld\n", pid, tid, proc, "sys_fdatasync", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_truncate_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_truncate_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_truncate_args *args = g_new(struct sys_truncate_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_truncate(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_truncate_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %li) = %ld\n", pid, tid, proc, "sys_truncate", (unsigned long) arg0, (long int) arg1, ret);
	g_free(args);
}

struct sys_ftruncate_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_ftruncate_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_ftruncate_args *args = g_new(struct sys_ftruncate_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_ftruncate(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_ftruncate_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu) = %ld\n", pid, tid, proc, "sys_ftruncate", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_getdents_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_getdents_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getdents_args *args = g_new(struct sys_getdents_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_getdents(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getdents_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_getdents", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_getcwd_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_getcwd_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getcwd_args *args = g_new(struct sys_getcwd_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_getcwd(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getcwd_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_getcwd", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_chdir_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_chdir_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_chdir_args *args = g_new(struct sys_chdir_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_chdir(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_chdir_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_chdir", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_fchdir_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_fchdir_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fchdir_args *args = g_new(struct sys_fchdir_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_fchdir(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fchdir_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu) = %ld\n", pid, tid, proc, "sys_fchdir", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_rename_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_rename_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rename_args *args = g_new(struct sys_rename_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_rename(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rename_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_rename", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_mkdir_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_mkdir_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mkdir_args *args = g_new(struct sys_mkdir_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_mkdir(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mkdir_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_mkdir", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_rmdir_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_rmdir_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rmdir_args *args = g_new(struct sys_rmdir_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_rmdir(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rmdir_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_rmdir", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_creat_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_creat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_creat_args *args = g_new(struct sys_creat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_creat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_creat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_creat", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_link_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_link_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_link_args *args = g_new(struct sys_link_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_link(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_link_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_link", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_unlink_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_unlink_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_unlink_args *args = g_new(struct sys_unlink_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_unlink(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_unlink_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_unlink", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_symlink_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_symlink_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_symlink_args *args = g_new(struct sys_symlink_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_symlink(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_symlink_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_symlink", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_readlink_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_readlink_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_readlink_args *args = g_new(struct sys_readlink_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_readlink(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_readlink_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_readlink", (unsigned long) arg0, (unsigned long) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_chmod_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_chmod_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_chmod_args *args = g_new(struct sys_chmod_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_chmod(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_chmod_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_chmod", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_fchmod_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_fchmod_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fchmod_args *args = g_new(struct sys_fchmod_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_fchmod(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fchmod_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu) = %ld\n", pid, tid, proc, "sys_fchmod", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_chown_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_chown_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_chown_args *args = g_new(struct sys_chown_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_chown(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_chown_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %lu) = %ld\n", pid, tid, proc, "sys_chown", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_fchown_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_fchown_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fchown_args *args = g_new(struct sys_fchown_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_fchown(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fchown_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu) = %ld\n", pid, tid, proc, "sys_fchown", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_lchown_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_lchown_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_lchown_args *args = g_new(struct sys_lchown_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_lchown(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_lchown_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %lu) = %ld\n", pid, tid, proc, "sys_lchown", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_umask_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_umask_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_umask_args *args = g_new(struct sys_umask_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_umask(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_umask_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i) = %ld\n", pid, tid, proc, "sys_umask", (int) arg0, ret);
	g_free(args);
}

struct sys_gettimeofday_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_gettimeofday_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_gettimeofday_args *args = g_new(struct sys_gettimeofday_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_gettimeofday(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_gettimeofday_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_gettimeofday", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_getrlimit_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_getrlimit_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getrlimit_args *args = g_new(struct sys_getrlimit_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_getrlimit(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getrlimit_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_getrlimit", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_getrusage_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_getrusage_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getrusage_args *args = g_new(struct sys_getrusage_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_getrusage(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getrusage_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_getrusage", (int) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_sysinfo_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_sysinfo_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sysinfo_args *args = g_new(struct sys_sysinfo_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_sysinfo(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sysinfo_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_sysinfo", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_times_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_times_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_times_args *args = g_new(struct sys_times_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_times(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_times_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_times", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_ptrace_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_ptrace_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_ptrace_args *args = g_new(struct sys_ptrace_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_ptrace(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_ptrace_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%li, %li, %lu, %lu) = %ld\n", pid, tid, proc, "sys_ptrace", (long int) arg0, (long int) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_getuid_args {
};

void *
generated_linux_record_syscall_sys_getuid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getuid_args *args = g_new(struct sys_getuid_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_getuid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getuid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_getuid", ret);
	g_free(args);
}

struct sys_syslog_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_syslog_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_syslog_args *args = g_new(struct sys_syslog_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_syslog(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_syslog_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_syslog", (int) arg0, (unsigned long) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_getgid_args {
};

void *
generated_linux_record_syscall_sys_getgid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getgid_args *args = g_new(struct sys_getgid_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_getgid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getgid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_getgid", ret);
	g_free(args);
}

struct sys_setuid_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_setuid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setuid_args *args = g_new(struct sys_setuid_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_setuid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setuid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu) = %ld\n", pid, tid, proc, "sys_setuid", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_setgid_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_setgid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setgid_args *args = g_new(struct sys_setgid_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_setgid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setgid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu) = %ld\n", pid, tid, proc, "sys_setgid", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_geteuid_args {
};

void *
generated_linux_record_syscall_sys_geteuid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_geteuid_args *args = g_new(struct sys_geteuid_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_geteuid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_geteuid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_geteuid", ret);
	g_free(args);
}

struct sys_getegid_args {
};

void *
generated_linux_record_syscall_sys_getegid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getegid_args *args = g_new(struct sys_getegid_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_getegid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getegid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_getegid", ret);
	g_free(args);
}

struct sys_setpgid_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_setpgid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setpgid_args *args = g_new(struct sys_setpgid_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_setpgid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setpgid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i) = %ld\n", pid, tid, proc, "sys_setpgid", (int) arg0, (int) arg1, ret);
	g_free(args);
}

struct sys_getppid_args {
};

void *
generated_linux_record_syscall_sys_getppid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getppid_args *args = g_new(struct sys_getppid_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_getppid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getppid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_getppid", ret);
	g_free(args);
}

struct sys_getpgrp_args {
};

void *
generated_linux_record_syscall_sys_getpgrp_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getpgrp_args *args = g_new(struct sys_getpgrp_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_getpgrp(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getpgrp_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_getpgrp", ret);
	g_free(args);
}

struct sys_setsid_args {
};

void *
generated_linux_record_syscall_sys_setsid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setsid_args *args = g_new(struct sys_setsid_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_setsid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setsid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_setsid", ret);
	g_free(args);
}

struct sys_setreuid_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_setreuid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setreuid_args *args = g_new(struct sys_setreuid_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_setreuid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setreuid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu) = %ld\n", pid, tid, proc, "sys_setreuid", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_setregid_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_setregid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setregid_args *args = g_new(struct sys_setregid_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_setregid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setregid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu) = %ld\n", pid, tid, proc, "sys_setregid", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_getgroups_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_getgroups_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getgroups_args *args = g_new(struct sys_getgroups_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_getgroups(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getgroups_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_getgroups", (int) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_setgroups_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_setgroups_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setgroups_args *args = g_new(struct sys_setgroups_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_setgroups(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setgroups_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_setgroups", (int) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_setresuid_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_setresuid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setresuid_args *args = g_new(struct sys_setresuid_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_setresuid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setresuid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu) = %ld\n", pid, tid, proc, "sys_setresuid", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_getresuid_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_getresuid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getresuid_args *args = g_new(struct sys_getresuid_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_getresuid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getresuid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_getresuid", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_setresgid_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_setresgid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setresgid_args *args = g_new(struct sys_setresgid_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_setresgid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setresgid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu) = %ld\n", pid, tid, proc, "sys_setresgid", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_getresgid_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_getresgid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getresgid_args *args = g_new(struct sys_getresgid_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_getresgid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getresgid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_getresgid", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_getpgid_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_getpgid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getpgid_args *args = g_new(struct sys_getpgid_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_getpgid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getpgid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i) = %ld\n", pid, tid, proc, "sys_getpgid", (int) arg0, ret);
	g_free(args);
}

struct sys_setfsuid_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_setfsuid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setfsuid_args *args = g_new(struct sys_setfsuid_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_setfsuid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setfsuid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu) = %ld\n", pid, tid, proc, "sys_setfsuid", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_setfsgid_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_setfsgid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setfsgid_args *args = g_new(struct sys_setfsgid_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_setfsgid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setfsgid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu) = %ld\n", pid, tid, proc, "sys_setfsgid", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_getsid_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_getsid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getsid_args *args = g_new(struct sys_getsid_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_getsid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getsid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i) = %ld\n", pid, tid, proc, "sys_getsid", (int) arg0, ret);
	g_free(args);
}

struct sys_capget_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_capget_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_capget_args *args = g_new(struct sys_capget_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_capget(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_capget_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_capget", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_capset_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_capset_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_capset_args *args = g_new(struct sys_capset_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_capset(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_capset_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_capset", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_rt_sigpending_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_rt_sigpending_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rt_sigpending_args *args = g_new(struct sys_rt_sigpending_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_rt_sigpending(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rt_sigpending_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_rt_sigpending", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_rt_sigtimedwait_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_rt_sigtimedwait_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rt_sigtimedwait_args *args = g_new(struct sys_rt_sigtimedwait_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_rt_sigtimedwait(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rt_sigtimedwait_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_rt_sigtimedwait", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_rt_sigqueueinfo_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_rt_sigqueueinfo_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rt_sigqueueinfo_args *args = g_new(struct sys_rt_sigqueueinfo_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_rt_sigqueueinfo(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rt_sigqueueinfo_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_rt_sigqueueinfo", (int) arg0, (int) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_rt_sigsuspend_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_rt_sigsuspend_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rt_sigsuspend_args *args = g_new(struct sys_rt_sigsuspend_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_rt_sigsuspend(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rt_sigsuspend_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_rt_sigsuspend", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_sigaltstack_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_sigaltstack_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sigaltstack_args *args = g_new(struct sys_sigaltstack_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_sigaltstack(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sigaltstack_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_sigaltstack", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_utime_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_utime_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_utime_args *args = g_new(struct sys_utime_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_utime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_utime_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_utime", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_mknod_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_mknod_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mknod_args *args = g_new(struct sys_mknod_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_mknod(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mknod_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %lu) = %ld\n", pid, tid, proc, "sys_mknod", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_uselib_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_uselib_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_uselib_args *args = g_new(struct sys_uselib_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_uselib(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_uselib_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_uselib", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_personality_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_personality_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_personality_args *args = g_new(struct sys_personality_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_personality(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_personality_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu) = %ld\n", pid, tid, proc, "sys_personality", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_ustat_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_ustat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_ustat_args *args = g_new(struct sys_ustat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_ustat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_ustat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_ustat", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_statfs_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_statfs_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_statfs_args *args = g_new(struct sys_statfs_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_statfs(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_statfs_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_statfs", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_fstatfs_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_fstatfs_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fstatfs_args *args = g_new(struct sys_fstatfs_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_fstatfs(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fstatfs_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_fstatfs", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_sysfs_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_sysfs_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sysfs_args *args = g_new(struct sys_sysfs_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_sysfs(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sysfs_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %lu) = %ld\n", pid, tid, proc, "sys_sysfs", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_getpriority_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_getpriority_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getpriority_args *args = g_new(struct sys_getpriority_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_getpriority(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getpriority_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i) = %ld\n", pid, tid, proc, "sys_getpriority", (int) arg0, (int) arg1, ret);
	g_free(args);
}

struct sys_setpriority_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_setpriority_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setpriority_args *args = g_new(struct sys_setpriority_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_setpriority(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setpriority_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i) = %ld\n", pid, tid, proc, "sys_setpriority", (int) arg0, (int) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_sched_setparam_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_sched_setparam_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_setparam_args *args = g_new(struct sys_sched_setparam_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_sched_setparam(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_setparam_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_sched_setparam", (int) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_sched_getparam_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_sched_getparam_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_getparam_args *args = g_new(struct sys_sched_getparam_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_sched_getparam(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_getparam_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_sched_getparam", (int) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_sched_setscheduler_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_sched_setscheduler_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_setscheduler_args *args = g_new(struct sys_sched_setscheduler_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_sched_setscheduler(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_setscheduler_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_sched_setscheduler", (int) arg0, (int) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_sched_getscheduler_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_sched_getscheduler_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_getscheduler_args *args = g_new(struct sys_sched_getscheduler_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_sched_getscheduler(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_getscheduler_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i) = %ld\n", pid, tid, proc, "sys_sched_getscheduler", (int) arg0, ret);
	g_free(args);
}

struct sys_sched_get_priority_max_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_sched_get_priority_max_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_get_priority_max_args *args = g_new(struct sys_sched_get_priority_max_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_sched_get_priority_max(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_get_priority_max_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i) = %ld\n", pid, tid, proc, "sys_sched_get_priority_max", (int) arg0, ret);
	g_free(args);
}

struct sys_sched_get_priority_min_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_sched_get_priority_min_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_get_priority_min_args *args = g_new(struct sys_sched_get_priority_min_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_sched_get_priority_min(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_get_priority_min_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i) = %ld\n", pid, tid, proc, "sys_sched_get_priority_min", (int) arg0, ret);
	g_free(args);
}

struct sys_sched_rr_get_interval_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_sched_rr_get_interval_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_rr_get_interval_args *args = g_new(struct sys_sched_rr_get_interval_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_sched_rr_get_interval(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_rr_get_interval_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_sched_rr_get_interval", (int) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_mlock_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_mlock_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mlock_args *args = g_new(struct sys_mlock_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_mlock(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mlock_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu) = %ld\n", pid, tid, proc, "sys_mlock", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_munlock_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_munlock_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_munlock_args *args = g_new(struct sys_munlock_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_munlock(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_munlock_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu) = %ld\n", pid, tid, proc, "sys_munlock", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_mlockall_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_mlockall_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mlockall_args *args = g_new(struct sys_mlockall_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_mlockall(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mlockall_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i) = %ld\n", pid, tid, proc, "sys_mlockall", (int) arg0, ret);
	g_free(args);
}

struct sys_munlockall_args {
};

void *
generated_linux_record_syscall_sys_munlockall_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_munlockall_args *args = g_new(struct sys_munlockall_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_munlockall(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_munlockall_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_munlockall", ret);
	g_free(args);
}

struct sys_vhangup_args {
};

void *
generated_linux_record_syscall_sys_vhangup_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_vhangup_args *args = g_new(struct sys_vhangup_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_vhangup(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_vhangup_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_vhangup", ret);
	g_free(args);
}

struct sys_modify_ldt_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_modify_ldt_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_modify_ldt_args *args = g_new(struct sys_modify_ldt_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_modify_ldt(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_modify_ldt_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_modify_ldt", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_pivot_root_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_pivot_root_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pivot_root_args *args = g_new(struct sys_pivot_root_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_pivot_root(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pivot_root_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_pivot_root", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_sysctl_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_sysctl_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sysctl_args *args = g_new(struct sys_sysctl_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_sysctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sysctl_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_sysctl", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_prctl_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_prctl_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_prctl_args *args = g_new(struct sys_prctl_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_prctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_prctl_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %lu, %lu, %lu) = %ld\n", pid, tid, proc, "sys_prctl", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_arch_prctl_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_arch_prctl_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_arch_prctl_args *args = g_new(struct sys_arch_prctl_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_arch_prctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_arch_prctl_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu) = %ld\n", pid, tid, proc, "sys_arch_prctl", (int) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_adjtimex_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_adjtimex_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_adjtimex_args *args = g_new(struct sys_adjtimex_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_adjtimex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_adjtimex_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_adjtimex", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_setrlimit_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_setrlimit_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setrlimit_args *args = g_new(struct sys_setrlimit_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_setrlimit(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setrlimit_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_setrlimit", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_chroot_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_chroot_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_chroot_args *args = g_new(struct sys_chroot_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_chroot(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_chroot_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_chroot", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_sync_args {
};

void *
generated_linux_record_syscall_sys_sync_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sync_args *args = g_new(struct sys_sync_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_sync(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sync_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_sync", ret);
	g_free(args);
}

struct sys_acct_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_acct_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_acct_args *args = g_new(struct sys_acct_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_acct(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_acct_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_acct", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_settimeofday_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_settimeofday_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_settimeofday_args *args = g_new(struct sys_settimeofday_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_settimeofday(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_settimeofday_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_settimeofday", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_mount_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_mount_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mount_args *args = g_new(struct sys_mount_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_mount(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mount_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_mount", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_umount2_args {
};

void *
generated_linux_record_syscall_sys_umount2_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_umount2_args *args = g_new(struct sys_umount2_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_umount2(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_umount2_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_umount2", ret);
	g_free(args);
}

struct sys_swapon_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_swapon_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_swapon_args *args = g_new(struct sys_swapon_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_swapon(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_swapon_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_swapon", (unsigned long) arg0, (int) arg1, ret);
	g_free(args);
}

struct sys_swapoff_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_swapoff_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_swapoff_args *args = g_new(struct sys_swapoff_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_swapoff(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_swapoff_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_swapoff", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_reboot_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_reboot_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_reboot_args *args = g_new(struct sys_reboot_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_reboot(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_reboot_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_reboot", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_sethostname_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_sethostname_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sethostname_args *args = g_new(struct sys_sethostname_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_sethostname(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sethostname_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_sethostname", (unsigned long) arg0, (int) arg1, ret);
	g_free(args);
}

struct sys_setdomainname_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_setdomainname_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setdomainname_args *args = g_new(struct sys_setdomainname_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_setdomainname(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setdomainname_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_setdomainname", (unsigned long) arg0, (int) arg1, ret);
	g_free(args);
}

struct sys_iopl_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_iopl_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_iopl_args *args = g_new(struct sys_iopl_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_iopl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_iopl_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu) = %ld\n", pid, tid, proc, "sys_iopl", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_ioperm_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_ioperm_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_ioperm_args *args = g_new(struct sys_ioperm_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_ioperm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_ioperm_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i) = %ld\n", pid, tid, proc, "sys_ioperm", (unsigned long) arg0, (unsigned long) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_create_module_args {
};

void *
generated_linux_record_syscall_sys_create_module_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_create_module_args *args = g_new(struct sys_create_module_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_create_module(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_create_module_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_create_module", ret);
	g_free(args);
}

struct sys_init_module_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_init_module_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_init_module_args *args = g_new(struct sys_init_module_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_init_module(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_init_module_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_init_module", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_delete_module_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_delete_module_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_delete_module_args *args = g_new(struct sys_delete_module_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_delete_module(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_delete_module_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_delete_module", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_get_kernel_syms_args {
};

void *
generated_linux_record_syscall_sys_get_kernel_syms_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_get_kernel_syms_args *args = g_new(struct sys_get_kernel_syms_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_get_kernel_syms(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_get_kernel_syms_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_get_kernel_syms", ret);
	g_free(args);
}

struct sys_query_module_args {
};

void *
generated_linux_record_syscall_sys_query_module_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_query_module_args *args = g_new(struct sys_query_module_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_query_module(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_query_module_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_query_module", ret);
	g_free(args);
}

struct sys_quotactl_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_quotactl_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_quotactl_args *args = g_new(struct sys_quotactl_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_quotactl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_quotactl_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_quotactl", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_nfsservctl_args {
};

void *
generated_linux_record_syscall_sys_nfsservctl_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_nfsservctl_args *args = g_new(struct sys_nfsservctl_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_nfsservctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_nfsservctl_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_nfsservctl", ret);
	g_free(args);
}

struct sys_getpmsg_args {
};

void *
generated_linux_record_syscall_sys_getpmsg_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getpmsg_args *args = g_new(struct sys_getpmsg_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_getpmsg(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getpmsg_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_getpmsg", ret);
	g_free(args);
}

struct sys_putpmsg_args {
};

void *
generated_linux_record_syscall_sys_putpmsg_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_putpmsg_args *args = g_new(struct sys_putpmsg_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_putpmsg(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_putpmsg_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_putpmsg", ret);
	g_free(args);
}

struct sys_afs_syscall_args {
};

void *
generated_linux_record_syscall_sys_afs_syscall_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_afs_syscall_args *args = g_new(struct sys_afs_syscall_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_afs_syscall(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_afs_syscall_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_afs_syscall", ret);
	g_free(args);
}

struct sys_tuxcall_args {
};

void *
generated_linux_record_syscall_sys_tuxcall_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_tuxcall_args *args = g_new(struct sys_tuxcall_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_tuxcall(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_tuxcall_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_tuxcall", ret);
	g_free(args);
}

struct sys_security_args {
};

void *
generated_linux_record_syscall_sys_security_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_security_args *args = g_new(struct sys_security_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_security(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_security_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_security", ret);
	g_free(args);
}

struct sys_gettid_args {
};

void *
generated_linux_record_syscall_sys_gettid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_gettid_args *args = g_new(struct sys_gettid_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_gettid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_gettid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_gettid", ret);
	g_free(args);
}

struct sys_readahead_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_readahead_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_readahead_args *args = g_new(struct sys_readahead_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_readahead(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_readahead_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %li, %lu) = %ld\n", pid, tid, proc, "sys_readahead", (int) arg0, (long int) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_setxattr_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_setxattr_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setxattr_args *args = g_new(struct sys_setxattr_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_setxattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setxattr_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, %i) = %ld\n", pid, tid, proc, "sys_setxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4, ret);
	g_free(args);
}

struct sys_lsetxattr_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_lsetxattr_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_lsetxattr_args *args = g_new(struct sys_lsetxattr_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_lsetxattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_lsetxattr_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, %i) = %ld\n", pid, tid, proc, "sys_lsetxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4, ret);
	g_free(args);
}

struct sys_fsetxattr_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_fsetxattr_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fsetxattr_args *args = g_new(struct sys_fsetxattr_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_fsetxattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fsetxattr_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %lu, %i) = %ld\n", pid, tid, proc, "sys_fsetxattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4, ret);
	g_free(args);
}

struct sys_getxattr_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_getxattr_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getxattr_args *args = g_new(struct sys_getxattr_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_getxattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getxattr_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_getxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_lgetxattr_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_lgetxattr_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_lgetxattr_args *args = g_new(struct sys_lgetxattr_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_lgetxattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_lgetxattr_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_lgetxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_fgetxattr_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_fgetxattr_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fgetxattr_args *args = g_new(struct sys_fgetxattr_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_fgetxattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fgetxattr_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_fgetxattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_listxattr_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_listxattr_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_listxattr_args *args = g_new(struct sys_listxattr_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_listxattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_listxattr_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_listxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_llistxattr_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_llistxattr_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_llistxattr_args *args = g_new(struct sys_llistxattr_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_llistxattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_llistxattr_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_llistxattr", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_flistxattr_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_flistxattr_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_flistxattr_args *args = g_new(struct sys_flistxattr_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_flistxattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_flistxattr_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_flistxattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_removexattr_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_removexattr_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_removexattr_args *args = g_new(struct sys_removexattr_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_removexattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_removexattr_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_removexattr", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_lremovexattr_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_lremovexattr_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_lremovexattr_args *args = g_new(struct sys_lremovexattr_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_lremovexattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_lremovexattr_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_lremovexattr", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_fremovexattr_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_fremovexattr_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fremovexattr_args *args = g_new(struct sys_fremovexattr_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_fremovexattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fremovexattr_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_fremovexattr", (int) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_tkill_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_tkill_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_tkill_args *args = g_new(struct sys_tkill_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_tkill(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_tkill_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i) = %ld\n", pid, tid, proc, "sys_tkill", (int) arg0, (int) arg1, ret);
	g_free(args);
}

struct sys_time_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_time_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_time_args *args = g_new(struct sys_time_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_time(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_time_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_time", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_futex_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
	reg_t arg5;
};

void *
generated_linux_record_syscall_sys_futex_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_futex_args *args = g_new(struct sys_futex_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	args->arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	return args;
}

void
generated_linux_print_syscall_sys_futex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_futex_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	reg_t arg5 = args->arg5;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_futex", (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5, ret);
	g_free(args);
}

struct sys_sched_setaffinity_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_sched_setaffinity_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_setaffinity_args *args = g_new(struct sys_sched_setaffinity_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_sched_setaffinity(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_setaffinity_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_sched_setaffinity", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_sched_getaffinity_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_sched_getaffinity_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_getaffinity_args *args = g_new(struct sys_sched_getaffinity_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_sched_getaffinity(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_getaffinity_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_sched_getaffinity", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_set_thread_area_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_set_thread_area_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_set_thread_area_args *args = g_new(struct sys_set_thread_area_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_set_thread_area(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_set_thread_area_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_set_thread_area", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_io_setup_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_io_setup_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_io_setup_args *args = g_new(struct sys_io_setup_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_io_setup(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_io_setup_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_io_setup", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_io_destroy_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_io_destroy_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_io_destroy_args *args = g_new(struct sys_io_destroy_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_io_destroy(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_io_destroy_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_io_destroy", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_io_getevents_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_io_getevents_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_io_getevents_args *args = g_new(struct sys_io_getevents_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_io_getevents(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_io_getevents_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %li, %li, 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_io_getevents", (unsigned long) arg0, (long int) arg1, (long int) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_io_submit_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_io_submit_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_io_submit_args *args = g_new(struct sys_io_submit_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_io_submit(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_io_submit_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %li, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_io_submit", (unsigned long) arg0, (long int) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_io_cancel_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_io_cancel_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_io_cancel_args *args = g_new(struct sys_io_cancel_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_io_cancel(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_io_cancel_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_io_cancel", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_get_thread_area_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_get_thread_area_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_get_thread_area_args *args = g_new(struct sys_get_thread_area_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_get_thread_area(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_get_thread_area_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_get_thread_area", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_lookup_dcookie_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_lookup_dcookie_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_lookup_dcookie_args *args = g_new(struct sys_lookup_dcookie_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_lookup_dcookie(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_lookup_dcookie_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_lookup_dcookie", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_epoll_create_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_epoll_create_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_epoll_create_args *args = g_new(struct sys_epoll_create_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_epoll_create(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_epoll_create_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i) = %ld\n", pid, tid, proc, "sys_epoll_create", (int) arg0, ret);
	g_free(args);
}

struct sys_epoll_ctl_old_args {
};

void *
generated_linux_record_syscall_sys_epoll_ctl_old_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_epoll_ctl_old_args *args = g_new(struct sys_epoll_ctl_old_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_epoll_ctl_old(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_epoll_ctl_old_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_epoll_ctl_old", ret);
	g_free(args);
}

struct sys_epoll_wait_old_args {
};

void *
generated_linux_record_syscall_sys_epoll_wait_old_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_epoll_wait_old_args *args = g_new(struct sys_epoll_wait_old_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_epoll_wait_old(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_epoll_wait_old_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_epoll_wait_old", ret);
	g_free(args);
}

struct sys_remap_file_pages_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_remap_file_pages_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_remap_file_pages_args *args = g_new(struct sys_remap_file_pages_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_remap_file_pages(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_remap_file_pages_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu, %lu, %lu) = %ld\n", pid, tid, proc, "sys_remap_file_pages", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_getdents64_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_getdents64_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getdents64_args *args = g_new(struct sys_getdents64_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_getdents64(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getdents64_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_getdents64", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_set_tid_address_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_set_tid_address_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_set_tid_address_args *args = g_new(struct sys_set_tid_address_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_set_tid_address(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_set_tid_address_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_set_tid_address", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_restart_syscall_args {
};

void *
generated_linux_record_syscall_sys_restart_syscall_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_restart_syscall_args *args = g_new(struct sys_restart_syscall_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_restart_syscall(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_restart_syscall_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_restart_syscall", ret);
	g_free(args);
}

struct sys_semtimedop_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_semtimedop_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_semtimedop_args *args = g_new(struct sys_semtimedop_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_semtimedop(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_semtimedop_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_semtimedop", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_fadvise64_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_fadvise64_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fadvise64_args *args = g_new(struct sys_fadvise64_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_fadvise64(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fadvise64_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %li, %lu, %i) = %ld\n", pid, tid, proc, "sys_fadvise64", (int) arg0, (long int) arg1, (unsigned long) arg2, (int) arg3, ret);
	g_free(args);
}

struct sys_timer_create_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_timer_create_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_timer_create_args *args = g_new(struct sys_timer_create_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_timer_create(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_timer_create_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_timer_create", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_timer_settime_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_timer_settime_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_timer_settime_args *args = g_new(struct sys_timer_settime_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_timer_settime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_timer_settime_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %i, 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_timer_settime", (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_timer_gettime_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_timer_gettime_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_timer_gettime_args *args = g_new(struct sys_timer_gettime_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_timer_gettime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_timer_gettime_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_timer_gettime", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_timer_getoverrun_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_timer_getoverrun_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_timer_getoverrun_args *args = g_new(struct sys_timer_getoverrun_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_timer_getoverrun(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_timer_getoverrun_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu) = %ld\n", pid, tid, proc, "sys_timer_getoverrun", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_timer_delete_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_timer_delete_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_timer_delete_args *args = g_new(struct sys_timer_delete_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_timer_delete(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_timer_delete_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu) = %ld\n", pid, tid, proc, "sys_timer_delete", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_clock_settime_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_clock_settime_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_clock_settime_args *args = g_new(struct sys_clock_settime_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_clock_settime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_clock_settime_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_clock_settime", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_clock_gettime_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_clock_gettime_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_clock_gettime_args *args = g_new(struct sys_clock_gettime_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_clock_gettime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_clock_gettime_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_clock_gettime", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_clock_getres_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_clock_getres_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_clock_getres_args *args = g_new(struct sys_clock_getres_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_clock_getres(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_clock_getres_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_clock_getres", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_clock_nanosleep_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_clock_nanosleep_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_clock_nanosleep_args *args = g_new(struct sys_clock_nanosleep_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_clock_nanosleep(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_clock_nanosleep_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %i, 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_clock_nanosleep", (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_exit_group_args {
	reg_t arg0;
};

void
generated_linux_print_syscall_sys_exit_group(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_exit_group_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i) = %ld\n", pid, tid, proc, "sys_exit_group", (int) arg0, ret);
	g_free(args);
}

void *
generated_linux_record_syscall_sys_exit_group_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_exit_group_args *args = g_new(struct sys_exit_group_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	generated_linux_print_syscall_sys_exit_group(state, pid, tid, args);
    return NULL;
}

struct sys_epoll_wait_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_epoll_wait_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_epoll_wait_args *args = g_new(struct sys_epoll_wait_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_epoll_wait(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_epoll_wait_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, %i) = %ld\n", pid, tid, proc, "sys_epoll_wait", (int) arg0, (unsigned long) arg1, (int) arg2, (int) arg3, ret);
	g_free(args);
}

struct sys_epoll_ctl_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_epoll_ctl_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_epoll_ctl_args *args = g_new(struct sys_epoll_ctl_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_epoll_ctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_epoll_ctl_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_epoll_ctl", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_tgkill_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_tgkill_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_tgkill_args *args = g_new(struct sys_tgkill_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_tgkill(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_tgkill_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i) = %ld\n", pid, tid, proc, "sys_tgkill", (int) arg0, (int) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_utimes_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_utimes_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_utimes_args *args = g_new(struct sys_utimes_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_utimes(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_utimes_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_utimes", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_vserver_args {
};

void *
generated_linux_record_syscall_sys_vserver_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_vserver_args *args = g_new(struct sys_vserver_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_vserver(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_vserver_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_vserver", ret);
	g_free(args);
}

struct sys_mbind_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
	reg_t arg5;
};

void *
generated_linux_record_syscall_sys_mbind_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mbind_args *args = g_new(struct sys_mbind_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	args->arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	return args;
}

void
generated_linux_print_syscall_sys_mbind(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mbind_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	reg_t arg5 = args->arg5;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu, 0x%"PRIx64", %lu, %lu) = %ld\n", pid, tid, proc, "sys_mbind", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5, ret);
	g_free(args);
}

struct sys_set_mempolicy_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_set_mempolicy_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_set_mempolicy_args *args = g_new(struct sys_set_mempolicy_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_set_mempolicy(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_set_mempolicy_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_set_mempolicy", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_get_mempolicy_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_get_mempolicy_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_get_mempolicy_args *args = g_new(struct sys_get_mempolicy_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_get_mempolicy(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_get_mempolicy_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", %lu, %lu, %lu) = %ld\n", pid, tid, proc, "sys_get_mempolicy", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_mq_open_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_mq_open_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mq_open_args *args = g_new(struct sys_mq_open_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_mq_open(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mq_open_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i, %lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_mq_open", (unsigned long) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_mq_unlink_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_mq_unlink_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mq_unlink_args *args = g_new(struct sys_mq_unlink_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_mq_unlink(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mq_unlink_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_mq_unlink", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_mq_timedsend_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_mq_timedsend_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mq_timedsend_args *args = g_new(struct sys_mq_timedsend_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_mq_timedsend(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mq_timedsend_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_mq_timedsend", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_mq_timedreceive_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_mq_timedreceive_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mq_timedreceive_args *args = g_new(struct sys_mq_timedreceive_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_mq_timedreceive(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mq_timedreceive_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_mq_timedreceive", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_mq_notify_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_mq_notify_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mq_notify_args *args = g_new(struct sys_mq_notify_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_mq_notify(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mq_notify_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_mq_notify", (int) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_mq_getsetattr_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_mq_getsetattr_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mq_getsetattr_args *args = g_new(struct sys_mq_getsetattr_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_mq_getsetattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mq_getsetattr_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_mq_getsetattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_kexec_load_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_kexec_load_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_kexec_load_args *args = g_new(struct sys_kexec_load_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_kexec_load(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_kexec_load_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_kexec_load", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_waitid_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_waitid_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_waitid_args *args = g_new(struct sys_waitid_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_waitid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_waitid_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64", %i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_waitid", (int) arg0, (int) arg1, (unsigned long) arg2, (int) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_add_key_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_add_key_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_add_key_args *args = g_new(struct sys_add_key_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_add_key(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_add_key_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %lu, %i) = %ld\n", pid, tid, proc, "sys_add_key", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4, ret);
	g_free(args);
}

struct sys_request_key_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_request_key_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_request_key_args *args = g_new(struct sys_request_key_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_request_key(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_request_key_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_request_key", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3, ret);
	g_free(args);
}

struct sys_keyctl_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_keyctl_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_keyctl_args *args = g_new(struct sys_keyctl_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_keyctl(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_keyctl_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %lu, %lu, %lu) = %ld\n", pid, tid, proc, "sys_keyctl", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_ioprio_set_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_ioprio_set_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_ioprio_set_args *args = g_new(struct sys_ioprio_set_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_ioprio_set(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_ioprio_set_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i) = %ld\n", pid, tid, proc, "sys_ioprio_set", (int) arg0, (int) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_ioprio_get_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_ioprio_get_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_ioprio_get_args *args = g_new(struct sys_ioprio_get_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_ioprio_get(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_ioprio_get_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i) = %ld\n", pid, tid, proc, "sys_ioprio_get", (int) arg0, (int) arg1, ret);
	g_free(args);
}

struct sys_inotify_init_args {
};

void *
generated_linux_record_syscall_sys_inotify_init_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_inotify_init_args *args = g_new(struct sys_inotify_init_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_inotify_init(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_inotify_init_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_inotify_init", ret);
	g_free(args);
}

struct sys_inotify_add_watch_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_inotify_add_watch_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_inotify_add_watch_args *args = g_new(struct sys_inotify_add_watch_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_inotify_add_watch(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_inotify_add_watch_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_inotify_add_watch", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_inotify_rm_watch_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_inotify_rm_watch_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_inotify_rm_watch_args *args = g_new(struct sys_inotify_rm_watch_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_inotify_rm_watch(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_inotify_rm_watch_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_inotify_rm_watch", (int) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_migrate_pages_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_migrate_pages_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_migrate_pages_args *args = g_new(struct sys_migrate_pages_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_migrate_pages(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_migrate_pages_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_migrate_pages", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_openat_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_openat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_openat_args *args = g_new(struct sys_openat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_openat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_openat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, %lu) = %ld\n", pid, tid, proc, "sys_openat", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_mkdirat_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_mkdirat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mkdirat_args *args = g_new(struct sys_mkdirat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_mkdirat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mkdirat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_mkdirat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_mknodat_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_mknodat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mknodat_args *args = g_new(struct sys_mknodat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_mknodat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mknodat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu) = %ld\n", pid, tid, proc, "sys_mknodat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_fchownat_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_fchownat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fchownat_args *args = g_new(struct sys_fchownat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_fchownat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fchownat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, %i) = %ld\n", pid, tid, proc, "sys_fchownat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4, ret);
	g_free(args);
}

struct sys_futimesat_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_futimesat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_futimesat_args *args = g_new(struct sys_futimesat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_futimesat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_futimesat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_futimesat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_newfstatat_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_newfstatat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_newfstatat_args *args = g_new(struct sys_newfstatat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_newfstatat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_newfstatat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_newfstatat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3, ret);
	g_free(args);
}

struct sys_unlinkat_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_unlinkat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_unlinkat_args *args = g_new(struct sys_unlinkat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_unlinkat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_unlinkat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_unlinkat", (int) arg0, (unsigned long) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_renameat_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_renameat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_renameat_args *args = g_new(struct sys_renameat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_renameat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_renameat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_renameat", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_linkat_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_linkat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_linkat_args *args = g_new(struct sys_linkat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_linkat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_linkat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_linkat", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (int) arg4, ret);
	g_free(args);
}

struct sys_symlinkat_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_symlinkat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_symlinkat_args *args = g_new(struct sys_symlinkat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_symlinkat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_symlinkat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_symlinkat", (unsigned long) arg0, (int) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_readlinkat_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_readlinkat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_readlinkat_args *args = g_new(struct sys_readlinkat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_readlinkat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_readlinkat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_readlinkat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3, ret);
	g_free(args);
}

struct sys_fchmodat_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_fchmodat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fchmodat_args *args = g_new(struct sys_fchmodat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_fchmodat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fchmodat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_fchmodat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_faccessat_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_faccessat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_faccessat_args *args = g_new(struct sys_faccessat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_faccessat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_faccessat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_faccessat", (int) arg0, (unsigned long) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_pselect6_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
	reg_t arg5;
};

void *
generated_linux_record_syscall_sys_pselect6_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pselect6_args *args = g_new(struct sys_pselect6_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	args->arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	return args;
}

void
generated_linux_print_syscall_sys_pselect6(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pselect6_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	reg_t arg5 = args->arg5;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_pselect6", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5, ret);
	g_free(args);
}

struct sys_ppoll_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_ppoll_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_ppoll_args *args = g_new(struct sys_ppoll_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_ppoll(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_ppoll_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_ppoll", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_unshare_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_unshare_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_unshare_args *args = g_new(struct sys_unshare_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_unshare(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_unshare_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu) = %ld\n", pid, tid, proc, "sys_unshare", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_set_robust_list_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_set_robust_list_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_set_robust_list_args *args = g_new(struct sys_set_robust_list_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_set_robust_list(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_set_robust_list_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_set_robust_list", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_get_robust_list_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_get_robust_list_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_get_robust_list_args *args = g_new(struct sys_get_robust_list_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_get_robust_list(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_get_robust_list_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_get_robust_list", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_splice_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
	reg_t arg5;
};

void *
generated_linux_record_syscall_sys_splice_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_splice_args *args = g_new(struct sys_splice_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	args->arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	return args;
}

void
generated_linux_print_syscall_sys_splice(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_splice_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	reg_t arg5 = args->arg5;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %lu, %lu) = %ld\n", pid, tid, proc, "sys_splice", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5, ret);
	g_free(args);
}

struct sys_tee_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_tee_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_tee_args *args = g_new(struct sys_tee_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_tee(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_tee_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %lu, %lu) = %ld\n", pid, tid, proc, "sys_tee", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_sync_file_range_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_sync_file_range_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sync_file_range_args *args = g_new(struct sys_sync_file_range_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_sync_file_range(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sync_file_range_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %li, %li, %lu) = %ld\n", pid, tid, proc, "sys_sync_file_range", (int) arg0, (long int) arg1, (long int) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_vmsplice_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_vmsplice_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_vmsplice_args *args = g_new(struct sys_vmsplice_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_vmsplice(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_vmsplice_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu) = %ld\n", pid, tid, proc, "sys_vmsplice", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_move_pages_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
	reg_t arg5;
};

void *
generated_linux_record_syscall_sys_move_pages_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_move_pages_args *args = g_new(struct sys_move_pages_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	args->arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	return args;
}

void
generated_linux_print_syscall_sys_move_pages(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_move_pages_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	reg_t arg5 = args->arg5;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_move_pages", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (int) arg5, ret);
	g_free(args);
}

struct sys_utimensat_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_utimensat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_utimensat_args *args = g_new(struct sys_utimensat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_utimensat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_utimensat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_utimensat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3, ret);
	g_free(args);
}

struct sys_epoll_pwait_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
	reg_t arg5;
};

void *
generated_linux_record_syscall_sys_epoll_pwait_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_epoll_pwait_args *args = g_new(struct sys_epoll_pwait_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	args->arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	return args;
}

void
generated_linux_print_syscall_sys_epoll_pwait(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_epoll_pwait_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	reg_t arg5 = args->arg5;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, %i, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_epoll_pwait", (int) arg0, (unsigned long) arg1, (int) arg2, (int) arg3, (unsigned long) arg4, (unsigned long) arg5, ret);
	g_free(args);
}

struct sys_signalfd_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_signalfd_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_signalfd_args *args = g_new(struct sys_signalfd_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_signalfd(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_signalfd_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_signalfd", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_timerfd_args {
};

void *
generated_linux_record_syscall_sys_timerfd_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_timerfd_args *args = g_new(struct sys_timerfd_args, 1);
	return args;
}

void
generated_linux_print_syscall_sys_timerfd(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_timerfd_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s() = %ld\n", pid, tid, proc, "sys_timerfd", ret);
	g_free(args);
}

struct sys_eventfd_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_eventfd_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_eventfd_args *args = g_new(struct sys_eventfd_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_eventfd(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_eventfd_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu) = %ld\n", pid, tid, proc, "sys_eventfd", (unsigned long) arg0, ret);
	g_free(args);
}

struct sys_fallocate_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_fallocate_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fallocate_args *args = g_new(struct sys_fallocate_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_fallocate(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fallocate_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %li, %li) = %ld\n", pid, tid, proc, "sys_fallocate", (int) arg0, (int) arg1, (long int) arg2, (long int) arg3, ret);
	g_free(args);
}

struct sys_timerfd_settime_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_timerfd_settime_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_timerfd_settime_args *args = g_new(struct sys_timerfd_settime_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_timerfd_settime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_timerfd_settime_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_timerfd_settime", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_timerfd_gettime_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_timerfd_gettime_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_timerfd_gettime_args *args = g_new(struct sys_timerfd_gettime_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_timerfd_gettime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_timerfd_gettime_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_timerfd_gettime", (int) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_accept4_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_accept4_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_accept4_args *args = g_new(struct sys_accept4_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_accept4(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_accept4_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_accept4", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3, ret);
	g_free(args);
}

struct sys_signalfd4_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_signalfd4_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_signalfd4_args *args = g_new(struct sys_signalfd4_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_signalfd4(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_signalfd4_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %i) = %ld\n", pid, tid, proc, "sys_signalfd4", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3, ret);
	g_free(args);
}

struct sys_eventfd2_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_eventfd2_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_eventfd2_args *args = g_new(struct sys_eventfd2_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_eventfd2(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_eventfd2_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %i) = %ld\n", pid, tid, proc, "sys_eventfd2", (unsigned long) arg0, (int) arg1, ret);
	g_free(args);
}

struct sys_epoll_create1_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_epoll_create1_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_epoll_create1_args *args = g_new(struct sys_epoll_create1_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_epoll_create1(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_epoll_create1_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i) = %ld\n", pid, tid, proc, "sys_epoll_create1", (int) arg0, ret);
	g_free(args);
}

struct sys_dup3_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_dup3_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_dup3_args *args = g_new(struct sys_dup3_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_dup3(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_dup3_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i) = %ld\n", pid, tid, proc, "sys_dup3", (unsigned long) arg0, (unsigned long) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_pipe2_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_pipe2_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pipe2_args *args = g_new(struct sys_pipe2_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_pipe2(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pipe2_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_pipe2", (unsigned long) arg0, (int) arg1, ret);
	g_free(args);
}

struct sys_inotify_init1_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_inotify_init1_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_inotify_init1_args *args = g_new(struct sys_inotify_init1_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_inotify_init1(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_inotify_init1_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i) = %ld\n", pid, tid, proc, "sys_inotify_init1", (int) arg0, ret);
	g_free(args);
}

struct sys_preadv_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_preadv_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_preadv_args *args = g_new(struct sys_preadv_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_preadv(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_preadv_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %lu, %lu) = %ld\n", pid, tid, proc, "sys_preadv", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_pwritev_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_pwritev_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pwritev_args *args = g_new(struct sys_pwritev_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_pwritev(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pwritev_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %lu, %lu) = %ld\n", pid, tid, proc, "sys_pwritev", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_rt_tgsigqueueinfo_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_rt_tgsigqueueinfo_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rt_tgsigqueueinfo_args *args = g_new(struct sys_rt_tgsigqueueinfo_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_rt_tgsigqueueinfo(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_rt_tgsigqueueinfo_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_rt_tgsigqueueinfo", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_perf_event_open_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_perf_event_open_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_perf_event_open_args *args = g_new(struct sys_perf_event_open_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_perf_event_open(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_perf_event_open_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %i, %i, %i, %lu) = %ld\n", pid, tid, proc, "sys_perf_event_open", (unsigned long) arg0, (int) arg1, (int) arg2, (int) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_recvmmsg_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_recvmmsg_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_recvmmsg_args *args = g_new(struct sys_recvmmsg_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_recvmmsg(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_recvmmsg_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_recvmmsg", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_fanotify_init_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_fanotify_init_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fanotify_init_args *args = g_new(struct sys_fanotify_init_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_fanotify_init(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fanotify_init_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu) = %ld\n", pid, tid, proc, "sys_fanotify_init", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_fanotify_mark_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_fanotify_mark_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fanotify_mark_args *args = g_new(struct sys_fanotify_mark_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_fanotify_mark(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_fanotify_mark_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, %lu, %i, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_fanotify_mark", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_prlimit64_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_prlimit64_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_prlimit64_args *args = g_new(struct sys_prlimit64_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_prlimit64(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_prlimit64_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %lu, 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_prlimit64", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_name_to_handle_at_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_name_to_handle_at_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_name_to_handle_at_args *args = g_new(struct sys_name_to_handle_at_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_name_to_handle_at(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_name_to_handle_at_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_name_to_handle_at", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4, ret);
	g_free(args);
}

struct sys_open_by_handle_at_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_open_by_handle_at_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_open_by_handle_at_args *args = g_new(struct sys_open_by_handle_at_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_open_by_handle_at(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_open_by_handle_at_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_open_by_handle_at", (int) arg0, (unsigned long) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_clock_adjtime_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_clock_adjtime_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_clock_adjtime_args *args = g_new(struct sys_clock_adjtime_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_clock_adjtime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_clock_adjtime_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_clock_adjtime", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_syncfs_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_syncfs_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_syncfs_args *args = g_new(struct sys_syncfs_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_syncfs(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_syncfs_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i) = %ld\n", pid, tid, proc, "sys_syncfs", (int) arg0, ret);
	g_free(args);
}

struct sys_sendmmsg_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_sendmmsg_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sendmmsg_args *args = g_new(struct sys_sendmmsg_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_sendmmsg(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sendmmsg_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu) = %ld\n", pid, tid, proc, "sys_sendmmsg", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_setns_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_setns_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setns_args *args = g_new(struct sys_setns_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_setns(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_setns_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i) = %ld\n", pid, tid, proc, "sys_setns", (int) arg0, (int) arg1, ret);
	g_free(args);
}

struct sys_getcpu_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_getcpu_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getcpu_args *args = g_new(struct sys_getcpu_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_getcpu(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getcpu_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_getcpu", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_process_vm_readv_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
	reg_t arg5;
};

void *
generated_linux_record_syscall_sys_process_vm_readv_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_process_vm_readv_args *args = g_new(struct sys_process_vm_readv_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	args->arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	return args;
}

void
generated_linux_print_syscall_sys_process_vm_readv(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_process_vm_readv_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	reg_t arg5 = args->arg5;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", %lu, %lu) = %ld\n", pid, tid, proc, "sys_process_vm_readv", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5, ret);
	g_free(args);
}

struct sys_process_vm_writev_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
	reg_t arg5;
};

void *
generated_linux_record_syscall_sys_process_vm_writev_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_process_vm_writev_args *args = g_new(struct sys_process_vm_writev_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	args->arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	return args;
}

void
generated_linux_print_syscall_sys_process_vm_writev(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_process_vm_writev_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	reg_t arg5 = args->arg5;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, 0x%"PRIx64", %lu, %lu) = %ld\n", pid, tid, proc, "sys_process_vm_writev", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5, ret);
	g_free(args);
}

struct sys_kcmp_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_kcmp_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_kcmp_args *args = g_new(struct sys_kcmp_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_kcmp(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_kcmp_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %i, %lu, %lu) = %ld\n", pid, tid, proc, "sys_kcmp", (int) arg0, (int) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_finit_module_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_finit_module_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_finit_module_args *args = g_new(struct sys_finit_module_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_finit_module(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_finit_module_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_finit_module", (int) arg0, (unsigned long) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_sched_setattr_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_sched_setattr_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_setattr_args *args = g_new(struct sys_sched_setattr_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_sched_setattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_setattr_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_sched_setattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_sched_getattr_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_sched_getattr_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_getattr_args *args = g_new(struct sys_sched_getattr_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_sched_getattr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_sched_getattr_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu) = %ld\n", pid, tid, proc, "sys_sched_getattr", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, ret);
	g_free(args);
}

struct sys_renameat2_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_renameat2_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_renameat2_args *args = g_new(struct sys_renameat2_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_renameat2(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_renameat2_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_renameat2", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_seccomp_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_seccomp_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_seccomp_args *args = g_new(struct sys_seccomp_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_seccomp(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_seccomp_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_seccomp", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_getrandom_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_getrandom_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getrandom_args *args = g_new(struct sys_getrandom_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_getrandom(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_getrandom_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu, %lu) = %ld\n", pid, tid, proc, "sys_getrandom", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_memfd_create_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_memfd_create_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_memfd_create_args *args = g_new(struct sys_memfd_create_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_memfd_create(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_memfd_create_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_memfd_create", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_kexec_file_load_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_kexec_file_load_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_kexec_file_load_args *args = g_new(struct sys_kexec_file_load_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_kexec_file_load(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_kexec_file_load_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i, %lu, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_kexec_file_load", (int) arg0, (int) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

struct sys_bpf_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_bpf_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_bpf_args *args = g_new(struct sys_bpf_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_bpf(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_bpf_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu) = %ld\n", pid, tid, proc, "sys_bpf", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, ret);
	g_free(args);
}

struct sys_execveat_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_execveat_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_execveat_args *args = g_new(struct sys_execveat_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_execveat(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_execveat_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64", %i) = %ld\n", pid, tid, proc, "sys_execveat", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (int) arg4, ret);
	g_free(args);
}

struct sys_userfaultfd_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_userfaultfd_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_userfaultfd_args *args = g_new(struct sys_userfaultfd_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_userfaultfd(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_userfaultfd_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i) = %ld\n", pid, tid, proc, "sys_userfaultfd", (int) arg0, ret);
	g_free(args);
}

struct sys_membarrier_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_membarrier_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_membarrier_args *args = g_new(struct sys_membarrier_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_membarrier(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_membarrier_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, %i) = %ld\n", pid, tid, proc, "sys_membarrier", (int) arg0, (int) arg1, ret);
	g_free(args);
}

struct sys_mlock2_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
};

void *
generated_linux_record_syscall_sys_mlock2_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mlock2_args *args = g_new(struct sys_mlock2_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	return args;
}

void
generated_linux_print_syscall_sys_mlock2(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_mlock2_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %i) = %ld\n", pid, tid, proc, "sys_mlock2", (unsigned long) arg0, (unsigned long) arg1, (int) arg2, ret);
	g_free(args);
}

struct sys_copy_file_range_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
	reg_t arg5;
};

void *
generated_linux_record_syscall_sys_copy_file_range_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_copy_file_range_args *args = g_new(struct sys_copy_file_range_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	args->arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	return args;
}

void
generated_linux_print_syscall_sys_copy_file_range(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_copy_file_range_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	reg_t arg5 = args->arg5;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %i, 0x%"PRIx64", %lu, %lu) = %ld\n", pid, tid, proc, "sys_copy_file_range", (int) arg0, (unsigned long) arg1, (int) arg2, (unsigned long) arg3, (unsigned long) arg4, (unsigned long) arg5, ret);
	g_free(args);
}

struct sys_preadv2_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
	reg_t arg5;
};

void *
generated_linux_record_syscall_sys_preadv2_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_preadv2_args *args = g_new(struct sys_preadv2_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	args->arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	return args;
}

void
generated_linux_print_syscall_sys_preadv2(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_preadv2_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	reg_t arg5 = args->arg5;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %lu, %lu, %i) = %ld\n", pid, tid, proc, "sys_preadv2", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (int) arg5, ret);
	g_free(args);
}

struct sys_pwritev2_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
	reg_t arg5;
};

void *
generated_linux_record_syscall_sys_pwritev2_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pwritev2_args *args = g_new(struct sys_pwritev2_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	args->arg5 = gt_guest_get_vmi_event(state)->x86_regs->r9;
	return args;
}

void
generated_linux_print_syscall_sys_pwritev2(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pwritev2_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	reg_t arg5 = args->arg5;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, 0x%"PRIx64", %lu, %lu, %lu, %i) = %ld\n", pid, tid, proc, "sys_pwritev2", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, (int) arg5, ret);
	g_free(args);
}

struct sys_pkey_mprotect_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
};

void *
generated_linux_record_syscall_sys_pkey_mprotect_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pkey_mprotect_args *args = g_new(struct sys_pkey_mprotect_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	return args;
}

void
generated_linux_print_syscall_sys_pkey_mprotect(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pkey_mprotect_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu, %lu, %i) = %ld\n", pid, tid, proc, "sys_pkey_mprotect", (unsigned long) arg0, (unsigned long) arg1, (unsigned long) arg2, (int) arg3, ret);
	g_free(args);
}

struct sys_pkey_alloc_args {
	reg_t arg0;
	reg_t arg1;
};

void *
generated_linux_record_syscall_sys_pkey_alloc_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pkey_alloc_args *args = g_new(struct sys_pkey_alloc_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	return args;
}

void
generated_linux_print_syscall_sys_pkey_alloc(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pkey_alloc_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%lu, %lu) = %ld\n", pid, tid, proc, "sys_pkey_alloc", (unsigned long) arg0, (unsigned long) arg1, ret);
	g_free(args);
}

struct sys_pkey_free_args {
	reg_t arg0;
};

void *
generated_linux_record_syscall_sys_pkey_free_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pkey_free_args *args = g_new(struct sys_pkey_free_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	return args;
}

void
generated_linux_print_syscall_sys_pkey_free(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_pkey_free_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i) = %ld\n", pid, tid, proc, "sys_pkey_free", (int) arg0, ret);
	g_free(args);
}

struct sys_statx_args {
	reg_t arg0;
	reg_t arg1;
	reg_t arg2;
	reg_t arg3;
	reg_t arg4;
};

void *
generated_linux_record_syscall_sys_statx_args(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_statx_args *args = g_new(struct sys_statx_args, 1);
	args->arg0 = gt_guest_get_vmi_event(state)->x86_regs->rdi;
	args->arg1 = gt_guest_get_vmi_event(state)->x86_regs->rsi;
	args->arg2 = gt_guest_get_vmi_event(state)->x86_regs->rdx;
	args->arg3 = gt_guest_get_vmi_event(state)->x86_regs->r10;
	args->arg4 = gt_guest_get_vmi_event(state)->x86_regs->r8;
	return args;
}

void
generated_linux_print_syscall_sys_statx(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *user_data)
{
	struct sys_statx_args *args = user_data;
	char *proc = gt_guest_get_process_name(state);
	reg_t ret = gt_guest_get_vmi_event(state)->x86_regs->rax;
	reg_t arg0 = args->arg0;
	reg_t arg1 = args->arg1;
	reg_t arg2 = args->arg2;
	reg_t arg3 = args->arg3;
	reg_t arg4 = args->arg4;
	fprintf(stderr, "pid: %u/0x%"PRIx64" (%s) syscall: %s(%i, 0x%"PRIx64", %lu, %lu, 0x%"PRIx64") = %ld\n", pid, tid, proc, "sys_statx", (int) arg0, (unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3, (unsigned long) arg4, ret);
	g_free(args);
}

const GtCallbackRegistry GENERATED_LINUX_SYSCALLS[] = {
	{ "sys_read", generated_linux_record_syscall_sys_read_args, generated_linux_print_syscall_sys_read },
	{ "sys_write", generated_linux_record_syscall_sys_write_args, generated_linux_print_syscall_sys_write },
	{ "sys_open", generated_linux_record_syscall_sys_open_args, generated_linux_print_syscall_sys_open },
	{ "sys_close", generated_linux_record_syscall_sys_close_args, generated_linux_print_syscall_sys_close },
	{ "sys_stat", generated_linux_record_syscall_sys_stat_args, generated_linux_print_syscall_sys_stat },
	{ "sys_fstat", generated_linux_record_syscall_sys_fstat_args, generated_linux_print_syscall_sys_fstat },
	{ "sys_lstat", generated_linux_record_syscall_sys_lstat_args, generated_linux_print_syscall_sys_lstat },
	{ "sys_poll", generated_linux_record_syscall_sys_poll_args, generated_linux_print_syscall_sys_poll },
	{ "sys_lseek", generated_linux_record_syscall_sys_lseek_args, generated_linux_print_syscall_sys_lseek },
	{ "sys_mmap", generated_linux_record_syscall_sys_mmap_args, generated_linux_print_syscall_sys_mmap },
	{ "sys_mprotect", generated_linux_record_syscall_sys_mprotect_args, generated_linux_print_syscall_sys_mprotect },
	{ "sys_munmap", generated_linux_record_syscall_sys_munmap_args, generated_linux_print_syscall_sys_munmap },
	{ "sys_brk", generated_linux_record_syscall_sys_brk_args, generated_linux_print_syscall_sys_brk },
	{ "sys_rt_sigaction", generated_linux_record_syscall_sys_rt_sigaction_args, generated_linux_print_syscall_sys_rt_sigaction },
	{ "sys_rt_sigprocmask", generated_linux_record_syscall_sys_rt_sigprocmask_args, generated_linux_print_syscall_sys_rt_sigprocmask },
	{ "sys_rt_sigreturn", generated_linux_record_syscall_sys_rt_sigreturn_args, generated_linux_print_syscall_sys_rt_sigreturn },
	{ "sys_ioctl", generated_linux_record_syscall_sys_ioctl_args, generated_linux_print_syscall_sys_ioctl },
	{ "sys_pread", generated_linux_record_syscall_sys_pread_args, generated_linux_print_syscall_sys_pread },
	{ "sys_pwrite", generated_linux_record_syscall_sys_pwrite_args, generated_linux_print_syscall_sys_pwrite },
	{ "sys_readv", generated_linux_record_syscall_sys_readv_args, generated_linux_print_syscall_sys_readv },
	{ "sys_writev", generated_linux_record_syscall_sys_writev_args, generated_linux_print_syscall_sys_writev },
	{ "sys_access", generated_linux_record_syscall_sys_access_args, generated_linux_print_syscall_sys_access },
	{ "sys_pipe", generated_linux_record_syscall_sys_pipe_args, generated_linux_print_syscall_sys_pipe },
	{ "sys_select", generated_linux_record_syscall_sys_select_args, generated_linux_print_syscall_sys_select },
	{ "sys_sched_yield", generated_linux_record_syscall_sys_sched_yield_args, generated_linux_print_syscall_sys_sched_yield },
	{ "sys_mremap", generated_linux_record_syscall_sys_mremap_args, generated_linux_print_syscall_sys_mremap },
	{ "sys_msync", generated_linux_record_syscall_sys_msync_args, generated_linux_print_syscall_sys_msync },
	{ "sys_mincore", generated_linux_record_syscall_sys_mincore_args, generated_linux_print_syscall_sys_mincore },
	{ "sys_madvise", generated_linux_record_syscall_sys_madvise_args, generated_linux_print_syscall_sys_madvise },
	{ "sys_shmget", generated_linux_record_syscall_sys_shmget_args, generated_linux_print_syscall_sys_shmget },
	{ "sys_shmat", generated_linux_record_syscall_sys_shmat_args, generated_linux_print_syscall_sys_shmat },
	{ "sys_shmctl", generated_linux_record_syscall_sys_shmctl_args, generated_linux_print_syscall_sys_shmctl },
	{ "sys_dup", generated_linux_record_syscall_sys_dup_args, generated_linux_print_syscall_sys_dup },
	{ "sys_dup2", generated_linux_record_syscall_sys_dup2_args, generated_linux_print_syscall_sys_dup2 },
	{ "sys_pause", generated_linux_record_syscall_sys_pause_args, generated_linux_print_syscall_sys_pause },
	{ "sys_nanosleep", generated_linux_record_syscall_sys_nanosleep_args, generated_linux_print_syscall_sys_nanosleep },
	{ "sys_getitimer", generated_linux_record_syscall_sys_getitimer_args, generated_linux_print_syscall_sys_getitimer },
	{ "sys_alarm", generated_linux_record_syscall_sys_alarm_args, generated_linux_print_syscall_sys_alarm },
	{ "sys_setitimer", generated_linux_record_syscall_sys_setitimer_args, generated_linux_print_syscall_sys_setitimer },
	{ "sys_getpid", generated_linux_record_syscall_sys_getpid_args, generated_linux_print_syscall_sys_getpid },
	{ "sys_sendfile", generated_linux_record_syscall_sys_sendfile_args, generated_linux_print_syscall_sys_sendfile },
	{ "sys_socket", generated_linux_record_syscall_sys_socket_args, generated_linux_print_syscall_sys_socket },
	{ "sys_connect", generated_linux_record_syscall_sys_connect_args, generated_linux_print_syscall_sys_connect },
	{ "sys_accept", generated_linux_record_syscall_sys_accept_args, generated_linux_print_syscall_sys_accept },
	{ "sys_sendto", generated_linux_record_syscall_sys_sendto_args, generated_linux_print_syscall_sys_sendto },
	{ "sys_recvfrom", generated_linux_record_syscall_sys_recvfrom_args, generated_linux_print_syscall_sys_recvfrom },
	{ "sys_sendmsg", generated_linux_record_syscall_sys_sendmsg_args, generated_linux_print_syscall_sys_sendmsg },
	{ "sys_recvmsg", generated_linux_record_syscall_sys_recvmsg_args, generated_linux_print_syscall_sys_recvmsg },
	{ "sys_shutdown", generated_linux_record_syscall_sys_shutdown_args, generated_linux_print_syscall_sys_shutdown },
	{ "sys_bind", generated_linux_record_syscall_sys_bind_args, generated_linux_print_syscall_sys_bind },
	{ "sys_listen", generated_linux_record_syscall_sys_listen_args, generated_linux_print_syscall_sys_listen },
	{ "sys_getsockname", generated_linux_record_syscall_sys_getsockname_args, generated_linux_print_syscall_sys_getsockname },
	{ "sys_getpeername", generated_linux_record_syscall_sys_getpeername_args, generated_linux_print_syscall_sys_getpeername },
	{ "sys_socketpair", generated_linux_record_syscall_sys_socketpair_args, generated_linux_print_syscall_sys_socketpair },
	{ "sys_setsockopt", generated_linux_record_syscall_sys_setsockopt_args, generated_linux_print_syscall_sys_setsockopt },
	{ "sys_getsockopt", generated_linux_record_syscall_sys_getsockopt_args, generated_linux_print_syscall_sys_getsockopt },
	{ "sys_clone", generated_linux_record_syscall_sys_clone_args, generated_linux_print_syscall_sys_clone },
	{ "sys_fork", generated_linux_record_syscall_sys_fork_args, generated_linux_print_syscall_sys_fork },
	{ "sys_vfork", generated_linux_record_syscall_sys_vfork_args, generated_linux_print_syscall_sys_vfork },
	{ "sys_execve", generated_linux_record_syscall_sys_execve_args, generated_linux_print_syscall_sys_execve },
	{ "sys_exit", generated_linux_record_syscall_sys_exit_args, NULL },
	{ "sys_wait4", generated_linux_record_syscall_sys_wait4_args, generated_linux_print_syscall_sys_wait4 },
	{ "sys_kill", generated_linux_record_syscall_sys_kill_args, generated_linux_print_syscall_sys_kill },
	{ "sys_uname", generated_linux_record_syscall_sys_uname_args, generated_linux_print_syscall_sys_uname },
	{ "sys_semget", generated_linux_record_syscall_sys_semget_args, generated_linux_print_syscall_sys_semget },
	{ "sys_semop", generated_linux_record_syscall_sys_semop_args, generated_linux_print_syscall_sys_semop },
	{ "sys_semctl", generated_linux_record_syscall_sys_semctl_args, generated_linux_print_syscall_sys_semctl },
	{ "sys_shmdt", generated_linux_record_syscall_sys_shmdt_args, generated_linux_print_syscall_sys_shmdt },
	{ "sys_msgget", generated_linux_record_syscall_sys_msgget_args, generated_linux_print_syscall_sys_msgget },
	{ "sys_msgsnd", generated_linux_record_syscall_sys_msgsnd_args, generated_linux_print_syscall_sys_msgsnd },
	{ "sys_msgrcv", generated_linux_record_syscall_sys_msgrcv_args, generated_linux_print_syscall_sys_msgrcv },
	{ "sys_msgctl", generated_linux_record_syscall_sys_msgctl_args, generated_linux_print_syscall_sys_msgctl },
	{ "sys_fcntl", generated_linux_record_syscall_sys_fcntl_args, generated_linux_print_syscall_sys_fcntl },
	{ "sys_flock", generated_linux_record_syscall_sys_flock_args, generated_linux_print_syscall_sys_flock },
	{ "sys_fsync", generated_linux_record_syscall_sys_fsync_args, generated_linux_print_syscall_sys_fsync },
	{ "sys_fdatasync", generated_linux_record_syscall_sys_fdatasync_args, generated_linux_print_syscall_sys_fdatasync },
	{ "sys_truncate", generated_linux_record_syscall_sys_truncate_args, generated_linux_print_syscall_sys_truncate },
	{ "sys_ftruncate", generated_linux_record_syscall_sys_ftruncate_args, generated_linux_print_syscall_sys_ftruncate },
	{ "sys_getdents", generated_linux_record_syscall_sys_getdents_args, generated_linux_print_syscall_sys_getdents },
	{ "sys_getcwd", generated_linux_record_syscall_sys_getcwd_args, generated_linux_print_syscall_sys_getcwd },
	{ "sys_chdir", generated_linux_record_syscall_sys_chdir_args, generated_linux_print_syscall_sys_chdir },
	{ "sys_fchdir", generated_linux_record_syscall_sys_fchdir_args, generated_linux_print_syscall_sys_fchdir },
	{ "sys_rename", generated_linux_record_syscall_sys_rename_args, generated_linux_print_syscall_sys_rename },
	{ "sys_mkdir", generated_linux_record_syscall_sys_mkdir_args, generated_linux_print_syscall_sys_mkdir },
	{ "sys_rmdir", generated_linux_record_syscall_sys_rmdir_args, generated_linux_print_syscall_sys_rmdir },
	{ "sys_creat", generated_linux_record_syscall_sys_creat_args, generated_linux_print_syscall_sys_creat },
	{ "sys_link", generated_linux_record_syscall_sys_link_args, generated_linux_print_syscall_sys_link },
	{ "sys_unlink", generated_linux_record_syscall_sys_unlink_args, generated_linux_print_syscall_sys_unlink },
	{ "sys_symlink", generated_linux_record_syscall_sys_symlink_args, generated_linux_print_syscall_sys_symlink },
	{ "sys_readlink", generated_linux_record_syscall_sys_readlink_args, generated_linux_print_syscall_sys_readlink },
	{ "sys_chmod", generated_linux_record_syscall_sys_chmod_args, generated_linux_print_syscall_sys_chmod },
	{ "sys_fchmod", generated_linux_record_syscall_sys_fchmod_args, generated_linux_print_syscall_sys_fchmod },
	{ "sys_chown", generated_linux_record_syscall_sys_chown_args, generated_linux_print_syscall_sys_chown },
	{ "sys_fchown", generated_linux_record_syscall_sys_fchown_args, generated_linux_print_syscall_sys_fchown },
	{ "sys_lchown", generated_linux_record_syscall_sys_lchown_args, generated_linux_print_syscall_sys_lchown },
	{ "sys_umask", generated_linux_record_syscall_sys_umask_args, generated_linux_print_syscall_sys_umask },
	{ "sys_gettimeofday", generated_linux_record_syscall_sys_gettimeofday_args, generated_linux_print_syscall_sys_gettimeofday },
	{ "sys_getrlimit", generated_linux_record_syscall_sys_getrlimit_args, generated_linux_print_syscall_sys_getrlimit },
	{ "sys_getrusage", generated_linux_record_syscall_sys_getrusage_args, generated_linux_print_syscall_sys_getrusage },
	{ "sys_sysinfo", generated_linux_record_syscall_sys_sysinfo_args, generated_linux_print_syscall_sys_sysinfo },
	{ "sys_times", generated_linux_record_syscall_sys_times_args, generated_linux_print_syscall_sys_times },
	{ "sys_ptrace", generated_linux_record_syscall_sys_ptrace_args, generated_linux_print_syscall_sys_ptrace },
	{ "sys_getuid", generated_linux_record_syscall_sys_getuid_args, generated_linux_print_syscall_sys_getuid },
	{ "sys_syslog", generated_linux_record_syscall_sys_syslog_args, generated_linux_print_syscall_sys_syslog },
	{ "sys_getgid", generated_linux_record_syscall_sys_getgid_args, generated_linux_print_syscall_sys_getgid },
	{ "sys_setuid", generated_linux_record_syscall_sys_setuid_args, generated_linux_print_syscall_sys_setuid },
	{ "sys_setgid", generated_linux_record_syscall_sys_setgid_args, generated_linux_print_syscall_sys_setgid },
	{ "sys_geteuid", generated_linux_record_syscall_sys_geteuid_args, generated_linux_print_syscall_sys_geteuid },
	{ "sys_getegid", generated_linux_record_syscall_sys_getegid_args, generated_linux_print_syscall_sys_getegid },
	{ "sys_setpgid", generated_linux_record_syscall_sys_setpgid_args, generated_linux_print_syscall_sys_setpgid },
	{ "sys_getppid", generated_linux_record_syscall_sys_getppid_args, generated_linux_print_syscall_sys_getppid },
	{ "sys_getpgrp", generated_linux_record_syscall_sys_getpgrp_args, generated_linux_print_syscall_sys_getpgrp },
	{ "sys_setsid", generated_linux_record_syscall_sys_setsid_args, generated_linux_print_syscall_sys_setsid },
	{ "sys_setreuid", generated_linux_record_syscall_sys_setreuid_args, generated_linux_print_syscall_sys_setreuid },
	{ "sys_setregid", generated_linux_record_syscall_sys_setregid_args, generated_linux_print_syscall_sys_setregid },
	{ "sys_getgroups", generated_linux_record_syscall_sys_getgroups_args, generated_linux_print_syscall_sys_getgroups },
	{ "sys_setgroups", generated_linux_record_syscall_sys_setgroups_args, generated_linux_print_syscall_sys_setgroups },
	{ "sys_setresuid", generated_linux_record_syscall_sys_setresuid_args, generated_linux_print_syscall_sys_setresuid },
	{ "sys_getresuid", generated_linux_record_syscall_sys_getresuid_args, generated_linux_print_syscall_sys_getresuid },
	{ "sys_setresgid", generated_linux_record_syscall_sys_setresgid_args, generated_linux_print_syscall_sys_setresgid },
	{ "sys_getresgid", generated_linux_record_syscall_sys_getresgid_args, generated_linux_print_syscall_sys_getresgid },
	{ "sys_getpgid", generated_linux_record_syscall_sys_getpgid_args, generated_linux_print_syscall_sys_getpgid },
	{ "sys_setfsuid", generated_linux_record_syscall_sys_setfsuid_args, generated_linux_print_syscall_sys_setfsuid },
	{ "sys_setfsgid", generated_linux_record_syscall_sys_setfsgid_args, generated_linux_print_syscall_sys_setfsgid },
	{ "sys_getsid", generated_linux_record_syscall_sys_getsid_args, generated_linux_print_syscall_sys_getsid },
	{ "sys_capget", generated_linux_record_syscall_sys_capget_args, generated_linux_print_syscall_sys_capget },
	{ "sys_capset", generated_linux_record_syscall_sys_capset_args, generated_linux_print_syscall_sys_capset },
	{ "sys_rt_sigpending", generated_linux_record_syscall_sys_rt_sigpending_args, generated_linux_print_syscall_sys_rt_sigpending },
	{ "sys_rt_sigtimedwait", generated_linux_record_syscall_sys_rt_sigtimedwait_args, generated_linux_print_syscall_sys_rt_sigtimedwait },
	{ "sys_rt_sigqueueinfo", generated_linux_record_syscall_sys_rt_sigqueueinfo_args, generated_linux_print_syscall_sys_rt_sigqueueinfo },
	{ "sys_rt_sigsuspend", generated_linux_record_syscall_sys_rt_sigsuspend_args, generated_linux_print_syscall_sys_rt_sigsuspend },
	{ "sys_sigaltstack", generated_linux_record_syscall_sys_sigaltstack_args, generated_linux_print_syscall_sys_sigaltstack },
	{ "sys_utime", generated_linux_record_syscall_sys_utime_args, generated_linux_print_syscall_sys_utime },
	{ "sys_mknod", generated_linux_record_syscall_sys_mknod_args, generated_linux_print_syscall_sys_mknod },
	{ "sys_uselib", generated_linux_record_syscall_sys_uselib_args, generated_linux_print_syscall_sys_uselib },
	{ "sys_personality", generated_linux_record_syscall_sys_personality_args, generated_linux_print_syscall_sys_personality },
	{ "sys_ustat", generated_linux_record_syscall_sys_ustat_args, generated_linux_print_syscall_sys_ustat },
	{ "sys_statfs", generated_linux_record_syscall_sys_statfs_args, generated_linux_print_syscall_sys_statfs },
	{ "sys_fstatfs", generated_linux_record_syscall_sys_fstatfs_args, generated_linux_print_syscall_sys_fstatfs },
	{ "sys_sysfs", generated_linux_record_syscall_sys_sysfs_args, generated_linux_print_syscall_sys_sysfs },
	{ "sys_getpriority", generated_linux_record_syscall_sys_getpriority_args, generated_linux_print_syscall_sys_getpriority },
	{ "sys_setpriority", generated_linux_record_syscall_sys_setpriority_args, generated_linux_print_syscall_sys_setpriority },
	{ "sys_sched_setparam", generated_linux_record_syscall_sys_sched_setparam_args, generated_linux_print_syscall_sys_sched_setparam },
	{ "sys_sched_getparam", generated_linux_record_syscall_sys_sched_getparam_args, generated_linux_print_syscall_sys_sched_getparam },
	{ "sys_sched_setscheduler", generated_linux_record_syscall_sys_sched_setscheduler_args, generated_linux_print_syscall_sys_sched_setscheduler },
	{ "sys_sched_getscheduler", generated_linux_record_syscall_sys_sched_getscheduler_args, generated_linux_print_syscall_sys_sched_getscheduler },
	{ "sys_sched_get_priority_max", generated_linux_record_syscall_sys_sched_get_priority_max_args, generated_linux_print_syscall_sys_sched_get_priority_max },
	{ "sys_sched_get_priority_min", generated_linux_record_syscall_sys_sched_get_priority_min_args, generated_linux_print_syscall_sys_sched_get_priority_min },
	{ "sys_sched_rr_get_interval", generated_linux_record_syscall_sys_sched_rr_get_interval_args, generated_linux_print_syscall_sys_sched_rr_get_interval },
	{ "sys_mlock", generated_linux_record_syscall_sys_mlock_args, generated_linux_print_syscall_sys_mlock },
	{ "sys_munlock", generated_linux_record_syscall_sys_munlock_args, generated_linux_print_syscall_sys_munlock },
	{ "sys_mlockall", generated_linux_record_syscall_sys_mlockall_args, generated_linux_print_syscall_sys_mlockall },
	{ "sys_munlockall", generated_linux_record_syscall_sys_munlockall_args, generated_linux_print_syscall_sys_munlockall },
	{ "sys_vhangup", generated_linux_record_syscall_sys_vhangup_args, generated_linux_print_syscall_sys_vhangup },
	{ "sys_modify_ldt", generated_linux_record_syscall_sys_modify_ldt_args, generated_linux_print_syscall_sys_modify_ldt },
	{ "sys_pivot_root", generated_linux_record_syscall_sys_pivot_root_args, generated_linux_print_syscall_sys_pivot_root },
	{ "sys_sysctl", generated_linux_record_syscall_sys_sysctl_args, generated_linux_print_syscall_sys_sysctl },
	{ "sys_prctl", generated_linux_record_syscall_sys_prctl_args, generated_linux_print_syscall_sys_prctl },
	{ "sys_arch_prctl", generated_linux_record_syscall_sys_arch_prctl_args, generated_linux_print_syscall_sys_arch_prctl },
	{ "sys_adjtimex", generated_linux_record_syscall_sys_adjtimex_args, generated_linux_print_syscall_sys_adjtimex },
	{ "sys_setrlimit", generated_linux_record_syscall_sys_setrlimit_args, generated_linux_print_syscall_sys_setrlimit },
	{ "sys_chroot", generated_linux_record_syscall_sys_chroot_args, generated_linux_print_syscall_sys_chroot },
	{ "sys_sync", generated_linux_record_syscall_sys_sync_args, generated_linux_print_syscall_sys_sync },
	{ "sys_acct", generated_linux_record_syscall_sys_acct_args, generated_linux_print_syscall_sys_acct },
	{ "sys_settimeofday", generated_linux_record_syscall_sys_settimeofday_args, generated_linux_print_syscall_sys_settimeofday },
	{ "sys_mount", generated_linux_record_syscall_sys_mount_args, generated_linux_print_syscall_sys_mount },
	{ "sys_umount2", generated_linux_record_syscall_sys_umount2_args, generated_linux_print_syscall_sys_umount2 },
	{ "sys_swapon", generated_linux_record_syscall_sys_swapon_args, generated_linux_print_syscall_sys_swapon },
	{ "sys_swapoff", generated_linux_record_syscall_sys_swapoff_args, generated_linux_print_syscall_sys_swapoff },
	{ "sys_reboot", generated_linux_record_syscall_sys_reboot_args, generated_linux_print_syscall_sys_reboot },
	{ "sys_sethostname", generated_linux_record_syscall_sys_sethostname_args, generated_linux_print_syscall_sys_sethostname },
	{ "sys_setdomainname", generated_linux_record_syscall_sys_setdomainname_args, generated_linux_print_syscall_sys_setdomainname },
	{ "sys_iopl", generated_linux_record_syscall_sys_iopl_args, generated_linux_print_syscall_sys_iopl },
	{ "sys_ioperm", generated_linux_record_syscall_sys_ioperm_args, generated_linux_print_syscall_sys_ioperm },
	{ "sys_create_module", generated_linux_record_syscall_sys_create_module_args, generated_linux_print_syscall_sys_create_module },
	{ "sys_init_module", generated_linux_record_syscall_sys_init_module_args, generated_linux_print_syscall_sys_init_module },
	{ "sys_delete_module", generated_linux_record_syscall_sys_delete_module_args, generated_linux_print_syscall_sys_delete_module },
	{ "sys_get_kernel_syms", generated_linux_record_syscall_sys_get_kernel_syms_args, generated_linux_print_syscall_sys_get_kernel_syms },
	{ "sys_query_module", generated_linux_record_syscall_sys_query_module_args, generated_linux_print_syscall_sys_query_module },
	{ "sys_quotactl", generated_linux_record_syscall_sys_quotactl_args, generated_linux_print_syscall_sys_quotactl },
	{ "sys_nfsservctl", generated_linux_record_syscall_sys_nfsservctl_args, generated_linux_print_syscall_sys_nfsservctl },
	{ "sys_getpmsg", generated_linux_record_syscall_sys_getpmsg_args, generated_linux_print_syscall_sys_getpmsg },
	{ "sys_putpmsg", generated_linux_record_syscall_sys_putpmsg_args, generated_linux_print_syscall_sys_putpmsg },
	{ "sys_afs_syscall", generated_linux_record_syscall_sys_afs_syscall_args, generated_linux_print_syscall_sys_afs_syscall },
	{ "sys_tuxcall", generated_linux_record_syscall_sys_tuxcall_args, generated_linux_print_syscall_sys_tuxcall },
	{ "sys_security", generated_linux_record_syscall_sys_security_args, generated_linux_print_syscall_sys_security },
	{ "sys_gettid", generated_linux_record_syscall_sys_gettid_args, generated_linux_print_syscall_sys_gettid },
	{ "sys_readahead", generated_linux_record_syscall_sys_readahead_args, generated_linux_print_syscall_sys_readahead },
	{ "sys_setxattr", generated_linux_record_syscall_sys_setxattr_args, generated_linux_print_syscall_sys_setxattr },
	{ "sys_lsetxattr", generated_linux_record_syscall_sys_lsetxattr_args, generated_linux_print_syscall_sys_lsetxattr },
	{ "sys_fsetxattr", generated_linux_record_syscall_sys_fsetxattr_args, generated_linux_print_syscall_sys_fsetxattr },
	{ "sys_getxattr", generated_linux_record_syscall_sys_getxattr_args, generated_linux_print_syscall_sys_getxattr },
	{ "sys_lgetxattr", generated_linux_record_syscall_sys_lgetxattr_args, generated_linux_print_syscall_sys_lgetxattr },
	{ "sys_fgetxattr", generated_linux_record_syscall_sys_fgetxattr_args, generated_linux_print_syscall_sys_fgetxattr },
	{ "sys_listxattr", generated_linux_record_syscall_sys_listxattr_args, generated_linux_print_syscall_sys_listxattr },
	{ "sys_llistxattr", generated_linux_record_syscall_sys_llistxattr_args, generated_linux_print_syscall_sys_llistxattr },
	{ "sys_flistxattr", generated_linux_record_syscall_sys_flistxattr_args, generated_linux_print_syscall_sys_flistxattr },
	{ "sys_removexattr", generated_linux_record_syscall_sys_removexattr_args, generated_linux_print_syscall_sys_removexattr },
	{ "sys_lremovexattr", generated_linux_record_syscall_sys_lremovexattr_args, generated_linux_print_syscall_sys_lremovexattr },
	{ "sys_fremovexattr", generated_linux_record_syscall_sys_fremovexattr_args, generated_linux_print_syscall_sys_fremovexattr },
	{ "sys_tkill", generated_linux_record_syscall_sys_tkill_args, generated_linux_print_syscall_sys_tkill },
	{ "sys_time", generated_linux_record_syscall_sys_time_args, generated_linux_print_syscall_sys_time },
	{ "sys_futex", generated_linux_record_syscall_sys_futex_args, generated_linux_print_syscall_sys_futex },
	{ "sys_sched_setaffinity", generated_linux_record_syscall_sys_sched_setaffinity_args, generated_linux_print_syscall_sys_sched_setaffinity },
	{ "sys_sched_getaffinity", generated_linux_record_syscall_sys_sched_getaffinity_args, generated_linux_print_syscall_sys_sched_getaffinity },
	{ "sys_set_thread_area", generated_linux_record_syscall_sys_set_thread_area_args, generated_linux_print_syscall_sys_set_thread_area },
	{ "sys_io_setup", generated_linux_record_syscall_sys_io_setup_args, generated_linux_print_syscall_sys_io_setup },
	{ "sys_io_destroy", generated_linux_record_syscall_sys_io_destroy_args, generated_linux_print_syscall_sys_io_destroy },
	{ "sys_io_getevents", generated_linux_record_syscall_sys_io_getevents_args, generated_linux_print_syscall_sys_io_getevents },
	{ "sys_io_submit", generated_linux_record_syscall_sys_io_submit_args, generated_linux_print_syscall_sys_io_submit },
	{ "sys_io_cancel", generated_linux_record_syscall_sys_io_cancel_args, generated_linux_print_syscall_sys_io_cancel },
	{ "sys_get_thread_area", generated_linux_record_syscall_sys_get_thread_area_args, generated_linux_print_syscall_sys_get_thread_area },
	{ "sys_lookup_dcookie", generated_linux_record_syscall_sys_lookup_dcookie_args, generated_linux_print_syscall_sys_lookup_dcookie },
	{ "sys_epoll_create", generated_linux_record_syscall_sys_epoll_create_args, generated_linux_print_syscall_sys_epoll_create },
	{ "sys_epoll_ctl_old", generated_linux_record_syscall_sys_epoll_ctl_old_args, generated_linux_print_syscall_sys_epoll_ctl_old },
	{ "sys_epoll_wait_old", generated_linux_record_syscall_sys_epoll_wait_old_args, generated_linux_print_syscall_sys_epoll_wait_old },
	{ "sys_remap_file_pages", generated_linux_record_syscall_sys_remap_file_pages_args, generated_linux_print_syscall_sys_remap_file_pages },
	{ "sys_getdents64", generated_linux_record_syscall_sys_getdents64_args, generated_linux_print_syscall_sys_getdents64 },
	{ "sys_set_tid_address", generated_linux_record_syscall_sys_set_tid_address_args, generated_linux_print_syscall_sys_set_tid_address },
	{ "sys_restart_syscall", generated_linux_record_syscall_sys_restart_syscall_args, generated_linux_print_syscall_sys_restart_syscall },
	{ "sys_semtimedop", generated_linux_record_syscall_sys_semtimedop_args, generated_linux_print_syscall_sys_semtimedop },
	{ "sys_fadvise64", generated_linux_record_syscall_sys_fadvise64_args, generated_linux_print_syscall_sys_fadvise64 },
	{ "sys_timer_create", generated_linux_record_syscall_sys_timer_create_args, generated_linux_print_syscall_sys_timer_create },
	{ "sys_timer_settime", generated_linux_record_syscall_sys_timer_settime_args, generated_linux_print_syscall_sys_timer_settime },
	{ "sys_timer_gettime", generated_linux_record_syscall_sys_timer_gettime_args, generated_linux_print_syscall_sys_timer_gettime },
	{ "sys_timer_getoverrun", generated_linux_record_syscall_sys_timer_getoverrun_args, generated_linux_print_syscall_sys_timer_getoverrun },
	{ "sys_timer_delete", generated_linux_record_syscall_sys_timer_delete_args, generated_linux_print_syscall_sys_timer_delete },
	{ "sys_clock_settime", generated_linux_record_syscall_sys_clock_settime_args, generated_linux_print_syscall_sys_clock_settime },
	{ "sys_clock_gettime", generated_linux_record_syscall_sys_clock_gettime_args, generated_linux_print_syscall_sys_clock_gettime },
	{ "sys_clock_getres", generated_linux_record_syscall_sys_clock_getres_args, generated_linux_print_syscall_sys_clock_getres },
	{ "sys_clock_nanosleep", generated_linux_record_syscall_sys_clock_nanosleep_args, generated_linux_print_syscall_sys_clock_nanosleep },
	{ "sys_exit_group", generated_linux_record_syscall_sys_exit_group_args, NULL },
	{ "sys_epoll_wait", generated_linux_record_syscall_sys_epoll_wait_args, generated_linux_print_syscall_sys_epoll_wait },
	{ "sys_epoll_ctl", generated_linux_record_syscall_sys_epoll_ctl_args, generated_linux_print_syscall_sys_epoll_ctl },
	{ "sys_tgkill", generated_linux_record_syscall_sys_tgkill_args, generated_linux_print_syscall_sys_tgkill },
	{ "sys_utimes", generated_linux_record_syscall_sys_utimes_args, generated_linux_print_syscall_sys_utimes },
	{ "sys_vserver", generated_linux_record_syscall_sys_vserver_args, generated_linux_print_syscall_sys_vserver },
	{ "sys_mbind", generated_linux_record_syscall_sys_mbind_args, generated_linux_print_syscall_sys_mbind },
	{ "sys_set_mempolicy", generated_linux_record_syscall_sys_set_mempolicy_args, generated_linux_print_syscall_sys_set_mempolicy },
	{ "sys_get_mempolicy", generated_linux_record_syscall_sys_get_mempolicy_args, generated_linux_print_syscall_sys_get_mempolicy },
	{ "sys_mq_open", generated_linux_record_syscall_sys_mq_open_args, generated_linux_print_syscall_sys_mq_open },
	{ "sys_mq_unlink", generated_linux_record_syscall_sys_mq_unlink_args, generated_linux_print_syscall_sys_mq_unlink },
	{ "sys_mq_timedsend", generated_linux_record_syscall_sys_mq_timedsend_args, generated_linux_print_syscall_sys_mq_timedsend },
	{ "sys_mq_timedreceive", generated_linux_record_syscall_sys_mq_timedreceive_args, generated_linux_print_syscall_sys_mq_timedreceive },
	{ "sys_mq_notify", generated_linux_record_syscall_sys_mq_notify_args, generated_linux_print_syscall_sys_mq_notify },
	{ "sys_mq_getsetattr", generated_linux_record_syscall_sys_mq_getsetattr_args, generated_linux_print_syscall_sys_mq_getsetattr },
	{ "sys_kexec_load", generated_linux_record_syscall_sys_kexec_load_args, generated_linux_print_syscall_sys_kexec_load },
	{ "sys_waitid", generated_linux_record_syscall_sys_waitid_args, generated_linux_print_syscall_sys_waitid },
	{ "sys_add_key", generated_linux_record_syscall_sys_add_key_args, generated_linux_print_syscall_sys_add_key },
	{ "sys_request_key", generated_linux_record_syscall_sys_request_key_args, generated_linux_print_syscall_sys_request_key },
	{ "sys_keyctl", generated_linux_record_syscall_sys_keyctl_args, generated_linux_print_syscall_sys_keyctl },
	{ "sys_ioprio_set", generated_linux_record_syscall_sys_ioprio_set_args, generated_linux_print_syscall_sys_ioprio_set },
	{ "sys_ioprio_get", generated_linux_record_syscall_sys_ioprio_get_args, generated_linux_print_syscall_sys_ioprio_get },
	{ "sys_inotify_init", generated_linux_record_syscall_sys_inotify_init_args, generated_linux_print_syscall_sys_inotify_init },
	{ "sys_inotify_add_watch", generated_linux_record_syscall_sys_inotify_add_watch_args, generated_linux_print_syscall_sys_inotify_add_watch },
	{ "sys_inotify_rm_watch", generated_linux_record_syscall_sys_inotify_rm_watch_args, generated_linux_print_syscall_sys_inotify_rm_watch },
	{ "sys_migrate_pages", generated_linux_record_syscall_sys_migrate_pages_args, generated_linux_print_syscall_sys_migrate_pages },
	{ "sys_openat", generated_linux_record_syscall_sys_openat_args, generated_linux_print_syscall_sys_openat },
	{ "sys_mkdirat", generated_linux_record_syscall_sys_mkdirat_args, generated_linux_print_syscall_sys_mkdirat },
	{ "sys_mknodat", generated_linux_record_syscall_sys_mknodat_args, generated_linux_print_syscall_sys_mknodat },
	{ "sys_fchownat", generated_linux_record_syscall_sys_fchownat_args, generated_linux_print_syscall_sys_fchownat },
	{ "sys_futimesat", generated_linux_record_syscall_sys_futimesat_args, generated_linux_print_syscall_sys_futimesat },
	{ "sys_newfstatat", generated_linux_record_syscall_sys_newfstatat_args, generated_linux_print_syscall_sys_newfstatat },
	{ "sys_unlinkat", generated_linux_record_syscall_sys_unlinkat_args, generated_linux_print_syscall_sys_unlinkat },
	{ "sys_renameat", generated_linux_record_syscall_sys_renameat_args, generated_linux_print_syscall_sys_renameat },
	{ "sys_linkat", generated_linux_record_syscall_sys_linkat_args, generated_linux_print_syscall_sys_linkat },
	{ "sys_symlinkat", generated_linux_record_syscall_sys_symlinkat_args, generated_linux_print_syscall_sys_symlinkat },
	{ "sys_readlinkat", generated_linux_record_syscall_sys_readlinkat_args, generated_linux_print_syscall_sys_readlinkat },
	{ "sys_fchmodat", generated_linux_record_syscall_sys_fchmodat_args, generated_linux_print_syscall_sys_fchmodat },
	{ "sys_faccessat", generated_linux_record_syscall_sys_faccessat_args, generated_linux_print_syscall_sys_faccessat },
	{ "sys_pselect6", generated_linux_record_syscall_sys_pselect6_args, generated_linux_print_syscall_sys_pselect6 },
	{ "sys_ppoll", generated_linux_record_syscall_sys_ppoll_args, generated_linux_print_syscall_sys_ppoll },
	{ "sys_unshare", generated_linux_record_syscall_sys_unshare_args, generated_linux_print_syscall_sys_unshare },
	{ "sys_set_robust_list", generated_linux_record_syscall_sys_set_robust_list_args, generated_linux_print_syscall_sys_set_robust_list },
	{ "sys_get_robust_list", generated_linux_record_syscall_sys_get_robust_list_args, generated_linux_print_syscall_sys_get_robust_list },
	{ "sys_splice", generated_linux_record_syscall_sys_splice_args, generated_linux_print_syscall_sys_splice },
	{ "sys_tee", generated_linux_record_syscall_sys_tee_args, generated_linux_print_syscall_sys_tee },
	{ "sys_sync_file_range", generated_linux_record_syscall_sys_sync_file_range_args, generated_linux_print_syscall_sys_sync_file_range },
	{ "sys_vmsplice", generated_linux_record_syscall_sys_vmsplice_args, generated_linux_print_syscall_sys_vmsplice },
	{ "sys_move_pages", generated_linux_record_syscall_sys_move_pages_args, generated_linux_print_syscall_sys_move_pages },
	{ "sys_utimensat", generated_linux_record_syscall_sys_utimensat_args, generated_linux_print_syscall_sys_utimensat },
	{ "sys_epoll_pwait", generated_linux_record_syscall_sys_epoll_pwait_args, generated_linux_print_syscall_sys_epoll_pwait },
	{ "sys_signalfd", generated_linux_record_syscall_sys_signalfd_args, generated_linux_print_syscall_sys_signalfd },
	{ "sys_timerfd", generated_linux_record_syscall_sys_timerfd_args, generated_linux_print_syscall_sys_timerfd },
	{ "sys_eventfd", generated_linux_record_syscall_sys_eventfd_args, generated_linux_print_syscall_sys_eventfd },
	{ "sys_fallocate", generated_linux_record_syscall_sys_fallocate_args, generated_linux_print_syscall_sys_fallocate },
	{ "sys_timerfd_settime", generated_linux_record_syscall_sys_timerfd_settime_args, generated_linux_print_syscall_sys_timerfd_settime },
	{ "sys_timerfd_gettime", generated_linux_record_syscall_sys_timerfd_gettime_args, generated_linux_print_syscall_sys_timerfd_gettime },
	{ "sys_accept4", generated_linux_record_syscall_sys_accept4_args, generated_linux_print_syscall_sys_accept4 },
	{ "sys_signalfd4", generated_linux_record_syscall_sys_signalfd4_args, generated_linux_print_syscall_sys_signalfd4 },
	{ "sys_eventfd2", generated_linux_record_syscall_sys_eventfd2_args, generated_linux_print_syscall_sys_eventfd2 },
	{ "sys_epoll_create1", generated_linux_record_syscall_sys_epoll_create1_args, generated_linux_print_syscall_sys_epoll_create1 },
	{ "sys_dup3", generated_linux_record_syscall_sys_dup3_args, generated_linux_print_syscall_sys_dup3 },
	{ "sys_pipe2", generated_linux_record_syscall_sys_pipe2_args, generated_linux_print_syscall_sys_pipe2 },
	{ "sys_inotify_init1", generated_linux_record_syscall_sys_inotify_init1_args, generated_linux_print_syscall_sys_inotify_init1 },
	{ "sys_preadv", generated_linux_record_syscall_sys_preadv_args, generated_linux_print_syscall_sys_preadv },
	{ "sys_pwritev", generated_linux_record_syscall_sys_pwritev_args, generated_linux_print_syscall_sys_pwritev },
	{ "sys_rt_tgsigqueueinfo", generated_linux_record_syscall_sys_rt_tgsigqueueinfo_args, generated_linux_print_syscall_sys_rt_tgsigqueueinfo },
	{ "sys_perf_event_open", generated_linux_record_syscall_sys_perf_event_open_args, generated_linux_print_syscall_sys_perf_event_open },
	{ "sys_recvmmsg", generated_linux_record_syscall_sys_recvmmsg_args, generated_linux_print_syscall_sys_recvmmsg },
	{ "sys_fanotify_init", generated_linux_record_syscall_sys_fanotify_init_args, generated_linux_print_syscall_sys_fanotify_init },
	{ "sys_fanotify_mark", generated_linux_record_syscall_sys_fanotify_mark_args, generated_linux_print_syscall_sys_fanotify_mark },
	{ "sys_prlimit64", generated_linux_record_syscall_sys_prlimit64_args, generated_linux_print_syscall_sys_prlimit64 },
	{ "sys_name_to_handle_at", generated_linux_record_syscall_sys_name_to_handle_at_args, generated_linux_print_syscall_sys_name_to_handle_at },
	{ "sys_open_by_handle_at", generated_linux_record_syscall_sys_open_by_handle_at_args, generated_linux_print_syscall_sys_open_by_handle_at },
	{ "sys_clock_adjtime", generated_linux_record_syscall_sys_clock_adjtime_args, generated_linux_print_syscall_sys_clock_adjtime },
	{ "sys_syncfs", generated_linux_record_syscall_sys_syncfs_args, generated_linux_print_syscall_sys_syncfs },
	{ "sys_sendmmsg", generated_linux_record_syscall_sys_sendmmsg_args, generated_linux_print_syscall_sys_sendmmsg },
	{ "sys_setns", generated_linux_record_syscall_sys_setns_args, generated_linux_print_syscall_sys_setns },
	{ "sys_getcpu", generated_linux_record_syscall_sys_getcpu_args, generated_linux_print_syscall_sys_getcpu },
	{ "sys_process_vm_readv", generated_linux_record_syscall_sys_process_vm_readv_args, generated_linux_print_syscall_sys_process_vm_readv },
	{ "sys_process_vm_writev", generated_linux_record_syscall_sys_process_vm_writev_args, generated_linux_print_syscall_sys_process_vm_writev },
	{ "sys_kcmp", generated_linux_record_syscall_sys_kcmp_args, generated_linux_print_syscall_sys_kcmp },
	{ "sys_finit_module", generated_linux_record_syscall_sys_finit_module_args, generated_linux_print_syscall_sys_finit_module },
	{ "sys_sched_setattr", generated_linux_record_syscall_sys_sched_setattr_args, generated_linux_print_syscall_sys_sched_setattr },
	{ "sys_sched_getattr", generated_linux_record_syscall_sys_sched_getattr_args, generated_linux_print_syscall_sys_sched_getattr },
	{ "sys_renameat2", generated_linux_record_syscall_sys_renameat2_args, generated_linux_print_syscall_sys_renameat2 },
	{ "sys_seccomp", generated_linux_record_syscall_sys_seccomp_args, generated_linux_print_syscall_sys_seccomp },
	{ "sys_getrandom", generated_linux_record_syscall_sys_getrandom_args, generated_linux_print_syscall_sys_getrandom },
	{ "sys_memfd_create", generated_linux_record_syscall_sys_memfd_create_args, generated_linux_print_syscall_sys_memfd_create },
	{ "sys_kexec_file_load", generated_linux_record_syscall_sys_kexec_file_load_args, generated_linux_print_syscall_sys_kexec_file_load },
	{ "sys_bpf", generated_linux_record_syscall_sys_bpf_args, generated_linux_print_syscall_sys_bpf },
	{ "sys_execveat", generated_linux_record_syscall_sys_execveat_args, generated_linux_print_syscall_sys_execveat },
	{ "sys_userfaultfd", generated_linux_record_syscall_sys_userfaultfd_args, generated_linux_print_syscall_sys_userfaultfd },
	{ "sys_membarrier", generated_linux_record_syscall_sys_membarrier_args, generated_linux_print_syscall_sys_membarrier },
	{ "sys_mlock2", generated_linux_record_syscall_sys_mlock2_args, generated_linux_print_syscall_sys_mlock2 },
	{ "sys_copy_file_range", generated_linux_record_syscall_sys_copy_file_range_args, generated_linux_print_syscall_sys_copy_file_range },
	{ "sys_preadv2", generated_linux_record_syscall_sys_preadv2_args, generated_linux_print_syscall_sys_preadv2 },
	{ "sys_pwritev2", generated_linux_record_syscall_sys_pwritev2_args, generated_linux_print_syscall_sys_pwritev2 },
	{ "sys_pkey_mprotect", generated_linux_record_syscall_sys_pkey_mprotect_args, generated_linux_print_syscall_sys_pkey_mprotect },
	{ "sys_pkey_alloc", generated_linux_record_syscall_sys_pkey_alloc_args, generated_linux_print_syscall_sys_pkey_alloc },
	{ "sys_pkey_free", generated_linux_record_syscall_sys_pkey_free_args, generated_linux_print_syscall_sys_pkey_free },
	{ "sys_statx", generated_linux_record_syscall_sys_statx_args, generated_linux_print_syscall_sys_statx },
	{ NULL, NULL, NULL }
};


#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "guestrace.h"
#include "generated-windows.h"

#define NUM_SYSCALL_ARGS 18

enum AccessMaskEnum
{
    FILE_READ_DATA        = 0x000001,
    FILE_LIST_DIRECTORY   = 0x000001,
    FILE_WRITE_DATA       = 0x000002,
    FILE_ADD_FILE         = 0x000002,
    FILE_APPEND_DATA      = 0x000004,
    FILE_ADD_SUBDIRECTORY = 0x000004,
    FILE_READ_EA          = 0x000008,
    FILE_WRITE_EA         = 0x000010,
    FILE_EXECUTE          = 0x000020,
    FILE_TRAVERSE         = 0x000020,
    FILE_DELETE_CHILD     = 0x000040,
    FILE_READ_ATTRIBUTES  = 0x000080,
    FILE_WRITE_ATTRIBUTES = 0x000100,
    DELETE                = 0x010000,
    READ_CONTROL          = 0x020000,
    WRITE_DAC             = 0x040000,
    WRITE_OWNER           = 0x080000,
    SYNCHRONIZE           = 0x100000,
    OWNER                 = FILE_READ_DATA | FILE_LIST_DIRECTORY | FILE_WRITE_DATA |
                            FILE_ADD_FILE  | FILE_APPEND_DATA    | FILE_ADD_SUBDIRECTORY |
                            FILE_READ_EA   | FILE_WRITE_EA       | FILE_EXECUTE |
                            FILE_TRAVERSE  | FILE_DELETE_CHILD   | FILE_READ_ATTRIBUTES |
                            FILE_WRITE_ATTRIBUTES | DELETE       | READ_CONTROL | 
                            WRITE_DAC      | WRITE_OWNER         | SYNCHRONIZE,
    READ_ONLY             = FILE_READ_DATA | FILE_LIST_DIRECTORY | FILE_READ_EA |
                            FILE_EXECUTE   | FILE_TRAVERSE | FILE_READ_ATTRIBUTES |
                            READ_CONTROL   | SYNCHRONIZE, 
    CONTRIBUTOR           = OWNER & ~(FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER)
};

struct win64_obj_attr {
	uint32_t length; // sizeof given struct
	uint64_t root_directory; // if not null, object_name is relative to this directory
	uint64_t object_name; // pointer to unicode string
	uint32_t attributes; // see microsoft documentation
	uint64_t security_descriptor; // see microsoft documentation
	uint64_t security_quality_of_service; // see microsoft documentation
};

struct win64_client_id {
	uint64_t unique_process; /* process id */
	uint64_t unique_thread; /* thread id */
};

/*
 * Get ObjectAttributes struct from virtual address
 */
static struct win64_obj_attr *
obj_attr_from_va(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid) {
	struct win64_obj_attr * buff = NULL;

	uint32_t struct_size = 0;

	if (VMI_SUCCESS != vmi_read_32_va(vmi, vaddr, pid, &struct_size)) {
		goto done;
	}

	struct_size = struct_size <= sizeof(struct win64_obj_attr) ? struct_size : sizeof(struct win64_obj_attr); // don't wanna read too much data

	buff = calloc(1, sizeof(struct win64_obj_attr));

	if (struct_size != vmi_read_va(vmi, vaddr, pid, buff, struct_size)) {
		free(buff);
		buff = NULL;
		goto done;
	}

done:
	return buff;
}

static char *
vf_get_simple_permissions(uint32_t permissions)
{
	char *buff = calloc(1, 1024);
	if (OWNER == permissions) {
		strcpy(buff, "OWNER");
		return buff;
	}
	if (READ_ONLY == permissions) {
		strcpy(buff, "READ_ONLY");
		return buff;
	}
	if (CONTRIBUTOR == permissions) {
		strcpy(buff, "CONTRIBUTOR");
		return buff;
	}
	if (permissions & FILE_READ_DATA)
		strcat(buff, "FILE_READ_DATA|");
	if (permissions & FILE_LIST_DIRECTORY)
		strcat(buff, "FILE_LIST_DIRECTORY|");
	if (permissions & FILE_WRITE_DATA)
		strcat(buff, "FILE_WRITE_DATA|");
	if (permissions & FILE_ADD_FILE)
		strcat(buff, "FILE_ADD_FILE|");
	if (permissions & FILE_APPEND_DATA)
		strcat(buff, "FILE_APPEND_DATA|");
	if (permissions & FILE_ADD_SUBDIRECTORY)
		strcat(buff, "FILE_ADD_SUBDIRECTORY|");
	if (permissions & FILE_READ_EA)
		strcat(buff, "FILE_READ_EA|");
	if (permissions & FILE_WRITE_EA)
		strcat(buff, "FILE_WRITE_EA|");
	if (permissions & FILE_EXECUTE)
		strcat(buff, "FILE_EXECUTE|");
	if (permissions & FILE_TRAVERSE)
		strcat(buff, "FILE_TRAVERSE|");
	if (permissions & FILE_DELETE_CHILD)
		strcat(buff, "FILE_DELETE_CHILD|");
	if (permissions & FILE_READ_ATTRIBUTES)
		strcat(buff, "FILE_READ_ATTRIBUTES|");
	if (permissions & FILE_WRITE_ATTRIBUTES)
		strcat(buff, "FILE_WRITE_ATTRIBUTES|");
	if (permissions & DELETE)
		strcat(buff, "DELETE|");
	if (permissions & READ_CONTROL)
		strcat(buff, "READ_CONTROL|");
	if (permissions & WRITE_DAC)
		strcat(buff, "WRITE_DAC|");
	if (permissions & WRITE_OWNER)
		strcat(buff, "WRITE_OWNER|");
	if (permissions & SYNCHRONIZE)
		strcat(buff, "SYNCHRONIZE|");
	if (strlen(buff) > 0) {
		buff[strlen(buff)-1] = 0;
	} else {
		strcpy(buff, "NONE");
	}
	return buff;
}

static uint8_t *
unicode_str_from_va(vmi_instance_t vmi, addr_t va, vmi_pid_t pid) {
	uint8_t *res = NULL;
	unicode_string_t * unicode_str = vmi_read_unicode_str_va(vmi, va, pid);

	if (unicode_str == NULL) {
		goto done;
	}

	unicode_string_t nunicode_str;
	if (VMI_SUCCESS != vmi_convert_str_encoding(unicode_str, &nunicode_str, "UTF-8")) {
		vmi_free_unicode_str(unicode_str);
		goto done;
	}

	res = nunicode_str.contents; /* points to malloc'd memory */
	vmi_free_unicode_str(unicode_str);

done:
	return res;
}

static uint64_t *
vf_get_args(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid) {
	uint64_t *args = calloc(NUM_SYSCALL_ARGS, sizeof(uint64_t));
	args[0] = event->x86_regs->rcx;
	args[1] = event->x86_regs->rdx;
	args[2] = event->x86_regs->r8;
	args[3] = event->x86_regs->r9;
	
	vmi_read_va(vmi, event->x86_regs->rsp + vmi_get_address_width(vmi) * 5, pid, &args[4], sizeof(uint64_t) * (NUM_SYSCALL_ARGS - 4));
	return args;
}

/* Gets the process name of the process with the PID that is input. */
static char *
get_process_name(vmi_instance_t vmi, vmi_pid_t pid) 
{
	/* Gets the process name of the process with the input pid */
	/* offsets from the LibVMI config file */	
	unsigned long task_offset = vmi_get_offset(vmi, "win_tasks");
	unsigned long pid_offset = vmi_get_offset(vmi, "win_pid");
	unsigned long name_offset = vmi_get_offset(vmi, "win_pname");
	
	/* addresses for the linux process list and current process */
	addr_t list_head = 0;
	addr_t list_curr = 0;
	addr_t curr_proc = 0;
	
	vmi_pid_t curr_pid = 0;		/* pid of the processes task struct we are examining */
	char *proc = NULL;		/* process name of the current process we are examining */

    if(VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &list_head)) {
        printf("Failed to find PsActiveProcessHead\n");
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
	return proc;

}
void *gt_windows_print_syscall_ntacceptconnectport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_3 = args[3] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAcceptConnectPort(PortContext: 0x%lx, ConnectionRequest: 0x%lx, AcceptConnection: %s, ServerView: 0x%lx)\n", pid, tid, proc, args[1], args[2], bool_3, args[4]);
	return args;
}

void gt_windows_print_sysret_ntacceptconnectport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PortHandle: 0x%lx, ServerView: 0x%lx, ClientView: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0, args[4], args[5]);
	free(args);
}

void *gt_windows_print_syscall_ntaccesscheckandauditalarm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	uint8_t *unicode_str_2 = unicode_str_from_va(vmi, args[2], pid);
	uint8_t *unicode_str_3 = unicode_str_from_va(vmi, args[3], pid);
	char *permissions_5 = vf_get_simple_permissions(args[5]);
	char *bool_7 = args[7] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAccessCheckAndAuditAlarm(SubsystemName: %s, HandleId: 0x%lx, ObjectTypeName: %s, ObjectName: %s, SecurityDescriptor: 0x%lx, DesiredAccess: %s [0x%lx], GenericMapping: 0x%lx, ObjectCreation: %s)\n", pid, tid, proc, unicode_str_0, args[1], unicode_str_2, unicode_str_3, args[4], permissions_5, args[5], args[6], bool_7);
	free(unicode_str_0);
	free(unicode_str_2);
	free(unicode_str_3);
	free(permissions_5);	return args;
}

void gt_windows_print_sysret_ntaccesscheckandauditalarm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(GrantedAccess: 0x%lx, AccessStatus: 0x%lx, GenerateOnClose: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[8], args[9], args[10]);
	free(args);
}

void *gt_windows_print_syscall_ntaccesscheckbytypeandauditalarm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	uint8_t *unicode_str_2 = unicode_str_from_va(vmi, args[2], pid);
	uint8_t *unicode_str_3 = unicode_str_from_va(vmi, args[3], pid);
	char *permissions_6 = vf_get_simple_permissions(args[6]);
	char *bool_12 = args[12] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAccessCheckByTypeAndAuditAlarm(SubsystemName: %s, HandleId: 0x%lx, ObjectTypeName: %s, ObjectName: %s, SecurityDescriptor: 0x%lx, PrincipalSelfSid: 0x%lx, DesiredAccess: %s [0x%lx], AuditType: 0x%lx, Flags: 0x%lx, ObjectTypeListLength: 0x%lx, GenericMapping: 0x%lx, ObjectCreation: %s)\n", pid, tid, proc, unicode_str_0, args[1], unicode_str_2, unicode_str_3, args[4], args[5], permissions_6, args[6], args[7], args[8], args[10], args[11], bool_12);
	free(unicode_str_0);
	free(unicode_str_2);
	free(unicode_str_3);
	free(permissions_6);	return args;
}

void gt_windows_print_sysret_ntaccesscheckbytypeandauditalarm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(GrantedAccess: 0x%lx, AccessStatus: 0x%lx, GenerateOnClose: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[13], args[14], args[15]);
	free(args);
}

void *gt_windows_print_syscall_ntaccesscheckbytype(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_3 = vf_get_simple_permissions(args[3]);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(vmi, args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAccessCheckByType(SecurityDescriptor: 0x%lx, PrincipalSelfSid: 0x%lx, ClientToken: 0x%lx, DesiredAccess: %s [0x%lx], ObjectTypeListLength: 0x%lx, GenericMapping: 0x%lx, PrivilegeSetLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], permissions_3, args[3], args[5], args[6], pulong_8);
	free(permissions_3);	return args;
}

void gt_windows_print_sysret_ntaccesscheckbytype(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(vmi, args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PrivilegeSetLength: 0x%lx, GrantedAccess: 0x%lx, AccessStatus: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_8, args[9], args[10]);
	free(args);
}

void *gt_windows_print_syscall_ntaccesscheckbytyperesultlistandauditalarmbyhandle(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	uint8_t *unicode_str_3 = unicode_str_from_va(vmi, args[3], pid);
	uint8_t *unicode_str_4 = unicode_str_from_va(vmi, args[4], pid);
	char *permissions_7 = vf_get_simple_permissions(args[7]);
	char *bool_13 = args[13] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAccessCheckByTypeResultListAndAuditAlarmByHandle(SubsystemName: %s, HandleId: 0x%lx, ClientToken: 0x%lx, ObjectTypeName: %s, ObjectName: %s, SecurityDescriptor: 0x%lx, PrincipalSelfSid: 0x%lx, DesiredAccess: %s [0x%lx], AuditType: 0x%lx, Flags: 0x%lx, ObjectTypeListLength: 0x%lx, GenericMapping: 0x%lx, ObjectCreation: %s)\n", pid, tid, proc, unicode_str_0, args[1], args[2], unicode_str_3, unicode_str_4, args[5], args[6], permissions_7, args[7], args[8], args[9], args[11], args[12], bool_13);
	free(unicode_str_0);
	free(unicode_str_3);
	free(unicode_str_4);
	free(permissions_7);	return args;
}

void gt_windows_print_sysret_ntaccesscheckbytyperesultlistandauditalarmbyhandle(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(GenerateOnClose: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[16]);
	free(args);
}

void *gt_windows_print_syscall_ntaccesscheckbytyperesultlistandauditalarm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	uint8_t *unicode_str_2 = unicode_str_from_va(vmi, args[2], pid);
	uint8_t *unicode_str_3 = unicode_str_from_va(vmi, args[3], pid);
	char *permissions_6 = vf_get_simple_permissions(args[6]);
	char *bool_12 = args[12] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAccessCheckByTypeResultListAndAuditAlarm(SubsystemName: %s, HandleId: 0x%lx, ObjectTypeName: %s, ObjectName: %s, SecurityDescriptor: 0x%lx, PrincipalSelfSid: 0x%lx, DesiredAccess: %s [0x%lx], AuditType: 0x%lx, Flags: 0x%lx, ObjectTypeListLength: 0x%lx, GenericMapping: 0x%lx, ObjectCreation: %s)\n", pid, tid, proc, unicode_str_0, args[1], unicode_str_2, unicode_str_3, args[4], args[5], permissions_6, args[6], args[7], args[8], args[10], args[11], bool_12);
	free(unicode_str_0);
	free(unicode_str_2);
	free(unicode_str_3);
	free(permissions_6);	return args;
}

void gt_windows_print_sysret_ntaccesscheckbytyperesultlistandauditalarm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(GenerateOnClose: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[15]);
	free(args);
}

void *gt_windows_print_syscall_ntaccesscheckbytyperesultlist(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_3 = vf_get_simple_permissions(args[3]);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(vmi, args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAccessCheckByTypeResultList(SecurityDescriptor: 0x%lx, PrincipalSelfSid: 0x%lx, ClientToken: 0x%lx, DesiredAccess: %s [0x%lx], ObjectTypeListLength: 0x%lx, GenericMapping: 0x%lx, PrivilegeSetLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], permissions_3, args[3], args[5], args[6], pulong_8);
	free(permissions_3);	return args;
}

void gt_windows_print_sysret_ntaccesscheckbytyperesultlist(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(vmi, args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PrivilegeSetLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_8);
	free(args);
}

void *gt_windows_print_syscall_ntaccesscheck(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_2 = vf_get_simple_permissions(args[2]);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAccessCheck(SecurityDescriptor: 0x%lx, ClientToken: 0x%lx, DesiredAccess: %s [0x%lx], GenericMapping: 0x%lx, PrivilegeSetLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], permissions_2, args[2], args[3], pulong_5);
	free(permissions_2);	return args;
}

void gt_windows_print_sysret_ntaccesscheck(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PrivilegeSetLength: 0x%lx, GrantedAccess: 0x%lx, AccessStatus: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_5, args[6], args[7]);
	free(args);
}

void *gt_windows_print_syscall_ntaddatom(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAddAtom(Length: 0x%lx)\n", pid, tid, proc, args[1]);
	return args;
}

void gt_windows_print_sysret_ntaddatom(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Atom: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntaddbootentry(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAddBootEntry(BootEntry: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntaddbootentry(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Id: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntadddriverentry(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAddDriverEntry(DriverEntry: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntadddriverentry(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Id: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntadjustgroupstoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_1 = args[1] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAdjustGroupsToken(TokenHandle: 0x%lx, ResetToDefault: %s, NewState: 0x%lx, BufferLength: 0x%lx)\n", pid, tid, proc, args[0], bool_1, args[2], args[3]);
	return args;
}

void gt_windows_print_sysret_ntadjustgroupstoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntadjustprivilegestoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_1 = args[1] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAdjustPrivilegesToken(TokenHandle: 0x%lx, DisableAllPrivileges: %s, NewState: 0x%lx, BufferLength: 0x%lx)\n", pid, tid, proc, args[0], bool_1, args[2], args[3]);
	return args;
}

void gt_windows_print_sysret_ntadjustprivilegestoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntalertresumethread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlertResumeThread(ThreadHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntalertresumethread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousSuspendCount: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntalertthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlertThread(ThreadHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntalertthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntallocatelocallyuniqueid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAllocateLocallyUniqueId()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntallocatelocallyuniqueid(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Luid: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[0]);
	free(args);
}

void *gt_windows_print_syscall_ntallocatereserveobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_1 = NULL;
	uint64_t root_dir_1 = 0;
	uint64_t attributes_1 = 0;
	struct win64_obj_attr *obj_attr_1 = obj_attr_from_va(vmi, args[1], pid);
	if (NULL != obj_attr_1) {
		unicode_str_1 = unicode_str_from_va(vmi, obj_attr_1->object_name, pid);
		root_dir_1 = obj_attr_1->root_directory;
		attributes_1 = obj_attr_1->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAllocateReserveObject(ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Type: 0x%lx)\n", pid, tid, proc, root_dir_1, unicode_str_1, attributes_1, args[2]);
	free(unicode_str_1);
	free(obj_attr_1);	return args;
}

void gt_windows_print_sysret_ntallocatereserveobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(MemoryReserveHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntallocateuserphysicalpages(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAllocateUserPhysicalPages(ProcessHandle: 0x%lx, NumberOfPages: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntallocateuserphysicalpages(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NumberOfPages: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntallocateuuids(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAllocateUuids()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntallocateuuids(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	uint64_t pulong_2 = 0;
	vmi_read_64_va(vmi, args[2], pid, &pulong_2);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Time: 0x%lx, Range: 0x%lx, Sequence: 0x%lx, Seed: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[0], pulong_1, pulong_2, args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntallocatevirtualmemory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAllocateVirtualMemory(ProcessHandle: 0x%lx, *BaseAddress: 0x%lx, ZeroBits: 0x%lx, RegionSize: 0x%lx, AllocationType: 0x%lx, Protect: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4], args[5]);
	return args;
}

void gt_windows_print_sysret_ntallocatevirtualmemory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*BaseAddress: 0x%lx, RegionSize: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1], args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntalpcacceptconnectport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_3 = NULL;
	uint64_t root_dir_3 = 0;
	uint64_t attributes_3 = 0;
	struct win64_obj_attr *obj_attr_3 = obj_attr_from_va(vmi, args[3], pid);
	if (NULL != obj_attr_3) {
		unicode_str_3 = unicode_str_from_va(vmi, obj_attr_3->object_name, pid);
		root_dir_3 = obj_attr_3->root_directory;
		attributes_3 = obj_attr_3->attributes;
	}
	char *bool_8 = args[8] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcAcceptConnectPort(ConnectionPortHandle: 0x%lx, Flags: 0x%lx, ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, PortAttributes: 0x%lx, PortContext: 0x%lx, ConnectionRequest: 0x%lx, ConnectionMessageAttributes: 0x%lx, AcceptConnection: %s)\n", pid, tid, proc, args[1], args[2], root_dir_3, unicode_str_3, attributes_3, args[4], args[5], args[6], args[7], bool_8);
	free(unicode_str_3);
	free(obj_attr_3);	return args;
}

void gt_windows_print_sysret_ntalpcacceptconnectport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PortHandle: 0x%lx, ConnectionMessageAttributes: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0, args[7]);
	free(args);
}

void *gt_windows_print_syscall_ntalpccancelmessage(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcCancelMessage(PortHandle: 0x%lx, Flags: 0x%lx, MessageContext: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntalpccancelmessage(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntalpcconnectport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(vmi, args[1], pid);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	uint64_t pulong_7 = 0;
	vmi_read_64_va(vmi, args[7], pid, &pulong_7);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcConnectPort(PortName: %s, ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, PortAttributes: 0x%lx, Flags: 0x%lx, RequiredServerSid: 0x%lx, ConnectionMessage: 0x%lx, BufferLength: 0x%lx, OutMessageAttributes: 0x%lx, InMessageAttributes: 0x%lx, Timeout: 0x%lx)\n", pid, tid, proc, unicode_str_1, root_dir_2, unicode_str_2, attributes_2, args[3], args[4], args[5], args[6], pulong_7, args[8], args[9], args[10]);
	free(unicode_str_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntalpcconnectport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	uint64_t pulong_7 = 0;
	vmi_read_64_va(vmi, args[7], pid, &pulong_7);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PortHandle: 0x%lx, ConnectionMessage: 0x%lx, BufferLength: 0x%lx, OutMessageAttributes: 0x%lx, InMessageAttributes: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0, args[6], pulong_7, args[8], args[9]);
	free(args);
}

void *gt_windows_print_syscall_ntalpccreateport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_1 = NULL;
	uint64_t root_dir_1 = 0;
	uint64_t attributes_1 = 0;
	struct win64_obj_attr *obj_attr_1 = obj_attr_from_va(vmi, args[1], pid);
	if (NULL != obj_attr_1) {
		unicode_str_1 = unicode_str_from_va(vmi, obj_attr_1->object_name, pid);
		root_dir_1 = obj_attr_1->root_directory;
		attributes_1 = obj_attr_1->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcCreatePort(ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, PortAttributes: 0x%lx)\n", pid, tid, proc, root_dir_1, unicode_str_1, attributes_1, args[2]);
	free(unicode_str_1);
	free(obj_attr_1);	return args;
}

void gt_windows_print_sysret_ntalpccreateport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PortHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntalpccreateportsection(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcCreatePortSection(PortHandle: 0x%lx, Flags: 0x%lx, SectionHandle: 0x%lx, SectionSize: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3]);
	return args;
}

void gt_windows_print_sysret_ntalpccreateportsection(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(AlpcSectionHandle: 0x%lx, ActualSectionSize: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[4], args[5]);
	free(args);
}

void *gt_windows_print_syscall_ntalpccreateresourcereserve(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcCreateResourceReserve(PortHandle: 0x%lx, MessageSize: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntalpccreateresourcereserve(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ResourceId: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntalpccreatesectionview(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcCreateSectionView(PortHandle: 0x%lx, ViewAttributes: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntalpccreatesectionview(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ViewAttributes: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntalpccreatesecuritycontext(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcCreateSecurityContext(PortHandle: 0x%lx, SecurityAttribute: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntalpccreatesecuritycontext(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(SecurityAttribute: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntalpcdeleteportsection(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcDeletePortSection(PortHandle: 0x%lx, SectionHandle: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntalpcdeleteportsection(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntalpcdeleteresourcereserve(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcDeleteResourceReserve(PortHandle: 0x%lx, ResourceId: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntalpcdeleteresourcereserve(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntalpcdeletesectionview(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcDeleteSectionView(PortHandle: 0x%lx, ViewBase: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntalpcdeletesectionview(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntalpcdeletesecuritycontext(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcDeleteSecurityContext(PortHandle: 0x%lx, ContextHandle: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntalpcdeletesecuritycontext(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntalpcdisconnectport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcDisconnectPort(PortHandle: 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntalpcdisconnectport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntalpcimpersonateclientofport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcImpersonateClientOfPort(PortHandle: 0x%lx, PortMessage: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntalpcimpersonateclientofport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntalpcopensenderprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_4 = vf_get_simple_permissions(args[4]);
	uint8_t *unicode_str_5 = NULL;
	uint64_t root_dir_5 = 0;
	uint64_t attributes_5 = 0;
	struct win64_obj_attr *obj_attr_5 = obj_attr_from_va(vmi, args[5], pid);
	if (NULL != obj_attr_5) {
		unicode_str_5 = unicode_str_from_va(vmi, obj_attr_5->object_name, pid);
		root_dir_5 = obj_attr_5->root_directory;
		attributes_5 = obj_attr_5->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcOpenSenderProcess(PortHandle: 0x%lx, PortMessage: 0x%lx, DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, args[1], args[2], permissions_4, args[4], root_dir_5, unicode_str_5, attributes_5);
	free(permissions_4);
	free(unicode_str_5);
	free(obj_attr_5);	return args;
}

void gt_windows_print_sysret_ntalpcopensenderprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ProcessHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntalpcopensenderthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_4 = vf_get_simple_permissions(args[4]);
	uint8_t *unicode_str_5 = NULL;
	uint64_t root_dir_5 = 0;
	uint64_t attributes_5 = 0;
	struct win64_obj_attr *obj_attr_5 = obj_attr_from_va(vmi, args[5], pid);
	if (NULL != obj_attr_5) {
		unicode_str_5 = unicode_str_from_va(vmi, obj_attr_5->object_name, pid);
		root_dir_5 = obj_attr_5->root_directory;
		attributes_5 = obj_attr_5->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcOpenSenderThread(PortHandle: 0x%lx, PortMessage: 0x%lx, DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, args[1], args[2], permissions_4, args[4], root_dir_5, unicode_str_5, attributes_5);
	free(permissions_4);
	free(unicode_str_5);
	free(obj_attr_5);	return args;
}

void gt_windows_print_sysret_ntalpcopensenderthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ThreadHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntalpcqueryinformation(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcQueryInformation(PortHandle: 0x%lx, PortInformationClass: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntalpcqueryinformation(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntalpcqueryinformationmessage(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcQueryInformationMessage(PortHandle: 0x%lx, PortMessage: 0x%lx, MessageInformationClass: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntalpcqueryinformationmessage(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntalpcrevokesecuritycontext(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcRevokeSecurityContext(PortHandle: 0x%lx, ContextHandle: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntalpcrevokesecuritycontext(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntalpcsendwaitreceiveport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcSendWaitReceivePort(PortHandle: 0x%lx, Flags: 0x%lx, SendMessage: 0x%lx, SendMessageAttributes: 0x%lx, ReceiveMessage: 0x%lx, BufferLength: 0x%lx, ReceiveMessageAttributes: 0x%lx, Timeout: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4], pulong_5, args[6], args[7]);
	return args;
}

void gt_windows_print_sysret_ntalpcsendwaitreceiveport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReceiveMessage: 0x%lx, BufferLength: 0x%lx, ReceiveMessageAttributes: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[4], pulong_5, args[6]);
	free(args);
}

void *gt_windows_print_syscall_ntalpcsetinformation(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcSetInformation(PortHandle: 0x%lx, PortInformationClass: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntalpcsetinformation(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntapphelpcachecontrol(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtApphelpCacheControl(type: 0x%lx, buf: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntapphelpcachecontrol(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntaremappedfilesthesame(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAreMappedFilesTheSame(File1MappedAsAnImage: 0x%lx, File2MappedAsFile: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntaremappedfilesthesame(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntassignprocesstojobobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAssignProcessToJobObject(JobHandle: 0x%lx, ProcessHandle: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntassignprocesstojobobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntcallbackreturn(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCallbackReturn(OutputBuffer: 0x%lx, OutputLength: 0x%lx, Status: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntcallbackreturn(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntcanceliofileex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCancelIoFileEx(FileHandle: 0x%lx, IoRequestToCancel: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntcanceliofileex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntcanceliofile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCancelIoFile(FileHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntcanceliofile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntcancelsynchronousiofile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCancelSynchronousIoFile(ThreadHandle: 0x%lx, IoRequestToCancel: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntcancelsynchronousiofile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntcanceltimer(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCancelTimer(TimerHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntcanceltimer(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(CurrentState: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntclearevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtClearEvent(EventHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntclearevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntclose(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtClose(Handle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntclose(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntcloseobjectauditalarm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	char *bool_2 = args[2] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCloseObjectAuditAlarm(SubsystemName: %s, HandleId: 0x%lx, GenerateOnClose: %s)\n", pid, tid, proc, unicode_str_0, args[1], bool_2);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntcloseobjectauditalarm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntcommitcomplete(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCommitComplete(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntcommitcomplete(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntcommitenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCommitEnlistment(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntcommitenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntcommittransaction(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_1 = args[1] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCommitTransaction(TransactionHandle: 0x%lx, Wait: %s)\n", pid, tid, proc, args[0], bool_1);
	return args;
}

void gt_windows_print_sysret_ntcommittransaction(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntcompactkeys(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCompactKeys(Count: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntcompactkeys(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntcomparetokens(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCompareTokens(FirstTokenHandle: 0x%lx, SecondTokenHandle: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntcomparetokens(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Equal: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntcompleteconnectport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCompleteConnectPort(PortHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntcompleteconnectport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntcompresskey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCompressKey(Key: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntcompresskey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntconnectport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(vmi, args[1], pid);
	uint64_t pulong_7 = 0;
	vmi_read_64_va(vmi, args[7], pid, &pulong_7);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtConnectPort(PortName: %s, SecurityQos: 0x%lx, ClientView: 0x%lx, ServerView: 0x%lx, ConnectionInformation: 0x%lx, ConnectionInformationLength: 0x%lx)\n", pid, tid, proc, unicode_str_1, args[2], args[3], args[4], args[6], pulong_7);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntconnectport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	uint64_t pulong_7 = 0;
	vmi_read_64_va(vmi, args[7], pid, &pulong_7);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PortHandle: 0x%lx, ClientView: 0x%lx, ServerView: 0x%lx, MaxMessageLength: 0x%lx, ConnectionInformation: 0x%lx, ConnectionInformationLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0, args[3], args[4], pulong_5, args[6], pulong_7);
	free(args);
}

void *gt_windows_print_syscall_ntcontinue(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtContinue()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntcontinue(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	char *bool_1 = args[1] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ContextRecord: 0x%lx, TestAlert: %s)\n", pid, tid, proc, event->x86_regs->rax, args[0], bool_1);
	free(args);
}

void *gt_windows_print_syscall_ntcreatedebugobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateDebugObject()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntcreatedebugobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(DebugObjectHandle: 0x%lx, DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	free(args);
}

void *gt_windows_print_syscall_ntcreatedirectoryobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateDirectoryObject(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatedirectoryobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(DirectoryHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_4 = NULL;
	uint64_t root_dir_4 = 0;
	uint64_t attributes_4 = 0;
	struct win64_obj_attr *obj_attr_4 = obj_attr_from_va(vmi, args[4], pid);
	if (NULL != obj_attr_4) {
		unicode_str_4 = unicode_str_from_va(vmi, obj_attr_4->object_name, pid);
		root_dir_4 = obj_attr_4->root_directory;
		attributes_4 = obj_attr_4->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateEnlistment(DesiredAccess: %s [0x%lx], ResourceManagerHandle: 0x%lx, TransactionHandle: 0x%lx, ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, CreateOptions: 0x%lx, NotificationMask: 0x%lx, EnlistmentKey: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], args[2], args[3], root_dir_4, unicode_str_4, attributes_4, args[5], args[6], args[7]);
	free(permissions_1);
	free(unicode_str_4);
	free(obj_attr_4);	return args;
}

void gt_windows_print_sysret_ntcreateenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(EnlistmentHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	char *bool_4 = args[4] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateEvent(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, EventType: 0x%lx, InitialState: %s)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], bool_4);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreateevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(EventHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateeventpair(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateEventPair(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreateeventpair(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(EventPairHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatefile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateFile(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, AllocationSize: 0x%lx, FileAttributes: 0x%lx, ShareAccess: 0x%lx, CreateDisposition: 0x%lx, CreateOptions: 0x%lx, EaLength: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[4], args[5], args[6], args[7], args[8], args[10]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatefile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(FileHandle: 0x%lx, IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0, args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntcreateiocompletion(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateIoCompletion(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Count: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreateiocompletion(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoCompletionHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatejobobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateJobObject(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatejobobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(JobHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatejobset(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateJobSet(NumJob: 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntcreatejobset(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntcreatekeyedevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateKeyedEvent(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatekeyedevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(KeyedEventHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	uint8_t *unicode_str_4 = unicode_str_from_va(vmi, args[4], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateKey(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Class: %s, CreateOptions: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, unicode_str_4, args[5]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);
	free(unicode_str_4);	return args;
}

void gt_windows_print_sysret_ntcreatekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	uint64_t pulong_6 = 0;
	vmi_read_64_va(vmi, args[6], pid, &pulong_6);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(KeyHandle: 0x%lx, Disposition: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0, pulong_6);
	free(args);
}

void *gt_windows_print_syscall_ntcreatekeytransacted(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	uint8_t *unicode_str_4 = unicode_str_from_va(vmi, args[4], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateKeyTransacted(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Class: %s, CreateOptions: 0x%lx, TransactionHandle: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, unicode_str_4, args[5], args[6]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);
	free(unicode_str_4);	return args;
}

void gt_windows_print_sysret_ntcreatekeytransacted(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	uint64_t pulong_7 = 0;
	vmi_read_64_va(vmi, args[7], pid, &pulong_7);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(KeyHandle: 0x%lx, Disposition: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0, pulong_7);
	free(args);
}

void *gt_windows_print_syscall_ntcreatemailslotfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateMailslotFile(DesiredAccess: 0x%lx, ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, CreateOptions: 0x%lx, MailslotQuota: 0x%lx, MaximumMessageSize: 0x%lx, ReadTimeout: 0x%lx)\n", pid, tid, proc, args[1], root_dir_2, unicode_str_2, attributes_2, args[4], args[5], args[6], args[7]);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatemailslotfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(FileHandle: 0x%lx, IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0, args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntcreatemutant(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	char *bool_3 = args[3] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateMutant(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, InitialOwner: %s)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, bool_3);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatemutant(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(MutantHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatenamedpipefile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateNamedPipeFile(DesiredAccess: 0x%lx, ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, ShareAccess: 0x%lx, CreateDisposition: 0x%lx, CreateOptions: 0x%lx, NamedPipeType: 0x%lx, ReadMode: 0x%lx, CompletionMode: 0x%lx, MaximumInstances: 0x%lx, InboundQuota: 0x%lx, OutboundQuota: 0x%lx, DefaultTimeout: 0x%lx)\n", pid, tid, proc, args[1], root_dir_2, unicode_str_2, attributes_2, args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13]);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatenamedpipefile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(FileHandle: 0x%lx, IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0, args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntcreatepagingfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreatePagingFile(PageFileName: %s, MinimumSize: 0x%lx, MaximumSize: 0x%lx, Priority: 0x%lx)\n", pid, tid, proc, unicode_str_0, args[1], args[2], args[3]);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntcreatepagingfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntcreateport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_1 = NULL;
	uint64_t root_dir_1 = 0;
	uint64_t attributes_1 = 0;
	struct win64_obj_attr *obj_attr_1 = obj_attr_from_va(vmi, args[1], pid);
	if (NULL != obj_attr_1) {
		unicode_str_1 = unicode_str_from_va(vmi, obj_attr_1->object_name, pid);
		root_dir_1 = obj_attr_1->root_directory;
		attributes_1 = obj_attr_1->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreatePort(ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, MaxConnectionInfoLength: 0x%lx, MaxMessageLength: 0x%lx, MaxPoolUsage: 0x%lx)\n", pid, tid, proc, root_dir_1, unicode_str_1, attributes_1, args[2], args[3], args[4]);
	free(unicode_str_1);
	free(obj_attr_1);	return args;
}

void gt_windows_print_sysret_ntcreateport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PortHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateprivatenamespace(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreatePrivateNamespace(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, BoundaryDescriptor: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreateprivatenamespace(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NamespaceHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateprocessex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateProcessEx(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, ParentProcess: 0x%lx, Flags: 0x%lx, SectionHandle: 0x%lx, DebugPort: 0x%lx, ExceptionPort: 0x%lx, JobMemberLevel: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[4], args[5], args[6], args[7], args[8]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreateprocessex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ProcessHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	char *bool_4 = args[4] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateProcess(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, ParentProcess: 0x%lx, InheritObjectTable: %s, SectionHandle: 0x%lx, DebugPort: 0x%lx, ExceptionPort: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], bool_4, args[5], args[6], args[7]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreateprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ProcessHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateprofileex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateProfileEx(Process: 0x%lx, ProfileBase: 0x%lx, ProfileSize: 0x%lx, BucketSize: 0x%lx, Buffer: 0x%lx, BufferSize: 0x%lx, ProfileSource: 0x%lx, GroupAffinityCount: 0x%lx, GroupAffinity: 0x%lx)\n", pid, tid, proc, args[1], args[2], args[3], args[4], pulong_5, args[6], args[7], args[8], args[9]);
	return args;
}

void gt_windows_print_sysret_ntcreateprofileex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ProfileHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateprofile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateProfile(Process: 0x%lx, RangeBase: 0x%lx, RangeSize: 0x%lx, BucketSize: 0x%lx, Buffer: 0x%lx, BufferSize: 0x%lx, ProfileSource: 0x%lx, Affinity: 0x%lx)\n", pid, tid, proc, args[1], args[2], args[3], args[4], pulong_5, args[6], args[7], args[8]);
	return args;
}

void gt_windows_print_sysret_ntcreateprofile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ProfileHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateresourcemanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_4 = NULL;
	uint64_t root_dir_4 = 0;
	uint64_t attributes_4 = 0;
	struct win64_obj_attr *obj_attr_4 = obj_attr_from_va(vmi, args[4], pid);
	if (NULL != obj_attr_4) {
		unicode_str_4 = unicode_str_from_va(vmi, obj_attr_4->object_name, pid);
		root_dir_4 = obj_attr_4->root_directory;
		attributes_4 = obj_attr_4->attributes;
	}
	uint8_t *unicode_str_6 = unicode_str_from_va(vmi, args[6], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateResourceManager(DesiredAccess: %s [0x%lx], TmHandle: 0x%lx, RmGuid: 0x%lx, ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, CreateOptions: 0x%lx, Description: %s)\n", pid, tid, proc, permissions_1, args[1], args[2], args[3], root_dir_4, unicode_str_4, attributes_4, args[5], unicode_str_6);
	free(permissions_1);
	free(unicode_str_4);
	free(obj_attr_4);
	free(unicode_str_6);	return args;
}

void gt_windows_print_sysret_ntcreateresourcemanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ResourceManagerHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatesection(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateSection(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, MaximumSize: 0x%lx, SectionPageProtection: 0x%lx, AllocationAttributes: 0x%lx, FileHandle: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[4], args[5], args[6]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatesection(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(SectionHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatesemaphore(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateSemaphore(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, InitialCount: 0x%lx, MaximumCount: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[4]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatesemaphore(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(SemaphoreHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatesymboliclinkobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	uint8_t *unicode_str_3 = unicode_str_from_va(vmi, args[3], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateSymbolicLinkObject(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, LinkTarget: %s)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, unicode_str_3);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);
	free(unicode_str_3);	return args;
}

void gt_windows_print_sysret_ntcreatesymboliclinkobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(LinkHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatethreadex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateThreadEx(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, ProcessHandle: 0x%lx, StartRoutine: 0x%lx, Argument: 0x%lx, CreateFlags: 0x%lx, ZeroBits: 0x%lx, StackSize: 0x%lx, MaximumStackSize: 0x%lx, AttributeList: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatethreadex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ThreadHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatethread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	char *bool_7 = args[7] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateThread(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, ProcessHandle: 0x%lx, ThreadContext: 0x%lx, InitialTeb: 0x%lx, CreateSuspended: %s)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[5], args[6], bool_7);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatethread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ThreadHandle: 0x%lx, ClientId: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0, args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntcreatetimer(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateTimer(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, TimerType: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatetimer(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TimerHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatetoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateToken(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, TokenType: 0x%lx, AuthenticationId: 0x%lx, ExpirationTime: 0x%lx, User: 0x%lx, Groups: 0x%lx, Privileges: 0x%lx, Owner: 0x%lx, PrimaryGroup: 0x%lx, DefaultDacl: 0x%lx, TokenSource: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatetoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TokenHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatetransactionmanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	uint8_t *unicode_str_3 = unicode_str_from_va(vmi, args[3], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateTransactionManager(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, LogFileName: %s, CreateOptions: 0x%lx, CommitStrength: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, unicode_str_3, args[4], args[5]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);
	free(unicode_str_3);	return args;
}

void gt_windows_print_sysret_ntcreatetransactionmanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TmHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatetransaction(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	uint8_t *unicode_str_9 = unicode_str_from_va(vmi, args[9], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateTransaction(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Uow: 0x%lx, TmHandle: 0x%lx, CreateOptions: 0x%lx, IsolationLevel: 0x%lx, IsolationFlags: 0x%lx, Timeout: 0x%lx, Description: %s)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[4], args[5], args[6], args[7], args[8], unicode_str_9);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);
	free(unicode_str_9);	return args;
}

void gt_windows_print_sysret_ntcreatetransaction(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TransactionHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateuserprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_2 = vf_get_simple_permissions(args[2]);
	char *permissions_3 = vf_get_simple_permissions(args[3]);
	uint8_t *unicode_str_4 = NULL;
	uint64_t root_dir_4 = 0;
	uint64_t attributes_4 = 0;
	struct win64_obj_attr *obj_attr_4 = obj_attr_from_va(vmi, args[4], pid);
	if (NULL != obj_attr_4) {
		unicode_str_4 = unicode_str_from_va(vmi, obj_attr_4->object_name, pid);
		root_dir_4 = obj_attr_4->root_directory;
		attributes_4 = obj_attr_4->attributes;
	}
	uint8_t *unicode_str_5 = NULL;
	uint64_t root_dir_5 = 0;
	uint64_t attributes_5 = 0;
	struct win64_obj_attr *obj_attr_5 = obj_attr_from_va(vmi, args[5], pid);
	if (NULL != obj_attr_5) {
		unicode_str_5 = unicode_str_from_va(vmi, obj_attr_5->object_name, pid);
		root_dir_5 = obj_attr_5->root_directory;
		attributes_5 = obj_attr_5->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateUserProcess(ProcessDesiredAccess: %s [0x%lx], ThreadDesiredAccess: %s [0x%lx], ProcessObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, ThreadObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, ProcessFlags: 0x%lx, ThreadFlags: 0x%lx, ProcessParameters: 0x%lx, CreateInfo: 0x%lx, AttributeList: 0x%lx)\n", pid, tid, proc, permissions_2, args[2], permissions_3, args[3], root_dir_4, unicode_str_4, attributes_4, root_dir_5, unicode_str_5, attributes_5, args[6], args[7], args[8], args[9], args[10]);
	free(permissions_2);
	free(permissions_3);
	free(unicode_str_4);
	free(obj_attr_4);
	free(unicode_str_5);
	free(obj_attr_5);	return args;
}

void gt_windows_print_sysret_ntcreateuserprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	uint64_t phandle_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &phandle_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ProcessHandle: 0x%lx, ThreadHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0, phandle_1);
	free(args);
}

void *gt_windows_print_syscall_ntcreatewaitableport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_1 = NULL;
	uint64_t root_dir_1 = 0;
	uint64_t attributes_1 = 0;
	struct win64_obj_attr *obj_attr_1 = obj_attr_from_va(vmi, args[1], pid);
	if (NULL != obj_attr_1) {
		unicode_str_1 = unicode_str_from_va(vmi, obj_attr_1->object_name, pid);
		root_dir_1 = obj_attr_1->root_directory;
		attributes_1 = obj_attr_1->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateWaitablePort(ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, MaxConnectionInfoLength: 0x%lx, MaxMessageLength: 0x%lx, MaxPoolUsage: 0x%lx)\n", pid, tid, proc, root_dir_1, unicode_str_1, attributes_1, args[2], args[3], args[4]);
	free(unicode_str_1);
	free(obj_attr_1);	return args;
}

void gt_windows_print_sysret_ntcreatewaitableport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PortHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateworkerfactory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateWorkerFactory(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, CompletionPortHandle: 0x%lx, WorkerProcessHandle: 0x%lx, StartRoutine: 0x%lx, StartParameter: 0x%lx, MaxThreadCount: 0x%lx, StackReserve: 0x%lx, StackCommit: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[4], args[5], args[6], args[7], args[8], args[9]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreateworkerfactory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(WorkerFactoryHandleReturn: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntdebugactiveprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDebugActiveProcess()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntdebugactiveprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ProcessHandle: 0x%lx, DebugObjectHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[0], args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntdebugcontinue(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDebugContinue()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntdebugcontinue(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(DebugObjectHandle: 0x%lx, ClientId: 0x%lx, ContinueStatus: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[0], args[1], args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntdelayexecution(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_0 = args[0] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDelayExecution(Alertable: %s, DelayInterval: 0x%lx)\n", pid, tid, proc, bool_0, args[1]);
	return args;
}

void gt_windows_print_sysret_ntdelayexecution(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntdeleteatom(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDeleteAtom(Atom: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntdeleteatom(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntdeletebootentry(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDeleteBootEntry(Id: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntdeletebootentry(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntdeletedriverentry(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDeleteDriverEntry(Id: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntdeletedriverentry(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntdeletefile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(vmi, args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(vmi, obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDeleteFile(ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0);
	free(unicode_str_0);
	free(obj_attr_0);	return args;
}

void gt_windows_print_sysret_ntdeletefile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntdeletekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDeleteKey(KeyHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntdeletekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntdeleteobjectauditalarm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	char *bool_2 = args[2] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDeleteObjectAuditAlarm(SubsystemName: %s, HandleId: 0x%lx, GenerateOnClose: %s)\n", pid, tid, proc, unicode_str_0, args[1], bool_2);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntdeleteobjectauditalarm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntdeleteprivatenamespace(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDeletePrivateNamespace(NamespaceHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntdeleteprivatenamespace(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntdeletevaluekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(vmi, args[1], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDeleteValueKey(KeyHandle: 0x%lx, ValueName: %s)\n", pid, tid, proc, args[0], unicode_str_1);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntdeletevaluekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntdeviceiocontrolfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDeviceIoControlFile(FileHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, IoControlCode: 0x%lx, InputBufferLength: 0x%lx, OutputBufferLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[5], args[7], args[9]);
	return args;
}

void gt_windows_print_sysret_ntdeviceiocontrolfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntdisablelastknowngood(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDisableLastKnownGood()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntdisablelastknowngood(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntdisplaystring(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDisplayString(String: %s)\n", pid, tid, proc, unicode_str_0);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntdisplaystring(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntdrawtext(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDrawText(Text: %s)\n", pid, tid, proc, unicode_str_0);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntdrawtext(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntduplicateobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_4 = vf_get_simple_permissions(args[4]);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDuplicateObject(SourceProcessHandle: 0x%lx, SourceHandle: 0x%lx, TargetProcessHandle: 0x%lx, DesiredAccess: %s [0x%lx], HandleAttributes: 0x%lx, Options: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], permissions_4, args[4], args[5], args[6]);
	free(permissions_4);	return args;
}

void gt_windows_print_sysret_ntduplicateobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_3 = 0;
	vmi_read_64_va(vmi, args[3], pid, &phandle_3);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TargetHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_3);
	free(args);
}

void *gt_windows_print_syscall_ntduplicatetoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	char *bool_3 = args[3] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDuplicateToken(ExistingTokenHandle: 0x%lx, DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, EffectiveOnly: %s, TokenType: 0x%lx)\n", pid, tid, proc, args[0], permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, bool_3, args[4]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntduplicatetoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &phandle_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NewTokenHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_5);
	free(args);
}

void *gt_windows_print_syscall_ntenablelastknowngood(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtEnableLastKnownGood()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntenablelastknowngood(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntenumeratebootentries(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtEnumerateBootEntries(BufferLength: 0x%lx)\n", pid, tid, proc, pulong_1);
	return args;
}

void gt_windows_print_sysret_ntenumeratebootentries(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(BufferLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntenumeratedriverentries(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtEnumerateDriverEntries(BufferLength: 0x%lx)\n", pid, tid, proc, pulong_1);
	return args;
}

void gt_windows_print_sysret_ntenumeratedriverentries(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(BufferLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntenumeratekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtEnumerateKey(KeyHandle: 0x%lx, Index: 0x%lx, KeyInformationClass: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntenumeratekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ResultLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntenumeratesystemenvironmentvaluesex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint64_t pulong_2 = 0;
	vmi_read_64_va(vmi, args[2], pid, &pulong_2);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtEnumerateSystemEnvironmentValuesEx(InformationClass: 0x%lx, BufferLength: 0x%lx)\n", pid, tid, proc, args[0], pulong_2);
	return args;
}

void gt_windows_print_sysret_ntenumeratesystemenvironmentvaluesex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_2 = 0;
	vmi_read_64_va(vmi, args[2], pid, &pulong_2);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Buffer: 0x%lx, BufferLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1], pulong_2);
	free(args);
}

void *gt_windows_print_syscall_ntenumeratetransactionobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtEnumerateTransactionObject(RootObjectHandle: 0x%lx, QueryType: 0x%lx, ObjectCursorLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntenumeratetransactionobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntenumeratevaluekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtEnumerateValueKey(KeyHandle: 0x%lx, Index: 0x%lx, KeyValueInformationClass: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntenumeratevaluekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ResultLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntextendsection(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtExtendSection(SectionHandle: 0x%lx, NewSectionSize: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntextendsection(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NewSectionSize: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntfiltertoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFilterToken(ExistingTokenHandle: 0x%lx, Flags: 0x%lx, SidsToDisable: 0x%lx, PrivilegesToDelete: 0x%lx, RestrictedSids: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4]);
	return args;
}

void gt_windows_print_sysret_ntfiltertoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &phandle_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NewTokenHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_5);
	free(args);
}

void *gt_windows_print_syscall_ntfindatom(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFindAtom(Length: 0x%lx)\n", pid, tid, proc, args[1]);
	return args;
}

void gt_windows_print_sysret_ntfindatom(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Atom: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntflushbuffersfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFlushBuffersFile(FileHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntflushbuffersfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntflushinstalluilanguage(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFlushInstallUILanguage(InstallUILanguage: 0x%lx, SetComittedFlag: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntflushinstalluilanguage(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntflushinstructioncache(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFlushInstructionCache(ProcessHandle: 0x%lx, BaseAddress: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntflushinstructioncache(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntflushkey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFlushKey(KeyHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntflushkey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntflushprocesswritebuffers(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFlushProcessWriteBuffers()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntflushprocesswritebuffers(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntflushvirtualmemory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFlushVirtualMemory(ProcessHandle: 0x%lx, *BaseAddress: 0x%lx, RegionSize: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntflushvirtualmemory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*BaseAddress: 0x%lx, RegionSize: 0x%lx, IoStatus: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1], args[2], args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntflushwritebuffer(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFlushWriteBuffer()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntflushwritebuffer(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntfreeuserphysicalpages(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFreeUserPhysicalPages(ProcessHandle: 0x%lx, NumberOfPages: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntfreeuserphysicalpages(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NumberOfPages: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntfreevirtualmemory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFreeVirtualMemory(ProcessHandle: 0x%lx, *BaseAddress: 0x%lx, RegionSize: 0x%lx, FreeType: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3]);
	return args;
}

void gt_windows_print_sysret_ntfreevirtualmemory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*BaseAddress: 0x%lx, RegionSize: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1], args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntfreezeregistry(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFreezeRegistry(TimeOutInSeconds: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntfreezeregistry(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntfreezetransactions(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFreezeTransactions(FreezeTimeout: 0x%lx, ThawTimeout: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntfreezetransactions(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntfscontrolfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFsControlFile(FileHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, IoControlCode: 0x%lx, InputBufferLength: 0x%lx, OutputBufferLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[5], args[7], args[9]);
	return args;
}

void gt_windows_print_sysret_ntfscontrolfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntgetcontextthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetContextThread(ThreadHandle: 0x%lx, ThreadContext: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntgetcontextthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ThreadContext: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntgetcurrentprocessornumber(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetCurrentProcessorNumber()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntgetcurrentprocessornumber(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntgetdevicepowerstate(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetDevicePowerState(Device: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntgetdevicepowerstate(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*State: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntgetmuiregistryinfo(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetMUIRegistryInfo(Flags: 0x%lx, DataSize: 0x%lx)\n", pid, tid, proc, args[0], pulong_1);
	return args;
}

void gt_windows_print_sysret_ntgetmuiregistryinfo(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(DataSize: 0x%lx, Data: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_1, args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntgetnextprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetNextProcess(ProcessHandle: 0x%lx, DesiredAccess: %s [0x%lx], HandleAttributes: 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, args[0], permissions_1, args[1], args[2], args[3]);
	free(permissions_1);	return args;
}

void gt_windows_print_sysret_ntgetnextprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &phandle_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NewProcessHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_4);
	free(args);
}

void *gt_windows_print_syscall_ntgetnextthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_2 = vf_get_simple_permissions(args[2]);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetNextThread(ProcessHandle: 0x%lx, ThreadHandle: 0x%lx, DesiredAccess: %s [0x%lx], HandleAttributes: 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, args[0], args[1], permissions_2, args[2], args[3], args[4]);
	free(permissions_2);	return args;
}

void gt_windows_print_sysret_ntgetnextthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &phandle_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NewThreadHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_5);
	free(args);
}

void *gt_windows_print_syscall_ntgetnlssectionptr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetNlsSectionPtr(SectionType: 0x%lx, SectionData: 0x%lx, ContextData: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntgetnlssectionptr(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*SectionPointer: 0x%lx, SectionSize: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[3], pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntgetnotificationresourcemanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetNotificationResourceManager(ResourceManagerHandle: 0x%lx, NotificationLength: 0x%lx, Timeout: 0x%lx, Asynchronous: 0x%lx, AsynchronousContext: 0x%lx)\n", pid, tid, proc, args[0], args[2], args[3], args[5], args[6]);
	return args;
}

void gt_windows_print_sysret_ntgetnotificationresourcemanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TransactionNotification: 0x%lx, ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1], pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntgetplugplayevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetPlugPlayEvent(EventHandle: 0x%lx, Context: 0x%lx, EventBufferSize: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntgetplugplayevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntgetwritewatch(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetWriteWatch(ProcessHandle: 0x%lx, Flags: 0x%lx, BaseAddress: 0x%lx, RegionSize: 0x%lx, EntriesInUserAddressArray: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[5]);
	return args;
}

void gt_windows_print_sysret_ntgetwritewatch(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_6 = 0;
	vmi_read_64_va(vmi, args[6], pid, &pulong_6);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(EntriesInUserAddressArray: 0x%lx, Granularity: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[5], pulong_6);
	free(args);
}

void *gt_windows_print_syscall_ntimpersonateanonymoustoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtImpersonateAnonymousToken(ThreadHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntimpersonateanonymoustoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntimpersonateclientofport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtImpersonateClientOfPort(PortHandle: 0x%lx, Message: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntimpersonateclientofport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntimpersonatethread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtImpersonateThread(ServerThreadHandle: 0x%lx, ClientThreadHandle: 0x%lx, SecurityQos: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntimpersonatethread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntinitializenlsfiles(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtInitializeNlsFiles()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntinitializenlsfiles(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*BaseAddress: 0x%lx, DefaultLocaleId: 0x%lx, DefaultCasingTableSize: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[0], args[1], args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntinitializeregistry(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtInitializeRegistry(BootCondition: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntinitializeregistry(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntinitiatepoweraction(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_3 = args[3] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtInitiatePowerAction(SystemAction: 0x%lx, MinSystemState: 0x%lx, Flags: 0x%lx, Asynchronous: %s)\n", pid, tid, proc, args[0], args[1], args[2], bool_3);
	return args;
}

void gt_windows_print_sysret_ntinitiatepoweraction(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntisprocessinjob(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtIsProcessInJob(ProcessHandle: 0x%lx, JobHandle: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntisprocessinjob(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntissystemresumeautomatic(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtIsSystemResumeAutomatic()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntissystemresumeautomatic(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntisuilanguagecomitted(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtIsUILanguageComitted()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntisuilanguagecomitted(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntlistenport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtListenPort(PortHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntlistenport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ConnectionRequest: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntloaddriver(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtLoadDriver(DriverServiceName: %s)\n", pid, tid, proc, unicode_str_0);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntloaddriver(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntloadkey2(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(vmi, args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(vmi, obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	uint8_t *unicode_str_1 = NULL;
	uint64_t root_dir_1 = 0;
	uint64_t attributes_1 = 0;
	struct win64_obj_attr *obj_attr_1 = obj_attr_from_va(vmi, args[1], pid);
	if (NULL != obj_attr_1) {
		unicode_str_1 = unicode_str_from_va(vmi, obj_attr_1->object_name, pid);
		root_dir_1 = obj_attr_1->root_directory;
		attributes_1 = obj_attr_1->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtLoadKey2(TargetKey: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, SourceFile: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0, root_dir_1, unicode_str_1, attributes_1, args[2]);
	free(unicode_str_0);
	free(obj_attr_0);
	free(unicode_str_1);
	free(obj_attr_1);	return args;
}

void gt_windows_print_sysret_ntloadkey2(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntloadkeyex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(vmi, args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(vmi, obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	uint8_t *unicode_str_1 = NULL;
	uint64_t root_dir_1 = 0;
	uint64_t attributes_1 = 0;
	struct win64_obj_attr *obj_attr_1 = obj_attr_from_va(vmi, args[1], pid);
	if (NULL != obj_attr_1) {
		unicode_str_1 = unicode_str_from_va(vmi, obj_attr_1->object_name, pid);
		root_dir_1 = obj_attr_1->root_directory;
		attributes_1 = obj_attr_1->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtLoadKeyEx(TargetKey: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, SourceFile: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Flags: 0x%lx, TrustClassKey: 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0, root_dir_1, unicode_str_1, attributes_1, args[2], args[3]);
	free(unicode_str_0);
	free(obj_attr_0);
	free(unicode_str_1);
	free(obj_attr_1);	return args;
}

void gt_windows_print_sysret_ntloadkeyex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntloadkey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(vmi, args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(vmi, obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	uint8_t *unicode_str_1 = NULL;
	uint64_t root_dir_1 = 0;
	uint64_t attributes_1 = 0;
	struct win64_obj_attr *obj_attr_1 = obj_attr_from_va(vmi, args[1], pid);
	if (NULL != obj_attr_1) {
		unicode_str_1 = unicode_str_from_va(vmi, obj_attr_1->object_name, pid);
		root_dir_1 = obj_attr_1->root_directory;
		attributes_1 = obj_attr_1->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtLoadKey(TargetKey: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, SourceFile: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0, root_dir_1, unicode_str_1, attributes_1);
	free(unicode_str_0);
	free(obj_attr_0);
	free(unicode_str_1);
	free(obj_attr_1);	return args;
}

void gt_windows_print_sysret_ntloadkey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntlockfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_8 = args[8] ? "TRUE" : "FALSE";
	char *bool_9 = args[9] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtLockFile(FileHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, ByteOffset: 0x%lx, Length: 0x%lx, Key: 0x%lx, FailImmediately: %s, ExclusiveLock: %s)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[5], args[6], args[7], bool_8, bool_9);
	return args;
}

void gt_windows_print_sysret_ntlockfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntlockproductactivationkeys(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtLockProductActivationKeys(*pPrivateVer: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntlockproductactivationkeys(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*pPrivateVer: 0x%lx, *pSafeMode: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[0], args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntlockregistrykey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtLockRegistryKey(KeyHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntlockregistrykey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntlockvirtualmemory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtLockVirtualMemory(ProcessHandle: 0x%lx, *BaseAddress: 0x%lx, RegionSize: 0x%lx, MapType: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3]);
	return args;
}

void gt_windows_print_sysret_ntlockvirtualmemory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*BaseAddress: 0x%lx, RegionSize: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1], args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntmakepermanentobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtMakePermanentObject(Handle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntmakepermanentobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntmaketemporaryobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtMakeTemporaryObject(Handle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntmaketemporaryobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntmapcmfmodule(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtMapCMFModule(What: 0x%lx, Index: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntmapcmfmodule(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_2 = 0;
	vmi_read_64_va(vmi, args[2], pid, &pulong_2);
	uint64_t pulong_3 = 0;
	vmi_read_64_va(vmi, args[3], pid, &pulong_3);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(CacheIndexOut: 0x%lx, CacheFlagsOut: 0x%lx, ViewSizeOut: 0x%lx, *BaseAddress: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_2, pulong_3, pulong_4, args[5]);
	free(args);
}

void *gt_windows_print_syscall_ntmapuserphysicalpages(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtMapUserPhysicalPages(VirtualAddress: 0x%lx, NumberOfPages: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntmapuserphysicalpages(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntmapuserphysicalpagesscatter(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtMapUserPhysicalPagesScatter(NumberOfPages: 0x%lx)\n", pid, tid, proc, args[1]);
	return args;
}

void gt_windows_print_sysret_ntmapuserphysicalpagesscatter(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntmapviewofsection(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtMapViewOfSection(SectionHandle: 0x%lx, ProcessHandle: 0x%lx, *BaseAddress: 0x%lx, ZeroBits: 0x%lx, CommitSize: 0x%lx, SectionOffset: 0x%lx, ViewSize: 0x%lx, InheritDisposition: 0x%lx, AllocationType: 0x%lx, Win32Protect: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9]);
	return args;
}

void gt_windows_print_sysret_ntmapviewofsection(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*BaseAddress: 0x%lx, SectionOffset: 0x%lx, ViewSize: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[2], args[5], args[6]);
	free(args);
}

void *gt_windows_print_syscall_ntmodifybootentry(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtModifyBootEntry(BootEntry: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntmodifybootentry(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntmodifydriverentry(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtModifyDriverEntry(DriverEntry: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntmodifydriverentry(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntnotifychangedirectoryfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_8 = args[8] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtNotifyChangeDirectoryFile(FileHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, Length: 0x%lx, CompletionFilter: 0x%lx, WatchTree: %s)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[6], args[7], bool_8);
	return args;
}

void gt_windows_print_sysret_ntnotifychangedirectoryfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntnotifychangekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_6 = args[6] ? "TRUE" : "FALSE";
	char *bool_9 = args[9] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtNotifyChangeKey(KeyHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, CompletionFilter: 0x%lx, WatchTree: %s, BufferSize: 0x%lx, Asynchronous: %s)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[5], bool_6, args[8], bool_9);
	return args;
}

void gt_windows_print_sysret_ntnotifychangekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntnotifychangemultiplekeys(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_8 = args[8] ? "TRUE" : "FALSE";
	char *bool_11 = args[11] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtNotifyChangeMultipleKeys(MasterKeyHandle: 0x%lx, Count: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, CompletionFilter: 0x%lx, WatchTree: %s, BufferSize: 0x%lx, Asynchronous: %s)\n", pid, tid, proc, args[0], args[1], args[3], args[4], args[5], args[7], bool_8, args[10], bool_11);
	return args;
}

void gt_windows_print_sysret_ntnotifychangemultiplekeys(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[6]);
	free(args);
}

void *gt_windows_print_syscall_ntnotifychangesession(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtNotifyChangeSession(Session: 0x%lx, IoStateSequence: 0x%lx, Reserved: 0x%lx, Action: 0x%lx, IoState: 0x%lx, IoState2: 0x%lx, Buffer: 0x%lx, BufferSize: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
	return args;
}

void gt_windows_print_sysret_ntnotifychangesession(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntopendirectoryobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenDirectoryObject(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopendirectoryobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(DirectoryHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_4 = NULL;
	uint64_t root_dir_4 = 0;
	uint64_t attributes_4 = 0;
	struct win64_obj_attr *obj_attr_4 = obj_attr_from_va(vmi, args[4], pid);
	if (NULL != obj_attr_4) {
		unicode_str_4 = unicode_str_from_va(vmi, obj_attr_4->object_name, pid);
		root_dir_4 = obj_attr_4->root_directory;
		attributes_4 = obj_attr_4->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenEnlistment(DesiredAccess: %s [0x%lx], ResourceManagerHandle: 0x%lx, EnlistmentGuid: 0x%lx, ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], args[2], args[3], root_dir_4, unicode_str_4, attributes_4);
	free(permissions_1);
	free(unicode_str_4);
	free(obj_attr_4);	return args;
}

void gt_windows_print_sysret_ntopenenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(EnlistmentHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenEvent(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(EventHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopeneventpair(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenEventPair(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopeneventpair(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(EventPairHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenFile(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, ShareAccess: 0x%lx, OpenOptions: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[4], args[5]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(FileHandle: 0x%lx, IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0, args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntopeniocompletion(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenIoCompletion(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopeniocompletion(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoCompletionHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenjobobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenJobObject(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenjobobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(JobHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenkeyedevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenKeyedEvent(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenkeyedevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(KeyedEventHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenkeyex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenKeyEx(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, OpenOptions: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenkeyex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(KeyHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenkey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenKey(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenkey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(KeyHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenkeytransactedex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenKeyTransactedEx(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, OpenOptions: 0x%lx, TransactionHandle: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[4]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenkeytransactedex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(KeyHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenkeytransacted(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenKeyTransacted(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, TransactionHandle: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenkeytransacted(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(KeyHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenmutant(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenMutant(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenmutant(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(MutantHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenobjectauditalarm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	uint8_t *unicode_str_2 = unicode_str_from_va(vmi, args[2], pid);
	uint8_t *unicode_str_3 = unicode_str_from_va(vmi, args[3], pid);
	char *permissions_6 = vf_get_simple_permissions(args[6]);
	char *permissions_7 = vf_get_simple_permissions(args[7]);
	char *bool_9 = args[9] ? "TRUE" : "FALSE";
	char *bool_10 = args[10] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenObjectAuditAlarm(SubsystemName: %s, HandleId: 0x%lx, ObjectTypeName: %s, ObjectName: %s, SecurityDescriptor: 0x%lx, ClientToken: 0x%lx, DesiredAccess: %s [0x%lx], GrantedAccess: %s [0x%lx], Privileges: 0x%lx, ObjectCreation: %s, AccessGranted: %s)\n", pid, tid, proc, unicode_str_0, args[1], unicode_str_2, unicode_str_3, args[4], args[5], permissions_6, args[6], permissions_7, args[7], args[8], bool_9, bool_10);
	free(unicode_str_0);
	free(unicode_str_2);
	free(unicode_str_3);
	free(permissions_6);
	free(permissions_7);	return args;
}

void gt_windows_print_sysret_ntopenobjectauditalarm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(GenerateOnClose: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[11]);
	free(args);
}

void *gt_windows_print_syscall_ntopenprivatenamespace(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenPrivateNamespace(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, BoundaryDescriptor: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenprivatenamespace(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NamespaceHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenProcess(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, ClientId: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ProcessHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenprocesstokenex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenProcessTokenEx(ProcessHandle: 0x%lx, DesiredAccess: %s [0x%lx], HandleAttributes: 0x%lx)\n", pid, tid, proc, args[0], permissions_1, args[1], args[2]);
	free(permissions_1);	return args;
}

void gt_windows_print_sysret_ntopenprocesstokenex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_3 = 0;
	vmi_read_64_va(vmi, args[3], pid, &phandle_3);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TokenHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_3);
	free(args);
}

void *gt_windows_print_syscall_ntopenprocesstoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenProcessToken(ProcessHandle: 0x%lx, DesiredAccess: %s [0x%lx])\n", pid, tid, proc, args[0], permissions_1, args[1]);
	free(permissions_1);	return args;
}

void gt_windows_print_sysret_ntopenprocesstoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_2 = 0;
	vmi_read_64_va(vmi, args[2], pid, &phandle_2);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TokenHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_2);
	free(args);
}

void *gt_windows_print_syscall_ntopenresourcemanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_4 = NULL;
	uint64_t root_dir_4 = 0;
	uint64_t attributes_4 = 0;
	struct win64_obj_attr *obj_attr_4 = obj_attr_from_va(vmi, args[4], pid);
	if (NULL != obj_attr_4) {
		unicode_str_4 = unicode_str_from_va(vmi, obj_attr_4->object_name, pid);
		root_dir_4 = obj_attr_4->root_directory;
		attributes_4 = obj_attr_4->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenResourceManager(DesiredAccess: %s [0x%lx], TmHandle: 0x%lx, ResourceManagerGuid: 0x%lx, ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], args[2], args[3], root_dir_4, unicode_str_4, attributes_4);
	free(permissions_1);
	free(unicode_str_4);
	free(obj_attr_4);	return args;
}

void gt_windows_print_sysret_ntopenresourcemanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ResourceManagerHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopensection(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenSection(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopensection(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(SectionHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopensemaphore(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenSemaphore(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopensemaphore(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(SemaphoreHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopensession(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenSession(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopensession(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(SessionHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopensymboliclinkobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenSymbolicLinkObject(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopensymboliclinkobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(LinkHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenThread(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, ClientId: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ThreadHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenthreadtokenex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	char *bool_2 = args[2] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenThreadTokenEx(ThreadHandle: 0x%lx, DesiredAccess: %s [0x%lx], OpenAsSelf: %s, HandleAttributes: 0x%lx)\n", pid, tid, proc, args[0], permissions_1, args[1], bool_2, args[3]);
	free(permissions_1);	return args;
}

void gt_windows_print_sysret_ntopenthreadtokenex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &phandle_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TokenHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_4);
	free(args);
}

void *gt_windows_print_syscall_ntopenthreadtoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	char *bool_2 = args[2] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenThreadToken(ThreadHandle: 0x%lx, DesiredAccess: %s [0x%lx], OpenAsSelf: %s)\n", pid, tid, proc, args[0], permissions_1, args[1], bool_2);
	free(permissions_1);	return args;
}

void gt_windows_print_sysret_ntopenthreadtoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_3 = 0;
	vmi_read_64_va(vmi, args[3], pid, &phandle_3);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TokenHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_3);
	free(args);
}

void *gt_windows_print_syscall_ntopentimer(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenTimer(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopentimer(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TimerHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopentransactionmanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	uint8_t *unicode_str_3 = unicode_str_from_va(vmi, args[3], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenTransactionManager(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, LogFileName: %s, TmIdentity: 0x%lx, OpenOptions: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, unicode_str_3, args[4], args[5]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);
	free(unicode_str_3);	return args;
}

void gt_windows_print_sysret_ntopentransactionmanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TmHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopentransaction(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenTransaction(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Uow: 0x%lx, TmHandle: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[4]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopentransaction(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TransactionHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntplugplaycontrol(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPlugPlayControl(PnPControlClass: 0x%lx, PnPControlDataLength: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntplugplaycontrol(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntpowerinformation(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPowerInformation(InformationLevel: 0x%lx, InputBufferLength: 0x%lx, OutputBufferLength: 0x%lx)\n", pid, tid, proc, args[0], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntpowerinformation(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntpreparecomplete(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPrepareComplete(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntpreparecomplete(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntprepareenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPrepareEnlistment(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntprepareenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntprepreparecomplete(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPrePrepareComplete(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntprepreparecomplete(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntpreprepareenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPrePrepareEnlistment(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntpreprepareenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntprivilegecheck(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPrivilegeCheck(ClientToken: 0x%lx, RequiredPrivileges: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntprivilegecheck(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(RequiredPrivileges: 0x%lx, Result: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1], args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntprivilegedserviceauditalarm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(vmi, args[1], pid);
	char *bool_4 = args[4] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPrivilegedServiceAuditAlarm(SubsystemName: %s, ServiceName: %s, ClientToken: 0x%lx, Privileges: 0x%lx, AccessGranted: %s)\n", pid, tid, proc, unicode_str_0, unicode_str_1, args[2], args[3], bool_4);
	free(unicode_str_0);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntprivilegedserviceauditalarm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntprivilegeobjectauditalarm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	char *permissions_3 = vf_get_simple_permissions(args[3]);
	char *bool_5 = args[5] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPrivilegeObjectAuditAlarm(SubsystemName: %s, HandleId: 0x%lx, ClientToken: 0x%lx, DesiredAccess: %s [0x%lx], Privileges: 0x%lx, AccessGranted: %s)\n", pid, tid, proc, unicode_str_0, args[1], args[2], permissions_3, args[3], args[4], bool_5);
	free(unicode_str_0);
	free(permissions_3);	return args;
}

void gt_windows_print_sysret_ntprivilegeobjectauditalarm(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntpropagationcomplete(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPropagationComplete(ResourceManagerHandle: 0x%lx, RequestCookie: 0x%lx, BufferLength: 0x%lx, Buffer: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3]);
	return args;
}

void gt_windows_print_sysret_ntpropagationcomplete(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntpropagationfailed(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPropagationFailed(ResourceManagerHandle: 0x%lx, RequestCookie: 0x%lx, PropStatus: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntpropagationfailed(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntprotectvirtualmemory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtProtectVirtualMemory(ProcessHandle: 0x%lx, *BaseAddress: 0x%lx, RegionSize: 0x%lx, NewProtectWin32: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3]);
	return args;
}

void gt_windows_print_sysret_ntprotectvirtualmemory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*BaseAddress: 0x%lx, RegionSize: 0x%lx, OldProtect: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1], args[2], pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntpulseevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPulseEvent(EventHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntpulseevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousState: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntqueryattributesfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(vmi, args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(vmi, obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryAttributesFile(ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0);
	free(unicode_str_0);
	free(obj_attr_0);	return args;
}

void gt_windows_print_sysret_ntqueryattributesfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(FileInformation: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntquerybootentryorder(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryBootEntryOrder(Count: 0x%lx)\n", pid, tid, proc, pulong_1);
	return args;
}

void gt_windows_print_sysret_ntquerybootentryorder(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Count: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntquerybootoptions(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryBootOptions(BootOptionsLength: 0x%lx)\n", pid, tid, proc, pulong_1);
	return args;
}

void gt_windows_print_sysret_ntquerybootoptions(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(BootOptionsLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntquerydebugfilterstate(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryDebugFilterState(ComponentId: 0x%lx, Level: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntquerydebugfilterstate(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntquerydefaultlocale(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_0 = args[0] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryDefaultLocale(UserProfile: %s)\n", pid, tid, proc, bool_0);
	return args;
}

void gt_windows_print_sysret_ntquerydefaultlocale(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(DefaultLocaleId: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntquerydefaultuilanguage(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryDefaultUILanguage()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntquerydefaultuilanguage(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*DefaultUILanguageId: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[0]);
	free(args);
}

void *gt_windows_print_syscall_ntquerydirectoryfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_8 = args[8] ? "TRUE" : "FALSE";
	uint8_t *unicode_str_9 = unicode_str_from_va(vmi, args[9], pid);
	char *bool_10 = args[10] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryDirectoryFile(FileHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, Length: 0x%lx, FileInformationClass: 0x%lx, ReturnSingleEntry: %s, FileName: %s, RestartScan: %s)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[6], args[7], bool_8, unicode_str_9, bool_10);
	free(unicode_str_9);	return args;
}

void gt_windows_print_sysret_ntquerydirectoryfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntquerydirectoryobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_3 = args[3] ? "TRUE" : "FALSE";
	char *bool_4 = args[4] ? "TRUE" : "FALSE";
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryDirectoryObject(DirectoryHandle: 0x%lx, Length: 0x%lx, ReturnSingleEntry: %s, RestartScan: %s, Context: 0x%lx)\n", pid, tid, proc, args[0], args[2], bool_3, bool_4, pulong_5);
	return args;
}

void gt_windows_print_sysret_ntquerydirectoryobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	uint64_t pulong_6 = 0;
	vmi_read_64_va(vmi, args[6], pid, &pulong_6);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Context: 0x%lx, ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_5, pulong_6);
	free(args);
}

void *gt_windows_print_syscall_ntquerydriverentryorder(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryDriverEntryOrder(Count: 0x%lx)\n", pid, tid, proc, pulong_1);
	return args;
}

void gt_windows_print_sysret_ntquerydriverentryorder(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Count: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntqueryeafile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_4 = args[4] ? "TRUE" : "FALSE";
	uint64_t pulong_7 = 0;
	vmi_read_64_va(vmi, args[7], pid, &pulong_7);
	char *bool_8 = args[8] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryEaFile(FileHandle: 0x%lx, Length: 0x%lx, ReturnSingleEntry: %s, EaListLength: 0x%lx, EaIndex: 0x%lx, RestartScan: %s)\n", pid, tid, proc, args[0], args[3], bool_4, args[6], pulong_7, bool_8);
	return args;
}

void gt_windows_print_sysret_ntqueryeafile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntqueryevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryEvent(EventHandle: 0x%lx, EventInformationClass: 0x%lx, EventInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryfullattributesfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(vmi, args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(vmi, obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryFullAttributesFile(ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0);
	free(unicode_str_0);
	free(obj_attr_0);	return args;
}

void gt_windows_print_sysret_ntqueryfullattributesfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(FileInformation: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationatom(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationAtom(Atom: 0x%lx, InformationClass: 0x%lx, AtomInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationatom(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationEnlistment(EnlistmentHandle: 0x%lx, EnlistmentInformationClass: 0x%lx, EnlistmentInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationFile(FileHandle: 0x%lx, Length: 0x%lx, FileInformationClass: 0x%lx)\n", pid, tid, proc, args[0], args[3], args[4]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationjobobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationJobObject(JobHandle: 0x%lx, JobObjectInformationClass: 0x%lx, JobObjectInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationjobobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationPort(PortHandle: 0x%lx, PortInformationClass: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationProcess(ProcessHandle: 0x%lx, ProcessInformationClass: 0x%lx, ProcessInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationresourcemanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationResourceManager(ResourceManagerHandle: 0x%lx, ResourceManagerInformationClass: 0x%lx, ResourceManagerInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationresourcemanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationThread(ThreadHandle: 0x%lx, ThreadInformationClass: 0x%lx, ThreadInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationtoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationToken(TokenHandle: 0x%lx, TokenInformationClass: 0x%lx, TokenInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationtoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationtransaction(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationTransaction(TransactionHandle: 0x%lx, TransactionInformationClass: 0x%lx, TransactionInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationtransaction(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationtransactionmanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationTransactionManager(TransactionManagerHandle: 0x%lx, TransactionManagerInformationClass: 0x%lx, TransactionManagerInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationtransactionmanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationworkerfactory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationWorkerFactory(WorkerFactoryHandle: 0x%lx, WorkerFactoryInformationClass: 0x%lx, WorkerFactoryInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationworkerfactory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinstalluilanguage(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInstallUILanguage()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntqueryinstalluilanguage(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*InstallUILanguageId: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[0]);
	free(args);
}

void *gt_windows_print_syscall_ntqueryintervalprofile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryIntervalProfile(ProfileSource: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntqueryintervalprofile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Interval: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntqueryiocompletion(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryIoCompletion(IoCompletionHandle: 0x%lx, IoCompletionInformationClass: 0x%lx, IoCompletionInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryiocompletion(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntquerykey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryKey(KeyHandle: 0x%lx, KeyInformationClass: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntquerykey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ResultLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntquerylicensevalue(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryLicenseValue(Name: %s, Length: 0x%lx)\n", pid, tid, proc, unicode_str_0, args[3]);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntquerylicensevalue(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Type: 0x%lx, ReturnedLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_1, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntquerymultiplevaluekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryMultipleValueKey(KeyHandle: 0x%lx, EntryCount: 0x%lx, BufferLength: 0x%lx)\n", pid, tid, proc, args[0], args[2], pulong_4);
	return args;
}

void gt_windows_print_sysret_ntquerymultiplevaluekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(BufferLength: 0x%lx, RequiredBufferLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4, pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntquerymutant(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryMutant(MutantHandle: 0x%lx, MutantInformationClass: 0x%lx, MutantInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntquerymutant(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryObject(Handle: 0x%lx, ObjectInformationClass: 0x%lx, ObjectInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryopensubkeysex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(vmi, args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(vmi, obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryOpenSubKeysEx(TargetKey: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, BufferLength: 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0, args[1]);
	free(unicode_str_0);
	free(obj_attr_0);	return args;
}

void gt_windows_print_sysret_ntqueryopensubkeysex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_3 = 0;
	vmi_read_64_va(vmi, args[3], pid, &pulong_3);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(RequiredSize: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_3);
	free(args);
}

void *gt_windows_print_syscall_ntqueryopensubkeys(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(vmi, args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(vmi, obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryOpenSubKeys(TargetKey: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0);
	free(unicode_str_0);
	free(obj_attr_0);	return args;
}

void gt_windows_print_sysret_ntqueryopensubkeys(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(HandleCount: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntqueryperformancecounter(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryPerformanceCounter()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntqueryperformancecounter(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PerformanceCounter: 0x%lx, PerformanceFrequency: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[0], args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntqueryportinformationprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryPortInformationProcess()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntqueryportinformationprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntqueryquotainformationfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_4 = args[4] ? "TRUE" : "FALSE";
	uint64_t pulong_7 = 0;
	vmi_read_64_va(vmi, args[7], pid, &pulong_7);
	char *bool_8 = args[8] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryQuotaInformationFile(FileHandle: 0x%lx, Length: 0x%lx, ReturnSingleEntry: %s, SidListLength: 0x%lx, StartSid: 0x%lx, RestartScan: %s)\n", pid, tid, proc, args[0], args[3], bool_4, args[6], pulong_7, bool_8);
	return args;
}

void gt_windows_print_sysret_ntqueryquotainformationfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntquerysection(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySection(SectionHandle: 0x%lx, SectionInformationClass: 0x%lx, SectionInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntquerysection(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntquerysecurityattributestoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySecurityAttributesToken(TokenHandle: 0x%lx, NumberOfAttributes: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntquerysecurityattributestoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntquerysecurityobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySecurityObject(Handle: 0x%lx, SecurityInformation: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntquerysecurityobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(LengthNeeded: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntquerysemaphore(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySemaphore(SemaphoreHandle: 0x%lx, SemaphoreInformationClass: 0x%lx, SemaphoreInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntquerysemaphore(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntquerysymboliclinkobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(vmi, args[1], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySymbolicLinkObject(LinkHandle: 0x%lx, LinkTarget: %s)\n", pid, tid, proc, args[0], unicode_str_1);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntquerysymboliclinkobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(vmi, args[1], pid);
	uint64_t pulong_2 = 0;
	vmi_read_64_va(vmi, args[2], pid, &pulong_2);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(LinkTarget: %s, ReturnedLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, unicode_str_1, pulong_2);
	free(unicode_str_1);	free(args);
}

void *gt_windows_print_syscall_ntquerysystemenvironmentvalueex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	uint64_t pulong_3 = 0;
	vmi_read_64_va(vmi, args[3], pid, &pulong_3);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySystemEnvironmentValueEx(VariableName: %s, VendorGuid: 0x%lx, ValueLength: 0x%lx)\n", pid, tid, proc, unicode_str_0, args[1], pulong_3);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntquerysystemenvironmentvalueex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_3 = 0;
	vmi_read_64_va(vmi, args[3], pid, &pulong_3);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ValueLength: 0x%lx, Attributes: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_3, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntquerysystemenvironmentvalue(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySystemEnvironmentValue(VariableName: %s, ValueLength: 0x%lx)\n", pid, tid, proc, unicode_str_0, args[2]);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntquerysystemenvironmentvalue(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntquerysysteminformationex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySystemInformationEx(SystemInformationClass: 0x%lx, QueryInformationLength: 0x%lx, SystemInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntquerysysteminformationex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntquerysysteminformation(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySystemInformation(SystemInformationClass: 0x%lx, SystemInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntquerysysteminformation(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_3 = 0;
	vmi_read_64_va(vmi, args[3], pid, &pulong_3);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_3);
	free(args);
}

void *gt_windows_print_syscall_ntquerysystemtime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySystemTime()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntquerysystemtime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(SystemTime: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[0]);
	free(args);
}

void *gt_windows_print_syscall_ntquerytimer(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryTimer(TimerHandle: 0x%lx, TimerInformationClass: 0x%lx, TimerInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntquerytimer(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntquerytimerresolution(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryTimerResolution()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntquerytimerresolution(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &pulong_0);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	uint64_t pulong_2 = 0;
	vmi_read_64_va(vmi, args[2], pid, &pulong_2);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(MaximumTime: 0x%lx, MinimumTime: 0x%lx, CurrentTime: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_0, pulong_1, pulong_2);
	free(args);
}

void *gt_windows_print_syscall_ntqueryvaluekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(vmi, args[1], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryValueKey(KeyHandle: 0x%lx, ValueName: %s, KeyValueInformationClass: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], unicode_str_1, args[2], args[4]);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntqueryvaluekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ResultLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntqueryvirtualmemory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryVirtualMemory(ProcessHandle: 0x%lx, BaseAddress: 0x%lx, MemoryInformationClass: 0x%lx, MemoryInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntqueryvirtualmemory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[5]);
	free(args);
}

void *gt_windows_print_syscall_ntqueryvolumeinformationfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryVolumeInformationFile(FileHandle: 0x%lx, Length: 0x%lx, FsInformationClass: 0x%lx)\n", pid, tid, proc, args[0], args[3], args[4]);
	return args;
}

void gt_windows_print_sysret_ntqueryvolumeinformationfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntqueueapcthreadex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueueApcThreadEx(ThreadHandle: 0x%lx, UserApcReserveHandle: 0x%lx, ApcRoutine: 0x%lx, ApcArgument1: 0x%lx, ApcArgument2: 0x%lx, ApcArgument3: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4], args[5]);
	return args;
}

void gt_windows_print_sysret_ntqueueapcthreadex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntqueueapcthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueueApcThread(ThreadHandle: 0x%lx, ApcRoutine: 0x%lx, ApcArgument1: 0x%lx, ApcArgument2: 0x%lx, ApcArgument3: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4]);
	return args;
}

void gt_windows_print_sysret_ntqueueapcthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntraiseexception(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRaiseException()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntraiseexception(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	char *bool_2 = args[2] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ExceptionRecord: 0x%lx, ContextRecord: 0x%lx, FirstChance: %s)\n", pid, tid, proc, event->x86_regs->rax, args[0], args[1], bool_2);
	free(args);
}

void *gt_windows_print_syscall_ntraiseharderror(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRaiseHardError(ErrorStatus: 0x%lx, NumberOfParameters: 0x%lx, UnicodeStringParameterMask: 0x%lx, ValidResponseOptions: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntraiseharderror(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Response: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntreadfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(vmi, args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReadFile(FileHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, Length: 0x%lx, ByteOffset: 0x%lx, Key: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[6], args[7], pulong_8);
	return args;
}

void gt_windows_print_sysret_ntreadfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntreadfilescatter(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(vmi, args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReadFileScatter(FileHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, SegmentArray: 0x%lx, Length: 0x%lx, ByteOffset: 0x%lx, Key: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[5], args[6], args[7], pulong_8);
	return args;
}

void gt_windows_print_sysret_ntreadfilescatter(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntreadonlyenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReadOnlyEnlistment(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntreadonlyenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntreadrequestdata(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReadRequestData(PortHandle: 0x%lx, Message: 0x%lx, DataEntryIndex: 0x%lx, BufferSize: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntreadrequestdata(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NumberOfBytesRead: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[5]);
	free(args);
}

void *gt_windows_print_syscall_ntreadvirtualmemory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReadVirtualMemory(ProcessHandle: 0x%lx, BaseAddress: 0x%lx, BufferSize: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntreadvirtualmemory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NumberOfBytesRead: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntrecoverenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRecoverEnlistment(EnlistmentHandle: 0x%lx, EnlistmentKey: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntrecoverenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntrecoverresourcemanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRecoverResourceManager(ResourceManagerHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntrecoverresourcemanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntrecovertransactionmanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRecoverTransactionManager(TransactionManagerHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntrecovertransactionmanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntregisterprotocoladdressinformation(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRegisterProtocolAddressInformation(ResourceManager: 0x%lx, ProtocolId: 0x%lx, ProtocolInformationSize: 0x%lx, ProtocolInformation: 0x%lx, CreateOptions: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4]);
	return args;
}

void gt_windows_print_sysret_ntregisterprotocoladdressinformation(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntregisterthreadterminateport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRegisterThreadTerminatePort(PortHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntregisterthreadterminateport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntreleasekeyedevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_2 = args[2] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReleaseKeyedEvent(KeyedEventHandle: 0x%lx, KeyValue: 0x%lx, Alertable: %s, Timeout: 0x%lx)\n", pid, tid, proc, args[0], args[1], bool_2, args[3]);
	return args;
}

void gt_windows_print_sysret_ntreleasekeyedevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntreleasemutant(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReleaseMutant(MutantHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntreleasemutant(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousCount: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntreleasesemaphore(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReleaseSemaphore(SemaphoreHandle: 0x%lx, ReleaseCount: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntreleasesemaphore(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousCount: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntreleaseworkerfactoryworker(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReleaseWorkerFactoryWorker(WorkerFactoryHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntreleaseworkerfactoryworker(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntremoveiocompletionex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_5 = args[5] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRemoveIoCompletionEx(IoCompletionHandle: 0x%lx, Count: 0x%lx, Timeout: 0x%lx, Alertable: %s)\n", pid, tid, proc, args[0], args[2], args[4], bool_5);
	return args;
}

void gt_windows_print_sysret_ntremoveiocompletionex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_3 = 0;
	vmi_read_64_va(vmi, args[3], pid, &pulong_3);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NumEntriesRemoved: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_3);
	free(args);
}

void *gt_windows_print_syscall_ntremoveiocompletion(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRemoveIoCompletion(IoCompletionHandle: 0x%lx, Timeout: 0x%lx)\n", pid, tid, proc, args[0], args[4]);
	return args;
}

void gt_windows_print_sysret_ntremoveiocompletion(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*KeyContext: 0x%lx, *ApcContext: 0x%lx, IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1], args[2], args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntremoveprocessdebug(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRemoveProcessDebug()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntremoveprocessdebug(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ProcessHandle: 0x%lx, DebugObjectHandle: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[0], args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntrenamekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(vmi, args[1], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRenameKey(KeyHandle: 0x%lx, NewName: %s)\n", pid, tid, proc, args[0], unicode_str_1);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntrenamekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntrenametransactionmanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRenameTransactionManager(LogFileName: %s, ExistingTransactionManagerGuid: 0x%lx)\n", pid, tid, proc, unicode_str_0, args[1]);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntrenametransactionmanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntreplacekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(vmi, args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(vmi, obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(vmi, args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(vmi, obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReplaceKey(NewFile: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, TargetHandle: 0x%lx, OldFile: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(unicode_str_0);
	free(obj_attr_0);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntreplacekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntreplacepartitionunit(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(vmi, args[1], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReplacePartitionUnit(TargetInstancePath: %s, SpareInstancePath: %s, Flags: 0x%lx)\n", pid, tid, proc, unicode_str_0, unicode_str_1, args[2]);
	free(unicode_str_0);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntreplacepartitionunit(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntreplyport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReplyPort(PortHandle: 0x%lx, ReplyMessage: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntreplyport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntreplywaitreceiveportex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReplyWaitReceivePortEx(PortHandle: 0x%lx, ReplyMessage: 0x%lx, Timeout: 0x%lx)\n", pid, tid, proc, args[0], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntreplywaitreceiveportex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*PortContext: 0x%lx, ReceiveMessage: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1], args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntreplywaitreceiveport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReplyWaitReceivePort(PortHandle: 0x%lx, ReplyMessage: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntreplywaitreceiveport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*PortContext: 0x%lx, ReceiveMessage: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1], args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntreplywaitreplyport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReplyWaitReplyPort(PortHandle: 0x%lx, ReplyMessage: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntreplywaitreplyport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReplyMessage: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntrequestport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRequestPort(PortHandle: 0x%lx, RequestMessage: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntrequestport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntrequestwaitreplyport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRequestWaitReplyPort(PortHandle: 0x%lx, RequestMessage: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntrequestwaitreplyport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReplyMessage: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntresetevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtResetEvent(EventHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntresetevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousState: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntresetwritewatch(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtResetWriteWatch(ProcessHandle: 0x%lx, BaseAddress: 0x%lx, RegionSize: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntresetwritewatch(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntrestorekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRestoreKey(KeyHandle: 0x%lx, FileHandle: 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntrestorekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntresumeprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtResumeProcess(ProcessHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntresumeprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntresumethread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtResumeThread(ThreadHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntresumethread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousSuspendCount: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntrollbackcomplete(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRollbackComplete(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntrollbackcomplete(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntrollbackenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRollbackEnlistment(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntrollbackenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntrollbacktransaction(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_1 = args[1] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRollbackTransaction(TransactionHandle: 0x%lx, Wait: %s)\n", pid, tid, proc, args[0], bool_1);
	return args;
}

void gt_windows_print_sysret_ntrollbacktransaction(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntrollforwardtransactionmanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRollforwardTransactionManager(TransactionManagerHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntrollforwardtransactionmanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsavekeyex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSaveKeyEx(KeyHandle: 0x%lx, FileHandle: 0x%lx, Format: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntsavekeyex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsavekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSaveKey(KeyHandle: 0x%lx, FileHandle: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntsavekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsavemergedkeys(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSaveMergedKeys(HighPrecedenceKeyHandle: 0x%lx, LowPrecedenceKeyHandle: 0x%lx, FileHandle: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntsavemergedkeys(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsecureconnectport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(vmi, args[1], pid);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(vmi, args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSecureConnectPort(PortName: %s, SecurityQos: 0x%lx, ClientView: 0x%lx, RequiredServerSid: 0x%lx, ServerView: 0x%lx, ConnectionInformation: 0x%lx, ConnectionInformationLength: 0x%lx)\n", pid, tid, proc, unicode_str_1, args[2], args[3], args[4], args[5], args[7], pulong_8);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntsecureconnectport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(vmi, args[0], pid, &phandle_0);
	uint64_t pulong_6 = 0;
	vmi_read_64_va(vmi, args[6], pid, &pulong_6);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(vmi, args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PortHandle: 0x%lx, ClientView: 0x%lx, ServerView: 0x%lx, MaxMessageLength: 0x%lx, ConnectionInformation: 0x%lx, ConnectionInformationLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, phandle_0, args[3], args[5], pulong_6, args[7], pulong_8);
	free(args);
}

void *gt_windows_print_syscall_ntserializeboot(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSerializeBoot()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntserializeboot(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetbootentryorder(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetBootEntryOrder(Count: 0x%lx)\n", pid, tid, proc, args[1]);
	return args;
}

void gt_windows_print_sysret_ntsetbootentryorder(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetbootoptions(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetBootOptions(BootOptions: 0x%lx, FieldsToChange: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntsetbootoptions(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetcontextthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetContextThread(ThreadHandle: 0x%lx, ThreadContext: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntsetcontextthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetdebugfilterstate(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_2 = args[2] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetDebugFilterState(ComponentId: 0x%lx, Level: 0x%lx, State: %s)\n", pid, tid, proc, args[0], args[1], bool_2);
	return args;
}

void gt_windows_print_sysret_ntsetdebugfilterstate(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetdefaultharderrorport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetDefaultHardErrorPort(DefaultHardErrorPort: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsetdefaultharderrorport(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetdefaultlocale(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_0 = args[0] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetDefaultLocale(UserProfile: %s, DefaultLocaleId: 0x%lx)\n", pid, tid, proc, bool_0, args[1]);
	return args;
}

void gt_windows_print_sysret_ntsetdefaultlocale(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetdefaultuilanguage(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetDefaultUILanguage(DefaultUILanguageId: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsetdefaultuilanguage(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetdriverentryorder(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetDriverEntryOrder(Count: 0x%lx)\n", pid, tid, proc, args[1]);
	return args;
}

void gt_windows_print_sysret_ntsetdriverentryorder(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntseteafile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetEaFile(FileHandle: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[3]);
	return args;
}

void gt_windows_print_sysret_ntseteafile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntseteventboostpriority(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetEventBoostPriority(EventHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntseteventboostpriority(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetEvent(EventHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsetevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousState: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntsethigheventpair(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetHighEventPair(EventPairHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsethigheventpair(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsethighwaitloweventpair(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetHighWaitLowEventPair(EventPairHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsethighwaitloweventpair(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationdebugobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationDebugObject()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntsetinformationdebugobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(vmi, args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(DebugObjectHandle: 0x%lx, DebugObjectInformationClass: 0x%lx, DebugInformation: 0x%lx, DebugInformationLength: 0x%lx, ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[0], args[1], args[2], args[3], pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationEnlistment(EnlistmentHandle: 0x%lx, EnlistmentInformationClass: 0x%lx, EnlistmentInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationenlistment(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationFile(FileHandle: 0x%lx, Length: 0x%lx, FileInformationClass: 0x%lx)\n", pid, tid, proc, args[0], args[3], args[4]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationjobobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationJobObject(JobHandle: 0x%lx, JobObjectInformationClass: 0x%lx, JobObjectInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationjobobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationkey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationKey(KeyHandle: 0x%lx, KeySetInformationClass: 0x%lx, KeySetInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationkey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationObject(Handle: 0x%lx, ObjectInformationClass: 0x%lx, ObjectInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationProcess(ProcessHandle: 0x%lx, ProcessInformationClass: 0x%lx, ProcessInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationresourcemanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationResourceManager(ResourceManagerHandle: 0x%lx, ResourceManagerInformationClass: 0x%lx, ResourceManagerInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationresourcemanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationThread(ThreadHandle: 0x%lx, ThreadInformationClass: 0x%lx, ThreadInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationtoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationToken(TokenHandle: 0x%lx, TokenInformationClass: 0x%lx, TokenInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationtoken(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationtransaction(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationTransaction(TransactionHandle: 0x%lx, TransactionInformationClass: 0x%lx, TransactionInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationtransaction(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationtransactionmanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationTransactionManager(TmHandle: 0x%lx, TransactionManagerInformationClass: 0x%lx, TransactionManagerInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationtransactionmanager(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationworkerfactory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationWorkerFactory(WorkerFactoryHandle: 0x%lx, WorkerFactoryInformationClass: 0x%lx, WorkerFactoryInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationworkerfactory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetintervalprofile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetIntervalProfile(Interval: 0x%lx, Source: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntsetintervalprofile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetiocompletionex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetIoCompletionEx(IoCompletionHandle: 0x%lx, IoCompletionReserveHandle: 0x%lx, KeyContext: 0x%lx, ApcContext: 0x%lx, IoStatus: 0x%lx, IoStatusInformation: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4], args[5]);
	return args;
}

void gt_windows_print_sysret_ntsetiocompletionex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetiocompletion(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetIoCompletion(IoCompletionHandle: 0x%lx, KeyContext: 0x%lx, ApcContext: 0x%lx, IoStatus: 0x%lx, IoStatusInformation: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4]);
	return args;
}

void gt_windows_print_sysret_ntsetiocompletion(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetldtentries(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetLdtEntries(Selector0: 0x%lx, Entry0Low: 0x%lx, Entry0Hi: 0x%lx, Selector1: 0x%lx, Entry1Low: 0x%lx, Entry1Hi: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4], args[5]);
	return args;
}

void gt_windows_print_sysret_ntsetldtentries(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetloweventpair(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetLowEventPair(EventPairHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsetloweventpair(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetlowwaithigheventpair(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetLowWaitHighEventPair(EventPairHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsetlowwaithigheventpair(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetquotainformationfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetQuotaInformationFile(FileHandle: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetquotainformationfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntsetsecurityobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetSecurityObject(Handle: 0x%lx, SecurityInformation: 0x%lx, SecurityDescriptor: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntsetsecurityobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetsystemenvironmentvalueex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetSystemEnvironmentValueEx(VariableName: %s, VendorGuid: 0x%lx, ValueLength: 0x%lx, Attributes: 0x%lx)\n", pid, tid, proc, unicode_str_0, args[1], args[3], args[4]);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntsetsystemenvironmentvalueex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetsystemenvironmentvalue(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(vmi, args[1], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetSystemEnvironmentValue(VariableName: %s, VariableValue: %s)\n", pid, tid, proc, unicode_str_0, unicode_str_1);
	free(unicode_str_0);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntsetsystemenvironmentvalue(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetsysteminformation(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetSystemInformation(SystemInformationClass: 0x%lx, SystemInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntsetsysteminformation(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetsystempowerstate(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetSystemPowerState(SystemAction: 0x%lx, MinSystemState: 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntsetsystempowerstate(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetsystemtime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetSystemTime(SystemTime: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsetsystemtime(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousTime: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntsetthreadexecutionstate(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetThreadExecutionState(esFlags: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsetthreadexecutionstate(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*PreviousFlags: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntsettimerex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetTimerEx(TimerHandle: 0x%lx, TimerSetInformationClass: 0x%lx, TimerSetInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsettimerex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsettimer(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_4 = args[4] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetTimer(TimerHandle: 0x%lx, DueTime: 0x%lx, TimerApcRoutine: 0x%lx, TimerContext: 0x%lx, WakeTimer: %s, Period: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], bool_4, args[5]);
	return args;
}

void gt_windows_print_sysret_ntsettimer(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousState: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[6]);
	free(args);
}

void *gt_windows_print_syscall_ntsettimerresolution(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_1 = args[1] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetTimerResolution(DesiredTime: 0x%lx, SetResolution: %s)\n", pid, tid, proc, args[0], bool_1);
	return args;
}

void gt_windows_print_sysret_ntsettimerresolution(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_2 = 0;
	vmi_read_64_va(vmi, args[2], pid, &pulong_2);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ActualTime: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_2);
	free(args);
}

void *gt_windows_print_syscall_ntsetuuidseed(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetUuidSeed(Seed: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsetuuidseed(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetvaluekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(vmi, args[1], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetValueKey(KeyHandle: 0x%lx, ValueName: %s, TitleIndex: 0x%lx, Type: 0x%lx, DataSize: 0x%lx)\n", pid, tid, proc, args[0], unicode_str_1, args[2], args[3], args[5]);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntsetvaluekey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsetvolumeinformationfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetVolumeInformationFile(FileHandle: 0x%lx, Length: 0x%lx, FsInformationClass: 0x%lx)\n", pid, tid, proc, args[0], args[3], args[4]);
	return args;
}

void gt_windows_print_sysret_ntsetvolumeinformationfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntshutdownsystem(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtShutdownSystem(Action: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntshutdownsystem(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntshutdownworkerfactory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtShutdownWorkerFactory(WorkerFactoryHandle: 0x%lx, *PendingWorkerCount: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntshutdownworkerfactory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*PendingWorkerCount: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntsignalandwaitforsingleobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_2 = args[2] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSignalAndWaitForSingleObject(SignalHandle: 0x%lx, WaitHandle: 0x%lx, Alertable: %s, Timeout: 0x%lx)\n", pid, tid, proc, args[0], args[1], bool_2, args[3]);
	return args;
}

void gt_windows_print_sysret_ntsignalandwaitforsingleobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsinglephasereject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSinglePhaseReject(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntsinglephasereject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntstartprofile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtStartProfile(ProfileHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntstartprofile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntstopprofile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtStopProfile(ProfileHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntstopprofile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsuspendprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSuspendProcess(ProcessHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsuspendprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntsuspendthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSuspendThread(ThreadHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsuspendthread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(vmi, args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousSuspendCount: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntsystemdebugcontrol(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSystemDebugControl(Command: 0x%lx, InputBufferLength: 0x%lx, OutputBufferLength: 0x%lx)\n", pid, tid, proc, args[0], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntsystemdebugcontrol(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntterminatejobobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtTerminateJobObject(JobHandle: 0x%lx, ExitStatus: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntterminatejobobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntterminateprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtTerminateProcess(ProcessHandle: 0x%lx, ExitStatus: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntterminateprocess(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntterminatethread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtTerminateThread(ThreadHandle: 0x%lx, ExitStatus: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntterminatethread(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_nttestalert(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtTestAlert()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_nttestalert(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntthawregistry(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtThawRegistry()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntthawregistry(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntthawtransactions(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtThawTransactions()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntthawtransactions(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_nttracecontrol(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtTraceControl(FunctionCode: 0x%lx, InBufferLen: 0x%lx, OutBufferLen: 0x%lx)\n", pid, tid, proc, args[0], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_nttracecontrol(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(vmi, args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_5);
	free(args);
}

void *gt_windows_print_syscall_nttraceevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtTraceEvent(TraceHandle: 0x%lx, Flags: 0x%lx, FieldSize: 0x%lx, Fields: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3]);
	return args;
}

void gt_windows_print_sysret_nttraceevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_nttranslatefilepath(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint64_t pulong_3 = 0;
	vmi_read_64_va(vmi, args[3], pid, &pulong_3);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtTranslateFilePath(InputFilePath: 0x%lx, OutputType: 0x%lx, OutputFilePathLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], pulong_3);
	return args;
}

void gt_windows_print_sysret_nttranslatefilepath(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	uint64_t pulong_3 = 0;
	vmi_read_64_va(vmi, args[3], pid, &pulong_3);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(OutputFilePathLength: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, pulong_3);
	free(args);
}

void *gt_windows_print_syscall_ntumsthreadyield(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtUmsThreadYield(SchedulerParam: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntumsthreadyield(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntunloaddriver(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(vmi, args[0], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtUnloadDriver(DriverServiceName: %s)\n", pid, tid, proc, unicode_str_0);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntunloaddriver(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntunloadkey2(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(vmi, args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(vmi, obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtUnloadKey2(TargetKey: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0, args[1]);
	free(unicode_str_0);
	free(obj_attr_0);	return args;
}

void gt_windows_print_sysret_ntunloadkey2(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntunloadkeyex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(vmi, args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(vmi, obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtUnloadKeyEx(TargetKey: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Event: 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0, args[1]);
	free(unicode_str_0);
	free(obj_attr_0);	return args;
}

void gt_windows_print_sysret_ntunloadkeyex(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntunloadkey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(vmi, args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(vmi, obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtUnloadKey(TargetKey: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0);
	free(unicode_str_0);
	free(obj_attr_0);	return args;
}

void gt_windows_print_sysret_ntunloadkey(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntunlockfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtUnlockFile(FileHandle: 0x%lx, ByteOffset: 0x%lx, Length: 0x%lx, Key: 0x%lx)\n", pid, tid, proc, args[0], args[2], args[3], args[4]);
	return args;
}

void gt_windows_print_sysret_ntunlockfile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntunlockvirtualmemory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtUnlockVirtualMemory(ProcessHandle: 0x%lx, *BaseAddress: 0x%lx, RegionSize: 0x%lx, MapType: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3]);
	return args;
}

void gt_windows_print_sysret_ntunlockvirtualmemory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*BaseAddress: 0x%lx, RegionSize: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1], args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntunmapviewofsection(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtUnmapViewOfSection(ProcessHandle: 0x%lx, BaseAddress: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntunmapviewofsection(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntvdmcontrol(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtVdmControl(Service: 0x%lx, ServiceData: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntvdmcontrol(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ServiceData: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntwaitfordebugevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWaitForDebugEvent()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntwaitfordebugevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);
	char *bool_1 = args[1] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(DebugObjectHandle: 0x%lx, Alertable: %s, Timeout: 0x%lx, WaitStateChange: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[0], bool_1, args[2], args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntwaitforkeyedevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_2 = args[2] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWaitForKeyedEvent(KeyedEventHandle: 0x%lx, KeyValue: 0x%lx, Alertable: %s, Timeout: 0x%lx)\n", pid, tid, proc, args[0], args[1], bool_2, args[3]);
	return args;
}

void gt_windows_print_sysret_ntwaitforkeyedevent(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntwaitformultipleobjects32(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_3 = args[3] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWaitForMultipleObjects32(Count: 0x%lx, WaitType: 0x%lx, Alertable: %s, Timeout: 0x%lx)\n", pid, tid, proc, args[0], args[2], bool_3, args[4]);
	return args;
}

void gt_windows_print_sysret_ntwaitformultipleobjects32(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntwaitformultipleobjects(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_3 = args[3] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWaitForMultipleObjects(Count: 0x%lx, WaitType: 0x%lx, Alertable: %s, Timeout: 0x%lx)\n", pid, tid, proc, args[0], args[2], bool_3, args[4]);
	return args;
}

void gt_windows_print_sysret_ntwaitformultipleobjects(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntwaitforsingleobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	char *bool_1 = args[1] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWaitForSingleObject(Handle: 0x%lx, Alertable: %s, Timeout: 0x%lx)\n", pid, tid, proc, args[0], bool_1, args[2]);
	return args;
}

void gt_windows_print_sysret_ntwaitforsingleobject(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntwaitforworkviaworkerfactory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWaitForWorkViaWorkerFactory(WorkerFactoryHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntwaitforworkviaworkerfactory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(MiniPacket: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntwaithigheventpair(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWaitHighEventPair(EventPairHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntwaithigheventpair(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntwaitloweventpair(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWaitLowEventPair(EventPairHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntwaitloweventpair(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntworkerfactoryworkerready(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWorkerFactoryWorkerReady(WorkerFactoryHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntworkerfactoryworkerready(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

void *gt_windows_print_syscall_ntwritefilegather(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(vmi, args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWriteFileGather(FileHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, SegmentArray: 0x%lx, Length: 0x%lx, ByteOffset: 0x%lx, Key: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[5], args[6], args[7], pulong_8);
	return args;
}

void gt_windows_print_sysret_ntwritefilegather(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntwritefile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(vmi, args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWriteFile(FileHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, Length: 0x%lx, ByteOffset: 0x%lx, Key: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[6], args[7], pulong_8);
	return args;
}

void gt_windows_print_sysret_ntwritefile(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntwriterequestdata(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWriteRequestData(PortHandle: 0x%lx, Message: 0x%lx, DataEntryIndex: 0x%lx, BufferSize: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntwriterequestdata(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NumberOfBytesWritten: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[5]);
	free(args);
}

void *gt_windows_print_syscall_ntwritevirtualmemory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWriteVirtualMemory(ProcessHandle: 0x%lx, BaseAddress: 0x%lx, BufferSize: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntwritevirtualmemory(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NumberOfBytesWritten: 0x%lx)\n", pid, tid, proc, event->x86_regs->rax, args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntyieldexecution(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid)
{
	char *proc = get_process_name(vmi, pid);
	uint64_t *args = vf_get_args(vmi, event, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtYieldExecution()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntyieldexecution(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = get_process_name(vmi, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, event->x86_regs->rax);
	free(args);
}

const GTSyscallCallback SYSCALLS[] = {
	{ "NtAcceptConnectPort", gt_windows_print_syscall_ntacceptconnectport, gt_windows_print_sysret_ntacceptconnectport },
	{ "NtAccessCheckAndAuditAlarm", gt_windows_print_syscall_ntaccesscheckandauditalarm, gt_windows_print_sysret_ntaccesscheckandauditalarm },
	{ "NtAccessCheckByTypeAndAuditAlarm", gt_windows_print_syscall_ntaccesscheckbytypeandauditalarm, gt_windows_print_sysret_ntaccesscheckbytypeandauditalarm },
	{ "NtAccessCheckByType", gt_windows_print_syscall_ntaccesscheckbytype, gt_windows_print_sysret_ntaccesscheckbytype },
	{ "NtAccessCheckByTypeResultListAndAuditAlarmByHandle", gt_windows_print_syscall_ntaccesscheckbytyperesultlistandauditalarmbyhandle, gt_windows_print_sysret_ntaccesscheckbytyperesultlistandauditalarmbyhandle },
	{ "NtAccessCheckByTypeResultListAndAuditAlarm", gt_windows_print_syscall_ntaccesscheckbytyperesultlistandauditalarm, gt_windows_print_sysret_ntaccesscheckbytyperesultlistandauditalarm },
	{ "NtAccessCheckByTypeResultList", gt_windows_print_syscall_ntaccesscheckbytyperesultlist, gt_windows_print_sysret_ntaccesscheckbytyperesultlist },
	{ "NtAccessCheck", gt_windows_print_syscall_ntaccesscheck, gt_windows_print_sysret_ntaccesscheck },
	{ "NtAddAtom", gt_windows_print_syscall_ntaddatom, gt_windows_print_sysret_ntaddatom },
	{ "NtAddBootEntry", gt_windows_print_syscall_ntaddbootentry, gt_windows_print_sysret_ntaddbootentry },
	{ "NtAddDriverEntry", gt_windows_print_syscall_ntadddriverentry, gt_windows_print_sysret_ntadddriverentry },
	{ "NtAdjustGroupsToken", gt_windows_print_syscall_ntadjustgroupstoken, gt_windows_print_sysret_ntadjustgroupstoken },
	{ "NtAdjustPrivilegesToken", gt_windows_print_syscall_ntadjustprivilegestoken, gt_windows_print_sysret_ntadjustprivilegestoken },
	{ "NtAlertResumeThread", gt_windows_print_syscall_ntalertresumethread, gt_windows_print_sysret_ntalertresumethread },
	{ "NtAlertThread", gt_windows_print_syscall_ntalertthread, gt_windows_print_sysret_ntalertthread },
	{ "NtAllocateLocallyUniqueId", gt_windows_print_syscall_ntallocatelocallyuniqueid, gt_windows_print_sysret_ntallocatelocallyuniqueid },
	{ "NtAllocateReserveObject", gt_windows_print_syscall_ntallocatereserveobject, gt_windows_print_sysret_ntallocatereserveobject },
	{ "NtAllocateUserPhysicalPages", gt_windows_print_syscall_ntallocateuserphysicalpages, gt_windows_print_sysret_ntallocateuserphysicalpages },
	{ "NtAllocateUuids", gt_windows_print_syscall_ntallocateuuids, gt_windows_print_sysret_ntallocateuuids },
	{ "NtAllocateVirtualMemory", gt_windows_print_syscall_ntallocatevirtualmemory, gt_windows_print_sysret_ntallocatevirtualmemory },
	{ "NtAlpcAcceptConnectPort", gt_windows_print_syscall_ntalpcacceptconnectport, gt_windows_print_sysret_ntalpcacceptconnectport },
	{ "NtAlpcCancelMessage", gt_windows_print_syscall_ntalpccancelmessage, gt_windows_print_sysret_ntalpccancelmessage },
	{ "NtAlpcConnectPort", gt_windows_print_syscall_ntalpcconnectport, gt_windows_print_sysret_ntalpcconnectport },
	{ "NtAlpcCreatePort", gt_windows_print_syscall_ntalpccreateport, gt_windows_print_sysret_ntalpccreateport },
	{ "NtAlpcCreatePortSection", gt_windows_print_syscall_ntalpccreateportsection, gt_windows_print_sysret_ntalpccreateportsection },
	{ "NtAlpcCreateResourceReserve", gt_windows_print_syscall_ntalpccreateresourcereserve, gt_windows_print_sysret_ntalpccreateresourcereserve },
	{ "NtAlpcCreateSectionView", gt_windows_print_syscall_ntalpccreatesectionview, gt_windows_print_sysret_ntalpccreatesectionview },
	{ "NtAlpcCreateSecurityContext", gt_windows_print_syscall_ntalpccreatesecuritycontext, gt_windows_print_sysret_ntalpccreatesecuritycontext },
	{ "NtAlpcDeletePortSection", gt_windows_print_syscall_ntalpcdeleteportsection, gt_windows_print_sysret_ntalpcdeleteportsection },
	{ "NtAlpcDeleteResourceReserve", gt_windows_print_syscall_ntalpcdeleteresourcereserve, gt_windows_print_sysret_ntalpcdeleteresourcereserve },
	{ "NtAlpcDeleteSectionView", gt_windows_print_syscall_ntalpcdeletesectionview, gt_windows_print_sysret_ntalpcdeletesectionview },
	{ "NtAlpcDeleteSecurityContext", gt_windows_print_syscall_ntalpcdeletesecuritycontext, gt_windows_print_sysret_ntalpcdeletesecuritycontext },
	{ "NtAlpcDisconnectPort", gt_windows_print_syscall_ntalpcdisconnectport, gt_windows_print_sysret_ntalpcdisconnectport },
	{ "NtAlpcImpersonateClientOfPort", gt_windows_print_syscall_ntalpcimpersonateclientofport, gt_windows_print_sysret_ntalpcimpersonateclientofport },
	{ "NtAlpcOpenSenderProcess", gt_windows_print_syscall_ntalpcopensenderprocess, gt_windows_print_sysret_ntalpcopensenderprocess },
	{ "NtAlpcOpenSenderThread", gt_windows_print_syscall_ntalpcopensenderthread, gt_windows_print_sysret_ntalpcopensenderthread },
	{ "NtAlpcQueryInformation", gt_windows_print_syscall_ntalpcqueryinformation, gt_windows_print_sysret_ntalpcqueryinformation },
	{ "NtAlpcQueryInformationMessage", gt_windows_print_syscall_ntalpcqueryinformationmessage, gt_windows_print_sysret_ntalpcqueryinformationmessage },
	{ "NtAlpcRevokeSecurityContext", gt_windows_print_syscall_ntalpcrevokesecuritycontext, gt_windows_print_sysret_ntalpcrevokesecuritycontext },
	{ "NtAlpcSendWaitReceivePort", gt_windows_print_syscall_ntalpcsendwaitreceiveport, gt_windows_print_sysret_ntalpcsendwaitreceiveport },
	{ "NtAlpcSetInformation", gt_windows_print_syscall_ntalpcsetinformation, gt_windows_print_sysret_ntalpcsetinformation },
	{ "NtApphelpCacheControl", gt_windows_print_syscall_ntapphelpcachecontrol, gt_windows_print_sysret_ntapphelpcachecontrol },
	{ "NtAreMappedFilesTheSame", gt_windows_print_syscall_ntaremappedfilesthesame, gt_windows_print_sysret_ntaremappedfilesthesame },
	{ "NtAssignProcessToJobObject", gt_windows_print_syscall_ntassignprocesstojobobject, gt_windows_print_sysret_ntassignprocesstojobobject },
	{ "NtCallbackReturn", gt_windows_print_syscall_ntcallbackreturn, gt_windows_print_sysret_ntcallbackreturn },
	{ "NtCancelIoFileEx", gt_windows_print_syscall_ntcanceliofileex, gt_windows_print_sysret_ntcanceliofileex },
	{ "NtCancelIoFile", gt_windows_print_syscall_ntcanceliofile, gt_windows_print_sysret_ntcanceliofile },
	{ "NtCancelSynchronousIoFile", gt_windows_print_syscall_ntcancelsynchronousiofile, gt_windows_print_sysret_ntcancelsynchronousiofile },
	{ "NtCancelTimer", gt_windows_print_syscall_ntcanceltimer, gt_windows_print_sysret_ntcanceltimer },
	{ "NtClearEvent", gt_windows_print_syscall_ntclearevent, gt_windows_print_sysret_ntclearevent },
	{ "NtClose", gt_windows_print_syscall_ntclose, gt_windows_print_sysret_ntclose },
	{ "NtCloseObjectAuditAlarm", gt_windows_print_syscall_ntcloseobjectauditalarm, gt_windows_print_sysret_ntcloseobjectauditalarm },
	{ "NtCommitComplete", gt_windows_print_syscall_ntcommitcomplete, gt_windows_print_sysret_ntcommitcomplete },
	{ "NtCommitEnlistment", gt_windows_print_syscall_ntcommitenlistment, gt_windows_print_sysret_ntcommitenlistment },
	{ "NtCommitTransaction", gt_windows_print_syscall_ntcommittransaction, gt_windows_print_sysret_ntcommittransaction },
	{ "NtCompactKeys", gt_windows_print_syscall_ntcompactkeys, gt_windows_print_sysret_ntcompactkeys },
	{ "NtCompareTokens", gt_windows_print_syscall_ntcomparetokens, gt_windows_print_sysret_ntcomparetokens },
	{ "NtCompleteConnectPort", gt_windows_print_syscall_ntcompleteconnectport, gt_windows_print_sysret_ntcompleteconnectport },
	{ "NtCompressKey", gt_windows_print_syscall_ntcompresskey, gt_windows_print_sysret_ntcompresskey },
	{ "NtConnectPort", gt_windows_print_syscall_ntconnectport, gt_windows_print_sysret_ntconnectport },
	{ "NtContinue", gt_windows_print_syscall_ntcontinue, gt_windows_print_sysret_ntcontinue },
	{ "NtCreateDebugObject", gt_windows_print_syscall_ntcreatedebugobject, gt_windows_print_sysret_ntcreatedebugobject },
	{ "NtCreateDirectoryObject", gt_windows_print_syscall_ntcreatedirectoryobject, gt_windows_print_sysret_ntcreatedirectoryobject },
	{ "NtCreateEnlistment", gt_windows_print_syscall_ntcreateenlistment, gt_windows_print_sysret_ntcreateenlistment },
	{ "NtCreateEvent", gt_windows_print_syscall_ntcreateevent, gt_windows_print_sysret_ntcreateevent },
	{ "NtCreateEventPair", gt_windows_print_syscall_ntcreateeventpair, gt_windows_print_sysret_ntcreateeventpair },
	{ "NtCreateFile", gt_windows_print_syscall_ntcreatefile, gt_windows_print_sysret_ntcreatefile },
	{ "NtCreateIoCompletion", gt_windows_print_syscall_ntcreateiocompletion, gt_windows_print_sysret_ntcreateiocompletion },
	{ "NtCreateJobObject", gt_windows_print_syscall_ntcreatejobobject, gt_windows_print_sysret_ntcreatejobobject },
	{ "NtCreateJobSet", gt_windows_print_syscall_ntcreatejobset, gt_windows_print_sysret_ntcreatejobset },
	{ "NtCreateKeyedEvent", gt_windows_print_syscall_ntcreatekeyedevent, gt_windows_print_sysret_ntcreatekeyedevent },
	{ "NtCreateKey", gt_windows_print_syscall_ntcreatekey, gt_windows_print_sysret_ntcreatekey },
	{ "NtCreateKeyTransacted", gt_windows_print_syscall_ntcreatekeytransacted, gt_windows_print_sysret_ntcreatekeytransacted },
	{ "NtCreateMailslotFile", gt_windows_print_syscall_ntcreatemailslotfile, gt_windows_print_sysret_ntcreatemailslotfile },
	{ "NtCreateMutant", gt_windows_print_syscall_ntcreatemutant, gt_windows_print_sysret_ntcreatemutant },
	{ "NtCreateNamedPipeFile", gt_windows_print_syscall_ntcreatenamedpipefile, gt_windows_print_sysret_ntcreatenamedpipefile },
	{ "NtCreatePagingFile", gt_windows_print_syscall_ntcreatepagingfile, gt_windows_print_sysret_ntcreatepagingfile },
	{ "NtCreatePort", gt_windows_print_syscall_ntcreateport, gt_windows_print_sysret_ntcreateport },
	{ "NtCreatePrivateNamespace", gt_windows_print_syscall_ntcreateprivatenamespace, gt_windows_print_sysret_ntcreateprivatenamespace },
	{ "NtCreateProcessEx", gt_windows_print_syscall_ntcreateprocessex, gt_windows_print_sysret_ntcreateprocessex },
	{ "NtCreateProcess", gt_windows_print_syscall_ntcreateprocess, gt_windows_print_sysret_ntcreateprocess },
	{ "NtCreateProfileEx", gt_windows_print_syscall_ntcreateprofileex, gt_windows_print_sysret_ntcreateprofileex },
	{ "NtCreateProfile", gt_windows_print_syscall_ntcreateprofile, gt_windows_print_sysret_ntcreateprofile },
	{ "NtCreateResourceManager", gt_windows_print_syscall_ntcreateresourcemanager, gt_windows_print_sysret_ntcreateresourcemanager },
	{ "NtCreateSection", gt_windows_print_syscall_ntcreatesection, gt_windows_print_sysret_ntcreatesection },
	{ "NtCreateSemaphore", gt_windows_print_syscall_ntcreatesemaphore, gt_windows_print_sysret_ntcreatesemaphore },
	{ "NtCreateSymbolicLinkObject", gt_windows_print_syscall_ntcreatesymboliclinkobject, gt_windows_print_sysret_ntcreatesymboliclinkobject },
	{ "NtCreateThreadEx", gt_windows_print_syscall_ntcreatethreadex, gt_windows_print_sysret_ntcreatethreadex },
	{ "NtCreateThread", gt_windows_print_syscall_ntcreatethread, gt_windows_print_sysret_ntcreatethread },
	{ "NtCreateTimer", gt_windows_print_syscall_ntcreatetimer, gt_windows_print_sysret_ntcreatetimer },
	{ "NtCreateToken", gt_windows_print_syscall_ntcreatetoken, gt_windows_print_sysret_ntcreatetoken },
	{ "NtCreateTransactionManager", gt_windows_print_syscall_ntcreatetransactionmanager, gt_windows_print_sysret_ntcreatetransactionmanager },
	{ "NtCreateTransaction", gt_windows_print_syscall_ntcreatetransaction, gt_windows_print_sysret_ntcreatetransaction },
	{ "NtCreateUserProcess", gt_windows_print_syscall_ntcreateuserprocess, gt_windows_print_sysret_ntcreateuserprocess },
	{ "NtCreateWaitablePort", gt_windows_print_syscall_ntcreatewaitableport, gt_windows_print_sysret_ntcreatewaitableport },
	{ "NtCreateWorkerFactory", gt_windows_print_syscall_ntcreateworkerfactory, gt_windows_print_sysret_ntcreateworkerfactory },
	{ "NtDebugActiveProcess", gt_windows_print_syscall_ntdebugactiveprocess, gt_windows_print_sysret_ntdebugactiveprocess },
	{ "NtDebugContinue", gt_windows_print_syscall_ntdebugcontinue, gt_windows_print_sysret_ntdebugcontinue },
	{ "NtDelayExecution", gt_windows_print_syscall_ntdelayexecution, gt_windows_print_sysret_ntdelayexecution },
	{ "NtDeleteAtom", gt_windows_print_syscall_ntdeleteatom, gt_windows_print_sysret_ntdeleteatom },
	{ "NtDeleteBootEntry", gt_windows_print_syscall_ntdeletebootentry, gt_windows_print_sysret_ntdeletebootentry },
	{ "NtDeleteDriverEntry", gt_windows_print_syscall_ntdeletedriverentry, gt_windows_print_sysret_ntdeletedriverentry },
	{ "NtDeleteFile", gt_windows_print_syscall_ntdeletefile, gt_windows_print_sysret_ntdeletefile },
	{ "NtDeleteKey", gt_windows_print_syscall_ntdeletekey, gt_windows_print_sysret_ntdeletekey },
	{ "NtDeleteObjectAuditAlarm", gt_windows_print_syscall_ntdeleteobjectauditalarm, gt_windows_print_sysret_ntdeleteobjectauditalarm },
	{ "NtDeletePrivateNamespace", gt_windows_print_syscall_ntdeleteprivatenamespace, gt_windows_print_sysret_ntdeleteprivatenamespace },
	{ "NtDeleteValueKey", gt_windows_print_syscall_ntdeletevaluekey, gt_windows_print_sysret_ntdeletevaluekey },
	{ "NtDeviceIoControlFile", gt_windows_print_syscall_ntdeviceiocontrolfile, gt_windows_print_sysret_ntdeviceiocontrolfile },
	{ "NtDisableLastKnownGood", gt_windows_print_syscall_ntdisablelastknowngood, gt_windows_print_sysret_ntdisablelastknowngood },
	{ "NtDisplayString", gt_windows_print_syscall_ntdisplaystring, gt_windows_print_sysret_ntdisplaystring },
	{ "NtDrawText", gt_windows_print_syscall_ntdrawtext, gt_windows_print_sysret_ntdrawtext },
	{ "NtDuplicateObject", gt_windows_print_syscall_ntduplicateobject, gt_windows_print_sysret_ntduplicateobject },
	{ "NtDuplicateToken", gt_windows_print_syscall_ntduplicatetoken, gt_windows_print_sysret_ntduplicatetoken },
	{ "NtEnableLastKnownGood", gt_windows_print_syscall_ntenablelastknowngood, gt_windows_print_sysret_ntenablelastknowngood },
	{ "NtEnumerateBootEntries", gt_windows_print_syscall_ntenumeratebootentries, gt_windows_print_sysret_ntenumeratebootentries },
	{ "NtEnumerateDriverEntries", gt_windows_print_syscall_ntenumeratedriverentries, gt_windows_print_sysret_ntenumeratedriverentries },
	{ "NtEnumerateKey", gt_windows_print_syscall_ntenumeratekey, gt_windows_print_sysret_ntenumeratekey },
	{ "NtEnumerateSystemEnvironmentValuesEx", gt_windows_print_syscall_ntenumeratesystemenvironmentvaluesex, gt_windows_print_sysret_ntenumeratesystemenvironmentvaluesex },
	{ "NtEnumerateTransactionObject", gt_windows_print_syscall_ntenumeratetransactionobject, gt_windows_print_sysret_ntenumeratetransactionobject },
	{ "NtEnumerateValueKey", gt_windows_print_syscall_ntenumeratevaluekey, gt_windows_print_sysret_ntenumeratevaluekey },
	{ "NtExtendSection", gt_windows_print_syscall_ntextendsection, gt_windows_print_sysret_ntextendsection },
	{ "NtFilterToken", gt_windows_print_syscall_ntfiltertoken, gt_windows_print_sysret_ntfiltertoken },
	{ "NtFindAtom", gt_windows_print_syscall_ntfindatom, gt_windows_print_sysret_ntfindatom },
	{ "NtFlushBuffersFile", gt_windows_print_syscall_ntflushbuffersfile, gt_windows_print_sysret_ntflushbuffersfile },
	{ "NtFlushInstallUILanguage", gt_windows_print_syscall_ntflushinstalluilanguage, gt_windows_print_sysret_ntflushinstalluilanguage },
	{ "NtFlushInstructionCache", gt_windows_print_syscall_ntflushinstructioncache, gt_windows_print_sysret_ntflushinstructioncache },
	{ "NtFlushKey", gt_windows_print_syscall_ntflushkey, gt_windows_print_sysret_ntflushkey },
	{ "NtFlushProcessWriteBuffers", gt_windows_print_syscall_ntflushprocesswritebuffers, gt_windows_print_sysret_ntflushprocesswritebuffers },
	{ "NtFlushVirtualMemory", gt_windows_print_syscall_ntflushvirtualmemory, gt_windows_print_sysret_ntflushvirtualmemory },
	{ "NtFlushWriteBuffer", gt_windows_print_syscall_ntflushwritebuffer, gt_windows_print_sysret_ntflushwritebuffer },
	{ "NtFreeUserPhysicalPages", gt_windows_print_syscall_ntfreeuserphysicalpages, gt_windows_print_sysret_ntfreeuserphysicalpages },
	{ "NtFreeVirtualMemory", gt_windows_print_syscall_ntfreevirtualmemory, gt_windows_print_sysret_ntfreevirtualmemory },
	{ "NtFreezeRegistry", gt_windows_print_syscall_ntfreezeregistry, gt_windows_print_sysret_ntfreezeregistry },
	{ "NtFreezeTransactions", gt_windows_print_syscall_ntfreezetransactions, gt_windows_print_sysret_ntfreezetransactions },
	{ "NtFsControlFile", gt_windows_print_syscall_ntfscontrolfile, gt_windows_print_sysret_ntfscontrolfile },
	{ "NtGetContextThread", gt_windows_print_syscall_ntgetcontextthread, gt_windows_print_sysret_ntgetcontextthread },
	{ "NtGetCurrentProcessorNumber", gt_windows_print_syscall_ntgetcurrentprocessornumber, gt_windows_print_sysret_ntgetcurrentprocessornumber },
	{ "NtGetDevicePowerState", gt_windows_print_syscall_ntgetdevicepowerstate, gt_windows_print_sysret_ntgetdevicepowerstate },
	{ "NtGetMUIRegistryInfo", gt_windows_print_syscall_ntgetmuiregistryinfo, gt_windows_print_sysret_ntgetmuiregistryinfo },
	{ "NtGetNextProcess", gt_windows_print_syscall_ntgetnextprocess, gt_windows_print_sysret_ntgetnextprocess },
	{ "NtGetNextThread", gt_windows_print_syscall_ntgetnextthread, gt_windows_print_sysret_ntgetnextthread },
	{ "NtGetNlsSectionPtr", gt_windows_print_syscall_ntgetnlssectionptr, gt_windows_print_sysret_ntgetnlssectionptr },
	{ "NtGetNotificationResourceManager", gt_windows_print_syscall_ntgetnotificationresourcemanager, gt_windows_print_sysret_ntgetnotificationresourcemanager },
	{ "NtGetPlugPlayEvent", gt_windows_print_syscall_ntgetplugplayevent, gt_windows_print_sysret_ntgetplugplayevent },
	{ "NtGetWriteWatch", gt_windows_print_syscall_ntgetwritewatch, gt_windows_print_sysret_ntgetwritewatch },
	{ "NtImpersonateAnonymousToken", gt_windows_print_syscall_ntimpersonateanonymoustoken, gt_windows_print_sysret_ntimpersonateanonymoustoken },
	{ "NtImpersonateClientOfPort", gt_windows_print_syscall_ntimpersonateclientofport, gt_windows_print_sysret_ntimpersonateclientofport },
	{ "NtImpersonateThread", gt_windows_print_syscall_ntimpersonatethread, gt_windows_print_sysret_ntimpersonatethread },
	{ "NtInitializeNlsFiles", gt_windows_print_syscall_ntinitializenlsfiles, gt_windows_print_sysret_ntinitializenlsfiles },
	{ "NtInitializeRegistry", gt_windows_print_syscall_ntinitializeregistry, gt_windows_print_sysret_ntinitializeregistry },
	{ "NtInitiatePowerAction", gt_windows_print_syscall_ntinitiatepoweraction, gt_windows_print_sysret_ntinitiatepoweraction },
	{ "NtIsProcessInJob", gt_windows_print_syscall_ntisprocessinjob, gt_windows_print_sysret_ntisprocessinjob },
	{ "NtIsSystemResumeAutomatic", gt_windows_print_syscall_ntissystemresumeautomatic, gt_windows_print_sysret_ntissystemresumeautomatic },
	{ "NtIsUILanguageComitted", gt_windows_print_syscall_ntisuilanguagecomitted, gt_windows_print_sysret_ntisuilanguagecomitted },
	{ "NtListenPort", gt_windows_print_syscall_ntlistenport, gt_windows_print_sysret_ntlistenport },
	{ "NtLoadDriver", gt_windows_print_syscall_ntloaddriver, gt_windows_print_sysret_ntloaddriver },
	{ "NtLoadKey2", gt_windows_print_syscall_ntloadkey2, gt_windows_print_sysret_ntloadkey2 },
	{ "NtLoadKeyEx", gt_windows_print_syscall_ntloadkeyex, gt_windows_print_sysret_ntloadkeyex },
	{ "NtLoadKey", gt_windows_print_syscall_ntloadkey, gt_windows_print_sysret_ntloadkey },
	{ "NtLockFile", gt_windows_print_syscall_ntlockfile, gt_windows_print_sysret_ntlockfile },
	{ "NtLockProductActivationKeys", gt_windows_print_syscall_ntlockproductactivationkeys, gt_windows_print_sysret_ntlockproductactivationkeys },
	{ "NtLockRegistryKey", gt_windows_print_syscall_ntlockregistrykey, gt_windows_print_sysret_ntlockregistrykey },
	{ "NtLockVirtualMemory", gt_windows_print_syscall_ntlockvirtualmemory, gt_windows_print_sysret_ntlockvirtualmemory },
	{ "NtMakePermanentObject", gt_windows_print_syscall_ntmakepermanentobject, gt_windows_print_sysret_ntmakepermanentobject },
	{ "NtMakeTemporaryObject", gt_windows_print_syscall_ntmaketemporaryobject, gt_windows_print_sysret_ntmaketemporaryobject },
	{ "NtMapCMFModule", gt_windows_print_syscall_ntmapcmfmodule, gt_windows_print_sysret_ntmapcmfmodule },
	{ "NtMapUserPhysicalPages", gt_windows_print_syscall_ntmapuserphysicalpages, gt_windows_print_sysret_ntmapuserphysicalpages },
	{ "NtMapUserPhysicalPagesScatter", gt_windows_print_syscall_ntmapuserphysicalpagesscatter, gt_windows_print_sysret_ntmapuserphysicalpagesscatter },
	{ "NtMapViewOfSection", gt_windows_print_syscall_ntmapviewofsection, gt_windows_print_sysret_ntmapviewofsection },
	{ "NtModifyBootEntry", gt_windows_print_syscall_ntmodifybootentry, gt_windows_print_sysret_ntmodifybootentry },
	{ "NtModifyDriverEntry", gt_windows_print_syscall_ntmodifydriverentry, gt_windows_print_sysret_ntmodifydriverentry },
	{ "NtNotifyChangeDirectoryFile", gt_windows_print_syscall_ntnotifychangedirectoryfile, gt_windows_print_sysret_ntnotifychangedirectoryfile },
	{ "NtNotifyChangeKey", gt_windows_print_syscall_ntnotifychangekey, gt_windows_print_sysret_ntnotifychangekey },
	{ "NtNotifyChangeMultipleKeys", gt_windows_print_syscall_ntnotifychangemultiplekeys, gt_windows_print_sysret_ntnotifychangemultiplekeys },
	{ "NtNotifyChangeSession", gt_windows_print_syscall_ntnotifychangesession, gt_windows_print_sysret_ntnotifychangesession },
	{ "NtOpenDirectoryObject", gt_windows_print_syscall_ntopendirectoryobject, gt_windows_print_sysret_ntopendirectoryobject },
	{ "NtOpenEnlistment", gt_windows_print_syscall_ntopenenlistment, gt_windows_print_sysret_ntopenenlistment },
	{ "NtOpenEvent", gt_windows_print_syscall_ntopenevent, gt_windows_print_sysret_ntopenevent },
	{ "NtOpenEventPair", gt_windows_print_syscall_ntopeneventpair, gt_windows_print_sysret_ntopeneventpair },
	{ "NtOpenFile", gt_windows_print_syscall_ntopenfile, gt_windows_print_sysret_ntopenfile },
	{ "NtOpenIoCompletion", gt_windows_print_syscall_ntopeniocompletion, gt_windows_print_sysret_ntopeniocompletion },
	{ "NtOpenJobObject", gt_windows_print_syscall_ntopenjobobject, gt_windows_print_sysret_ntopenjobobject },
	{ "NtOpenKeyedEvent", gt_windows_print_syscall_ntopenkeyedevent, gt_windows_print_sysret_ntopenkeyedevent },
	{ "NtOpenKeyEx", gt_windows_print_syscall_ntopenkeyex, gt_windows_print_sysret_ntopenkeyex },
	{ "NtOpenKey", gt_windows_print_syscall_ntopenkey, gt_windows_print_sysret_ntopenkey },
	{ "NtOpenKeyTransactedEx", gt_windows_print_syscall_ntopenkeytransactedex, gt_windows_print_sysret_ntopenkeytransactedex },
	{ "NtOpenKeyTransacted", gt_windows_print_syscall_ntopenkeytransacted, gt_windows_print_sysret_ntopenkeytransacted },
	{ "NtOpenMutant", gt_windows_print_syscall_ntopenmutant, gt_windows_print_sysret_ntopenmutant },
	{ "NtOpenObjectAuditAlarm", gt_windows_print_syscall_ntopenobjectauditalarm, gt_windows_print_sysret_ntopenobjectauditalarm },
	{ "NtOpenPrivateNamespace", gt_windows_print_syscall_ntopenprivatenamespace, gt_windows_print_sysret_ntopenprivatenamespace },
	{ "NtOpenProcess", gt_windows_print_syscall_ntopenprocess, gt_windows_print_sysret_ntopenprocess },
	{ "NtOpenProcessTokenEx", gt_windows_print_syscall_ntopenprocesstokenex, gt_windows_print_sysret_ntopenprocesstokenex },
	{ "NtOpenProcessToken", gt_windows_print_syscall_ntopenprocesstoken, gt_windows_print_sysret_ntopenprocesstoken },
	{ "NtOpenResourceManager", gt_windows_print_syscall_ntopenresourcemanager, gt_windows_print_sysret_ntopenresourcemanager },
	{ "NtOpenSection", gt_windows_print_syscall_ntopensection, gt_windows_print_sysret_ntopensection },
	{ "NtOpenSemaphore", gt_windows_print_syscall_ntopensemaphore, gt_windows_print_sysret_ntopensemaphore },
	{ "NtOpenSession", gt_windows_print_syscall_ntopensession, gt_windows_print_sysret_ntopensession },
	{ "NtOpenSymbolicLinkObject", gt_windows_print_syscall_ntopensymboliclinkobject, gt_windows_print_sysret_ntopensymboliclinkobject },
	{ "NtOpenThread", gt_windows_print_syscall_ntopenthread, gt_windows_print_sysret_ntopenthread },
	{ "NtOpenThreadTokenEx", gt_windows_print_syscall_ntopenthreadtokenex, gt_windows_print_sysret_ntopenthreadtokenex },
	{ "NtOpenThreadToken", gt_windows_print_syscall_ntopenthreadtoken, gt_windows_print_sysret_ntopenthreadtoken },
	{ "NtOpenTimer", gt_windows_print_syscall_ntopentimer, gt_windows_print_sysret_ntopentimer },
	{ "NtOpenTransactionManager", gt_windows_print_syscall_ntopentransactionmanager, gt_windows_print_sysret_ntopentransactionmanager },
	{ "NtOpenTransaction", gt_windows_print_syscall_ntopentransaction, gt_windows_print_sysret_ntopentransaction },
	{ "NtPlugPlayControl", gt_windows_print_syscall_ntplugplaycontrol, gt_windows_print_sysret_ntplugplaycontrol },
	{ "NtPowerInformation", gt_windows_print_syscall_ntpowerinformation, gt_windows_print_sysret_ntpowerinformation },
	{ "NtPrepareComplete", gt_windows_print_syscall_ntpreparecomplete, gt_windows_print_sysret_ntpreparecomplete },
	{ "NtPrepareEnlistment", gt_windows_print_syscall_ntprepareenlistment, gt_windows_print_sysret_ntprepareenlistment },
	{ "NtPrePrepareComplete", gt_windows_print_syscall_ntprepreparecomplete, gt_windows_print_sysret_ntprepreparecomplete },
	{ "NtPrePrepareEnlistment", gt_windows_print_syscall_ntpreprepareenlistment, gt_windows_print_sysret_ntpreprepareenlistment },
	{ "NtPrivilegeCheck", gt_windows_print_syscall_ntprivilegecheck, gt_windows_print_sysret_ntprivilegecheck },
	{ "NtPrivilegedServiceAuditAlarm", gt_windows_print_syscall_ntprivilegedserviceauditalarm, gt_windows_print_sysret_ntprivilegedserviceauditalarm },
	{ "NtPrivilegeObjectAuditAlarm", gt_windows_print_syscall_ntprivilegeobjectauditalarm, gt_windows_print_sysret_ntprivilegeobjectauditalarm },
	{ "NtPropagationComplete", gt_windows_print_syscall_ntpropagationcomplete, gt_windows_print_sysret_ntpropagationcomplete },
	{ "NtPropagationFailed", gt_windows_print_syscall_ntpropagationfailed, gt_windows_print_sysret_ntpropagationfailed },
	{ "NtProtectVirtualMemory", gt_windows_print_syscall_ntprotectvirtualmemory, gt_windows_print_sysret_ntprotectvirtualmemory },
	{ "NtPulseEvent", gt_windows_print_syscall_ntpulseevent, gt_windows_print_sysret_ntpulseevent },
	{ "NtQueryAttributesFile", gt_windows_print_syscall_ntqueryattributesfile, gt_windows_print_sysret_ntqueryattributesfile },
	{ "NtQueryBootEntryOrder", gt_windows_print_syscall_ntquerybootentryorder, gt_windows_print_sysret_ntquerybootentryorder },
	{ "NtQueryBootOptions", gt_windows_print_syscall_ntquerybootoptions, gt_windows_print_sysret_ntquerybootoptions },
	{ "NtQueryDebugFilterState", gt_windows_print_syscall_ntquerydebugfilterstate, gt_windows_print_sysret_ntquerydebugfilterstate },
	{ "NtQueryDefaultLocale", gt_windows_print_syscall_ntquerydefaultlocale, gt_windows_print_sysret_ntquerydefaultlocale },
	{ "NtQueryDefaultUILanguage", gt_windows_print_syscall_ntquerydefaultuilanguage, gt_windows_print_sysret_ntquerydefaultuilanguage },
	{ "NtQueryDirectoryFile", gt_windows_print_syscall_ntquerydirectoryfile, gt_windows_print_sysret_ntquerydirectoryfile },
	{ "NtQueryDirectoryObject", gt_windows_print_syscall_ntquerydirectoryobject, gt_windows_print_sysret_ntquerydirectoryobject },
	{ "NtQueryDriverEntryOrder", gt_windows_print_syscall_ntquerydriverentryorder, gt_windows_print_sysret_ntquerydriverentryorder },
	{ "NtQueryEaFile", gt_windows_print_syscall_ntqueryeafile, gt_windows_print_sysret_ntqueryeafile },
	{ "NtQueryEvent", gt_windows_print_syscall_ntqueryevent, gt_windows_print_sysret_ntqueryevent },
	{ "NtQueryFullAttributesFile", gt_windows_print_syscall_ntqueryfullattributesfile, gt_windows_print_sysret_ntqueryfullattributesfile },
	{ "NtQueryInformationAtom", gt_windows_print_syscall_ntqueryinformationatom, gt_windows_print_sysret_ntqueryinformationatom },
	{ "NtQueryInformationEnlistment", gt_windows_print_syscall_ntqueryinformationenlistment, gt_windows_print_sysret_ntqueryinformationenlistment },
	{ "NtQueryInformationFile", gt_windows_print_syscall_ntqueryinformationfile, gt_windows_print_sysret_ntqueryinformationfile },
	{ "NtQueryInformationJobObject", gt_windows_print_syscall_ntqueryinformationjobobject, gt_windows_print_sysret_ntqueryinformationjobobject },
	{ "NtQueryInformationPort", gt_windows_print_syscall_ntqueryinformationport, gt_windows_print_sysret_ntqueryinformationport },
	{ "NtQueryInformationProcess", gt_windows_print_syscall_ntqueryinformationprocess, gt_windows_print_sysret_ntqueryinformationprocess },
	{ "NtQueryInformationResourceManager", gt_windows_print_syscall_ntqueryinformationresourcemanager, gt_windows_print_sysret_ntqueryinformationresourcemanager },
	{ "NtQueryInformationThread", gt_windows_print_syscall_ntqueryinformationthread, gt_windows_print_sysret_ntqueryinformationthread },
	{ "NtQueryInformationToken", gt_windows_print_syscall_ntqueryinformationtoken, gt_windows_print_sysret_ntqueryinformationtoken },
	{ "NtQueryInformationTransaction", gt_windows_print_syscall_ntqueryinformationtransaction, gt_windows_print_sysret_ntqueryinformationtransaction },
	{ "NtQueryInformationTransactionManager", gt_windows_print_syscall_ntqueryinformationtransactionmanager, gt_windows_print_sysret_ntqueryinformationtransactionmanager },
	{ "NtQueryInformationWorkerFactory", gt_windows_print_syscall_ntqueryinformationworkerfactory, gt_windows_print_sysret_ntqueryinformationworkerfactory },
	{ "NtQueryInstallUILanguage", gt_windows_print_syscall_ntqueryinstalluilanguage, gt_windows_print_sysret_ntqueryinstalluilanguage },
	{ "NtQueryIntervalProfile", gt_windows_print_syscall_ntqueryintervalprofile, gt_windows_print_sysret_ntqueryintervalprofile },
	{ "NtQueryIoCompletion", gt_windows_print_syscall_ntqueryiocompletion, gt_windows_print_sysret_ntqueryiocompletion },
	{ "NtQueryKey", gt_windows_print_syscall_ntquerykey, gt_windows_print_sysret_ntquerykey },
	{ "NtQueryLicenseValue", gt_windows_print_syscall_ntquerylicensevalue, gt_windows_print_sysret_ntquerylicensevalue },
	{ "NtQueryMultipleValueKey", gt_windows_print_syscall_ntquerymultiplevaluekey, gt_windows_print_sysret_ntquerymultiplevaluekey },
	{ "NtQueryMutant", gt_windows_print_syscall_ntquerymutant, gt_windows_print_sysret_ntquerymutant },
	{ "NtQueryObject", gt_windows_print_syscall_ntqueryobject, gt_windows_print_sysret_ntqueryobject },
	{ "NtQueryOpenSubKeysEx", gt_windows_print_syscall_ntqueryopensubkeysex, gt_windows_print_sysret_ntqueryopensubkeysex },
	{ "NtQueryOpenSubKeys", gt_windows_print_syscall_ntqueryopensubkeys, gt_windows_print_sysret_ntqueryopensubkeys },
	{ "NtQueryPerformanceCounter", gt_windows_print_syscall_ntqueryperformancecounter, gt_windows_print_sysret_ntqueryperformancecounter },
	{ "NtQueryPortInformationProcess", gt_windows_print_syscall_ntqueryportinformationprocess, gt_windows_print_sysret_ntqueryportinformationprocess },
	{ "NtQueryQuotaInformationFile", gt_windows_print_syscall_ntqueryquotainformationfile, gt_windows_print_sysret_ntqueryquotainformationfile },
	{ "NtQuerySection", gt_windows_print_syscall_ntquerysection, gt_windows_print_sysret_ntquerysection },
	{ "NtQuerySecurityAttributesToken", gt_windows_print_syscall_ntquerysecurityattributestoken, gt_windows_print_sysret_ntquerysecurityattributestoken },
	{ "NtQuerySecurityObject", gt_windows_print_syscall_ntquerysecurityobject, gt_windows_print_sysret_ntquerysecurityobject },
	{ "NtQuerySemaphore", gt_windows_print_syscall_ntquerysemaphore, gt_windows_print_sysret_ntquerysemaphore },
	{ "NtQuerySymbolicLinkObject", gt_windows_print_syscall_ntquerysymboliclinkobject, gt_windows_print_sysret_ntquerysymboliclinkobject },
	{ "NtQuerySystemEnvironmentValueEx", gt_windows_print_syscall_ntquerysystemenvironmentvalueex, gt_windows_print_sysret_ntquerysystemenvironmentvalueex },
	{ "NtQuerySystemEnvironmentValue", gt_windows_print_syscall_ntquerysystemenvironmentvalue, gt_windows_print_sysret_ntquerysystemenvironmentvalue },
	{ "NtQuerySystemInformationEx", gt_windows_print_syscall_ntquerysysteminformationex, gt_windows_print_sysret_ntquerysysteminformationex },
	{ "NtQuerySystemInformation", gt_windows_print_syscall_ntquerysysteminformation, gt_windows_print_sysret_ntquerysysteminformation },
	{ "NtQuerySystemTime", gt_windows_print_syscall_ntquerysystemtime, gt_windows_print_sysret_ntquerysystemtime },
	{ "NtQueryTimer", gt_windows_print_syscall_ntquerytimer, gt_windows_print_sysret_ntquerytimer },
	{ "NtQueryTimerResolution", gt_windows_print_syscall_ntquerytimerresolution, gt_windows_print_sysret_ntquerytimerresolution },
	{ "NtQueryValueKey", gt_windows_print_syscall_ntqueryvaluekey, gt_windows_print_sysret_ntqueryvaluekey },
	{ "NtQueryVirtualMemory", gt_windows_print_syscall_ntqueryvirtualmemory, gt_windows_print_sysret_ntqueryvirtualmemory },
	{ "NtQueryVolumeInformationFile", gt_windows_print_syscall_ntqueryvolumeinformationfile, gt_windows_print_sysret_ntqueryvolumeinformationfile },
	{ "NtQueueApcThreadEx", gt_windows_print_syscall_ntqueueapcthreadex, gt_windows_print_sysret_ntqueueapcthreadex },
	{ "NtQueueApcThread", gt_windows_print_syscall_ntqueueapcthread, gt_windows_print_sysret_ntqueueapcthread },
	{ "NtRaiseException", gt_windows_print_syscall_ntraiseexception, gt_windows_print_sysret_ntraiseexception },
	{ "NtRaiseHardError", gt_windows_print_syscall_ntraiseharderror, gt_windows_print_sysret_ntraiseharderror },
	{ "NtReadFile", gt_windows_print_syscall_ntreadfile, gt_windows_print_sysret_ntreadfile },
	{ "NtReadFileScatter", gt_windows_print_syscall_ntreadfilescatter, gt_windows_print_sysret_ntreadfilescatter },
	{ "NtReadOnlyEnlistment", gt_windows_print_syscall_ntreadonlyenlistment, gt_windows_print_sysret_ntreadonlyenlistment },
	{ "NtReadRequestData", gt_windows_print_syscall_ntreadrequestdata, gt_windows_print_sysret_ntreadrequestdata },
	{ "NtReadVirtualMemory", gt_windows_print_syscall_ntreadvirtualmemory, gt_windows_print_sysret_ntreadvirtualmemory },
	{ "NtRecoverEnlistment", gt_windows_print_syscall_ntrecoverenlistment, gt_windows_print_sysret_ntrecoverenlistment },
	{ "NtRecoverResourceManager", gt_windows_print_syscall_ntrecoverresourcemanager, gt_windows_print_sysret_ntrecoverresourcemanager },
	{ "NtRecoverTransactionManager", gt_windows_print_syscall_ntrecovertransactionmanager, gt_windows_print_sysret_ntrecovertransactionmanager },
	{ "NtRegisterProtocolAddressInformation", gt_windows_print_syscall_ntregisterprotocoladdressinformation, gt_windows_print_sysret_ntregisterprotocoladdressinformation },
	{ "NtRegisterThreadTerminatePort", gt_windows_print_syscall_ntregisterthreadterminateport, gt_windows_print_sysret_ntregisterthreadterminateport },
	{ "NtReleaseKeyedEvent", gt_windows_print_syscall_ntreleasekeyedevent, gt_windows_print_sysret_ntreleasekeyedevent },
	{ "NtReleaseMutant", gt_windows_print_syscall_ntreleasemutant, gt_windows_print_sysret_ntreleasemutant },
	{ "NtReleaseSemaphore", gt_windows_print_syscall_ntreleasesemaphore, gt_windows_print_sysret_ntreleasesemaphore },
	{ "NtReleaseWorkerFactoryWorker", gt_windows_print_syscall_ntreleaseworkerfactoryworker, gt_windows_print_sysret_ntreleaseworkerfactoryworker },
	{ "NtRemoveIoCompletionEx", gt_windows_print_syscall_ntremoveiocompletionex, gt_windows_print_sysret_ntremoveiocompletionex },
	{ "NtRemoveIoCompletion", gt_windows_print_syscall_ntremoveiocompletion, gt_windows_print_sysret_ntremoveiocompletion },
	{ "NtRemoveProcessDebug", gt_windows_print_syscall_ntremoveprocessdebug, gt_windows_print_sysret_ntremoveprocessdebug },
	{ "NtRenameKey", gt_windows_print_syscall_ntrenamekey, gt_windows_print_sysret_ntrenamekey },
	{ "NtRenameTransactionManager", gt_windows_print_syscall_ntrenametransactionmanager, gt_windows_print_sysret_ntrenametransactionmanager },
	{ "NtReplaceKey", gt_windows_print_syscall_ntreplacekey, gt_windows_print_sysret_ntreplacekey },
	{ "NtReplacePartitionUnit", gt_windows_print_syscall_ntreplacepartitionunit, gt_windows_print_sysret_ntreplacepartitionunit },
	{ "NtReplyPort", gt_windows_print_syscall_ntreplyport, gt_windows_print_sysret_ntreplyport },
	{ "NtReplyWaitReceivePortEx", gt_windows_print_syscall_ntreplywaitreceiveportex, gt_windows_print_sysret_ntreplywaitreceiveportex },
	{ "NtReplyWaitReceivePort", gt_windows_print_syscall_ntreplywaitreceiveport, gt_windows_print_sysret_ntreplywaitreceiveport },
	{ "NtReplyWaitReplyPort", gt_windows_print_syscall_ntreplywaitreplyport, gt_windows_print_sysret_ntreplywaitreplyport },
	{ "NtRequestPort", gt_windows_print_syscall_ntrequestport, gt_windows_print_sysret_ntrequestport },
	{ "NtRequestWaitReplyPort", gt_windows_print_syscall_ntrequestwaitreplyport, gt_windows_print_sysret_ntrequestwaitreplyport },
	{ "NtResetEvent", gt_windows_print_syscall_ntresetevent, gt_windows_print_sysret_ntresetevent },
	{ "NtResetWriteWatch", gt_windows_print_syscall_ntresetwritewatch, gt_windows_print_sysret_ntresetwritewatch },
	{ "NtRestoreKey", gt_windows_print_syscall_ntrestorekey, gt_windows_print_sysret_ntrestorekey },
	{ "NtResumeProcess", gt_windows_print_syscall_ntresumeprocess, gt_windows_print_sysret_ntresumeprocess },
	{ "NtResumeThread", gt_windows_print_syscall_ntresumethread, gt_windows_print_sysret_ntresumethread },
	{ "NtRollbackComplete", gt_windows_print_syscall_ntrollbackcomplete, gt_windows_print_sysret_ntrollbackcomplete },
	{ "NtRollbackEnlistment", gt_windows_print_syscall_ntrollbackenlistment, gt_windows_print_sysret_ntrollbackenlistment },
	{ "NtRollbackTransaction", gt_windows_print_syscall_ntrollbacktransaction, gt_windows_print_sysret_ntrollbacktransaction },
	{ "NtRollforwardTransactionManager", gt_windows_print_syscall_ntrollforwardtransactionmanager, gt_windows_print_sysret_ntrollforwardtransactionmanager },
	{ "NtSaveKeyEx", gt_windows_print_syscall_ntsavekeyex, gt_windows_print_sysret_ntsavekeyex },
	{ "NtSaveKey", gt_windows_print_syscall_ntsavekey, gt_windows_print_sysret_ntsavekey },
	{ "NtSaveMergedKeys", gt_windows_print_syscall_ntsavemergedkeys, gt_windows_print_sysret_ntsavemergedkeys },
	{ "NtSecureConnectPort", gt_windows_print_syscall_ntsecureconnectport, gt_windows_print_sysret_ntsecureconnectport },
	{ "NtSerializeBoot", gt_windows_print_syscall_ntserializeboot, gt_windows_print_sysret_ntserializeboot },
	{ "NtSetBootEntryOrder", gt_windows_print_syscall_ntsetbootentryorder, gt_windows_print_sysret_ntsetbootentryorder },
	{ "NtSetBootOptions", gt_windows_print_syscall_ntsetbootoptions, gt_windows_print_sysret_ntsetbootoptions },
	{ "NtSetContextThread", gt_windows_print_syscall_ntsetcontextthread, gt_windows_print_sysret_ntsetcontextthread },
	{ "NtSetDebugFilterState", gt_windows_print_syscall_ntsetdebugfilterstate, gt_windows_print_sysret_ntsetdebugfilterstate },
	{ "NtSetDefaultHardErrorPort", gt_windows_print_syscall_ntsetdefaultharderrorport, gt_windows_print_sysret_ntsetdefaultharderrorport },
	{ "NtSetDefaultLocale", gt_windows_print_syscall_ntsetdefaultlocale, gt_windows_print_sysret_ntsetdefaultlocale },
	{ "NtSetDefaultUILanguage", gt_windows_print_syscall_ntsetdefaultuilanguage, gt_windows_print_sysret_ntsetdefaultuilanguage },
	{ "NtSetDriverEntryOrder", gt_windows_print_syscall_ntsetdriverentryorder, gt_windows_print_sysret_ntsetdriverentryorder },
	{ "NtSetEaFile", gt_windows_print_syscall_ntseteafile, gt_windows_print_sysret_ntseteafile },
	{ "NtSetEventBoostPriority", gt_windows_print_syscall_ntseteventboostpriority, gt_windows_print_sysret_ntseteventboostpriority },
	{ "NtSetEvent", gt_windows_print_syscall_ntsetevent, gt_windows_print_sysret_ntsetevent },
	{ "NtSetHighEventPair", gt_windows_print_syscall_ntsethigheventpair, gt_windows_print_sysret_ntsethigheventpair },
	{ "NtSetHighWaitLowEventPair", gt_windows_print_syscall_ntsethighwaitloweventpair, gt_windows_print_sysret_ntsethighwaitloweventpair },
	{ "NtSetInformationDebugObject", gt_windows_print_syscall_ntsetinformationdebugobject, gt_windows_print_sysret_ntsetinformationdebugobject },
	{ "NtSetInformationEnlistment", gt_windows_print_syscall_ntsetinformationenlistment, gt_windows_print_sysret_ntsetinformationenlistment },
	{ "NtSetInformationFile", gt_windows_print_syscall_ntsetinformationfile, gt_windows_print_sysret_ntsetinformationfile },
	{ "NtSetInformationJobObject", gt_windows_print_syscall_ntsetinformationjobobject, gt_windows_print_sysret_ntsetinformationjobobject },
	{ "NtSetInformationKey", gt_windows_print_syscall_ntsetinformationkey, gt_windows_print_sysret_ntsetinformationkey },
	{ "NtSetInformationObject", gt_windows_print_syscall_ntsetinformationobject, gt_windows_print_sysret_ntsetinformationobject },
	{ "NtSetInformationProcess", gt_windows_print_syscall_ntsetinformationprocess, gt_windows_print_sysret_ntsetinformationprocess },
	{ "NtSetInformationResourceManager", gt_windows_print_syscall_ntsetinformationresourcemanager, gt_windows_print_sysret_ntsetinformationresourcemanager },
	{ "NtSetInformationThread", gt_windows_print_syscall_ntsetinformationthread, gt_windows_print_sysret_ntsetinformationthread },
	{ "NtSetInformationToken", gt_windows_print_syscall_ntsetinformationtoken, gt_windows_print_sysret_ntsetinformationtoken },
	{ "NtSetInformationTransaction", gt_windows_print_syscall_ntsetinformationtransaction, gt_windows_print_sysret_ntsetinformationtransaction },
	{ "NtSetInformationTransactionManager", gt_windows_print_syscall_ntsetinformationtransactionmanager, gt_windows_print_sysret_ntsetinformationtransactionmanager },
	{ "NtSetInformationWorkerFactory", gt_windows_print_syscall_ntsetinformationworkerfactory, gt_windows_print_sysret_ntsetinformationworkerfactory },
	{ "NtSetIntervalProfile", gt_windows_print_syscall_ntsetintervalprofile, gt_windows_print_sysret_ntsetintervalprofile },
	{ "NtSetIoCompletionEx", gt_windows_print_syscall_ntsetiocompletionex, gt_windows_print_sysret_ntsetiocompletionex },
	{ "NtSetIoCompletion", gt_windows_print_syscall_ntsetiocompletion, gt_windows_print_sysret_ntsetiocompletion },
	{ "NtSetLdtEntries", gt_windows_print_syscall_ntsetldtentries, gt_windows_print_sysret_ntsetldtentries },
	{ "NtSetLowEventPair", gt_windows_print_syscall_ntsetloweventpair, gt_windows_print_sysret_ntsetloweventpair },
	{ "NtSetLowWaitHighEventPair", gt_windows_print_syscall_ntsetlowwaithigheventpair, gt_windows_print_sysret_ntsetlowwaithigheventpair },
	{ "NtSetQuotaInformationFile", gt_windows_print_syscall_ntsetquotainformationfile, gt_windows_print_sysret_ntsetquotainformationfile },
	{ "NtSetSecurityObject", gt_windows_print_syscall_ntsetsecurityobject, gt_windows_print_sysret_ntsetsecurityobject },
	{ "NtSetSystemEnvironmentValueEx", gt_windows_print_syscall_ntsetsystemenvironmentvalueex, gt_windows_print_sysret_ntsetsystemenvironmentvalueex },
	{ "NtSetSystemEnvironmentValue", gt_windows_print_syscall_ntsetsystemenvironmentvalue, gt_windows_print_sysret_ntsetsystemenvironmentvalue },
	{ "NtSetSystemInformation", gt_windows_print_syscall_ntsetsysteminformation, gt_windows_print_sysret_ntsetsysteminformation },
	{ "NtSetSystemPowerState", gt_windows_print_syscall_ntsetsystempowerstate, gt_windows_print_sysret_ntsetsystempowerstate },
	{ "NtSetSystemTime", gt_windows_print_syscall_ntsetsystemtime, gt_windows_print_sysret_ntsetsystemtime },
	{ "NtSetThreadExecutionState", gt_windows_print_syscall_ntsetthreadexecutionstate, gt_windows_print_sysret_ntsetthreadexecutionstate },
	{ "NtSetTimerEx", gt_windows_print_syscall_ntsettimerex, gt_windows_print_sysret_ntsettimerex },
	{ "NtSetTimer", gt_windows_print_syscall_ntsettimer, gt_windows_print_sysret_ntsettimer },
	{ "NtSetTimerResolution", gt_windows_print_syscall_ntsettimerresolution, gt_windows_print_sysret_ntsettimerresolution },
	{ "NtSetUuidSeed", gt_windows_print_syscall_ntsetuuidseed, gt_windows_print_sysret_ntsetuuidseed },
	{ "NtSetValueKey", gt_windows_print_syscall_ntsetvaluekey, gt_windows_print_sysret_ntsetvaluekey },
	{ "NtSetVolumeInformationFile", gt_windows_print_syscall_ntsetvolumeinformationfile, gt_windows_print_sysret_ntsetvolumeinformationfile },
	{ "NtShutdownSystem", gt_windows_print_syscall_ntshutdownsystem, gt_windows_print_sysret_ntshutdownsystem },
	{ "NtShutdownWorkerFactory", gt_windows_print_syscall_ntshutdownworkerfactory, gt_windows_print_sysret_ntshutdownworkerfactory },
	{ "NtSignalAndWaitForSingleObject", gt_windows_print_syscall_ntsignalandwaitforsingleobject, gt_windows_print_sysret_ntsignalandwaitforsingleobject },
	{ "NtSinglePhaseReject", gt_windows_print_syscall_ntsinglephasereject, gt_windows_print_sysret_ntsinglephasereject },
	{ "NtStartProfile", gt_windows_print_syscall_ntstartprofile, gt_windows_print_sysret_ntstartprofile },
	{ "NtStopProfile", gt_windows_print_syscall_ntstopprofile, gt_windows_print_sysret_ntstopprofile },
	{ "NtSuspendProcess", gt_windows_print_syscall_ntsuspendprocess, gt_windows_print_sysret_ntsuspendprocess },
	{ "NtSuspendThread", gt_windows_print_syscall_ntsuspendthread, gt_windows_print_sysret_ntsuspendthread },
	{ "NtSystemDebugControl", gt_windows_print_syscall_ntsystemdebugcontrol, gt_windows_print_sysret_ntsystemdebugcontrol },
	{ "NtTerminateJobObject", gt_windows_print_syscall_ntterminatejobobject, gt_windows_print_sysret_ntterminatejobobject },
	{ "NtTerminateProcess", gt_windows_print_syscall_ntterminateprocess, gt_windows_print_sysret_ntterminateprocess },
	{ "NtTerminateThread", gt_windows_print_syscall_ntterminatethread, gt_windows_print_sysret_ntterminatethread },
	{ "NtTestAlert", gt_windows_print_syscall_nttestalert, gt_windows_print_sysret_nttestalert },
	{ "NtThawRegistry", gt_windows_print_syscall_ntthawregistry, gt_windows_print_sysret_ntthawregistry },
	{ "NtThawTransactions", gt_windows_print_syscall_ntthawtransactions, gt_windows_print_sysret_ntthawtransactions },
	{ "NtTraceControl", gt_windows_print_syscall_nttracecontrol, gt_windows_print_sysret_nttracecontrol },
	{ "NtTraceEvent", gt_windows_print_syscall_nttraceevent, gt_windows_print_sysret_nttraceevent },
	{ "NtTranslateFilePath", gt_windows_print_syscall_nttranslatefilepath, gt_windows_print_sysret_nttranslatefilepath },
	{ "NtUmsThreadYield", gt_windows_print_syscall_ntumsthreadyield, gt_windows_print_sysret_ntumsthreadyield },
	{ "NtUnloadDriver", gt_windows_print_syscall_ntunloaddriver, gt_windows_print_sysret_ntunloaddriver },
	{ "NtUnloadKey2", gt_windows_print_syscall_ntunloadkey2, gt_windows_print_sysret_ntunloadkey2 },
	{ "NtUnloadKeyEx", gt_windows_print_syscall_ntunloadkeyex, gt_windows_print_sysret_ntunloadkeyex },
	{ "NtUnloadKey", gt_windows_print_syscall_ntunloadkey, gt_windows_print_sysret_ntunloadkey },
	{ "NtUnlockFile", gt_windows_print_syscall_ntunlockfile, gt_windows_print_sysret_ntunlockfile },
	{ "NtUnlockVirtualMemory", gt_windows_print_syscall_ntunlockvirtualmemory, gt_windows_print_sysret_ntunlockvirtualmemory },
	{ "NtUnmapViewOfSection", gt_windows_print_syscall_ntunmapviewofsection, gt_windows_print_sysret_ntunmapviewofsection },
	{ "NtVdmControl", gt_windows_print_syscall_ntvdmcontrol, gt_windows_print_sysret_ntvdmcontrol },
	{ "NtWaitForDebugEvent", gt_windows_print_syscall_ntwaitfordebugevent, gt_windows_print_sysret_ntwaitfordebugevent },
	{ "NtWaitForKeyedEvent", gt_windows_print_syscall_ntwaitforkeyedevent, gt_windows_print_sysret_ntwaitforkeyedevent },
	{ "NtWaitForMultipleObjects32", gt_windows_print_syscall_ntwaitformultipleobjects32, gt_windows_print_sysret_ntwaitformultipleobjects32 },
	{ "NtWaitForMultipleObjects", gt_windows_print_syscall_ntwaitformultipleobjects, gt_windows_print_sysret_ntwaitformultipleobjects },
	{ "NtWaitForSingleObject", gt_windows_print_syscall_ntwaitforsingleobject, gt_windows_print_sysret_ntwaitforsingleobject },
	{ "NtWaitForWorkViaWorkerFactory", gt_windows_print_syscall_ntwaitforworkviaworkerfactory, gt_windows_print_sysret_ntwaitforworkviaworkerfactory },
	{ "NtWaitHighEventPair", gt_windows_print_syscall_ntwaithigheventpair, gt_windows_print_sysret_ntwaithigheventpair },
	{ "NtWaitLowEventPair", gt_windows_print_syscall_ntwaitloweventpair, gt_windows_print_sysret_ntwaitloweventpair },
	{ "NtWorkerFactoryWorkerReady", gt_windows_print_syscall_ntworkerfactoryworkerready, gt_windows_print_sysret_ntworkerfactoryworkerready },
	{ "NtWriteFileGather", gt_windows_print_syscall_ntwritefilegather, gt_windows_print_sysret_ntwritefilegather },
	{ "NtWriteFile", gt_windows_print_syscall_ntwritefile, gt_windows_print_sysret_ntwritefile },
	{ "NtWriteRequestData", gt_windows_print_syscall_ntwriterequestdata, gt_windows_print_sysret_ntwriterequestdata },
	{ "NtWriteVirtualMemory", gt_windows_print_syscall_ntwritevirtualmemory, gt_windows_print_sysret_ntwritevirtualmemory },
	{ "NtYieldExecution", gt_windows_print_syscall_ntyieldexecution, gt_windows_print_sysret_ntyieldexecution },
	{ NULL, NULL, NULL },
};
/*
 * For each of the system calls libvmi is interested in, establish a memory trap
 * on the page containing the system call handler's first instruction. An
 * execute trap will cause guestrace to emplace a breakpoint. A read/write trap
 * (i.e., kernel patch protection) will cause guestrace to restore the original
 * instruction.
 */
void
_gt_windows_find_syscalls_and_setup_mem_traps(GTLoop *loop)
{
	/*
	 * Delete everything but the line below if you want to release
	 * hell on your processor...
	 *     gt_loop_set_cbs(loop, SYSCALLS);
	 */
	char *TRACED_SYSCALLS[] = {
		"NtOpenFile",
		"NtOpenProcess",
		"NtClose",
		"NtReadFile",
		"NtOpenFile",
		"NtOpenProcess",
		NULL,
	};

	for (int i = 0; TRACED_SYSCALLS[i]; i++) {
		for (int j = 0; SYSCALLS[j].name; j++) {
			if (strcmp(TRACED_SYSCALLS[i], SYSCALLS[j].name)) {
				continue;
			}

			gt_loop_set_cb(loop, SYSCALLS[j].name, SYSCALLS[j].syscall_cb, SYSCALLS[j].sysret_cb);
		}
	}
}

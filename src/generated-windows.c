#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "guestrace.h"
#include "functions-windows.h"
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
obj_attr_from_va(vmi_instance_t vmi, addr_t vaddr, gt_pid_t pid) {
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
unicode_str_from_va(vmi_instance_t vmi, addr_t va, gt_pid_t pid) {
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
vf_get_args(GtGuestState *state, gt_pid_t pid) {
	uint64_t *args = calloc(NUM_SYSCALL_ARGS, sizeof(uint64_t));
	args[0] = gt_guest_get_register(state, RCX);
	args[1] = gt_guest_get_register(state, RDX);
	args[2] = gt_guest_get_register(state, R8);
	args[3] = gt_guest_get_register(state, R9);
	
	vmi_read_va(gt_guest_get_vmi_instance(state), gt_guest_get_register(state, RSP) + vmi_get_address_width(gt_guest_get_vmi_instance(state)) * 5, pid, &args[4], sizeof(uint64_t) * (NUM_SYSCALL_ARGS - 4));
	return args;
}
void *gt_windows_print_syscall_ntacceptconnectport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_3 = args[3] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAcceptConnectPort(PortContext: 0x%lx, ConnectionRequest: 0x%lx, AcceptConnection: %s, ServerView: 0x%lx)\n", pid, tid, proc, args[1], args[2], bool_3, args[4]);
	return args;
}

void gt_windows_print_sysret_ntacceptconnectport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PortHandle: 0x%lx, ServerView: 0x%lx, ClientView: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0, args[4], args[5]);
	free(args);
}

void *gt_windows_print_syscall_ntaccesscheckandauditalarm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	uint8_t *unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	uint8_t *unicode_str_3 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[3], pid);
	char *permissions_5 = vf_get_simple_permissions(args[5]);
	char *bool_7 = args[7] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAccessCheckAndAuditAlarm(SubsystemName: %s, HandleId: 0x%lx, ObjectTypeName: %s, ObjectName: %s, SecurityDescriptor: 0x%lx, DesiredAccess: %s [0x%lx], GenericMapping: 0x%lx, ObjectCreation: %s)\n", pid, tid, proc, unicode_str_0, args[1], unicode_str_2, unicode_str_3, args[4], permissions_5, args[5], args[6], bool_7);
	free(unicode_str_0);
	free(unicode_str_2);
	free(unicode_str_3);
	free(permissions_5);	return args;
}

void gt_windows_print_sysret_ntaccesscheckandauditalarm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(GrantedAccess: 0x%lx, AccessStatus: 0x%lx, GenerateOnClose: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[8], args[9], args[10]);
	free(args);
}

void *gt_windows_print_syscall_ntaccesscheckbytypeandauditalarm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	uint8_t *unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	uint8_t *unicode_str_3 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[3], pid);
	char *permissions_6 = vf_get_simple_permissions(args[6]);
	char *bool_12 = args[12] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAccessCheckByTypeAndAuditAlarm(SubsystemName: %s, HandleId: 0x%lx, ObjectTypeName: %s, ObjectName: %s, SecurityDescriptor: 0x%lx, PrincipalSelfSid: 0x%lx, DesiredAccess: %s [0x%lx], AuditType: 0x%lx, Flags: 0x%lx, ObjectTypeListLength: 0x%lx, GenericMapping: 0x%lx, ObjectCreation: %s)\n", pid, tid, proc, unicode_str_0, args[1], unicode_str_2, unicode_str_3, args[4], args[5], permissions_6, args[6], args[7], args[8], args[10], args[11], bool_12);
	free(unicode_str_0);
	free(unicode_str_2);
	free(unicode_str_3);
	free(permissions_6);	return args;
}

void gt_windows_print_sysret_ntaccesscheckbytypeandauditalarm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(GrantedAccess: 0x%lx, AccessStatus: 0x%lx, GenerateOnClose: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[13], args[14], args[15]);
	free(args);
}

void *gt_windows_print_syscall_ntaccesscheckbytype(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_3 = vf_get_simple_permissions(args[3]);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAccessCheckByType(SecurityDescriptor: 0x%lx, PrincipalSelfSid: 0x%lx, ClientToken: 0x%lx, DesiredAccess: %s [0x%lx], ObjectTypeListLength: 0x%lx, GenericMapping: 0x%lx, PrivilegeSetLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], permissions_3, args[3], args[5], args[6], pulong_8);
	free(permissions_3);	return args;
}

void gt_windows_print_sysret_ntaccesscheckbytype(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PrivilegeSetLength: 0x%lx, GrantedAccess: 0x%lx, AccessStatus: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_8, args[9], args[10]);
	free(args);
}

void *gt_windows_print_syscall_ntaccesscheckbytyperesultlistandauditalarmbyhandle(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	uint8_t *unicode_str_3 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[3], pid);
	uint8_t *unicode_str_4 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[4], pid);
	char *permissions_7 = vf_get_simple_permissions(args[7]);
	char *bool_13 = args[13] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAccessCheckByTypeResultListAndAuditAlarmByHandle(SubsystemName: %s, HandleId: 0x%lx, ClientToken: 0x%lx, ObjectTypeName: %s, ObjectName: %s, SecurityDescriptor: 0x%lx, PrincipalSelfSid: 0x%lx, DesiredAccess: %s [0x%lx], AuditType: 0x%lx, Flags: 0x%lx, ObjectTypeListLength: 0x%lx, GenericMapping: 0x%lx, ObjectCreation: %s)\n", pid, tid, proc, unicode_str_0, args[1], args[2], unicode_str_3, unicode_str_4, args[5], args[6], permissions_7, args[7], args[8], args[9], args[11], args[12], bool_13);
	free(unicode_str_0);
	free(unicode_str_3);
	free(unicode_str_4);
	free(permissions_7);	return args;
}

void gt_windows_print_sysret_ntaccesscheckbytyperesultlistandauditalarmbyhandle(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(GenerateOnClose: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[16]);
	free(args);
}

void *gt_windows_print_syscall_ntaccesscheckbytyperesultlistandauditalarm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	uint8_t *unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	uint8_t *unicode_str_3 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[3], pid);
	char *permissions_6 = vf_get_simple_permissions(args[6]);
	char *bool_12 = args[12] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAccessCheckByTypeResultListAndAuditAlarm(SubsystemName: %s, HandleId: 0x%lx, ObjectTypeName: %s, ObjectName: %s, SecurityDescriptor: 0x%lx, PrincipalSelfSid: 0x%lx, DesiredAccess: %s [0x%lx], AuditType: 0x%lx, Flags: 0x%lx, ObjectTypeListLength: 0x%lx, GenericMapping: 0x%lx, ObjectCreation: %s)\n", pid, tid, proc, unicode_str_0, args[1], unicode_str_2, unicode_str_3, args[4], args[5], permissions_6, args[6], args[7], args[8], args[10], args[11], bool_12);
	free(unicode_str_0);
	free(unicode_str_2);
	free(unicode_str_3);
	free(permissions_6);	return args;
}

void gt_windows_print_sysret_ntaccesscheckbytyperesultlistandauditalarm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(GenerateOnClose: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[15]);
	free(args);
}

void *gt_windows_print_syscall_ntaccesscheckbytyperesultlist(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_3 = vf_get_simple_permissions(args[3]);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAccessCheckByTypeResultList(SecurityDescriptor: 0x%lx, PrincipalSelfSid: 0x%lx, ClientToken: 0x%lx, DesiredAccess: %s [0x%lx], ObjectTypeListLength: 0x%lx, GenericMapping: 0x%lx, PrivilegeSetLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], permissions_3, args[3], args[5], args[6], pulong_8);
	free(permissions_3);	return args;
}

void gt_windows_print_sysret_ntaccesscheckbytyperesultlist(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PrivilegeSetLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_8);
	free(args);
}

void *gt_windows_print_syscall_ntaccesscheck(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_2 = vf_get_simple_permissions(args[2]);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAccessCheck(SecurityDescriptor: 0x%lx, ClientToken: 0x%lx, DesiredAccess: %s [0x%lx], GenericMapping: 0x%lx, PrivilegeSetLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], permissions_2, args[2], args[3], pulong_5);
	free(permissions_2);	return args;
}

void gt_windows_print_sysret_ntaccesscheck(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PrivilegeSetLength: 0x%lx, GrantedAccess: 0x%lx, AccessStatus: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_5, args[6], args[7]);
	free(args);
}

void *gt_windows_print_syscall_ntaddatom(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAddAtom(Length: 0x%lx)\n", pid, tid, proc, args[1]);
	return args;
}

void gt_windows_print_sysret_ntaddatom(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Atom: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntaddbootentry(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAddBootEntry(BootEntry: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntaddbootentry(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Id: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntadddriverentry(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAddDriverEntry(DriverEntry: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntadddriverentry(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Id: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntadjustgroupstoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_1 = args[1] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAdjustGroupsToken(TokenHandle: 0x%lx, ResetToDefault: %s, NewState: 0x%lx, BufferLength: 0x%lx)\n", pid, tid, proc, args[0], bool_1, args[2], args[3]);
	return args;
}

void gt_windows_print_sysret_ntadjustgroupstoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntadjustprivilegestoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_1 = args[1] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAdjustPrivilegesToken(TokenHandle: 0x%lx, DisableAllPrivileges: %s, NewState: 0x%lx, BufferLength: 0x%lx)\n", pid, tid, proc, args[0], bool_1, args[2], args[3]);
	return args;
}

void gt_windows_print_sysret_ntadjustprivilegestoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntalertresumethread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlertResumeThread(ThreadHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntalertresumethread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousSuspendCount: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntalertthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlertThread(ThreadHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntalertthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntallocatelocallyuniqueid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAllocateLocallyUniqueId()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntallocatelocallyuniqueid(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Luid: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[0]);
	free(args);
}

void *gt_windows_print_syscall_ntallocatereserveobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_1 = NULL;
	uint64_t root_dir_1 = 0;
	uint64_t attributes_1 = 0;
	struct win64_obj_attr *obj_attr_1 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	if (NULL != obj_attr_1) {
		unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_1->object_name, pid);
		root_dir_1 = obj_attr_1->root_directory;
		attributes_1 = obj_attr_1->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAllocateReserveObject(ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Type: 0x%lx)\n", pid, tid, proc, root_dir_1, unicode_str_1, attributes_1, args[2]);
	free(unicode_str_1);
	free(obj_attr_1);	return args;
}

void gt_windows_print_sysret_ntallocatereserveobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(MemoryReserveHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntallocateuserphysicalpages(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAllocateUserPhysicalPages(ProcessHandle: 0x%lx, NumberOfPages: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntallocateuserphysicalpages(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NumberOfPages: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntallocateuuids(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAllocateUuids()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntallocateuuids(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	uint64_t pulong_2 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[2], pid, &pulong_2);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Time: 0x%lx, Range: 0x%lx, Sequence: 0x%lx, Seed: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[0], pulong_1, pulong_2, args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntallocatevirtualmemory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAllocateVirtualMemory(ProcessHandle: 0x%lx, *BaseAddress: 0x%lx, ZeroBits: 0x%lx, RegionSize: 0x%lx, AllocationType: 0x%lx, Protect: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4], args[5]);
	return args;
}

void gt_windows_print_sysret_ntallocatevirtualmemory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*BaseAddress: 0x%lx, RegionSize: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1], args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntalpcacceptconnectport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_3 = NULL;
	uint64_t root_dir_3 = 0;
	uint64_t attributes_3 = 0;
	struct win64_obj_attr *obj_attr_3 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[3], pid);
	if (NULL != obj_attr_3) {
		unicode_str_3 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_3->object_name, pid);
		root_dir_3 = obj_attr_3->root_directory;
		attributes_3 = obj_attr_3->attributes;
	}
	char *bool_8 = args[8] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcAcceptConnectPort(ConnectionPortHandle: 0x%lx, Flags: 0x%lx, ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, PortAttributes: 0x%lx, PortContext: 0x%lx, ConnectionRequest: 0x%lx, ConnectionMessageAttributes: 0x%lx, AcceptConnection: %s)\n", pid, tid, proc, args[1], args[2], root_dir_3, unicode_str_3, attributes_3, args[4], args[5], args[6], args[7], bool_8);
	free(unicode_str_3);
	free(obj_attr_3);	return args;
}

void gt_windows_print_sysret_ntalpcacceptconnectport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PortHandle: 0x%lx, ConnectionMessageAttributes: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0, args[7]);
	free(args);
}

void *gt_windows_print_syscall_ntalpccancelmessage(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcCancelMessage(PortHandle: 0x%lx, Flags: 0x%lx, MessageContext: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntalpccancelmessage(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntalpcconnectport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	uint64_t pulong_7 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[7], pid, &pulong_7);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcConnectPort(PortName: %s, ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, PortAttributes: 0x%lx, Flags: 0x%lx, RequiredServerSid: 0x%lx, ConnectionMessage: 0x%lx, BufferLength: 0x%lx, OutMessageAttributes: 0x%lx, InMessageAttributes: 0x%lx, Timeout: 0x%lx)\n", pid, tid, proc, unicode_str_1, root_dir_2, unicode_str_2, attributes_2, args[3], args[4], args[5], args[6], pulong_7, args[8], args[9], args[10]);
	free(unicode_str_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntalpcconnectport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	uint64_t pulong_7 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[7], pid, &pulong_7);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PortHandle: 0x%lx, ConnectionMessage: 0x%lx, BufferLength: 0x%lx, OutMessageAttributes: 0x%lx, InMessageAttributes: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0, args[6], pulong_7, args[8], args[9]);
	free(args);
}

void *gt_windows_print_syscall_ntalpccreateport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_1 = NULL;
	uint64_t root_dir_1 = 0;
	uint64_t attributes_1 = 0;
	struct win64_obj_attr *obj_attr_1 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	if (NULL != obj_attr_1) {
		unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_1->object_name, pid);
		root_dir_1 = obj_attr_1->root_directory;
		attributes_1 = obj_attr_1->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcCreatePort(ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, PortAttributes: 0x%lx)\n", pid, tid, proc, root_dir_1, unicode_str_1, attributes_1, args[2]);
	free(unicode_str_1);
	free(obj_attr_1);	return args;
}

void gt_windows_print_sysret_ntalpccreateport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PortHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntalpccreateportsection(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcCreatePortSection(PortHandle: 0x%lx, Flags: 0x%lx, SectionHandle: 0x%lx, SectionSize: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3]);
	return args;
}

void gt_windows_print_sysret_ntalpccreateportsection(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(AlpcSectionHandle: 0x%lx, ActualSectionSize: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[4], args[5]);
	free(args);
}

void *gt_windows_print_syscall_ntalpccreateresourcereserve(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcCreateResourceReserve(PortHandle: 0x%lx, MessageSize: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntalpccreateresourcereserve(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ResourceId: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntalpccreatesectionview(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcCreateSectionView(PortHandle: 0x%lx, ViewAttributes: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntalpccreatesectionview(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ViewAttributes: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntalpccreatesecuritycontext(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcCreateSecurityContext(PortHandle: 0x%lx, SecurityAttribute: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntalpccreatesecuritycontext(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(SecurityAttribute: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntalpcdeleteportsection(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcDeletePortSection(PortHandle: 0x%lx, SectionHandle: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntalpcdeleteportsection(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntalpcdeleteresourcereserve(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcDeleteResourceReserve(PortHandle: 0x%lx, ResourceId: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntalpcdeleteresourcereserve(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntalpcdeletesectionview(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcDeleteSectionView(PortHandle: 0x%lx, ViewBase: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntalpcdeletesectionview(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntalpcdeletesecuritycontext(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcDeleteSecurityContext(PortHandle: 0x%lx, ContextHandle: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntalpcdeletesecuritycontext(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntalpcdisconnectport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcDisconnectPort(PortHandle: 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntalpcdisconnectport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntalpcimpersonateclientofport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcImpersonateClientOfPort(PortHandle: 0x%lx, PortMessage: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntalpcimpersonateclientofport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntalpcopensenderprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_4 = vf_get_simple_permissions(args[4]);
	uint8_t *unicode_str_5 = NULL;
	uint64_t root_dir_5 = 0;
	uint64_t attributes_5 = 0;
	struct win64_obj_attr *obj_attr_5 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[5], pid);
	if (NULL != obj_attr_5) {
		unicode_str_5 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_5->object_name, pid);
		root_dir_5 = obj_attr_5->root_directory;
		attributes_5 = obj_attr_5->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcOpenSenderProcess(PortHandle: 0x%lx, PortMessage: 0x%lx, DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, args[1], args[2], permissions_4, args[4], root_dir_5, unicode_str_5, attributes_5);
	free(permissions_4);
	free(unicode_str_5);
	free(obj_attr_5);	return args;
}

void gt_windows_print_sysret_ntalpcopensenderprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ProcessHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntalpcopensenderthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_4 = vf_get_simple_permissions(args[4]);
	uint8_t *unicode_str_5 = NULL;
	uint64_t root_dir_5 = 0;
	uint64_t attributes_5 = 0;
	struct win64_obj_attr *obj_attr_5 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[5], pid);
	if (NULL != obj_attr_5) {
		unicode_str_5 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_5->object_name, pid);
		root_dir_5 = obj_attr_5->root_directory;
		attributes_5 = obj_attr_5->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcOpenSenderThread(PortHandle: 0x%lx, PortMessage: 0x%lx, DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, args[1], args[2], permissions_4, args[4], root_dir_5, unicode_str_5, attributes_5);
	free(permissions_4);
	free(unicode_str_5);
	free(obj_attr_5);	return args;
}

void gt_windows_print_sysret_ntalpcopensenderthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ThreadHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntalpcqueryinformation(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcQueryInformation(PortHandle: 0x%lx, PortInformationClass: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntalpcqueryinformation(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntalpcqueryinformationmessage(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcQueryInformationMessage(PortHandle: 0x%lx, PortMessage: 0x%lx, MessageInformationClass: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntalpcqueryinformationmessage(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntalpcrevokesecuritycontext(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcRevokeSecurityContext(PortHandle: 0x%lx, ContextHandle: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntalpcrevokesecuritycontext(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntalpcsendwaitreceiveport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcSendWaitReceivePort(PortHandle: 0x%lx, Flags: 0x%lx, SendMessage: 0x%lx, SendMessageAttributes: 0x%lx, ReceiveMessage: 0x%lx, BufferLength: 0x%lx, ReceiveMessageAttributes: 0x%lx, Timeout: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4], pulong_5, args[6], args[7]);
	return args;
}

void gt_windows_print_sysret_ntalpcsendwaitreceiveport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReceiveMessage: 0x%lx, BufferLength: 0x%lx, ReceiveMessageAttributes: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[4], pulong_5, args[6]);
	free(args);
}

void *gt_windows_print_syscall_ntalpcsetinformation(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAlpcSetInformation(PortHandle: 0x%lx, PortInformationClass: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntalpcsetinformation(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntapphelpcachecontrol(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtApphelpCacheControl(type: 0x%lx, buf: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntapphelpcachecontrol(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntaremappedfilesthesame(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAreMappedFilesTheSame(File1MappedAsAnImage: 0x%lx, File2MappedAsFile: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntaremappedfilesthesame(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntassignprocesstojobobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtAssignProcessToJobObject(JobHandle: 0x%lx, ProcessHandle: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntassignprocesstojobobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntcallbackreturn(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCallbackReturn(OutputBuffer: 0x%lx, OutputLength: 0x%lx, Status: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntcallbackreturn(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntcanceliofileex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCancelIoFileEx(FileHandle: 0x%lx, IoRequestToCancel: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntcanceliofileex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntcanceliofile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCancelIoFile(FileHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntcanceliofile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntcancelsynchronousiofile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCancelSynchronousIoFile(ThreadHandle: 0x%lx, IoRequestToCancel: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntcancelsynchronousiofile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntcanceltimer(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCancelTimer(TimerHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntcanceltimer(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(CurrentState: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntclearevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtClearEvent(EventHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntclearevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntclose(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtClose(Handle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntclose(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntcloseobjectauditalarm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	char *bool_2 = args[2] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCloseObjectAuditAlarm(SubsystemName: %s, HandleId: 0x%lx, GenerateOnClose: %s)\n", pid, tid, proc, unicode_str_0, args[1], bool_2);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntcloseobjectauditalarm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntcommitcomplete(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCommitComplete(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntcommitcomplete(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntcommitenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCommitEnlistment(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntcommitenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntcommittransaction(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_1 = args[1] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCommitTransaction(TransactionHandle: 0x%lx, Wait: %s)\n", pid, tid, proc, args[0], bool_1);
	return args;
}

void gt_windows_print_sysret_ntcommittransaction(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntcompactkeys(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCompactKeys(Count: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntcompactkeys(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntcomparetokens(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCompareTokens(FirstTokenHandle: 0x%lx, SecondTokenHandle: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntcomparetokens(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Equal: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntcompleteconnectport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCompleteConnectPort(PortHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntcompleteconnectport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntcompresskey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCompressKey(Key: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntcompresskey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntconnectport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	uint64_t pulong_7 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[7], pid, &pulong_7);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtConnectPort(PortName: %s, SecurityQos: 0x%lx, ClientView: 0x%lx, ServerView: 0x%lx, ConnectionInformation: 0x%lx, ConnectionInformationLength: 0x%lx)\n", pid, tid, proc, unicode_str_1, args[2], args[3], args[4], args[6], pulong_7);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntconnectport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	uint64_t pulong_7 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[7], pid, &pulong_7);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PortHandle: 0x%lx, ClientView: 0x%lx, ServerView: 0x%lx, MaxMessageLength: 0x%lx, ConnectionInformation: 0x%lx, ConnectionInformationLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0, args[3], args[4], pulong_5, args[6], pulong_7);
	free(args);
}

void *gt_windows_print_syscall_ntcontinue(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtContinue()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntcontinue(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	char *bool_1 = args[1] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ContextRecord: 0x%lx, TestAlert: %s)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[0], bool_1);
	free(args);
}

void *gt_windows_print_syscall_ntcreatedebugobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateDebugObject()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntcreatedebugobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(DebugObjectHandle: 0x%lx, DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	free(args);
}

void *gt_windows_print_syscall_ntcreatedirectoryobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateDirectoryObject(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatedirectoryobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(DirectoryHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_4 = NULL;
	uint64_t root_dir_4 = 0;
	uint64_t attributes_4 = 0;
	struct win64_obj_attr *obj_attr_4 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[4], pid);
	if (NULL != obj_attr_4) {
		unicode_str_4 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_4->object_name, pid);
		root_dir_4 = obj_attr_4->root_directory;
		attributes_4 = obj_attr_4->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateEnlistment(DesiredAccess: %s [0x%lx], ResourceManagerHandle: 0x%lx, TransactionHandle: 0x%lx, ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, CreateOptions: 0x%lx, NotificationMask: 0x%lx, EnlistmentKey: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], args[2], args[3], root_dir_4, unicode_str_4, attributes_4, args[5], args[6], args[7]);
	free(permissions_1);
	free(unicode_str_4);
	free(obj_attr_4);	return args;
}

void gt_windows_print_sysret_ntcreateenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(EnlistmentHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	char *bool_4 = args[4] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateEvent(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, EventType: 0x%lx, InitialState: %s)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], bool_4);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreateevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(EventHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateeventpair(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateEventPair(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreateeventpair(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(EventPairHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatefile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateFile(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, AllocationSize: 0x%lx, FileAttributes: 0x%lx, ShareAccess: 0x%lx, CreateDisposition: 0x%lx, CreateOptions: 0x%lx, EaLength: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[4], args[5], args[6], args[7], args[8], args[10]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatefile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(FileHandle: 0x%lx, IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0, args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntcreateiocompletion(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateIoCompletion(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Count: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreateiocompletion(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoCompletionHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatejobobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateJobObject(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatejobobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(JobHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatejobset(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateJobSet(NumJob: 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntcreatejobset(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntcreatekeyedevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateKeyedEvent(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatekeyedevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(KeyedEventHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	uint8_t *unicode_str_4 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[4], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateKey(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Class: %s, CreateOptions: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, unicode_str_4, args[5]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);
	free(unicode_str_4);	return args;
}

void gt_windows_print_sysret_ntcreatekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	uint64_t pulong_6 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[6], pid, &pulong_6);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(KeyHandle: 0x%lx, Disposition: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0, pulong_6);
	free(args);
}

void *gt_windows_print_syscall_ntcreatekeytransacted(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	uint8_t *unicode_str_4 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[4], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateKeyTransacted(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Class: %s, CreateOptions: 0x%lx, TransactionHandle: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, unicode_str_4, args[5], args[6]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);
	free(unicode_str_4);	return args;
}

void gt_windows_print_sysret_ntcreatekeytransacted(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	uint64_t pulong_7 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[7], pid, &pulong_7);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(KeyHandle: 0x%lx, Disposition: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0, pulong_7);
	free(args);
}

void *gt_windows_print_syscall_ntcreatemailslotfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateMailslotFile(DesiredAccess: 0x%lx, ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, CreateOptions: 0x%lx, MailslotQuota: 0x%lx, MaximumMessageSize: 0x%lx, ReadTimeout: 0x%lx)\n", pid, tid, proc, args[1], root_dir_2, unicode_str_2, attributes_2, args[4], args[5], args[6], args[7]);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatemailslotfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(FileHandle: 0x%lx, IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0, args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntcreatemutant(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	char *bool_3 = args[3] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateMutant(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, InitialOwner: %s)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, bool_3);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatemutant(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(MutantHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatenamedpipefile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateNamedPipeFile(DesiredAccess: 0x%lx, ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, ShareAccess: 0x%lx, CreateDisposition: 0x%lx, CreateOptions: 0x%lx, NamedPipeType: 0x%lx, ReadMode: 0x%lx, CompletionMode: 0x%lx, MaximumInstances: 0x%lx, InboundQuota: 0x%lx, OutboundQuota: 0x%lx, DefaultTimeout: 0x%lx)\n", pid, tid, proc, args[1], root_dir_2, unicode_str_2, attributes_2, args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13]);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatenamedpipefile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(FileHandle: 0x%lx, IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0, args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntcreatepagingfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreatePagingFile(PageFileName: %s, MinimumSize: 0x%lx, MaximumSize: 0x%lx, Priority: 0x%lx)\n", pid, tid, proc, unicode_str_0, args[1], args[2], args[3]);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntcreatepagingfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntcreateport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_1 = NULL;
	uint64_t root_dir_1 = 0;
	uint64_t attributes_1 = 0;
	struct win64_obj_attr *obj_attr_1 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	if (NULL != obj_attr_1) {
		unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_1->object_name, pid);
		root_dir_1 = obj_attr_1->root_directory;
		attributes_1 = obj_attr_1->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreatePort(ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, MaxConnectionInfoLength: 0x%lx, MaxMessageLength: 0x%lx, MaxPoolUsage: 0x%lx)\n", pid, tid, proc, root_dir_1, unicode_str_1, attributes_1, args[2], args[3], args[4]);
	free(unicode_str_1);
	free(obj_attr_1);	return args;
}

void gt_windows_print_sysret_ntcreateport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PortHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateprivatenamespace(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreatePrivateNamespace(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, BoundaryDescriptor: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreateprivatenamespace(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NamespaceHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateprocessex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateProcessEx(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, ParentProcess: 0x%lx, Flags: 0x%lx, SectionHandle: 0x%lx, DebugPort: 0x%lx, ExceptionPort: 0x%lx, JobMemberLevel: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[4], args[5], args[6], args[7], args[8]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreateprocessex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ProcessHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	char *bool_4 = args[4] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateProcess(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, ParentProcess: 0x%lx, InheritObjectTable: %s, SectionHandle: 0x%lx, DebugPort: 0x%lx, ExceptionPort: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], bool_4, args[5], args[6], args[7]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreateprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ProcessHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateprofileex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateProfileEx(Process: 0x%lx, ProfileBase: 0x%lx, ProfileSize: 0x%lx, BucketSize: 0x%lx, Buffer: 0x%lx, BufferSize: 0x%lx, ProfileSource: 0x%lx, GroupAffinityCount: 0x%lx, GroupAffinity: 0x%lx)\n", pid, tid, proc, args[1], args[2], args[3], args[4], pulong_5, args[6], args[7], args[8], args[9]);
	return args;
}

void gt_windows_print_sysret_ntcreateprofileex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ProfileHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateprofile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateProfile(Process: 0x%lx, RangeBase: 0x%lx, RangeSize: 0x%lx, BucketSize: 0x%lx, Buffer: 0x%lx, BufferSize: 0x%lx, ProfileSource: 0x%lx, Affinity: 0x%lx)\n", pid, tid, proc, args[1], args[2], args[3], args[4], pulong_5, args[6], args[7], args[8]);
	return args;
}

void gt_windows_print_sysret_ntcreateprofile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ProfileHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateresourcemanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_4 = NULL;
	uint64_t root_dir_4 = 0;
	uint64_t attributes_4 = 0;
	struct win64_obj_attr *obj_attr_4 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[4], pid);
	if (NULL != obj_attr_4) {
		unicode_str_4 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_4->object_name, pid);
		root_dir_4 = obj_attr_4->root_directory;
		attributes_4 = obj_attr_4->attributes;
	}
	uint8_t *unicode_str_6 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[6], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateResourceManager(DesiredAccess: %s [0x%lx], TmHandle: 0x%lx, RmGuid: 0x%lx, ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, CreateOptions: 0x%lx, Description: %s)\n", pid, tid, proc, permissions_1, args[1], args[2], args[3], root_dir_4, unicode_str_4, attributes_4, args[5], unicode_str_6);
	free(permissions_1);
	free(unicode_str_4);
	free(obj_attr_4);
	free(unicode_str_6);	return args;
}

void gt_windows_print_sysret_ntcreateresourcemanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ResourceManagerHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatesection(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateSection(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, MaximumSize: 0x%lx, SectionPageProtection: 0x%lx, AllocationAttributes: 0x%lx, FileHandle: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[4], args[5], args[6]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatesection(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(SectionHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatesemaphore(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateSemaphore(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, InitialCount: 0x%lx, MaximumCount: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[4]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatesemaphore(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(SemaphoreHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatesymboliclinkobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	uint8_t *unicode_str_3 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[3], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateSymbolicLinkObject(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, LinkTarget: %s)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, unicode_str_3);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);
	free(unicode_str_3);	return args;
}

void gt_windows_print_sysret_ntcreatesymboliclinkobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(LinkHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatethreadex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateThreadEx(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, ProcessHandle: 0x%lx, StartRoutine: 0x%lx, Argument: 0x%lx, CreateFlags: 0x%lx, ZeroBits: 0x%lx, StackSize: 0x%lx, MaximumStackSize: 0x%lx, AttributeList: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatethreadex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ThreadHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatethread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	char *bool_7 = args[7] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateThread(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, ProcessHandle: 0x%lx, ThreadContext: 0x%lx, InitialTeb: 0x%lx, CreateSuspended: %s)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[5], args[6], bool_7);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatethread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ThreadHandle: 0x%lx, ClientId: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0, args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntcreatetimer(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateTimer(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, TimerType: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatetimer(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TimerHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatetoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateToken(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, TokenType: 0x%lx, AuthenticationId: 0x%lx, ExpirationTime: 0x%lx, User: 0x%lx, Groups: 0x%lx, Privileges: 0x%lx, Owner: 0x%lx, PrimaryGroup: 0x%lx, DefaultDacl: 0x%lx, TokenSource: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreatetoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TokenHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatetransactionmanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	uint8_t *unicode_str_3 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[3], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateTransactionManager(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, LogFileName: %s, CreateOptions: 0x%lx, CommitStrength: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, unicode_str_3, args[4], args[5]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);
	free(unicode_str_3);	return args;
}

void gt_windows_print_sysret_ntcreatetransactionmanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TmHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreatetransaction(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	uint8_t *unicode_str_9 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[9], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateTransaction(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Uow: 0x%lx, TmHandle: 0x%lx, CreateOptions: 0x%lx, IsolationLevel: 0x%lx, IsolationFlags: 0x%lx, Timeout: 0x%lx, Description: %s)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[4], args[5], args[6], args[7], args[8], unicode_str_9);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);
	free(unicode_str_9);	return args;
}

void gt_windows_print_sysret_ntcreatetransaction(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TransactionHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateuserprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_2 = vf_get_simple_permissions(args[2]);
	char *permissions_3 = vf_get_simple_permissions(args[3]);
	uint8_t *unicode_str_4 = NULL;
	uint64_t root_dir_4 = 0;
	uint64_t attributes_4 = 0;
	struct win64_obj_attr *obj_attr_4 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[4], pid);
	if (NULL != obj_attr_4) {
		unicode_str_4 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_4->object_name, pid);
		root_dir_4 = obj_attr_4->root_directory;
		attributes_4 = obj_attr_4->attributes;
	}
	uint8_t *unicode_str_5 = NULL;
	uint64_t root_dir_5 = 0;
	uint64_t attributes_5 = 0;
	struct win64_obj_attr *obj_attr_5 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[5], pid);
	if (NULL != obj_attr_5) {
		unicode_str_5 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_5->object_name, pid);
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

void gt_windows_print_sysret_ntcreateuserprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	uint64_t phandle_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &phandle_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ProcessHandle: 0x%lx, ThreadHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0, phandle_1);
	free(args);
}

void *gt_windows_print_syscall_ntcreatewaitableport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_1 = NULL;
	uint64_t root_dir_1 = 0;
	uint64_t attributes_1 = 0;
	struct win64_obj_attr *obj_attr_1 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	if (NULL != obj_attr_1) {
		unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_1->object_name, pid);
		root_dir_1 = obj_attr_1->root_directory;
		attributes_1 = obj_attr_1->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateWaitablePort(ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, MaxConnectionInfoLength: 0x%lx, MaxMessageLength: 0x%lx, MaxPoolUsage: 0x%lx)\n", pid, tid, proc, root_dir_1, unicode_str_1, attributes_1, args[2], args[3], args[4]);
	free(unicode_str_1);
	free(obj_attr_1);	return args;
}

void gt_windows_print_sysret_ntcreatewaitableport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PortHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntcreateworkerfactory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtCreateWorkerFactory(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, CompletionPortHandle: 0x%lx, WorkerProcessHandle: 0x%lx, StartRoutine: 0x%lx, StartParameter: 0x%lx, MaxThreadCount: 0x%lx, StackReserve: 0x%lx, StackCommit: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[4], args[5], args[6], args[7], args[8], args[9]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntcreateworkerfactory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(WorkerFactoryHandleReturn: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntdebugactiveprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDebugActiveProcess()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntdebugactiveprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ProcessHandle: 0x%lx, DebugObjectHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[0], args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntdebugcontinue(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDebugContinue()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntdebugcontinue(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(DebugObjectHandle: 0x%lx, ClientId: 0x%lx, ContinueStatus: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[0], args[1], args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntdelayexecution(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_0 = args[0] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDelayExecution(Alertable: %s, DelayInterval: 0x%lx)\n", pid, tid, proc, bool_0, args[1]);
	return args;
}

void gt_windows_print_sysret_ntdelayexecution(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntdeleteatom(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDeleteAtom(Atom: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntdeleteatom(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntdeletebootentry(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDeleteBootEntry(Id: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntdeletebootentry(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntdeletedriverentry(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDeleteDriverEntry(Id: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntdeletedriverentry(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntdeletefile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDeleteFile(ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0);
	free(unicode_str_0);
	free(obj_attr_0);	return args;
}

void gt_windows_print_sysret_ntdeletefile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntdeletekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDeleteKey(KeyHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntdeletekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntdeleteobjectauditalarm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	char *bool_2 = args[2] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDeleteObjectAuditAlarm(SubsystemName: %s, HandleId: 0x%lx, GenerateOnClose: %s)\n", pid, tid, proc, unicode_str_0, args[1], bool_2);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntdeleteobjectauditalarm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntdeleteprivatenamespace(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDeletePrivateNamespace(NamespaceHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntdeleteprivatenamespace(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntdeletevaluekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDeleteValueKey(KeyHandle: 0x%lx, ValueName: %s)\n", pid, tid, proc, args[0], unicode_str_1);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntdeletevaluekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntdeviceiocontrolfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDeviceIoControlFile(FileHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, IoControlCode: 0x%lx, InputBufferLength: 0x%lx, OutputBufferLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[5], args[7], args[9]);
	return args;
}

void gt_windows_print_sysret_ntdeviceiocontrolfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntdisablelastknowngood(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDisableLastKnownGood()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntdisablelastknowngood(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntdisplaystring(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDisplayString(String: %s)\n", pid, tid, proc, unicode_str_0);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntdisplaystring(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntdrawtext(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDrawText(Text: %s)\n", pid, tid, proc, unicode_str_0);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntdrawtext(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntduplicateobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_4 = vf_get_simple_permissions(args[4]);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDuplicateObject(SourceProcessHandle: 0x%lx, SourceHandle: 0x%lx, TargetProcessHandle: 0x%lx, DesiredAccess: %s [0x%lx], HandleAttributes: 0x%lx, Options: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], permissions_4, args[4], args[5], args[6]);
	free(permissions_4);	return args;
}

void gt_windows_print_sysret_ntduplicateobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_3 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[3], pid, &phandle_3);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TargetHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_3);
	free(args);
}

void *gt_windows_print_syscall_ntduplicatetoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	char *bool_3 = args[3] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtDuplicateToken(ExistingTokenHandle: 0x%lx, DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, EffectiveOnly: %s, TokenType: 0x%lx)\n", pid, tid, proc, args[0], permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, bool_3, args[4]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntduplicatetoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &phandle_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NewTokenHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_5);
	free(args);
}

void *gt_windows_print_syscall_ntenablelastknowngood(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtEnableLastKnownGood()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntenablelastknowngood(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntenumeratebootentries(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtEnumerateBootEntries(BufferLength: 0x%lx)\n", pid, tid, proc, pulong_1);
	return args;
}

void gt_windows_print_sysret_ntenumeratebootentries(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(BufferLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntenumeratedriverentries(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtEnumerateDriverEntries(BufferLength: 0x%lx)\n", pid, tid, proc, pulong_1);
	return args;
}

void gt_windows_print_sysret_ntenumeratedriverentries(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(BufferLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntenumeratekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtEnumerateKey(KeyHandle: 0x%lx, Index: 0x%lx, KeyInformationClass: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntenumeratekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ResultLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntenumeratesystemenvironmentvaluesex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint64_t pulong_2 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[2], pid, &pulong_2);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtEnumerateSystemEnvironmentValuesEx(InformationClass: 0x%lx, BufferLength: 0x%lx)\n", pid, tid, proc, args[0], pulong_2);
	return args;
}

void gt_windows_print_sysret_ntenumeratesystemenvironmentvaluesex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_2 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[2], pid, &pulong_2);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Buffer: 0x%lx, BufferLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1], pulong_2);
	free(args);
}

void *gt_windows_print_syscall_ntenumeratetransactionobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtEnumerateTransactionObject(RootObjectHandle: 0x%lx, QueryType: 0x%lx, ObjectCursorLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntenumeratetransactionobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntenumeratevaluekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtEnumerateValueKey(KeyHandle: 0x%lx, Index: 0x%lx, KeyValueInformationClass: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntenumeratevaluekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ResultLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntextendsection(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtExtendSection(SectionHandle: 0x%lx, NewSectionSize: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntextendsection(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NewSectionSize: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntfiltertoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFilterToken(ExistingTokenHandle: 0x%lx, Flags: 0x%lx, SidsToDisable: 0x%lx, PrivilegesToDelete: 0x%lx, RestrictedSids: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4]);
	return args;
}

void gt_windows_print_sysret_ntfiltertoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &phandle_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NewTokenHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_5);
	free(args);
}

void *gt_windows_print_syscall_ntfindatom(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFindAtom(Length: 0x%lx)\n", pid, tid, proc, args[1]);
	return args;
}

void gt_windows_print_sysret_ntfindatom(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Atom: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntflushbuffersfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFlushBuffersFile(FileHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntflushbuffersfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntflushinstalluilanguage(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFlushInstallUILanguage(InstallUILanguage: 0x%lx, SetComittedFlag: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntflushinstalluilanguage(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntflushinstructioncache(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFlushInstructionCache(ProcessHandle: 0x%lx, BaseAddress: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntflushinstructioncache(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntflushkey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFlushKey(KeyHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntflushkey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntflushprocesswritebuffers(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFlushProcessWriteBuffers()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntflushprocesswritebuffers(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntflushvirtualmemory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFlushVirtualMemory(ProcessHandle: 0x%lx, *BaseAddress: 0x%lx, RegionSize: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntflushvirtualmemory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*BaseAddress: 0x%lx, RegionSize: 0x%lx, IoStatus: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1], args[2], args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntflushwritebuffer(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFlushWriteBuffer()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntflushwritebuffer(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntfreeuserphysicalpages(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFreeUserPhysicalPages(ProcessHandle: 0x%lx, NumberOfPages: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntfreeuserphysicalpages(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NumberOfPages: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntfreevirtualmemory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFreeVirtualMemory(ProcessHandle: 0x%lx, *BaseAddress: 0x%lx, RegionSize: 0x%lx, FreeType: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3]);
	return args;
}

void gt_windows_print_sysret_ntfreevirtualmemory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*BaseAddress: 0x%lx, RegionSize: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1], args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntfreezeregistry(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFreezeRegistry(TimeOutInSeconds: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntfreezeregistry(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntfreezetransactions(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFreezeTransactions(FreezeTimeout: 0x%lx, ThawTimeout: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntfreezetransactions(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntfscontrolfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtFsControlFile(FileHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, IoControlCode: 0x%lx, InputBufferLength: 0x%lx, OutputBufferLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[5], args[7], args[9]);
	return args;
}

void gt_windows_print_sysret_ntfscontrolfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntgetcontextthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetContextThread(ThreadHandle: 0x%lx, ThreadContext: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntgetcontextthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ThreadContext: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntgetcurrentprocessornumber(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetCurrentProcessorNumber()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntgetcurrentprocessornumber(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntgetdevicepowerstate(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetDevicePowerState(Device: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntgetdevicepowerstate(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*State: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntgetmuiregistryinfo(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetMUIRegistryInfo(Flags: 0x%lx, DataSize: 0x%lx)\n", pid, tid, proc, args[0], pulong_1);
	return args;
}

void gt_windows_print_sysret_ntgetmuiregistryinfo(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(DataSize: 0x%lx, Data: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_1, args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntgetnextprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetNextProcess(ProcessHandle: 0x%lx, DesiredAccess: %s [0x%lx], HandleAttributes: 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, args[0], permissions_1, args[1], args[2], args[3]);
	free(permissions_1);	return args;
}

void gt_windows_print_sysret_ntgetnextprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &phandle_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NewProcessHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_4);
	free(args);
}

void *gt_windows_print_syscall_ntgetnextthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_2 = vf_get_simple_permissions(args[2]);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetNextThread(ProcessHandle: 0x%lx, ThreadHandle: 0x%lx, DesiredAccess: %s [0x%lx], HandleAttributes: 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, args[0], args[1], permissions_2, args[2], args[3], args[4]);
	free(permissions_2);	return args;
}

void gt_windows_print_sysret_ntgetnextthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &phandle_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NewThreadHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_5);
	free(args);
}

void *gt_windows_print_syscall_ntgetnlssectionptr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetNlsSectionPtr(SectionType: 0x%lx, SectionData: 0x%lx, ContextData: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntgetnlssectionptr(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*SectionPointer: 0x%lx, SectionSize: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[3], pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntgetnotificationresourcemanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetNotificationResourceManager(ResourceManagerHandle: 0x%lx, NotificationLength: 0x%lx, Timeout: 0x%lx, Asynchronous: 0x%lx, AsynchronousContext: 0x%lx)\n", pid, tid, proc, args[0], args[2], args[3], args[5], args[6]);
	return args;
}

void gt_windows_print_sysret_ntgetnotificationresourcemanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TransactionNotification: 0x%lx, ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1], pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntgetplugplayevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetPlugPlayEvent(EventHandle: 0x%lx, Context: 0x%lx, EventBufferSize: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntgetplugplayevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntgetwritewatch(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtGetWriteWatch(ProcessHandle: 0x%lx, Flags: 0x%lx, BaseAddress: 0x%lx, RegionSize: 0x%lx, EntriesInUserAddressArray: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[5]);
	return args;
}

void gt_windows_print_sysret_ntgetwritewatch(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_6 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[6], pid, &pulong_6);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(EntriesInUserAddressArray: 0x%lx, Granularity: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[5], pulong_6);
	free(args);
}

void *gt_windows_print_syscall_ntimpersonateanonymoustoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtImpersonateAnonymousToken(ThreadHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntimpersonateanonymoustoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntimpersonateclientofport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtImpersonateClientOfPort(PortHandle: 0x%lx, Message: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntimpersonateclientofport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntimpersonatethread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtImpersonateThread(ServerThreadHandle: 0x%lx, ClientThreadHandle: 0x%lx, SecurityQos: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntimpersonatethread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntinitializenlsfiles(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtInitializeNlsFiles()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntinitializenlsfiles(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*BaseAddress: 0x%lx, DefaultLocaleId: 0x%lx, DefaultCasingTableSize: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[0], args[1], args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntinitializeregistry(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtInitializeRegistry(BootCondition: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntinitializeregistry(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntinitiatepoweraction(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_3 = args[3] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtInitiatePowerAction(SystemAction: 0x%lx, MinSystemState: 0x%lx, Flags: 0x%lx, Asynchronous: %s)\n", pid, tid, proc, args[0], args[1], args[2], bool_3);
	return args;
}

void gt_windows_print_sysret_ntinitiatepoweraction(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntisprocessinjob(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtIsProcessInJob(ProcessHandle: 0x%lx, JobHandle: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntisprocessinjob(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntissystemresumeautomatic(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtIsSystemResumeAutomatic()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntissystemresumeautomatic(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntisuilanguagecomitted(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtIsUILanguageComitted()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntisuilanguagecomitted(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntlistenport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtListenPort(PortHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntlistenport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ConnectionRequest: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntloaddriver(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtLoadDriver(DriverServiceName: %s)\n", pid, tid, proc, unicode_str_0);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntloaddriver(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntloadkey2(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	uint8_t *unicode_str_1 = NULL;
	uint64_t root_dir_1 = 0;
	uint64_t attributes_1 = 0;
	struct win64_obj_attr *obj_attr_1 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	if (NULL != obj_attr_1) {
		unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_1->object_name, pid);
		root_dir_1 = obj_attr_1->root_directory;
		attributes_1 = obj_attr_1->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtLoadKey2(TargetKey: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, SourceFile: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0, root_dir_1, unicode_str_1, attributes_1, args[2]);
	free(unicode_str_0);
	free(obj_attr_0);
	free(unicode_str_1);
	free(obj_attr_1);	return args;
}

void gt_windows_print_sysret_ntloadkey2(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntloadkeyex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	uint8_t *unicode_str_1 = NULL;
	uint64_t root_dir_1 = 0;
	uint64_t attributes_1 = 0;
	struct win64_obj_attr *obj_attr_1 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	if (NULL != obj_attr_1) {
		unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_1->object_name, pid);
		root_dir_1 = obj_attr_1->root_directory;
		attributes_1 = obj_attr_1->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtLoadKeyEx(TargetKey: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, SourceFile: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Flags: 0x%lx, TrustClassKey: 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0, root_dir_1, unicode_str_1, attributes_1, args[2], args[3]);
	free(unicode_str_0);
	free(obj_attr_0);
	free(unicode_str_1);
	free(obj_attr_1);	return args;
}

void gt_windows_print_sysret_ntloadkeyex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntloadkey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	uint8_t *unicode_str_1 = NULL;
	uint64_t root_dir_1 = 0;
	uint64_t attributes_1 = 0;
	struct win64_obj_attr *obj_attr_1 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	if (NULL != obj_attr_1) {
		unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_1->object_name, pid);
		root_dir_1 = obj_attr_1->root_directory;
		attributes_1 = obj_attr_1->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtLoadKey(TargetKey: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, SourceFile: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0, root_dir_1, unicode_str_1, attributes_1);
	free(unicode_str_0);
	free(obj_attr_0);
	free(unicode_str_1);
	free(obj_attr_1);	return args;
}

void gt_windows_print_sysret_ntloadkey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntlockfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_8 = args[8] ? "TRUE" : "FALSE";
	char *bool_9 = args[9] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtLockFile(FileHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, ByteOffset: 0x%lx, Length: 0x%lx, Key: 0x%lx, FailImmediately: %s, ExclusiveLock: %s)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[5], args[6], args[7], bool_8, bool_9);
	return args;
}

void gt_windows_print_sysret_ntlockfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntlockproductactivationkeys(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtLockProductActivationKeys(*pPrivateVer: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntlockproductactivationkeys(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*pPrivateVer: 0x%lx, *pSafeMode: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[0], args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntlockregistrykey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtLockRegistryKey(KeyHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntlockregistrykey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntlockvirtualmemory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtLockVirtualMemory(ProcessHandle: 0x%lx, *BaseAddress: 0x%lx, RegionSize: 0x%lx, MapType: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3]);
	return args;
}

void gt_windows_print_sysret_ntlockvirtualmemory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*BaseAddress: 0x%lx, RegionSize: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1], args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntmakepermanentobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtMakePermanentObject(Handle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntmakepermanentobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntmaketemporaryobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtMakeTemporaryObject(Handle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntmaketemporaryobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntmapcmfmodule(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtMapCMFModule(What: 0x%lx, Index: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntmapcmfmodule(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_2 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[2], pid, &pulong_2);
	uint64_t pulong_3 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[3], pid, &pulong_3);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(CacheIndexOut: 0x%lx, CacheFlagsOut: 0x%lx, ViewSizeOut: 0x%lx, *BaseAddress: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_2, pulong_3, pulong_4, args[5]);
	free(args);
}

void *gt_windows_print_syscall_ntmapuserphysicalpages(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtMapUserPhysicalPages(VirtualAddress: 0x%lx, NumberOfPages: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntmapuserphysicalpages(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntmapuserphysicalpagesscatter(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtMapUserPhysicalPagesScatter(NumberOfPages: 0x%lx)\n", pid, tid, proc, args[1]);
	return args;
}

void gt_windows_print_sysret_ntmapuserphysicalpagesscatter(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntmapviewofsection(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtMapViewOfSection(SectionHandle: 0x%lx, ProcessHandle: 0x%lx, *BaseAddress: 0x%lx, ZeroBits: 0x%lx, CommitSize: 0x%lx, SectionOffset: 0x%lx, ViewSize: 0x%lx, InheritDisposition: 0x%lx, AllocationType: 0x%lx, Win32Protect: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9]);
	return args;
}

void gt_windows_print_sysret_ntmapviewofsection(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*BaseAddress: 0x%lx, SectionOffset: 0x%lx, ViewSize: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[2], args[5], args[6]);
	free(args);
}

void *gt_windows_print_syscall_ntmodifybootentry(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtModifyBootEntry(BootEntry: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntmodifybootentry(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntmodifydriverentry(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtModifyDriverEntry(DriverEntry: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntmodifydriverentry(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntnotifychangedirectoryfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_8 = args[8] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtNotifyChangeDirectoryFile(FileHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, Length: 0x%lx, CompletionFilter: 0x%lx, WatchTree: %s)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[6], args[7], bool_8);
	return args;
}

void gt_windows_print_sysret_ntnotifychangedirectoryfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntnotifychangekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_6 = args[6] ? "TRUE" : "FALSE";
	char *bool_9 = args[9] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtNotifyChangeKey(KeyHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, CompletionFilter: 0x%lx, WatchTree: %s, BufferSize: 0x%lx, Asynchronous: %s)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[5], bool_6, args[8], bool_9);
	return args;
}

void gt_windows_print_sysret_ntnotifychangekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntnotifychangemultiplekeys(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_8 = args[8] ? "TRUE" : "FALSE";
	char *bool_11 = args[11] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtNotifyChangeMultipleKeys(MasterKeyHandle: 0x%lx, Count: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, CompletionFilter: 0x%lx, WatchTree: %s, BufferSize: 0x%lx, Asynchronous: %s)\n", pid, tid, proc, args[0], args[1], args[3], args[4], args[5], args[7], bool_8, args[10], bool_11);
	return args;
}

void gt_windows_print_sysret_ntnotifychangemultiplekeys(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[6]);
	free(args);
}

void *gt_windows_print_syscall_ntnotifychangesession(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtNotifyChangeSession(Session: 0x%lx, IoStateSequence: 0x%lx, Reserved: 0x%lx, Action: 0x%lx, IoState: 0x%lx, IoState2: 0x%lx, Buffer: 0x%lx, BufferSize: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
	return args;
}

void gt_windows_print_sysret_ntnotifychangesession(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntopendirectoryobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenDirectoryObject(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopendirectoryobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(DirectoryHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_4 = NULL;
	uint64_t root_dir_4 = 0;
	uint64_t attributes_4 = 0;
	struct win64_obj_attr *obj_attr_4 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[4], pid);
	if (NULL != obj_attr_4) {
		unicode_str_4 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_4->object_name, pid);
		root_dir_4 = obj_attr_4->root_directory;
		attributes_4 = obj_attr_4->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenEnlistment(DesiredAccess: %s [0x%lx], ResourceManagerHandle: 0x%lx, EnlistmentGuid: 0x%lx, ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], args[2], args[3], root_dir_4, unicode_str_4, attributes_4);
	free(permissions_1);
	free(unicode_str_4);
	free(obj_attr_4);	return args;
}

void gt_windows_print_sysret_ntopenenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(EnlistmentHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenEvent(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(EventHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopeneventpair(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenEventPair(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopeneventpair(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(EventPairHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenFile(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, ShareAccess: 0x%lx, OpenOptions: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[4], args[5]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(FileHandle: 0x%lx, IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0, args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntopeniocompletion(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenIoCompletion(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopeniocompletion(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoCompletionHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenjobobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenJobObject(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenjobobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(JobHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenkeyedevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenKeyedEvent(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenkeyedevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(KeyedEventHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenkeyex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenKeyEx(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, OpenOptions: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenkeyex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(KeyHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenkey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenKey(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenkey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(KeyHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenkeytransactedex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenKeyTransactedEx(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, OpenOptions: 0x%lx, TransactionHandle: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[4]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenkeytransactedex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(KeyHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenkeytransacted(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenKeyTransacted(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, TransactionHandle: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenkeytransacted(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(KeyHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenmutant(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenMutant(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenmutant(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(MutantHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenobjectauditalarm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	uint8_t *unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	uint8_t *unicode_str_3 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[3], pid);
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

void gt_windows_print_sysret_ntopenobjectauditalarm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(GenerateOnClose: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[11]);
	free(args);
}

void *gt_windows_print_syscall_ntopenprivatenamespace(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenPrivateNamespace(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, BoundaryDescriptor: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenprivatenamespace(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NamespaceHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenProcess(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, ClientId: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ProcessHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenprocesstokenex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenProcessTokenEx(ProcessHandle: 0x%lx, DesiredAccess: %s [0x%lx], HandleAttributes: 0x%lx)\n", pid, tid, proc, args[0], permissions_1, args[1], args[2]);
	free(permissions_1);	return args;
}

void gt_windows_print_sysret_ntopenprocesstokenex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_3 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[3], pid, &phandle_3);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TokenHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_3);
	free(args);
}

void *gt_windows_print_syscall_ntopenprocesstoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenProcessToken(ProcessHandle: 0x%lx, DesiredAccess: %s [0x%lx])\n", pid, tid, proc, args[0], permissions_1, args[1]);
	free(permissions_1);	return args;
}

void gt_windows_print_sysret_ntopenprocesstoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_2 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[2], pid, &phandle_2);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TokenHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_2);
	free(args);
}

void *gt_windows_print_syscall_ntopenresourcemanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_4 = NULL;
	uint64_t root_dir_4 = 0;
	uint64_t attributes_4 = 0;
	struct win64_obj_attr *obj_attr_4 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[4], pid);
	if (NULL != obj_attr_4) {
		unicode_str_4 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_4->object_name, pid);
		root_dir_4 = obj_attr_4->root_directory;
		attributes_4 = obj_attr_4->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenResourceManager(DesiredAccess: %s [0x%lx], TmHandle: 0x%lx, ResourceManagerGuid: 0x%lx, ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], args[2], args[3], root_dir_4, unicode_str_4, attributes_4);
	free(permissions_1);
	free(unicode_str_4);
	free(obj_attr_4);	return args;
}

void gt_windows_print_sysret_ntopenresourcemanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ResourceManagerHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopensection(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenSection(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopensection(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(SectionHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopensemaphore(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenSemaphore(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopensemaphore(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(SemaphoreHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopensession(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenSession(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopensession(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(SessionHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopensymboliclinkobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenSymbolicLinkObject(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopensymboliclinkobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(LinkHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenThread(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, ClientId: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopenthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ThreadHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopenthreadtokenex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	char *bool_2 = args[2] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenThreadTokenEx(ThreadHandle: 0x%lx, DesiredAccess: %s [0x%lx], OpenAsSelf: %s, HandleAttributes: 0x%lx)\n", pid, tid, proc, args[0], permissions_1, args[1], bool_2, args[3]);
	free(permissions_1);	return args;
}

void gt_windows_print_sysret_ntopenthreadtokenex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &phandle_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TokenHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_4);
	free(args);
}

void *gt_windows_print_syscall_ntopenthreadtoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	char *bool_2 = args[2] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenThreadToken(ThreadHandle: 0x%lx, DesiredAccess: %s [0x%lx], OpenAsSelf: %s)\n", pid, tid, proc, args[0], permissions_1, args[1], bool_2);
	free(permissions_1);	return args;
}

void gt_windows_print_sysret_ntopenthreadtoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_3 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[3], pid, &phandle_3);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TokenHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_3);
	free(args);
}

void *gt_windows_print_syscall_ntopentimer(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenTimer(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopentimer(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TimerHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopentransactionmanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	uint8_t *unicode_str_3 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[3], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenTransactionManager(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, LogFileName: %s, TmIdentity: 0x%lx, OpenOptions: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, unicode_str_3, args[4], args[5]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);
	free(unicode_str_3);	return args;
}

void gt_windows_print_sysret_ntopentransactionmanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TmHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntopentransaction(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *permissions_1 = vf_get_simple_permissions(args[1]);
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtOpenTransaction(DesiredAccess: %s [0x%lx], ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Uow: 0x%lx, TmHandle: 0x%lx)\n", pid, tid, proc, permissions_1, args[1], root_dir_2, unicode_str_2, attributes_2, args[3], args[4]);
	free(permissions_1);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntopentransaction(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(TransactionHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0);
	free(args);
}

void *gt_windows_print_syscall_ntplugplaycontrol(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPlugPlayControl(PnPControlClass: 0x%lx, PnPControlDataLength: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntplugplaycontrol(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntpowerinformation(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPowerInformation(InformationLevel: 0x%lx, InputBufferLength: 0x%lx, OutputBufferLength: 0x%lx)\n", pid, tid, proc, args[0], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntpowerinformation(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntpreparecomplete(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPrepareComplete(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntpreparecomplete(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntprepareenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPrepareEnlistment(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntprepareenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntprepreparecomplete(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPrePrepareComplete(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntprepreparecomplete(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntpreprepareenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPrePrepareEnlistment(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntpreprepareenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntprivilegecheck(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPrivilegeCheck(ClientToken: 0x%lx, RequiredPrivileges: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntprivilegecheck(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(RequiredPrivileges: 0x%lx, Result: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1], args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntprivilegedserviceauditalarm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	char *bool_4 = args[4] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPrivilegedServiceAuditAlarm(SubsystemName: %s, ServiceName: %s, ClientToken: 0x%lx, Privileges: 0x%lx, AccessGranted: %s)\n", pid, tid, proc, unicode_str_0, unicode_str_1, args[2], args[3], bool_4);
	free(unicode_str_0);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntprivilegedserviceauditalarm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntprivilegeobjectauditalarm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	char *permissions_3 = vf_get_simple_permissions(args[3]);
	char *bool_5 = args[5] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPrivilegeObjectAuditAlarm(SubsystemName: %s, HandleId: 0x%lx, ClientToken: 0x%lx, DesiredAccess: %s [0x%lx], Privileges: 0x%lx, AccessGranted: %s)\n", pid, tid, proc, unicode_str_0, args[1], args[2], permissions_3, args[3], args[4], bool_5);
	free(unicode_str_0);
	free(permissions_3);	return args;
}

void gt_windows_print_sysret_ntprivilegeobjectauditalarm(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntpropagationcomplete(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPropagationComplete(ResourceManagerHandle: 0x%lx, RequestCookie: 0x%lx, BufferLength: 0x%lx, Buffer: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3]);
	return args;
}

void gt_windows_print_sysret_ntpropagationcomplete(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntpropagationfailed(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPropagationFailed(ResourceManagerHandle: 0x%lx, RequestCookie: 0x%lx, PropStatus: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntpropagationfailed(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntprotectvirtualmemory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtProtectVirtualMemory(ProcessHandle: 0x%lx, *BaseAddress: 0x%lx, RegionSize: 0x%lx, NewProtectWin32: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3]);
	return args;
}

void gt_windows_print_sysret_ntprotectvirtualmemory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*BaseAddress: 0x%lx, RegionSize: 0x%lx, OldProtect: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1], args[2], pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntpulseevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtPulseEvent(EventHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntpulseevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousState: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntqueryattributesfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryAttributesFile(ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0);
	free(unicode_str_0);
	free(obj_attr_0);	return args;
}

void gt_windows_print_sysret_ntqueryattributesfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(FileInformation: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntquerybootentryorder(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryBootEntryOrder(Count: 0x%lx)\n", pid, tid, proc, pulong_1);
	return args;
}

void gt_windows_print_sysret_ntquerybootentryorder(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Count: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntquerybootoptions(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryBootOptions(BootOptionsLength: 0x%lx)\n", pid, tid, proc, pulong_1);
	return args;
}

void gt_windows_print_sysret_ntquerybootoptions(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(BootOptionsLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntquerydebugfilterstate(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryDebugFilterState(ComponentId: 0x%lx, Level: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntquerydebugfilterstate(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntquerydefaultlocale(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_0 = args[0] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryDefaultLocale(UserProfile: %s)\n", pid, tid, proc, bool_0);
	return args;
}

void gt_windows_print_sysret_ntquerydefaultlocale(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(DefaultLocaleId: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntquerydefaultuilanguage(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryDefaultUILanguage()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntquerydefaultuilanguage(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*DefaultUILanguageId: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[0]);
	free(args);
}

void *gt_windows_print_syscall_ntquerydirectoryfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_8 = args[8] ? "TRUE" : "FALSE";
	uint8_t *unicode_str_9 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[9], pid);
	char *bool_10 = args[10] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryDirectoryFile(FileHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, Length: 0x%lx, FileInformationClass: 0x%lx, ReturnSingleEntry: %s, FileName: %s, RestartScan: %s)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[6], args[7], bool_8, unicode_str_9, bool_10);
	free(unicode_str_9);	return args;
}

void gt_windows_print_sysret_ntquerydirectoryfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntquerydirectoryobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_3 = args[3] ? "TRUE" : "FALSE";
	char *bool_4 = args[4] ? "TRUE" : "FALSE";
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryDirectoryObject(DirectoryHandle: 0x%lx, Length: 0x%lx, ReturnSingleEntry: %s, RestartScan: %s, Context: 0x%lx)\n", pid, tid, proc, args[0], args[2], bool_3, bool_4, pulong_5);
	return args;
}

void gt_windows_print_sysret_ntquerydirectoryobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	uint64_t pulong_6 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[6], pid, &pulong_6);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Context: 0x%lx, ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_5, pulong_6);
	free(args);
}

void *gt_windows_print_syscall_ntquerydriverentryorder(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryDriverEntryOrder(Count: 0x%lx)\n", pid, tid, proc, pulong_1);
	return args;
}

void gt_windows_print_sysret_ntquerydriverentryorder(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Count: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntqueryeafile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_4 = args[4] ? "TRUE" : "FALSE";
	uint64_t pulong_7 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[7], pid, &pulong_7);
	char *bool_8 = args[8] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryEaFile(FileHandle: 0x%lx, Length: 0x%lx, ReturnSingleEntry: %s, EaListLength: 0x%lx, EaIndex: 0x%lx, RestartScan: %s)\n", pid, tid, proc, args[0], args[3], bool_4, args[6], pulong_7, bool_8);
	return args;
}

void gt_windows_print_sysret_ntqueryeafile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntqueryevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryEvent(EventHandle: 0x%lx, EventInformationClass: 0x%lx, EventInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryfullattributesfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryFullAttributesFile(ObjectAttributes: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0);
	free(unicode_str_0);
	free(obj_attr_0);	return args;
}

void gt_windows_print_sysret_ntqueryfullattributesfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(FileInformation: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationatom(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationAtom(Atom: 0x%lx, InformationClass: 0x%lx, AtomInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationatom(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationEnlistment(EnlistmentHandle: 0x%lx, EnlistmentInformationClass: 0x%lx, EnlistmentInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationFile(FileHandle: 0x%lx, Length: 0x%lx, FileInformationClass: 0x%lx)\n", pid, tid, proc, args[0], args[3], args[4]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationjobobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationJobObject(JobHandle: 0x%lx, JobObjectInformationClass: 0x%lx, JobObjectInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationjobobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationPort(PortHandle: 0x%lx, PortInformationClass: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationProcess(ProcessHandle: 0x%lx, ProcessInformationClass: 0x%lx, ProcessInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationresourcemanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationResourceManager(ResourceManagerHandle: 0x%lx, ResourceManagerInformationClass: 0x%lx, ResourceManagerInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationresourcemanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationThread(ThreadHandle: 0x%lx, ThreadInformationClass: 0x%lx, ThreadInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationtoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationToken(TokenHandle: 0x%lx, TokenInformationClass: 0x%lx, TokenInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationtoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationtransaction(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationTransaction(TransactionHandle: 0x%lx, TransactionInformationClass: 0x%lx, TransactionInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationtransaction(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationtransactionmanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationTransactionManager(TransactionManagerHandle: 0x%lx, TransactionManagerInformationClass: 0x%lx, TransactionManagerInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationtransactionmanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinformationworkerfactory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInformationWorkerFactory(WorkerFactoryHandle: 0x%lx, WorkerFactoryInformationClass: 0x%lx, WorkerFactoryInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryinformationworkerfactory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryinstalluilanguage(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryInstallUILanguage()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntqueryinstalluilanguage(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*InstallUILanguageId: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[0]);
	free(args);
}

void *gt_windows_print_syscall_ntqueryintervalprofile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryIntervalProfile(ProfileSource: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntqueryintervalprofile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Interval: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntqueryiocompletion(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryIoCompletion(IoCompletionHandle: 0x%lx, IoCompletionInformationClass: 0x%lx, IoCompletionInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryiocompletion(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntquerykey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryKey(KeyHandle: 0x%lx, KeyInformationClass: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntquerykey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ResultLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntquerylicensevalue(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryLicenseValue(Name: %s, Length: 0x%lx)\n", pid, tid, proc, unicode_str_0, args[3]);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntquerylicensevalue(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Type: 0x%lx, ReturnedLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_1, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntquerymultiplevaluekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryMultipleValueKey(KeyHandle: 0x%lx, EntryCount: 0x%lx, BufferLength: 0x%lx)\n", pid, tid, proc, args[0], args[2], pulong_4);
	return args;
}

void gt_windows_print_sysret_ntquerymultiplevaluekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(BufferLength: 0x%lx, RequiredBufferLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4, pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntquerymutant(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryMutant(MutantHandle: 0x%lx, MutantInformationClass: 0x%lx, MutantInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntquerymutant(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryObject(Handle: 0x%lx, ObjectInformationClass: 0x%lx, ObjectInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntqueryobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntqueryopensubkeysex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryOpenSubKeysEx(TargetKey: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, BufferLength: 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0, args[1]);
	free(unicode_str_0);
	free(obj_attr_0);	return args;
}

void gt_windows_print_sysret_ntqueryopensubkeysex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_3 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[3], pid, &pulong_3);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(RequiredSize: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_3);
	free(args);
}

void *gt_windows_print_syscall_ntqueryopensubkeys(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryOpenSubKeys(TargetKey: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0);
	free(unicode_str_0);
	free(obj_attr_0);	return args;
}

void gt_windows_print_sysret_ntqueryopensubkeys(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(HandleCount: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntqueryperformancecounter(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryPerformanceCounter()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntqueryperformancecounter(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PerformanceCounter: 0x%lx, PerformanceFrequency: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[0], args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntqueryportinformationprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryPortInformationProcess()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntqueryportinformationprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntqueryquotainformationfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_4 = args[4] ? "TRUE" : "FALSE";
	uint64_t pulong_7 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[7], pid, &pulong_7);
	char *bool_8 = args[8] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryQuotaInformationFile(FileHandle: 0x%lx, Length: 0x%lx, ReturnSingleEntry: %s, SidListLength: 0x%lx, StartSid: 0x%lx, RestartScan: %s)\n", pid, tid, proc, args[0], args[3], bool_4, args[6], pulong_7, bool_8);
	return args;
}

void gt_windows_print_sysret_ntqueryquotainformationfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntquerysection(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySection(SectionHandle: 0x%lx, SectionInformationClass: 0x%lx, SectionInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntquerysection(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntquerysecurityattributestoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySecurityAttributesToken(TokenHandle: 0x%lx, NumberOfAttributes: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntquerysecurityattributestoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntquerysecurityobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySecurityObject(Handle: 0x%lx, SecurityInformation: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntquerysecurityobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(LengthNeeded: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntquerysemaphore(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySemaphore(SemaphoreHandle: 0x%lx, SemaphoreInformationClass: 0x%lx, SemaphoreInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntquerysemaphore(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntquerysymboliclinkobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySymbolicLinkObject(LinkHandle: 0x%lx, LinkTarget: %s)\n", pid, tid, proc, args[0], unicode_str_1);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntquerysymboliclinkobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	uint64_t pulong_2 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[2], pid, &pulong_2);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(LinkTarget: %s, ReturnedLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), unicode_str_1, pulong_2);
	free(unicode_str_1);	free(args);
}

void *gt_windows_print_syscall_ntquerysystemenvironmentvalueex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	uint64_t pulong_3 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[3], pid, &pulong_3);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySystemEnvironmentValueEx(VariableName: %s, VendorGuid: 0x%lx, ValueLength: 0x%lx)\n", pid, tid, proc, unicode_str_0, args[1], pulong_3);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntquerysystemenvironmentvalueex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_3 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[3], pid, &pulong_3);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ValueLength: 0x%lx, Attributes: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_3, pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntquerysystemenvironmentvalue(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySystemEnvironmentValue(VariableName: %s, ValueLength: 0x%lx)\n", pid, tid, proc, unicode_str_0, args[2]);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntquerysystemenvironmentvalue(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntquerysysteminformationex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySystemInformationEx(SystemInformationClass: 0x%lx, QueryInformationLength: 0x%lx, SystemInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntquerysysteminformationex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntquerysysteminformation(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySystemInformation(SystemInformationClass: 0x%lx, SystemInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntquerysysteminformation(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_3 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[3], pid, &pulong_3);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_3);
	free(args);
}

void *gt_windows_print_syscall_ntquerysystemtime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQuerySystemTime()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntquerysystemtime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(SystemTime: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[0]);
	free(args);
}

void *gt_windows_print_syscall_ntquerytimer(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryTimer(TimerHandle: 0x%lx, TimerInformationClass: 0x%lx, TimerInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntquerytimer(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntquerytimerresolution(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryTimerResolution()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntquerytimerresolution(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &pulong_0);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	uint64_t pulong_2 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[2], pid, &pulong_2);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(MaximumTime: 0x%lx, MinimumTime: 0x%lx, CurrentTime: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_0, pulong_1, pulong_2);
	free(args);
}

void *gt_windows_print_syscall_ntqueryvaluekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryValueKey(KeyHandle: 0x%lx, ValueName: %s, KeyValueInformationClass: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], unicode_str_1, args[2], args[4]);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntqueryvaluekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ResultLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntqueryvirtualmemory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryVirtualMemory(ProcessHandle: 0x%lx, BaseAddress: 0x%lx, MemoryInformationClass: 0x%lx, MemoryInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntqueryvirtualmemory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[5]);
	free(args);
}

void *gt_windows_print_syscall_ntqueryvolumeinformationfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueryVolumeInformationFile(FileHandle: 0x%lx, Length: 0x%lx, FsInformationClass: 0x%lx)\n", pid, tid, proc, args[0], args[3], args[4]);
	return args;
}

void gt_windows_print_sysret_ntqueryvolumeinformationfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntqueueapcthreadex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueueApcThreadEx(ThreadHandle: 0x%lx, UserApcReserveHandle: 0x%lx, ApcRoutine: 0x%lx, ApcArgument1: 0x%lx, ApcArgument2: 0x%lx, ApcArgument3: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4], args[5]);
	return args;
}

void gt_windows_print_sysret_ntqueueapcthreadex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntqueueapcthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtQueueApcThread(ThreadHandle: 0x%lx, ApcRoutine: 0x%lx, ApcArgument1: 0x%lx, ApcArgument2: 0x%lx, ApcArgument3: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4]);
	return args;
}

void gt_windows_print_sysret_ntqueueapcthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntraiseexception(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRaiseException()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntraiseexception(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	char *bool_2 = args[2] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ExceptionRecord: 0x%lx, ContextRecord: 0x%lx, FirstChance: %s)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[0], args[1], bool_2);
	free(args);
}

void *gt_windows_print_syscall_ntraiseharderror(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRaiseHardError(ErrorStatus: 0x%lx, NumberOfParameters: 0x%lx, UnicodeStringParameterMask: 0x%lx, ValidResponseOptions: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntraiseharderror(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(Response: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntreadfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReadFile(FileHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, Length: 0x%lx, ByteOffset: 0x%lx, Key: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[6], args[7], pulong_8);
	return args;
}

void gt_windows_print_sysret_ntreadfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntreadfilescatter(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReadFileScatter(FileHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, SegmentArray: 0x%lx, Length: 0x%lx, ByteOffset: 0x%lx, Key: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[5], args[6], args[7], pulong_8);
	return args;
}

void gt_windows_print_sysret_ntreadfilescatter(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntreadonlyenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReadOnlyEnlistment(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntreadonlyenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntreadrequestdata(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReadRequestData(PortHandle: 0x%lx, Message: 0x%lx, DataEntryIndex: 0x%lx, BufferSize: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntreadrequestdata(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NumberOfBytesRead: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[5]);
	free(args);
}

void *gt_windows_print_syscall_ntreadvirtualmemory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReadVirtualMemory(ProcessHandle: 0x%lx, BaseAddress: 0x%lx, BufferSize: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntreadvirtualmemory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NumberOfBytesRead: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntrecoverenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRecoverEnlistment(EnlistmentHandle: 0x%lx, EnlistmentKey: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntrecoverenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntrecoverresourcemanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRecoverResourceManager(ResourceManagerHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntrecoverresourcemanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntrecovertransactionmanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRecoverTransactionManager(TransactionManagerHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntrecovertransactionmanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntregisterprotocoladdressinformation(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRegisterProtocolAddressInformation(ResourceManager: 0x%lx, ProtocolId: 0x%lx, ProtocolInformationSize: 0x%lx, ProtocolInformation: 0x%lx, CreateOptions: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4]);
	return args;
}

void gt_windows_print_sysret_ntregisterprotocoladdressinformation(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntregisterthreadterminateport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRegisterThreadTerminatePort(PortHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntregisterthreadterminateport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntreleasekeyedevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_2 = args[2] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReleaseKeyedEvent(KeyedEventHandle: 0x%lx, KeyValue: 0x%lx, Alertable: %s, Timeout: 0x%lx)\n", pid, tid, proc, args[0], args[1], bool_2, args[3]);
	return args;
}

void gt_windows_print_sysret_ntreleasekeyedevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntreleasemutant(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReleaseMutant(MutantHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntreleasemutant(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousCount: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntreleasesemaphore(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReleaseSemaphore(SemaphoreHandle: 0x%lx, ReleaseCount: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntreleasesemaphore(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousCount: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntreleaseworkerfactoryworker(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReleaseWorkerFactoryWorker(WorkerFactoryHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntreleaseworkerfactoryworker(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntremoveiocompletionex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_5 = args[5] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRemoveIoCompletionEx(IoCompletionHandle: 0x%lx, Count: 0x%lx, Timeout: 0x%lx, Alertable: %s)\n", pid, tid, proc, args[0], args[2], args[4], bool_5);
	return args;
}

void gt_windows_print_sysret_ntremoveiocompletionex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_3 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[3], pid, &pulong_3);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NumEntriesRemoved: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_3);
	free(args);
}

void *gt_windows_print_syscall_ntremoveiocompletion(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRemoveIoCompletion(IoCompletionHandle: 0x%lx, Timeout: 0x%lx)\n", pid, tid, proc, args[0], args[4]);
	return args;
}

void gt_windows_print_sysret_ntremoveiocompletion(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*KeyContext: 0x%lx, *ApcContext: 0x%lx, IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1], args[2], args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntremoveprocessdebug(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRemoveProcessDebug()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntremoveprocessdebug(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ProcessHandle: 0x%lx, DebugObjectHandle: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[0], args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntrenamekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRenameKey(KeyHandle: 0x%lx, NewName: %s)\n", pid, tid, proc, args[0], unicode_str_1);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntrenamekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntrenametransactionmanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRenameTransactionManager(LogFileName: %s, ExistingTransactionManagerGuid: 0x%lx)\n", pid, tid, proc, unicode_str_0, args[1]);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntrenametransactionmanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntreplacekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	uint8_t *unicode_str_2 = NULL;
	uint64_t root_dir_2 = 0;
	uint64_t attributes_2 = 0;
	struct win64_obj_attr *obj_attr_2 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[2], pid);
	if (NULL != obj_attr_2) {
		unicode_str_2 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_2->object_name, pid);
		root_dir_2 = obj_attr_2->root_directory;
		attributes_2 = obj_attr_2->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReplaceKey(NewFile: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, TargetHandle: 0x%lx, OldFile: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0, args[1], root_dir_2, unicode_str_2, attributes_2);
	free(unicode_str_0);
	free(obj_attr_0);
	free(unicode_str_2);
	free(obj_attr_2);	return args;
}

void gt_windows_print_sysret_ntreplacekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntreplacepartitionunit(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReplacePartitionUnit(TargetInstancePath: %s, SpareInstancePath: %s, Flags: 0x%lx)\n", pid, tid, proc, unicode_str_0, unicode_str_1, args[2]);
	free(unicode_str_0);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntreplacepartitionunit(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntreplyport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReplyPort(PortHandle: 0x%lx, ReplyMessage: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntreplyport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntreplywaitreceiveportex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReplyWaitReceivePortEx(PortHandle: 0x%lx, ReplyMessage: 0x%lx, Timeout: 0x%lx)\n", pid, tid, proc, args[0], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntreplywaitreceiveportex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*PortContext: 0x%lx, ReceiveMessage: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1], args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntreplywaitreceiveport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReplyWaitReceivePort(PortHandle: 0x%lx, ReplyMessage: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntreplywaitreceiveport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*PortContext: 0x%lx, ReceiveMessage: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1], args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntreplywaitreplyport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtReplyWaitReplyPort(PortHandle: 0x%lx, ReplyMessage: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntreplywaitreplyport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReplyMessage: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntrequestport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRequestPort(PortHandle: 0x%lx, RequestMessage: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntrequestport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntrequestwaitreplyport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRequestWaitReplyPort(PortHandle: 0x%lx, RequestMessage: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntrequestwaitreplyport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReplyMessage: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntresetevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtResetEvent(EventHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntresetevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousState: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntresetwritewatch(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtResetWriteWatch(ProcessHandle: 0x%lx, BaseAddress: 0x%lx, RegionSize: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntresetwritewatch(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntrestorekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRestoreKey(KeyHandle: 0x%lx, FileHandle: 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntrestorekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntresumeprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtResumeProcess(ProcessHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntresumeprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntresumethread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtResumeThread(ThreadHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntresumethread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousSuspendCount: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntrollbackcomplete(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRollbackComplete(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntrollbackcomplete(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntrollbackenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRollbackEnlistment(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntrollbackenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntrollbacktransaction(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_1 = args[1] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRollbackTransaction(TransactionHandle: 0x%lx, Wait: %s)\n", pid, tid, proc, args[0], bool_1);
	return args;
}

void gt_windows_print_sysret_ntrollbacktransaction(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntrollforwardtransactionmanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtRollforwardTransactionManager(TransactionManagerHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntrollforwardtransactionmanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsavekeyex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSaveKeyEx(KeyHandle: 0x%lx, FileHandle: 0x%lx, Format: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntsavekeyex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsavekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSaveKey(KeyHandle: 0x%lx, FileHandle: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntsavekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsavemergedkeys(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSaveMergedKeys(HighPrecedenceKeyHandle: 0x%lx, LowPrecedenceKeyHandle: 0x%lx, FileHandle: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntsavemergedkeys(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsecureconnectport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSecureConnectPort(PortName: %s, SecurityQos: 0x%lx, ClientView: 0x%lx, RequiredServerSid: 0x%lx, ServerView: 0x%lx, ConnectionInformation: 0x%lx, ConnectionInformationLength: 0x%lx)\n", pid, tid, proc, unicode_str_1, args[2], args[3], args[4], args[5], args[7], pulong_8);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntsecureconnectport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t phandle_0 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[0], pid, &phandle_0);
	uint64_t pulong_6 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[6], pid, &pulong_6);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PortHandle: 0x%lx, ClientView: 0x%lx, ServerView: 0x%lx, MaxMessageLength: 0x%lx, ConnectionInformation: 0x%lx, ConnectionInformationLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), phandle_0, args[3], args[5], pulong_6, args[7], pulong_8);
	free(args);
}

void *gt_windows_print_syscall_ntserializeboot(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSerializeBoot()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntserializeboot(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetbootentryorder(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetBootEntryOrder(Count: 0x%lx)\n", pid, tid, proc, args[1]);
	return args;
}

void gt_windows_print_sysret_ntsetbootentryorder(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetbootoptions(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetBootOptions(BootOptions: 0x%lx, FieldsToChange: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntsetbootoptions(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetcontextthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetContextThread(ThreadHandle: 0x%lx, ThreadContext: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntsetcontextthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetdebugfilterstate(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_2 = args[2] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetDebugFilterState(ComponentId: 0x%lx, Level: 0x%lx, State: %s)\n", pid, tid, proc, args[0], args[1], bool_2);
	return args;
}

void gt_windows_print_sysret_ntsetdebugfilterstate(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetdefaultharderrorport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetDefaultHardErrorPort(DefaultHardErrorPort: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsetdefaultharderrorport(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetdefaultlocale(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_0 = args[0] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetDefaultLocale(UserProfile: %s, DefaultLocaleId: 0x%lx)\n", pid, tid, proc, bool_0, args[1]);
	return args;
}

void gt_windows_print_sysret_ntsetdefaultlocale(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetdefaultuilanguage(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetDefaultUILanguage(DefaultUILanguageId: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsetdefaultuilanguage(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetdriverentryorder(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetDriverEntryOrder(Count: 0x%lx)\n", pid, tid, proc, args[1]);
	return args;
}

void gt_windows_print_sysret_ntsetdriverentryorder(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntseteafile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetEaFile(FileHandle: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[3]);
	return args;
}

void gt_windows_print_sysret_ntseteafile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntseteventboostpriority(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetEventBoostPriority(EventHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntseteventboostpriority(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetEvent(EventHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsetevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousState: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntsethigheventpair(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetHighEventPair(EventPairHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsethigheventpair(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsethighwaitloweventpair(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetHighWaitLowEventPair(EventPairHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsethighwaitloweventpair(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationdebugobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationDebugObject()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntsetinformationdebugobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_4 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[4], pid, &pulong_4);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(DebugObjectHandle: 0x%lx, DebugObjectInformationClass: 0x%lx, DebugInformation: 0x%lx, DebugInformationLength: 0x%lx, ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[0], args[1], args[2], args[3], pulong_4);
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationEnlistment(EnlistmentHandle: 0x%lx, EnlistmentInformationClass: 0x%lx, EnlistmentInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationenlistment(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationFile(FileHandle: 0x%lx, Length: 0x%lx, FileInformationClass: 0x%lx)\n", pid, tid, proc, args[0], args[3], args[4]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationjobobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationJobObject(JobHandle: 0x%lx, JobObjectInformationClass: 0x%lx, JobObjectInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationjobobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationkey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationKey(KeyHandle: 0x%lx, KeySetInformationClass: 0x%lx, KeySetInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationkey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationObject(Handle: 0x%lx, ObjectInformationClass: 0x%lx, ObjectInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationProcess(ProcessHandle: 0x%lx, ProcessInformationClass: 0x%lx, ProcessInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationresourcemanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationResourceManager(ResourceManagerHandle: 0x%lx, ResourceManagerInformationClass: 0x%lx, ResourceManagerInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationresourcemanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationThread(ThreadHandle: 0x%lx, ThreadInformationClass: 0x%lx, ThreadInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationtoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationToken(TokenHandle: 0x%lx, TokenInformationClass: 0x%lx, TokenInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationtoken(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationtransaction(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationTransaction(TransactionHandle: 0x%lx, TransactionInformationClass: 0x%lx, TransactionInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationtransaction(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationtransactionmanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationTransactionManager(TmHandle: 0x%lx, TransactionManagerInformationClass: 0x%lx, TransactionManagerInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationtransactionmanager(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetinformationworkerfactory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetInformationWorkerFactory(WorkerFactoryHandle: 0x%lx, WorkerFactoryInformationClass: 0x%lx, WorkerFactoryInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetinformationworkerfactory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetintervalprofile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetIntervalProfile(Interval: 0x%lx, Source: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntsetintervalprofile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetiocompletionex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetIoCompletionEx(IoCompletionHandle: 0x%lx, IoCompletionReserveHandle: 0x%lx, KeyContext: 0x%lx, ApcContext: 0x%lx, IoStatus: 0x%lx, IoStatusInformation: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4], args[5]);
	return args;
}

void gt_windows_print_sysret_ntsetiocompletionex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetiocompletion(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetIoCompletion(IoCompletionHandle: 0x%lx, KeyContext: 0x%lx, ApcContext: 0x%lx, IoStatus: 0x%lx, IoStatusInformation: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4]);
	return args;
}

void gt_windows_print_sysret_ntsetiocompletion(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetldtentries(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetLdtEntries(Selector0: 0x%lx, Entry0Low: 0x%lx, Entry0Hi: 0x%lx, Selector1: 0x%lx, Entry1Low: 0x%lx, Entry1Hi: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[4], args[5]);
	return args;
}

void gt_windows_print_sysret_ntsetldtentries(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetloweventpair(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetLowEventPair(EventPairHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsetloweventpair(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetlowwaithigheventpair(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetLowWaitHighEventPair(EventPairHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsetlowwaithigheventpair(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetquotainformationfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetQuotaInformationFile(FileHandle: 0x%lx, Length: 0x%lx)\n", pid, tid, proc, args[0], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsetquotainformationfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntsetsecurityobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetSecurityObject(Handle: 0x%lx, SecurityInformation: 0x%lx, SecurityDescriptor: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntsetsecurityobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetsystemenvironmentvalueex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetSystemEnvironmentValueEx(VariableName: %s, VendorGuid: 0x%lx, ValueLength: 0x%lx, Attributes: 0x%lx)\n", pid, tid, proc, unicode_str_0, args[1], args[3], args[4]);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntsetsystemenvironmentvalueex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetsystemenvironmentvalue(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetSystemEnvironmentValue(VariableName: %s, VariableValue: %s)\n", pid, tid, proc, unicode_str_0, unicode_str_1);
	free(unicode_str_0);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntsetsystemenvironmentvalue(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetsysteminformation(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetSystemInformation(SystemInformationClass: 0x%lx, SystemInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[2]);
	return args;
}

void gt_windows_print_sysret_ntsetsysteminformation(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetsystempowerstate(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetSystemPowerState(SystemAction: 0x%lx, MinSystemState: 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2]);
	return args;
}

void gt_windows_print_sysret_ntsetsystempowerstate(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetsystemtime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetSystemTime(SystemTime: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsetsystemtime(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousTime: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntsetthreadexecutionstate(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetThreadExecutionState(esFlags: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsetthreadexecutionstate(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*PreviousFlags: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntsettimerex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetTimerEx(TimerHandle: 0x%lx, TimerSetInformationClass: 0x%lx, TimerSetInformationLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntsettimerex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsettimer(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_4 = args[4] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetTimer(TimerHandle: 0x%lx, DueTime: 0x%lx, TimerApcRoutine: 0x%lx, TimerContext: 0x%lx, WakeTimer: %s, Period: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], bool_4, args[5]);
	return args;
}

void gt_windows_print_sysret_ntsettimer(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousState: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[6]);
	free(args);
}

void *gt_windows_print_syscall_ntsettimerresolution(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_1 = args[1] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetTimerResolution(DesiredTime: 0x%lx, SetResolution: %s)\n", pid, tid, proc, args[0], bool_1);
	return args;
}

void gt_windows_print_sysret_ntsettimerresolution(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_2 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[2], pid, &pulong_2);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ActualTime: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_2);
	free(args);
}

void *gt_windows_print_syscall_ntsetuuidseed(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetUuidSeed(Seed: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsetuuidseed(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetvaluekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_1 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[1], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetValueKey(KeyHandle: 0x%lx, ValueName: %s, TitleIndex: 0x%lx, Type: 0x%lx, DataSize: 0x%lx)\n", pid, tid, proc, args[0], unicode_str_1, args[2], args[3], args[5]);
	free(unicode_str_1);	return args;
}

void gt_windows_print_sysret_ntsetvaluekey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsetvolumeinformationfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSetVolumeInformationFile(FileHandle: 0x%lx, Length: 0x%lx, FsInformationClass: 0x%lx)\n", pid, tid, proc, args[0], args[3], args[4]);
	return args;
}

void gt_windows_print_sysret_ntsetvolumeinformationfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntshutdownsystem(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtShutdownSystem(Action: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntshutdownsystem(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntshutdownworkerfactory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtShutdownWorkerFactory(WorkerFactoryHandle: 0x%lx, *PendingWorkerCount: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntshutdownworkerfactory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*PendingWorkerCount: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntsignalandwaitforsingleobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_2 = args[2] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSignalAndWaitForSingleObject(SignalHandle: 0x%lx, WaitHandle: 0x%lx, Alertable: %s, Timeout: 0x%lx)\n", pid, tid, proc, args[0], args[1], bool_2, args[3]);
	return args;
}

void gt_windows_print_sysret_ntsignalandwaitforsingleobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsinglephasereject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSinglePhaseReject(EnlistmentHandle: 0x%lx, TmVirtualClock: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntsinglephasereject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntstartprofile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtStartProfile(ProfileHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntstartprofile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntstopprofile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtStopProfile(ProfileHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntstopprofile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsuspendprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSuspendProcess(ProcessHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsuspendprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntsuspendthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSuspendThread(ThreadHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntsuspendthread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_1 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[1], pid, &pulong_1);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(PreviousSuspendCount: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_1);
	free(args);
}

void *gt_windows_print_syscall_ntsystemdebugcontrol(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtSystemDebugControl(Command: 0x%lx, InputBufferLength: 0x%lx, OutputBufferLength: 0x%lx)\n", pid, tid, proc, args[0], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntsystemdebugcontrol(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_5);
	free(args);
}

void *gt_windows_print_syscall_ntterminatejobobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtTerminateJobObject(JobHandle: 0x%lx, ExitStatus: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntterminatejobobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntterminateprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtTerminateProcess(ProcessHandle: 0x%lx, ExitStatus: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntterminateprocess(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntterminatethread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtTerminateThread(ThreadHandle: 0x%lx, ExitStatus: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntterminatethread(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_nttestalert(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtTestAlert()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_nttestalert(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntthawregistry(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtThawRegistry()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntthawregistry(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntthawtransactions(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtThawTransactions()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntthawtransactions(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_nttracecontrol(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtTraceControl(FunctionCode: 0x%lx, InBufferLen: 0x%lx, OutBufferLen: 0x%lx)\n", pid, tid, proc, args[0], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_nttracecontrol(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_5 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[5], pid, &pulong_5);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ReturnLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_5);
	free(args);
}

void *gt_windows_print_syscall_nttraceevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtTraceEvent(TraceHandle: 0x%lx, Flags: 0x%lx, FieldSize: 0x%lx, Fields: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3]);
	return args;
}

void gt_windows_print_sysret_nttraceevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_nttranslatefilepath(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint64_t pulong_3 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[3], pid, &pulong_3);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtTranslateFilePath(InputFilePath: 0x%lx, OutputType: 0x%lx, OutputFilePathLength: 0x%lx)\n", pid, tid, proc, args[0], args[1], pulong_3);
	return args;
}

void gt_windows_print_sysret_nttranslatefilepath(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t pulong_3 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[3], pid, &pulong_3);
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(OutputFilePathLength: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), pulong_3);
	free(args);
}

void *gt_windows_print_syscall_ntumsthreadyield(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtUmsThreadYield(SchedulerParam: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntumsthreadyield(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntunloaddriver(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtUnloadDriver(DriverServiceName: %s)\n", pid, tid, proc, unicode_str_0);
	free(unicode_str_0);	return args;
}

void gt_windows_print_sysret_ntunloaddriver(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntunloadkey2(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtUnloadKey2(TargetKey: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Flags: 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0, args[1]);
	free(unicode_str_0);
	free(obj_attr_0);	return args;
}

void gt_windows_print_sysret_ntunloadkey2(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntunloadkeyex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtUnloadKeyEx(TargetKey: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx, Event: 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0, args[1]);
	free(unicode_str_0);
	free(obj_attr_0);	return args;
}

void gt_windows_print_sysret_ntunloadkeyex(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntunloadkey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint8_t *unicode_str_0 = NULL;
	uint64_t root_dir_0 = 0;
	uint64_t attributes_0 = 0;
	struct win64_obj_attr *obj_attr_0 = obj_attr_from_va(gt_guest_get_vmi_instance(state), args[0], pid);
	if (NULL != obj_attr_0) {
		unicode_str_0 = unicode_str_from_va(gt_guest_get_vmi_instance(state), obj_attr_0->object_name, pid);
		root_dir_0 = obj_attr_0->root_directory;
		attributes_0 = obj_attr_0->attributes;
	}
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtUnloadKey(TargetKey: RootDirectory = 0x%lx | ObjectName = %s | Attributes = 0x%lx)\n", pid, tid, proc, root_dir_0, unicode_str_0, attributes_0);
	free(unicode_str_0);
	free(obj_attr_0);	return args;
}

void gt_windows_print_sysret_ntunloadkey(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntunlockfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtUnlockFile(FileHandle: 0x%lx, ByteOffset: 0x%lx, Length: 0x%lx, Key: 0x%lx)\n", pid, tid, proc, args[0], args[2], args[3], args[4]);
	return args;
}

void gt_windows_print_sysret_ntunlockfile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntunlockvirtualmemory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtUnlockVirtualMemory(ProcessHandle: 0x%lx, *BaseAddress: 0x%lx, RegionSize: 0x%lx, MapType: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3]);
	return args;
}

void gt_windows_print_sysret_ntunlockvirtualmemory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(*BaseAddress: 0x%lx, RegionSize: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1], args[2]);
	free(args);
}

void *gt_windows_print_syscall_ntunmapviewofsection(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtUnmapViewOfSection(ProcessHandle: 0x%lx, BaseAddress: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntunmapviewofsection(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntvdmcontrol(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtVdmControl(Service: 0x%lx, ServiceData: 0x%lx)\n", pid, tid, proc, args[0], args[1]);
	return args;
}

void gt_windows_print_sysret_ntvdmcontrol(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(ServiceData: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntwaitfordebugevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWaitForDebugEvent()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntwaitfordebugevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	char *bool_1 = args[1] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(DebugObjectHandle: 0x%lx, Alertable: %s, Timeout: 0x%lx, WaitStateChange: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[0], bool_1, args[2], args[3]);
	free(args);
}

void *gt_windows_print_syscall_ntwaitforkeyedevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_2 = args[2] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWaitForKeyedEvent(KeyedEventHandle: 0x%lx, KeyValue: 0x%lx, Alertable: %s, Timeout: 0x%lx)\n", pid, tid, proc, args[0], args[1], bool_2, args[3]);
	return args;
}

void gt_windows_print_sysret_ntwaitforkeyedevent(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntwaitformultipleobjects32(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_3 = args[3] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWaitForMultipleObjects32(Count: 0x%lx, WaitType: 0x%lx, Alertable: %s, Timeout: 0x%lx)\n", pid, tid, proc, args[0], args[2], bool_3, args[4]);
	return args;
}

void gt_windows_print_sysret_ntwaitformultipleobjects32(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntwaitformultipleobjects(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_3 = args[3] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWaitForMultipleObjects(Count: 0x%lx, WaitType: 0x%lx, Alertable: %s, Timeout: 0x%lx)\n", pid, tid, proc, args[0], args[2], bool_3, args[4]);
	return args;
}

void gt_windows_print_sysret_ntwaitformultipleobjects(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntwaitforsingleobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	char *bool_1 = args[1] ? "TRUE" : "FALSE";
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWaitForSingleObject(Handle: 0x%lx, Alertable: %s, Timeout: 0x%lx)\n", pid, tid, proc, args[0], bool_1, args[2]);
	return args;
}

void gt_windows_print_sysret_ntwaitforsingleobject(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntwaitforworkviaworkerfactory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWaitForWorkViaWorkerFactory(WorkerFactoryHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntwaitforworkviaworkerfactory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(MiniPacket: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[1]);
	free(args);
}

void *gt_windows_print_syscall_ntwaithigheventpair(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWaitHighEventPair(EventPairHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntwaithigheventpair(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntwaitloweventpair(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWaitLowEventPair(EventPairHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntwaitloweventpair(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntworkerfactoryworkerready(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWorkerFactoryWorkerReady(WorkerFactoryHandle: 0x%lx)\n", pid, tid, proc, args[0]);
	return args;
}

void gt_windows_print_sysret_ntworkerfactoryworkerready(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

void *gt_windows_print_syscall_ntwritefilegather(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWriteFileGather(FileHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, SegmentArray: 0x%lx, Length: 0x%lx, ByteOffset: 0x%lx, Key: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[5], args[6], args[7], pulong_8);
	return args;
}

void gt_windows_print_sysret_ntwritefilegather(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntwritefile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);
	uint64_t pulong_8 = 0;
	vmi_read_64_va(gt_guest_get_vmi_instance(state), args[8], pid, &pulong_8);
	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWriteFile(FileHandle: 0x%lx, Event: 0x%lx, ApcRoutine: 0x%lx, ApcContext: 0x%lx, Length: 0x%lx, ByteOffset: 0x%lx, Key: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[3], args[6], args[7], pulong_8);
	return args;
}

void gt_windows_print_sysret_ntwritefile(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(IoStatusBlock: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntwriterequestdata(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWriteRequestData(PortHandle: 0x%lx, Message: 0x%lx, DataEntryIndex: 0x%lx, BufferSize: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[2], args[4]);
	return args;
}

void gt_windows_print_sysret_ntwriterequestdata(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NumberOfBytesWritten: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[5]);
	free(args);
}

void *gt_windows_print_syscall_ntwritevirtualmemory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtWriteVirtualMemory(ProcessHandle: 0x%lx, BaseAddress: 0x%lx, BufferSize: 0x%lx)\n", pid, tid, proc, args[0], args[1], args[3]);
	return args;
}

void gt_windows_print_sysret_ntwritevirtualmemory(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT(NumberOfBytesWritten: 0x%lx)\n", pid, tid, proc, gt_guest_get_register(state, RAX), args[4]);
	free(args);
}

void *gt_windows_print_syscall_ntyieldexecution(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);
	uint64_t *args = vf_get_args(state, pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) syscall: NtYieldExecution()\n", pid, tid, proc);
	return args;
}

void gt_windows_print_sysret_ntyieldexecution(GtGuestState *state, gt_pid_t pid, gt_tid_t tid, void *data)
{
	uint64_t *args = (uint64_t*)data;
	char *proc = gt_windows_get_process_name(gt_guest_get_vmi_instance(state), pid);

	fprintf(stderr, "pid: %u/0x%lx (%s) sysret: Status(0x%lx) OUT()\n", pid, tid, proc, gt_guest_get_register(state, RAX));
	free(args);
}

const GtCallbackRegistry GT_WINDOWS_SYSCALLS[] = {
	{ "NtAcceptConnectPort", gt_windows_print_syscall_ntacceptconnectport, gt_windows_print_sysret_ntacceptconnectport, NULL },
	{ "NtAccessCheckAndAuditAlarm", gt_windows_print_syscall_ntaccesscheckandauditalarm, gt_windows_print_sysret_ntaccesscheckandauditalarm, NULL },
	{ "NtAccessCheckByTypeAndAuditAlarm", gt_windows_print_syscall_ntaccesscheckbytypeandauditalarm, gt_windows_print_sysret_ntaccesscheckbytypeandauditalarm, NULL },
	{ "NtAccessCheckByType", gt_windows_print_syscall_ntaccesscheckbytype, gt_windows_print_sysret_ntaccesscheckbytype, NULL },
	{ "NtAccessCheckByTypeResultListAndAuditAlarmByHandle", gt_windows_print_syscall_ntaccesscheckbytyperesultlistandauditalarmbyhandle, gt_windows_print_sysret_ntaccesscheckbytyperesultlistandauditalarmbyhandle, NULL },
	{ "NtAccessCheckByTypeResultListAndAuditAlarm", gt_windows_print_syscall_ntaccesscheckbytyperesultlistandauditalarm, gt_windows_print_sysret_ntaccesscheckbytyperesultlistandauditalarm, NULL },
	{ "NtAccessCheckByTypeResultList", gt_windows_print_syscall_ntaccesscheckbytyperesultlist, gt_windows_print_sysret_ntaccesscheckbytyperesultlist, NULL },
	{ "NtAccessCheck", gt_windows_print_syscall_ntaccesscheck, gt_windows_print_sysret_ntaccesscheck, NULL },
	{ "NtAddAtom", gt_windows_print_syscall_ntaddatom, gt_windows_print_sysret_ntaddatom, NULL },
	{ "NtAddBootEntry", gt_windows_print_syscall_ntaddbootentry, gt_windows_print_sysret_ntaddbootentry, NULL },
	{ "NtAddDriverEntry", gt_windows_print_syscall_ntadddriverentry, gt_windows_print_sysret_ntadddriverentry, NULL },
	{ "NtAdjustGroupsToken", gt_windows_print_syscall_ntadjustgroupstoken, gt_windows_print_sysret_ntadjustgroupstoken, NULL },
	{ "NtAdjustPrivilegesToken", gt_windows_print_syscall_ntadjustprivilegestoken, gt_windows_print_sysret_ntadjustprivilegestoken, NULL },
	{ "NtAlertResumeThread", gt_windows_print_syscall_ntalertresumethread, gt_windows_print_sysret_ntalertresumethread, NULL },
	{ "NtAlertThread", gt_windows_print_syscall_ntalertthread, gt_windows_print_sysret_ntalertthread, NULL },
	{ "NtAllocateLocallyUniqueId", gt_windows_print_syscall_ntallocatelocallyuniqueid, gt_windows_print_sysret_ntallocatelocallyuniqueid, NULL },
	{ "NtAllocateReserveObject", gt_windows_print_syscall_ntallocatereserveobject, gt_windows_print_sysret_ntallocatereserveobject, NULL },
	{ "NtAllocateUserPhysicalPages", gt_windows_print_syscall_ntallocateuserphysicalpages, gt_windows_print_sysret_ntallocateuserphysicalpages, NULL },
	{ "NtAllocateUuids", gt_windows_print_syscall_ntallocateuuids, gt_windows_print_sysret_ntallocateuuids, NULL },
	{ "NtAllocateVirtualMemory", gt_windows_print_syscall_ntallocatevirtualmemory, gt_windows_print_sysret_ntallocatevirtualmemory, NULL },
	{ "NtAlpcAcceptConnectPort", gt_windows_print_syscall_ntalpcacceptconnectport, gt_windows_print_sysret_ntalpcacceptconnectport, NULL },
	{ "NtAlpcCancelMessage", gt_windows_print_syscall_ntalpccancelmessage, gt_windows_print_sysret_ntalpccancelmessage, NULL },
	{ "NtAlpcConnectPort", gt_windows_print_syscall_ntalpcconnectport, gt_windows_print_sysret_ntalpcconnectport, NULL },
	{ "NtAlpcCreatePort", gt_windows_print_syscall_ntalpccreateport, gt_windows_print_sysret_ntalpccreateport, NULL },
	{ "NtAlpcCreatePortSection", gt_windows_print_syscall_ntalpccreateportsection, gt_windows_print_sysret_ntalpccreateportsection, NULL },
	{ "NtAlpcCreateResourceReserve", gt_windows_print_syscall_ntalpccreateresourcereserve, gt_windows_print_sysret_ntalpccreateresourcereserve, NULL },
	{ "NtAlpcCreateSectionView", gt_windows_print_syscall_ntalpccreatesectionview, gt_windows_print_sysret_ntalpccreatesectionview, NULL },
	{ "NtAlpcCreateSecurityContext", gt_windows_print_syscall_ntalpccreatesecuritycontext, gt_windows_print_sysret_ntalpccreatesecuritycontext, NULL },
	{ "NtAlpcDeletePortSection", gt_windows_print_syscall_ntalpcdeleteportsection, gt_windows_print_sysret_ntalpcdeleteportsection, NULL },
	{ "NtAlpcDeleteResourceReserve", gt_windows_print_syscall_ntalpcdeleteresourcereserve, gt_windows_print_sysret_ntalpcdeleteresourcereserve, NULL },
	{ "NtAlpcDeleteSectionView", gt_windows_print_syscall_ntalpcdeletesectionview, gt_windows_print_sysret_ntalpcdeletesectionview, NULL },
	{ "NtAlpcDeleteSecurityContext", gt_windows_print_syscall_ntalpcdeletesecuritycontext, gt_windows_print_sysret_ntalpcdeletesecuritycontext, NULL },
	{ "NtAlpcDisconnectPort", gt_windows_print_syscall_ntalpcdisconnectport, gt_windows_print_sysret_ntalpcdisconnectport, NULL },
	{ "NtAlpcImpersonateClientOfPort", gt_windows_print_syscall_ntalpcimpersonateclientofport, gt_windows_print_sysret_ntalpcimpersonateclientofport, NULL },
	{ "NtAlpcOpenSenderProcess", gt_windows_print_syscall_ntalpcopensenderprocess, gt_windows_print_sysret_ntalpcopensenderprocess, NULL },
	{ "NtAlpcOpenSenderThread", gt_windows_print_syscall_ntalpcopensenderthread, gt_windows_print_sysret_ntalpcopensenderthread, NULL },
	{ "NtAlpcQueryInformation", gt_windows_print_syscall_ntalpcqueryinformation, gt_windows_print_sysret_ntalpcqueryinformation, NULL },
	{ "NtAlpcQueryInformationMessage", gt_windows_print_syscall_ntalpcqueryinformationmessage, gt_windows_print_sysret_ntalpcqueryinformationmessage, NULL },
	{ "NtAlpcRevokeSecurityContext", gt_windows_print_syscall_ntalpcrevokesecuritycontext, gt_windows_print_sysret_ntalpcrevokesecuritycontext, NULL },
	{ "NtAlpcSendWaitReceivePort", gt_windows_print_syscall_ntalpcsendwaitreceiveport, gt_windows_print_sysret_ntalpcsendwaitreceiveport, NULL },
	{ "NtAlpcSetInformation", gt_windows_print_syscall_ntalpcsetinformation, gt_windows_print_sysret_ntalpcsetinformation, NULL },
	{ "NtApphelpCacheControl", gt_windows_print_syscall_ntapphelpcachecontrol, gt_windows_print_sysret_ntapphelpcachecontrol, NULL },
	{ "NtAreMappedFilesTheSame", gt_windows_print_syscall_ntaremappedfilesthesame, gt_windows_print_sysret_ntaremappedfilesthesame, NULL },
	{ "NtAssignProcessToJobObject", gt_windows_print_syscall_ntassignprocesstojobobject, gt_windows_print_sysret_ntassignprocesstojobobject, NULL },
	{ "NtCallbackReturn", gt_windows_print_syscall_ntcallbackreturn, gt_windows_print_sysret_ntcallbackreturn, NULL },
	{ "NtCancelIoFileEx", gt_windows_print_syscall_ntcanceliofileex, gt_windows_print_sysret_ntcanceliofileex, NULL },
	{ "NtCancelIoFile", gt_windows_print_syscall_ntcanceliofile, gt_windows_print_sysret_ntcanceliofile, NULL },
	{ "NtCancelSynchronousIoFile", gt_windows_print_syscall_ntcancelsynchronousiofile, gt_windows_print_sysret_ntcancelsynchronousiofile, NULL },
	{ "NtCancelTimer", gt_windows_print_syscall_ntcanceltimer, gt_windows_print_sysret_ntcanceltimer, NULL },
	{ "NtClearEvent", gt_windows_print_syscall_ntclearevent, gt_windows_print_sysret_ntclearevent, NULL },
	{ "NtClose", gt_windows_print_syscall_ntclose, gt_windows_print_sysret_ntclose, NULL },
	{ "NtCloseObjectAuditAlarm", gt_windows_print_syscall_ntcloseobjectauditalarm, gt_windows_print_sysret_ntcloseobjectauditalarm, NULL },
	{ "NtCommitComplete", gt_windows_print_syscall_ntcommitcomplete, gt_windows_print_sysret_ntcommitcomplete, NULL },
	{ "NtCommitEnlistment", gt_windows_print_syscall_ntcommitenlistment, gt_windows_print_sysret_ntcommitenlistment, NULL },
	{ "NtCommitTransaction", gt_windows_print_syscall_ntcommittransaction, gt_windows_print_sysret_ntcommittransaction, NULL },
	{ "NtCompactKeys", gt_windows_print_syscall_ntcompactkeys, gt_windows_print_sysret_ntcompactkeys, NULL },
	{ "NtCompareTokens", gt_windows_print_syscall_ntcomparetokens, gt_windows_print_sysret_ntcomparetokens, NULL },
	{ "NtCompleteConnectPort", gt_windows_print_syscall_ntcompleteconnectport, gt_windows_print_sysret_ntcompleteconnectport, NULL },
	{ "NtCompressKey", gt_windows_print_syscall_ntcompresskey, gt_windows_print_sysret_ntcompresskey, NULL },
	{ "NtConnectPort", gt_windows_print_syscall_ntconnectport, gt_windows_print_sysret_ntconnectport, NULL },
	{ "NtContinue", gt_windows_print_syscall_ntcontinue, gt_windows_print_sysret_ntcontinue, NULL },
	{ "NtCreateDebugObject", gt_windows_print_syscall_ntcreatedebugobject, gt_windows_print_sysret_ntcreatedebugobject, NULL },
	{ "NtCreateDirectoryObject", gt_windows_print_syscall_ntcreatedirectoryobject, gt_windows_print_sysret_ntcreatedirectoryobject, NULL },
	{ "NtCreateEnlistment", gt_windows_print_syscall_ntcreateenlistment, gt_windows_print_sysret_ntcreateenlistment, NULL },
	{ "NtCreateEvent", gt_windows_print_syscall_ntcreateevent, gt_windows_print_sysret_ntcreateevent, NULL },
	{ "NtCreateEventPair", gt_windows_print_syscall_ntcreateeventpair, gt_windows_print_sysret_ntcreateeventpair, NULL },
	{ "NtCreateFile", gt_windows_print_syscall_ntcreatefile, gt_windows_print_sysret_ntcreatefile, NULL },
	{ "NtCreateIoCompletion", gt_windows_print_syscall_ntcreateiocompletion, gt_windows_print_sysret_ntcreateiocompletion, NULL },
	{ "NtCreateJobObject", gt_windows_print_syscall_ntcreatejobobject, gt_windows_print_sysret_ntcreatejobobject, NULL },
	{ "NtCreateJobSet", gt_windows_print_syscall_ntcreatejobset, gt_windows_print_sysret_ntcreatejobset, NULL },
	{ "NtCreateKeyedEvent", gt_windows_print_syscall_ntcreatekeyedevent, gt_windows_print_sysret_ntcreatekeyedevent, NULL },
	{ "NtCreateKey", gt_windows_print_syscall_ntcreatekey, gt_windows_print_sysret_ntcreatekey, NULL },
	{ "NtCreateKeyTransacted", gt_windows_print_syscall_ntcreatekeytransacted, gt_windows_print_sysret_ntcreatekeytransacted, NULL },
	{ "NtCreateMailslotFile", gt_windows_print_syscall_ntcreatemailslotfile, gt_windows_print_sysret_ntcreatemailslotfile, NULL },
	{ "NtCreateMutant", gt_windows_print_syscall_ntcreatemutant, gt_windows_print_sysret_ntcreatemutant, NULL },
	{ "NtCreateNamedPipeFile", gt_windows_print_syscall_ntcreatenamedpipefile, gt_windows_print_sysret_ntcreatenamedpipefile, NULL },
	{ "NtCreatePagingFile", gt_windows_print_syscall_ntcreatepagingfile, gt_windows_print_sysret_ntcreatepagingfile, NULL },
	{ "NtCreatePort", gt_windows_print_syscall_ntcreateport, gt_windows_print_sysret_ntcreateport, NULL },
	{ "NtCreatePrivateNamespace", gt_windows_print_syscall_ntcreateprivatenamespace, gt_windows_print_sysret_ntcreateprivatenamespace, NULL },
	{ "NtCreateProcessEx", gt_windows_print_syscall_ntcreateprocessex, gt_windows_print_sysret_ntcreateprocessex, NULL },
	{ "NtCreateProcess", gt_windows_print_syscall_ntcreateprocess, gt_windows_print_sysret_ntcreateprocess, NULL },
	{ "NtCreateProfileEx", gt_windows_print_syscall_ntcreateprofileex, gt_windows_print_sysret_ntcreateprofileex, NULL },
	{ "NtCreateProfile", gt_windows_print_syscall_ntcreateprofile, gt_windows_print_sysret_ntcreateprofile, NULL },
	{ "NtCreateResourceManager", gt_windows_print_syscall_ntcreateresourcemanager, gt_windows_print_sysret_ntcreateresourcemanager, NULL },
	{ "NtCreateSection", gt_windows_print_syscall_ntcreatesection, gt_windows_print_sysret_ntcreatesection, NULL },
	{ "NtCreateSemaphore", gt_windows_print_syscall_ntcreatesemaphore, gt_windows_print_sysret_ntcreatesemaphore, NULL },
	{ "NtCreateSymbolicLinkObject", gt_windows_print_syscall_ntcreatesymboliclinkobject, gt_windows_print_sysret_ntcreatesymboliclinkobject, NULL },
	{ "NtCreateThreadEx", gt_windows_print_syscall_ntcreatethreadex, gt_windows_print_sysret_ntcreatethreadex, NULL },
	{ "NtCreateThread", gt_windows_print_syscall_ntcreatethread, gt_windows_print_sysret_ntcreatethread, NULL },
	{ "NtCreateTimer", gt_windows_print_syscall_ntcreatetimer, gt_windows_print_sysret_ntcreatetimer, NULL },
	{ "NtCreateToken", gt_windows_print_syscall_ntcreatetoken, gt_windows_print_sysret_ntcreatetoken, NULL },
	{ "NtCreateTransactionManager", gt_windows_print_syscall_ntcreatetransactionmanager, gt_windows_print_sysret_ntcreatetransactionmanager, NULL },
	{ "NtCreateTransaction", gt_windows_print_syscall_ntcreatetransaction, gt_windows_print_sysret_ntcreatetransaction, NULL },
	{ "NtCreateUserProcess", gt_windows_print_syscall_ntcreateuserprocess, gt_windows_print_sysret_ntcreateuserprocess, NULL },
	{ "NtCreateWaitablePort", gt_windows_print_syscall_ntcreatewaitableport, gt_windows_print_sysret_ntcreatewaitableport, NULL },
	{ "NtCreateWorkerFactory", gt_windows_print_syscall_ntcreateworkerfactory, gt_windows_print_sysret_ntcreateworkerfactory, NULL },
	{ "NtDebugActiveProcess", gt_windows_print_syscall_ntdebugactiveprocess, gt_windows_print_sysret_ntdebugactiveprocess, NULL },
	{ "NtDebugContinue", gt_windows_print_syscall_ntdebugcontinue, gt_windows_print_sysret_ntdebugcontinue, NULL },
	{ "NtDelayExecution", gt_windows_print_syscall_ntdelayexecution, gt_windows_print_sysret_ntdelayexecution, NULL },
	{ "NtDeleteAtom", gt_windows_print_syscall_ntdeleteatom, gt_windows_print_sysret_ntdeleteatom, NULL },
	{ "NtDeleteBootEntry", gt_windows_print_syscall_ntdeletebootentry, gt_windows_print_sysret_ntdeletebootentry, NULL },
	{ "NtDeleteDriverEntry", gt_windows_print_syscall_ntdeletedriverentry, gt_windows_print_sysret_ntdeletedriverentry, NULL },
	{ "NtDeleteFile", gt_windows_print_syscall_ntdeletefile, gt_windows_print_sysret_ntdeletefile, NULL },
	{ "NtDeleteKey", gt_windows_print_syscall_ntdeletekey, gt_windows_print_sysret_ntdeletekey, NULL },
	{ "NtDeleteObjectAuditAlarm", gt_windows_print_syscall_ntdeleteobjectauditalarm, gt_windows_print_sysret_ntdeleteobjectauditalarm, NULL },
	{ "NtDeletePrivateNamespace", gt_windows_print_syscall_ntdeleteprivatenamespace, gt_windows_print_sysret_ntdeleteprivatenamespace, NULL },
	{ "NtDeleteValueKey", gt_windows_print_syscall_ntdeletevaluekey, gt_windows_print_sysret_ntdeletevaluekey, NULL },
	{ "NtDeviceIoControlFile", gt_windows_print_syscall_ntdeviceiocontrolfile, gt_windows_print_sysret_ntdeviceiocontrolfile, NULL },
	{ "NtDisableLastKnownGood", gt_windows_print_syscall_ntdisablelastknowngood, gt_windows_print_sysret_ntdisablelastknowngood, NULL },
	{ "NtDisplayString", gt_windows_print_syscall_ntdisplaystring, gt_windows_print_sysret_ntdisplaystring, NULL },
	{ "NtDrawText", gt_windows_print_syscall_ntdrawtext, gt_windows_print_sysret_ntdrawtext, NULL },
	{ "NtDuplicateObject", gt_windows_print_syscall_ntduplicateobject, gt_windows_print_sysret_ntduplicateobject, NULL },
	{ "NtDuplicateToken", gt_windows_print_syscall_ntduplicatetoken, gt_windows_print_sysret_ntduplicatetoken, NULL },
	{ "NtEnableLastKnownGood", gt_windows_print_syscall_ntenablelastknowngood, gt_windows_print_sysret_ntenablelastknowngood, NULL },
	{ "NtEnumerateBootEntries", gt_windows_print_syscall_ntenumeratebootentries, gt_windows_print_sysret_ntenumeratebootentries, NULL },
	{ "NtEnumerateDriverEntries", gt_windows_print_syscall_ntenumeratedriverentries, gt_windows_print_sysret_ntenumeratedriverentries, NULL },
	{ "NtEnumerateKey", gt_windows_print_syscall_ntenumeratekey, gt_windows_print_sysret_ntenumeratekey, NULL },
	{ "NtEnumerateSystemEnvironmentValuesEx", gt_windows_print_syscall_ntenumeratesystemenvironmentvaluesex, gt_windows_print_sysret_ntenumeratesystemenvironmentvaluesex, NULL },
	{ "NtEnumerateTransactionObject", gt_windows_print_syscall_ntenumeratetransactionobject, gt_windows_print_sysret_ntenumeratetransactionobject, NULL },
	{ "NtEnumerateValueKey", gt_windows_print_syscall_ntenumeratevaluekey, gt_windows_print_sysret_ntenumeratevaluekey, NULL },
	{ "NtExtendSection", gt_windows_print_syscall_ntextendsection, gt_windows_print_sysret_ntextendsection, NULL },
	{ "NtFilterToken", gt_windows_print_syscall_ntfiltertoken, gt_windows_print_sysret_ntfiltertoken, NULL },
	{ "NtFindAtom", gt_windows_print_syscall_ntfindatom, gt_windows_print_sysret_ntfindatom, NULL },
	{ "NtFlushBuffersFile", gt_windows_print_syscall_ntflushbuffersfile, gt_windows_print_sysret_ntflushbuffersfile, NULL },
	{ "NtFlushInstallUILanguage", gt_windows_print_syscall_ntflushinstalluilanguage, gt_windows_print_sysret_ntflushinstalluilanguage, NULL },
	{ "NtFlushInstructionCache", gt_windows_print_syscall_ntflushinstructioncache, gt_windows_print_sysret_ntflushinstructioncache, NULL },
	{ "NtFlushKey", gt_windows_print_syscall_ntflushkey, gt_windows_print_sysret_ntflushkey, NULL },
	{ "NtFlushProcessWriteBuffers", gt_windows_print_syscall_ntflushprocesswritebuffers, gt_windows_print_sysret_ntflushprocesswritebuffers, NULL },
	{ "NtFlushVirtualMemory", gt_windows_print_syscall_ntflushvirtualmemory, gt_windows_print_sysret_ntflushvirtualmemory, NULL },
	{ "NtFlushWriteBuffer", gt_windows_print_syscall_ntflushwritebuffer, gt_windows_print_sysret_ntflushwritebuffer, NULL },
	{ "NtFreeUserPhysicalPages", gt_windows_print_syscall_ntfreeuserphysicalpages, gt_windows_print_sysret_ntfreeuserphysicalpages, NULL },
	{ "NtFreeVirtualMemory", gt_windows_print_syscall_ntfreevirtualmemory, gt_windows_print_sysret_ntfreevirtualmemory, NULL },
	{ "NtFreezeRegistry", gt_windows_print_syscall_ntfreezeregistry, gt_windows_print_sysret_ntfreezeregistry, NULL },
	{ "NtFreezeTransactions", gt_windows_print_syscall_ntfreezetransactions, gt_windows_print_sysret_ntfreezetransactions, NULL },
	{ "NtFsControlFile", gt_windows_print_syscall_ntfscontrolfile, gt_windows_print_sysret_ntfscontrolfile, NULL },
	{ "NtGetContextThread", gt_windows_print_syscall_ntgetcontextthread, gt_windows_print_sysret_ntgetcontextthread, NULL },
	{ "NtGetCurrentProcessorNumber", gt_windows_print_syscall_ntgetcurrentprocessornumber, gt_windows_print_sysret_ntgetcurrentprocessornumber, NULL },
	{ "NtGetDevicePowerState", gt_windows_print_syscall_ntgetdevicepowerstate, gt_windows_print_sysret_ntgetdevicepowerstate, NULL },
	{ "NtGetMUIRegistryInfo", gt_windows_print_syscall_ntgetmuiregistryinfo, gt_windows_print_sysret_ntgetmuiregistryinfo, NULL },
	{ "NtGetNextProcess", gt_windows_print_syscall_ntgetnextprocess, gt_windows_print_sysret_ntgetnextprocess, NULL },
	{ "NtGetNextThread", gt_windows_print_syscall_ntgetnextthread, gt_windows_print_sysret_ntgetnextthread, NULL },
	{ "NtGetNlsSectionPtr", gt_windows_print_syscall_ntgetnlssectionptr, gt_windows_print_sysret_ntgetnlssectionptr, NULL },
	{ "NtGetNotificationResourceManager", gt_windows_print_syscall_ntgetnotificationresourcemanager, gt_windows_print_sysret_ntgetnotificationresourcemanager, NULL },
	{ "NtGetPlugPlayEvent", gt_windows_print_syscall_ntgetplugplayevent, gt_windows_print_sysret_ntgetplugplayevent, NULL },
	{ "NtGetWriteWatch", gt_windows_print_syscall_ntgetwritewatch, gt_windows_print_sysret_ntgetwritewatch, NULL },
	{ "NtImpersonateAnonymousToken", gt_windows_print_syscall_ntimpersonateanonymoustoken, gt_windows_print_sysret_ntimpersonateanonymoustoken, NULL },
	{ "NtImpersonateClientOfPort", gt_windows_print_syscall_ntimpersonateclientofport, gt_windows_print_sysret_ntimpersonateclientofport, NULL },
	{ "NtImpersonateThread", gt_windows_print_syscall_ntimpersonatethread, gt_windows_print_sysret_ntimpersonatethread, NULL },
	{ "NtInitializeNlsFiles", gt_windows_print_syscall_ntinitializenlsfiles, gt_windows_print_sysret_ntinitializenlsfiles, NULL },
	{ "NtInitializeRegistry", gt_windows_print_syscall_ntinitializeregistry, gt_windows_print_sysret_ntinitializeregistry, NULL },
	{ "NtInitiatePowerAction", gt_windows_print_syscall_ntinitiatepoweraction, gt_windows_print_sysret_ntinitiatepoweraction, NULL },
	{ "NtIsProcessInJob", gt_windows_print_syscall_ntisprocessinjob, gt_windows_print_sysret_ntisprocessinjob, NULL },
	{ "NtIsSystemResumeAutomatic", gt_windows_print_syscall_ntissystemresumeautomatic, gt_windows_print_sysret_ntissystemresumeautomatic, NULL },
	{ "NtIsUILanguageComitted", gt_windows_print_syscall_ntisuilanguagecomitted, gt_windows_print_sysret_ntisuilanguagecomitted, NULL },
	{ "NtListenPort", gt_windows_print_syscall_ntlistenport, gt_windows_print_sysret_ntlistenport, NULL },
	{ "NtLoadDriver", gt_windows_print_syscall_ntloaddriver, gt_windows_print_sysret_ntloaddriver, NULL },
	{ "NtLoadKey2", gt_windows_print_syscall_ntloadkey2, gt_windows_print_sysret_ntloadkey2, NULL },
	{ "NtLoadKeyEx", gt_windows_print_syscall_ntloadkeyex, gt_windows_print_sysret_ntloadkeyex, NULL },
	{ "NtLoadKey", gt_windows_print_syscall_ntloadkey, gt_windows_print_sysret_ntloadkey, NULL },
	{ "NtLockFile", gt_windows_print_syscall_ntlockfile, gt_windows_print_sysret_ntlockfile, NULL },
	{ "NtLockProductActivationKeys", gt_windows_print_syscall_ntlockproductactivationkeys, gt_windows_print_sysret_ntlockproductactivationkeys, NULL },
	{ "NtLockRegistryKey", gt_windows_print_syscall_ntlockregistrykey, gt_windows_print_sysret_ntlockregistrykey, NULL },
	{ "NtLockVirtualMemory", gt_windows_print_syscall_ntlockvirtualmemory, gt_windows_print_sysret_ntlockvirtualmemory, NULL },
	{ "NtMakePermanentObject", gt_windows_print_syscall_ntmakepermanentobject, gt_windows_print_sysret_ntmakepermanentobject, NULL },
	{ "NtMakeTemporaryObject", gt_windows_print_syscall_ntmaketemporaryobject, gt_windows_print_sysret_ntmaketemporaryobject, NULL },
	{ "NtMapCMFModule", gt_windows_print_syscall_ntmapcmfmodule, gt_windows_print_sysret_ntmapcmfmodule, NULL },
	{ "NtMapUserPhysicalPages", gt_windows_print_syscall_ntmapuserphysicalpages, gt_windows_print_sysret_ntmapuserphysicalpages, NULL },
	{ "NtMapUserPhysicalPagesScatter", gt_windows_print_syscall_ntmapuserphysicalpagesscatter, gt_windows_print_sysret_ntmapuserphysicalpagesscatter, NULL },
	{ "NtMapViewOfSection", gt_windows_print_syscall_ntmapviewofsection, gt_windows_print_sysret_ntmapviewofsection, NULL },
	{ "NtModifyBootEntry", gt_windows_print_syscall_ntmodifybootentry, gt_windows_print_sysret_ntmodifybootentry, NULL },
	{ "NtModifyDriverEntry", gt_windows_print_syscall_ntmodifydriverentry, gt_windows_print_sysret_ntmodifydriverentry, NULL },
	{ "NtNotifyChangeDirectoryFile", gt_windows_print_syscall_ntnotifychangedirectoryfile, gt_windows_print_sysret_ntnotifychangedirectoryfile, NULL },
	{ "NtNotifyChangeKey", gt_windows_print_syscall_ntnotifychangekey, gt_windows_print_sysret_ntnotifychangekey, NULL },
	{ "NtNotifyChangeMultipleKeys", gt_windows_print_syscall_ntnotifychangemultiplekeys, gt_windows_print_sysret_ntnotifychangemultiplekeys, NULL },
	{ "NtNotifyChangeSession", gt_windows_print_syscall_ntnotifychangesession, gt_windows_print_sysret_ntnotifychangesession, NULL },
	{ "NtOpenDirectoryObject", gt_windows_print_syscall_ntopendirectoryobject, gt_windows_print_sysret_ntopendirectoryobject, NULL },
	{ "NtOpenEnlistment", gt_windows_print_syscall_ntopenenlistment, gt_windows_print_sysret_ntopenenlistment, NULL },
	{ "NtOpenEvent", gt_windows_print_syscall_ntopenevent, gt_windows_print_sysret_ntopenevent, NULL },
	{ "NtOpenEventPair", gt_windows_print_syscall_ntopeneventpair, gt_windows_print_sysret_ntopeneventpair, NULL },
	{ "NtOpenFile", gt_windows_print_syscall_ntopenfile, gt_windows_print_sysret_ntopenfile, NULL },
	{ "NtOpenIoCompletion", gt_windows_print_syscall_ntopeniocompletion, gt_windows_print_sysret_ntopeniocompletion, NULL },
	{ "NtOpenJobObject", gt_windows_print_syscall_ntopenjobobject, gt_windows_print_sysret_ntopenjobobject, NULL },
	{ "NtOpenKeyedEvent", gt_windows_print_syscall_ntopenkeyedevent, gt_windows_print_sysret_ntopenkeyedevent, NULL },
	{ "NtOpenKeyEx", gt_windows_print_syscall_ntopenkeyex, gt_windows_print_sysret_ntopenkeyex, NULL },
	{ "NtOpenKey", gt_windows_print_syscall_ntopenkey, gt_windows_print_sysret_ntopenkey, NULL },
	{ "NtOpenKeyTransactedEx", gt_windows_print_syscall_ntopenkeytransactedex, gt_windows_print_sysret_ntopenkeytransactedex, NULL },
	{ "NtOpenKeyTransacted", gt_windows_print_syscall_ntopenkeytransacted, gt_windows_print_sysret_ntopenkeytransacted, NULL },
	{ "NtOpenMutant", gt_windows_print_syscall_ntopenmutant, gt_windows_print_sysret_ntopenmutant, NULL },
	{ "NtOpenObjectAuditAlarm", gt_windows_print_syscall_ntopenobjectauditalarm, gt_windows_print_sysret_ntopenobjectauditalarm, NULL },
	{ "NtOpenPrivateNamespace", gt_windows_print_syscall_ntopenprivatenamespace, gt_windows_print_sysret_ntopenprivatenamespace, NULL },
	{ "NtOpenProcess", gt_windows_print_syscall_ntopenprocess, gt_windows_print_sysret_ntopenprocess, NULL },
	{ "NtOpenProcessTokenEx", gt_windows_print_syscall_ntopenprocesstokenex, gt_windows_print_sysret_ntopenprocesstokenex, NULL },
	{ "NtOpenProcessToken", gt_windows_print_syscall_ntopenprocesstoken, gt_windows_print_sysret_ntopenprocesstoken, NULL },
	{ "NtOpenResourceManager", gt_windows_print_syscall_ntopenresourcemanager, gt_windows_print_sysret_ntopenresourcemanager, NULL },
	{ "NtOpenSection", gt_windows_print_syscall_ntopensection, gt_windows_print_sysret_ntopensection, NULL },
	{ "NtOpenSemaphore", gt_windows_print_syscall_ntopensemaphore, gt_windows_print_sysret_ntopensemaphore, NULL },
	{ "NtOpenSession", gt_windows_print_syscall_ntopensession, gt_windows_print_sysret_ntopensession, NULL },
	{ "NtOpenSymbolicLinkObject", gt_windows_print_syscall_ntopensymboliclinkobject, gt_windows_print_sysret_ntopensymboliclinkobject, NULL },
	{ "NtOpenThread", gt_windows_print_syscall_ntopenthread, gt_windows_print_sysret_ntopenthread, NULL },
	{ "NtOpenThreadTokenEx", gt_windows_print_syscall_ntopenthreadtokenex, gt_windows_print_sysret_ntopenthreadtokenex, NULL },
	{ "NtOpenThreadToken", gt_windows_print_syscall_ntopenthreadtoken, gt_windows_print_sysret_ntopenthreadtoken, NULL },
	{ "NtOpenTimer", gt_windows_print_syscall_ntopentimer, gt_windows_print_sysret_ntopentimer, NULL },
	{ "NtOpenTransactionManager", gt_windows_print_syscall_ntopentransactionmanager, gt_windows_print_sysret_ntopentransactionmanager, NULL },
	{ "NtOpenTransaction", gt_windows_print_syscall_ntopentransaction, gt_windows_print_sysret_ntopentransaction, NULL },
	{ "NtPlugPlayControl", gt_windows_print_syscall_ntplugplaycontrol, gt_windows_print_sysret_ntplugplaycontrol, NULL },
	{ "NtPowerInformation", gt_windows_print_syscall_ntpowerinformation, gt_windows_print_sysret_ntpowerinformation, NULL },
	{ "NtPrepareComplete", gt_windows_print_syscall_ntpreparecomplete, gt_windows_print_sysret_ntpreparecomplete, NULL },
	{ "NtPrepareEnlistment", gt_windows_print_syscall_ntprepareenlistment, gt_windows_print_sysret_ntprepareenlistment, NULL },
	{ "NtPrePrepareComplete", gt_windows_print_syscall_ntprepreparecomplete, gt_windows_print_sysret_ntprepreparecomplete, NULL },
	{ "NtPrePrepareEnlistment", gt_windows_print_syscall_ntpreprepareenlistment, gt_windows_print_sysret_ntpreprepareenlistment, NULL },
	{ "NtPrivilegeCheck", gt_windows_print_syscall_ntprivilegecheck, gt_windows_print_sysret_ntprivilegecheck, NULL },
	{ "NtPrivilegedServiceAuditAlarm", gt_windows_print_syscall_ntprivilegedserviceauditalarm, gt_windows_print_sysret_ntprivilegedserviceauditalarm, NULL },
	{ "NtPrivilegeObjectAuditAlarm", gt_windows_print_syscall_ntprivilegeobjectauditalarm, gt_windows_print_sysret_ntprivilegeobjectauditalarm, NULL },
	{ "NtPropagationComplete", gt_windows_print_syscall_ntpropagationcomplete, gt_windows_print_sysret_ntpropagationcomplete, NULL },
	{ "NtPropagationFailed", gt_windows_print_syscall_ntpropagationfailed, gt_windows_print_sysret_ntpropagationfailed, NULL },
	{ "NtProtectVirtualMemory", gt_windows_print_syscall_ntprotectvirtualmemory, gt_windows_print_sysret_ntprotectvirtualmemory, NULL },
	{ "NtPulseEvent", gt_windows_print_syscall_ntpulseevent, gt_windows_print_sysret_ntpulseevent, NULL },
	{ "NtQueryAttributesFile", gt_windows_print_syscall_ntqueryattributesfile, gt_windows_print_sysret_ntqueryattributesfile, NULL },
	{ "NtQueryBootEntryOrder", gt_windows_print_syscall_ntquerybootentryorder, gt_windows_print_sysret_ntquerybootentryorder, NULL },
	{ "NtQueryBootOptions", gt_windows_print_syscall_ntquerybootoptions, gt_windows_print_sysret_ntquerybootoptions, NULL },
	{ "NtQueryDebugFilterState", gt_windows_print_syscall_ntquerydebugfilterstate, gt_windows_print_sysret_ntquerydebugfilterstate, NULL },
	{ "NtQueryDefaultLocale", gt_windows_print_syscall_ntquerydefaultlocale, gt_windows_print_sysret_ntquerydefaultlocale, NULL },
	{ "NtQueryDefaultUILanguage", gt_windows_print_syscall_ntquerydefaultuilanguage, gt_windows_print_sysret_ntquerydefaultuilanguage, NULL },
	{ "NtQueryDirectoryFile", gt_windows_print_syscall_ntquerydirectoryfile, gt_windows_print_sysret_ntquerydirectoryfile, NULL },
	{ "NtQueryDirectoryObject", gt_windows_print_syscall_ntquerydirectoryobject, gt_windows_print_sysret_ntquerydirectoryobject, NULL },
	{ "NtQueryDriverEntryOrder", gt_windows_print_syscall_ntquerydriverentryorder, gt_windows_print_sysret_ntquerydriverentryorder, NULL },
	{ "NtQueryEaFile", gt_windows_print_syscall_ntqueryeafile, gt_windows_print_sysret_ntqueryeafile, NULL },
	{ "NtQueryEvent", gt_windows_print_syscall_ntqueryevent, gt_windows_print_sysret_ntqueryevent, NULL },
	{ "NtQueryFullAttributesFile", gt_windows_print_syscall_ntqueryfullattributesfile, gt_windows_print_sysret_ntqueryfullattributesfile, NULL },
	{ "NtQueryInformationAtom", gt_windows_print_syscall_ntqueryinformationatom, gt_windows_print_sysret_ntqueryinformationatom, NULL },
	{ "NtQueryInformationEnlistment", gt_windows_print_syscall_ntqueryinformationenlistment, gt_windows_print_sysret_ntqueryinformationenlistment, NULL },
	{ "NtQueryInformationFile", gt_windows_print_syscall_ntqueryinformationfile, gt_windows_print_sysret_ntqueryinformationfile, NULL },
	{ "NtQueryInformationJobObject", gt_windows_print_syscall_ntqueryinformationjobobject, gt_windows_print_sysret_ntqueryinformationjobobject, NULL },
	{ "NtQueryInformationPort", gt_windows_print_syscall_ntqueryinformationport, gt_windows_print_sysret_ntqueryinformationport, NULL },
	{ "NtQueryInformationProcess", gt_windows_print_syscall_ntqueryinformationprocess, gt_windows_print_sysret_ntqueryinformationprocess, NULL },
	{ "NtQueryInformationResourceManager", gt_windows_print_syscall_ntqueryinformationresourcemanager, gt_windows_print_sysret_ntqueryinformationresourcemanager, NULL },
	{ "NtQueryInformationThread", gt_windows_print_syscall_ntqueryinformationthread, gt_windows_print_sysret_ntqueryinformationthread, NULL },
	{ "NtQueryInformationToken", gt_windows_print_syscall_ntqueryinformationtoken, gt_windows_print_sysret_ntqueryinformationtoken, NULL },
	{ "NtQueryInformationTransaction", gt_windows_print_syscall_ntqueryinformationtransaction, gt_windows_print_sysret_ntqueryinformationtransaction, NULL },
	{ "NtQueryInformationTransactionManager", gt_windows_print_syscall_ntqueryinformationtransactionmanager, gt_windows_print_sysret_ntqueryinformationtransactionmanager, NULL },
	{ "NtQueryInformationWorkerFactory", gt_windows_print_syscall_ntqueryinformationworkerfactory, gt_windows_print_sysret_ntqueryinformationworkerfactory, NULL },
	{ "NtQueryInstallUILanguage", gt_windows_print_syscall_ntqueryinstalluilanguage, gt_windows_print_sysret_ntqueryinstalluilanguage, NULL },
	{ "NtQueryIntervalProfile", gt_windows_print_syscall_ntqueryintervalprofile, gt_windows_print_sysret_ntqueryintervalprofile, NULL },
	{ "NtQueryIoCompletion", gt_windows_print_syscall_ntqueryiocompletion, gt_windows_print_sysret_ntqueryiocompletion, NULL },
	{ "NtQueryKey", gt_windows_print_syscall_ntquerykey, gt_windows_print_sysret_ntquerykey, NULL },
	{ "NtQueryLicenseValue", gt_windows_print_syscall_ntquerylicensevalue, gt_windows_print_sysret_ntquerylicensevalue, NULL },
	{ "NtQueryMultipleValueKey", gt_windows_print_syscall_ntquerymultiplevaluekey, gt_windows_print_sysret_ntquerymultiplevaluekey, NULL },
	{ "NtQueryMutant", gt_windows_print_syscall_ntquerymutant, gt_windows_print_sysret_ntquerymutant, NULL },
	{ "NtQueryObject", gt_windows_print_syscall_ntqueryobject, gt_windows_print_sysret_ntqueryobject, NULL },
	{ "NtQueryOpenSubKeysEx", gt_windows_print_syscall_ntqueryopensubkeysex, gt_windows_print_sysret_ntqueryopensubkeysex, NULL },
	{ "NtQueryOpenSubKeys", gt_windows_print_syscall_ntqueryopensubkeys, gt_windows_print_sysret_ntqueryopensubkeys, NULL },
	{ "NtQueryPerformanceCounter", gt_windows_print_syscall_ntqueryperformancecounter, gt_windows_print_sysret_ntqueryperformancecounter, NULL },
	{ "NtQueryPortInformationProcess", gt_windows_print_syscall_ntqueryportinformationprocess, gt_windows_print_sysret_ntqueryportinformationprocess, NULL },
	{ "NtQueryQuotaInformationFile", gt_windows_print_syscall_ntqueryquotainformationfile, gt_windows_print_sysret_ntqueryquotainformationfile, NULL },
	{ "NtQuerySection", gt_windows_print_syscall_ntquerysection, gt_windows_print_sysret_ntquerysection, NULL },
	{ "NtQuerySecurityAttributesToken", gt_windows_print_syscall_ntquerysecurityattributestoken, gt_windows_print_sysret_ntquerysecurityattributestoken, NULL },
	{ "NtQuerySecurityObject", gt_windows_print_syscall_ntquerysecurityobject, gt_windows_print_sysret_ntquerysecurityobject, NULL },
	{ "NtQuerySemaphore", gt_windows_print_syscall_ntquerysemaphore, gt_windows_print_sysret_ntquerysemaphore, NULL },
	{ "NtQuerySymbolicLinkObject", gt_windows_print_syscall_ntquerysymboliclinkobject, gt_windows_print_sysret_ntquerysymboliclinkobject, NULL },
	{ "NtQuerySystemEnvironmentValueEx", gt_windows_print_syscall_ntquerysystemenvironmentvalueex, gt_windows_print_sysret_ntquerysystemenvironmentvalueex, NULL },
	{ "NtQuerySystemEnvironmentValue", gt_windows_print_syscall_ntquerysystemenvironmentvalue, gt_windows_print_sysret_ntquerysystemenvironmentvalue, NULL },
	{ "NtQuerySystemInformationEx", gt_windows_print_syscall_ntquerysysteminformationex, gt_windows_print_sysret_ntquerysysteminformationex, NULL },
	{ "NtQuerySystemInformation", gt_windows_print_syscall_ntquerysysteminformation, gt_windows_print_sysret_ntquerysysteminformation, NULL },
	{ "NtQuerySystemTime", gt_windows_print_syscall_ntquerysystemtime, gt_windows_print_sysret_ntquerysystemtime, NULL },
	{ "NtQueryTimer", gt_windows_print_syscall_ntquerytimer, gt_windows_print_sysret_ntquerytimer, NULL },
	{ "NtQueryTimerResolution", gt_windows_print_syscall_ntquerytimerresolution, gt_windows_print_sysret_ntquerytimerresolution, NULL },
	{ "NtQueryValueKey", gt_windows_print_syscall_ntqueryvaluekey, gt_windows_print_sysret_ntqueryvaluekey, NULL },
	{ "NtQueryVirtualMemory", gt_windows_print_syscall_ntqueryvirtualmemory, gt_windows_print_sysret_ntqueryvirtualmemory, NULL },
	{ "NtQueryVolumeInformationFile", gt_windows_print_syscall_ntqueryvolumeinformationfile, gt_windows_print_sysret_ntqueryvolumeinformationfile, NULL },
	{ "NtQueueApcThreadEx", gt_windows_print_syscall_ntqueueapcthreadex, gt_windows_print_sysret_ntqueueapcthreadex, NULL },
	{ "NtQueueApcThread", gt_windows_print_syscall_ntqueueapcthread, gt_windows_print_sysret_ntqueueapcthread, NULL },
	{ "NtRaiseException", gt_windows_print_syscall_ntraiseexception, gt_windows_print_sysret_ntraiseexception, NULL },
	{ "NtRaiseHardError", gt_windows_print_syscall_ntraiseharderror, gt_windows_print_sysret_ntraiseharderror, NULL },
	{ "NtReadFile", gt_windows_print_syscall_ntreadfile, gt_windows_print_sysret_ntreadfile, NULL },
	{ "NtReadFileScatter", gt_windows_print_syscall_ntreadfilescatter, gt_windows_print_sysret_ntreadfilescatter, NULL },
	{ "NtReadOnlyEnlistment", gt_windows_print_syscall_ntreadonlyenlistment, gt_windows_print_sysret_ntreadonlyenlistment, NULL },
	{ "NtReadRequestData", gt_windows_print_syscall_ntreadrequestdata, gt_windows_print_sysret_ntreadrequestdata, NULL },
	{ "NtReadVirtualMemory", gt_windows_print_syscall_ntreadvirtualmemory, gt_windows_print_sysret_ntreadvirtualmemory, NULL },
	{ "NtRecoverEnlistment", gt_windows_print_syscall_ntrecoverenlistment, gt_windows_print_sysret_ntrecoverenlistment, NULL },
	{ "NtRecoverResourceManager", gt_windows_print_syscall_ntrecoverresourcemanager, gt_windows_print_sysret_ntrecoverresourcemanager, NULL },
	{ "NtRecoverTransactionManager", gt_windows_print_syscall_ntrecovertransactionmanager, gt_windows_print_sysret_ntrecovertransactionmanager, NULL },
	{ "NtRegisterProtocolAddressInformation", gt_windows_print_syscall_ntregisterprotocoladdressinformation, gt_windows_print_sysret_ntregisterprotocoladdressinformation, NULL },
	{ "NtRegisterThreadTerminatePort", gt_windows_print_syscall_ntregisterthreadterminateport, gt_windows_print_sysret_ntregisterthreadterminateport, NULL },
	{ "NtReleaseKeyedEvent", gt_windows_print_syscall_ntreleasekeyedevent, gt_windows_print_sysret_ntreleasekeyedevent, NULL },
	{ "NtReleaseMutant", gt_windows_print_syscall_ntreleasemutant, gt_windows_print_sysret_ntreleasemutant, NULL },
	{ "NtReleaseSemaphore", gt_windows_print_syscall_ntreleasesemaphore, gt_windows_print_sysret_ntreleasesemaphore, NULL },
	{ "NtReleaseWorkerFactoryWorker", gt_windows_print_syscall_ntreleaseworkerfactoryworker, gt_windows_print_sysret_ntreleaseworkerfactoryworker, NULL },
	{ "NtRemoveIoCompletionEx", gt_windows_print_syscall_ntremoveiocompletionex, gt_windows_print_sysret_ntremoveiocompletionex, NULL },
	{ "NtRemoveIoCompletion", gt_windows_print_syscall_ntremoveiocompletion, gt_windows_print_sysret_ntremoveiocompletion, NULL },
	{ "NtRemoveProcessDebug", gt_windows_print_syscall_ntremoveprocessdebug, gt_windows_print_sysret_ntremoveprocessdebug, NULL },
	{ "NtRenameKey", gt_windows_print_syscall_ntrenamekey, gt_windows_print_sysret_ntrenamekey, NULL },
	{ "NtRenameTransactionManager", gt_windows_print_syscall_ntrenametransactionmanager, gt_windows_print_sysret_ntrenametransactionmanager, NULL },
	{ "NtReplaceKey", gt_windows_print_syscall_ntreplacekey, gt_windows_print_sysret_ntreplacekey, NULL },
	{ "NtReplacePartitionUnit", gt_windows_print_syscall_ntreplacepartitionunit, gt_windows_print_sysret_ntreplacepartitionunit, NULL },
	{ "NtReplyPort", gt_windows_print_syscall_ntreplyport, gt_windows_print_sysret_ntreplyport, NULL },
	{ "NtReplyWaitReceivePortEx", gt_windows_print_syscall_ntreplywaitreceiveportex, gt_windows_print_sysret_ntreplywaitreceiveportex, NULL },
	{ "NtReplyWaitReceivePort", gt_windows_print_syscall_ntreplywaitreceiveport, gt_windows_print_sysret_ntreplywaitreceiveport, NULL },
	{ "NtReplyWaitReplyPort", gt_windows_print_syscall_ntreplywaitreplyport, gt_windows_print_sysret_ntreplywaitreplyport, NULL },
	{ "NtRequestPort", gt_windows_print_syscall_ntrequestport, gt_windows_print_sysret_ntrequestport, NULL },
	{ "NtRequestWaitReplyPort", gt_windows_print_syscall_ntrequestwaitreplyport, gt_windows_print_sysret_ntrequestwaitreplyport, NULL },
	{ "NtResetEvent", gt_windows_print_syscall_ntresetevent, gt_windows_print_sysret_ntresetevent, NULL },
	{ "NtResetWriteWatch", gt_windows_print_syscall_ntresetwritewatch, gt_windows_print_sysret_ntresetwritewatch, NULL },
	{ "NtRestoreKey", gt_windows_print_syscall_ntrestorekey, gt_windows_print_sysret_ntrestorekey, NULL },
	{ "NtResumeProcess", gt_windows_print_syscall_ntresumeprocess, gt_windows_print_sysret_ntresumeprocess, NULL },
	{ "NtResumeThread", gt_windows_print_syscall_ntresumethread, gt_windows_print_sysret_ntresumethread, NULL },
	{ "NtRollbackComplete", gt_windows_print_syscall_ntrollbackcomplete, gt_windows_print_sysret_ntrollbackcomplete, NULL },
	{ "NtRollbackEnlistment", gt_windows_print_syscall_ntrollbackenlistment, gt_windows_print_sysret_ntrollbackenlistment, NULL },
	{ "NtRollbackTransaction", gt_windows_print_syscall_ntrollbacktransaction, gt_windows_print_sysret_ntrollbacktransaction, NULL },
	{ "NtRollforwardTransactionManager", gt_windows_print_syscall_ntrollforwardtransactionmanager, gt_windows_print_sysret_ntrollforwardtransactionmanager, NULL },
	{ "NtSaveKeyEx", gt_windows_print_syscall_ntsavekeyex, gt_windows_print_sysret_ntsavekeyex, NULL },
	{ "NtSaveKey", gt_windows_print_syscall_ntsavekey, gt_windows_print_sysret_ntsavekey, NULL },
	{ "NtSaveMergedKeys", gt_windows_print_syscall_ntsavemergedkeys, gt_windows_print_sysret_ntsavemergedkeys, NULL },
	{ "NtSecureConnectPort", gt_windows_print_syscall_ntsecureconnectport, gt_windows_print_sysret_ntsecureconnectport, NULL },
	{ "NtSerializeBoot", gt_windows_print_syscall_ntserializeboot, gt_windows_print_sysret_ntserializeboot, NULL },
	{ "NtSetBootEntryOrder", gt_windows_print_syscall_ntsetbootentryorder, gt_windows_print_sysret_ntsetbootentryorder, NULL },
	{ "NtSetBootOptions", gt_windows_print_syscall_ntsetbootoptions, gt_windows_print_sysret_ntsetbootoptions, NULL },
	{ "NtSetContextThread", gt_windows_print_syscall_ntsetcontextthread, gt_windows_print_sysret_ntsetcontextthread, NULL },
	{ "NtSetDebugFilterState", gt_windows_print_syscall_ntsetdebugfilterstate, gt_windows_print_sysret_ntsetdebugfilterstate, NULL },
	{ "NtSetDefaultHardErrorPort", gt_windows_print_syscall_ntsetdefaultharderrorport, gt_windows_print_sysret_ntsetdefaultharderrorport, NULL },
	{ "NtSetDefaultLocale", gt_windows_print_syscall_ntsetdefaultlocale, gt_windows_print_sysret_ntsetdefaultlocale, NULL },
	{ "NtSetDefaultUILanguage", gt_windows_print_syscall_ntsetdefaultuilanguage, gt_windows_print_sysret_ntsetdefaultuilanguage, NULL },
	{ "NtSetDriverEntryOrder", gt_windows_print_syscall_ntsetdriverentryorder, gt_windows_print_sysret_ntsetdriverentryorder, NULL },
	{ "NtSetEaFile", gt_windows_print_syscall_ntseteafile, gt_windows_print_sysret_ntseteafile, NULL },
	{ "NtSetEventBoostPriority", gt_windows_print_syscall_ntseteventboostpriority, gt_windows_print_sysret_ntseteventboostpriority, NULL },
	{ "NtSetEvent", gt_windows_print_syscall_ntsetevent, gt_windows_print_sysret_ntsetevent, NULL },
	{ "NtSetHighEventPair", gt_windows_print_syscall_ntsethigheventpair, gt_windows_print_sysret_ntsethigheventpair, NULL },
	{ "NtSetHighWaitLowEventPair", gt_windows_print_syscall_ntsethighwaitloweventpair, gt_windows_print_sysret_ntsethighwaitloweventpair, NULL },
	{ "NtSetInformationDebugObject", gt_windows_print_syscall_ntsetinformationdebugobject, gt_windows_print_sysret_ntsetinformationdebugobject, NULL },
	{ "NtSetInformationEnlistment", gt_windows_print_syscall_ntsetinformationenlistment, gt_windows_print_sysret_ntsetinformationenlistment, NULL },
	{ "NtSetInformationFile", gt_windows_print_syscall_ntsetinformationfile, gt_windows_print_sysret_ntsetinformationfile, NULL },
	{ "NtSetInformationJobObject", gt_windows_print_syscall_ntsetinformationjobobject, gt_windows_print_sysret_ntsetinformationjobobject, NULL },
	{ "NtSetInformationKey", gt_windows_print_syscall_ntsetinformationkey, gt_windows_print_sysret_ntsetinformationkey, NULL },
	{ "NtSetInformationObject", gt_windows_print_syscall_ntsetinformationobject, gt_windows_print_sysret_ntsetinformationobject, NULL },
	{ "NtSetInformationProcess", gt_windows_print_syscall_ntsetinformationprocess, gt_windows_print_sysret_ntsetinformationprocess, NULL },
	{ "NtSetInformationResourceManager", gt_windows_print_syscall_ntsetinformationresourcemanager, gt_windows_print_sysret_ntsetinformationresourcemanager, NULL },
	{ "NtSetInformationThread", gt_windows_print_syscall_ntsetinformationthread, gt_windows_print_sysret_ntsetinformationthread, NULL },
	{ "NtSetInformationToken", gt_windows_print_syscall_ntsetinformationtoken, gt_windows_print_sysret_ntsetinformationtoken, NULL },
	{ "NtSetInformationTransaction", gt_windows_print_syscall_ntsetinformationtransaction, gt_windows_print_sysret_ntsetinformationtransaction, NULL },
	{ "NtSetInformationTransactionManager", gt_windows_print_syscall_ntsetinformationtransactionmanager, gt_windows_print_sysret_ntsetinformationtransactionmanager, NULL },
	{ "NtSetInformationWorkerFactory", gt_windows_print_syscall_ntsetinformationworkerfactory, gt_windows_print_sysret_ntsetinformationworkerfactory, NULL },
	{ "NtSetIntervalProfile", gt_windows_print_syscall_ntsetintervalprofile, gt_windows_print_sysret_ntsetintervalprofile, NULL },
	{ "NtSetIoCompletionEx", gt_windows_print_syscall_ntsetiocompletionex, gt_windows_print_sysret_ntsetiocompletionex, NULL },
	{ "NtSetIoCompletion", gt_windows_print_syscall_ntsetiocompletion, gt_windows_print_sysret_ntsetiocompletion, NULL },
	{ "NtSetLdtEntries", gt_windows_print_syscall_ntsetldtentries, gt_windows_print_sysret_ntsetldtentries, NULL },
	{ "NtSetLowEventPair", gt_windows_print_syscall_ntsetloweventpair, gt_windows_print_sysret_ntsetloweventpair, NULL },
	{ "NtSetLowWaitHighEventPair", gt_windows_print_syscall_ntsetlowwaithigheventpair, gt_windows_print_sysret_ntsetlowwaithigheventpair, NULL },
	{ "NtSetQuotaInformationFile", gt_windows_print_syscall_ntsetquotainformationfile, gt_windows_print_sysret_ntsetquotainformationfile, NULL },
	{ "NtSetSecurityObject", gt_windows_print_syscall_ntsetsecurityobject, gt_windows_print_sysret_ntsetsecurityobject, NULL },
	{ "NtSetSystemEnvironmentValueEx", gt_windows_print_syscall_ntsetsystemenvironmentvalueex, gt_windows_print_sysret_ntsetsystemenvironmentvalueex, NULL },
	{ "NtSetSystemEnvironmentValue", gt_windows_print_syscall_ntsetsystemenvironmentvalue, gt_windows_print_sysret_ntsetsystemenvironmentvalue, NULL },
	{ "NtSetSystemInformation", gt_windows_print_syscall_ntsetsysteminformation, gt_windows_print_sysret_ntsetsysteminformation, NULL },
	{ "NtSetSystemPowerState", gt_windows_print_syscall_ntsetsystempowerstate, gt_windows_print_sysret_ntsetsystempowerstate, NULL },
	{ "NtSetSystemTime", gt_windows_print_syscall_ntsetsystemtime, gt_windows_print_sysret_ntsetsystemtime, NULL },
	{ "NtSetThreadExecutionState", gt_windows_print_syscall_ntsetthreadexecutionstate, gt_windows_print_sysret_ntsetthreadexecutionstate, NULL },
	{ "NtSetTimerEx", gt_windows_print_syscall_ntsettimerex, gt_windows_print_sysret_ntsettimerex, NULL },
	{ "NtSetTimer", gt_windows_print_syscall_ntsettimer, gt_windows_print_sysret_ntsettimer, NULL },
	{ "NtSetTimerResolution", gt_windows_print_syscall_ntsettimerresolution, gt_windows_print_sysret_ntsettimerresolution, NULL },
	{ "NtSetUuidSeed", gt_windows_print_syscall_ntsetuuidseed, gt_windows_print_sysret_ntsetuuidseed, NULL },
	{ "NtSetValueKey", gt_windows_print_syscall_ntsetvaluekey, gt_windows_print_sysret_ntsetvaluekey, NULL },
	{ "NtSetVolumeInformationFile", gt_windows_print_syscall_ntsetvolumeinformationfile, gt_windows_print_sysret_ntsetvolumeinformationfile, NULL },
	{ "NtShutdownSystem", gt_windows_print_syscall_ntshutdownsystem, gt_windows_print_sysret_ntshutdownsystem, NULL },
	{ "NtShutdownWorkerFactory", gt_windows_print_syscall_ntshutdownworkerfactory, gt_windows_print_sysret_ntshutdownworkerfactory, NULL },
	{ "NtSignalAndWaitForSingleObject", gt_windows_print_syscall_ntsignalandwaitforsingleobject, gt_windows_print_sysret_ntsignalandwaitforsingleobject, NULL },
	{ "NtSinglePhaseReject", gt_windows_print_syscall_ntsinglephasereject, gt_windows_print_sysret_ntsinglephasereject, NULL },
	{ "NtStartProfile", gt_windows_print_syscall_ntstartprofile, gt_windows_print_sysret_ntstartprofile, NULL },
	{ "NtStopProfile", gt_windows_print_syscall_ntstopprofile, gt_windows_print_sysret_ntstopprofile, NULL },
	{ "NtSuspendProcess", gt_windows_print_syscall_ntsuspendprocess, gt_windows_print_sysret_ntsuspendprocess, NULL },
	{ "NtSuspendThread", gt_windows_print_syscall_ntsuspendthread, gt_windows_print_sysret_ntsuspendthread, NULL },
	{ "NtSystemDebugControl", gt_windows_print_syscall_ntsystemdebugcontrol, gt_windows_print_sysret_ntsystemdebugcontrol, NULL },
	{ "NtTerminateJobObject", gt_windows_print_syscall_ntterminatejobobject, gt_windows_print_sysret_ntterminatejobobject, NULL },
	{ "NtTerminateProcess", gt_windows_print_syscall_ntterminateprocess, gt_windows_print_sysret_ntterminateprocess, NULL },
	{ "NtTerminateThread", gt_windows_print_syscall_ntterminatethread, gt_windows_print_sysret_ntterminatethread, NULL },
	{ "NtTestAlert", gt_windows_print_syscall_nttestalert, gt_windows_print_sysret_nttestalert, NULL },
	{ "NtThawRegistry", gt_windows_print_syscall_ntthawregistry, gt_windows_print_sysret_ntthawregistry, NULL },
	{ "NtThawTransactions", gt_windows_print_syscall_ntthawtransactions, gt_windows_print_sysret_ntthawtransactions, NULL },
	{ "NtTraceControl", gt_windows_print_syscall_nttracecontrol, gt_windows_print_sysret_nttracecontrol, NULL },
	{ "NtTraceEvent", gt_windows_print_syscall_nttraceevent, gt_windows_print_sysret_nttraceevent, NULL },
	{ "NtTranslateFilePath", gt_windows_print_syscall_nttranslatefilepath, gt_windows_print_sysret_nttranslatefilepath, NULL },
	{ "NtUmsThreadYield", gt_windows_print_syscall_ntumsthreadyield, gt_windows_print_sysret_ntumsthreadyield, NULL },
	{ "NtUnloadDriver", gt_windows_print_syscall_ntunloaddriver, gt_windows_print_sysret_ntunloaddriver, NULL },
	{ "NtUnloadKey2", gt_windows_print_syscall_ntunloadkey2, gt_windows_print_sysret_ntunloadkey2, NULL },
	{ "NtUnloadKeyEx", gt_windows_print_syscall_ntunloadkeyex, gt_windows_print_sysret_ntunloadkeyex, NULL },
	{ "NtUnloadKey", gt_windows_print_syscall_ntunloadkey, gt_windows_print_sysret_ntunloadkey, NULL },
	{ "NtUnlockFile", gt_windows_print_syscall_ntunlockfile, gt_windows_print_sysret_ntunlockfile, NULL },
	{ "NtUnlockVirtualMemory", gt_windows_print_syscall_ntunlockvirtualmemory, gt_windows_print_sysret_ntunlockvirtualmemory, NULL },
	{ "NtUnmapViewOfSection", gt_windows_print_syscall_ntunmapviewofsection, gt_windows_print_sysret_ntunmapviewofsection, NULL },
	{ "NtVdmControl", gt_windows_print_syscall_ntvdmcontrol, gt_windows_print_sysret_ntvdmcontrol, NULL },
	{ "NtWaitForDebugEvent", gt_windows_print_syscall_ntwaitfordebugevent, gt_windows_print_sysret_ntwaitfordebugevent, NULL },
	{ "NtWaitForKeyedEvent", gt_windows_print_syscall_ntwaitforkeyedevent, gt_windows_print_sysret_ntwaitforkeyedevent, NULL },
	{ "NtWaitForMultipleObjects32", gt_windows_print_syscall_ntwaitformultipleobjects32, gt_windows_print_sysret_ntwaitformultipleobjects32, NULL },
	{ "NtWaitForMultipleObjects", gt_windows_print_syscall_ntwaitformultipleobjects, gt_windows_print_sysret_ntwaitformultipleobjects, NULL },
	{ "NtWaitForSingleObject", gt_windows_print_syscall_ntwaitforsingleobject, gt_windows_print_sysret_ntwaitforsingleobject, NULL },
	{ "NtWaitForWorkViaWorkerFactory", gt_windows_print_syscall_ntwaitforworkviaworkerfactory, gt_windows_print_sysret_ntwaitforworkviaworkerfactory, NULL },
	{ "NtWaitHighEventPair", gt_windows_print_syscall_ntwaithigheventpair, gt_windows_print_sysret_ntwaithigheventpair, NULL },
	{ "NtWaitLowEventPair", gt_windows_print_syscall_ntwaitloweventpair, gt_windows_print_sysret_ntwaitloweventpair, NULL },
	{ "NtWorkerFactoryWorkerReady", gt_windows_print_syscall_ntworkerfactoryworkerready, gt_windows_print_sysret_ntworkerfactoryworkerready, NULL },
	{ "NtWriteFileGather", gt_windows_print_syscall_ntwritefilegather, gt_windows_print_sysret_ntwritefilegather, NULL },
	{ "NtWriteFile", gt_windows_print_syscall_ntwritefile, gt_windows_print_sysret_ntwritefile, NULL },
	{ "NtWriteRequestData", gt_windows_print_syscall_ntwriterequestdata, gt_windows_print_sysret_ntwriterequestdata, NULL },
	{ "NtWriteVirtualMemory", gt_windows_print_syscall_ntwritevirtualmemory, gt_windows_print_sysret_ntwritevirtualmemory, NULL },
	{ "NtYieldExecution", gt_windows_print_syscall_ntyieldexecution, gt_windows_print_sysret_ntyieldexecution, NULL },
	{ NULL, NULL, NULL },
};
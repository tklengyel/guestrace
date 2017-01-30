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

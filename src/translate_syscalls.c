/* Generated on Linux_4.6.7-300.fc24.x86_64 on 30 Aug 2016o 16:18:03 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include "syscall_enum.h"

struct win32_obj_attr {
	uint32_t length; // sizeof given struct
	uint32_t root_directory; // if not null, object_name is relative to this directory
	uint32_t object_name; // pointer to unicode string
	uint32_t attributes; // see microsoft documentation
	uint32_t security_descriptor; // see microsoft documentation
	uint32_t security_quality_of_service; // see microsoft documentation
};

struct win32_obj_attr * obj_attr_from_va(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid);
uint8_t * filename_from_arg(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid) ;

const char * symbol_from_syscall_num(unsigned int sysnum) {
	if (sysnum >> 12 == 0) { /* normal syscalls lead with 0 */
		if (sysnum >= NUM_SYSCALLS || sysnum < 0 || NUM_TO_SYSCALL[sysnum] == NULL) {
			return NULL;
		} else {
			return NUM_TO_SYSCALL[sysnum];
		}
	} else if (sysnum >> 12 == 1) { /* windows graphical syscalls lead with 1 */
		sysnum = sysnum & (0x1000 - 1);
		if (sysnum >= NUM_SYSCALLSK || sysnum < 0 || NUM_TO_SYSCALLK[sysnum] == NULL) {
			return NULL;
		} else {
			return NUM_TO_SYSCALLK[sysnum];
		}
	} else {
		return NULL;
	}
}

/*
 * Tries to return a UTF-8 string representing the filename of an ObjectAttribute
 * vaddr must point to an ObjectAttribute virtual address
 * Must free what it returns
 */

uint8_t * filename_from_arg(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid) {
	struct win32_obj_attr * obj_attr = obj_attr_from_va(vmi, vaddr, pid);

	uint8_t * res = NULL;

	if (obj_attr == NULL) {
		goto done;
	}

	unicode_string_t * filename = vmi_read_unicode_str_va(vmi, obj_attr->object_name, pid);

	if (filename == NULL) {
		free(obj_attr);
		goto done;
	}

	unicode_string_t nfilename;
	if (VMI_SUCCESS != vmi_convert_str_encoding(filename, &nfilename, "UTF-8")) {
		free(obj_attr);
		vmi_free_unicode_str(filename);
		goto done;
	}

	res = nfilename.contents; // points to malloc'd memory
	free(obj_attr);
	vmi_free_unicode_str(filename);

done:
	return res;
}

/*
 * Get ObjectAttributes struct from virtual address
 */
struct win32_obj_attr * obj_attr_from_va(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid) {
	struct win32_obj_attr * buff = NULL;

	unsigned int struct_size = 0;

	if (VMI_SUCCESS != vmi_read_32_va(vmi, vaddr, pid, &struct_size)) {
		goto done;
	}

	struct_size = struct_size <= sizeof(struct win32_obj_attr) ? struct_size : sizeof(struct win32_obj_attr); // don't wanna read too much data

	buff = calloc(1, sizeof(struct win32_obj_attr));

	if (struct_size != vmi_read_va(vmi, vaddr, pid, buff, struct_size)) {
		free(buff);
		buff = NULL;
		goto done;
	}

done:
	return buff;
}

char *
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
	if (NULL == proc) {		/* if proc is NULL we don't know the process name */
		return "unknown";
	}
	
	return proc;

}


void 
print_syscall(vmi_instance_t vmi, vmi_event_t *event) 
{
	/* 
 	 *  This function is used to translate the 
 	 *  raw values found in registers on a syscall to a readable string
 	 *  that is printed to stdout. It displays the PID, Process name,
 	 *  and the syscall name with all of its arguments formatted to 
 	 *  show as an integer, hex value or string if possible.
 	 */

	/* Every case will make use of the following values */

	reg_t syscall_number = event->x86_regs->rax;			/* stores the syscall number from rax */

	int win_syscall = syscall_number & 0xFFFF;

	const char * syscall_symbol = symbol_from_syscall_num(win_syscall);

	if (syscall_symbol == NULL) {
		syscall_symbol = "Unknown Symbol";
	}

	time_t now = time(NULL);

	char * timestamp = ctime(&now); // y u have a newline
	timestamp[strlen(timestamp)-1] = 0;
	vmi_pid_t pid = vmi_dtb_to_pid(vmi, event->x86_regs->cr3);
	char *proc_name = get_process_name(vmi, pid);
	
	//if (strcmp(proc_name, "notepad.exe") == 0) {
		fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n", timestamp, proc_name, pid, syscall_symbol, win_syscall);

		unsigned int raw_args[16] = {0};
		vmi_read_va(vmi, event->x86_regs->rdx, pid, raw_args, sizeof(raw_args));
		unsigned int * args = &raw_args[2]; /* don't know what the first two arguments are yet, so let's ignore them */

		switch (win_syscall) {

			case NTOPENFILE:
			{
				fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n", timestamp, proc_name, pid, syscall_symbol, win_syscall);

				uint8_t * filename = filename_from_arg(vmi, args[2], pid);

				if (filename != NULL) {
					fprintf(stderr, "%s\n", filename);
				}

				break;
			} 

			case NTOPENSYMBOLICLINKOBJECT:
			{
				fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n", timestamp, proc_name, pid, syscall_symbol, win_syscall);

				uint8_t * filename = filename_from_arg(vmi, args[2], pid);

				if (filename != NULL) {
					fprintf(stderr, "%s\n", filename);
				}

				break;
			}

			case NTCREATEFILE:
			{
				fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n", timestamp, proc_name, pid, syscall_symbol, win_syscall);

				uint8_t * filename = filename_from_arg(vmi, args[2], pid);

				if (filename != NULL) {
					fprintf(stderr, "%s\n", filename);
				}

				break;
			}

			case NTOPENDIRECTORYOBJECT:
			{
				fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n", timestamp, proc_name, pid, syscall_symbol, win_syscall);

				uint8_t * filename = filename_from_arg(vmi, args[2], pid);

				if (filename != NULL) {
					fprintf(stderr, "%s\n", filename);
				}

				break;
			}

			case NTOPENPROCESS:
			{
				fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n", timestamp, proc_name, pid, syscall_symbol, win_syscall);

				uint8_t * filename = filename_from_arg(vmi, args[2], pid);

				if (filename != NULL) {
					fprintf(stderr, "%s\n", filename);
				}

				break;
			}

			default:
			{
				/* do something here? */
			}
		}
	//}

	free(proc_name);
}

void 
print_sysret(vmi_instance_t vmi, vmi_event_t *event) 
{
	/* Print the pid, process name and return value of a system call */
	reg_t syscall_return = event->x86_regs->rax;			/* get the return value out of rax */
	vmi_pid_t pid = vmi_dtb_to_pid(vmi, event->x86_regs->cr3);	/* get the pid of the process */
	char *proc_name = get_process_name(vmi, pid);				/* get the process name */

	fprintf(stderr, "pid: %u ( %s ) return: 0x%"PRIx64"\n",  pid, proc_name, syscall_return);

	free(proc_name);
}

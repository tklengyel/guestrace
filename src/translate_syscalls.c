/* Generated on Linux_4.6.7-300.fc24.x86_64 on 30 Aug 2016o 16:18:03 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#include "syscall_enum.h"

struct win64_obj_attr {
	uint64_t length; // sizeof given struct
	uint64_t root_directory; // if not null, object_name is relative to this directory
	uint64_t object_name; // pointer to unicode string
	uint64_t attributes; // see microsoft documentation
	uint64_t security_descriptor; // see microsoft documentation
	uint64_t security_quality_of_service; // see microsoft documentation
};

typedef struct visor_proc {
	vmi_pid_t pid; /* current process pid */
	char * name; /* this will be removed automatically */
	uint16_t sysnum; /* 0xFFFF if not waiting on syscall to finish, otherwise sysnum */
	uint64_t * args; /* saved arguments to use between syscall start and finish. must be freed in ret */
	struct visor_proc * next; /* todo: don't use linked list */
} visor_proc;

#define NUM_SYSCALL_ARGS 8

visor_proc * PROC_HEAD = NULL;

struct win64_obj_attr * obj_attr_from_va(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid);
uint8_t * filename_from_arg(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid);
visor_proc * get_process_from_pid(vmi_pid_t pid);
visor_proc * allocate_process(vmi_pid_t pid, char * name);
void delete_process(vmi_pid_t pid);

visor_proc * get_process_from_pid(vmi_pid_t pid) {
	visor_proc * curr = PROC_HEAD;

	while (NULL != curr) {
		if (curr->pid == pid) {
			break;
		}
		curr = curr->next;
	}

	return curr;
}

visor_proc * allocate_process(vmi_pid_t pid, char * name) {
	visor_proc * result = NULL;

	/* we never delete processes, only replace them if another is allocated with same PID */
	if (NULL != get_process_from_pid(pid)) {
		delete_process(pid);
	}

	result = calloc(1, sizeof(visor_proc));

	if (NULL == result) {
		goto done;
	}

	result->pid = pid;
	result->sysnum = 0xFFFF; /* not waiting on any syscall */
	result->name = name;

	/* let's append this to the current list */
	if (NULL == PROC_HEAD) {
		PROC_HEAD = result;
	} else {
		visor_proc * tail = PROC_HEAD;

		while (tail->next != NULL) {
			tail = tail->next;
		}

		tail->next = result;
	}

done:
	return result;
}

void delete_process(vmi_pid_t pid) {
	if (NULL == PROC_HEAD) {
		return;
	}

	if (PROC_HEAD->pid == pid) {
		visor_proc * saved = PROC_HEAD->next;
		free(PROC_HEAD->name);
		free(PROC_HEAD);
		PROC_HEAD = saved;
	} else {
		visor_proc * curr = PROC_HEAD;

		while (NULL != curr->next) {
			if (curr->next->pid == pid) {
				visor_proc * saved = curr->next->next;
				free(curr->next->name);
				free(curr->next);
				curr->next = saved;
				return;
			}
		}
	}
}

//const char * symbol_from_syscall_num(uint16_t sysnum) {
//	if (sysnum >> 12 == 0) { /* normal syscalls lead with 0 */
//		if (sysnum >= NUM_SYSCALLS || sysnum < 0 || NUM_TO_SYSCALL[sysnum] == NULL) {
//			return NULL;
//		} else {
//			return NUM_TO_SYSCALL[sysnum];
//		}
//	} else if (sysnum >> 12 == 1) { /* windows graphical syscalls lead with 1 */
//		return NULL; /* ignore graphical syscalls for performance */
//	} else {
//		return NULL;
//	}
//}

/*
 * Tries to return a UTF-8 string representing the filename of an ObjectAttribute
 * vaddr must point to an ObjectAttribute virtual address
 * Must free what it returns
 */

uint8_t * filename_from_arg(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid) {
	struct win64_obj_attr * obj_attr = obj_attr_from_va(vmi, vaddr, pid);

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

	res = nfilename.contents; /* points to malloc'd memory */
	free(obj_attr);
	vmi_free_unicode_str(filename);

done:
	return res;
}

/*
 * Get ObjectAttributes struct from virtual address
 */
struct win64_obj_attr * obj_attr_from_va(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid) {
	struct win64_obj_attr * buff = NULL;

	uint64_t struct_size = 0;

	if (VMI_SUCCESS != vmi_read_64_va(vmi, vaddr, pid, &struct_size)) {
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
	return proc;

}


void 
print_syscall(vmi_instance_t vmi, vmi_event_t *event, uint16_t syscall_num) 
{
	vmi_pid_t pid = vmi_dtb_to_pid(vmi, event->x86_regs->cr3);

	if (0 == pid) { /* it can't find the PID sometimes... */
		return;
	}

	visor_proc * curr_proc = get_process_from_pid(pid);

	if (NULL == curr_proc) {
		char * proc_name = get_process_name(vmi, pid);

		//if (strcmp(proc_name, "cmd.exe") == 0) { /* let's only track cmd.exe for now */
			curr_proc = allocate_process(pid, proc_name);

			if (NULL == curr_proc) {
				free(proc_name);
			}
		//}
	}
	
	if (NULL == curr_proc) { /* we don't want to track this PID */
		return;
	}

	if (0xFFFF != curr_proc->sysnum) {
		fprintf(stderr, "Warning: system call didn't return before new system call.  Multi-threaded process?\n");
	}

	curr_proc->sysnum = syscall_num;
	
	time_t now = time(NULL);

	char * timestamp = ctime(&now); // y u have a newline
	timestamp[strlen(timestamp)-1] = 0;

	if (NULL != curr_proc->args) {
		free(curr_proc->args);
		curr_proc->args = NULL;
	}

	curr_proc->args = calloc(NUM_SYSCALL_ARGS, sizeof(uint64_t));
	curr_proc->args[0] = event->x86_regs->rcx;
	curr_proc->args[1] = event->x86_regs->rdx;
	curr_proc->args[2] = event->x86_regs->r8;
	curr_proc->args[3] = event->x86_regs->r9;

	/* todo figure out how to get rest of arguments */
	//vmi_read_va(vmi, event->x86_regs->rdx + sizeof(uint32_t) * 2, curr_proc->pid, curr_proc->args, NUM_SYSCALL_ARGS * sizeof(uint32_t));
}

void 
print_sysret(vmi_instance_t vmi, vmi_event_t *event) 
{
	vmi_pid_t pid = vmi_dtb_to_pid(vmi, event->x86_regs->cr3);

	if (0 == pid) { /* it can't find the PID sometimes... */
		return;
	}

	visor_proc * curr_proc = get_process_from_pid(pid);

	if (NULL == curr_proc) { /* not tracking this process */
		return;
	}

	if (0xFFFF == curr_proc->sysnum) {
		fprintf(stderr, "Error: system call returned without setting valid sysnum for PID %d\n", pid);
		return;
	}

	/* Print the pid, process name and return value of a system call */
	reg_t ret_status = event->x86_regs->rax;			/* get the return value out of rax */

	time_t now = time(NULL);

	char * timestamp = ctime(&now); // y u have a newline
	timestamp[strlen(timestamp)-1] = 0;

	//const char * syscall_symbol = symbol_from_syscall_num(curr_proc->sysnum);

	//if (syscall_symbol == NULL) {
	//	syscall_symbol = "Unknown Symbol";
	//}

	switch (curr_proc->sysnum) {

		case NTOPENFILE:
		{
			uint8_t * filename = filename_from_arg(vmi, curr_proc->args[2], curr_proc->pid);

			uint64_t handle = 0;
			vmi_read_64_va(vmi, curr_proc->args[0], curr_proc->pid, &handle);

			const char * syscall_symbol = "NtOpenFile";

			fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n\targuments:\t'%s'\n\treturn status:\t0x%lx\n\thandle value:\t0x%lx\n", timestamp, curr_proc->name, curr_proc->pid, syscall_symbol, curr_proc->sysnum, filename, ret_status, handle);

			break;
		} 

		case NTOPENSYMBOLICLINKOBJECT:
		{
			uint8_t * filename = filename_from_arg(vmi, curr_proc->args[2], curr_proc->pid);

			uint64_t handle = 0;
			vmi_read_64_va(vmi, curr_proc->args[0], curr_proc->pid, &handle);

			const char * syscall_symbol = "NtOpenSymbolicLinkObject";

			fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n\targuments:\t'%s'\n\treturn status:\t0x%lx\n\thandle value:\t0x%lx\n", timestamp, curr_proc->name, curr_proc->pid, syscall_symbol, curr_proc->sysnum, filename, ret_status, handle);

			break;
		}

		case NTCREATEFILE:
		{
			uint8_t * filename = filename_from_arg(vmi, curr_proc->args[2], curr_proc->pid);

			uint64_t handle = 0;
			vmi_read_64_va(vmi, curr_proc->args[0], curr_proc->pid, &handle);

			const char * syscall_symbol = "NtCreateFile";

			fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n\targuments:\t'%s'\n\treturn status:\t0x%lx\n\thandle value:\t0x%lx\n", timestamp, curr_proc->name, curr_proc->pid, syscall_symbol, curr_proc->sysnum, filename, ret_status, handle);

			break;
		}

		case NTOPENDIRECTORYOBJECT:
		{
			uint8_t * filename = filename_from_arg(vmi, curr_proc->args[2], curr_proc->pid);

			uint64_t handle = 0;
			vmi_read_64_va(vmi, curr_proc->args[0], curr_proc->pid, &handle);

			const char * syscall_symbol = "NtOpenDirectoryObject";

			fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n\targuments:\t'%s'\n\treturn status:\t0x%lx\n\thandle value:\t0x%lx\n", timestamp, curr_proc->name, curr_proc->pid, syscall_symbol, curr_proc->sysnum, filename, ret_status, handle);

			break;
		}

		case NTOPENPROCESS:
		{
			uint8_t * filename = filename_from_arg(vmi, curr_proc->args[2], curr_proc->pid);

			uint64_t handle = 0;
			vmi_read_64_va(vmi, curr_proc->args[0], curr_proc->pid, &handle);

			const char * syscall_symbol = "NtOpenProcess";

			fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n\targuments:\t'%s'\n\treturn status:\t0x%lx\n\thandle value:\t0x%lx\n", timestamp, curr_proc->name, curr_proc->pid, syscall_symbol, curr_proc->sysnum, filename, ret_status, handle);

			break;
		}

		case NTREADFILE:
		{
			const char * syscall_symbol = "NtReadFile";

			fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n\targuments:\t0x%lx\n\treturn status:\t0x%lx\n", timestamp, curr_proc->name, curr_proc->pid, syscall_symbol, curr_proc->sysnum, curr_proc->args[0], ret_status);

			break;
		}

		case NTWRITEFILE:
		{
			const char * syscall_symbol = "NtWriteFile";

			fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n\targuments:\t0x%lx\n\treturn status:\t0x%lx\n", timestamp, curr_proc->name, curr_proc->pid, syscall_symbol, curr_proc->sysnum, curr_proc->args[0], ret_status);

			break;
		}

		default:
		{
			//fprintf(stderr, "[%s] %s (PID: %d) -> %s (SysNum: 0x%x)\n\treturn status:\t0x%lx\n", timestamp, curr_proc->name, curr_proc->pid, syscall_symbol, curr_proc->sysnum, ret_status);
		}
	}

	curr_proc->sysnum = 0xFFFF; /* clean out the syscall */

	if (NULL != curr_proc->args) {
		free(curr_proc->args);
		curr_proc->args = NULL;
	}
}

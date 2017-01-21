#include <libvmi/libvmi.h>
#include <libvmi/events.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "functions_linux.h"
#include "generated_linux.h"

struct os_functions os_functions_linux = {
	.print_syscall          = vf_linux_print_syscall,
	.print_sysret           = vf_linux_print_sysret,
	.find_syscalls_and_setup_mem_traps \
	                        = vf_linux_find_syscalls_and_setup_mem_traps
};

bool
vf_linux_find_syscalls_and_setup_mem_traps(vf_state *state)
{
	return vf_find_syscalls_and_setup_mem_traps(state,
	                                            VM_LINUX_SYSCALLS,
	                                            VM_LINUX_TRACED_SYSCALLS);
}

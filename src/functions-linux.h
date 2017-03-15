#ifndef FUNCTIONS_LINUX_H
#define FUNCTIONS_LINUX_H

#include "guestrace-private.h"

extern struct os_functions os_functions_linux;

addr_t _gt_linux_find_return_point_addr(GtLoop *loop);
char * gt_linux_get_process_name(vmi_instance_t vmi, gt_pid_t pid);

#endif

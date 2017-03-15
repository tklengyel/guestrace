#ifndef FUNCTIONS_WINDOWS_H
#define FUNCTIONS_WINDOWS_H

#include "guestrace-private.h"

extern struct os_functions os_functions_windows;

addr_t _gt_windows_find_return_point_addr(GtLoop *loop);
char * gt_windows_get_process_name(vmi_instance_t vmi, gt_pid_t pid);

#endif

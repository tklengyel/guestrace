#ifndef FUNCTIONS_WINDOWS_H
#define FUNCTIONS_WINDOWS_H

#include "guestrace.h"

extern struct os_functions os_functions_windows;

addr_t vf_windows_find_return_point_addr(GTLoop *loop);

#endif

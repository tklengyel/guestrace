#ifndef _EARLY_BOOT_H
#define _EARLY_BOOT_H

#include "gt.h"
#include "gt-private.h"

status_t early_boot_wait_for_os_load(GtLoop *loop);
status_t early_boot_wait_for_first_process(GtLoop *loop);

#endif

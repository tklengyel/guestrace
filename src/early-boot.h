#ifndef _EARLY_BOOT_H
#define _EARLY_BOOT_H

#define XC_WANT_COMPAT_EVTCHN_API

#include "gt.h"
#include "gt-private.h"

status_t early_boot_wait_for_os_load(GtLoop *loop);

#endif

#ifndef EARLY_BOOT_H
#define EARLY_BOOT_H

#include "guestrace.h"
#include "guestrace-private.h"

status_t early_boot_set_initialize_breakpoint(GtLoop *loop);
status_t early_boot_reset_initialize_breakpoint(GtLoop *loop);
status_t early_boot_remove_initialize_breakpoint(GtLoop *loop);
status_t early_boot_wait_for_lstar(GtLoop *loop);
status_t early_boot_wait_for_initialized(GtLoop *loop);


#endif

#ifndef REKALL_H
#define REKALL_H

#include <libvmi/libvmi.h>

status_t
rekall_profile_symbol_to_rva(const char *rekall_profile,
                             const char *symbol,
                             const char *subsymbol,
                             addr_t *rva);

#endif

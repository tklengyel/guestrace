#ifndef REKALL_PRIVATE_H
#define REKALL_PRIVATE_H

#include <libvmi/libvmi.h>
#include <glib.h>

gboolean gt_rekall_symbol_to_rva(const char *rekall_profile,
                                 const char *symbol,
                                 const char *subsymbol,
                                 addr_t *rva);

#endif

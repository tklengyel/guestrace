#ifndef _GT_REKALL_PRIVATE_H
#define _GT_REKALL_PRIVATE_H

#include <libvmi/libvmi.h>
#include <glib.h>

typedef struct offset_definition_t {
	int   id;
	char *struct_name;
	char *field_name;
} offset_definition_t;

gboolean gt_rekall_private_symbol_to_rva(const char *rekall_profile,
                                         const char *symbol,
                                         const char *subsymbol,
                                         addr_t *rva);

gboolean gt_rekall_private_initialize(GtLoop *loop,
                                      addr_t *offset,
                                      offset_definition_t *def,
                                      size_t def_size);

#endif

/* This code comes from libvmi. Should they export this function? */

#include <json-c/json.h>

#include "gt-private.h"
#include "gt-rekall.h"
#include "gt-rekall-private.h"

gboolean
gt_rekall_private_symbol_to_rva(const char *rekall_profile,
                                const char *symbol,
                                const char *subsymbol,
                                addr_t *rva)
{
	gboolean ok = FALSE;
	json_object *root = NULL;

	if(!rekall_profile || !symbol) {
		goto done;
	}

	root = json_object_from_file(rekall_profile);
	if(!root) {
		goto done;
	}

	if(!subsymbol) {
		json_object *constants = NULL, *functions = NULL, *jsymbol = NULL;
			if (json_object_object_get_ex(root, "$CONSTANTS", &constants)) {
				if (json_object_object_get_ex(constants, symbol, &jsymbol)) {
					*rva = json_object_get_int64(jsymbol);

					ok = TRUE;
					goto done;
				}
			}

		if (json_object_object_get_ex(root, "$FUNCTIONS", &functions)) {
			if (json_object_object_get_ex(functions, symbol, &jsymbol)) {
				*rva = json_object_get_int64(jsymbol);

				ok = TRUE;
				goto done;
			}
		}
	} else {
		json_object *structs = NULL;
		json_object *jstruct = NULL;
		json_object *jstruct2 = NULL;
		json_object *jmember = NULL;
		json_object *jvalue = NULL;

		if (!json_object_object_get_ex(root, "$STRUCTS", &structs)) {
			goto done;
		}

		if (!json_object_object_get_ex(structs, symbol, &jstruct)) {
			goto done;
		}

		jstruct2 = json_object_array_get_idx(jstruct, 1);
		if (!jstruct2) {
			goto done;
		}

		if (!json_object_object_get_ex(jstruct2, subsymbol, &jmember)) {
			goto done;
		}

		jvalue = json_object_array_get_idx(jmember, 0);
		if (!jvalue) {
			goto done;
		}

		*rva = json_object_get_int64(jvalue);
		ok = TRUE;
	}

done:
	json_object_put(root);
	return ok;
}

gboolean
gt_rekall_private_initialize(GtLoop *loop,
                             addr_t *offset,
                             offset_definition_t *def,
                             size_t def_size)
{
	gboolean ok = FALSE;
	const char *rekall_profile;

	rekall_profile = vmi_get_rekall_path(loop->vmi);
	if (NULL == rekall_profile) {
		goto done;
	}

	for (int i = 0; i < def_size; i++) {
		ok = gt_rekall_private_symbol_to_rva(rekall_profile,
		                                     def[i].struct_name,
		                                     def[i].field_name,
		                                    &offset[i]);
		if (!ok) {
			goto done;
		}
	}

done:
	return ok;
}

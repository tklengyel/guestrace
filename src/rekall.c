/* This code comes from libvmi. Should they export this function? */

#include <json-c/json.h>

#include "rekall.h"

status_t
rekall_profile_symbol_to_rva(const char *rekall_profile,
                             const char *symbol,
                             const char *subsymbol,
                             addr_t *rva)
{
    status_t ret = VMI_FAILURE;
    if(!rekall_profile || !symbol) {
        return ret;
    }

    json_object *root = json_object_from_file(rekall_profile);
    if(!root) {
        return ret;
    }

    if(!subsymbol) {
        json_object *constants = NULL, *functions = NULL, *jsymbol = NULL;
        if (json_object_object_get_ex(root, "$CONSTANTS", &constants)) {
            if (json_object_object_get_ex(constants, symbol, &jsymbol)) {
                *rva = json_object_get_int64(jsymbol);

                ret = VMI_SUCCESS;
                goto exit;
            }
        }

        if (json_object_object_get_ex(root, "$FUNCTIONS", &functions)) {
            if (json_object_object_get_ex(functions, symbol, &jsymbol)) {
                *rva = json_object_get_int64(jsymbol);

                ret = VMI_SUCCESS;
                goto exit;
            }
        }
    } else {
        json_object *structs = NULL;
	json_object *jstruct = NULL;
	json_object *jstruct2 = NULL;
	json_object *jmember = NULL;
	json_object *jvalue = NULL;
        if (!json_object_object_get_ex(root, "$STRUCTS", &structs)) {
            goto exit;
        }
        if (!json_object_object_get_ex(structs, symbol, &jstruct)) {
            goto exit;
        }

        jstruct2 = json_object_array_get_idx(jstruct, 1);
        if (!jstruct2) {
            goto exit;
        }

        if (!json_object_object_get_ex(jstruct2, subsymbol, &jmember)) {
            goto exit;
        }

        jvalue = json_object_array_get_idx(jmember, 0);
        if (!jvalue) {
            goto exit;
        }

        *rva = json_object_get_int64(jvalue);
        ret = VMI_SUCCESS;
    }

exit:
    json_object_put(root);
    return ret;
}

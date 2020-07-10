/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */





#include "iot_import.h"

#include "shadow_debug.h"
#include "iotx_utils.h"
#include "utils_list.h"
#include "shadow_delta.h"

static int iotx_shadow_delta_response(iotx_shadow_pt pshadow)
{
#define IOTX_SHADOW_DELTA_RESPONSE_LEN     (256)

    int rc;
    void *buf;
    format_data_t format;

    buf = SHADOW_malloc(IOTX_SHADOW_DELTA_RESPONSE_LEN);
    if (NULL == buf) {
        return ERROR_NO_MEM;
    }

    iotx_ds_common_format_init(pshadow, &format, buf, IOTX_SHADOW_DELTA_RESPONSE_LEN, "update",
                               "\"state\":{\"desired\":\"null\"");
    iotx_ds_common_format_finalize(pshadow, &format, "}", 0);

    rc = iotx_ds_common_publish2update(pshadow, format.buf, format.offset);

    LITE_free(buf);

    return (rc >= 0) ? SUCCESS_RETURN : rc;
}



static uint32_t iotx_shadow_get_timestamp(const char *pmetadata_desired,
        size_t len_metadata_desired,
        const char *pname)
{
    const char *pdata_desired;
    const char *pdata;

    uint32_t ret = 0;

    /* attribute be matched, and then get timestamp */

    pdata_desired = LITE_json_value_of((char *)pname, (char *)pmetadata_desired);

    if (NULL != pdata_desired) {
        pdata = LITE_json_value_of((char *)"timestamp", (char *)pdata_desired);
        if (NULL != pdata) {
            ret = atoi(pdata);
            LITE_free(pdata);
            LITE_free(pdata_desired);
            return ret;
        }

        LITE_free(pdata_desired);
    }

    shadow_err("NOT timestamp in JSON doc");
    return 0;
}


static iotx_err_t iotx_shadow_delta_update_attr_value(
            iotx_shadow_attr_pt pattr,
            const char *pvalue,
            size_t value_len)
{
    return iotx_ds_common_convert_string2data(pvalue, value_len, pattr->attr_type, pattr->pattr_data);
}


static int iotx_shadow_delta_update_attr(iotx_shadow_pt pshadow,
        const char *json_doc_attr,
        uint32_t json_doc_attr_len,
        const char *json_doc_metadata,
        uint32_t json_doc_metadata_len)
{
    const char *pvalue;
    iotx_shadow_attr_pt pattr;
    list_iterator_t *iter;
    list_node_t *node;
    int need_update = 0;

    /* Iterate the list and check JSON document according to list_node.val.pattr_name */
    /* If the attribute be found, call the function registered by calling iotx_shadow_delta_register_attr() */

    HAL_MutexLock(pshadow->mutex);
    iter = list_iterator_new(pshadow->inner_data.attr_list, LIST_TAIL);
    if (NULL == iter) {
        HAL_MutexUnlock(pshadow->mutex);
        shadow_warning("Allocate memory failed");
        need_update = 0;
        return need_update;
    }

    while (node = list_iterator_next(iter), NULL != node) {
        pattr = (iotx_shadow_attr_pt)node->val;
        pvalue = LITE_json_value_of((char *)pattr->pattr_name, (char *)json_doc_attr);

        /* check if match attribute or not be matched */
        if (NULL != pvalue) { /* attribute be matched */
            /* get timestamp */
            need_update = 1;
            pattr->timestamp = iotx_shadow_get_timestamp(
                                           json_doc_metadata,
                                           json_doc_metadata_len,
                                           pattr->pattr_name);

            /* convert string of JSON value according to destination data type. */
            if (SUCCESS_RETURN != iotx_shadow_delta_update_attr_value(pattr, pvalue, strlen(pvalue))) {
                shadow_warning("Update attribute value failed.");
            }else{
                pattr->method_type = pshadow->inner_data.method_type;
                pattr->flag_update = 1;
            }
			
#if 0
            if (NULL != pattr->callback) {
                HAL_MutexUnlock(pshadow->mutex);
                /* call related callback function */
                pattr->callback(pattr);
                HAL_MutexLock(pshadow->mutex);
            }
#endif
            LITE_free(pvalue);
        }
    }

error:
    list_iterator_destroy(iter);
    HAL_MutexUnlock(pshadow->mutex);

    return need_update;
}

/* handle response ACK of UPDATE */
void iotx_shadow_delta_entry(
            iotx_shadow_pt pshadow,
            const char *json_doc,
            size_t json_doc_len)
{
    const char *key_metadata;
    const char *pstate, *pmetadata;
    int ret = 0;

    pstate = LITE_json_value_of((char *)"payload.state.desired", (char *)json_doc);
    if (NULL != pstate) {
        key_metadata = "payload.metadata.desired";
    } else {
        /* if have not desired key, get reported key instead. */
        key_metadata = "payload.metadata.reported";
        pstate = LITE_json_value_of((char *)"payload.state.reported", (char *)json_doc);
    }

    pmetadata = LITE_json_value_of((char *)key_metadata, (char *)json_doc);

    if ((NULL == pstate) || (NULL == pmetadata)) {
        shadow_err("Invalid JSON Doc");
        return;
    }

    ret = iotx_shadow_delta_update_attr(pshadow,
                                  pstate,
                                  strlen(pstate),
                                  pmetadata,
                                  strlen(pmetadata));

    LITE_free(pstate);
    LITE_free(pmetadata);

    /* generate ACK and publish to @update topic using QOS1 */
    /* if not found related any value, do not need to response */
    if(ret != 0){
        iotx_shadow_delta_response(pshadow);
    }
}


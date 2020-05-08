/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */



#include "iotx_dm_internal.h"

static dm_mgr_ctx g_dm_mgr = {0};

static dm_mgr_ctx *_dm_mgr_get_ctx(void)
{
    return &g_dm_mgr;
}

static void _dm_mgr_mutex_lock(void)
{
    dm_mgr_ctx *ctx = _dm_mgr_get_ctx();
    if (ctx->mutex) {
        HAL_MutexLock(ctx->mutex);
    }
}

static void _dm_mgr_mutex_unlock(void)
{
    dm_mgr_ctx *ctx = _dm_mgr_get_ctx();
    if (ctx->mutex) {
        HAL_MutexUnlock(ctx->mutex);
    }
}

static int _dm_mgr_next_devid(void)
{
    dm_mgr_ctx *ctx = _dm_mgr_get_ctx();

    return ctx->global_devid++;
}

static int _dm_mgr_search_dev_by_devid(_IN_ int devid, _OU_ dm_mgr_dev_node_t **node)
{
    dm_mgr_ctx *ctx = _dm_mgr_get_ctx();
    dm_mgr_dev_node_t *search_node = NULL;

    list_for_each_entry(search_node, &ctx->dev_list, linked_list, dm_mgr_dev_node_t) {
        if (search_node->devid == devid) {
            /* dm_log_debug("Device Found, devid: %d", devid); */
            if (node) {
                *node = search_node;
            }
            return SUCCESS_RETURN;
        }
    }

    dm_log_debug("Device Not Found, devid: %d", devid);
    return FAIL_RETURN;
}

static int _dm_mgr_search_dev_by_pkdn(_IN_ char product_key[PRODUCT_KEY_MAXLEN],
                                      _IN_ char device_name[DEVICE_NAME_MAXLEN], _OU_ dm_mgr_dev_node_t **node)
{
    dm_mgr_ctx *ctx = _dm_mgr_get_ctx();
    dm_mgr_dev_node_t *search_node = NULL;

    list_for_each_entry(search_node, &ctx->dev_list, linked_list, dm_mgr_dev_node_t) {
        if ((strlen(search_node->product_key) == strlen(product_key)) &&
            (memcmp(search_node->product_key, product_key, strlen(product_key)) == 0) &&
            (strlen(search_node->device_name) == strlen(device_name)) &&
            (memcmp(search_node->device_name, device_name, strlen(device_name)) == 0)) {
            /* dm_log_debug("Device Found, Product Key: %s, Device Name: %s", product_key, device_name); */
            if (node) {
                *node = search_node;
            }
            return SUCCESS_RETURN;
        }
    }

    dm_log_debug("Device Not Found, Product Key: %s, Device Name: %s", product_key, device_name);
    return FAIL_RETURN;
}

static int _dm_mgr_insert_dev(_IN_ int devid, _IN_ int dev_type, char product_key[PRODUCT_KEY_MAXLEN],
                              char device_name[DEVICE_NAME_MAXLEN])
{
    int res = 0;
    dm_mgr_ctx *ctx = _dm_mgr_get_ctx();
    dm_mgr_dev_node_t *node = NULL;

    if (devid < 0 || product_key == NULL || strlen(product_key) >= PRODUCT_KEY_MAXLEN ||
        device_name == NULL || strlen(device_name) >= DEVICE_NAME_MAXLEN) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_devid(devid, NULL);
    if (res == SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    node = DM_malloc(sizeof(dm_mgr_dev_node_t));
    if (node == NULL) {
        return DM_MEMORY_NOT_ENOUGH;
    }
    memset(node, 0, sizeof(dm_mgr_dev_node_t));

    node->devid = devid;
    node->dev_type = dev_type;
    memcpy(node->product_key, product_key, strlen(product_key));
    memcpy(node->device_name, device_name, strlen(device_name));
    INIT_LIST_HEAD(&node->linked_list);

    list_add_tail(&node->linked_list, &ctx->dev_list);

    return SUCCESS_RETURN;
}

static void _dm_mgr_destroy_devlist(void)
{
    dm_mgr_ctx *ctx = _dm_mgr_get_ctx();
    dm_mgr_dev_node_t *del_node = NULL;
    dm_mgr_dev_node_t *next_node = NULL;

    list_for_each_entry_safe(del_node, next_node, &ctx->dev_list, linked_list, dm_mgr_dev_node_t) {
        list_del(&del_node->linked_list);

        DM_free(del_node);
    }
}

int dm_mgr_init(void)
{
    int res = 0;
    dm_mgr_ctx *ctx = _dm_mgr_get_ctx();
    char product_key[PRODUCT_KEY_MAXLEN] = {0};
    char device_name[DEVICE_NAME_MAXLEN] = {0};

    memset(ctx, 0, sizeof(dm_mgr_ctx));

    /* Create Mutex */
    ctx->mutex = HAL_MutexCreate();
    if (ctx->mutex == NULL) {
        goto ERROR;
    }

    /* Init Device Id*/
    ctx->global_devid = IOTX_DM_LOCAL_NODE_DEVID + 1;

    /* Init Device List */
    INIT_LIST_HEAD(&ctx->dev_list);

    /* Local Node */
    HAL_GetProductKey(product_key);
    HAL_GetDeviceName(device_name);
    res = _dm_mgr_insert_dev(IOTX_DM_LOCAL_NODE_DEVID, IOTX_DM_DEVICE_TYPE, product_key, device_name);
    if (res != SUCCESS_RETURN) {
        goto ERROR;
    }

    return SUCCESS_RETURN;

ERROR:
    if (ctx->mutex) {
        HAL_MutexDestroy(ctx->mutex);
    }
    memset(ctx, 0, sizeof(dm_mgr_ctx));
    return FAIL_RETURN;
}

int dm_mgr_deinit(void)
{
    dm_mgr_ctx *ctx = _dm_mgr_get_ctx();

    _dm_mgr_mutex_lock();
    _dm_mgr_destroy_devlist();
    _dm_mgr_mutex_unlock();

    if (ctx->mutex) {
        HAL_MutexDestroy(ctx->mutex);
    }

    return SUCCESS_RETURN;
}

int dm_mgr_device_create(_IN_ int dev_type, _IN_ char product_key[PRODUCT_KEY_MAXLEN],
                         _IN_ char device_name[DEVICE_NAME_MAXLEN], _IN_ char device_secret[DEVICE_SECRET_MAXLEN], _OU_ int *devid)
{
    int res = 0;
    dm_mgr_ctx *ctx = _dm_mgr_get_ctx();
    dm_mgr_dev_node_t *node = NULL;

    if (product_key == NULL || device_name == NULL ||
        strlen(product_key) >= PRODUCT_KEY_MAXLEN ||
        strlen(device_name) >= DEVICE_NAME_MAXLEN) {
        return DM_INVALID_PARAMETER;
    }

    if (device_secret != NULL && strlen(device_secret) >= DEVICE_SECRET_MAXLEN) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_pkdn(product_key, device_name, &node);
    if (res == SUCCESS_RETURN) {
        if (devid) {
            *devid = node->devid;
        }
        return FAIL_RETURN;
    }

    node = DM_malloc(sizeof(dm_mgr_dev_node_t));
    if (node == NULL) {
        return DM_MEMORY_NOT_ENOUGH;
    }
    memset(node, 0, sizeof(dm_mgr_dev_node_t));

    node->devid = _dm_mgr_next_devid();
    node->dev_type = dev_type;

    memcpy(node->product_key, product_key, strlen(product_key));
    memcpy(node->device_name, device_name, strlen(device_name));
    if (device_secret != NULL) {
        memcpy(node->device_secret, device_secret, strlen(device_secret));
    }
    node->dev_status = IOTX_DM_DEV_STATUS_AUTHORIZED;
    INIT_LIST_HEAD(&node->linked_list);

    list_add_tail(&node->linked_list, &ctx->dev_list);

    if (devid) {
        *devid = node->devid;
    }

    return SUCCESS_RETURN;
}

int dm_mgr_device_destroy(_IN_ int devid)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    if (node->devid == IOTX_DM_LOCAL_NODE_DEVID) {
        return FAIL_RETURN;
    }

    list_del(&node->linked_list);

    DM_free(node);

    return SUCCESS_RETURN;
}

int dm_mgr_device_number(void)
{
    int index = 0;
    dm_mgr_ctx *ctx = _dm_mgr_get_ctx();
    dm_mgr_dev_node_t *search_node = NULL;

    list_for_each_entry(search_node, &ctx->dev_list, linked_list, dm_mgr_dev_node_t) {
        index++;
    }

    return index;
}

int dm_mgr_get_devid_by_index(_IN_ int index, _OU_ int *devid)
{
    int search_index = 0;
    dm_mgr_ctx *ctx = _dm_mgr_get_ctx();
    dm_mgr_dev_node_t *search_node = NULL;

    if (index < 0 || devid == NULL) {
        return DM_INVALID_PARAMETER;
    }

    list_for_each_entry(search_node, &ctx->dev_list, linked_list, dm_mgr_dev_node_t) {
        if (search_index == index) {
            *devid = search_node->devid;
            return SUCCESS_RETURN;
        }
        search_index++;
    }

    return FAIL_RETURN;
}

int dm_mgr_get_next_devid(_IN_ int devid, _OU_ int *devid_next)
{
    dm_mgr_ctx *ctx = _dm_mgr_get_ctx();
    dm_mgr_dev_node_t *search_node = NULL;
    dm_mgr_dev_node_t *next_node = NULL;

    if (devid < 0 || devid_next == NULL) {
        return DM_INVALID_PARAMETER;
    }

    list_for_each_entry(next_node, &ctx->dev_list, linked_list, dm_mgr_dev_node_t) {
        if (search_node && search_node->devid == devid) {
            *devid_next = next_node->devid;
            return SUCCESS_RETURN;
        }

        if (next_node->devid == devid) {
            search_node = next_node;
        }
    }

    return FAIL_RETURN;
}

int dm_mgr_search_device_by_devid(_IN_ int devid, _OU_ char product_key[PRODUCT_KEY_MAXLEN],
                                  _OU_ char device_name[DEVICE_NAME_MAXLEN], _OU_ char device_secret[DEVICE_SECRET_MAXLEN])
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;

    if (product_key == NULL || device_name == NULL || device_secret == NULL) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    memcpy(product_key, node->product_key, strlen(node->product_key));
    memcpy(device_name, node->device_name, strlen(node->device_name));
    memcpy(device_secret, node->device_secret, strlen(node->device_secret));

    return SUCCESS_RETURN;
}

int dm_mgr_search_device_by_pkdn(_IN_ char product_key[PRODUCT_KEY_MAXLEN], _IN_ char device_name[DEVICE_NAME_MAXLEN],
                                 _OU_ int *devid)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;

    if (product_key == NULL || device_name == NULL) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_pkdn(product_key, device_name, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    if (devid) {
        *devid = node->devid;
    }

    return SUCCESS_RETURN;
}

int dm_mgr_search_device_node_by_devid(_IN_ int devid, _OU_ void **node)
{
    int res = 0;
    dm_mgr_dev_node_t *search_node = NULL;

    res = _dm_mgr_search_dev_by_devid(devid, &search_node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    if (node) {
        *node = (void *)search_node;
    }

    return SUCCESS_RETURN;
}

int dm_mgr_get_dev_type(_IN_ int devid, _OU_ int *dev_type)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;

    if (devid < 0 || dev_type == NULL) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    *dev_type = node->dev_type;

    return SUCCESS_RETURN;
}

int dm_mgr_set_dev_enable(_IN_ int devid)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    node->status = IOTX_DM_DEV_AVAIL_ENABLE;

    return SUCCESS_RETURN;
}

int dm_mgr_set_dev_disable(_IN_ int devid)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    node->status = IOTX_DM_DEV_AVAIL_DISABLE;

    return SUCCESS_RETURN;
}

int dm_mgr_get_dev_avail(_IN_ char product_key[PRODUCT_KEY_MAXLEN], _IN_ char device_name[DEVICE_NAME_MAXLEN],
                         _OU_ iotx_dm_dev_avail_t *status)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;

    if (product_key == NULL || device_name == NULL || status == NULL ||
        (strlen(product_key) >= PRODUCT_KEY_MAXLEN) ||
        (strlen(device_name) >= DEVICE_NAME_MAXLEN)) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_pkdn(product_key, device_name, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    *status = node->status;

    return SUCCESS_RETURN;
}

int dm_mgr_set_dev_status(_IN_ int devid, _IN_ iotx_dm_dev_status_t status)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    node->dev_status = status;

    return SUCCESS_RETURN;
}

int dm_mgr_get_dev_status(_IN_ int devid, _OU_ iotx_dm_dev_status_t *status)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;

    if (devid < 0 || status == NULL) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    *status = node->dev_status;

    return SUCCESS_RETURN;
}

int dm_mgr_set_device_secret(_IN_ int devid, _IN_ char device_secret[DEVICE_SECRET_MAXLEN])
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;

    if (devid < 0 || device_secret == NULL ||
        strlen(device_secret) >= DEVICE_SECRET_MAXLEN) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    memset(node->device_secret, 0, DEVICE_SECRET_MAXLEN);
    memcpy(node->device_secret, device_secret, strlen(device_secret));

    return SUCCESS_RETURN;
}

int dm_mgr_dev_initialized(int devid)
{
    int res = 0, message_len = 0;
    char *message = NULL;
    const char *fmt = "{\"devid\":%d}";

    message_len = strlen(fmt) + DM_UTILS_UINT32_STRLEN + 1;
    message = DM_malloc(message_len);
    if (message == NULL) {
        return DM_MEMORY_NOT_ENOUGH;
    }
    memset(message, 0, message_len);
    HAL_Snprintf(message, message_len, fmt, devid);

    res = _dm_msg_send_to_user(IOTX_DM_EVENT_INITIALIZED, message);
    if (res != SUCCESS_RETURN) {
        DM_free(message);
        return FAIL_RETURN;
    }

    return SUCCESS_RETURN;
}

#ifdef DEVICE_MODEL_GATEWAY
#ifdef DM_SUBDEV_NEW_CONNECT
int dm_mgr_subdev_connect(int devid, const char *params, int params_len)
{
    int res = 0;
    char *payload = NULL;
    int payload_len = 0;
    char *params_fmt = "{\"identifier\":\"activation.Connect\",\"serviceParams\":{\"DeviceList\":%s}}";

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    payload_len = strlen(params_fmt) + params_len;
    payload = DM_malloc(payload_len);
    if (!payload) {
        return DM_MEMORY_NOT_ENOUGH;
    }

    HAL_Snprintf(payload, payload_len, params_fmt, params);

    res = dm_mgr_unified_service_post(devid, payload, strlen(payload));

    if (payload) DM_free(payload);

    return res;
}

int dm_mgr_all_subdev_connect(_IN_ int devid)
{
    int res = 0, index = 0, search_devid = 0;
    char product_key[PRODUCT_KEY_MAXLEN] = {0};
    char device_name[DEVICE_NAME_MAXLEN] = {0};
    char device_secret[DEVICE_SECRET_MAXLEN] = {0};

    char *device_array = NULL;
    lite_cjson_item_t *lite_array = NULL, *lite_object = NULL;

    int sign_source_len = 0;
    const char sign_source_fmt[] = "clientId%sdeviceName%sproductKey%stimestamp%s";
    char timestamp[DM_UTILS_UINT64_STRLEN] = {0};
    char client_id[PRODUCT_KEY_MAXLEN + DEVICE_NAME_MAXLEN + 1] = {0};
    char *sign_method = DM_MSG_SIGN_METHOD_HMACSHA1;
    char *sign_source = NULL;
    char sign[64] = {0};

    lite_array = lite_cjson_create_array();
    if (lite_array == NULL) {
        return DM_MEMORY_NOT_ENOUGH;
    }

    /* Get Product Key And Device Name Of All Device */
    for (index = 0; index < dm_mgr_device_number(); index++) {
        search_devid = 0;
        lite_object = NULL;
        memset(product_key, 0, PRODUCT_KEY_MAXLEN);
        memset(device_name, 0, DEVICE_NAME_MAXLEN);
        memset(device_secret, 0, DEVICE_SECRET_MAXLEN);

        res = dm_mgr_get_devid_by_index(index, &search_devid);
        if (res != SUCCESS_RETURN) {
            lite_cjson_delete(lite_array);
            return FAIL_RETURN;
        }

        //We only need sub dev
        if (search_devid < 1) continue;

        res = dm_mgr_search_device_by_devid(search_devid, product_key, device_name, device_secret);
        if (res != SUCCESS_RETURN) {
            lite_cjson_delete(lite_array);
            return FAIL_RETURN;
        }

        lite_object = lite_cjson_create_object();
        if (lite_object == NULL) {
            lite_cjson_delete(lite_array);
            return FAIL_RETURN;
        }

        /* TimeStamp */
        memset(timestamp, 0, DM_UTILS_UINT64_STRLEN);
        HAL_Snprintf(timestamp, DM_UTILS_UINT64_STRLEN, "%llu", HAL_UptimeMs());
        /* dm_log_debug("Time Stamp: %s", timestamp); */

        /* Client ID */
        memset(client_id, 0, PRODUCT_KEY_MAXLEN + DEVICE_NAME_MAXLEN + 1);
        HAL_Snprintf(client_id, PRODUCT_KEY_MAXLEN + DEVICE_NAME_MAXLEN + 1, "%s.%s", product_key, device_name);

        /* Sign */
        sign_source_len = strlen(sign_source_fmt) + strlen(client_id) +
                        strlen(device_name) + strlen(product_key) + strlen(timestamp) + 1;
        sign_source = DM_malloc(sign_source_len);
        if (sign_source == NULL) {
            return DM_MEMORY_NOT_ENOUGH;
        }
        memset(sign_source, 0, sign_source_len);
        HAL_Snprintf(sign_source, sign_source_len, sign_source_fmt, client_id,
                    device_name, product_key, timestamp);

        utils_hmac_sha1(sign_source, strlen(sign_source), sign, device_secret, strlen(device_secret));

        DM_free(sign_source);

        lite_cjson_add_string_to_object(lite_object, "ProductKey", product_key);
        lite_cjson_add_string_to_object(lite_object, "DeviceName", device_name);
        lite_cjson_add_string_to_object(lite_object, "clientId", client_id);
        lite_cjson_add_string_to_object(lite_object, "timestamp", timestamp);
        lite_cjson_add_string_to_object(lite_object, "signMethod", DM_MSG_SIGN_METHOD_HMACSHA1);
        lite_cjson_add_string_to_object(lite_object, "sign", sign);
        lite_cjson_add_string_to_object(lite_object, "cleanSession", "true");

        lite_cjson_add_item_to_array(lite_array, lite_object);
    }

    device_array = lite_cjson_print_unformatted(lite_array);
    lite_cjson_delete(lite_array);
    if (device_array == NULL) {
        return DM_MEMORY_NOT_ENOUGH;
    }

    res = dm_mgr_subdev_connect(devid, device_array, strlen(device_array));

    DM_free(device_array);

    return res;
}
#endif

int dm_mgr_upstream_thing_sub_register(_IN_ int devid)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;
    dm_msg_request_t request;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    memset(&request, 0, sizeof(dm_msg_request_t));
    request.service_prefix = DM_URI_SYS_PREFIX;
    request.service_name = DM_URI_THING_SUB_REGISTER;
    HAL_GetProductKey(request.product_key);
    HAL_GetDeviceName(request.device_name);

    /* Get Params And Method */
    res = dm_msg_thing_sub_register(node->product_key, node->device_name, &request);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    /* Get Msg ID */
    request.msgid = iotx_report_id();

    /* Get Dev ID */
    request.devid = devid;

    /* Callback */
    request.callback = dm_client_thing_sub_register_reply;

    /* Send Message To Cloud */
    res = dm_msg_request(DM_MSG_DEST_CLOUD, &request);
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    if (res == SUCCESS_RETURN) {
        dm_msg_cache_insert(request.msgid, request.devid, IOTX_DM_EVENT_SUBDEV_REGISTER_REPLY, NULL);
        res = request.msgid;
    }
#endif
    DM_free(request.params);

    return res;
}

int dm_mgr_upstream_thing_sub_unregister(_IN_ int devid)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;
    dm_msg_request_t request;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    memset(&request, 0, sizeof(dm_msg_request_t));
    request.service_prefix = DM_URI_SYS_PREFIX;
    request.service_name = DM_URI_THING_SUB_UNREGISTER;
    HAL_GetProductKey(request.product_key);
    HAL_GetDeviceName(request.device_name);

    /* Get Params And Method */
    res = dm_msg_thing_sub_unregister(node->product_key, node->device_name, &request);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    /* Get Msg ID */
    request.msgid = iotx_report_id();

    /* Get Dev ID */
    request.devid = devid;

    /* Callback */
    request.callback = dm_client_thing_sub_unregister_reply;

    /* Send Message To Cloud */
    res = dm_msg_request(DM_MSG_DEST_CLOUD, &request);
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    if (res == SUCCESS_RETURN) {
        dm_msg_cache_insert(request.msgid, request.devid, IOTX_DM_EVENT_SUBDEV_UNREGISTER_REPLY, NULL);
        res = request.msgid;
    }
#endif
    DM_free(request.params);

    return res;
}

int dm_mgr_upstream_thing_topo_add(_IN_ int devid)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;
    dm_msg_request_t request;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    memset(&request, 0, sizeof(dm_msg_request_t));
    request.service_prefix = DM_URI_SYS_PREFIX;
    request.service_name = DM_URI_THING_TOPO_ADD;
    HAL_GetProductKey(request.product_key);
    HAL_GetDeviceName(request.device_name);

    /* Get Params And Method */
    res = dm_msg_thing_topo_add(node->product_key, node->device_name, node->device_secret, &request);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    /* Get Msg ID */
    request.msgid = iotx_report_id();

    /* Get Dev ID */
    request.devid = devid;

    /* Callback */
    request.callback = dm_client_thing_topo_add_reply;

    /* Send Message To Cloud */
    res = dm_msg_request(DM_MSG_DEST_CLOUD, &request);
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    if (res == SUCCESS_RETURN) {
        dm_msg_cache_insert(request.msgid, request.devid, IOTX_DM_EVENT_TOPO_ADD_REPLY, NULL);
        res = request.msgid;
    }
#endif
    DM_free(request.params);

    return res;
}

int dm_mgr_upstream_thing_topo_delete(_IN_ int devid)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;
    dm_msg_request_t request;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    memset(&request, 0, sizeof(dm_msg_request_t));
    request.service_prefix = DM_URI_SYS_PREFIX;
    request.service_name = DM_URI_THING_TOPO_DELETE;
    HAL_GetProductKey(request.product_key);
    HAL_GetDeviceName(request.device_name);

    /* Get Params And Method */
    res = dm_msg_thing_topo_delete(node->product_key, node->device_name, &request);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    /* Get Msg ID */
    request.msgid = iotx_report_id();

    /* Get Dev ID */
    request.devid = devid;

    /* Callback */
    request.callback = dm_client_thing_topo_delete_reply;

    /* Send Message To Cloud */
    res = dm_msg_request(DM_MSG_DEST_CLOUD, &request);
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    if (res == SUCCESS_RETURN) {
        dm_msg_cache_insert(request.msgid, request.devid, IOTX_DM_EVENT_TOPO_DELETE_REPLY, NULL);
        res = request.msgid;
    }
#endif
    DM_free(request.params);

    return res;
}

int dm_mgr_upstream_thing_subdev_reset(_IN_ int devid)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;
    dm_msg_request_t request;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    memset(&request, 0, sizeof(dm_msg_request_t));
    request.service_prefix = DM_URI_SYS_PREFIX;
    request.service_name = DM_URI_THING_SUB_RESET;

    memcpy(request.product_key, node->product_key, strlen(node->product_key));
    memcpy(request.device_name, node->device_name, strlen(node->device_name));

    /* Get Params And Method */
    res = dm_msg_thing_subdev_reset(&request);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    /* Get Msg ID */
    request.msgid = iotx_report_id();

    /* Get Dev ID */
    request.devid = devid;

    /* Callback */
    request.callback = NULL;

    /* Send Message To Cloud */
    res = dm_msg_request(DM_MSG_DEST_CLOUD, &request);
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    if (res == SUCCESS_RETURN) {
        dm_msg_cache_insert(request.msgid, request.devid, IOTX_DM_EVENT_SUBDEV_RESET_REPLY, NULL);
        res = request.msgid;
    }
#endif
    DM_free(request.params);

    return res;
}

int dm_mgr_upstream_thing_topo_get(void)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;
    dm_msg_request_t request;

    memset(&request, 0, sizeof(dm_msg_request_t));
    request.service_prefix = DM_URI_SYS_PREFIX;
    request.service_name = DM_URI_THING_TOPO_GET;
    HAL_GetProductKey(request.product_key);
    HAL_GetDeviceName(request.device_name);

    res = _dm_mgr_search_dev_by_pkdn(request.product_key, request.device_name, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    /* Get Params And Method */
    res = dm_msg_thing_topo_get(&request);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    /* Get Msg ID */
    request.msgid = iotx_report_id();

    /* Get Dev ID */
    request.devid = node->devid;

    /* Callback */
    request.callback = dm_client_thing_topo_get_reply;

    /* Send Message To Cloud */
    res = dm_msg_request(DM_MSG_DEST_CLOUD, &request);
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    if (res == SUCCESS_RETURN) {
        dm_msg_cache_insert(request.msgid, request.devid, IOTX_DM_EVENT_TOPO_GET_REPLY, NULL);
        res = request.msgid;
    }
#endif
    DM_free(request.params);

    return res;
}

int dm_mgr_upstream_thing_list_found(_IN_ int devid)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;
    dm_msg_request_t request;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    memset(&request, 0, sizeof(dm_msg_request_t));
    request.service_prefix = DM_URI_SYS_PREFIX;
    request.service_name = DM_URI_THING_LIST_FOUND;
    HAL_GetProductKey(request.product_key);
    HAL_GetDeviceName(request.device_name);

    /* Get Params And Method */
    res = dm_msg_thing_list_found(node->product_key, node->device_name, &request);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    /* Get Msg ID */
    request.msgid = iotx_report_id();

    /* Get Dev ID */
    request.devid = devid;

    /* Callback */
    request.callback = dm_client_thing_list_found_reply;

    /* Send Message To Cloud */
    res = dm_msg_request(DM_MSG_DEST_CLOUD, &request);
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    if (res == SUCCESS_RETURN) {
        dm_msg_cache_insert(request.msgid, request.devid, IOTX_DM_EVENT_TOPO_ADD_NOTIFY_REPLY, NULL);
        res = request.msgid;
    }
#endif
    DM_free(request.params);

    return res;
}

int dm_mgr_upstream_combine_login(_IN_ int devid)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;
    dm_msg_request_t request;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    memset(&request, 0, sizeof(dm_msg_request_t));
    request.service_prefix = DM_URI_EXT_SESSION_PREFIX;
    request.service_name = DM_URI_COMBINE_LOGIN;
    HAL_GetProductKey(request.product_key);
    HAL_GetDeviceName(request.device_name);

    /* Get Params And Method */
    res = dm_msg_combine_login(node->product_key, node->device_name, node->device_secret, &request);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    /* Get Msg ID */
    request.msgid = iotx_report_id();

    /* Get Dev ID */
    request.devid = devid;

    /* Callback */
    request.callback = dm_client_combine_login_reply;

    /* Send Message To Cloud */
    res = dm_msg_request(DM_MSG_DEST_CLOUD, &request);
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    if (res == SUCCESS_RETURN) {
        dm_msg_cache_insert(request.msgid, request.devid, IOTX_DM_EVENT_COMBINE_LOGIN_REPLY, NULL);
        res = request.msgid;
    }
#endif
    DM_free(request.params);

    return res;
}

int dm_mgr_upstream_combine_logout(_IN_ int devid)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;
    dm_msg_request_t request;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    if (node->dev_status < IOTX_DM_DEV_STATUS_LOGINED) {
        return FAIL_RETURN;
    }

    memset(&request, 0, sizeof(dm_msg_request_t));
    request.service_prefix = DM_URI_EXT_SESSION_PREFIX;
    request.service_name = DM_URI_COMBINE_LOGOUT;
    HAL_GetProductKey(request.product_key);
    HAL_GetDeviceName(request.device_name);

    /* Get Params And Method */
    res = dm_msg_combine_logout(node->product_key, node->device_name, &request);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    /* Get Msg ID */
    request.msgid = iotx_report_id();

    /* Get Dev ID */
    request.devid = devid;

    /* Callback */
    request.callback = dm_client_combine_logout_reply;

    /* Send Message To Cloud */
    res = dm_msg_request(DM_MSG_DEST_CLOUD, &request);
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    if (res == SUCCESS_RETURN) {
        dm_msg_cache_insert(request.msgid, request.devid, IOTX_DM_EVENT_COMBINE_LOGOUT_REPLY, NULL);
        res = request.msgid;
    }
#endif
    DM_free(request.params);

    return res;
}
#endif

int dm_mgr_upstream_thing_model_up_raw(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0, res1 = 0;
    dm_mgr_dev_node_t *node = NULL;
    char *uri = NULL;
    dm_msg_request_t request;

    if (devid < 0 || payload == NULL || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    memset(&request, 0, sizeof(dm_msg_request_t));
    request.service_prefix = DM_URI_SYS_PREFIX;
    request.service_name = DM_URI_THING_MODEL_UP_RAW;
    memcpy(request.product_key, node->product_key, strlen(node->product_key));
    memcpy(request.device_name, node->device_name, strlen(node->device_name));

    /* Request URI */
    res = dm_utils_service_name(request.service_prefix, request.service_name,
                                request.product_key, request.device_name, &uri);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    dm_log_info("DM Send Raw Data:");
    HEXDUMP_INFO(payload, payload_len);

    res = dm_client_publish(uri, (unsigned char *)payload, payload_len, dm_client_thing_model_up_raw_reply);
#ifdef ALCS_ENABLED
    res1 = dm_server_send(uri, (unsigned char *)payload, payload_len, NULL);
#endif

    if (res < SUCCESS_RETURN || res1 < SUCCESS_RETURN) {
        DM_free(uri);
        return FAIL_RETURN;
    }

    DM_free(uri);
    return SUCCESS_RETURN;
}

#if !defined(DEVICE_MODEL_RAWDATA_SOLO)
static int _dm_mgr_upstream_request_assemble(_IN_ int msgid, _IN_ int devid, _IN_ const char *service_prefix,
        _IN_ const char *service_name,
        _IN_ char *params, _IN_ int params_len, _IN_ char *method, _OU_ dm_msg_request_t *request)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    request->msgid = msgid;
    request->devid = devid;
    request->service_prefix = service_prefix;
    request->service_name = service_name;
    memcpy(request->product_key, node->product_key, strlen(node->product_key));
    memcpy(request->device_name, node->device_name, strlen(node->device_name));
    request->params = params;
    request->params_len = params_len;
    request->method = method;

    return SUCCESS_RETURN;
}

int dm_mgr_upstream_thing_property_post(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0;
    dm_msg_request_t request;

    if (devid < 0 || payload == NULL || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    memset(&request, 0, sizeof(dm_msg_request_t));
    res = _dm_mgr_upstream_request_assemble(iotx_report_id(), devid, DM_URI_SYS_PREFIX, DM_URI_THING_EVENT_PROPERTY_POST,
                                            payload, payload_len, "thing.event.property.post", &request);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    /* Callback */
    request.callback = dm_client_thing_event_post_reply;

    /* Send Message To Cloud */
    res = dm_msg_request(DM_MSG_DEST_ALL, &request);
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    if (res == SUCCESS_RETURN) {
        int prop_post_reply = 0;
        res = dm_opt_get(DM_OPT_DOWNSTREAM_EVENT_POST_REPLY, &prop_post_reply);
        if (res == SUCCESS_RETURN && prop_post_reply) {
            dm_msg_cache_insert(request.msgid, request.devid, IOTX_DM_EVENT_EVENT_PROPERTY_POST_REPLY, NULL);
        }
        res = request.msgid;
    }
#endif
    return res;
}

#ifdef DM_UNIFIED_SERVICE_POST
int dm_mgr_unified_service_post(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0;
    dm_msg_request_t request;

    if (devid < 0 || payload == NULL || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    memset(&request, 0, sizeof(dm_msg_request_t));

    request.msgid = iotx_report_id();
    request.devid = devid;
    request.service_prefix = DM_URI_SYS_PREFIX;
    request.service_name = DM_URI_UNIFIED_SERVICE_POST;
    request.params = payload;
    request.params_len = payload_len;
    request.method = "_thing.service.post";

    HAL_GetProductKey(request.product_key);
    HAL_GetDeviceName(request.device_name);

    /* Callback */
    request.callback = dm_client_unified_service_post_reply;

    /* Send Message To Cloud */
    res = dm_msg_request(DM_MSG_DEST_ALL, &request);
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    if (res == SUCCESS_RETURN) {
        int prop_post_reply = 0;
        res = dm_opt_get(DM_OPT_DOWNSTREAM_EVENT_POST_REPLY, &prop_post_reply);
        if (res == SUCCESS_RETURN && prop_post_reply) {
            dm_msg_cache_insert(request.msgid, request.devid, IOTX_DM_EVENT_EVENT_PROPERTY_POST_REPLY, NULL);
        }
        res = request.msgid;
    }
#endif
    return res;
}
#endif

int dm_mgr_upstream_thing_event_notify(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0;
    dm_msg_request_t request;

    if (devid < 0 || payload == NULL || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    memset(&request, 0, sizeof(dm_msg_request_t));
    res = _dm_mgr_upstream_request_assemble(iotx_report_id(), devid, DM_URI_SYS_PREFIX, DM_URI_THING_EVENT_PROPERTY_POST,
                                            payload, payload_len, "thing.event.property.post", &request);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    /* Callback */
    request.callback = dm_client_thing_event_post_reply;

    /* Send Message To Cloud */
    res = dm_msg_request(DM_MSG_DEST_ALL, &request);
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    if (res == SUCCESS_RETURN) {
        int prop_post_reply = 0;
        res = dm_opt_get(DM_OPT_DOWNSTREAM_EVENT_POST_REPLY, &prop_post_reply);
        if (res == SUCCESS_RETURN && prop_post_reply) {
            dm_msg_cache_insert(request.msgid, request.devid, IOTX_DM_EVENT_EVENT_PROPERTY_POST_REPLY, NULL);
        }
        res = request.msgid;
    }
#endif
    return res;
}

int dm_mgr_upstream_thing_event_notify_reply(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0;
    dm_msg_request_t request;

    if (devid < 0 || payload == NULL || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    memset(&request, 0, sizeof(dm_msg_request_t));
    res = _dm_mgr_upstream_request_assemble(iotx_report_id(), devid, DM_URI_SYS_PREFIX, DM_URI_THING_EVENT_NOTIFY_REPLY,
                                            payload, payload_len, "_thing.event.notify", &request);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    /* Callback */
    request.callback = dm_client_thing_event_notify_reply;

    /* Send Message To Cloud */
    res = dm_msg_request(DM_MSG_DEST_CLOUD, &request);
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    if (res == SUCCESS_RETURN) {
        int event_notify_reply = 0;
        res = dm_opt_get(DM_OPT_UPSTREAM_EVENT_NOTIFY_REPLY, &event_notify_reply);
        if (res == SUCCESS_RETURN && event_notify_reply) {
            dm_msg_cache_insert(request.msgid, request.devid, IOTX_DM_EVENT_THING_EVENT_NOTIFY_REPLY, NULL);
        }
        res = request.msgid;
    }
#endif
    return res;
}

#ifdef LOG_REPORT_TO_CLOUD
static unsigned int log_size = 0;
int dm_mgr_upstream_thing_log_post(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len, int force_upload)
{
    int res = 0;
    dm_msg_request_t request;

    if (0 == force_upload) {
        if (devid < 0 || payload == NULL || payload_len <= 0) {
            return DM_INVALID_PARAMETER;
        }

        if (log_size + payload_len < OVERFLOW_LEN) {
            log_size = push_log(payload, payload_len);
        } else {
            /* it should NOT happen; it means that it is too late to upload log files */
            reset_log_poll();
            dm_log_err("it it too late to upload log, reset pool");
            return FAIL_RETURN;
        }

        dm_log_info("push log, len is %d, log_size is %d\n", payload_len, log_size);
        extern REPORT_STATE g_report_status;
        if (!(log_size > REPORT_LEN && DONE == g_report_status)) {
            return SUCCESS_RETURN;
        }
    }

    extern char *g_log_poll;
    log_size = add_tail();
    memset(&request, 0, sizeof(dm_msg_request_t));
    res = _dm_mgr_upstream_request_assemble(iotx_report_id(), devid, DM_URI_SYS_PREFIX, DM_URI_THING_LOG_POST,
                                            g_log_poll, log_size + 1, "thing.log.post", &request);

    if (res != SUCCESS_RETURN) {
        reset_log_poll();
        return FAIL_RETURN;
    }

    /* Send Message To Cloud */
    res = dm_msg_request(DM_MSG_DEST_CLOUD, &request);
    reset_log_poll();
    return res;
}
#endif

int dm_mgr_upstream_thing_event_post(_IN_ int devid, _IN_ char *identifier, _IN_ int identifier_len, _IN_ char *method,
                                     _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0, service_name_len = 0;
    char *service_name = NULL;
    dm_msg_request_t request;

    if (devid < 0 || identifier == NULL || identifier_len <= 0 ||
        method == NULL || payload == NULL || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    service_name_len = strlen(DM_URI_THING_EVENT_POST) + identifier_len + 1;
    service_name = DM_malloc(service_name_len);
    if (service_name == NULL) {
        return DM_MEMORY_NOT_ENOUGH;
    }
    memset(service_name, 0, service_name_len);
    HAL_Snprintf(service_name, service_name_len, DM_URI_THING_EVENT_POST, identifier_len, identifier);

    memset(&request, 0, sizeof(dm_msg_request_t));
    res = _dm_mgr_upstream_request_assemble(iotx_report_id(), devid, DM_URI_SYS_PREFIX, service_name,
                                            payload, payload_len, method, &request);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    /* Callback */
    request.callback = dm_client_thing_event_post_reply;

    /* Send Message To Cloud */
    res = dm_msg_request(DM_MSG_DEST_ALL, &request);
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    if (res == SUCCESS_RETURN) {
        int event_post_reply = 0;
        res = dm_opt_get(DM_OPT_DOWNSTREAM_EVENT_POST_REPLY, &event_post_reply);
        if (res == SUCCESS_RETURN && event_post_reply) {
            dm_msg_cache_insert(request.msgid, request.devid, IOTX_DM_EVENT_EVENT_PROPERTY_POST_REPLY, NULL);
        }
        res = request.msgid;
    }
#endif
    DM_free(service_name);

    return res;
}

int dm_mgr_upstream_thing_deviceinfo_update(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0;
    dm_msg_request_t request;

    if (devid < 0 || payload == NULL || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    memset(&request, 0, sizeof(dm_msg_request_t));
    res = _dm_mgr_upstream_request_assemble(iotx_report_id(), devid, DM_URI_SYS_PREFIX, DM_URI_THING_DEVICEINFO_UPDATE,
                                            payload, payload_len, "thing.deviceinfo.update", &request);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    /* Callback */
    request.callback = dm_client_thing_deviceinfo_update_reply;

    /* Send Message To Cloud */
    res = dm_msg_request(DM_MSG_DEST_CLOUD, &request);
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    if (res == SUCCESS_RETURN) {
        dm_msg_cache_insert(request.msgid, request.devid, IOTX_DM_EVENT_DEVICEINFO_UPDATE_REPLY, NULL);
        res = request.msgid;
    }
#endif
    return res;
}

int dm_mgr_upstream_thing_deviceinfo_delete(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0;
    dm_msg_request_t request;

    if (devid < 0 || payload == NULL || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    memset(&request, 0, sizeof(dm_msg_request_t));
    res = _dm_mgr_upstream_request_assemble(iotx_report_id(), devid, DM_URI_SYS_PREFIX, DM_URI_THING_DEVICEINFO_DELETE,
                                            payload, payload_len, "thing.deviceinfo.delete", &request);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    /* Callback */
    request.callback = dm_client_thing_deviceinfo_delete_reply;

    /* Send Message To Cloud */
    res = dm_msg_request(DM_MSG_DEST_CLOUD, &request);
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    if (res == SUCCESS_RETURN) {
        dm_msg_cache_insert(request.msgid, request.devid, IOTX_DM_EVENT_DEVICEINFO_DELETE_REPLY, NULL);
        res = request.msgid;
    }
#endif
    return res;
}

int dm_mgr_upstream_thing_dsltemplate_get(_IN_ int devid)
{
    int res = 0;
    char *params = "{}";
    int params_len = strlen(params);
    dm_msg_request_t request;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    memset(&request, 0, sizeof(dm_msg_request_t));
    res = _dm_mgr_upstream_request_assemble(iotx_report_id(), devid, DM_URI_SYS_PREFIX, DM_URI_THING_DSLTEMPLATE_GET,
                                            params, params_len, "thing.dsltemplate.get", &request);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    /* Send Message To Cloud */
    res = dm_msg_request(DM_MSG_DEST_CLOUD, &request);
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    if (res == SUCCESS_RETURN) {
        dm_msg_cache_insert(request.msgid, request.devid, IOTX_DM_EVENT_DSLTEMPLATE_GET_REPLY, NULL);
        res = request.msgid;
    }
#endif
    return res;
}

int dm_mgr_upstream_ntp_request(void)
{
    int res = 0;
    const char *ntp_request_fmt = "{\"deviceSendTime\":\"1234\"}";
    char /* *cloud_payload = NULL, */ *uri = NULL;
    dm_msg_request_t request;

    memset(&request, 0, sizeof(dm_msg_request_t));
    request.service_prefix = DM_URI_EXT_NTP_PREFIX;
    request.service_name = DM_URI_NTP_REQUEST;
    HAL_GetProductKey(request.product_key);
    HAL_GetDeviceName(request.device_name);

    /* Request URI */
    res = dm_utils_service_name(request.service_prefix, request.service_name,
                                request.product_key, request.device_name, &uri);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    res = dm_client_publish(uri, (unsigned char *)ntp_request_fmt, strlen(ntp_request_fmt), dm_client_ntp_response);
    if (res != SUCCESS_RETURN) {
        DM_free(uri);//DM_free(cloud_payload);
        return FAIL_RETURN;
    }

    DM_free(uri);//DM_free(cloud_payload);
    return SUCCESS_RETURN;
}

static int _dm_mgr_upstream_response_assemble(_IN_ int devid, _IN_ char *msgid, _IN_ int msgid_len,
        _IN_ const char *prefix,
        _IN_ const char *service_name, _IN_ int code, _OU_ dm_msg_request_payload_t *request, _OU_ dm_msg_response_t *response)
{
    int res = 0;
    dm_mgr_dev_node_t *node = NULL;

    res = _dm_mgr_search_dev_by_devid(devid, &node);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    request->id.value = msgid;
    request->id.value_length = msgid_len;

    response->service_prefix = DM_URI_SYS_PREFIX;
    response->service_name = service_name;
    memcpy(response->product_key, node->product_key, strlen(node->product_key));
    memcpy(response->device_name, node->device_name, strlen(node->device_name));
    response->code = code;

    return SUCCESS_RETURN;
}

#ifndef LINK_VISUAL_ENABLE
int dm_mgr_upstream_thing_service_response(_IN_ int devid, _IN_ char *msgid, _IN_ int msgid_len,
        _IN_ iotx_dm_error_code_t code,
        _IN_ char *identifier, _IN_ int identifier_len, _IN_ char *payload, _IN_ int payload_len, void *ctx)
{
    int res = 0, service_name_len = 0;
    char *service_name = NULL;
    dm_msg_request_payload_t request;
    dm_msg_response_t response;

    memset(&request, 0, sizeof(dm_msg_request_payload_t));
    memset(&response, 0, sizeof(dm_msg_response_t));

    if (devid < 0 || msgid == NULL || msgid_len <= 0 || identifier == NULL || identifier_len <= 0 ||
        payload == NULL || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    /* Service Name */
    service_name_len = strlen(DM_URI_THING_SERVICE_RESPONSE) + identifier_len + 1;
    service_name = DM_malloc(service_name_len);
    if (service_name == NULL) {
        return DM_MEMORY_NOT_ENOUGH;
    }
    memset(service_name, 0, service_name_len);
    HAL_Snprintf(service_name, service_name_len, DM_URI_THING_SERVICE_RESPONSE, identifier_len, identifier);

    res = _dm_mgr_upstream_response_assemble(devid, msgid, msgid_len, DM_URI_SYS_PREFIX, service_name, code, &request,
            &response);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    dm_log_debug("Current Service Name: %s", service_name);
    if (ctx != NULL) {
        dm_msg_response(DM_MSG_DEST_LOCAL, &request, &response, payload, payload_len, ctx);
    } else {
        dm_msg_response(DM_MSG_DEST_CLOUD, &request, &response, payload, payload_len, ctx);
    }

    DM_free(service_name);
    return SUCCESS_RETURN;
}
#else
int dm_mgr_upstream_thing_service_response(_IN_ int devid, _IN_ char *msgid, _IN_ int msgid_len,
        _IN_ iotx_dm_error_code_t code,
        _IN_ char *identifier, _IN_ int identifier_len, _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0, service_name_len = 0;
    char *service_name = NULL;
    dm_msg_request_payload_t request;
    dm_msg_response_t response;

    memset(&request, 0, sizeof(dm_msg_request_payload_t));
    memset(&response, 0, sizeof(dm_msg_response_t));
    if (devid < 0 || msgid == NULL || msgid_len <= 0 || identifier == NULL || identifier_len <= 0 ||
        payload == NULL || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }
    service_name_len = strlen(DM_URI_THING_SERVICE_RESPONSE) + identifier_len + 1;
    service_name = DM_malloc(service_name_len);
    if (service_name == NULL) {
        return DM_MEMORY_NOT_ENOUGH;
    }
    memset(service_name, 0, service_name_len);
    HAL_Snprintf(service_name, service_name_len, DM_URI_THING_SERVICE_RESPONSE, identifier_len, identifier);
    res = _dm_mgr_upstream_response_assemble(devid, msgid, msgid_len, DM_URI_SYS_PREFIX, service_name, code, &request,
            &response);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }
    dm_log_debug("Current Service Name: %s", service_name);
    dm_msg_response(DM_MSG_DEST_ALL, &request, &response, payload, payload_len, NULL);
    DM_free(service_name);
    return SUCCESS_RETURN;
}
#endif
int dm_mgr_upstream_thing_property_get_response(_IN_ int devid, _IN_ char *msgid, _IN_ int msgid_len,
        _IN_ iotx_dm_error_code_t code,
        _IN_ char *payload, _IN_ int payload_len, _IN_ void *ctx)
{
    int res = 0;
    dm_msg_request_payload_t request;
    dm_msg_response_t response;

    if (devid < 0 || msgid == NULL || msgid_len <= 0 ||
        payload == NULL || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    memset(&request, 0, sizeof(dm_msg_request_payload_t));
    memset(&response, 0, sizeof(dm_msg_response_t));

    res = _dm_mgr_upstream_response_assemble(devid, msgid, msgid_len, DM_URI_SYS_PREFIX,
            DM_URI_THING_SERVICE_PROPERTY_GET, code, &request, &response);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    dm_log_debug("Current Service Name: %s", DM_URI_THING_SERVICE_PROPERTY_GET);

    /* Send Property Get Response Message To Local */
    dm_msg_response(DM_MSG_DEST_LOCAL, &request, &response, payload, payload_len, ctx);

#ifdef ALCS_ENABLED
    dm_server_alcs_context_t *alcs_context = (dm_server_alcs_context_t *)ctx;

    if (alcs_context) {
        DM_free(alcs_context->ip);
        DM_free(alcs_context->token);
        DM_free(alcs_context);
    }
#endif

    return SUCCESS_RETURN;
}

int dm_mgr_upstream_rrpc_response(_IN_ int devid, _IN_ char *msgid, _IN_ int msgid_len, _IN_ iotx_dm_error_code_t code,
                                  _IN_ char *rrpcid, _IN_ int rrpcid_len, _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0, service_name_len = 0;
    const char *rrpc_response_service_name = "rrpc/response/%.*s";
    char *service_name = NULL;
    dm_msg_request_payload_t request;
    dm_msg_response_t response;

    memset(&request, 0, sizeof(dm_msg_request_payload_t));
    memset(&response, 0, sizeof(dm_msg_response_t));

    if (devid < 0 || msgid == NULL || msgid_len <= 0 ||
        rrpcid == NULL || rrpcid_len <= 0 || payload == NULL || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    /* Service Name */
    service_name_len = strlen(rrpc_response_service_name) + rrpcid_len + 1;
    service_name = DM_malloc(service_name_len);
    if (service_name == NULL) {
        return DM_MEMORY_NOT_ENOUGH;
    }
    memset(service_name, 0, service_name_len);
    HAL_Snprintf(service_name, service_name_len, rrpc_response_service_name, rrpcid_len, rrpcid);

    res = _dm_mgr_upstream_response_assemble(devid, msgid, msgid_len, DM_URI_SYS_PREFIX, service_name, code, &request,
            &response);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    dm_log_debug("Current Service Name: %s", service_name);
    dm_msg_response(DM_MSG_DEST_ALL, &request, &response, payload, payload_len, NULL);

    DM_free(service_name);

    return SUCCESS_RETURN;
}
#endif

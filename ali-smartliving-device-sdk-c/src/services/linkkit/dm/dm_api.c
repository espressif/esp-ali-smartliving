/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */



#include "iotx_dm_internal.h"

static dm_api_ctx_t g_dm_api_ctx;

static dm_api_ctx_t *_dm_api_get_ctx(void)
{
    return &g_dm_api_ctx;
}

static void _dm_api_lock(void)
{
    dm_api_ctx_t *ctx = _dm_api_get_ctx();
    if (ctx->mutex) {
        HAL_MutexLock(ctx->mutex);
    }
}

static void _dm_api_unlock(void)
{
    dm_api_ctx_t *ctx = _dm_api_get_ctx();
    if (ctx->mutex) {
        HAL_MutexUnlock(ctx->mutex);
    }
}

int iotx_dm_open(void)
{
    int res = 0;
    dm_api_ctx_t *ctx = _dm_api_get_ctx();

    memset(ctx, 0, sizeof(dm_api_ctx_t));

#if defined(ALCS_ENABLED)
    /* lite-cjson Hooks Init */
    lite_cjson_hooks hooks;
    hooks.malloc_fn = dm_utils_malloc;
    hooks.free_fn = dm_utils_free;
    lite_cjson_init_hooks(&hooks);
#endif

    /* DM Mutex Create*/
    ctx->mutex = HAL_MutexCreate();
    if (ctx->mutex == NULL) {
        return DM_MEMORY_NOT_ENOUGH;
    }

#if defined(OTA_ENABLED) && !defined(BUILD_AOS)
    /* DM OTA Module Init */
    res = dm_ota_init();
    if (res != SUCCESS_RETURN) {
        goto ERROR;
    }
#endif

#if !defined(DM_MESSAGE_CACHE_DISABLED)
    /* DM Message Cache Init */
    res = dm_msg_cache_init();
    if (res != SUCCESS_RETURN) {
        goto ERROR;
    }
#endif
    /* DM Cloud Message Parse And Assemble Module Init */
    res = dm_msg_init();
    if (res != SUCCESS_RETURN) {
        goto ERROR;
    }

    /* DM IPC Module Init */
    res = dm_ipc_init(CONFIG_DISPATCH_QUEUE_MAXLEN);
    if (res != SUCCESS_RETURN) {
        goto ERROR;
    }

    /* DM Manager Module Init */
    res = dm_mgr_init();
    if (res != SUCCESS_RETURN) {
        goto ERROR;
    }

#ifdef ALCS_ENABLED
    /* Open Local Connection */
    res = dm_server_open();
    if (res < SUCCESS_RETURN) {
        goto ERROR;
    }
#endif
#if defined(OTA_ENABLED) && !defined(BUILD_AOS)
    /* DM OTA Module Init */
    res = dm_ota_sub();
    if (res == SUCCESS_RETURN) {
        /* DM Config OTA Module Init */
        dm_cota_init();

        /* DM Firmware OTA Mudule Init */
        dm_fota_init();
    }
#endif

    /* Open Cloud Connection */
    res = dm_client_open();
    if (res < SUCCESS_RETURN) {
        goto ERROR;
    }

    return SUCCESS_RETURN;

ERROR:
    dm_client_close();
#ifdef ALCS_ENABLED
    dm_server_close();
#endif
    dm_mgr_deinit();
    dm_ipc_deinit();
    dm_msg_deinit();
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    dm_msg_cache_deinit();
#endif
#if defined(OTA_ENABLED) && !defined(BUILD_AOS)
    dm_ota_deinit();
#endif

    if (ctx->mutex) {
        HAL_MutexDestroy(ctx->mutex);
    }
    return FAIL_RETURN;
}

int iotx_dm_connect(_IN_ iotx_dm_init_params_t *init_params)
{
    int res = 0;
    dm_api_ctx_t *ctx = _dm_api_get_ctx();

    if (init_params == NULL) {
        return DM_INVALID_PARAMETER;
    }

    /* DM Event Callback */
    if (init_params->event_callback != NULL) {
        ctx->event_callback = init_params->event_callback;
    }

    res = dm_client_connect(IOTX_DM_CLIENT_CONNECT_TIMEOUT_MS);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

#ifdef ALCS_ENABLED
    /* DM Connect Local */
    do{
        res = dm_server_connect();
        if (res < 0) {
            dm_log_err("dm_server_connect Failed, retry after 2s...\n");
            HAL_SleepMs(2000);
        }
    }while(res < 0);
    // res = dm_server_connect();
    // if (res != SUCCESS_RETURN) {
    //     return FAIL_RETURN;
    // }
#endif

    return SUCCESS_RETURN;
}

int iotx_dm_subscribe(_IN_ int devid)
{
    int res = 0, dev_type = 0;
    char product_key[PRODUCT_KEY_MAXLEN] = {0};
    char device_name[DEVICE_NAME_MAXLEN] = {0};
    char device_secret[DEVICE_SECRET_MAXLEN] = {0};

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();
    res = dm_mgr_search_device_by_devid(devid, product_key, device_name, device_secret);
    if (res < SUCCESS_RETURN) {
        _dm_api_unlock();
        return res;
    }

    res = dm_mgr_get_dev_type(devid, &dev_type);
    if (res < SUCCESS_RETURN) {
        _dm_api_unlock();
        return res;
    }

#ifdef ALCS_ENABLED
    if(devid > 0) {
        res = dm_server_add_device(product_key, device_name);
        if (res < SUCCESS_RETURN) {
            _dm_api_unlock();
            return res;
        }
    }
    
    res = dm_server_subscribe_all(product_key, device_name);
    if (res < SUCCESS_RETURN) {
        _dm_api_unlock();
        return res;
    }
#endif

    res = dm_client_subscribe_all(devid, product_key, device_name, dev_type);
    if (res < SUCCESS_RETURN) {
        _dm_api_unlock();
        return res;
    }

    _dm_api_unlock();
    dm_log_info("Devid %d Sub Completed", devid);

    return SUCCESS_RETURN;
}

int iotx_dm_close(void)
{
    dm_api_ctx_t *ctx = _dm_api_get_ctx();

    dm_client_close();
#ifdef ALCS_ENABLED
    dm_server_close();
#endif
    dm_mgr_deinit();
    dm_ipc_deinit();
    dm_msg_deinit();
#if !defined(DM_MESSAGE_CACHE_DISABLED)
    dm_msg_cache_deinit();
#endif
#if defined(OTA_ENABLED) && !defined(BUILD_AOS)
    dm_cota_deinit();
    dm_fota_deinit();
    dm_ota_deinit();
#endif

    if (ctx->mutex) {
        HAL_MutexDestroy(ctx->mutex);
    }
#ifdef LOG_REPORT_TO_CLOUD
    remove_log_poll();
#endif
    return SUCCESS_RETURN;
}

int iotx_dm_yield(int timeout_ms)
{
    if (timeout_ms <= 0) {
        return DM_INVALID_PARAMETER;
    }

    dm_client_yield(timeout_ms);
#ifdef ALCS_ENABLED
    dm_server_yield();
#endif

    return SUCCESS_RETURN;
}

void iotx_dm_dispatch(void)
{
    int count = 0;
    void *data = NULL;
    dm_api_ctx_t *ctx = _dm_api_get_ctx();

#if !defined(DM_MESSAGE_CACHE_DISABLED)
    dm_msg_cache_tick();
#endif
#if defined(OTA_ENABLED) && !defined(BUILD_AOS)
    dm_cota_status_check();
    dm_fota_status_check();
#endif
    while (CONFIG_DISPATCH_QUEUE_MAXLEN == 0 || count++ < CONFIG_DISPATCH_QUEUE_MAXLEN) {
        if (dm_ipc_msg_next(&data) == SUCCESS_RETURN) {
            dm_ipc_msg_t *msg = (dm_ipc_msg_t *)data;

            if (ctx->event_callback) {
                ctx->event_callback(msg->type, msg->data);
            }

            if (msg->data) {
                DM_free(msg->data);
            }
            DM_free(msg);
            data = NULL;
        } else {
            break;
        }
    }
}

int iotx_dm_post_rawdata(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0;

    if (devid < 0 || payload == NULL || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();

    res = dm_mgr_upstream_thing_model_up_raw(devid, payload, payload_len);
    if (res != SUCCESS_RETURN) {
        _dm_api_unlock();
        return FAIL_RETURN;
    }

    _dm_api_unlock();
    return SUCCESS_RETURN;
}

#if !defined(DEVICE_MODEL_RAWDATA_SOLO)
int iotx_dm_set_opt(int opt, void *data)
{
    return dm_opt_set(opt, data);
}

int iotx_dm_get_opt(int opt, void *data)
{
    if (data == NULL) {
        return FAIL_RETURN;
    }

    return dm_opt_get(opt, data);
}

int iotx_dm_post_property(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0;

    _dm_api_lock();

    res = dm_mgr_upstream_thing_property_post(devid, payload, payload_len);
    if (res < SUCCESS_RETURN) {
        _dm_api_unlock();
        return FAIL_RETURN;
    }

    _dm_api_unlock();
    return res;
}

#ifdef DM_UNIFIED_SERVICE_POST
int iotx_dm_unified_service_post(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0;

    _dm_api_lock();

    res = dm_mgr_unified_service_post(devid, payload, payload_len);
    if (res < SUCCESS_RETURN) {
        _dm_api_unlock();
        return FAIL_RETURN;
    }

    _dm_api_unlock();
    return res;
}
#endif

int iotx_dm_event_notify_reply(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0;

    _dm_api_lock();

    res = dm_mgr_upstream_thing_event_notify_reply(devid, payload, payload_len);
    if (res < SUCCESS_RETURN) {
        _dm_api_unlock();
        return FAIL_RETURN;
    }

    _dm_api_unlock();
    return res;
}

#ifdef LOG_REPORT_TO_CLOUD
int iotx_dm_log_post(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0;

    _dm_api_lock();

    res = dm_mgr_upstream_thing_log_post(devid, payload, payload_len, 0);
    if (res < SUCCESS_RETURN) {
        _dm_api_unlock();
        return FAIL_RETURN;
    }

    _dm_api_unlock();
    return res;
}
#endif

int iotx_dm_post_event(_IN_ int devid, _IN_ char *identifier, _IN_ int identifier_len, _IN_ char *payload,
                       _IN_ int payload_len)
{
    int res = 0, method_len = 0;
    const char *method_fmt = "thing.event.%.*s.post";
    char *method = NULL;

    if (devid < 0 || identifier == NULL || identifier_len == 0 || payload == NULL || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();

    method_len = strlen(method_fmt) + strlen(identifier) + 1;
    method = DM_malloc(method_len);
    if (method == NULL) {
        _dm_api_unlock();
        return DM_MEMORY_NOT_ENOUGH;
    }
    memset(method, 0, method_len);
    HAL_Snprintf(method, method_len, method_fmt, identifier_len, identifier);

    res = dm_mgr_upstream_thing_event_post(devid, identifier, identifier_len, method, payload, payload_len);
    if (res < SUCCESS_RETURN) {
        DM_free(method);
        _dm_api_unlock();
        return FAIL_RETURN;
    }

    DM_free(method);
    _dm_api_unlock();
    return res;
}
#ifndef LINK_VISUAL_ENABLE
int iotx_dm_send_service_response(_IN_ int devid, _IN_ char *msgid, _IN_ int msgid_len, _IN_ iotx_dm_error_code_t code,
                                  _IN_ char *identifier,
                                  _IN_ int identifier_len, _IN_ char *payload, _IN_ int payload_len, void *ctx)
{
    int res = 0;

    if (devid < 0 || msgid == NULL || msgid_len <= 0 || identifier == NULL || identifier_len <= 0 || payload == NULL
        || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();

    dm_log_debug("Current Service Response Payload, Length: %d, Payload: %.*s", payload_len, payload_len, payload);

    res = dm_mgr_upstream_thing_service_response(devid, msgid, msgid_len, code, identifier, identifier_len, payload,
            payload_len, ctx);

    _dm_api_unlock();
    return res;
}
#else
int iotx_dm_send_service_response(_IN_ int devid, _IN_ char *msgid, _IN_ int msgid_len, _IN_ iotx_dm_error_code_t code,
                                  _IN_ char *identifier,
                                  _IN_ int identifier_len, _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0;
    if (devid < 0 || msgid == NULL || msgid_len <= 0 || identifier == NULL || identifier_len <= 0 || payload == NULL
        || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }
    _dm_api_lock();
    dm_log_debug("Current Service Response Payload, Length: %d, Payload: %.*s", payload_len, payload_len, payload);
    res = dm_mgr_upstream_thing_service_response(devid, msgid, msgid_len, code, identifier, identifier_len, payload,
            payload_len);
    _dm_api_unlock();
    return res;
}
#endif

int iotx_dm_send_property_get_response(_IN_ int devid, _IN_ char *msgid, _IN_ int msgid_len,
                                       _IN_ iotx_dm_error_code_t code, _IN_ char *payload, _IN_ int payload_len, void *ctx)
{
    int res = 0;

    if (devid < 0 || msgid == NULL || msgid_len <= 0 || payload == NULL || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();

    dm_log_debug("Current Property Get Response Payload, Length: %d, Payload: %.*s", payload_len, payload_len, payload);

    res = dm_mgr_upstream_thing_property_get_response(devid, msgid, msgid_len, code, payload,
            payload_len, ctx);

    _dm_api_unlock();
    return res;
}

int iotx_dm_deviceinfo_update(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0;

    if (devid < 0 || payload == NULL || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();

    res = dm_mgr_upstream_thing_deviceinfo_update(devid, payload, payload_len);
    if (res < SUCCESS_RETURN) {
        _dm_api_unlock();
        return FAIL_RETURN;
    }

    _dm_api_unlock();
    return res;
}

int iotx_dm_deviceinfo_delete(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0;

    if (devid < 0 || payload == NULL || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();

    res = dm_mgr_upstream_thing_deviceinfo_delete(devid, payload, payload_len);
    if (res < SUCCESS_RETURN) {
        _dm_api_unlock();
        return FAIL_RETURN;
    }

    _dm_api_unlock();
    return res;
}

int iotx_dm_qurey_ntp(void)
{
    int res = 0;

    _dm_api_lock();

    res = dm_mgr_upstream_ntp_request();
    if (res < SUCCESS_RETURN) {
        _dm_api_unlock();
        return FAIL_RETURN;
    }

    _dm_api_unlock();
    return res;
}

int iotx_dm_send_aos_active(int devid)
{
    int active_param_len;
    int i;
    char *active_param;
    char aos_active_data[AOS_ACTIVE_INFO_LEN];
    char subdev_aos_verson[VERSION_NUM_SIZE] = {0};
    char subdev_mac_num[MAC_ADDRESS_SIZE] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, ACTIVE_SUBDEV, ACTIVE_LINKKIT_OTHERS};
    char subdev_chip_code[CHIP_CODE_SIZE] = {0x01, 0x02, 0x03, 0x04};
    char random_num[RANDOM_NUM_SIZE];
    const char *fmt =
                "[{\"attrKey\":\"SYS_ALIOS_ACTIVATION\",\"attrValue\":\"%s\",\"domain\":\"SYSTEM\"}]";

    aos_get_version_hex((unsigned char *)subdev_aos_verson);

    HAL_Srandom(HAL_UptimeMs());
    for (i = 0; i < 4; i ++) {
        random_num[i] = (char)HAL_Random(0xFF);
    }
    aos_get_version_info((unsigned char *)subdev_aos_verson, (unsigned char *)random_num, (unsigned char *)subdev_mac_num,
                         (unsigned char *)subdev_chip_code, (unsigned char *)aos_active_data, AOS_ACTIVE_INFO_LEN);
    memcpy(aos_active_data + 40, "1111111111222222222233333333334444444444", 40);

    active_param_len = strlen(fmt) + strlen(aos_active_data) + 1;
    active_param = DM_malloc(active_param_len);
    if (active_param == NULL) {
        return FAIL_RETURN;
    }
    HAL_Snprintf(active_param, active_param_len, fmt, aos_active_data);
    iotx_dm_deviceinfo_update(devid, active_param, active_param_len);
    DM_free(active_param);

    return SUCCESS_RETURN;
}

int iotx_dm_send_rrpc_response(_IN_ int devid, _IN_ char *msgid, _IN_ int msgid_len, _IN_ iotx_dm_error_code_t code,
                               _IN_ char *rrpcid, _IN_ int rrpcid_len, _IN_ char *payload, _IN_ int payload_len)
{
    int res = 0;

    if (devid < 0 || msgid == NULL || msgid_len <= 0 || rrpcid == NULL || rrpcid_len <= 0 || payload == NULL
        || payload_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();

    res = dm_mgr_upstream_rrpc_response(devid, msgid, msgid_len, code, rrpcid, rrpcid_len, payload, payload_len);

    _dm_api_unlock();
    return res;
}
#endif

int iotx_dm_cota_perform_sync(_OU_ char *buffer, _IN_ int buffer_len)
{
#if defined(OTA_ENABLED) && !defined(BUILD_AOS)
    return dm_cota_perform_sync(buffer, buffer_len);
#else
    return -1;
#endif
}

int iotx_dm_cota_get_config(_IN_ const char *config_scope, const char *get_type, const char *attribute_keys)
{
#if defined(OTA_ENABLED) && !defined(BUILD_AOS)
    return dm_cota_get_config(config_scope, get_type, attribute_keys);
#else
    return -1;
#endif
}

int iotx_dm_fota_perform_sync(_OU_ char *buffer, _IN_ int buffer_len)
{
#if defined(OTA_ENABLED) && !defined(BUILD_AOS)
    return dm_fota_perform_sync(buffer, buffer_len);
#else
    return -1;
#endif
}

int iotx_dm_fota_request_image(const char *version, int buffer_len)
{
#if defined(OTA_ENABLED) && !defined(BUILD_AOS)
    return dm_fota_request_image(version, buffer_len);
#else
    return -1;
#endif
}

#ifdef DEVICE_MODEL_GATEWAY
int iotx_dm_query_topo_list(void)
{
    int res = 0;

    _dm_api_lock();

    res = dm_mgr_upstream_thing_topo_get();
    if (res < SUCCESS_RETURN) {
        _dm_api_unlock();
        return FAIL_RETURN;
    }

    _dm_api_unlock();
    return res;
}

#ifdef LINK_VISUAL_ENABLE
int iotx_dm_get_triple_by_devid(_IN_ int devid, _OU_ char **product_key, _OU_ char **device_name, _OU_ char **device_secret)
{
    int res = 0;
    dm_mgr_dev_node_t *search_node = NULL;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();
    res = dm_mgr_search_device_node_by_devid(devid, (void **)&search_node);
    if (res != SUCCESS_RETURN) {
        _dm_api_unlock();
        return FAIL_RETURN;
    }
	if(product_key)
		*product_key = search_node->product_key;
   	
	if(device_name) 
		*device_name = search_node->device_name;
   	
	if(device_secret) 
		*device_secret = search_node->device_secret;
    _dm_api_unlock();
    return res;
}
#endif

int iotx_dm_subdev_query(_IN_ char product_key[IOTX_PRODUCT_KEY_LEN + 1],
                         _IN_ char device_name[IOTX_DEVICE_NAME_LEN + 1],
                         _OU_ int *devid)
{
    int res = 0;

    if (product_key == NULL || device_name == NULL ||
        (strlen(product_key) >= IOTX_PRODUCT_KEY_LEN + 1) ||
        (strlen(device_name) >= IOTX_DEVICE_NAME_LEN + 1) ||
        devid == NULL) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();
    res = dm_mgr_search_device_by_pkdn(product_key, device_name, devid);
    if (res != SUCCESS_RETURN) {
        _dm_api_unlock();
        return FAIL_RETURN;
    }
    _dm_api_unlock();

    return SUCCESS_RETURN;
}

int iotx_dm_subdev_create(_IN_ char product_key[PRODUCT_KEY_MAXLEN], _IN_ char device_name[DEVICE_NAME_MAXLEN],
                          _IN_ char device_secret[DEVICE_SECRET_MAXLEN], _OU_ int *devid)
{
    int res = 0;

    if (product_key == NULL || device_name == NULL ||
        (strlen(product_key) == 0) ||
        (strlen(device_name) == 0) ||
        (strlen(product_key) >= PRODUCT_KEY_MAXLEN) ||
        (strlen(device_name) >= DEVICE_NAME_MAXLEN) ||
        devid == NULL) {
        return DM_INVALID_PARAMETER;
    }

    if (device_secret != NULL && strlen(device_secret) >= DEVICE_SECRET_MAXLEN) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();
    res = dm_mgr_device_create(IOTX_DM_DEVICE_SUBDEV, product_key, device_name, device_secret, devid);
    if (res != SUCCESS_RETURN) {
        _dm_api_unlock();
        return FAIL_RETURN;
    }
    _dm_api_unlock();
    return SUCCESS_RETURN;
}

int iotx_dm_subdev_destroy(_IN_ int devid)
{
    int res = 0;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();
    res = dm_mgr_device_destroy(devid);
    if (res != SUCCESS_RETURN) {
        _dm_api_unlock();
        return FAIL_RETURN;
    }

    _dm_api_unlock();
    return SUCCESS_RETURN;
}

int iotx_dm_subdev_number(void)
{
    int number = 0;

    _dm_api_lock();
    number = dm_mgr_device_number();
    _dm_api_unlock();

    return number;
}

#ifdef DM_SUBDEV_NEW_CONNECT
int iotx_dm_subdev_connect(_IN_ int devid)
{
    int res = 0;
    char *p_subdev_info = NULL;
    int subdev_info_len = 0;
    const char sign_source_fmt[] = "clientId%sdeviceName%sproductKey%stimestamp%s";
    const char subdev_info_fmt[] = "[{\"ProductKey\":\"%s\",\"DeviceName\":\"%s\",\"clientId\":\"%s\",\"timestamp\":\"%s\",\"signMethod\":\"%s\",\"sign\":\"%s\",\"cleanSession\":\"%s\"}]";
    dm_mgr_dev_node_t *search_node = NULL;

    char timestamp[DM_UTILS_UINT64_STRLEN] = {0};
    char client_id[PRODUCT_KEY_MAXLEN + DEVICE_NAME_MAXLEN + 1] = {0};
    char *sign_method = DM_MSG_SIGN_METHOD_HMACSHA1;
    char *sign_source = NULL;
    int sign_source_len = 0;
    char sign[64] = {0};
    char *clean_session = "true";

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();
    res = dm_mgr_search_device_node_by_devid(devid, (void **)&search_node);
    if (res != SUCCESS_RETURN) {
        _dm_api_unlock();
        return FAIL_RETURN;
    }

    if ((strlen(search_node->product_key) <= 0)
        || (strlen(search_node->device_name) <= 0)
        || (strlen(search_node->device_secret) <= 0)) {
        _dm_api_unlock();
        dm_log_err("dev info err");
        return FAIL_RETURN;
    }

    /* TimeStamp */
    HAL_Snprintf(timestamp, DM_UTILS_UINT64_STRLEN, "%llu", HAL_UptimeMs());
    /* dm_log_debug("Time Stamp: %s", timestamp); */

    /* Client ID */
    HAL_Snprintf(client_id, PRODUCT_KEY_MAXLEN + DEVICE_NAME_MAXLEN + 1, "%s.%s", search_node->product_key, search_node->device_name);

    /* Sign */
    sign_source_len = strlen(sign_source_fmt) + strlen(client_id) +
                      strlen(search_node->device_name) + strlen(search_node->product_key) + strlen(timestamp) + 1;
    sign_source = DM_malloc(sign_source_len);
    if (sign_source == NULL) {
        return DM_MEMORY_NOT_ENOUGH;
    }
    memset(sign_source, 0, sign_source_len);
    HAL_Snprintf(sign_source, sign_source_len, sign_source_fmt, client_id,
                 search_node->device_name, search_node->product_key, timestamp);


    utils_hmac_sha1(sign_source, strlen(sign_source), sign, search_node->device_secret, strlen(search_node->device_secret));

    DM_free(sign_source);

    subdev_info_len = strlen(subdev_info_fmt) + strlen(search_node->product_key) + strlen(search_node->device_name) + strlen(sign_method) + strlen(sign) + strlen(timestamp) + strlen(client_id) + strlen(clean_session) + 1;;
    p_subdev_info = DM_malloc(subdev_info_len);
    if (!p_subdev_info) {
        return DM_MEMORY_NOT_ENOUGH;
    }

    memset(p_subdev_info, 0, subdev_info_len);
    HAL_Snprintf(p_subdev_info, subdev_info_len, subdev_info_fmt, search_node->product_key, search_node->device_name, client_id, timestamp, sign_method, sign, clean_session);

    res = dm_mgr_subdev_connect(devid, p_subdev_info, strlen(p_subdev_info));

    DM_free(p_subdev_info);

    _dm_api_unlock();

    return res;
}

int iotx_dm_all_subdev_connect(_IN_ int devid)
{
    int res = 0;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();

    res = dm_mgr_all_subdev_connect(devid);

    _dm_api_unlock();

    return res;
}
#endif

int iotx_dm_subdev_register(_IN_ int devid)
{
    int res = 0;
    dm_mgr_dev_node_t *search_node = NULL;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();
    res = dm_mgr_search_device_node_by_devid(devid, (void **)&search_node);
    if (res != SUCCESS_RETURN) {
        _dm_api_unlock();
        return FAIL_RETURN;
    }

    if ((strlen(search_node->device_secret) > 0) && (strlen(search_node->device_secret) < DEVICE_SECRET_MAXLEN)) {
        _dm_api_unlock();
        return SUCCESS_RETURN;
    }

    res = dm_mgr_upstream_thing_sub_register(devid);

    _dm_api_unlock();
    return res;
}

int iotx_dm_subdev_unregister(_IN_ int devid)
{
    int res = 0;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();

    res = dm_mgr_upstream_thing_sub_unregister(devid);

    _dm_api_unlock();
    return res;
}

int iotx_dm_subdev_topo_add(_IN_ int devid)
{
    int res = 0;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();

    res = dm_mgr_upstream_thing_topo_add(devid);

    _dm_api_unlock();
    return res;
}

int iotx_dm_subdev_topo_del(_IN_ int devid)
{
    int res = 0;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();

    res = dm_mgr_upstream_thing_topo_delete(devid);

    _dm_api_unlock();
    return res;
}

int iotx_dm_subdev_reset(_IN_ int devid)
{
    int res = 0;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();

    res = dm_mgr_upstream_thing_subdev_reset(devid);

    _dm_api_unlock();
    return res;
}

int iotx_dm_subdev_login(_IN_ int devid)
{
    int res = 0;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();

    res = dm_mgr_upstream_combine_login(devid);

    _dm_api_unlock();
    return res;
}

int iotx_dm_subdev_logout(_IN_ int devid)
{
    int res = 0;

    if (devid < 0) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();

    res = dm_mgr_upstream_combine_logout(devid);

    _dm_api_unlock();
    return res;
}

int iotx_dm_get_device_type(_IN_ int devid, _OU_ int *type)
{
    int res = 0;

    if (devid < 0 || type == NULL) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();
    res = dm_mgr_get_dev_type(devid, type);
    if (res != SUCCESS_RETURN) {
        _dm_api_unlock();
        return FAIL_RETURN;
    }

    _dm_api_unlock();
    return SUCCESS_RETURN;
}

int iotx_dm_get_device_avail_status(_IN_ int devid, _OU_ iotx_dm_dev_avail_t *status)
{
    int res = 0;
    char product_key[PRODUCT_KEY_MAXLEN] = {0};
    char device_name[DEVICE_NAME_MAXLEN] = {0};
    char device_secret[DEVICE_SECRET_MAXLEN] = {0};

    if (devid < 0 || status == NULL) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();
    res = dm_mgr_search_device_by_devid(devid, product_key, device_name, device_secret);
    if (res != SUCCESS_RETURN) {
        _dm_api_unlock();
        return FAIL_RETURN;
    }

    res = dm_mgr_get_dev_avail(product_key, device_name, status);
    if (res != SUCCESS_RETURN) {
        _dm_api_unlock();
        return FAIL_RETURN;
    }

    _dm_api_unlock();
    return SUCCESS_RETURN;
}

int iotx_dm_get_device_status(_IN_ int devid, _OU_ iotx_dm_dev_status_t *status)
{
    int res = 0;

    if (devid < 0 || status == NULL) {
        return DM_INVALID_PARAMETER;
    }

    _dm_api_lock();
    res = dm_mgr_get_dev_status(devid, status);
    _dm_api_unlock();

    return res;
}
#endif

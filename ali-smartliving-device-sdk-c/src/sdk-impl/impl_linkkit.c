/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */



#if defined(DEVICE_MODEL_ENABLED)

#include "iot_export_linkkit.h"
#include "sdk-impl_internal.h"
#include "iotx_system.h"
#include "iotx_utils.h"
#include "iotx_dm.h"

#define IMPL_LINKKIT_MALLOC(size) LITE_malloc(size, MEM_MAGIC, "impl.linkkit")
#define IMPL_LINKKIT_FREE(ptr)    LITE_free(ptr)

#define IOTX_LINKKIT_KEY_ID          "id"
#define IOTX_LINKKIT_KEY_CODE        "code"
#define IOTX_LINKKIT_KEY_DEVID       "devid"
#define IOTX_LINKKIT_KEY_SERVICEID   "serviceid"
#define IOTX_LINKKIT_KEY_PROPERTYID  "propertyid"
#define IOTX_LINKKIT_KEY_EVENTID     "eventid"
#define IOTX_LINKKIT_KEY_PAYLOAD     "payload"
#define IOTX_LINKKIT_KEY_CONFIG_ID   "configId"
#define IOTX_LINKKIT_KEY_CONFIG_SIZE "configSize"
#define IOTX_LINKKIT_KEY_GET_TYPE    "getType"
#define IOTX_LINKKIT_KEY_SIGN        "sign"
#define IOTX_LINKKIT_KEY_SIGN_METHOD "signMethod"
#define IOTX_LINKKIT_KEY_URL         "url"
#define IOTX_LINKKIT_KEY_VERSION     "version"
#define IOTX_LINKKIT_KEY_UTC         "utc"
#define IOTX_LINKKIT_KEY_RRPCID      "rrpcid"
#define IOTX_LINKKIT_KEY_CTX         "ctx"
#define IOTX_LINKKIT_KEY_TOPO        "topo"
#define IOTX_LINKKIT_KEY_PRODUCT_KEY "productKey"
#define IOTX_LINKKIT_KEY_TIME        "time"
#define IOTX_LINKKIT_KEY_DATA        "data"
#define IOTX_LINKKIT_KEY_MESSAGE     "message"


#define IOTX_LINKKIT_SYNC_DEFAULT_TIMEOUT_MS 10000

typedef struct {
    int msgid;
    void *semaphore;
    int code;
    struct list_head linked_list;
} iotx_linkkit_upstream_sync_callback_node_t;

typedef struct {
    void *mutex;
    void *upstream_mutex;
    int is_opened;
    int is_connected;
    int cloud_redirect;
    struct list_head upstream_sync_callback_list;
} iotx_linkkit_ctx_t;

static iotx_linkkit_ctx_t g_iotx_linkkit_ctx = {0};
static int _awss_reported = 0;

static iotx_linkkit_ctx_t *_iotx_linkkit_get_ctx(void)
{
    return &g_iotx_linkkit_ctx;
}

static void _iotx_linkkit_mutex_lock(void)
{
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();
    if (ctx->mutex) {
        HAL_MutexLock(ctx->mutex);
    }
}

static void _iotx_linkkit_mutex_unlock(void)
{
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();
    if (ctx->mutex) {
        HAL_MutexUnlock(ctx->mutex);
    }
}

static int _impl_copy(_IN_ void *input, _IN_ int input_len, _OU_ void **output, _IN_ int output_len)
{
    if (input == NULL || output == NULL || *output != NULL) {
        return DM_INVALID_PARAMETER;
    }

    *output = sdk_malloc(output_len);
    if (*output == NULL) {
        return DM_MEMORY_NOT_ENOUGH;
    }
    memset(*output, 0, output_len);
    memcpy(*output, input, input_len);

    return SUCCESS_RETURN;
}

#ifdef DEVICE_MODEL_GATEWAY
static void _iotx_linkkit_upstream_mutex_lock(void)
{
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();
    if (ctx->upstream_mutex) {
        HAL_MutexLock(ctx->upstream_mutex);
    }
}

static void _iotx_linkkit_upstream_mutex_unlock(void)
{
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();
    if (ctx->upstream_mutex) {
        HAL_MutexUnlock(ctx->upstream_mutex);
    }
}


static int _iotx_linkkit_upstream_sync_callback_list_insert(int msgid, void *semaphore,
        iotx_linkkit_upstream_sync_callback_node_t **node)
{
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();
    iotx_linkkit_upstream_sync_callback_node_t *search_node = NULL;

    list_for_each_entry(search_node, &ctx->upstream_sync_callback_list, linked_list,
                        iotx_linkkit_upstream_sync_callback_node_t) {
        if (search_node->msgid == msgid) {
            sdk_debug("Message Already Exist: %d", msgid);
            return FAIL_RETURN;
        }
    }

    search_node = IMPL_LINKKIT_MALLOC(sizeof(iotx_linkkit_upstream_sync_callback_node_t));
    if (search_node == NULL) {
        sdk_debug("malloc error");
        return FAIL_RETURN;
    }
    memset(search_node, 0, sizeof(iotx_linkkit_upstream_sync_callback_node_t));
    search_node->msgid = msgid;
    search_node->semaphore = semaphore;
    INIT_LIST_HEAD(&search_node->linked_list);

    list_add(&search_node->linked_list, &ctx->upstream_sync_callback_list);
    sdk_debug("New Message, msgid: %d", msgid);

    *node = search_node;
    return SUCCESS_RETURN;
}

static int _iotx_linkkit_upstream_sync_callback_list_remove(int msgid)
{
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();
    iotx_linkkit_upstream_sync_callback_node_t *search_node = NULL;

    list_for_each_entry(search_node, &ctx->upstream_sync_callback_list, linked_list,
                        iotx_linkkit_upstream_sync_callback_node_t) {
        if (search_node->msgid == msgid) {
            sdk_debug("Message Found: %d, Delete It", msgid);
            HAL_SemaphoreDestroy(search_node->semaphore);
            list_del(&search_node->linked_list);
            IMPL_LINKKIT_FREE(search_node);
            return SUCCESS_RETURN;
        }
    }

    return FAIL_RETURN;
}

static int _iotx_linkkit_upstream_sync_callback_list_search(int msgid,
        iotx_linkkit_upstream_sync_callback_node_t **node)
{
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();
    iotx_linkkit_upstream_sync_callback_node_t *search_node = NULL;

    if (node == NULL || *node != NULL) {
        sdk_debug("invalid param");
        return FAIL_RETURN;
    }

    list_for_each_entry(search_node, &ctx->upstream_sync_callback_list, linked_list,
                        iotx_linkkit_upstream_sync_callback_node_t) {
        if (search_node->msgid == msgid) {
            sdk_debug("Sync Message Found: %d", msgid);
            *node = search_node;
            return SUCCESS_RETURN;
        }
    }

    return FAIL_RETURN;
}

static void _iotx_linkkit_upstream_sync_callback_list_destroy(void)
{
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();
    iotx_linkkit_upstream_sync_callback_node_t *search_node = NULL, *next_node = NULL;

    list_for_each_entry_safe(search_node, next_node, &ctx->upstream_sync_callback_list, linked_list,
                             iotx_linkkit_upstream_sync_callback_node_t) {
        list_del(&search_node->linked_list);
        HAL_SemaphoreDestroy(search_node->semaphore);
        IMPL_LINKKIT_FREE(search_node);
    }
}


static void _iotx_linkkit_upstream_callback_remove(int msgid, int code)
{
    int res = 0;
    iotx_linkkit_upstream_sync_callback_node_t *sync_node = NULL;
    res = _iotx_linkkit_upstream_sync_callback_list_search(msgid, &sync_node);
    if (res == SUCCESS_RETURN) {
        sync_node->code = (code == IOTX_DM_ERR_CODE_SUCCESS) ? (SUCCESS_RETURN) : (FAIL_RETURN);
        sdk_debug("Sync Message %d Result: %d", msgid, sync_node->code);
        HAL_SemaphorePost(sync_node->semaphore);
    }
}
#endif

#ifdef LOG_REPORT_TO_CLOUD
    int  report_sample = 0;
#endif
#ifdef ALCS_ENABLED
    extern void dm_server_free_context(_IN_ void *ctx);
#endif
static void _iotx_linkkit_event_callback(iotx_dm_event_types_t type, char *payload)
{
    int res = 0;
    void *callback;
#ifdef LOG_REPORT_TO_CLOUD
    lite_cjson_t msg_id;
#endif
    lite_cjson_t lite, lite_item_id, lite_item_devid, lite_item_serviceid, lite_item_payload, lite_item_ctx;
    lite_cjson_t lite_item_code, lite_item_eventid, lite_item_utc, lite_item_rrpcid, lite_item_topo;
    lite_cjson_t lite_item_pk, lite_item_time;
    lite_cjson_t lite_item_version, lite_item_configid, lite_item_configsize, lite_item_gettype, lite_item_sign,
                 lite_item_signmethod, lite_item_url, lite_item_data, lite_item_message;

    sdk_info("Receive Message Type: %d", type);
    if (payload) {
        sdk_info("Receive Message: %s", payload);
        res = dm_utils_json_parse(payload, strlen(payload), cJSON_Invalid, &lite);
        if (res != SUCCESS_RETURN) {
            return;
        }
#ifdef LOG_REPORT_TO_CLOUD
        dm_utils_json_object_item(&lite, "msgid", 5, cJSON_Invalid, &msg_id);
#endif
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_ID, strlen(IOTX_LINKKIT_KEY_ID), cJSON_Invalid, &lite_item_id);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_DEVID, strlen(IOTX_LINKKIT_KEY_DEVID), cJSON_Invalid,
                                  &lite_item_devid);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_SERVICEID, strlen(IOTX_LINKKIT_KEY_SERVICEID), cJSON_Invalid,
                                  &lite_item_serviceid);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_PAYLOAD, strlen(IOTX_LINKKIT_KEY_PAYLOAD), cJSON_Invalid,
                                  &lite_item_payload);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_CTX, strlen(IOTX_LINKKIT_KEY_CTX), cJSON_Invalid, &lite_item_ctx);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_CODE, strlen(IOTX_LINKKIT_KEY_CODE), cJSON_Invalid, &lite_item_code);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_EVENTID, strlen(IOTX_LINKKIT_KEY_EVENTID), cJSON_Invalid,
                                  &lite_item_eventid);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_UTC, strlen(IOTX_LINKKIT_KEY_UTC), cJSON_Invalid, &lite_item_utc);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_RRPCID, strlen(IOTX_LINKKIT_KEY_RRPCID), cJSON_Invalid,
                                  &lite_item_rrpcid);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_TOPO, strlen(IOTX_LINKKIT_KEY_TOPO), cJSON_Invalid,
                                  &lite_item_topo);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_PRODUCT_KEY, strlen(IOTX_LINKKIT_KEY_PRODUCT_KEY), cJSON_Invalid,
                                  &lite_item_pk);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_TIME, strlen(IOTX_LINKKIT_KEY_TIME), cJSON_Invalid,
                                  &lite_item_time);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_VERSION, strlen(IOTX_LINKKIT_KEY_VERSION), cJSON_Invalid,
                                  &lite_item_version);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_CONFIG_ID, strlen(IOTX_LINKKIT_KEY_CONFIG_ID), cJSON_Invalid,
                                  &lite_item_configid);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_CONFIG_SIZE, strlen(IOTX_LINKKIT_KEY_CONFIG_SIZE), cJSON_Invalid,
                                  &lite_item_configsize);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_GET_TYPE, strlen(IOTX_LINKKIT_KEY_GET_TYPE), cJSON_Invalid,
                                  &lite_item_gettype);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_SIGN, strlen(IOTX_LINKKIT_KEY_SIGN), cJSON_Invalid,
                                  &lite_item_sign);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_SIGN_METHOD, strlen(IOTX_LINKKIT_KEY_SIGN_METHOD), cJSON_Invalid,
                                  &lite_item_signmethod);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_URL, strlen(IOTX_LINKKIT_KEY_URL), cJSON_Invalid,
                                  &lite_item_url);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_DATA, strlen(IOTX_LINKKIT_KEY_DATA), cJSON_Invalid,
                                  &lite_item_data);
        dm_utils_json_object_item(&lite, IOTX_LINKKIT_KEY_MESSAGE, strlen(IOTX_LINKKIT_KEY_MESSAGE), cJSON_Invalid,
                                  &lite_item_message);
    }

    switch (type) {
        case IOTX_DM_EVENT_CLOUD_CONNECTED: {
#ifdef DEV_BIND_ENABLED
            if (_awss_reported == 0)
            {
                awss_report_cloud();
                _awss_reported = 1;
            }
#endif
            callback = iotx_event_callback(ITE_CONNECT_SUCC);
            if (callback) {
                ((int (*)(void))callback)();
            }
        }
        break;
        case IOTX_DM_EVENT_CLOUD_DISCONNECT: {
            callback = iotx_event_callback(ITE_DISCONNECTED);
            if (callback) {
                ((int (*)(void))callback)();
            }
        }
        break;
        case IOTX_DM_EVENT_INITIALIZED: {
            if (payload == NULL || lite_item_devid.type != cJSON_Number) {
                return;
            }

            sdk_debug("Current Devid: %d", lite_item_devid.value_int);

            callback = iotx_event_callback(ITE_INITIALIZE_COMPLETED);
            if (callback) {
                ((int (*)(const int))callback)(lite_item_devid.value_int);
            }
        }
        break;
        case IOTX_DM_EVENT_MODEL_DOWN_RAW: {
            int raw_data_len = 0;
            unsigned char *raw_data = NULL;

            if (payload == NULL || lite_item_devid.type != cJSON_Number || lite_item_payload.type != cJSON_String) {
                return;
            }

            sdk_debug("Current Devid: %d", lite_item_devid.value_int);
            sdk_debug("Current Raw Data: %.*s", lite_item_payload.value_length, lite_item_payload.value);

            raw_data_len = lite_item_payload.value_length / 2;
            raw_data = IMPL_LINKKIT_MALLOC(raw_data_len);
            if (raw_data == NULL) {
                sdk_err("No Enough Memory");
                return;
            }
            LITE_hexstr_convert(lite_item_payload.value, lite_item_payload.value_length, raw_data, raw_data_len);

            HEXDUMP_DEBUG(raw_data, raw_data_len);

            callback = iotx_event_callback(ITE_RAWDATA_ARRIVED);
            if (callback) {
                ((int (*)(const int, const unsigned char *, const int))callback)(lite_item_devid.value_int, raw_data, raw_data_len);
            }

            IMPL_LINKKIT_FREE(raw_data);
        }
        break;
#ifdef LINK_VISUAL_ENABLE
        case IOTX_DM_EVENT_MODEL_LINK_VISUAL: {
            if (payload == NULL || lite_item_devid.type != cJSON_Number || lite_item_payload.type != cJSON_Object ||
                lite_item_serviceid.type != cJSON_String) {
                return;
            }

            sdk_debug("Current Id: %.*s", lite_item_id.value_length, lite_item_id.value);
            sdk_debug("Current ServiceID: %.*s", lite_item_serviceid.value_length, lite_item_serviceid.value);
            sdk_debug("Current Devid: %d", lite_item_devid.value_int);
            sdk_debug("Current Raw Data: %.*s", lite_item_payload.value_length, lite_item_payload.value);
            unsigned char *request = IMPL_LINKKIT_MALLOC(lite_item_payload.value_length + 1);
            if (request == NULL) {
                sdk_err("Not Enough Memory");
                return;
            }
            memset(request, 0, lite_item_payload.value_length + 1);
            memcpy(request, lite_item_payload.value, lite_item_payload.value_length);
            callback = iotx_event_callback(ITE_LINK_VISUAL);
            if (callback) {
                ((int (*)(const int, const char *, const int, const unsigned char *, const int))callback)(lite_item_devid.value_int, lite_item_serviceid.value, lite_item_serviceid.value_length,request, lite_item_payload.value_length);
            }
            IMPL_LINKKIT_FREE(request);
        }
        break;
#endif
        case IOTX_DM_EVENT_MODEL_UP_RAW_REPLY: {
            int raw_data_len = 0;
            unsigned char *raw_data = NULL;

            if (payload == NULL || lite_item_devid.type != cJSON_Number || lite_item_payload.type != cJSON_String) {
                return;
            }

            sdk_debug("Current Devid: %d", lite_item_devid.value_int);
            sdk_debug("Current Raw Data: %.*s", lite_item_payload.value_length, lite_item_payload.value);

            raw_data_len = lite_item_payload.value_length / 2;
            raw_data = IMPL_LINKKIT_MALLOC(raw_data_len);
            if (raw_data == NULL) {
                sdk_err("No Enough Memory");
                return;
            }
            memset(raw_data, 0, raw_data_len);
            LITE_hexstr_convert(lite_item_payload.value, lite_item_payload.value_length, raw_data, raw_data_len);

            HEXDUMP_DEBUG(raw_data, raw_data_len);

            callback = iotx_event_callback(ITE_RAWDATA_ARRIVED);
            if (callback) {
                ((int (*)(const int, const unsigned char *, const int))callback)(lite_item_devid.value_int, raw_data, raw_data_len);
            }

            IMPL_LINKKIT_FREE(raw_data);
        }
        break;
#if !defined(DEVICE_MODEL_RAWDATA_SOLO)
        case IOTX_DM_EVENT_THING_SERVICE_REQUEST: {
            int response_len = 0;
            char *request = NULL, *response = NULL;

            uintptr_t property_get_ctx_num = 0;
            void *property_get_ctx = NULL;

            if (payload == NULL || lite_item_id.type != cJSON_String || lite_item_devid.type != cJSON_Number ||
                lite_item_serviceid.type != cJSON_String || lite_item_payload.type != cJSON_Object) {
                return;
            }

            sdk_err("Current Id: %.*s", lite_item_id.value_length, lite_item_id.value);
            sdk_debug("Current Devid: %d", lite_item_devid.value_int);
            sdk_debug("Current ServiceID: %.*s", lite_item_serviceid.value_length, lite_item_serviceid.value);
            sdk_debug("Current Payload: %.*s", lite_item_payload.value_length, lite_item_payload.value);
            sdk_debug("Current Ctx: %.*s", lite_item_ctx.value_length, lite_item_ctx.value);

            LITE_hexstr_convert(lite_item_ctx.value, lite_item_ctx.value_length, (unsigned char *)&property_get_ctx_num,
                                sizeof(uintptr_t));
            property_get_ctx = (void *)property_get_ctx_num;
            // sdk_debug("property_get_ctx_num: %0x016llX", property_get_ctx_num);
            // sdk_debug("property_get_ctx: %p", property_get_ctx);

            request = IMPL_LINKKIT_MALLOC(lite_item_payload.value_length + 1);
            if (request == NULL) {
                sdk_err("Not Enough Memory");
                return;
            }
            memset(request, 0, lite_item_payload.value_length + 1);
            memcpy(request, lite_item_payload.value, lite_item_payload.value_length);
#ifndef LINK_VISUAL_ENABLE
            callback = iotx_event_callback(ITE_SERVICE_REQUEST);
            if (callback) {
                res = ((int (*)(const int, const char *, const int, const char *, const int, char **,
                                int *))callback)(lite_item_devid.value_int, lite_item_serviceid.value,
                                                 lite_item_serviceid.value_length, request, lite_item_payload.value_length, &response, &response_len);
                if (response != NULL && response_len > 0) {
                    /* service response exist */
                    iotx_dm_error_code_t code = (res == 0) ? (IOTX_DM_ERR_CODE_SUCCESS) : (IOTX_DM_ERR_CODE_REQUEST_ERROR);
                    iotx_dm_send_service_response(lite_item_devid.value_int, lite_item_id.value, lite_item_id.value_length, code,
                                                  lite_item_serviceid.value,
                                                  lite_item_serviceid.value_length,
                                                  response, response_len, property_get_ctx);
                    HAL_Free(response);
                }
            }
#else
            callback = iotx_event_callback(ITE_SERVICE_REQUST);
            if (callback) {
                res = ((int (*)(const int, const char *, const int, const char *, const int, const char *, const int, char **,
                int *))callback)(lite_item_devid.value_int, lite_item_id.value, lite_item_id.value_length, lite_item_serviceid.value,
                                 lite_item_serviceid.value_length, request, lite_item_payload.value_length, &response, &response_len);
                if (response != NULL && response_len > 0) {
                    iotx_dm_error_code_t code = (res == 0) ? (IOTX_DM_ERR_CODE_SUCCESS) : (IOTX_DM_ERR_CODE_REQUEST_ERROR);
                    iotx_dm_send_service_response(lite_item_devid.value_int, lite_item_id.value, lite_item_id.value_length, code,
                                                  lite_item_serviceid.value,
                                                  lite_item_serviceid.value_length,
                                                  response, response_len);
                    IMPL_LINKKIT_FREE(response);
                }
            }
#endif
#ifdef ALCS_ENABLED
            if (property_get_ctx) {
                dm_server_free_context(property_get_ctx);
            }
#endif
            IMPL_LINKKIT_FREE(request);
        }
        break;
        case IOTX_DM_EVENT_THING_EVENT_NOTIFY: {
            char *property_payload = NULL;
            lite_cjson_t lite_identifier, lite_iden_val;

            if (payload == NULL || lite_item_devid.type != cJSON_Number || lite_item_payload.type != cJSON_Object) {
                return;
            }

            sdk_debug("Current Devid: %d", lite_item_devid.value_int);
            sdk_debug("Current Payload: %.*s", lite_item_payload.value_length, lite_item_payload.value);

            property_payload = IMPL_LINKKIT_MALLOC(lite_item_payload.value_length + 1);
            if (property_payload == NULL) {
                sdk_err("No Enough Memory");
                return;
            }

            dm_utils_json_object_item(&lite_item_payload, "identifier", strlen("identifier"), cJSON_Invalid,
                                  &lite_identifier);
            dm_utils_json_object_item(&lite_item_payload, "value", strlen("value"), cJSON_Invalid,
                                  &lite_iden_val);

#ifdef LOG_REPORT_TO_CLOUD
            if (SUCCESS_RETURN == check_target_msg(msg_id.value, msg_id.value_length)) {
                report_sample = 1;
                send_permance_info(msg_id.value, msg_id.value_length, "3", 1);
            }
#endif

            memset(property_payload, 0, lite_item_payload.value_length + 1);
            memcpy(property_payload, lite_item_payload.value, lite_item_payload.value_length);
#ifdef ALCS_GROUP_COMM_ENABLE
            #ifdef DM_UNIFIED_SERVICE_POST
            if ( NULL != strstr(property_payload, "_LivingLink.alcs.localgroup") ){
                iotx_alcs_localgroup_rsp(property_payload, lite_item_payload.value, 2);
                IMPL_LINKKIT_FREE(property_payload);
                return;
            }
            #endif
#endif
#if defined(AWSS_BATCH_DEVAP_ENABLE) && defined(AWSS_SUPPORT_ZEROCONFIG) && !defined(AWSS_DISABLE_REGISTRAR)
            // Find "awss.modeswitch" identifier and do awss mode switch or not.
            //sdk_debug("identifier: %.*s", lite_identifier.value_length, lite_identifier.value);
            if ( (lite_identifier.type == cJSON_String)
                && !strncmp(lite_identifier.value, "awss.modeswitch", strlen("awss.modeswitch"))
                && lite_iden_val.type == cJSON_Object ) {
                lite_cjson_t lite_awss_mode, lite_mode_pk;
                uint8_t tomode = 0xFF;
                uint8_t pk_found = 0;

                //sdk_debug("awss.modeswitch found, value(%.*s)", lite_iden_val.value_length, lite_iden_val.value);
                dm_utils_json_object_item(&lite_iden_val, "mode", strlen("mode"), cJSON_Invalid,
                                  &lite_awss_mode);
                dm_utils_json_object_item(&lite_iden_val, "productKey", strlen("productKey"), cJSON_Invalid,
                                  &lite_mode_pk);
                // Parse switch mode and product Key from awss.modeswitch payload
                if (lite_awss_mode.type == cJSON_String) {
                    if (!strncmp(lite_awss_mode.value, "0", strlen("0"))) {
                        // tomode: 0 - switch to zero config
                        tomode = 0;
                        sdk_debug("mode found(%d))", tomode);
                    } else {
                        sdk_err("awss.modeswitch mode not support");
                        // invalid mode switch, should be ignored
                        tomode = 0xFF;
                    }
                }
                if ( (lite_mode_pk.type == cJSON_String) && (lite_mode_pk.value_length > 0) ) {
                    pk_found = 1;
                    sdk_debug("mode pk found");
                }
                // Do awss mode switch action based on command parsed from cloud
                if (tomode != 0xFF) {
                    extern void registrar_switchmode_start(char *p_productkey, int pk_len, uint8_t awss_mode);
                    registrar_switchmode_start(pk_found ? lite_mode_pk.value : NULL, lite_mode_pk.value_length, tomode);
                }
            }
#endif

            if (!strncmp(lite_identifier.value, "_LivingLink.thing.reset.reply", strlen("_LivingLink.thing.reset.reply")))
            {
                sdk_info("got cloud reset done");
                awss_handle_reset_cloud_reply();
            }

            callback = iotx_event_callback(ITE_EVENT_NOTIFY);
            if (callback) {
                ((int (*)(const int, const char *, const int))callback)(lite_item_devid.value_int, property_payload,
                        lite_item_payload.value_length);
            }
#ifdef LOG_REPORT_TO_CLOUD
            if (1 == report_sample) {
                send_permance_info(NULL, 0, "5", 2);
                report_sample = 0;
            }
#endif

            IMPL_LINKKIT_FREE(property_payload);
        }
        break;
        case IOTX_DM_EVENT_PROPERTY_SET: {
            char *property_payload = NULL;

            if (payload == NULL || lite_item_devid.type != cJSON_Number || lite_item_payload.type != cJSON_Object) {
                return;
            }

            sdk_debug("Current Devid: %d", lite_item_devid.value_int);
            sdk_debug("Current Payload: %.*s", lite_item_payload.value_length, lite_item_payload.value);

            property_payload = IMPL_LINKKIT_MALLOC(lite_item_payload.value_length + 1);
            if (property_payload == NULL) {
                sdk_err("No Enough Memory");
                return;
            }
#ifdef LOG_REPORT_TO_CLOUD
            if (SUCCESS_RETURN == check_target_msg(msg_id.value, msg_id.value_length)) {
                report_sample = 1;
                send_permance_info(msg_id.value, msg_id.value_length, "3", 1);
            }
#endif

            memset(property_payload, 0, lite_item_payload.value_length + 1);
            memcpy(property_payload, lite_item_payload.value, lite_item_payload.value_length);
            callback = iotx_event_callback(ITE_PROPERTY_SET);
            if (callback) {
                ((int (*)(const int, const char *, const int))callback)(lite_item_devid.value_int, property_payload,
                        lite_item_payload.value_length);
            }
#ifdef LOG_REPORT_TO_CLOUD
            if (1 == report_sample) {
                send_permance_info(NULL, 0, "5", 2);
                report_sample = 0;
            }
#endif

            IMPL_LINKKIT_FREE(property_payload);
        }
        break;
        case IOTX_DM_EVENT_PROPERTY_GET: {
            int response_len = 0;
            char *request = NULL, *response = NULL;
            uintptr_t property_get_ctx_num = 0;
            void *property_get_ctx = NULL;

            if (payload == NULL || lite_item_id.type != cJSON_String || lite_item_devid.type != cJSON_Number ||
                lite_item_payload.type != cJSON_Array || lite_item_ctx.type != cJSON_String) {
                return;
            }

            sdk_debug("Current Id: %.*s", lite_item_id.value_length, lite_item_id.value);
            sdk_debug("Current Devid: %d", lite_item_devid.value_int);
            sdk_debug("Current Payload: %.*s", lite_item_payload.value_length, lite_item_payload.value);
            sdk_debug("Current Ctx: %.*s", lite_item_ctx.value_length, lite_item_ctx.value);

            LITE_hexstr_convert(lite_item_ctx.value, lite_item_ctx.value_length, (unsigned char *)&property_get_ctx_num,
                                sizeof(uintptr_t));
            property_get_ctx = (void *)property_get_ctx_num;
            sdk_debug("property_get_ctx_num: %0x016llX", property_get_ctx_num);
            sdk_debug("property_get_ctx: %p", property_get_ctx);

            request = IMPL_LINKKIT_MALLOC(lite_item_payload.value_length + 1);
            if (request == NULL) {
                sdk_err("No Enough Memory");
                return;
            }
            memset(request, 0, lite_item_payload.value_length + 1);
            memcpy(request, lite_item_payload.value, lite_item_payload.value_length);

            callback = iotx_event_callback(ITE_PROPERTY_GET);
            if (callback) {
                res = ((int (*)(const int, const char *, const int, char **, int *))callback)(lite_item_devid.value_int, request,
                        lite_item_payload.value_length, &response, &response_len);

                if (response != NULL && response_len > 0) {
                    /* property get response exist */
                    iotx_dm_error_code_t code = (res == 0) ? (IOTX_DM_ERR_CODE_SUCCESS) : (IOTX_DM_ERR_CODE_REQUEST_ERROR);
                    iotx_dm_send_property_get_response(lite_item_devid.value_int, lite_item_id.value, lite_item_id.value_length, code,
                                                       response, response_len, property_get_ctx);
                    HAL_Free(response);
                }
            }

            IMPL_LINKKIT_FREE(request);
        }
        break;
        case IOTX_DM_EVENT_EVENT_PROPERTY_POST_REPLY:
        case IOTX_DM_EVENT_DEVICEINFO_UPDATE_REPLY:
        case IOTX_DM_EVENT_DEVICEINFO_DELETE_REPLY: {
            char *user_payload = NULL;
            int user_payload_length = 0;

            if (payload == NULL || lite_item_id.type != cJSON_Number || lite_item_code.type != cJSON_Number
                || lite_item_devid.type != cJSON_Number) {
                return;
            }

            sdk_debug("Current Id: %d", lite_item_id.value_int);
            sdk_debug("Current Code: %d", lite_item_code.value_int);
            sdk_debug("Current Devid: %d", lite_item_devid.value_int);

            if (lite_item_payload.type == cJSON_Object && lite_item_payload.value_length > 0) {
                user_payload = IMPL_LINKKIT_MALLOC(lite_item_payload.value_length + 1);
                if (user_payload == NULL) {
                    sdk_err("No Enough Memory");
                    return;
                }
                memset(user_payload, 0, lite_item_payload.value_length + 1);
                memcpy(user_payload, lite_item_payload.value, lite_item_payload.value_length);
                user_payload_length = lite_item_payload.value_length;
            }

            callback = iotx_event_callback(ITE_REPORT_REPLY);
            if (callback) {
                ((int (*)(const int, const int, const int, const char *, const int))callback)(lite_item_devid.value_int,
                        lite_item_id.value_int, lite_item_code.value_int, user_payload,
                        user_payload_length);
            }

            if (user_payload) {
                IMPL_LINKKIT_FREE(user_payload);
            }
        }
        break;
        case IOTX_DM_EVENT_EVENT_SPECIFIC_POST_REPLY: {
            char *user_eventid = NULL;
            char *user_payload = NULL;

            if (payload == NULL || lite_item_id.type != cJSON_Number || lite_item_code.type != cJSON_Number ||
                lite_item_devid.type != cJSON_Number || lite_item_eventid.type != cJSON_String
                || lite_item_payload.type != cJSON_String) {
                return;
            }

            sdk_debug("Current Id: %d", lite_item_id.value_int);
            sdk_debug("Current Code: %d", lite_item_code.value_int);
            sdk_debug("Current Devid: %d", lite_item_devid.value_int);
            sdk_debug("Current EventID: %.*s", lite_item_eventid.value_length, lite_item_eventid.value);
            sdk_debug("Current Message: %.*s", lite_item_payload.value_length, lite_item_payload.value);

            user_eventid = IMPL_LINKKIT_MALLOC(lite_item_eventid.value_length + 1);
            if (user_eventid == NULL) {
                sdk_err("Not Enough Memory");
                return;
            }
            memset(user_eventid, 0, lite_item_eventid.value_length + 1);
            memcpy(user_eventid, lite_item_eventid.value, lite_item_eventid.value_length);

            user_payload = IMPL_LINKKIT_MALLOC(lite_item_payload.value_length + 1);
            if (user_payload == NULL) {
                sdk_err("Not Enough Memory");
                IMPL_LINKKIT_FREE(user_eventid);
                return;
            }
            memset(user_payload, 0, lite_item_payload.value_length + 1);
            memcpy(user_payload, lite_item_payload.value, lite_item_payload.value_length);


            callback = iotx_event_callback(ITE_TRIGGER_EVENT_REPLY);
            if (callback) {
                ((int (*)(const int, const int, const int, const char *, const int, const char *,
                          const int))callback)(lite_item_devid.value_int,
                                               lite_item_id.value_int, lite_item_code.value_int,
                                               user_eventid, lite_item_eventid.value_length, user_payload, lite_item_payload.value_length);
            }

            IMPL_LINKKIT_FREE(user_eventid);
            IMPL_LINKKIT_FREE(user_payload);
        }
        break;
#ifdef DM_UNIFIED_SERVICE_POST
        case IOTX_DM_UNIFIED_SERVICE_POST_REPLY:{
            char *user_payload = NULL;
            char is_need_callback = 1;

            if (payload == NULL || lite_item_id.type != cJSON_Number || lite_item_code.type != cJSON_Number ||
                lite_item_devid.type != cJSON_Number || lite_item_payload.type != cJSON_Object) {
                return;
            }

            sdk_debug("Current Id: %d", lite_item_id.value_int);
            sdk_debug("Current Code: %d", lite_item_code.value_int);
            sdk_debug("Current Devid: %d", lite_item_devid.value_int);
            sdk_debug("Current Message: %.*s", lite_item_payload.value_length, lite_item_payload.value);

            user_payload = IMPL_LINKKIT_MALLOC(lite_item_payload.value_length + 1);
            if (user_payload == NULL) {
                sdk_err("No mem");
                return;
            }
            memset(user_payload, 0, lite_item_payload.value_length + 1);
            memcpy(user_payload, lite_item_payload.value, lite_item_payload.value_length);


            if (lite_item_code.value_int == 200) {
                lite_cjson_t lite_identifier;
                dm_utils_json_object_item(&lite_item_payload, "identifier", strlen("identifier"), cJSON_String,
                                    &lite_identifier);
#ifdef DEVICE_MODEL_GATEWAY
                if ((lite_identifier.type == cJSON_String) &&
                     !strncmp(lite_identifier.value, "_LivingLink.activation.subdevice.connect", strlen("_LivingLink.activation.subdevice.connect")))
                {
                    lite_cjson_t lite_serviceResult;
                    lite_cjson_t lite_DeviceList;
                    dm_utils_json_object_item(&lite_item_payload, "serviceResult", strlen("serviceResult"), cJSON_Object,
                                        &lite_serviceResult);

                    dm_utils_json_object_item(&lite_serviceResult, "DeviceList", strlen("DeviceList"), cJSON_Array,
                                        &lite_DeviceList);

                    char *device_list = IMPL_LINKKIT_MALLOC(lite_DeviceList.value_length + 1);
                    if (device_list == NULL) {
                        sdk_err("No mem");
                        IMPL_LINKKIT_FREE(user_payload);
                        return;
                    }
                    memset(device_list, 0, lite_DeviceList.value_length + 1);
                    memcpy(device_list, lite_DeviceList.value, lite_DeviceList.value_length);
                    iotx_dm_subdev_connect_reply(lite_item_id.value_int, device_list, lite_DeviceList.value_length);
                    IMPL_LINKKIT_FREE(device_list);

                    _iotx_linkkit_upstream_mutex_lock();
                    _iotx_linkkit_upstream_callback_remove(lite_item_id.value_int, lite_item_code.value_int);
                    _iotx_linkkit_upstream_mutex_unlock();
                }

                is_need_callback = 0;
#endif
            }

            #ifdef ALCS_GROUP_COMM_ENABLE
            if ( NULL != strstr(user_payload, "_LivingLink.alcs.localgroup") ){
                iotx_alcs_localgroup_rsp(user_payload, lite_item_payload.value, 1);
                is_need_callback = 0;
            }
            #endif
            if (is_need_callback) {
                callback = iotx_event_callback(ITE_UNIFIED_SERVICE_POST);
                if (callback) {
                    ((int (*)(const int, const int, const int, const char *, const int))callback)(lite_item_devid.value_int,
                    lite_item_id.value_int, lite_item_code.value_int, user_payload, lite_item_payload.value_length);
                }
            }

            IMPL_LINKKIT_FREE(user_payload);
        }break;
#endif
        case IOTX_DM_EVENT_NTP_RESPONSE: {
            char *utc_payload = NULL;

            if (payload == NULL || lite_item_utc.type != cJSON_String) {
                return;
            }

            sdk_debug("Current UTC: %.*s", lite_item_utc.value_length, lite_item_utc.value);

            utc_payload = IMPL_LINKKIT_MALLOC(lite_item_utc.value_length + 1);
            if (utc_payload == NULL) {
                sdk_err("Not Enough Memory");
                return;
            }
            memset(utc_payload, 0, lite_item_utc.value_length + 1);
            memcpy(utc_payload, lite_item_utc.value, lite_item_utc.value_length);

            callback = iotx_event_callback(ITE_TIMESTAMP_REPLY);
            if (callback) {
                ((int (*)(const char *))callback)(utc_payload);
            }

            IMPL_LINKKIT_FREE(utc_payload);
        }
        break;
        case IOTX_DM_EVENT_CLOUD_ERROR: {
            char *err_data = NULL;
            char *err_detail = NULL;

            if (payload == NULL) {
                return;
            }
            if (payload == NULL || lite_item_code.type != cJSON_Number) {
                return;
            }

            err_data = IMPL_LINKKIT_MALLOC(lite_item_data.value_length + 1);
            if (err_data == NULL) {
                sdk_err("Not Enough Memory");
                return;
            }

            memset(err_data, 0, lite_item_data.value_length + 1);
            memcpy(err_data, lite_item_data.value, lite_item_data.value_length);

            err_detail = IMPL_LINKKIT_MALLOC(lite_item_message.value_length + 1);
            if (err_detail == NULL) {
                sdk_err("Not Enough Memory");
                IMPL_LINKKIT_FREE(err_data);
                return;
            }

            memset(err_detail, 0, lite_item_message.value_length + 1);
            memcpy(err_detail, lite_item_message.value, lite_item_message.value_length);

            callback = iotx_event_callback(ITE_CLOUD_ERROR);
            if (callback) {
                ((int (*)(int ,const char *,const char *))callback)(lite_item_code.value_int, err_data, err_detail);
            }
            IMPL_LINKKIT_FREE(err_data);
            IMPL_LINKKIT_FREE(err_detail);
        }
        break;
        case IOTX_DM_EVENT_RRPC_REQUEST: {
            int rrpc_response_len = 0;
            char *rrpc_request = NULL, *rrpc_response = NULL;

            if (payload == NULL || lite_item_id.type != cJSON_String || lite_item_devid.type != cJSON_Number ||
                lite_item_serviceid.type != cJSON_String || lite_item_rrpcid.type != cJSON_String
                || lite_item_payload.type != cJSON_Object) {
                return;
            }

            sdk_debug("Current Id: %.*s", lite_item_id.value_length, lite_item_id.value);
            sdk_debug("Current Devid: %d", lite_item_devid.value_int);
            sdk_debug("Current ServiceID: %.*s", lite_item_serviceid.value_length, lite_item_serviceid.value);
            sdk_debug("Current RRPC ID: %.*s", lite_item_rrpcid.value_length, lite_item_rrpcid.value);
            sdk_debug("Current Payload: %.*s", lite_item_payload.value_length, lite_item_payload.value);

            rrpc_request = IMPL_LINKKIT_MALLOC(lite_item_payload.value_length + 1);
            if (rrpc_request == NULL) {
                sdk_err("Not Enough Memory");
                return;
            }
            memset(rrpc_request, 0, lite_item_payload.value_length + 1);
            memcpy(rrpc_request, lite_item_payload.value, lite_item_payload.value_length);
#ifndef LINK_VISUAL_ENABLE
            callback = iotx_event_callback(ITE_SERVICE_REQUEST);
            if (callback) {
                res = ((int (*)(const int, const char *, const int, const char *, const int, char **,
                                int *))callback)(lite_item_devid.value_int, lite_item_serviceid.value,
                                                 lite_item_serviceid.value_length,
                                                 rrpc_request, lite_item_payload.value_length, &rrpc_response, &rrpc_response_len);
                if (rrpc_response != NULL && rrpc_response_len > 0) {
                    iotx_dm_error_code_t code = (res == 0) ? (IOTX_DM_ERR_CODE_SUCCESS) : (IOTX_DM_ERR_CODE_REQUEST_ERROR);
                    iotx_dm_send_rrpc_response(lite_item_devid.value_int, lite_item_id.value, lite_item_id.value_length, code,
                                               lite_item_rrpcid.value,
                                               lite_item_rrpcid.value_length,
                                               rrpc_response, rrpc_response_len);
                    IMPL_LINKKIT_FREE(rrpc_response);
                }
            }
#else
            callback = iotx_event_callback(ITE_SERVICE_REQUST);
            if (callback) {
                res = ((int (*)(const int, const char *, const int, const char *, const int, const char *, const int, char **,
                                int *))callback)(lite_item_devid.value_int,
                                                 lite_item_rrpcid.value, lite_item_rrpcid.value_length,
                                                 lite_item_serviceid.value,
                                                 lite_item_serviceid.value_length,
                                                 rrpc_request, lite_item_payload.value_length, &rrpc_response, &rrpc_response_len);
                if (rrpc_response != NULL && rrpc_response_len > 0) {
                    iotx_dm_error_code_t code = (res == 0) ? (IOTX_DM_ERR_CODE_SUCCESS) : (IOTX_DM_ERR_CODE_REQUEST_ERROR);
                    iotx_dm_send_rrpc_response(lite_item_devid.value_int, lite_item_id.value, lite_item_id.value_length, code,
                                               lite_item_rrpcid.value,
                                               lite_item_rrpcid.value_length,
                                               rrpc_response, rrpc_response_len);
                    IMPL_LINKKIT_FREE(rrpc_response);
                }
            }
#endif
            IMPL_LINKKIT_FREE(rrpc_request);
        }
        break;
#endif
        case IOTX_DM_EVENT_FOTA_NEW_FIRMWARE: {
            char *version = NULL;

            if (payload == NULL || lite_item_version.type != cJSON_String) {
                return;
            }

            sdk_debug("Current Firmware Version: %.*s", lite_item_version.value_length, lite_item_version.value);

            version = sdk_malloc(lite_item_version.value_length + 1);
            if (version == NULL) {
                return;
            }
            memset(version, 0, lite_item_version.value_length + 1);
            memcpy(version, lite_item_version.value, lite_item_version.value_length);

            callback = iotx_event_callback(ITE_FOTA);
            if (callback) {
                ((int (*)(const int, const char *))callback)(0, version);
            }

            if (version) {
                sdk_free(version);
            }
        }
        break;
        case IOTX_DM_EVENT_COTA_NEW_CONFIG: {
            char *config_id = NULL, *get_type = NULL, *sign = NULL, *sign_method = NULL, *url = NULL;

            if (payload == NULL || lite_item_configid.type != cJSON_String || lite_item_configsize.type != cJSON_Number ||
                lite_item_gettype.type != cJSON_String || lite_item_sign.type != cJSON_String
                || lite_item_signmethod.type != cJSON_String ||
                lite_item_url.type != cJSON_String) {
                return;
            }

            sdk_debug("Current Config ID: %.*s", lite_item_configid.value_length, lite_item_configid.value);
            sdk_debug("Current Config Size: %d", lite_item_configsize.value_int);
            sdk_debug("Current Get Type: %.*s", lite_item_gettype.value_length, lite_item_gettype.value);
            sdk_debug("Current Sign: %.*s", lite_item_sign.value_length, lite_item_sign.value);
            sdk_debug("Current Sign Method: %.*s", lite_item_signmethod.value_length, lite_item_signmethod.value);
            sdk_debug("Current URL: %.*s", lite_item_url.value_length, lite_item_url.value);

            _impl_copy(lite_item_configid.value, lite_item_configid.value_length, (void **)&config_id,
                       lite_item_configid.value_length + 1);
            _impl_copy(lite_item_gettype.value, lite_item_gettype.value_length, (void **)&get_type,
                       lite_item_gettype.value_length + 1);
            _impl_copy(lite_item_sign.value, lite_item_sign.value_length, (void **)&sign, lite_item_sign.value_length + 1);
            _impl_copy(lite_item_signmethod.value, lite_item_signmethod.value_length, (void **)&sign_method,
                       lite_item_signmethod.value_length + 1);
            _impl_copy(lite_item_url.value, lite_item_url.value_length, (void **)&url, lite_item_url.value_length + 1);

            if (config_id == NULL || get_type == NULL || sign == NULL || sign_method == NULL || url == NULL) {
                if (config_id) {
                    sdk_free(config_id);
                }
                if (get_type) {
                    sdk_free(get_type);
                }
                if (sign) {
                    sdk_free(sign);
                }
                if (sign_method) {
                    sdk_free(sign_method);
                }
                if (url) {
                    sdk_free(url);
                }
                return;
            }

            callback = iotx_event_callback(ITE_COTA);
            if (callback) {
                ((int (*)(const int, const char *, int, const char *, const char *, const char *, const char *))callback)(0, config_id,
                        lite_item_configsize.value_int, get_type, sign, sign_method, url);
            }

            if (config_id) {
                sdk_free(config_id);
            }
            if (get_type) {
                sdk_free(get_type);
            }
            if (sign) {
                sdk_free(sign);
            }
            if (sign_method) {
                sdk_free(sign_method);
            }
            if (url) {
                sdk_free(url);
            }
        }
        break;
#ifdef DEVICE_MODEL_GATEWAY
        case IOTX_DM_EVENT_TOPO_GET_REPLY: {
            char *topo_list = NULL;

            if (payload == NULL || lite_item_id.type != cJSON_Number || lite_item_devid.type != cJSON_Number ||
                lite_item_code.type != cJSON_Number || lite_item_topo.type != cJSON_Array) {
                return;
            }
            sdk_debug("Current Id: %d", lite_item_id.value_int);
            sdk_debug("Current Devid: %d", lite_item_devid.value_int);
            sdk_debug("Current Code: %d", lite_item_code.value_int);
            sdk_debug("Current Topo List: %.*s", lite_item_topo.value_length, lite_item_topo.value);

            topo_list = IMPL_LINKKIT_MALLOC(lite_item_topo.value_length + 1);
            if (topo_list == NULL) {
                sdk_err("Not Enough Memory");
                return;
            }
            memset(topo_list, 0, lite_item_topo.value_length + 1);
            memcpy(topo_list, lite_item_topo.value, lite_item_topo.value_length);

            callback = iotx_event_callback(ITE_TOPOLIST_REPLY);
            if (callback) {
                ((int (*)(const int, const int, const int, const char *, const int))callback)(lite_item_devid.value_int,
                        lite_item_id.value_int,
                        lite_item_code.value_int, topo_list, lite_item_topo.value_length);
            }

            IMPL_LINKKIT_FREE(topo_list);
        }
        break;
        case IOTX_DM_EVENT_TOPO_DELETE_REPLY:
        case IOTX_DM_EVENT_SUBDEV_RESET_REPLY:
        case IOTX_DM_EVENT_TOPO_ADD_REPLY:
        case IOTX_DM_EVENT_SUBDEV_REGISTER_REPLY:
        case IOTX_DM_EVENT_COMBINE_LOGIN_REPLY:
        case IOTX_DM_EVENT_COMBINE_LOGOUT_REPLY: {
            int itm_event = -1;

            if (payload == NULL || lite_item_id.type != cJSON_Number || lite_item_devid.type != cJSON_Number ||
                lite_item_code.type != cJSON_Number)
            {
                return;
            }
            sdk_debug("Current Id: %d", lite_item_id.value_int);
            sdk_debug("Current Code: %d", lite_item_code.value_int);
            sdk_debug("Current Devid: %d", lite_item_devid.value_int);

            _iotx_linkkit_upstream_mutex_lock();
            _iotx_linkkit_upstream_callback_remove(lite_item_id.value_int, lite_item_code.value_int);
            _iotx_linkkit_upstream_mutex_unlock();

            switch (type)
            {
                case IOTX_DM_EVENT_TOPO_DELETE_REPLY:
                {
                    itm_event = ITM_EVENT_TOPO_DELETE_REPLY;
                }
                break;
                case IOTX_DM_EVENT_SUBDEV_RESET_REPLY:
                {
                    itm_event = ITM_EVENT_SUBDEV_RESET_REPLY;
                }
                break;
                case IOTX_DM_EVENT_TOPO_ADD_REPLY:
                {
                    itm_event = ITM_EVENT_TOPO_ADD_REPLY;
                }
                break;
                case IOTX_DM_EVENT_COMBINE_LOGIN_REPLY:
                {
                    itm_event = ITM_EVENT_COMBINE_LOGIN_REPLY;
                }
                break;
                case IOTX_DM_EVENT_COMBINE_LOGOUT_REPLY:
                {
                    itm_event = ITM_EVENT_COMBINE_LOGOUT_REPLY;
                }
                break;

                default:break;
            }

            if (-1 != itm_event)
            {
                char *user_payload = NULL;
                int user_payload_len = 0;

                if (lite_item_payload.value_length == 0)
                {
                    user_payload_len = 2 + 1;
                }
                else
                {
                    user_payload_len = lite_item_payload.value_length + 1;
                }

                user_payload = IMPL_LINKKIT_MALLOC(user_payload_len);
                if (user_payload == NULL)
                {
                    sdk_err("No mem");
                    return;
                }

                memset(user_payload, 0, user_payload_len);
                if (lite_item_payload.value_length == 0)
                {
                    HAL_Snprintf(user_payload, user_payload_len, "%s", "{}");
                }
                else
                {
                    memcpy(user_payload, lite_item_payload.value, lite_item_payload.value_length);
                }

                callback = iotx_event_callback(ITE_SUBDEV_MISC_OPS);
                if (callback)
                {
                    ((int (*)(const int, int, const int, const char *, const int))callback)(lite_item_devid.value_int,
                                                                                                itm_event, lite_item_code.value_int, user_payload, user_payload_len - 1);
                }

                IMPL_LINKKIT_FREE(user_payload);
            }
        }
        break;
        case IOTX_DM_EVENT_GATEWAY_PERMIT: {
            char *product_key = "";

            if (payload == NULL || lite_item_time.type != cJSON_Number) {
                return;
            }
            sdk_debug("Current Time: %d", lite_item_time.value_int);

            if (lite_item_pk.type == cJSON_String) {
                sdk_debug("Current Product Key: %.*s", lite_item_pk.value_length, lite_item_pk.value);
                product_key = IMPL_LINKKIT_MALLOC(lite_item_pk.value_length + 1);
                if (product_key == NULL) {
                    sdk_err("Not Enough Memory");
                    return;
                }
                memset(product_key, 0, lite_item_pk.value_length + 1);
                memcpy(product_key, lite_item_pk.value, lite_item_pk.value_length);
            }

            callback = iotx_event_callback(ITE_PERMIT_JOIN);
            if (callback) {
                ((int (*)(const char *, int))callback)((const char *)product_key, (const int)lite_item_time.value_int);
            }

            if (lite_item_pk.type == cJSON_String) {
                IMPL_LINKKIT_FREE(product_key);
            }
        }
        break;
        case IOTX_DM_EVENT_TOPO_CHANGE:
        {
            char *user_payload = NULL;
            int user_payload_len = 0;

            if (lite_item_payload.value_length == 0)
            {
                user_payload_len = 2 + 1;
            }
            else
            {
                user_payload_len = lite_item_payload.value_length + 1;
            }

            user_payload = IMPL_LINKKIT_MALLOC(user_payload_len);
            if (user_payload == NULL)
            {
                sdk_err("No mem");
                return;
            }

            memset(user_payload, 0, user_payload_len);
            if (lite_item_payload.value_length == 0)
            {
                HAL_Snprintf(user_payload, user_payload_len, "%s", "{}");
            }
            else
            {
                memcpy(user_payload, lite_item_payload.value, lite_item_payload.value_length);
            }

            callback = iotx_event_callback(ITE_TOPO_CHANGE);
            if (callback)
            {
                ((int (*)(const int, const char *, const int))callback)(lite_item_devid.value_int, user_payload, user_payload_len - 1);
            }

            IMPL_LINKKIT_FREE(user_payload);
        }
#endif
        default: {
        }
        break;
    }
}

static int _iotx_linkkit_master_open(iotx_linkkit_dev_meta_info_t *meta_info)
{
    int res = 0;
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();

    if (ctx->is_opened) {
        return FAIL_RETURN;
    }
    ctx->is_opened = 1;

    HAL_SetProductKey(meta_info->product_key);
    HAL_SetProductSecret(meta_info->product_secret);
    HAL_SetDeviceName(meta_info->device_name);
    HAL_SetDeviceSecret(meta_info->device_secret);

    /* Create Mutex */
    ctx->mutex = HAL_MutexCreate();
    if (ctx->mutex == NULL) {
        sdk_err("Not Enough Memory");
        ctx->is_opened = 0;
        return FAIL_RETURN;
    }

#ifdef DEVICE_MODEL_GATEWAY
    ctx->upstream_mutex = HAL_MutexCreate();
    if (ctx->upstream_mutex == NULL) {
        HAL_MutexDestroy(ctx->mutex);
        sdk_err("Not Enough Memory");
        ctx->is_opened = 0;
        return FAIL_RETURN;
    }
#endif

    res = iotx_dm_open();
    if (res != SUCCESS_RETURN) {
#ifdef DEVICE_MODEL_GATEWAY
        HAL_MutexDestroy(ctx->upstream_mutex);
#endif
        HAL_MutexDestroy(ctx->mutex);
        ctx->is_opened = 0;
        return FAIL_RETURN;
    }

    INIT_LIST_HEAD(&ctx->upstream_sync_callback_list);

    return SUCCESS_RETURN;
}

#ifdef DEVICE_MODEL_GATEWAY
static int _iotx_linkkit_slave_open(iotx_linkkit_dev_meta_info_t *meta_info)
{
    int res = 0, devid = 0;
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();

    if (!ctx->is_opened) {
        return FAIL_RETURN;
    }

    res = iotx_dm_subdev_create(meta_info->product_key, meta_info->device_name, meta_info->device_secret, &devid);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    return devid;
}

static int _iotx_linkkit_slave_close(int devid)
{
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();

    _iotx_linkkit_mutex_lock();
    if (ctx->is_opened == 0) {
        _iotx_linkkit_mutex_unlock();
        return FAIL_RETURN;
    }

    /* Release Subdev Resources */
    iotx_dm_subdev_destroy(devid);

    _iotx_linkkit_mutex_unlock();

    return SUCCESS_RETURN;
}
#endif

static int _iotx_linkkit_master_connect(void)
{
    int res = 0;
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();
    iotx_dm_init_params_t dm_init_params;

    if (ctx->is_connected) {
        return FAIL_RETURN;
    }
    ctx->is_connected = 1;

    memset(&dm_init_params, 0, sizeof(iotx_dm_init_params_t));
    dm_init_params.event_callback = _iotx_linkkit_event_callback;

    res = iotx_dm_subscribe(IOTX_DM_LOCAL_NODE_DEVID);
    if (res != SUCCESS_RETURN)
    {
        sdk_err("DM Subscribe Failed");
        ctx->is_connected = 0;
        return FAIL_RETURN;
    }

    res = iotx_dm_connect(&dm_init_params);
    if (res != SUCCESS_RETURN)
    {
        sdk_err("DM Start Failed");
        ctx->is_connected = 0;
        return FAIL_RETURN;
    }

    //Let user event handle at last
    iotx_dm_event_types_t type = IOTX_DM_EVENT_INITIALIZED;
    _iotx_linkkit_event_callback(type, "{\"devid\":0}");

    return SUCCESS_RETURN;
}

#ifdef DEVICE_MODEL_GATEWAY
typedef int (*dm_subdev_connect_cb)(int devid, iotx_linkkit_dev_meta_info_t *subdev_list, int subdev_total);
static int _iotx_linkkit_subdev_connect(int devid, dm_subdev_connect_cb connect_cb, iotx_linkkit_dev_meta_info_t *subdev_list, int subdev_total)
{
    int res = 0, msgid = 0, code = 0;
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();
    iotx_linkkit_upstream_sync_callback_node_t *node = NULL;
    void *semaphore = NULL;

    if (ctx->is_connected == 0) {
        sdk_err("master isn't start");
        return FAIL_RETURN;
    }

    if (devid <= 0 || !connect_cb) {
        sdk_err("param err");
        return FAIL_RETURN;
    }

    /* Subdev connect */
    res = connect_cb(devid, subdev_list, subdev_total);
    if (res < SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    if (res > SUCCESS_RETURN) {
        semaphore = HAL_SemaphoreCreate();
        if (semaphore == NULL) {
            return FAIL_RETURN;
        }

        msgid = res;

        _iotx_linkkit_upstream_mutex_lock();
        res = _iotx_linkkit_upstream_sync_callback_list_insert(msgid, semaphore, &node);
        if (res != SUCCESS_RETURN) {
            HAL_SemaphoreDestroy(semaphore);
            _iotx_linkkit_upstream_mutex_unlock();
            return FAIL_RETURN;
        }
        _iotx_linkkit_upstream_mutex_unlock();

        res = HAL_SemaphoreWait(semaphore, IOTX_LINKKIT_SYNC_DEFAULT_TIMEOUT_MS);
        if (res < SUCCESS_RETURN) {
            _iotx_linkkit_upstream_mutex_lock();
            _iotx_linkkit_upstream_sync_callback_list_remove(msgid);
            _iotx_linkkit_upstream_mutex_unlock();
            return FAIL_RETURN;
        }

        _iotx_linkkit_upstream_mutex_lock();
        code = node->code;
        _iotx_linkkit_upstream_sync_callback_list_remove(msgid);
        if (code != SUCCESS_RETURN) {
            _iotx_linkkit_upstream_mutex_unlock();
            return FAIL_RETURN;
        }
        _iotx_linkkit_upstream_mutex_unlock();
    }

    return SUCCESS_RETURN;
}

static int _iotx_linkkit_slave_connect(int devid)
{
    int res = 0, msgid = 0, code = 0;
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();
    iotx_linkkit_upstream_sync_callback_node_t *node = NULL;
    void *semaphore = NULL;

    if (ctx->is_connected == 0) {
        sdk_err("master isn't start");
        return FAIL_RETURN;
    }

    if (devid <= 0) {
        sdk_err("devid invalid");
        return FAIL_RETURN;
    }

    /* Subdev Register */
    res = iotx_dm_subdev_register(devid);
    if (res < SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    if (res > SUCCESS_RETURN) {
        semaphore = HAL_SemaphoreCreate();
        if (semaphore == NULL) {
            return FAIL_RETURN;
        }

        msgid = res;

        _iotx_linkkit_upstream_mutex_lock();
        res = _iotx_linkkit_upstream_sync_callback_list_insert(msgid, semaphore, &node);
        if (res != SUCCESS_RETURN) {
            HAL_SemaphoreDestroy(semaphore);
            _iotx_linkkit_upstream_mutex_unlock();
            return FAIL_RETURN;
        }
        _iotx_linkkit_upstream_mutex_unlock();

        res = HAL_SemaphoreWait(semaphore, IOTX_LINKKIT_SYNC_DEFAULT_TIMEOUT_MS);
        if (res < SUCCESS_RETURN) {
            _iotx_linkkit_upstream_mutex_lock();
            _iotx_linkkit_upstream_sync_callback_list_remove(msgid);
            _iotx_linkkit_upstream_mutex_unlock();
            return FAIL_RETURN;
        }

        _iotx_linkkit_upstream_mutex_lock();
        code = node->code;
        _iotx_linkkit_upstream_sync_callback_list_remove(msgid);
        if (code != SUCCESS_RETURN) {
            _iotx_linkkit_upstream_mutex_unlock();
            return FAIL_RETURN;
        }
        _iotx_linkkit_upstream_mutex_unlock();
    }

    /* Subdev Add Topo */
    res = iotx_dm_subdev_topo_add(devid);
    if (res < SUCCESS_RETURN) {
        _iotx_linkkit_mutex_unlock();
        return FAIL_RETURN;
    }

    semaphore = HAL_SemaphoreCreate();
    if (semaphore == NULL) {
        _iotx_linkkit_mutex_unlock();
        return FAIL_RETURN;
    }

    msgid = res;
    _iotx_linkkit_upstream_mutex_lock();
    res = _iotx_linkkit_upstream_sync_callback_list_insert(msgid, semaphore, &node);
    if (res != SUCCESS_RETURN) {
        HAL_SemaphoreDestroy(semaphore);
        _iotx_linkkit_upstream_mutex_unlock();
        return FAIL_RETURN;
    }
    _iotx_linkkit_upstream_mutex_unlock();

    res = HAL_SemaphoreWait(semaphore, IOTX_LINKKIT_SYNC_DEFAULT_TIMEOUT_MS);
    if (res < SUCCESS_RETURN) {
        _iotx_linkkit_upstream_mutex_lock();
        _iotx_linkkit_upstream_sync_callback_list_remove(msgid);
        _iotx_linkkit_upstream_mutex_unlock();
        return FAIL_RETURN;
    }

    _iotx_linkkit_upstream_mutex_lock();
    code = node->code;
    _iotx_linkkit_upstream_sync_callback_list_remove(msgid);
    if (code != SUCCESS_RETURN) {
        _iotx_linkkit_upstream_mutex_unlock();
        return FAIL_RETURN;
    }
    _iotx_linkkit_upstream_mutex_unlock();

    return SUCCESS_RETURN;
}

static int _iotx_linkkit_subdev_delete_topo(int devid)
{
    int res = 0, msgid = 0, code = 0;
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();
    iotx_linkkit_upstream_sync_callback_node_t *node = NULL;
    void *semaphore = NULL;

    if (ctx->is_connected == 0) {
        sdk_err("master isn't start");
        return FAIL_RETURN;
    }

    if (devid <= 0) {
        sdk_err("devid invalid");
        return FAIL_RETURN;
    }

    /* Subdev Delete Topo */
    res = iotx_dm_subdev_topo_del(devid);
    if (res < SUCCESS_RETURN) {
        return FAIL_RETURN;
    }
    msgid = res;

    semaphore = HAL_SemaphoreCreate();
    if (semaphore == NULL) {
        return FAIL_RETURN;
    }

    _iotx_linkkit_upstream_mutex_lock();
    res = _iotx_linkkit_upstream_sync_callback_list_insert(msgid, semaphore, &node);
    if (res != SUCCESS_RETURN) {
        HAL_SemaphoreDestroy(semaphore);
        _iotx_linkkit_upstream_mutex_unlock();
        return FAIL_RETURN;
    }
    _iotx_linkkit_upstream_mutex_unlock();

    res = HAL_SemaphoreWait(semaphore, IOTX_LINKKIT_SYNC_DEFAULT_TIMEOUT_MS);
    if (res < SUCCESS_RETURN) {
        _iotx_linkkit_upstream_mutex_lock();
        _iotx_linkkit_upstream_sync_callback_list_remove(msgid);
        _iotx_linkkit_upstream_mutex_unlock();
        return FAIL_RETURN;
    }

    _iotx_linkkit_upstream_mutex_lock();
    code = node->code;
    _iotx_linkkit_upstream_sync_callback_list_remove(msgid);
    if (code != SUCCESS_RETURN) {
        _iotx_linkkit_upstream_mutex_unlock();
        return FAIL_RETURN;
    }
    _iotx_linkkit_upstream_mutex_unlock();

    return SUCCESS_RETURN;
}

static int _iotx_linkkit_subdev_reset(int devid)
{
    int res = 0, msgid = 0, code = 0;
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();
    iotx_linkkit_upstream_sync_callback_node_t *node = NULL;
    void *semaphore = NULL;

    if (ctx->is_connected == 0) {
        sdk_err("master isn't start");
        return FAIL_RETURN;
    }

    if (devid <= 0) {
        sdk_err("devid invalid");
        return FAIL_RETURN;
    }

    /* Subdev Delete Topo */
    res = iotx_dm_subdev_reset(devid);
    if (res < SUCCESS_RETURN) {
        return FAIL_RETURN;
    }
    msgid = res;

    semaphore = HAL_SemaphoreCreate();
    if (semaphore == NULL) {
        return FAIL_RETURN;
    }

    _iotx_linkkit_upstream_mutex_lock();
    res = _iotx_linkkit_upstream_sync_callback_list_insert(msgid, semaphore, &node);
    if (res != SUCCESS_RETURN) {
        HAL_SemaphoreDestroy(semaphore);
        _iotx_linkkit_upstream_mutex_unlock();
        return FAIL_RETURN;
    }
    _iotx_linkkit_upstream_mutex_unlock();

    res = HAL_SemaphoreWait(semaphore, IOTX_LINKKIT_SYNC_DEFAULT_TIMEOUT_MS);
    if (res < SUCCESS_RETURN) {
        _iotx_linkkit_upstream_mutex_lock();
        _iotx_linkkit_upstream_sync_callback_list_remove(msgid);
        _iotx_linkkit_upstream_mutex_unlock();
        return FAIL_RETURN;
    }

    _iotx_linkkit_upstream_mutex_lock();
    code = node->code;
    _iotx_linkkit_upstream_sync_callback_list_remove(msgid);
    if (code != SUCCESS_RETURN) {
        _iotx_linkkit_upstream_mutex_unlock();
        return FAIL_RETURN;
    }
    _iotx_linkkit_upstream_mutex_unlock();

    return SUCCESS_RETURN;
}
#endif

static int _iotx_linkkit_master_close(void)
{
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();

    _iotx_linkkit_mutex_lock();
    if (ctx->is_opened == 0) {
        _iotx_linkkit_mutex_unlock();
        return FAIL_RETURN;
    }
    ctx->is_opened = 0;

    iotx_dm_close();
#ifdef DEVICE_MODEL_GATEWAY
    _iotx_linkkit_upstream_sync_callback_list_destroy();
    HAL_MutexDestroy(ctx->upstream_mutex);
#endif
    _iotx_linkkit_mutex_unlock();
    HAL_MutexDestroy(ctx->mutex);
    memset(ctx, 0, sizeof(iotx_linkkit_ctx_t));
    _awss_reported = 0;

    return SUCCESS_RETURN;
}

//data moved from global data center to the region user used, MUST reinitialized sdk and all devices.
int user_handle_redirect()
{
    iotx_linkkit_dev_meta_info_t meta_info;
    int id = 0;
    int res = 0;

    //close master

        memset(&meta_info, 0, sizeof(iotx_linkkit_dev_meta_info_t));
        HAL_GetProductKey(meta_info.product_key);
        HAL_GetProductSecret(meta_info.product_secret);
        HAL_GetDeviceName(meta_info.device_name);
        HAL_GetDeviceSecret(meta_info.device_secret);

        IOT_Linkkit_Close(IOTX_DM_LOCAL_NODE_DEVID);
        /* Create Master Device Resources */
        do {
            id = IOT_Linkkit_Open(IOTX_LINKKIT_DEV_TYPE_MASTER, &meta_info);
            if (id < 0) {
                sdk_err("IOT_Linkkit_Open Failed, retry after 5s...\n");
                HAL_SleepMs(5000);
            }
        } while (id < 0);
        /* Start Connect Aliyun Server */
        do {
            res = IOT_Linkkit_Connect(id);
            if (res < 0) {
                sdk_err("IOT_Linkkit_Connect Failed, retry after 5s...\n");
                HAL_SleepMs(5000);
            }
        } while (res < 0);

    return 0;
}

static int user_redirect_event_handler(void)
{
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();

    sdk_debug("Cloud Redirect");

    ctx->cloud_redirect = 1;

    return 0;
}

int IOT_Linkkit_Open(iotx_linkkit_dev_type_t dev_type, iotx_linkkit_dev_meta_info_t *meta_info)
{
    int res = 0;

    if (dev_type < 0 || dev_type >= IOTX_LINKKIT_DEV_TYPE_MAX || meta_info == NULL) {
        sdk_err("Invalid Parameter");
        return FAIL_RETURN;
    }

    switch (dev_type) {
        case IOTX_LINKKIT_DEV_TYPE_MASTER: {
            res = _iotx_linkkit_master_open(meta_info);
            if (res == SUCCESS_RETURN) {
                res = IOTX_DM_LOCAL_NODE_DEVID;
                IOT_RegisterCallback(ITE_REDIRECT, user_redirect_event_handler);
            }
        }
        break;
        case IOTX_LINKKIT_DEV_TYPE_SLAVE: {
#ifdef DEVICE_MODEL_GATEWAY
            res = _iotx_linkkit_slave_open(meta_info);
#else
            res = FAIL_RETURN;
#endif
        }
        break;
        default: {
            sdk_err("Unknown Device Type");
            res = FAIL_RETURN;
        }
        break;
    }

    return res;
}

int IOT_Linkkit_Connect(int devid)
{
    int res = 0;
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();

    if (devid < 0) {
        sdk_err("Invalid Parameter");
        return FAIL_RETURN;
    }

    if (ctx->is_opened == 0) {

        return FAIL_RETURN;
    }

    _iotx_linkkit_mutex_lock();

    if (devid == IOTX_DM_LOCAL_NODE_DEVID) {
        res = _iotx_linkkit_master_connect();
    } else {
#ifdef DEVICE_MODEL_GATEWAY
        res = _iotx_linkkit_subdev_connect(devid, iotx_dm_subdev_connect, NULL, 0);
#else
        res = FAIL_RETURN;
#endif
    }
    _iotx_linkkit_mutex_unlock();

    return res;
}

void IOT_Linkkit_Yield(int timeout_ms)
{
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();

    if (timeout_ms <= 0) {
        sdk_err("Invalid Parameter");
        return;
    }

    if (ctx->is_opened == 0 || ctx->is_connected == 0) {
        HAL_SleepMs(timeout_ms);
        return;
    }

    // NOTICE: Do Not remove the following codes!
    if (ctx->cloud_redirect == 1){
        user_handle_redirect();
        ctx->cloud_redirect = 0;
    }

    iotx_dm_yield(timeout_ms);
    iotx_dm_dispatch();

#if (CONFIG_SDK_THREAD_COST == 1)
    HAL_SleepMs(timeout_ms);
#endif
}

int IOT_Linkkit_Close(int devid)
{
    int res = 0;

    if (devid < 0) {
        sdk_err("Invalid Parameter");
        return FAIL_RETURN;
    }

    if (devid == IOTX_DM_LOCAL_NODE_DEVID) {
#ifdef DEV_BIND_ENABLED
        extern void awss_bind_deinit(void);
        awss_bind_deinit();
#endif
        res = _iotx_linkkit_master_close();
    } else {
#ifdef DEVICE_MODEL_GATEWAY
        res = _iotx_linkkit_slave_close(devid);
#else
        res = FAIL_RETURN;
#endif
    }

    return res;
}

#ifdef DEVICE_MODEL_GATEWAY
static int _iotx_linkkit_subdev_login(int devid)
{
    int res = 0, msgid = 0, code = 0;
    iotx_linkkit_upstream_sync_callback_node_t *node = NULL;
    void *semaphore = NULL;

    res = iotx_dm_subdev_login(devid);
    if (res < SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    msgid = res;
    semaphore = HAL_SemaphoreCreate();
    if (semaphore == NULL) {
        return FAIL_RETURN;
    }

    _iotx_linkkit_upstream_mutex_lock();
    res = _iotx_linkkit_upstream_sync_callback_list_insert(msgid, semaphore, &node);
    if (res != SUCCESS_RETURN) {
        HAL_SemaphoreDestroy(semaphore);
        _iotx_linkkit_upstream_mutex_unlock();
        return FAIL_RETURN;
    }
    _iotx_linkkit_upstream_mutex_unlock();

    res = HAL_SemaphoreWait(semaphore, IOTX_LINKKIT_SYNC_DEFAULT_TIMEOUT_MS);
    if (res < SUCCESS_RETURN) {
        _iotx_linkkit_upstream_mutex_lock();
        _iotx_linkkit_upstream_sync_callback_list_remove(msgid);
        _iotx_linkkit_upstream_mutex_unlock();
        return FAIL_RETURN;
    }

    _iotx_linkkit_upstream_mutex_lock();
    code = node->code;
    _iotx_linkkit_upstream_sync_callback_list_remove(msgid);
    if (code != SUCCESS_RETURN) {
        _iotx_linkkit_upstream_mutex_unlock();
        return FAIL_RETURN;
    }
    _iotx_linkkit_upstream_mutex_unlock();

    res = iotx_dm_subscribe(devid);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    void *callback = iotx_event_callback(ITE_INITIALIZE_COMPLETED);
    if (callback) {
        ((int (*)(const int))callback)(devid);
    }


    return res;
}

static int _iotx_linkkit_subdev_logout(int devid)
{
    int res = 0, msgid = 0, code = 0;
    iotx_linkkit_upstream_sync_callback_node_t *node = NULL;
    void *semaphore = NULL;

    res = iotx_dm_subdev_logout(devid);
    if (res < SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    msgid = res;
    semaphore = HAL_SemaphoreCreate();
    if (semaphore == NULL) {
        return FAIL_RETURN;
    }

    _iotx_linkkit_upstream_mutex_lock();
    res = _iotx_linkkit_upstream_sync_callback_list_insert(msgid, semaphore, &node);
    if (res != SUCCESS_RETURN) {
        HAL_SemaphoreDestroy(semaphore);
        _iotx_linkkit_upstream_mutex_unlock();
        return FAIL_RETURN;
    }
    _iotx_linkkit_upstream_mutex_unlock();

    res = HAL_SemaphoreWait(semaphore, IOTX_LINKKIT_SYNC_DEFAULT_TIMEOUT_MS);
    if (res < SUCCESS_RETURN) {
        _iotx_linkkit_upstream_mutex_lock();
        _iotx_linkkit_upstream_sync_callback_list_remove(msgid);
        _iotx_linkkit_upstream_mutex_unlock();
        return FAIL_RETURN;
    }

    _iotx_linkkit_upstream_mutex_lock();
    code = node->code;
    _iotx_linkkit_upstream_sync_callback_list_remove(msgid);
    if (code != SUCCESS_RETURN) {
        _iotx_linkkit_upstream_mutex_unlock();
        return FAIL_RETURN;
    }
    _iotx_linkkit_upstream_mutex_unlock();

    return res;
}
#endif

int IOT_Linkkit_Report_Ext(int devid, iotx_linkkit_msg_type_t msg_type, unsigned char *payload, int payload_len, int sendto)
{
    int res = 0;
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();

    if (devid < 0 || msg_type < 0 || msg_type >= IOTX_LINKKIT_MSG_MAX) {
        sdk_err("Invalid Parameter");
        return FAIL_RETURN;
    }

    if (ctx->is_opened == 0 || ctx->is_connected == 0) {
        return FAIL_RETURN;
    }

    _iotx_linkkit_mutex_lock();
    switch (msg_type) {
#if !defined(DEVICE_MODEL_RAWDATA_SOLO)
        case ITM_MSG_POST_PROPERTY: {
            if (payload == NULL || payload_len <= 0) {
                sdk_err("Invalid Parameter");
                _iotx_linkkit_mutex_unlock();
                return FAIL_RETURN;
            }
            res = iotx_dm_post_property_to(devid, (char *)payload, payload_len, sendto);
#ifdef LOG_REPORT_TO_CLOUD
            if (1 == report_sample) {
                send_permance_info(NULL, 0, "4", 1);
            }
#endif
        }
        break;
#endif
        default: {
            sdk_err("Unknown Message Type");
            res = FAIL_RETURN;
        }
        break;
    }
    _iotx_linkkit_mutex_unlock();
    return res;
}

int IOT_Linkkit_Report(int devid, iotx_linkkit_msg_type_t msg_type, unsigned char *payload, int payload_len)
{
    int res = 0;
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();

    if (devid < 0 || msg_type < 0 || msg_type >= IOTX_LINKKIT_MSG_MAX) {
        sdk_err("Invalid Parameter");
        return FAIL_RETURN;
    }

    if (ctx->is_opened == 0 || ctx->is_connected == 0) {
        return FAIL_RETURN;
    }

    _iotx_linkkit_mutex_lock();
    switch (msg_type) {
#if !defined(DEVICE_MODEL_RAWDATA_SOLO)
        case ITM_MSG_POST_PROPERTY: {
            if (payload == NULL || payload_len <= 0) {
                sdk_err("Invalid Parameter");
                _iotx_linkkit_mutex_unlock();
                return FAIL_RETURN;
            }
            res = iotx_dm_post_property(devid, (char *)payload, payload_len);
#ifdef LOG_REPORT_TO_CLOUD
            if (1 == report_sample) {
                send_permance_info(NULL, 0, "4", 1);
            }
#endif
        }
        break;
#ifdef DM_UNIFIED_SERVICE_POST
        case ITM_MSG_UNIFIED_SERVICE_POST: {
            if (payload == NULL || payload_len <= 0) {
                sdk_err("param err");
                _iotx_linkkit_mutex_unlock();
                return FAIL_RETURN;
            }
            res = iotx_dm_unified_service_post(devid, (char *)payload, payload_len);
#ifdef LOG_REPORT_TO_CLOUD
            if (1 == report_sample) {
                send_permance_info(NULL, 0, "4", 1);
            }
#endif
        }break;
#endif

#ifdef DEVICE_MODEL_GATEWAY
        case ITM_MSG_CONNECT_SUBDEV:
        {
            if (payload && payload_len > 0)
            {
                int subdev_id = -1;
                int subdev_total = 0;
                int subdev_valid_num = 0;
                int index = 0;
                iotx_linkkit_dev_meta_info_t *p_subdev_list = (iotx_linkkit_dev_meta_info_t*)payload;
                iotx_linkkit_dev_meta_info_t *p_subdev_valid_list = NULL;

                subdev_total = payload_len / sizeof(iotx_linkkit_dev_meta_info_t);

                p_subdev_valid_list = IMPL_LINKKIT_MALLOC(payload_len);
                if (p_subdev_valid_list == NULL)
                {
                    sdk_err("no mem");
                    return ERROR_NO_ENOUGH_MEM;
                }

                for(index = 0;index < subdev_total;index++)
                {
                    iotx_linkkit_dev_meta_info_t *p_subdev = p_subdev_list + index;
                    subdev_id = _iotx_linkkit_slave_open(p_subdev);
                    if (subdev_id > 0) {
                        memcpy(p_subdev_valid_list + subdev_valid_num, p_subdev, sizeof(iotx_linkkit_dev_meta_info_t));
                        subdev_valid_num ++;
                    }
                    else
                    {
                        sdk_err("open dn(%s) fail", p_subdev->device_name);
                    }
                }
                res = _iotx_linkkit_subdev_connect(1, iotx_dm_multi_subdev_connect, p_subdev_valid_list, subdev_valid_num);

                if (p_subdev_valid_list) IMPL_LINKKIT_FREE(p_subdev_valid_list);

#ifdef LOG_REPORT_TO_CLOUD
                if (1 == report_sample) {
                    send_permance_info(NULL, 0, "4", 1);
                }
#endif
            }

        }break;
#endif
        case ITM_MSG_EVENT_NOTIFY_REPLY: {
            if (payload == NULL || payload_len <= 0) {
                sdk_err("Invalid Parameter");
                _iotx_linkkit_mutex_unlock();
                return FAIL_RETURN;
            }
            res = iotx_dm_event_notify_reply(devid, (char *)payload, payload_len);
#ifdef LOG_REPORT_TO_CLOUD
            if (1 == report_sample) {
                send_permance_info(NULL, 0, "4", 1);
            }
#endif
        }
        break;
        case ITM_MSG_DEVICEINFO_UPDATE: {
            if (payload == NULL || payload_len <= 0) {
                sdk_err("Invalid Parameter");
                _iotx_linkkit_mutex_unlock();
                return FAIL_RETURN;
            }
            res = iotx_dm_deviceinfo_update(devid, (char *)payload, payload_len);
        }
        break;
        case ITM_MSG_DEVICEINFO_DELETE: {
            if (payload == NULL || payload_len <= 0) {
                sdk_err("Invalid Parameter");
                _iotx_linkkit_mutex_unlock();
                return FAIL_RETURN;
            }
            res = iotx_dm_deviceinfo_delete(devid, (char *)payload, payload_len);
        }
        break;
#endif
        case ITM_MSG_POST_RAW_DATA: {
            if (payload == NULL || payload_len <= 0) {
                sdk_err("Invalid Parameter");
                _iotx_linkkit_mutex_unlock();
                return FAIL_RETURN;
            }
            res = iotx_dm_post_rawdata(devid, (char *)payload, payload_len);
        }
        break;
        case ITM_MSG_LOGIN: {
#ifdef DEVICE_MODEL_GATEWAY
        res = _iotx_linkkit_subdev_login(devid);
        if (res != SUCCESS_RETURN) {
            _iotx_linkkit_mutex_unlock();
            return FAIL_RETURN;
        }
#else
            res = FAIL_RETURN;
#endif
        }
        break;
#ifdef DEVICE_MODEL_GATEWAY
        case ITM_MSG_LOGOUT: {
            res = _iotx_linkkit_subdev_logout(devid);
            if (res != SUCCESS_RETURN) {
                _iotx_linkkit_mutex_unlock();
                return FAIL_RETURN;
            }
        }
        break;
        case ITM_MSG_DELETE_TOPO: {
            if (payload && payload_len == sizeof(iotx_linkkit_dev_meta_info_t)) {
                int subdev_id = -1;
                int ret = 0;

                iotx_linkkit_dev_meta_info_t *p_subdev = (iotx_linkkit_dev_meta_info_t*)payload;

                ret = iotx_dm_subdev_query(p_subdev->product_key, p_subdev->device_name, &subdev_id);
                if (SUCCESS_RETURN == ret && subdev_id > 0) {
                   devid = subdev_id;
                }
            }

            res = _iotx_linkkit_subdev_delete_topo(devid);
            if (res != SUCCESS_RETURN) {
                _iotx_linkkit_mutex_unlock();
                return FAIL_RETURN;
            }
        }
        break;
        case ITM_MSG_SUBDEV_RESET:
        {
            if (payload && payload_len == sizeof(iotx_linkkit_dev_meta_info_t)) {
                int subdev_id = -1;
                int ret = 0;

                iotx_linkkit_dev_meta_info_t *p_subdev = (iotx_linkkit_dev_meta_info_t*)payload;

                ret = iotx_dm_subdev_query(p_subdev->product_key, p_subdev->device_name, &subdev_id);
                if (SUCCESS_RETURN == ret && subdev_id > 0) {
                   devid = subdev_id;
                }
            }

            res = _iotx_linkkit_subdev_reset(devid);
            if (res != SUCCESS_RETURN) {
                _iotx_linkkit_mutex_unlock();
                return FAIL_RETURN;
            }
        }
        break;
#endif
        default: {
            sdk_err("Unknown Message Type");
            res = FAIL_RETURN;
        }
        break;
    }
    _iotx_linkkit_mutex_unlock();
    return res;
}

int IOT_Linkkit_Query(int devid, iotx_linkkit_msg_type_t msg_type, unsigned char *payload, int payload_len)
{
    int res = 0;
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();

    if (devid < 0 || msg_type < 0 || msg_type >= IOTX_LINKKIT_MSG_MAX) {
        sdk_err("Invalid Parameter");
        return FAIL_RETURN;
    }

    if (ctx->is_opened == 0 || ctx->is_connected == 0) {
        return FAIL_RETURN;
    }

    _iotx_linkkit_mutex_lock();
    switch (msg_type) {
#if !defined(DEVICE_MODEL_RAWDATA_SOLO)
        case ITM_MSG_QUERY_TIMESTAMP: {
            res = iotx_dm_qurey_ntp();
        }
        break;
#endif
        case ITM_MSG_QUERY_TOPOLIST: {
#ifdef DEVICE_MODEL_GATEWAY
            res = iotx_dm_query_topo_list();
#else
            res = FAIL_RETURN;
#endif
        }
        break;
        case ITM_MSG_QUERY_FOTA_DATA: {
            res = iotx_dm_fota_perform_sync((char *)payload, payload_len);
        }
        break;
        case ITM_MSG_QUERY_COTA_DATA: {
            res = iotx_dm_cota_perform_sync((char *)payload, payload_len);
        }
        break;
        case ITM_MSG_REQUEST_COTA: {
            res = iotx_dm_cota_get_config("product", "file", "");
        }
        break;
        case ITM_MSG_REQUEST_FOTA_IMAGE: {
            res = iotx_dm_fota_request_image((const char *)payload, payload_len);
        }
        break;
#ifdef DEVICE_MODEL_GATEWAY
        case ITM_MSG_QUERY_SUBDEV_ID:
        {
            if (payload && payload_len == sizeof(iotx_linkkit_dev_meta_info_t)) {
                int subdev_id = -1;
                int ret = 0;

                iotx_linkkit_dev_meta_info_t *p_subdev = (iotx_linkkit_dev_meta_info_t*)payload;

                ret = iotx_dm_subdev_query(p_subdev->product_key, p_subdev->device_name, &subdev_id);
                if (SUCCESS_RETURN != ret) {
                   subdev_id = -1;
                   sdk_err("No subdev dn:%s", p_subdev->device_name);
                }

                _iotx_linkkit_mutex_unlock();
                return subdev_id;
            }
        }
        break;
#endif
        default: {
            sdk_err("Unknown Message Type");
            res = FAIL_RETURN;
        }
        break;
    }
    _iotx_linkkit_mutex_unlock();
    return res;
}

int IOT_Linkkit_TriggerEvent(int devid, char *eventid, int eventid_len, char *payload, int payload_len)
{
#if !defined(DEVICE_MODEL_RAWDATA_SOLO)
    int res = 0;
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();

    if (devid < 0 || eventid == NULL || eventid_len <= 0 || payload == NULL || payload_len <= 0) {
        sdk_err("Invalid Parameter");
        return FAIL_RETURN;
    }

    if (ctx->is_opened == 0 || ctx->is_connected == 0) {
        return FAIL_RETURN;
    }

    _iotx_linkkit_mutex_lock();
    res = iotx_dm_post_event(devid, eventid, eventid_len, payload, payload_len);
    _iotx_linkkit_mutex_unlock();

    return res;
#else
    return -1;
#endif
}

#ifdef DEVICE_MODEL_GATEWAY
#ifdef LINK_VISUAL_ENABLE
int iot_linkkit_subdev_query_id(char product_key[IOTX_PRODUCT_KEY_LEN + 1], char device_name[IOTX_DEVICE_NAME_LEN + 1])
{
    int res = -1;
    iotx_linkkit_ctx_t *ctx = _iotx_linkkit_get_ctx();
    if (ctx->is_opened == 0) {
        return res;
    }
    iotx_dm_subdev_query(product_key, device_name, &res);
    return res;
}
#endif
#endif /* #ifdef DEVICE_MODEL_GATEWAY */
#endif

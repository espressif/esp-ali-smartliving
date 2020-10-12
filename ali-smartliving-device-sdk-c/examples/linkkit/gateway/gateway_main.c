/*
 * Copyright (C) 2015-2019 Alibaba Group Holding Limited
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "iot_import.h"
#include "iot_export_linkkit.h"

#include "iotx_log.h"

#include "gateway_main.h"
#include "gateway_api.h"
#include "gateway_ut.h"

static gateway_ctx_t g_gateway_ctx;
static void *permit_join_timer = NULL;

gateway_ctx_t *gateway_get_ctx(void)
{
    return &g_gateway_ctx;
}

static int user_connected_event_handler(void)
{
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();

    gateway_info("Cloud Connected");

    gateway_ctx->cloud_connected = 1;

    if (gateway_ctx->master_initialized == 1) //initialized
    {
#ifdef GATEWAY_UT_TESTING
        gateway_ut_update_subdev(GW_TOPO_GET_REASON_CONNECT_CLOUD);
#endif
    }

    return 0;
}

static int user_disconnected_event_handler(void)
{
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();

    gateway_info("Cloud Disconnected");

    gateway_ctx->cloud_connected = 0;

    return 0;
}

static int user_down_raw_data_arrived_event_handler(const int devid, const unsigned char *payload,
                                                    const int payload_len)
{
    gateway_info("Down Raw Message, Devid: %d, Payload Length: %d", devid, payload_len);
    return 0;
}

static int user_service_request_event_handler(const int devid, const char *serviceid, const int serviceid_len,
                                              const char *request, const int request_len,
                                              char **response, int *response_len)
{
    gateway_info("Service Request Received, Devid: %d, Service ID: %.*s, Payload: %s", devid, serviceid_len,
                 serviceid,
                 request);

    return 0;
}

#ifdef ALCS_ENABLED
//Just for reference,user have to change his owner properties
static int user_property_get_event_handler(const int devid, const char *request, const int request_len, char **response,
                                           int *response_len)
{
    cJSON *request_root = NULL, *item_propertyid = NULL;
    cJSON *response_root = NULL;
    int index = 0;
    gateway_info("Property Get Received, Devid: %d, Request: %s", devid, request);

    /* Parse Request */
    request_root = cJSON_Parse(request);
    if (request_root == NULL || !cJSON_IsArray(request_root))
    {
        gateway_info("JSON Parse Error");
        return -1;
    }

    /* Prepare Response */
    response_root = cJSON_CreateObject();
    if (response_root == NULL)
    {
        gateway_info("No Enough Memory");
        cJSON_Delete(request_root);
        return -1;
    }

    for (index = 0; index < cJSON_GetArraySize(request_root); index++)
    {
        item_propertyid = cJSON_GetArrayItem(request_root, index);
        if (item_propertyid == NULL || !cJSON_IsString(item_propertyid))
        {
            gateway_info("JSON Parse Error");
            cJSON_Delete(request_root);
            cJSON_Delete(response_root);
            return -1;
        }

        gateway_info("Property ID, index: %d, Value: %s", index, item_propertyid->valuestring);
        if (strcmp("WIFI_Tx_Rate", item_propertyid->valuestring) == 0)
        {
            cJSON_AddNumberToObject(response_root, "WIFI_Tx_Rate", 1111);
        }
        else if (strcmp("WIFI_Rx_Rate", item_propertyid->valuestring) == 0)
        {
            cJSON_AddNumberToObject(response_root, "WIFI_Rx_Rate", 2222);
        }
        else if (strcmp("LocalTimer", item_propertyid->valuestring) == 0)
        {
            cJSON *array_localtimer = cJSON_CreateArray();
            if (array_localtimer == NULL)
            {
                cJSON_Delete(request_root);
                cJSON_Delete(response_root);
                return -1;
            }

            cJSON *item_localtimer = cJSON_CreateObject();
            if (item_localtimer == NULL)
            {
                cJSON_Delete(request_root);
                cJSON_Delete(response_root);
                cJSON_Delete(array_localtimer);
                return -1;
            }
            cJSON_AddStringToObject(item_localtimer, "Timer", "10 11 * * * 1 2 3 4 5");
            cJSON_AddNumberToObject(item_localtimer, "Enable", 1);
            cJSON_AddNumberToObject(item_localtimer, "IsValid", 1);
            cJSON_AddItemToArray(array_localtimer, item_localtimer);
            cJSON_AddItemToObject(response_root, "LocalTimer", array_localtimer);
        }
    }
    cJSON_Delete(request_root);

    *response = cJSON_PrintUnformatted(response_root);
    if (*response == NULL)
    {
        gateway_info("No Enough Memory");
        cJSON_Delete(response_root);
        return -1;
    }
    cJSON_Delete(response_root);
    *response_len = strlen(*response);

    gateway_info("Property Get Response: %s", *response);

    return SUCCESS_RETURN;
}
#endif

//When code is not 200,maybe call this function
static int user_property_cloud_error_handler(const int code, const char *data, const char *detail)
{
    gateway_info("code =%d ,data=%s, detail=%s", code, data, detail);

    return 0;
}

static int user_property_set_event_handler(const int devid, const char *request, const int request_len)
{
    int res = 0;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    gateway_info("Property Set Received, Devid: %d, Request: %s", devid, request);

    res = IOT_Linkkit_Report(devid, ITM_MSG_POST_PROPERTY,
                             (unsigned char *)request, request_len);

    gateway_info("Post Property Message ID: %d", res);

    return 0;
}

static int user_report_reply_event_handler(const int devid, const int msgid, const int code, const char *reply,
                                           const int reply_len)
{
    const char *reply_value = (reply == NULL) ? ("NULL") : (reply);
    const int reply_value_len = (reply_len == 0) ? (strlen("NULL")) : (reply_len);

    gateway_info("Message Post Reply Received, Devid: %d, Message ID: %d, Code: %d, Reply: %.*s", devid, msgid, code,
                 reply_value_len,
                 reply_value);
    return 0;
}

static int user_trigger_event_reply_event_handler(const int devid, const int msgid, const int code, const char *eventid,
                                                  const int eventid_len, const char *message, const int message_len)
{
    gateway_info("Trigger Event Reply Received, Devid: %d, Message ID: %d, Code: %d, EventID: %.*s, Message: %.*s", devid,
                 msgid, code,
                 eventid_len,
                 eventid, message_len, message);

    return 0;
}

static int user_timestamp_reply_event_handler(const char *timestamp)
{
    gateway_info("Current Timestamp: %s", timestamp);

    return 0;
}

static uint64_t user_update_sec(void)
{
    static uint64_t time_start_ms = 0;

    if (time_start_ms == 0)
    {
        time_start_ms = HAL_UptimeMs();
    }

    return (HAL_UptimeMs() - time_start_ms) / 1000;
}

static int user_initialized(const int devid)
{
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    gateway_info("Device Initialized, Devid: %d", devid);

    if (gateway_ctx->master_devid == devid)
    {
        gateway_ctx->master_initialized = 1;
    }

    return 0;
}

static int user_master_dev_available(void)
{
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();

    if (gateway_ctx->cloud_connected && gateway_ctx->master_initialized)
    {
        return 1;
    }

    return 0;
}

static int gw_notify_msg_handle(int devid, const char *request, const int request_len)
{
    int ret = 0;
    cJSON *request_root = NULL;
    cJSON *item = NULL;
    gateway_msg_t gw_msg;

    request_root = cJSON_Parse(request);
    if (request_root == NULL)
    {
        gateway_info("JSON Parse Error");
        return -1;
    }

    item = cJSON_GetObjectItem(request_root, "identifier");
    if (item == NULL || !cJSON_IsString(item))
    {
        cJSON_Delete(request_root);
        return -1;
    }

    if (!strcmp(item->valuestring, "awss.BindNotify"))
    {
        cJSON *value = cJSON_GetObjectItem(request_root, "value");
        if (value == NULL || !cJSON_IsObject(value))
        {
            cJSON_Delete(request_root);
            return -1;
        }
        cJSON *op = cJSON_GetObjectItem(value, "Operation");
        if (op != NULL && cJSON_IsString(op))
        {
            if (!strcmp(op->valuestring, "Bind"))
            {
                gateway_info("Device Bind");
            }
            else if (!strcmp(op->valuestring, "Unbind"))
            {
                gateway_info("Device unBind");
                if (devid > 0) //User unbind subdev
                {
                    memset(&gw_msg, 0, sizeof(gateway_msg_t));
                    gw_msg.msg_type = GATEWAY_MSG_TYPE_DEL;
                    gw_msg.devid = devid;

                    ret = gateway_ut_send_msg(&gw_msg, sizeof(gateway_msg_t));
                }
            }
            else if (!strcmp(op->valuestring, "Reset"))
            {
                gateway_info("Device reset");
                if (devid > 0) //User reset subdev
                {
                    memset(&gw_msg, 0, sizeof(gateway_msg_t));
                    gw_msg.msg_type = GATEWAY_MSG_TYPE_RESET;
                    gw_msg.devid = devid;

                    ret = gateway_ut_send_msg(&gw_msg, sizeof(gateway_msg_t));
                }
            }
        }
    }

    cJSON_Delete(request_root);
    return 0;
}

static int user_event_notify_handler(const int devid, const char *request, const int request_len)
{
    int res = 0;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    gateway_info("Event notify Received, Devid: %d, Request: %s", devid, request);

    gw_notify_msg_handle(devid, request, request_len);
    res = IOT_Linkkit_Report(gateway_ctx->master_devid, ITM_MSG_EVENT_NOTIFY_REPLY,
                             (unsigned char *)request, request_len);
    gateway_info("Post Property Message ID: %d", res);

    return 0;
}

//get topo list reply
static int user_topolist_reply_handler(const int devid, const int id, const int code, const char *payload, const int payload_len)
{
    gateway_info("Receive topolist reply, code:%d, payload:%s", code, payload);

#ifdef GATEWAY_UT_TESTING
    if (code == 200 && payload && payload_len > 0)
    {
        gateway_ut_handle_topolist_reply(payload, payload_len);
    }
#endif

    return 0;
}

static int permit_join_timer_cb(void)
{
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();

    if (permit_join_timer)
    {
        HAL_Timer_Stop(permit_join_timer);
        HAL_Timer_Delete(permit_join_timer);
        permit_join_timer = NULL;
        gateway_ctx->permit_join = 0;
        gateway_info("delete permit join timer");
    }

    return 0;
}

static int user_permit_join_event_handler(const char *product_key, const int time)
{
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();

    gateway_info("Product Key: %s, Time: %dS", product_key, time);

    memset(gateway_ctx->permit_join_pk, '\0', PRODUCT_KEY_MAXLEN);
    if (strlen(product_key) > 0 && strlen(product_key) < PRODUCT_KEY_MAXLEN)
    {
        HAL_Snprintf(gateway_ctx->permit_join_pk, PRODUCT_KEY_MAXLEN, "%s", product_key);
    }

    gateway_ctx->permit_join = 1;

    if (permit_join_timer) //Just restart this timer
    {
        HAL_Timer_Stop(permit_join_timer);
        HAL_Timer_Start(permit_join_timer, time * 1000);
    }
    else if (time > 0)
    {
        permit_join_timer = HAL_Timer_Create("oll_upload", (void (*)(void *))permit_join_timer_cb, NULL);
        if (permit_join_timer)
        {
            HAL_Timer_Stop(permit_join_timer);
            HAL_Timer_Start(permit_join_timer, time * 1000);
        }
    }

#ifdef GATEWAY_UT_TESTING
    gateway_ut_handle_permit_join();
#endif

    return 0;
}

#ifdef GATEWAY_SUPPORT_TOPO_CHANGE
static int user_gateway_topo_change_handler(const int devid, const char *payload, const int payload_len)
{
    int index = 0;
    int subdev_id = -1;
    cJSON *topo_change = NULL, *status = NULL, *subList = NULL;
    cJSON *subdev, *pk = NULL, *dn = NULL;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    iotx_linkkit_dev_meta_info_t subdev_mate;

    gateway_debug("Receive topo change, payload:%s", payload);

    /* Parse Request */
    topo_change = cJSON_Parse(payload);
    if (topo_change == NULL)
    {
        gateway_err("topo change json format err");
        return -1;
    }

    status = cJSON_GetObjectItem(topo_change, TOPO_CHANGE_STATUS);
    if (!cJSON_IsNumber(status))
    {
        gateway_err("topo change status err");
        cJSON_Delete(topo_change);
        return -1;
    }

    subList = cJSON_GetObjectItem(topo_change, TOPO_CHANGE_SUBLIST);
    if (!cJSON_IsArray(subList))
    {
        gateway_err("topo change subList err");
        cJSON_Delete(topo_change);
        return -1;
    }

    for (index = 0; index < cJSON_GetArraySize(subList); index++)
    {
        subdev = cJSON_GetArrayItem(subList, index);
        if (subdev == NULL || !cJSON_IsObject(subdev))
        {
            gateway_err("subdev json err");
            cJSON_Delete(topo_change);
            return -1;
        }

        pk = cJSON_GetObjectItem(subdev, TOPO_LIST_PK);
        dn = cJSON_GetObjectItem(subdev, TOPO_LIST_DN);
        if (cJSON_IsString(pk) && cJSON_IsString(dn))
        {
            memset(&subdev_mate, 0, sizeof(iotx_linkkit_dev_meta_info_t));
            HAL_Snprintf(subdev_mate.product_key, PRODUCT_KEY_MAXLEN, "%s", pk->valuestring);
            HAL_Snprintf(subdev_mate.device_name, DEVICE_NAME_MAXLEN, "%s", dn->valuestring);
            subdev_id = gateway_query_subdev_id(gateway_ctx->master_devid, &subdev_mate);
            if (subdev_id > 0)
            {
                switch (status->valueint)
                {
                case GW_TOPO_CHANGE_STATUS_ADD:
                {
                }
                break;
                case GW_TOPO_CHANGE_STATUS_DELETE:
                {
                    gateway_info("topo change del dn:%s", subdev_mate.device_name);
                    IOT_Linkkit_Close(subdev_id);
                }
                break;
                case GW_TOPO_CHANGE_STATUS_ENABLE:
                {
                }
                break;
                case GW_TOPO_CHANGE_STATUS_DISABLE:
                {
                }
                break;
                default:
                    break;
                }
            }
        }
    }

    cJSON_Delete(topo_change);

    return 0;
}
#endif

static int user_subdev_misc_reply_handler(const int devid, const int event_id, const int code, const char *payload, const int payload_len)
{
    gateway_info("Receive subdev misc reply, code:%d, payload:%s", code, payload);
    switch (event_id)
    {
    case ITM_EVENT_TOPO_DELETE_REPLY:
    {
        gateway_info("ITM_EVENT_TOPO_DELETE_REPLY, devid:%d code:%d, payload:%s", devid, code, payload);
        if (200 == code)
        {
            IOT_Linkkit_Close(devid); //remove subdev from dm(device manager)
        }
    }
    break;
    case ITM_EVENT_SUBDEV_RESET_REPLY:
    {
        gateway_info("ITM_EVENT_SUBDEV_RESET_REPLY, devid:%d code:%d, payload:%s", devid, code, payload);
    }
    break;
    case ITM_EVENT_TOPO_ADD_REPLY:
    {
        gateway_info("ITM_EVENT_TOPO_ADD_REPLY, devid:%d code:%d, payload:%s", devid, code, payload);
    }
    break;
    case ITM_EVENT_COMBINE_LOGIN_REPLY:
    {
        gateway_info("ITM_EVENT_COMBINE_LOGIN_REPLY, devid:%d code:%d, payload:%s", devid, code, payload);
    }
    break;
    case ITM_EVENT_COMBINE_LOGOUT_REPLY:
    {
        gateway_info("ITM_EVENT_COMBINE_LOGOUT_REPLY, devid:%d code:%d, payload:%s", devid, code, payload);
    }
    break;

    default:
        break;
    }
    return 0;
}

static int user_fota_event_handler(int type, const char *version)
{
    char *p_fota_buffer = NULL;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();

    p_fota_buffer = HAL_Malloc(GATEWAY_OTA_BUFFER_LEN);
    if (!p_fota_buffer)
    {
        gateway_err("no mem");
        return -1;
    }

    if (type == 0)
    {
        gateway_info("New Firmware Version: %s", version);
        memset(p_fota_buffer, 0, GATEWAY_OTA_BUFFER_LEN);
        IOT_Linkkit_Query(gateway_ctx->master_devid, ITM_MSG_QUERY_FOTA_DATA, (unsigned char *)p_fota_buffer, GATEWAY_OTA_BUFFER_LEN);
    }

    if (p_fota_buffer)
        HAL_Free(p_fota_buffer);

    return 0;
}

static int user_cota_event_handler(int type, const char *config_id, int config_size, const char *get_type,
                                   const char *sign, const char *sign_method, const char *url)
{
    char *p_cota_buffer = NULL;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();

    p_cota_buffer = HAL_Malloc(GATEWAY_OTA_BUFFER_LEN);
    if (!p_cota_buffer)
    {
        gateway_err("no mem");
        return -1;
    }

    if (type == 0)
    {
        gateway_info("New Config ID: %s", config_id);
        gateway_info("New Config Size: %d", config_size);
        gateway_info("New Config Type: %s", get_type);
        gateway_info("New Config Sign: %s", sign);
        gateway_info("New Config Sign Method: %s", sign_method);
        gateway_info("New Config URL: %s", url);

        IOT_Linkkit_Query(gateway_ctx->master_devid, ITM_MSG_QUERY_COTA_DATA, (unsigned char *)p_cota_buffer, GATEWAY_OTA_BUFFER_LEN);
    }

    if (p_cota_buffer)
        HAL_Free(p_cota_buffer);

    return 0;
}

static int user_offline_reset_handler(void)
{
    gateway_info("user callback user_offline_reset_handler called.");

    return 0;
}

static int user_dev_bind_event(const int state_code, const char *state_message)
{
    gateway_info("state_code: -0x%04x, str_msg= %s", -state_code, state_message == NULL ? "NULL" : state_message);
    return 0;
}

#ifdef DM_UNIFIED_SERVICE_POST
static int user_unified_service_post_reply_handler(const int devid, const int id, const int code, const char *payload, const int payload_len)
{
    gateway_info("Receive unified service post reply, code:%d, payload:%s", code, payload);

    return 0;
}
#endif

void *user_dispatch_yield(void *args)
{
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();

    while (gateway_ctx->g_user_dispatch_thread_running)
    {
        IOT_Linkkit_Yield(GATEWAY_YIELD_TIMEOUT_MS);
    }

    return NULL;
}

static iotx_linkkit_dev_meta_info_t *gateway_main_init(gateway_ctx_t *gateway_ctx)
{
    int ret = 0;
    int dynamic_register = 0; //0:You have to burn DS for each devices,1:Request DS from cloud by https
    int post_event_reply = 1;
    iotx_linkkit_dev_meta_info_t *p_master_meta = NULL;

    memset(gateway_ctx, 0, sizeof(gateway_ctx_t));

    p_master_meta = HAL_Malloc(sizeof(iotx_linkkit_dev_meta_info_t));
    if (p_master_meta == NULL)
    {
        gateway_err("no mem");
        return NULL;
    }

    memset(p_master_meta, 0, sizeof(iotx_linkkit_dev_meta_info_t));
    HAL_GetProductKey(p_master_meta->product_key);
    HAL_GetDeviceName(p_master_meta->device_name);
    HAL_GetDeviceSecret(p_master_meta->device_secret);
    HAL_GetProductSecret(p_master_meta->product_secret);

    if ((0 == strlen(p_master_meta->product_key)) || (0 == strlen(p_master_meta->device_name)) || (0 == dynamic_register && (0 == strlen(p_master_meta->device_secret))) || (0 == strlen(p_master_meta->product_secret)))
    {
        while (1)
        {
            printf("Master meta info is invalid...\r\n");
            printf("pk[%s]\r\n", p_master_meta->product_key);
            printf("ps[%s]\r\n", p_master_meta->product_secret);
            printf("dn[%s]\r\n", p_master_meta->device_name);
            printf("ds[%s]\r\n", p_master_meta->device_secret);
            HAL_SleepMs(2000);
        }
    }

    /* Register Callback */
    IOT_RegisterCallback(ITE_INITIALIZE_COMPLETED, user_initialized);
    IOT_RegisterCallback(ITE_CONNECT_SUCC, user_connected_event_handler);
    IOT_RegisterCallback(ITE_DISCONNECTED, user_disconnected_event_handler);
    IOT_RegisterCallback(ITE_RAWDATA_ARRIVED, user_down_raw_data_arrived_event_handler);
    IOT_RegisterCallback(ITE_SERVICE_REQUEST, user_service_request_event_handler);
    IOT_RegisterCallback(ITE_PROPERTY_SET, user_property_set_event_handler);
#ifdef ALCS_ENABLED
    /*Only for local communication service(ALCS)*/
    IOT_RegisterCallback(ITE_PROPERTY_GET, user_property_get_event_handler);
#endif
    IOT_RegisterCallback(ITE_REPORT_REPLY, user_report_reply_event_handler);
    IOT_RegisterCallback(ITE_TRIGGER_EVENT_REPLY, user_trigger_event_reply_event_handler);
    IOT_RegisterCallback(ITE_TIMESTAMP_REPLY, user_timestamp_reply_event_handler);

    IOT_RegisterCallback(ITE_PERMIT_JOIN, user_permit_join_event_handler);
    IOT_RegisterCallback(ITE_CLOUD_ERROR, user_property_cloud_error_handler);
    IOT_RegisterCallback(ITE_EVENT_NOTIFY, user_event_notify_handler);

    IOT_RegisterCallback(ITE_TOPOLIST_REPLY, user_topolist_reply_handler);
    IOT_RegisterCallback(ITE_SUBDEV_MISC_OPS, user_subdev_misc_reply_handler);
#ifdef GATEWAY_SUPPORT_TOPO_CHANGE
    IOT_RegisterCallback(ITE_TOPO_CHANGE, user_gateway_topo_change_handler);
#endif

    IOT_RegisterCallback(ITE_FOTA, user_fota_event_handler);
    IOT_RegisterCallback(ITE_COTA, user_cota_event_handler);
    IOT_RegisterCallback(ITE_STATE_DEV_BIND, user_dev_bind_event);
    IOT_RegisterCallback(ITE_OFFLINE_RESET, user_offline_reset_handler);

#ifdef DM_UNIFIED_SERVICE_POST
    IOT_RegisterCallback(ITE_UNIFIED_SERVICE_POST, user_unified_service_post_reply_handler);
#endif

    IOT_Ioctl(IOTX_IOCTL_SET_DYNAMIC_REGISTER, (void *)&dynamic_register);

    /* Choose Whether You Need Post Property/Event Reply */
    IOT_Ioctl(IOTX_IOCTL_RECV_EVENT_REPLY, (void *)&post_event_reply);

#ifdef GATEWAY_UT_TESTING
    gateway_ut_init();
#endif

    return p_master_meta;
}

int gateway_main(void *paras)
{
    int res = 0;
    uint64_t time_prev_sec = 0, time_now_sec = 0, time_begin_sec = 0;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    iotx_linkkit_dev_meta_info_t *p_master_meta = NULL;
    hal_os_thread_param_t hal_os_thread_param;

    p_master_meta = gateway_main_init(gateway_ctx);
    if (NULL == p_master_meta)
    {
        printf("OOPS:gateway_main_init failed");
        return -1;
    }

    /* Create Master Device Resources */
    do
    {
        gateway_ctx->master_devid = IOT_Linkkit_Open(IOTX_LINKKIT_DEV_TYPE_MASTER, p_master_meta);
        if (gateway_ctx->master_devid < 0)
        {
            printf("IOT_Linkkit_Open Failed, retry after 5s...\r\n");
            HAL_SleepMs(5000);
        }
    } while (gateway_ctx->master_devid < 0);
    /* Start Connect Aliyun Server */
    do
    {
        res = IOT_Linkkit_Connect(gateway_ctx->master_devid);
        if (res < 0)
        {
            printf("IOT_Linkkit_Connect Failed, retry after 5s...\r\n");
            HAL_SleepMs(5000);
        }
    } while (res < 0);

    gateway_ctx->g_user_dispatch_thread_running = 1;

    //Attation:please don't remove this thread,because sub dev operations is sync
    memset(&hal_os_thread_param, 0, sizeof(hal_os_thread_param_t));
    hal_os_thread_param.stack_size = GATEWAY_YIELD_THREAD_STACKSIZE;
    hal_os_thread_param.name = GATEWAY_YIELD_THREAD_NAME;

    res = HAL_ThreadCreate(&gateway_ctx->g_user_dispatch_thread, user_dispatch_yield, NULL, &hal_os_thread_param, NULL);
    if (res < 0)
    {
        gateway_info("HAL_ThreadCreate Failed\n");
        IOT_Linkkit_Close(gateway_ctx->master_devid);
        return -1;
    }

    time_begin_sec = user_update_sec();

    while (1)
    {
        time_now_sec = user_update_sec();
        if (time_prev_sec == time_now_sec)
        {
            continue;
        }

#ifdef GATEWAY_UT_TESTING
        HAL_SleepMs(GATEWAY_YIELD_TIMEOUT_MS / 2);

        if (user_master_dev_available())
        {
            gateway_ut_msg_process(gateway_ctx->master_devid, GATEWAY_YIELD_TIMEOUT_MS / 2);
            gateway_ut_misc_process(time_now_sec);
        }
#else
        HAL_SleepMs(GATEWAY_YIELD_TIMEOUT_MS);
#endif
        time_prev_sec = time_now_sec;
    }

    //Should never come here
    gateway_ctx->g_user_dispatch_thread_running = 0;

    if (p_master_meta)
    {
        HAL_Free(p_master_meta);
    }

    IOT_DumpMemoryStats(IOT_LOG_DEBUG);

    return 0;
}

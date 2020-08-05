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

#include "living_platform_rawdata_main.h"
#include "app_entry.h"
#include "living_platform_rawdata_ut.h"

static living_platform_rawdata_ctx_t g_living_platform_rawdata_ctx;

living_platform_rawdata_ctx_t *living_platform_rawdata_get_ctx(void)
{
    return &g_living_platform_rawdata_ctx;
}

static int user_connected_event_handler(void)
{
    living_platform_rawdata_ctx_t *living_platform_rawdata_ctx = living_platform_rawdata_get_ctx();

    living_platform_rawdata_info("Cloud Connected");

    living_platform_rawdata_ctx->cloud_connected = 1;

    if (living_platform_rawdata_ctx->master_initialized == 1) //initialized
    {
    }

    return 0;
}

static int user_disconnected_event_handler(void)
{
    living_platform_rawdata_ctx_t *living_platform_rawdata_ctx = living_platform_rawdata_get_ctx();

    living_platform_rawdata_info("Cloud Disconnected");

    living_platform_rawdata_ctx->cloud_connected = 0;

    return 0;
}

static int user_down_raw_data_arrived_event_handler(const int devid, const unsigned char *payload,
                                                    const int payload_len)
{
    living_platform_rawdata_info("Down Raw Message, Devid: %d, Payload Length: %d", devid, payload_len);
    if (payload[0] == 0x02 && payload_len == 6)
    {
        living_platform_rawdata_ut_set_LightSwitch(payload[5]);
    }

    return 0;
}

//When code is not 200,maybe call this function
static int user_property_cloud_error_handler(const int code, const char *data, const char *detail)
{
    living_platform_rawdata_info("code =%d ,data=%s, detail=%s", code, data, detail);

    return 0;
}

static int user_report_reply_event_handler(const int devid, const int msgid, const int code, const char *reply,
                                           const int reply_len)
{
    const char *reply_value = (reply == NULL) ? ("NULL") : (reply);
    const int reply_value_len = (reply_len == 0) ? (strlen("NULL")) : (reply_len);

    living_platform_rawdata_info("Message Post Reply Received, Devid: %d, Message ID: %d, Code: %d, Reply: %.*s", devid, msgid, code,
            reply_value_len,
            reply_value);
    return 0;
}

static int user_trigger_event_reply_event_handler(const int devid, const int msgid, const int code, const char *eventid,
                                                  const int eventid_len, const char *message, const int message_len)
{
    living_platform_rawdata_info("Trigger Event Reply Received, Devid: %d, Message ID: %d, Code: %d, EventID: %.*s, Message: %.*s", devid,
            msgid, code,
            eventid_len,
            eventid, message_len, message);

    return 0;
}

static int user_timestamp_reply_event_handler(const char *timestamp)
{
    living_platform_rawdata_info("Current Timestamp: %s", timestamp);

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

static int living_platform_rawdata_ut_query_timestamp(void)
{
    living_platform_rawdata_ctx_t *living_platform_rawdata_ctx = living_platform_rawdata_get_ctx();
    living_platform_rawdata_info("do query timestamp");

    IOT_Linkkit_Query(living_platform_rawdata_ctx->master_devid, ITM_MSG_QUERY_TIMESTAMP, NULL, 0);

    return 0;
}

static int user_initialized(const int devid)
{
    living_platform_rawdata_ctx_t *living_platform_rawdata_ctx = living_platform_rawdata_get_ctx();
    living_platform_rawdata_info("Device Initialized, Devid: %d", devid);

    if (living_platform_rawdata_ctx->master_devid == devid)
    {
        living_platform_rawdata_ctx->master_initialized = 1;
    }

    return 0;
}

static int user_master_dev_available(void)
{
    living_platform_rawdata_ctx_t *living_platform_rawdata_ctx = living_platform_rawdata_get_ctx();

    if (living_platform_rawdata_ctx->cloud_connected && living_platform_rawdata_ctx->master_initialized)
    {
        return 1;
    }

    return 0;
}

static int living_platform_rawdata_notify_msg_handle(int devid, const char *request, const int request_len)
{
    int ret = 0;
    cJSON *request_root = NULL;
    cJSON *item = NULL;

    request_root = cJSON_Parse(request);
    if (request_root == NULL)
    {
        living_platform_rawdata_info("JSON Parse Error");
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
                living_platform_rawdata_info("Device Bind");
                //TODO:User can do something according thier own requirements
            }
            else if (!strcmp(op->valuestring, "Unbind"))
            {
                living_platform_rawdata_info("Device unBind");
                //TODO:User can do something according thier own requirements
            }
            else if (!strcmp(op->valuestring, "Reset"))
            {
                living_platform_rawdata_info("Device reset");
                //TODO:User can do something according thier own requirements
            }
        }
    }

    cJSON_Delete(request_root);
    return 0;
}

static int user_event_notify_handler(const int devid, const char *request, const int request_len)
{
    int res = 0;
    living_platform_rawdata_ctx_t *living_platform_rawdata_ctx = living_platform_rawdata_get_ctx();
    living_platform_rawdata_info("Event notify Received, Devid: %d, Request: %s", devid, request);

    living_platform_rawdata_notify_msg_handle(devid, request, request_len);
    res = IOT_Linkkit_Report(living_platform_rawdata_ctx->master_devid, ITM_MSG_EVENT_NOTIFY_REPLY,
                             (unsigned char *)request, request_len);
    living_platform_rawdata_info("Post Property Message ID: %d", res);

    return 0;
}

static int user_fota_event_handler(int type, const char *version)
{
    char *p_fota_buffer = NULL;
    living_platform_rawdata_ctx_t *living_platform_rawdata_ctx = living_platform_rawdata_get_ctx();

    p_fota_buffer = HAL_Malloc(LIVING_PLATFORM_RAWDATA_OTA_BUFFER_LEN);
    if (!p_fota_buffer)
    {
        living_platform_rawdata_err("no mem");
        return -1;
    }

    if (type == 0)
    {
        living_platform_rawdata_info("New Firmware Version: %s", version);
        memset(p_fota_buffer, 0, LIVING_PLATFORM_RAWDATA_OTA_BUFFER_LEN);
        IOT_Linkkit_Query(living_platform_rawdata_ctx->master_devid, ITM_MSG_QUERY_FOTA_DATA, (unsigned char *)p_fota_buffer, LIVING_PLATFORM_RAWDATA_OTA_BUFFER_LEN);
    }

    if (p_fota_buffer)
        HAL_Free(p_fota_buffer);

    return 0;
}

static int user_cota_event_handler(int type, const char *config_id, int config_size, const char *get_type,
                                   const char *sign, const char *sign_method, const char *url)
{
    char *p_cota_buffer = NULL;
    living_platform_rawdata_ctx_t *living_platform_rawdata_ctx = living_platform_rawdata_get_ctx();

    p_cota_buffer = HAL_Malloc(LIVING_PLATFORM_RAWDATA_OTA_BUFFER_LEN);
    if (!p_cota_buffer)
    {
        living_platform_rawdata_err("no mem");
        return -1;
    }

    if (type == 0)
    {
        living_platform_rawdata_info("New Config ID: %s", config_id);
        living_platform_rawdata_info("New Config Size: %d", config_size);
        living_platform_rawdata_info("New Config Type: %s", get_type);
        living_platform_rawdata_info("New Config Sign: %s", sign);
        living_platform_rawdata_info("New Config Sign Method: %s", sign_method);
        living_platform_rawdata_info("New Config URL: %s", url);

        IOT_Linkkit_Query(living_platform_rawdata_ctx->master_devid, ITM_MSG_QUERY_COTA_DATA, (unsigned char *)p_cota_buffer, LIVING_PLATFORM_RAWDATA_OTA_BUFFER_LEN);
    }

    if (p_cota_buffer)
        HAL_Free(p_cota_buffer);

    return 0;
}

static int user_offline_reset_handler(void)
{
    living_platform_rawdata_info("user callback user_offline_reset_handler called.");

    return 0;
}

static int user_dev_bind_event(const int state_code, const char *state_message)
{
    living_platform_rawdata_info("state_code: -0x%04x, str_msg= %s", -state_code, state_message == NULL ? "NULL" : state_message);
    return 0;
}

#ifdef DM_UNIFIED_SERVICE_POST
static int user_unified_service_post_reply_handler(const int devid, const int id, const int code, const char *payload, const int payload_len)
{
    living_platform_rawdata_info("Receive unified service post reply, code:%d, payload:%s", code, payload);

    return 0;
}
#endif

static iotx_linkkit_dev_meta_info_t *living_platform_rawdata_main_init(living_platform_rawdata_ctx_t *living_platform_rawdata_ctx)
{
    int register_type = 0;
    int post_event_reply = 1;
    iotx_linkkit_dev_meta_info_t *p_master_meta = NULL;

    memset(living_platform_rawdata_ctx, 0, sizeof(living_platform_rawdata_ctx_t));

    p_master_meta = HAL_Malloc(sizeof(iotx_linkkit_dev_meta_info_t));
    if (p_master_meta == NULL)
    {
        living_platform_rawdata_err("no mem");
        return NULL;
    }

    memset(p_master_meta, 0, sizeof(iotx_linkkit_dev_meta_info_t));
    HAL_GetProductKey(p_master_meta->product_key);
    HAL_GetDeviceName(p_master_meta->device_name);
    HAL_GetDeviceSecret(p_master_meta->device_secret);
    HAL_GetProductSecret(p_master_meta->product_secret);

    if ((0 == strlen(p_master_meta->product_key)) || (0 == strlen(p_master_meta->device_name)) ||
        (0 == register_type && (0 == strlen(p_master_meta->device_secret))) || (0 == strlen(p_master_meta->product_secret)))
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

#ifdef LIVING_PLATFORM_RAWDATA_PRODUCT_DYNAMIC_REGISTER
    register_type = 1;
#endif

    /* Register Callback */
    IOT_RegisterCallback(ITE_INITIALIZE_COMPLETED, user_initialized);
    IOT_RegisterCallback(ITE_CONNECT_SUCC, user_connected_event_handler);
    IOT_RegisterCallback(ITE_DISCONNECTED, user_disconnected_event_handler);
    IOT_RegisterCallback(ITE_RAWDATA_ARRIVED, user_down_raw_data_arrived_event_handler);

    IOT_RegisterCallback(ITE_REPORT_REPLY, user_report_reply_event_handler);
    IOT_RegisterCallback(ITE_TRIGGER_EVENT_REPLY, user_trigger_event_reply_event_handler);
    IOT_RegisterCallback(ITE_TIMESTAMP_REPLY, user_timestamp_reply_event_handler);

    IOT_RegisterCallback(ITE_CLOUD_ERROR, user_property_cloud_error_handler);

    IOT_RegisterCallback(ITE_FOTA, user_fota_event_handler);
    IOT_RegisterCallback(ITE_COTA, user_cota_event_handler);

    IOT_RegisterCallback(ITE_EVENT_NOTIFY, user_event_notify_handler);
    IOT_RegisterCallback(ITE_STATE_DEV_BIND, user_dev_bind_event);

    IOT_RegisterCallback(ITE_OFFLINE_RESET, user_offline_reset_handler);

    IOT_Ioctl(IOTX_IOCTL_SET_DYNAMIC_REGISTER, (void *)&register_type);

    /* Choose Whether You Need Post Property/Event Reply */
    IOT_Ioctl(IOTX_IOCTL_RECV_EVENT_REPLY, (void *)&post_event_reply);

#ifdef LIVING_PLATFORM_RAWDATA_USE_UT_FOR_TESTING
    living_platform_rawdata_ut_init();
#endif

    return p_master_meta;
}

int living_platform_rawdata_main(void *paras)
{
    int res = 0;
    uint64_t time_prev_sec = 0, time_now_sec = 0;
    living_platform_rawdata_ctx_t *living_platform_rawdata_ctx = living_platform_rawdata_get_ctx();
    iotx_linkkit_dev_meta_info_t *p_master_meta = NULL;

    p_master_meta = living_platform_rawdata_main_init(living_platform_rawdata_ctx);
    if (NULL == p_master_meta)
    {
        printf("OOPS:living_platform_rawdata_main_init failed");
        return -1;
    }

    /* Create Master Device Resources */
    do
    {
        living_platform_rawdata_ctx->master_devid = IOT_Linkkit_Open(IOTX_LINKKIT_DEV_TYPE_MASTER, p_master_meta);
        if (living_platform_rawdata_ctx->master_devid < 0)
        {
            printf("IOT_Linkkit_Open Failed, retry after 5s...\r\n");
            HAL_SleepMs(5000);
        }
    } while (living_platform_rawdata_ctx->master_devid < 0);
    /* Start Connect Aliyun Server */
    do
    {
        res = IOT_Linkkit_Connect(living_platform_rawdata_ctx->master_devid);
        if (res < 0)
        {
            printf("IOT_Linkkit_Connect Failed, retry after 5s...\r\n");
            HAL_SleepMs(5000);
        }
    } while (res < 0);

    living_platform_rawdata_ut_query_timestamp();


//User can call this function to start device AP of AWSS
void living_platform_rawdata_do_awss_dev_ap(void);

//User can call this function to start smartconfig of AWSS
void living_platform_rawdata_do_awss(void);

//User can call this function for system reset
void living_platform_rawdata_awss_reset(void);
    living_platform_rawdata_awss_reset();
    while (1)
    {
        IOT_Linkkit_Yield(LIVING_PLATFORM_RAWDATA_YIELD_TIMEOUT_MS);

        time_now_sec = user_update_sec();
        if (time_prev_sec == time_now_sec)
        {
            continue;
        }

        if (user_master_dev_available())
        {
            #ifdef LIVING_PLATFORM_RAWDATA_USE_UT_FOR_TESTING
            living_platform_rawdata_ut_misc_process(time_now_sec);
            #endif
        }

        time_prev_sec = time_now_sec;
    }

    //Should never come here
    living_platform_rawdata_ctx->g_user_dispatch_thread_running = 0;

    if (p_master_meta)
    {
        HAL_Free(p_master_meta);
    }

    IOT_DumpMemoryStats(IOT_LOG_DEBUG);

    return 0;
}

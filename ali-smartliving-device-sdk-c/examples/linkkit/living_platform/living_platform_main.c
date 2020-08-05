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

#include "living_platform_main.h"
#include "app_entry.h"
#include "living_platform_ut.h"

static living_platform_ctx_t g_living_platform_ctx;

living_platform_ctx_t *living_platform_get_ctx(void)
{
    return &g_living_platform_ctx;
}

static int user_connected_event_handler(void)
{
    living_platform_ctx_t *living_platform_ctx = living_platform_get_ctx();

    living_platform_info("Cloud Connected");

    living_platform_ctx->cloud_connected = 1;

    if (living_platform_ctx->master_initialized == 1) //initialized
    {
    }

    return 0;
}

static int user_disconnected_event_handler(void)
{
    living_platform_ctx_t *living_platform_ctx = living_platform_get_ctx();

    living_platform_info("Cloud Disconnected");

    living_platform_ctx->cloud_connected = 0;

    return 0;
}

static int user_down_raw_data_arrived_event_handler(const int devid, const unsigned char *payload,
                                                    const int payload_len)
{
    living_platform_info("Down Raw Message, Devid: %d, Payload Length: %d", devid, payload_len);
    if (payload[0] == 0x02 && payload_len == 6)
    {
        living_platform_ut_set_LightSwitch(payload[5]);
    }

    return 0;
}

static int user_service_request_event_handler(const int devid, const char *serviceid, const int serviceid_len,
                                              const char *request, const int request_len,
                                              char **response, int *response_len)
{
    int transparency = 0;
    cJSON *root = NULL, *item_transparency = NULL;

    living_platform_info("Service Request Received, Devid: %d, Service ID: %.*s, Payload: %s", devid, serviceid_len,
            serviceid,
            request);

    /* Parse Root */
    root = cJSON_Parse(request);
    if (root == NULL || !cJSON_IsObject(root))
    {
        living_platform_err("JSON Parse Error");
        return -1;
    }

    if (strlen("Custom") == serviceid_len && memcmp("Custom", serviceid, serviceid_len) == 0)
    {
        /* Parse Item */
        const char *response_fmt = "{\"transparency\":%d}";
        item_transparency = cJSON_GetObjectItem(root, "transparency");
        if (item_transparency == NULL || !cJSON_IsNumber(item_transparency))
        {
            cJSON_Delete(root);
            return -1;
        }
        living_platform_info("transparency: %d", item_transparency->valueint);
        transparency = item_transparency->valueint + 1;
        if (transparency > 100)
        {
            transparency = 100;
        }

        /* Send Service Response To Cloud */
        *response_len = strlen(response_fmt) + 10 + 1;
        *response = (char *)HAL_Malloc(*response_len);
        if (*response == NULL)
        {
            living_platform_err("Memory Not Enough");
            return -1;
        }
        memset(*response, 0, *response_len);
        HAL_Snprintf(*response, *response_len, response_fmt, transparency);
        *response_len = strlen(*response);
    }
    else if (strlen("ToggleLightSwitch") == serviceid_len && memcmp("ToggleLightSwitch", serviceid, serviceid_len) == 0)
    {
        /* Parse Item */
        const char *response_fmt = "{\"LightSwitch\":%d}";

        /* Send Service Response To Cloud */
        *response_len = strlen(response_fmt) + strlen("LightSwitch") + 10;
        *response = (char *)HAL_Malloc(*response_len);
        if (*response == NULL)
        {
            living_platform_err("Memory Not Enough");
            return -1;
        }
        memset(*response, 0, *response_len);
        if (living_platform_ut_get_LightSwitch() == 0)
        {
            living_platform_ut_set_LightSwitch(1);
        }
        else
        {
            living_platform_ut_set_LightSwitch(0);
        }

        HAL_Snprintf(*response, *response_len, response_fmt, living_platform_ut_get_LightSwitch());
        *response_len = strlen(*response);
    }

    cJSON_Delete(root);

    return 0;
}

#ifdef ALCS_ENABLED
//Just for reference,user have to change his owner properties
static int user_property_get_event_handler(const int devid, const char *request, const int request_len, char **response,
                                           int *response_len)
{
    int index = 0;
    living_platform_tsl_t *p_living_platform_tsl_data = living_platform_ut_get_tsl_data();
    cJSON *response_root = NULL;
    cJSON *request_root = NULL, *item_propertyid = NULL;
    living_platform_info("Property Get Received, Devid: %d, Request: %s", devid, request);

    /* Parse Request */
    request_root = cJSON_Parse(request);
    if (request_root == NULL || !cJSON_IsArray(request_root))
    {
        living_platform_info("JSON Parse Error");
        return -1;
    }

    /* Prepare Response */
    response_root = cJSON_CreateObject();
    if (response_root == NULL)
    {
        living_platform_info("No Enough Memory");
        cJSON_Delete(request_root);
        return -1;
    }

    for (index = 0; index < cJSON_GetArraySize(request_root); index++)
    {
        item_propertyid = cJSON_GetArrayItem(request_root, index);
        if (item_propertyid == NULL || !cJSON_IsString(item_propertyid))
        {
            living_platform_info("JSON Parse Error");
            cJSON_Delete(request_root);
            cJSON_Delete(response_root);
            return -1;
        }

        living_platform_info("Property ID, index: %d, Value: %s", index, item_propertyid->valuestring);
        if (strcmp("WIFI_Band", item_propertyid->valuestring) == 0)
        {
            cJSON_AddStringToObject(response_root, "WIFI_Band", p_living_platform_tsl_data->wifi.band);
        }
        else if (strcmp("WIFI_AP_BSSID", item_propertyid->valuestring) == 0)
        {
            cJSON_AddStringToObject(response_root, "WIFI_AP_BSSID", p_living_platform_tsl_data->wifi.bssid);
        }
        else if (strcmp("WIFI_Channel", item_propertyid->valuestring) == 0)
        {
            cJSON_AddNumberToObject(response_root, "WIFI_Channel", p_living_platform_tsl_data->wifi.Channel);
        }
        else if (strcmp("WiFI_SNR", item_propertyid->valuestring) == 0)
        {
            cJSON_AddNumberToObject(response_root, "WiFI_SNR", p_living_platform_tsl_data->wifi.SNR);
        }
        else if (strcmp("WiFI_RSSI", item_propertyid->valuestring) == 0)
        {
            cJSON_AddNumberToObject(response_root, "WiFI_RSSI", p_living_platform_tsl_data->wifi.rssi);
        }
        else if (strcmp("LightSwitch", item_propertyid->valuestring) == 0)
        {
            cJSON_AddBoolToObject(response_root, "LightSwitch", p_living_platform_tsl_data->LightSwitch);
        }
        else if (strcmp("NightLightSwitch", item_propertyid->valuestring) == 0)
        {
            cJSON_AddBoolToObject(response_root, "NightLightSwitch", p_living_platform_tsl_data->NightLightSwitch);
        }
        else if (strcmp("WorkMode", item_propertyid->valuestring) == 0)
        {
            cJSON_AddNumberToObject(response_root, "WorkMode", p_living_platform_tsl_data->WorkMode);
        }
        else if (strcmp("worktime", item_propertyid->valuestring) == 0)
        {
            cJSON_AddStringToObject(response_root, "worktime", p_living_platform_tsl_data->WorkTime);
        }
        else if (strcmp("Brightness", item_propertyid->valuestring) == 0)
        {
            cJSON_AddNumberToObject(response_root, "Brightness", p_living_platform_tsl_data->Brightness);
        }
        else if (strcmp("onlyread", item_propertyid->valuestring) == 0)
        {
            cJSON_AddNumberToObject(response_root, "onlyread", p_living_platform_tsl_data->readonly);
        }
        else if (strcmp("floatid", item_propertyid->valuestring) == 0)
        {
            cJSON_AddNumberToObject(response_root, "floatid", p_living_platform_tsl_data->f);
        }
        else if (strcmp("doubleid", item_propertyid->valuestring) == 0)
        {
            cJSON_AddNumberToObject(response_root, "doubleid", p_living_platform_tsl_data->d);
        }
        else if (strcmp("PropertyString", item_propertyid->valuestring) == 0)
        {
            cJSON_AddStringToObject(response_root, "PropertyString", p_living_platform_tsl_data->PropertyString);
        }
        else if (strcmp("RGBColor", item_propertyid->valuestring) == 0)
        {
            cJSON *item_RGBColor = cJSON_CreateObject();
            if (item_RGBColor == NULL)
            {
                cJSON_Delete(request_root);
                cJSON_Delete(response_root);

                return -1;
            }
            cJSON_AddNumberToObject(item_RGBColor, "Red", p_living_platform_tsl_data->RGB.R);
            cJSON_AddNumberToObject(item_RGBColor, "Green", p_living_platform_tsl_data->RGB.G);
            cJSON_AddNumberToObject(item_RGBColor, "Blue", p_living_platform_tsl_data->RGB.B);

            cJSON_AddItemToObject(response_root, "RGBColor", item_RGBColor);
        }
    }
    cJSON_Delete(request_root);

    *response = cJSON_PrintUnformatted(response_root);
    if (*response == NULL)
    {
        living_platform_info("No Enough Memory");
        cJSON_Delete(response_root);
        return -1;
    }
    cJSON_Delete(response_root);
    *response_len = strlen(*response);

    living_platform_info("Property Get Response: %s", *response);

    return SUCCESS_RETURN;
}
#endif

//When code is not 200,maybe call this function
static int user_property_cloud_error_handler(const int code, const char *data, const char *detail)
{
    living_platform_info("code =%d ,data=%s, detail=%s", code, data, detail);

    return 0;
}

/**
 * @brief 解析所有属性设置的值
 * @param request 指向属性设置请求payload的指针
 * @param request_len 属性设置请求的payload长度
 * @return 解析成功: 0, 解析失败: <0
 */
int32_t app_parse_property(const char *request, uint32_t request_len)
{
    cJSON *lightswitch = NULL;
    cJSON *rgbcolor = NULL;
    cJSON *nightlightswitch = NULL;
    cJSON *workmode = NULL;
    cJSON *brightness = NULL;
    cJSON *worktime = NULL;
    cJSON *floatid = NULL;
    cJSON *doubleid = NULL;
    cJSON *propertystring = NULL;

    cJSON *req = cJSON_Parse(request);
    if (req == NULL || !cJSON_IsObject(req))
    {
        return -0x911;
    }

    lightswitch = cJSON_GetObjectItem(req, "LightSwitch");
    if (lightswitch != NULL && cJSON_IsNumber(lightswitch))
    {
        /* process property LightSwitch here */

        living_platform_info("property id: LightSwitch, value: %d", lightswitch->valueint);
        living_platform_ut_set_LightSwitch(lightswitch->valueint);
    }

    rgbcolor = cJSON_GetObjectItem(req, "RGBColor");
    if (rgbcolor != NULL && cJSON_IsObject(rgbcolor))
    {
        /* process property RGBColor here */
        cJSON *R = cJSON_GetObjectItem(rgbcolor, "Red");
        cJSON *G = cJSON_GetObjectItem(rgbcolor, "Green");
        cJSON *B = cJSON_GetObjectItem(rgbcolor, "Blue");

        if ((R != NULL && cJSON_IsNumber(R)) &&
            (G != NULL && cJSON_IsNumber(G)) &&
            (B != NULL && cJSON_IsNumber(B)))
        {
            living_platform_info("struct property id: RGBColor R:%d G:%d B:%d", R->valueint, G->valueint, B->valueint);
            living_platform_ut_set_RGB(R->valueint, G->valueint, B->valueint);
        }
    }

    nightlightswitch = cJSON_GetObjectItem(req, "NightLightSwitch");
    if (nightlightswitch != NULL && cJSON_IsNumber(nightlightswitch))
    {
        /* process property NightLightSwitch here */

        living_platform_info("property id: NightLightSwitch, value: %d", nightlightswitch->valueint);
        living_platform_ut_set_NightLightSwitch(nightlightswitch->valueint);
    }

    workmode = cJSON_GetObjectItem(req, "WorkMode");
    if (workmode != NULL && cJSON_IsNumber(workmode))
    {
        /* process property WorkMode here */

        living_platform_info("property id: WorkMode, value: %d", workmode->valueint);
        living_platform_ut_set_WorkMode(workmode->valueint);
    }

    brightness = cJSON_GetObjectItem(req, "Brightness");
    if (brightness != NULL && cJSON_IsNumber(brightness))
    {
        /* process property Brightness here */

        living_platform_info("property id: Brightness, value: %d", brightness->valueint);
        living_platform_ut_set_Brightness(brightness->valueint);
    }

    worktime = cJSON_GetObjectItem(req, "worktime");
    if (worktime != NULL && cJSON_IsString(worktime))
    {
        /* process property worktime here */

        living_platform_info("property id: worktime, value: %s", worktime->valuestring);
        living_platform_ut_set_WorkTime(worktime->valuestring);
    }

    floatid = cJSON_GetObjectItem(req, "floatid");
    if (floatid != NULL && cJSON_IsNumber(floatid))
    {
        /* process property float here */

        living_platform_info("property id: float, value: %f", floatid->valuedouble);
        living_platform_ut_set_Float(floatid->valuedouble);
    }

    doubleid = cJSON_GetObjectItem(req, "doubleid");
    if (doubleid != NULL && cJSON_IsNumber(doubleid))
    {
        /* process property double here */

        living_platform_info("property id: double, value: %f", doubleid->valuedouble);
        living_platform_ut_set_Double(doubleid->valuedouble);
    }

    propertystring = cJSON_GetObjectItem(req, "PropertyString");
    if (propertystring != NULL && cJSON_IsString(propertystring))
    {
        /* process property PropertyString here */

        living_platform_info("property id: PropertyString, value: %s", propertystring->valuestring);
        living_platform_ut_set_PropertyString(propertystring->valuestring);
    }

    cJSON_Delete(req);
    return 0;
}

static int user_property_set_event_handler(const int devid, const char *request, const int request_len)
{
    int res = 0;
    living_platform_ctx_t *living_platform_ctx = living_platform_get_ctx();
    living_platform_info("Property Set Received, Devid: %d, Request: %s", devid, request);

    app_parse_property(request, request_len);
    res = IOT_Linkkit_Report(living_platform_ctx->master_devid, ITM_MSG_POST_PROPERTY,
                             (unsigned char *)request, request_len);

    living_platform_info("Post Property Message ID: %d", res);

    return 0;
}

static int user_report_reply_event_handler(const int devid, const int msgid, const int code, const char *reply,
                                           const int reply_len)
{
    const char *reply_value = (reply == NULL) ? ("NULL") : (reply);
    const int reply_value_len = (reply_len == 0) ? (strlen("NULL")) : (reply_len);

    living_platform_info("Message Post Reply Received, Devid: %d, Message ID: %d, Code: %d, Reply: %.*s", devid, msgid, code,
            reply_value_len,
            reply_value);
    return 0;
}

static int user_trigger_event_reply_event_handler(const int devid, const int msgid, const int code, const char *eventid,
                                                  const int eventid_len, const char *message, const int message_len)
{
    living_platform_info("Trigger Event Reply Received, Devid: %d, Message ID: %d, Code: %d, EventID: %.*s, Message: %.*s", devid,
            msgid, code,
            eventid_len,
            eventid, message_len, message);

    return 0;
}

static int user_timestamp_reply_event_handler(const char *timestamp)
{
    living_platform_info("Current Timestamp: %s", timestamp);

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

static int living_platform_ut_query_timestamp(void)
{
    living_platform_ctx_t *living_platform_ctx = living_platform_get_ctx();
    living_platform_info("do query timestamp");

    IOT_Linkkit_Query(living_platform_ctx->master_devid, ITM_MSG_QUERY_TIMESTAMP, NULL, 0);

    return 0;
}

static int user_initialized(const int devid)
{
    living_platform_ctx_t *living_platform_ctx = living_platform_get_ctx();
    living_platform_info("Device Initialized, Devid: %d", devid);

    if (living_platform_ctx->master_devid == devid)
    {
        living_platform_ctx->master_initialized = 1;
    }

    return 0;
}

static int user_master_dev_available(void)
{
    living_platform_ctx_t *living_platform_ctx = living_platform_get_ctx();

    if (living_platform_ctx->cloud_connected && living_platform_ctx->master_initialized)
    {
        return 1;
    }

    return 0;
}

static int living_platform_notify_msg_handle(int devid, const char *request, const int request_len)
{
    int ret = 0;
    cJSON *request_root = NULL;
    cJSON *item = NULL;

    request_root = cJSON_Parse(request);
    if (request_root == NULL)
    {
        living_platform_info("JSON Parse Error");
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
                living_platform_info("Device Bind");
                //TODO:User can do something according thier own requirements
            }
            else if (!strcmp(op->valuestring, "Unbind"))
            {
                living_platform_info("Device unBind");
                //TODO:User can do something according thier own requirements
            }
            else if (!strcmp(op->valuestring, "Reset"))
            {
                living_platform_info("Device reset");
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
    living_platform_ctx_t *living_platform_ctx = living_platform_get_ctx();
    living_platform_info("Event notify Received, Devid: %d, Request: %s", devid, request);

    living_platform_notify_msg_handle(devid, request, request_len);
    res = IOT_Linkkit_Report(living_platform_ctx->master_devid, ITM_MSG_EVENT_NOTIFY_REPLY,
                             (unsigned char *)request, request_len);
    living_platform_info("Post Property Message ID: %d", res);

    return 0;
}

static int user_fota_event_handler(int type, const char *version)
{
    char *p_fota_buffer = NULL;
    living_platform_ctx_t *living_platform_ctx = living_platform_get_ctx();

    p_fota_buffer = HAL_Malloc(LIVING_PLATFORM_OTA_BUFFER_LEN);
    if (!p_fota_buffer)
    {
        living_platform_err("no mem");
        return -1;
    }

    if (type == 0)
    {
        living_platform_info("New Firmware Version: %s", version);
        memset(p_fota_buffer, 0, LIVING_PLATFORM_OTA_BUFFER_LEN);
        IOT_Linkkit_Query(living_platform_ctx->master_devid, ITM_MSG_QUERY_FOTA_DATA, (unsigned char *)p_fota_buffer, LIVING_PLATFORM_OTA_BUFFER_LEN);
    }

    if (p_fota_buffer)
        HAL_Free(p_fota_buffer);

    return 0;
}

static int user_cota_event_handler(int type, const char *config_id, int config_size, const char *get_type,
                                   const char *sign, const char *sign_method, const char *url)
{
    char *p_cota_buffer = NULL;
    living_platform_ctx_t *living_platform_ctx = living_platform_get_ctx();

    p_cota_buffer = HAL_Malloc(LIVING_PLATFORM_OTA_BUFFER_LEN);
    if (!p_cota_buffer)
    {
        living_platform_err("no mem");
        return -1;
    }

    if (type == 0)
    {
        living_platform_info("New Config ID: %s", config_id);
        living_platform_info("New Config Size: %d", config_size);
        living_platform_info("New Config Type: %s", get_type);
        living_platform_info("New Config Sign: %s", sign);
        living_platform_info("New Config Sign Method: %s", sign_method);
        living_platform_info("New Config URL: %s", url);

        IOT_Linkkit_Query(living_platform_ctx->master_devid, ITM_MSG_QUERY_COTA_DATA, (unsigned char *)p_cota_buffer, LIVING_PLATFORM_OTA_BUFFER_LEN);
    }

    if (p_cota_buffer)
        HAL_Free(p_cota_buffer);

    return 0;
}

static int user_offline_reset_handler(void)
{
    living_platform_info("user callback user_offline_reset_handler called.");

    return 0;
}

static int user_dev_bind_event(const int state_code, const char *state_message)
{
    living_platform_info("state_code: -0x%04x, str_msg= %s", -state_code, state_message == NULL ? "NULL" : state_message);
    return 0;
}

#ifdef DM_UNIFIED_SERVICE_POST
static int user_unified_service_post_reply_handler(const int devid, const int id, const int code, const char *payload, const int payload_len)
{
    living_platform_info("Receive unified service post reply, code:%d, payload:%s", code, payload);

    return 0;
}
#endif

static iotx_linkkit_dev_meta_info_t *living_platform_main_init(living_platform_ctx_t *living_platform_ctx)
{
    int register_type = 0;
    int post_event_reply = 1;
    iotx_linkkit_dev_meta_info_t *p_master_meta = NULL;

    memset(living_platform_ctx, 0, sizeof(living_platform_ctx_t));

    p_master_meta = HAL_Malloc(sizeof(iotx_linkkit_dev_meta_info_t));
    if (p_master_meta == NULL)
    {
        living_platform_err("no mem");
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

#ifdef LIVING_PLATFORM_PRODUCT_DYNAMIC_REGISTER
    register_type = 1;
#endif

    /* Register Callback */
    IOT_RegisterCallback(ITE_INITIALIZE_COMPLETED, user_initialized);
    IOT_RegisterCallback(ITE_CONNECT_SUCC, user_connected_event_handler);
    IOT_RegisterCallback(ITE_DISCONNECTED, user_disconnected_event_handler);
    IOT_RegisterCallback(ITE_RAWDATA_ARRIVED, user_down_raw_data_arrived_event_handler);
#ifndef LINK_VISUAL_ENABLE
    IOT_RegisterCallback(ITE_SERVICE_REQUEST, user_service_request_event_handler);
#endif
    IOT_RegisterCallback(ITE_PROPERTY_SET, user_property_set_event_handler);
#ifdef ALCS_ENABLED
    /*Only for local communication service(ALCS)*/
    IOT_RegisterCallback(ITE_PROPERTY_GET, user_property_get_event_handler);
#endif
    IOT_RegisterCallback(ITE_REPORT_REPLY, user_report_reply_event_handler);
    IOT_RegisterCallback(ITE_TRIGGER_EVENT_REPLY, user_trigger_event_reply_event_handler);
    IOT_RegisterCallback(ITE_TIMESTAMP_REPLY, user_timestamp_reply_event_handler);

    IOT_RegisterCallback(ITE_CLOUD_ERROR, user_property_cloud_error_handler);

    IOT_RegisterCallback(ITE_FOTA, user_fota_event_handler);
    IOT_RegisterCallback(ITE_COTA, user_cota_event_handler);

    IOT_RegisterCallback(ITE_EVENT_NOTIFY, user_event_notify_handler);
    IOT_RegisterCallback(ITE_STATE_DEV_BIND, user_dev_bind_event);

    IOT_RegisterCallback(ITE_OFFLINE_RESET, user_offline_reset_handler);

#ifdef DM_UNIFIED_SERVICE_POST
    IOT_RegisterCallback(ITE_UNIFIED_SERVICE_POST, user_unified_service_post_reply_handler);
#endif

    IOT_Ioctl(IOTX_IOCTL_SET_DYNAMIC_REGISTER, (void *)&register_type);

    /* Choose Whether You Need Post Property/Event Reply */
    IOT_Ioctl(IOTX_IOCTL_RECV_EVENT_REPLY, (void *)&post_event_reply);

#ifdef LIVING_PLATFORM_USE_UT_FOR_TESTING
    living_platform_ut_init();
#endif

    return p_master_meta;
}

int living_platform_main(void *paras)
{
    int res = 0;
    uint64_t time_prev_sec = 0, time_now_sec = 0;
    living_platform_ctx_t *living_platform_ctx = living_platform_get_ctx();
    iotx_linkkit_dev_meta_info_t *p_master_meta = NULL;

    p_master_meta = living_platform_main_init(living_platform_ctx);
    if (NULL == p_master_meta)
    {
        printf("OOPS:living_platform_main_init failed");
        return -1;
    }

    /* Create Master Device Resources */
    do
    {
        living_platform_ctx->master_devid = IOT_Linkkit_Open(IOTX_LINKKIT_DEV_TYPE_MASTER, p_master_meta);
        if (living_platform_ctx->master_devid < 0)
        {
            printf("IOT_Linkkit_Open Failed, retry after 5s...\r\n");
            HAL_SleepMs(5000);
        }
    } while (living_platform_ctx->master_devid < 0);
    /* Start Connect Aliyun Server */
    do
    {
        res = IOT_Linkkit_Connect(living_platform_ctx->master_devid);
        if (res < 0)
        {
            printf("IOT_Linkkit_Connect Failed, retry after 5s...\r\n");
            HAL_SleepMs(5000);
        }
    } while (res < 0);

    living_platform_ut_query_timestamp();

    while (1)
    {
        IOT_Linkkit_Yield(LIVING_PLATFORM_YIELD_TIMEOUT_MS);

        time_now_sec = user_update_sec();
        if (time_prev_sec == time_now_sec)
        {
            continue;
        }

        if (user_master_dev_available())
        {
            #ifdef LIVING_PLATFORM_USE_UT_FOR_TESTING
            living_platform_ut_misc_process(time_now_sec);
            #endif
        }

        time_prev_sec = time_now_sec;
    }

    //Should never come here
    living_platform_ctx->g_user_dispatch_thread_running = 0;

    if (p_master_meta)
    {
        HAL_Free(p_master_meta);
    }

    IOT_DumpMemoryStats(IOT_LOG_DEBUG);

    return 0;
}

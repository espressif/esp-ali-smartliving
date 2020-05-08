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
#include "iotx_utils.h"
#include "iotx_dm.h"
#include <iotx_log.h>

#if defined(OTA_ENABLED) && defined(BUILD_AOS)
#include "ota_service.h"
#endif

#define gateway_debug(...) log_debug("gateway", __VA_ARGS__)
#define gateway_info(...) log_info("gateway", __VA_ARGS__)
#define gateway_warn(...) log_warning("gateway", __VA_ARGS__)
#define gateway_err(...) log_err("gateway", __VA_ARGS__)
#define gateway_crit(...) log_crit("gateway", __VA_ARGS__)

#define GATEWAY_YIELD_TIMEOUT_MS (200)
#define GATEWAY_SUBDEV_MAX_NUM (2)

//You should undefine this Macro in your products
#define GATEWAY_UT_TEST
//#define GATEWAY_CALL_SDK_API_EXAMPLE

typedef struct
{
    int master_devid;
    int cloud_connected;
    int master_initialized;
    int subdev_index;
    int permit_join;
    void *g_user_dispatch_thread;
    int g_user_dispatch_thread_running;
} gateway_ctx_t;

static gateway_ctx_t g_gateway_ctx;

#ifdef GATEWAY_UT_TEST
//This example sub dev mate mainly for CI
//Attation:Please remove these codes from your products
//You have to burn your meta info use your way
static iotx_linkkit_dev_meta_info_t subdevArr[GATEWAY_SUBDEV_MAX_NUM] = {
#ifdef REGION_SINGAPORE
    {"PK_SUB_1",
     "PS_SUB_1",
     "DN_SUB_1",
     "DS_SUB_1"},
    {"PK_SUB_2",
     "PS_SUB_2",
     "DN_SUB_2",
     "DS_SUB_2"},
#else /* Mainland(Shanghai) for default */
    {"PK_SUB_3",
     "PS_SUB_3",
     "DN_SUB_3",
     "DS_SUB_3"},
    {"PK_SUB_4",
     "PS_SUB_4",
     "DN_SUB_4",
     "DS_SUB_4"},
#endif
};
#endif

static gateway_ctx_t *gateway_get_ctx(void)
{
    return &g_gateway_ctx;
}

static int user_connected_event_handler(void)
{
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();

    gateway_info("Cloud Connected");

    gateway_ctx->cloud_connected = 1;
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

    res = IOT_Linkkit_Report(gateway_ctx->master_devid, ITM_MSG_POST_PROPERTY,
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

//Just for reference
void user_post_property(void)
{
    int res = 0;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    char *property_payload = "{\"LightSwitch\":1}";

    res = IOT_Linkkit_Report(gateway_ctx->master_devid, ITM_MSG_POST_PROPERTY,
                             (unsigned char *)property_payload, strlen(property_payload));

    gateway_info("Post Property Message ID: %d", res);
}

//Just for reference
void user_post_sub_property(int subdev_id)
{
    int res = 0;
    char *property_payload = "{\"LightSwitch\":1}";

    res = IOT_Linkkit_Report(subdev_id, ITM_MSG_POST_PROPERTY,
                             (unsigned char *)property_payload, strlen(property_payload));

    gateway_info("Post Property Message ID: %d", res);
}

//Just for reference
void user_post_event(void)
{
    int res = 0;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    char *event_id = "Error";
    char *event_payload = "{\"ErrorCode\":0}";

    res = IOT_Linkkit_TriggerEvent(gateway_ctx->master_devid, event_id, strlen(event_id),
                                   event_payload, strlen(event_payload));
    gateway_info("Post Event Message ID: %d", res);
}

//Just for reference
void user_deviceinfo_update(void)
{
    int res = 0;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    char *device_info_update = "[{\"attrKey\":\"gateway\",\"attrValue\":\"I am a gateway\"},{\"attrKey\":\"subdev\",\"attrValue\":\"I am a subdev\"}]";

    res = IOT_Linkkit_Report(gateway_ctx->master_devid, ITM_MSG_DEVICEINFO_UPDATE,
                             (unsigned char *)device_info_update, strlen(device_info_update));
    gateway_info("Device Info Update Message ID: %d", res);
}

//Just for reference
void user_deviceinfo_delete(void)
{
    int res = 0;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    char *device_info_delete = "[{\"attrKey\":\"subdev\"}]";

    res = IOT_Linkkit_Report(gateway_ctx->master_devid, ITM_MSG_DEVICEINFO_DELETE,
                             (unsigned char *)device_info_delete, strlen(device_info_delete));
    gateway_info("Device Info Delete Message ID: %d", res);
}

//Just for reference
void user_post_raw_data(void)
{
    int res = 0;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    //raw_data is ASCII of [This is raw data.]
    unsigned char raw_data[] = {0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x72, 0x61, 0x77, 0x20, 0x64, 0x61, 0x74, 0x61, 0x2E};

    res = IOT_Linkkit_Report(gateway_ctx->master_devid, ITM_MSG_POST_RAW_DATA,
                             raw_data, sizeof(raw_data));

    gateway_info("Post Raw Data Message ID: %d", res);
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

static int user_event_notify_handler(const int devid, const char *request, const int request_len)
{
    int res = 0;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    gateway_info("Event notify Received, Devid: %d, Request: %s", devid, request);

    res = IOT_Linkkit_Report(gateway_ctx->master_devid, ITM_MSG_EVENT_NOTIFY_REPLY,
                             (unsigned char *)request, request_len);
    gateway_info("Post Property Message ID: %d", res);

    return 0;
}

//get topo list reply
static int user_topolist_reply_handler(const int devid, const int id, const int code, const char *payload, const int payload_len)
{
    gateway_info("Receive topolist reply, code:%d, payload:%s", code, payload);

    return 0;
}

static int user_subdev_misc_reply_handler(const int devid, const int event_id, const int code, const char *payload, const int payload_len)
{
    gateway_info("Receive subdev misc reply, code:%d, payload:%s", code, payload);
    switch (event_id)
    {
    case IOTX_DM_EVENT_TOPO_DELETE_REPLY:
    {
        gateway_info("IOTX_DM_EVENT_TOPO_DELETE_REPLY, devid:%d code:%d, payload:%s", devid, code, payload);
        if (200 == code)
        {
            IOT_Linkkit_Close(devid); //remove subdev from dm(device manager)
        }
    }
    break;
    case IOTX_DM_EVENT_SUBDEV_RESET_REPLY:
    {
        gateway_info("IOTX_DM_EVENT_SUBDEV_RESET_REPLY, devid:%d code:%d, payload:%s", devid, code, payload);
    }
    break;
    case IOTX_DM_EVENT_TOPO_ADD_REPLY:
    {
        gateway_info("IOTX_DM_EVENT_TOPO_ADD_REPLY, devid:%d code:%d, payload:%s", devid, code, payload);
    }
    break;
    case IOTX_DM_EVENT_COMBINE_LOGIN_REPLY:
    {
        gateway_info("IOTX_DM_EVENT_COMBINE_LOGIN_REPLY, devid:%d code:%d, payload:%s", devid, code, payload);
    }
    break;
    case IOTX_DM_EVENT_COMBINE_LOGOUT_REPLY:
    {
        gateway_info("IOTX_DM_EVENT_COMBINE_LOGOUT_REPLY, devid:%d code:%d, payload:%s", devid, code, payload);
    }
    break;
    default:
        break;
    }
    return 0;
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

int user_permit_join_event_handler(const char *product_key, const int time)
{
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();

    gateway_info("Product Key: %s, Time: %d", product_key, time);

    gateway_ctx->permit_join = 0;

    return 0;
}

void *user_dispatch_yield(void *args)
{
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();

    while (gateway_ctx->g_user_dispatch_thread_running)
    {
        IOT_Linkkit_Yield(GATEWAY_YIELD_TIMEOUT_MS);
    }

    return NULL;
}

//This is example for add one subdev
static int gateway_add_subdev(iotx_linkkit_dev_meta_info_t *subdev_mate)
{
    int res = 0;
    int devid = -1;

    devid = IOT_Linkkit_Open(IOTX_LINKKIT_DEV_TYPE_SLAVE, subdev_mate);
    if (devid == FAIL_RETURN)
    {
        gateway_info("subdev open Failed\n");
        return FAIL_RETURN;
    }
    gateway_info("subdev open susseed, devid = %d\n", devid);

    res = IOT_Linkkit_Connect(devid);
    if (res == FAIL_RETURN)
    {
        gateway_info("subdev connect Failed\n");
        return res;
    }
    gateway_info("subdev connect success: devid = %d\n", devid);

    res = IOT_Linkkit_Report(devid, ITM_MSG_LOGIN, NULL, 0);
    if (res == FAIL_RETURN)
    {
        gateway_info("subdev login Failed\n");
        return res;
    }

#if 0 //TODO:This is for sub dev ota function
#if defined(OTA_ENABLED) && defined(BUILD_AOS)
    static ota_service_t ctx = {0};
    memset(&ctx, 0, sizeof(ota_service_t));
    strncpy(ctx.pk, meta_info->product_key, sizeof(ctx.pk) - 1);
    strncpy(ctx.dn, meta_info->device_name, sizeof(ctx.dn) - 1);
    strncpy(ctx.ds, meta_info->product_secret, sizeof(ctx.ds) - 1);
    ctx.trans_protcol = 0;
    ctx.dl_protcol = 3;
    ctx.dev_type = 1;
    ota_service_init(&ctx);
#endif
#endif

    return res;
}

#ifdef GATEWAY_CALL_SDK_API_EXAMPLE
//This is example for testing of del a subdev
static int gateway_del_subdev(iotx_linkkit_dev_meta_info_t *subdev_mate)
{
    int subdev_id = 1000; //set an not exist subdev id
    int ret = -1;

    gateway_info("do del subdev");

    //Here pk and dn of subdev is priorior than subdev id
    ret = IOT_Linkkit_Report(subdev_id, ITM_MSG_DELETE_TOPO, (unsigned char *)subdev_mate, sizeof(iotx_linkkit_dev_meta_info_t));
    if (SUCCESS_RETURN != ret)
    {
        gateway_err("del subdev failed");
    }

    return 0;
}

//This is example for testing of reset a subdev
static int gateway_reset_subdev(iotx_linkkit_dev_meta_info_t *subdev_mate)
{
    int subdev_id = 1000; //set an not exist subdev id
    int ret = 0;

    gateway_info("do reset subdev");

    //Here pk and dn of subdev is priorior than subdev id
    ret = IOT_Linkkit_Report(subdev_id, ITM_MSG_SUBDEV_RESET, (unsigned char *)subdev_mate, sizeof(iotx_linkkit_dev_meta_info_t));
    if (SUCCESS_RETURN != ret)
    {
        gateway_err("reset subdev failed");
    }

    return ret;
}

//This is an example for get topolist info
//you can get topo list info in func:user_topolist_reply_handler
static int gateway_update_subdev(void)
{
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    gateway_info("do update subdev");

    IOT_Linkkit_Query(gateway_ctx->master_devid, ITM_MSG_QUERY_TOPOLIST, NULL, 0);

    return 0;
}

//This is example for query subdev id by PK and DN
static int gateway_query_subdev_id(iotx_linkkit_dev_meta_info_t *subdev_mate)
{
    int subdev_id = -1; //set an not exist subdev id
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    gateway_info("query subdev id");

    subdev_id = IOT_Linkkit_Query(gateway_ctx->master_devid, ITM_MSG_QUERY_SUBDEV_ID, (unsigned char *)subdev_mate, sizeof(iotx_linkkit_dev_meta_info_t));
    if (subdev_id < 0)
    {
        gateway_err("subdev not exist");
    }
    else
    {
        gateway_info("got subdev id is %d", subdev_id);
    }

    return subdev_id;
}
#endif

static iotx_linkkit_dev_meta_info_t *gateway_main_init(gateway_ctx_t *gateway_ctx)
{
    int domain_type = IOTX_CLOUD_REGION_SINGAPORE;
    int dynamic_register = 0; //0:You have to burn DS for each devices,1:Request DS from cloud by https
    int post_event_reply = 1;
    iotx_linkkit_dev_meta_info_t *p_master_meta = NULL;

    memset(gateway_ctx, 0, sizeof(gateway_ctx_t));
    gateway_ctx->permit_join = 1;

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

    IOT_RegisterCallback(ITE_INITIALIZE_COMPLETED, user_initialized);
    IOT_RegisterCallback(ITE_PERMIT_JOIN, user_permit_join_event_handler);
    IOT_RegisterCallback(ITE_CLOUD_ERROR, user_property_cloud_error_handler);
    IOT_RegisterCallback(ITE_EVENT_NOTIFY, user_event_notify_handler);

    IOT_RegisterCallback(ITE_TOPOLIST_REPLY, user_topolist_reply_handler);
    IOT_RegisterCallback(ITE_SUBDEV_MISC_OPS, user_subdev_misc_reply_handler);

#ifdef REGION_SINGAPORE
    domain_type = IOTX_CLOUD_REGION_SINGAPORE;
#elif REGION_GERMANY
    domain_type = IOTX_CLOUD_REGION_GERMANY;
#else /* Mainland(Shanghai) for default */
    domain_type = IOTX_CLOUD_REGION_SHANGHAI;
#endif

    IOT_Ioctl(IOTX_IOCTL_SET_DOMAIN, (void *)&domain_type);

    IOT_Ioctl(IOTX_IOCTL_SET_DYNAMIC_REGISTER, (void *)&dynamic_register);

    /* Choose Whether You Need Post Property/Event Reply */
    IOT_Ioctl(IOTX_IOCTL_RECV_EVENT_REPLY, (void *)&post_event_reply);

    return p_master_meta;
}

int linkkit_main(void *paras)
{
    int res = 0;
    uint64_t time_prev_sec = 0, time_now_sec = 0;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    iotx_linkkit_dev_meta_info_t *p_master_meta = NULL;

//Attation:Please remove these codes from your products
//You have to burn your meta info use your way
#ifdef GATEWAY_UT_TEST
#define PRODUCT_KEY "MASTER_DEVICE_PK"
#define PRODUCT_SECRET "MASTER_DEVICE_PS"
#define DEVICE_NAME "MASTER_DEVICE_DN"
#define DEVICE_SECRET "MASTER_DEVICE_DS"

    HAL_SetProductKey(PRODUCT_KEY);
    HAL_SetProductSecret(PRODUCT_SECRET);
    HAL_SetDeviceName(DEVICE_NAME);
    HAL_SetDeviceSecret(DEVICE_SECRET);
#endif

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
    res = HAL_ThreadCreate(&gateway_ctx->g_user_dispatch_thread, user_dispatch_yield, NULL, NULL, NULL);
    if (res < 0)
    {
        gateway_info("HAL_ThreadCreate Failed\n");
        IOT_Linkkit_Close(gateway_ctx->master_devid);
        return -1;
    }

    while (1)
    {
        time_now_sec = user_update_sec();
        if (time_prev_sec == time_now_sec)
        {
            continue;
        }

#ifdef GATEWAY_UT_TEST
        HAL_SleepMs(GATEWAY_YIELD_TIMEOUT_MS);

        /* Add subdev */
        if (gateway_ctx->cloud_connected && gateway_ctx->permit_join && (gateway_ctx->subdev_index < GATEWAY_SUBDEV_MAX_NUM))
        {
            /* Add next subdev */
            if (gateway_add_subdev(&subdevArr[gateway_ctx->subdev_index]) == SUCCESS_RETURN)
            {
                gateway_info("subdev DN:%s add succeed", subdevArr[gateway_ctx->subdev_index].device_name);
            }
            else
            {
                gateway_info("subdev DN:%s add failed", subdevArr[gateway_ctx->subdev_index].device_name);
            }

            gateway_ctx->subdev_index++;
        }

        /* Post Proprety Example */
        if (time_now_sec % 11 == 0 && user_master_dev_available())
        {
            user_post_property();
            user_post_sub_property(gateway_ctx->subdev_index);
        }
        /* Post Event Example */
        if (time_now_sec % 17 == 0 && user_master_dev_available())
        {
            user_post_event();
        }

        /* Device Info Update Example */
        if (time_now_sec % 23 == 0 && user_master_dev_available())
        {
            user_deviceinfo_update();
        }

        /* Device Info Delete Example */
        if (time_now_sec % 29 == 0 && user_master_dev_available())
        {
            user_deviceinfo_delete();
        }

        /* Post Raw Example */
        if (time_now_sec % 37 == 0 && user_master_dev_available())
        {
            user_post_raw_data();
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

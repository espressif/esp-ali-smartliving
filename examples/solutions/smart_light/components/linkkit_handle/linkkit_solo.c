
/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

void HAL_Printf(const char *fmt, ...);
int HAL_Snprintf(char *str, const int len, const char *fmt, ...);

#ifdef DEPRECATED_LINKKIT
#include "solo.c"
#else
#include "iot_export_linkkit.h"
#include "cJSON.h"

#include "lightbulb.h"
#include "esp_log.h"

static const char* TAG = "linkkit_example_solo";

#define EXAMPLE_TRACE(...)                                          \
    do {                                                            \
        HAL_Printf("\033[1;32;40m%s.%d: ", __func__, __LINE__);     \
        HAL_Printf(__VA_ARGS__);                                    \
        HAL_Printf("\033[0m\r\n");                                  \
    } while (0)

#define EXAMPLE_MASTER_DEVID            (0)
#define EXAMPLE_YIELD_TIMEOUT_MS        (200)

typedef struct {
    int master_devid;
    int cloud_connected;
    int master_initialized;
} user_example_ctx_t;

/**
 * These PRODUCT_KEY|PRODUCT_SECRET|DEVICE_NAME|DEVICE_SECRET are listed for demo only
 *
 * When you created your own devices on iot.console.com, you SHOULD replace them with what you got from console
 *
 */

char PRODUCT_KEY[PRODUCT_KEY_MAXLEN] = {0};
char PRODUCT_SECRET[PRODUCT_SECRET_MAXLEN] = {0};
char DEVICE_NAME[DEVICE_NAME_MAXLEN] = {0};
char DEVICE_SECRET[DEVICE_SECRET_MAXLEN] = {0};

static user_example_ctx_t g_user_example_ctx;

/** Awss Status event callback */
static int user_awss_status_event_handler(int status)
{
    EXAMPLE_TRACE("Awss Status %d", status);

    return SUCCESS_RETURN;
}

/** cloud connected event callback */
static int user_connected_event_handler(void)
{
    EXAMPLE_TRACE("Cloud Connected");
    g_user_example_ctx.cloud_connected = 1;

    return 0;
}

/** cloud connect fail event callback */
static int user_connect_fail_event_handler(void) 
{
    EXAMPLE_TRACE("Cloud Connect Fail");

    return SUCCESS_RETURN;
}

/** cloud disconnected event callback */
static int user_disconnected_event_handler(void)
{
    EXAMPLE_TRACE("Cloud Disconnected");
    g_user_example_ctx.cloud_connected = 0;

    return 0;
}

/** cloud raw_data arrived event callback */
static int user_rawdata_arrived_event_handler(const int devid, const unsigned char *request, const int request_len)
{
    EXAMPLE_TRACE("Cloud Rawdata Arrived");

    return 0;
}

/* device initialized event callback */
static int user_initialized(const int devid)
{
    EXAMPLE_TRACE("Device Initialized");
    g_user_example_ctx.master_initialized = 1;

    return 0;
}

/** recv property post response message from cloud **/
static int user_report_reply_event_handler(const int devid, const int msgid, const int code, const char *reply,
        const int reply_len)
{
    EXAMPLE_TRACE("Message Post Reply Received, Message ID: %d, Code: %d, Reply: %.*s", msgid, code,
                  reply_len,
                  (reply == NULL)? ("NULL") : (reply));
    return 0;
}

/** recv event post response message from cloud **/
static int user_trigger_event_reply_event_handler(const int devid, const int msgid, const int code, const char *eventid,
        const int eventid_len, const char *message, const int message_len)
{
    EXAMPLE_TRACE("Trigger Event Reply Received, Message ID: %d, Code: %d, EventID: %.*s, Message: %.*s",
                  msgid, code,
                  eventid_len,
                  eventid, message_len, message);

    return 0;
}

static int user_property_set_event_handler(const int devid, const char *request, const int request_len)
{
    int res = 0;
    cJSON *root = NULL, *LightSwitch = NULL, *LightColor = NULL;
    ESP_LOGI(TAG,"Property Set Received, Devid: %d, Request: %s", devid, request);
    
    lightbulb_set_brightness(78);
    lightbulb_set_saturation(100);
    
    if (!request) {
        return NULL_VALUE_ERROR;
    }

    /* Parse Root */
    root = cJSON_Parse(request);
    if (!root) {
        ESP_LOGI(TAG,"JSON Parse Error");
        return FAIL_RETURN;
    }

    /** Switch Lightbulb On/Off   */
    LightSwitch = cJSON_GetObjectItem(root, "LightSwitch");
    if (LightSwitch) {
        lightbulb_set_on(LightSwitch->valueint);
    } 

    /** Switch Lightbulb Hue */
    LightSwitch = cJSON_GetObjectItem(root, "RGBColor");
    if (LightSwitch) {
        LightColor = cJSON_GetObjectItem(LightSwitch, "Red");
        lightbulb_set_hue(LightColor ? LightColor->valueint : 0);
        LightColor = cJSON_GetObjectItem(LightSwitch, "Green");
        lightbulb_set_hue(LightColor ? LightColor->valueint : 120);
        LightColor = cJSON_GetObjectItem(LightSwitch, "Blue");
        lightbulb_set_hue(LightColor ? LightColor->valueint : 240);
    }
    
    cJSON_Delete(root);

    res = IOT_Linkkit_Report(EXAMPLE_MASTER_DEVID, ITM_MSG_POST_PROPERTY,
                             (unsigned char *)request, request_len);
    ESP_LOGI(TAG,"Post Property Message ID: %d", res);

    return SUCCESS_RETURN;
}

static int user_property_get_event_handler(const int devid, const char *request, const int request_len, char **response,
                                           int *response_len)
{
    cJSON *request_root = NULL, *item_propertyid = NULL;
    cJSON *response_root = NULL;
    int index = 0;
    EXAMPLE_TRACE("Property Get Received, Devid: %d, Request: %s", devid, request);

    /* Parse Request */
    request_root = cJSON_Parse(request);
    if (request_root == NULL || !cJSON_IsArray(request_root)) {
        EXAMPLE_TRACE("JSON Parse Error");
        return -1;
    }

    /* Prepare Response */
    response_root = cJSON_CreateObject();
    if (response_root == NULL) {
        EXAMPLE_TRACE("No Enough Memory");
        cJSON_Delete(request_root);
        return -1;
    }

    for (index = 0; index < cJSON_GetArraySize(request_root); index++) {
        item_propertyid = cJSON_GetArrayItem(request_root, index);
        if (item_propertyid == NULL || !cJSON_IsString(item_propertyid)) {
            EXAMPLE_TRACE("JSON Parse Error");
            cJSON_Delete(request_root);
            cJSON_Delete(response_root);
            return -1;
        }

        EXAMPLE_TRACE("Property ID, index: %d, Value: %s", index, item_propertyid->valuestring);

        if (strcmp("WIFI_Tx_Rate", item_propertyid->valuestring) == 0) {
            cJSON_AddNumberToObject(response_root, "WIFI_Tx_Rate", 1111);
        } else if (strcmp("WIFI_Rx_Rate", item_propertyid->valuestring) == 0) {
            cJSON_AddNumberToObject(response_root, "WIFI_Rx_Rate", 2222);
        } else if (strcmp("RGBColor", item_propertyid->valuestring) == 0) {
            cJSON *item_rgbcolor = cJSON_CreateObject();
            if (item_rgbcolor == NULL) {
                cJSON_Delete(request_root);
                cJSON_Delete(response_root);
                return -1;
            }
            cJSON_AddNumberToObject(item_rgbcolor, "Red", 100);
            cJSON_AddNumberToObject(item_rgbcolor, "Green", 100);
            cJSON_AddNumberToObject(item_rgbcolor, "Blue", 100);
            cJSON_AddItemToObject(response_root, "RGBColor", item_rgbcolor);
        } else if (strcmp("HSVColor", item_propertyid->valuestring) == 0) {
            cJSON *item_hsvcolor = cJSON_CreateObject();
            if (item_hsvcolor == NULL) {
                cJSON_Delete(request_root);
                cJSON_Delete(response_root);
                return -1;
            }
            cJSON_AddNumberToObject(item_hsvcolor, "Hue", 50);
            cJSON_AddNumberToObject(item_hsvcolor, "Saturation", 50);
            cJSON_AddNumberToObject(item_hsvcolor, "Value", 50);
            cJSON_AddItemToObject(response_root, "HSVColor", item_hsvcolor);
        } else if (strcmp("HSLColor", item_propertyid->valuestring) == 0) {
            cJSON *item_hslcolor = cJSON_CreateObject();
            if (item_hslcolor == NULL) {
                cJSON_Delete(request_root);
                cJSON_Delete(response_root);
                return -1;
            }
            cJSON_AddNumberToObject(item_hslcolor, "Hue", 70);
            cJSON_AddNumberToObject(item_hslcolor, "Saturation", 70);
            cJSON_AddNumberToObject(item_hslcolor, "Lightness", 70);
            cJSON_AddItemToObject(response_root, "HSLColor", item_hslcolor);
        } else if (strcmp("WorkMode", item_propertyid->valuestring) == 0) {
            cJSON_AddNumberToObject(response_root, "WorkMode", 4);
        } else if (strcmp("NightLightSwitch", item_propertyid->valuestring) == 0) {
            cJSON_AddNumberToObject(response_root, "NightLightSwitch", 1);
        } else if (strcmp("Brightness", item_propertyid->valuestring) == 0) {
            cJSON_AddNumberToObject(response_root, "Brightness", 30);
        } else if (strcmp("LightSwitch", item_propertyid->valuestring) == 0) {
            cJSON_AddNumberToObject(response_root, "LightSwitch", 1);
        } else if (strcmp("ColorTemperature", item_propertyid->valuestring) == 0) {
            cJSON_AddNumberToObject(response_root, "ColorTemperature", 2800);
        } else if (strcmp("PropertyCharacter", item_propertyid->valuestring) == 0) {
            cJSON_AddStringToObject(response_root, "PropertyCharacter", "testprop");
        } else if (strcmp("Propertypoint", item_propertyid->valuestring) == 0) {
            cJSON_AddNumberToObject(response_root, "Propertypoint", 50);
        } else if (strcmp("LocalTimer", item_propertyid->valuestring) == 0) {
            cJSON *array_localtimer = cJSON_CreateArray();
            if (array_localtimer == NULL) {
                cJSON_Delete(request_root);
                cJSON_Delete(response_root);
                return -1;
            }

            cJSON *item_localtimer = cJSON_CreateObject();
            if (item_localtimer == NULL) {
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
    if (*response == NULL) {
        EXAMPLE_TRACE("No Enough Memory");
        cJSON_Delete(response_root);
        return -1;
    }
    cJSON_Delete(response_root);
    *response_len = strlen(*response);

    EXAMPLE_TRACE("Property Get Response: %s", *response);

    return SUCCESS_RETURN;
}


static int user_service_request_event_handler(const int devid, const char *serviceid, const int serviceid_len,
        const char *request, const int request_len,
        char **response, int *response_len)
{
    int contrastratio = 0, to_cloud = 0;
    cJSON *root = NULL, *item_transparency = NULL, *item_from_cloud = NULL;
    ESP_LOGI(TAG,"Service Request Received, Devid: %d, Service ID: %.*s, Payload: %s", devid, serviceid_len,
                  serviceid,
                  request);

    /* Parse Root */
    root = cJSON_Parse(request);
    if (root == NULL || !cJSON_IsObject(root)) {
        ESP_LOGI(TAG,"JSON Parse Error");
        return -1;
    }

    if (strlen("Custom") == serviceid_len && memcmp("Custom", serviceid, serviceid_len) == 0) {
        /* Parse Item */
        const char *response_fmt = "{\"Contrastratio\":%d}";
        item_transparency = cJSON_GetObjectItem(root, "transparency");
        if (item_transparency == NULL || !cJSON_IsNumber(item_transparency)) {
            cJSON_Delete(root);
            return -1;
        }
        ESP_LOGI(TAG,"transparency: %d", item_transparency->valueint);
        contrastratio = item_transparency->valueint + 1;

        /* Send Service Response To Cloud */
        *response_len = strlen(response_fmt) + 10 + 1;
        *response = malloc(*response_len);
        if (*response == NULL) {
            ESP_LOGW(TAG,"Memory Not Enough");
            return -1;
        }
        memset(*response, 0, *response_len);
        snprintf(*response, *response_len, response_fmt, contrastratio);
        *response_len = strlen(*response);
    } else if (strlen("SyncService") == serviceid_len && memcmp("SyncService", serviceid, serviceid_len) == 0) {
        /* Parse Item */
        const char *response_fmt = "{\"ToCloud\":%d}";
        item_from_cloud = cJSON_GetObjectItem(root, "FromCloud");
        if (item_from_cloud == NULL || !cJSON_IsNumber(item_from_cloud)) {
            cJSON_Delete(root);
            return -1;
        }
        ESP_LOGI(TAG,"FromCloud: %d", item_from_cloud->valueint);
        to_cloud = item_from_cloud->valueint + 1;

        /* Send Service Response To Cloud */
        *response_len = strlen(response_fmt) + 10 + 1;
        *response = malloc(*response_len);
        if (*response == NULL) {
            ESP_LOGW(TAG,"Memory Not Enough");
            return -1;
        }
        memset(*response, 0, *response_len);
        snprintf(*response, *response_len, response_fmt, to_cloud);
        *response_len = strlen(*response);
    }
    cJSON_Delete(root);

    return 0;
}

static int user_timestamp_reply_event_handler(const char *timestamp)
{
    EXAMPLE_TRACE("Current Timestamp: %s", timestamp);

    return SUCCESS_RETURN;
}

static int user_topolist_reply_handler(const int devid, const int id, const int code, const char *payload, const int payload_len)
{
    EXAMPLE_TRACE("ITE_TOPOLIST_REPLY");

    return SUCCESS_RETURN;
}

static int user_permit_join_event_handler(const char *product_key, const int time)
{
    EXAMPLE_TRACE("ITE_PERMIT_JOIN");
    
    return SUCCESS_RETURN;
}

/** fota event handler **/
static int user_fota_event_handler(int type, const char *version)
{
    char buffer[1024] = {0};
    int buffer_length = 1024;

    /* 0 - new firmware exist, query the new firmware */
    if (type == 0) {
        EXAMPLE_TRACE("New Firmware Version: %s", version);

        IOT_Linkkit_Query(EXAMPLE_MASTER_DEVID, ITM_MSG_QUERY_FOTA_DATA, (unsigned char *)buffer, buffer_length);
    }

    return 0;
}

/* cota event handler */
static int user_cota_event_handler(int type, const char *config_id, int config_size, const char *get_type,
                                   const char *sign, const char *sign_method, const char *url)
{
    char buffer[128] = {0};
    int buffer_length = 128;

    /* type = 0, new config exist, query the new config */
    if (type == 0) {
        EXAMPLE_TRACE("New Config ID: %s", config_id);
        EXAMPLE_TRACE("New Config Size: %d", config_size);
        EXAMPLE_TRACE("New Config Type: %s", get_type);
        EXAMPLE_TRACE("New Config Sign: %s", sign);
        EXAMPLE_TRACE("New Config Sign Method: %s", sign_method);
        EXAMPLE_TRACE("New Config URL: %s", url);

        IOT_Linkkit_Query(EXAMPLE_MASTER_DEVID, ITM_MSG_QUERY_COTA_DATA, (unsigned char *)buffer, buffer_length);
    }

    return 0;
}

static int user_mqtt_connect_succ_event_handler(void)
{
    EXAMPLE_TRACE("ITE_MQTT_CONNECT_SUCC");
    
    return SUCCESS_RETURN;
}

static int user_event_notify_handler(const int devid, const char *request, const int request_len)
{
    int res = 0;
    EXAMPLE_TRACE("Event notify Received, Devid: %d, Request: %s", devid, request);

    res = IOT_Linkkit_Report(EXAMPLE_MASTER_DEVID, ITM_MSG_EVENT_NOTIFY_REPLY,
                             (unsigned char *)request, request_len);
    EXAMPLE_TRACE("Post Property Message ID: %d", res);

    return 0;
}

static int linkkit_thread(void *paras)
{
    int res = 0;
    iotx_linkkit_dev_meta_info_t master_meta_info;
    int domain_type = 0, dynamic_register = 0, post_reply_need = 0;

#ifdef ATM_ENABLED
    if (IOT_ATM_Init() < 0) {
        EXAMPLE_TRACE("IOT ATM init failed!\n");
        return -1;
    }
#endif

    memset(&g_user_example_ctx, 0, sizeof(user_example_ctx_t));

    HAL_GetProductKey(PRODUCT_KEY);
    HAL_GetProductSecret(PRODUCT_SECRET);
    HAL_GetDeviceName(DEVICE_NAME);
    HAL_GetDeviceSecret(DEVICE_SECRET);
    memset(&master_meta_info, 0, sizeof(iotx_linkkit_dev_meta_info_t));
    memcpy(master_meta_info.product_key, PRODUCT_KEY, strlen(PRODUCT_KEY));
    memcpy(master_meta_info.product_secret, PRODUCT_SECRET, strlen(PRODUCT_SECRET));
    memcpy(master_meta_info.device_name, DEVICE_NAME, strlen(DEVICE_NAME));
    memcpy(master_meta_info.device_secret, DEVICE_SECRET, strlen(DEVICE_SECRET));

    /* Register Callback */
    IOT_RegisterCallback(ITE_AWSS_STATUS, user_awss_status_event_handler);
    IOT_RegisterCallback(ITE_CONNECT_SUCC, user_connected_event_handler);
    IOT_RegisterCallback(ITE_CONNECT_FAIL, user_connect_fail_event_handler);
    IOT_RegisterCallback(ITE_DISCONNECTED, user_disconnected_event_handler);
    IOT_RegisterCallback(ITE_RAWDATA_ARRIVED, user_rawdata_arrived_event_handler);
    IOT_RegisterCallback(ITE_SERVICE_REQUEST, user_service_request_event_handler);
    IOT_RegisterCallback(ITE_PROPERTY_SET, user_property_set_event_handler);
    /*Only for local communication service(ALCS)*/
    IOT_RegisterCallback(ITE_PROPERTY_GET, user_property_get_event_handler);
    IOT_RegisterCallback(ITE_REPORT_REPLY, user_report_reply_event_handler);
    IOT_RegisterCallback(ITE_TRIGGER_EVENT_REPLY, user_trigger_event_reply_event_handler);
    IOT_RegisterCallback(ITE_TIMESTAMP_REPLY, user_timestamp_reply_event_handler);
    IOT_RegisterCallback(ITE_TOPOLIST_REPLY, user_topolist_reply_handler);
    IOT_RegisterCallback(ITE_PERMIT_JOIN, user_permit_join_event_handler);
    IOT_RegisterCallback(ITE_INITIALIZE_COMPLETED, user_initialized);
    IOT_RegisterCallback(ITE_FOTA, user_fota_event_handler);
    IOT_RegisterCallback(ITE_COTA, user_cota_event_handler);
    IOT_RegisterCallback(ITE_MQTT_CONNECT_SUCC, user_mqtt_connect_succ_event_handler);
    IOT_RegisterCallback(ITE_EVENT_NOTIFY, user_event_notify_handler);

    domain_type = IOTX_CLOUD_REGION_SHANGHAI;
    IOT_Ioctl(IOTX_IOCTL_SET_DOMAIN, (void *)&domain_type);

    /* Choose Login Method */
    dynamic_register = 0;
    IOT_Ioctl(IOTX_IOCTL_SET_DYNAMIC_REGISTER, (void *)&dynamic_register);

    /* post reply doesn't need */
    post_reply_need = 1;
    IOT_Ioctl(IOTX_IOCTL_RECV_EVENT_REPLY, (void *)&post_reply_need);

    /* Create Master Device Resources */
    g_user_example_ctx.master_devid = IOT_Linkkit_Open(IOTX_LINKKIT_DEV_TYPE_MASTER, &master_meta_info);
    if (g_user_example_ctx.master_devid < 0) {
        EXAMPLE_TRACE("IOT_Linkkit_Open Failed\n");
        return -1;
    }

    /* Start Connect Aliyun Server */
    res = IOT_Linkkit_Connect(g_user_example_ctx.master_devid);
    if (res < 0) {
        EXAMPLE_TRACE("IOT_Linkkit_Connect Failed\n");
        IOT_Linkkit_Close(g_user_example_ctx.master_devid);
        return -1;
    }

    while (1) {
        IOT_Linkkit_Yield(EXAMPLE_YIELD_TIMEOUT_MS);
    }

    IOT_Linkkit_Close(g_user_example_ctx.master_devid);

    IOT_DumpMemoryStats(IOT_LOG_DEBUG);
    IOT_SetLogLevel(IOT_LOG_NONE);
    return 0;
}

void linkkit_main(void *paras)
{
    while (1) {
        linkkit_thread(NULL);
    }
}
#endif

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

static living_platform_tsl_t living_platform_tsl_data;

living_platform_tsl_t *living_platform_ut_get_tsl_data(void)
{
    return &living_platform_tsl_data;
}

int living_platform_ut_set_LightSwitch(char LightSwitch)
{
    living_platform_tsl_data.LightSwitch = LightSwitch;
    living_platform_info("set LightSwitch:%s", (LightSwitch == 0) ? "off" : "on");

    return 0;
}

int living_platform_ut_get_LightSwitch(void)
{
    return living_platform_tsl_data.LightSwitch;
}

int living_platform_ut_set_NightLightSwitch(char NightLightSwitch)
{
    living_platform_tsl_data.NightLightSwitch = NightLightSwitch;

    return 0;
}

int living_platform_ut_set_WorkMode(unsigned char WorkMode)
{
    living_platform_tsl_data.WorkMode = WorkMode;

    return 0;
}

int living_platform_ut_set_Brightness(unsigned char Brightness)
{
    living_platform_tsl_data.Brightness = Brightness;

    return 0;
}

int living_platform_ut_set_RGB(unsigned char R, unsigned char G, unsigned char B)
{
    living_platform_tsl_data.RGB.R = R;
    living_platform_tsl_data.RGB.G = G;
    living_platform_tsl_data.RGB.B = B;

    return 0;
}

int living_platform_ut_set_Float(float f)
{
    living_platform_tsl_data.f = f;

    return 0;
}

int living_platform_ut_set_Double(double d)
{
    living_platform_tsl_data.d = d;

    return 0;
}

int living_platform_ut_set_PropertyString(char *PropertyString)
{
    if (PropertyString)
    {
        HAL_Snprintf(living_platform_tsl_data.PropertyString, PROPERTY_STRING_MAX_LEN, "%s", PropertyString);
    }

    return 0;
}

int living_platform_ut_set_WorkTime(char *WorkTime)
{
    if (WorkTime)
    {
        HAL_Snprintf(living_platform_tsl_data.WorkTime, WORKTIME_MAX_LEN, "%s", WorkTime);
    }

    return 0;
}

/**
 * @brief 上报属性LightSwitch到云端
 * @param devid 由调用IOT_Linkkit_Open返回的设备标示符
 * @param value 属性LightSwitch的值，数据类型uint8_t
 * @return 消息id:(>=1), 上报失败: <0
 */
int32_t app_post_property_LightSwitch(uint32_t devid, uint8_t value)
{
    int32_t res = -0x100;
    char property_payload[64] = {0};

    res = HAL_Snprintf(property_payload, sizeof(property_payload), "{\"LightSwitch\": %d}", value);
    if (res < 0)
    {
        return -0x10E;
    }

    res = IOT_Linkkit_Report(devid, ITM_MSG_POST_PROPERTY,
                             (uint8_t *)property_payload, strlen(property_payload));
    return res;
}

/**
 * @brief 上报属性WIFI_Band到云端
 * @param devid 由调用IOT_Linkkit_Open返回的设备标示符
 * @param value 属性WIFI_Band的值，数据类型char*
 * @return 消息id:(>=1), 上报失败: <0
 */
int32_t app_post_property_WIFI_Band(uint32_t devid, char *value)
{
    int32_t res = -0x100;
    char *property_payload = NULL;
    uint32_t property_payload_len = 0;

    if (value == NULL)
    {
        return -0x101;
    }

    property_payload_len = strlen("WIFI_Band") + strlen(value) + 10;
    property_payload = HAL_Malloc(property_payload_len);
    if (property_payload == NULL)
    {
        return -0x201;
    }
    memset(property_payload, 0, property_payload_len);

    res = HAL_Snprintf(property_payload, property_payload_len, "{\"WIFI_Band\": \"%s\"}", value);
    if (res < 0)
    {
        return -0x10E;
    }

    res = IOT_Linkkit_Report(devid, ITM_MSG_POST_PROPERTY,
                             (uint8_t *)property_payload, strlen(property_payload));
    HAL_Free(property_payload);
    return res;
}

/**
 * @brief 上报属性WiFI_RSSI到云端
 * @param devid 由调用IOT_Linkkit_Open返回的设备标示符
 * @param value 属性WiFI_RSSI的值，数据类型int32_t
 * @return 消息id:(>=1), 上报失败: <0
 */
int32_t app_post_property_WiFI_RSSI(uint32_t devid, int32_t value)
{
    int32_t res = -0x100;
    char property_payload[64] = {0};

    res = HAL_Snprintf(property_payload, sizeof(property_payload), "{\"WiFI_RSSI\": %d}", value);
    if (res < 0)
    {
        return -0x10E;
    }

    res = IOT_Linkkit_Report(devid, ITM_MSG_POST_PROPERTY,
                             (uint8_t *)property_payload, strlen(property_payload));
    return res;
}

/**
 * @brief 上报属性WIFI_AP_BSSID到云端
 * @param devid 由调用IOT_Linkkit_Open返回的设备标示符
 * @param value 属性WIFI_AP_BSSID的值，数据类型char*
 * @return 消息id:(>=1), 上报失败: <0
 */
int32_t app_post_property_WIFI_AP_BSSID(uint32_t devid, char *value)
{
    int32_t res = -0x100;
    char *property_payload = NULL;
    uint32_t property_payload_len = 0;

    if (value == NULL)
    {
        return -0x101;
    }

    property_payload_len = strlen("WIFI_AP_BSSID") + strlen(value) + 10;
    property_payload = HAL_Malloc(property_payload_len);
    if (property_payload == NULL)
    {
        return -0x201;
    }
    memset(property_payload, 0, property_payload_len);

    res = HAL_Snprintf(property_payload, property_payload_len, "{\"WIFI_AP_BSSID\": \"%s\"}", value);
    if (res < 0)
    {
        return -0x10E;
    }

    res = IOT_Linkkit_Report(devid, ITM_MSG_POST_PROPERTY,
                             (uint8_t *)property_payload, strlen(property_payload));
    HAL_Free(property_payload);
    return res;
}

/**
 * @brief 上报属性WIFI_Channel到云端
 * @param devid 由调用IOT_Linkkit_Open返回的设备标示符
 * @param value 属性WIFI_Channel的值，数据类型int32_t
 * @return 消息id:(>=1), 上报失败: <0
 */
int32_t app_post_property_WIFI_Channel(uint32_t devid, int32_t value)
{
    int32_t res = -0x100;
    char property_payload[64] = {0};

    res = HAL_Snprintf(property_payload, sizeof(property_payload), "{\"WIFI_Channel\": %d}", value);
    if (res < 0)
    {
        return -0x10E;
    }

    res = IOT_Linkkit_Report(devid, ITM_MSG_POST_PROPERTY,
                             (uint8_t *)property_payload, strlen(property_payload));
    return res;
}

/**
 * @brief 上报属性WiFI_SNR到云端
 * @param devid 由调用IOT_Linkkit_Open返回的设备标示符
 * @param value 属性WiFI_SNR的值，数据类型int32_t
 * @return 消息id:(>=1), 上报失败: <0
 */
int32_t app_post_property_WiFI_SNR(uint32_t devid, int32_t value)
{
    int32_t res = -0x100;
    char property_payload[64] = {0};

    res = HAL_Snprintf(property_payload, sizeof(property_payload), "{\"WiFI_SNR\": %d}", value);
    if (res < 0)
    {
        return -0x10E;
    }

    res = IOT_Linkkit_Report(devid, ITM_MSG_POST_PROPERTY,
                             (uint8_t *)property_payload, strlen(property_payload));
    return res;
}

/**
 * @brief 上报属性NightLightSwitch到云端
 * @param devid 由调用IOT_Linkkit_Open返回的设备标示符
 * @param value 属性NightLightSwitch的值，数据类型uint8_t
 * @return 消息id:(>=1), 上报失败: <0
 */
int32_t app_post_property_NightLightSwitch(uint32_t devid, uint8_t value)
{
    int32_t res = -0x100;
    char property_payload[64] = {0};

    res = HAL_Snprintf(property_payload, sizeof(property_payload), "{\"NightLightSwitch\": %d}", value);
    if (res < 0)
    {
        return -0x10E;
    }

    res = IOT_Linkkit_Report(devid, ITM_MSG_POST_PROPERTY,
                             (uint8_t *)property_payload, strlen(property_payload));
    return res;
}

/**
 * @brief 上报属性WorkMode到云端
 * @param devid 由调用IOT_Linkkit_Open返回的设备标示符
 * @param value 属性WorkMode的值，数据类型uint32_t
 * @return 消息id:(>=1), 上报失败: <0
 */
int32_t app_post_property_WorkMode(uint32_t devid, uint32_t value)
{
    int32_t res = -0x100;
    char property_payload[64] = {0};

    res = HAL_Snprintf(property_payload, sizeof(property_payload), "{\"WorkMode\": %d}", value);
    if (res < 0)
    {
        return -0x10E;
    }

    res = IOT_Linkkit_Report(devid, ITM_MSG_POST_PROPERTY,
                             (uint8_t *)property_payload, strlen(property_payload));
    return res;
}

/**
 * @brief 上报属性Brightness到云端
 * @param devid 由调用IOT_Linkkit_Open返回的设备标示符
 * @param value 属性Brightness的值，数据类型int32_t
 * @return 消息id:(>=1), 上报失败: <0
 */
int32_t app_post_property_Brightness(uint32_t devid, int32_t value)
{
    int32_t res = -0x100;
    char property_payload[64] = {0};

    res = HAL_Snprintf(property_payload, sizeof(property_payload), "{\"Brightness\": %d}", value);
    if (res < 0)
    {
        return -0x10E;
    }

    res = IOT_Linkkit_Report(devid, ITM_MSG_POST_PROPERTY,
                             (uint8_t *)property_payload, strlen(property_payload));
    return res;
}

/**
 * @brief 上报属性worktime到云端
 * @param devid 由调用IOT_Linkkit_Open返回的设备标示符
 * @param utc 属性worktime的值，数据类型${dataType}
 * @return 消息id:(>=1), 上报失败: <0
 */
int32_t app_post_property_worktime(uint32_t devid, char *worktime)
{
    int32_t res = -0x100;
    char property_payload[64] = {0};

    res = HAL_Snprintf(property_payload, sizeof(property_payload), "{\"worktime\": \"%s\"}", worktime);
    if (res < 0)
    {
        return -0x10E;
    }

    res = IOT_Linkkit_Report(devid, ITM_MSG_POST_PROPERTY,
                             (uint8_t *)property_payload, strlen(property_payload));
    return res;
}

int32_t app_post_property_RGB(uint32_t devid, unsigned char R, unsigned char G, unsigned char B)
{
    int32_t res = -0x100;
    char property_payload[64] = {0};

    res = HAL_Snprintf(property_payload, sizeof(property_payload), "{\"RGBColor\": {\"Red\": %d, \"Green\": %d, \"Blue\": %d}}", R, G, B);
    if (res < 0)
    {
        return -0x10E;
    }

    res = IOT_Linkkit_Report(devid, ITM_MSG_POST_PROPERTY,
                             (uint8_t *)property_payload, strlen(property_payload));

    return res;
}

/**
 * @brief 上报属性onlyread到云端
 * @param devid 由调用IOT_Linkkit_Open返回的设备标示符
 * @param value 属性onlyread的值，数据类型int32_t
 * @return 消息id:(>=1), 上报失败: <0
 */
int32_t app_post_property_onlyread(uint32_t devid, int32_t value)
{
    int32_t res = -0x100;
    char property_payload[64] = {0};

    res = HAL_Snprintf(property_payload, sizeof(property_payload), "{\"onlyread\": %d}", value);
    if (res < 0)
    {
        return -0x10E;
    }

    res = IOT_Linkkit_Report(devid, ITM_MSG_POST_PROPERTY,
                             (uint8_t *)property_payload, strlen(property_payload));
    return res;
}

/**
 * @brief 上报属性float到云端
 * @param devid 由调用IOT_Linkkit_Open返回的设备标示符
 * @param value 属性float的值，数据类型float
 * @return 消息id:(>=1), 上报失败: <0
 */
int32_t app_post_property_float(uint32_t devid, float value)
{
    int32_t res = -0x100;
    char property_payload[64] = {0};

    res = HAL_Snprintf(property_payload, sizeof(property_payload), "{\"floatid\": %f}", value);
    if (res < 0)
    {
        return -0x10E;
    }

    res = IOT_Linkkit_Report(devid, ITM_MSG_POST_PROPERTY,
                             (uint8_t *)property_payload, strlen(property_payload));
    return res;
}

/**
 * @brief 上报属性double到云端
 * @param devid 由调用IOT_Linkkit_Open返回的设备标示符
 * @param value 属性double的值，数据类型double
 * @return 消息id:(>=1), 上报失败: <0
 */
int32_t app_post_property_double(uint32_t devid, double value)
{
    int32_t res = -0x100;
    char property_payload[64] = {0};

    res = HAL_Snprintf(property_payload, sizeof(property_payload), "{\"doubleid\": %f}", value);
    if (res < 0)
    {
        return -0x10E;
    }

    res = IOT_Linkkit_Report(devid, ITM_MSG_POST_PROPERTY,
                             (uint8_t *)property_payload, strlen(property_payload));
    return res;
}

/**
 * @brief 上报属性PropertyString到云端
 * @param devid 由调用IOT_Linkkit_Open返回的设备标示符
 * @param value 属性PropertyString的值，数据类型char*
 * @return 消息id:(>=1), 上报失败: <0
 */
int32_t app_post_property_PropertyString(uint32_t devid, char *value)
{
    int32_t res = -0x100;
    char *property_payload = NULL;
    uint32_t property_payload_len = 0;

    if (value == NULL)
    {
        return -0x101;
    }

    property_payload_len = strlen("PropertyString") + strlen(value) + 10;
    property_payload = HAL_Malloc(property_payload_len);
    if (property_payload == NULL)
    {
        return -0x201;
    }
    memset(property_payload, 0, property_payload_len);

    res = HAL_Snprintf(property_payload, property_payload_len, "{\"PropertyString\": \"%s\"}", value);
    if (res < 0)
    {
        HAL_Free(property_payload);
        return -0x10E;
    }

    res = IOT_Linkkit_Report(devid, ITM_MSG_POST_PROPERTY,
                             (uint8_t *)property_payload, strlen(property_payload));
    HAL_Free(property_payload);
    return res;
}

/**
 * @brief 上报事件Error到云端
 * @param devid 由调用IOT_Linkkit_Open返回的设备标示符
 * @param value 事件Error的值，数据类型uint32_t
 * @return 消息id:(>=1), 上报失败: <0
 */
int32_t app_post_event_Error(uint32_t devid, uint32_t value)
{
    int32_t res = -0x100;
    char *event_id = "Error";
    char event_payload[64] = {0};

    res = HAL_Snprintf(event_payload, sizeof(event_payload), "{\"ErrorCode\": %d}", value);
    if (res < 0)
    {
        return -0x10E;
    }

    res = IOT_Linkkit_TriggerEvent(EXAMPLE_MASTER_DEVID, event_id, strlen(event_id),
                                   event_payload, strlen(event_payload));
    return res;
}

/**
 * @brief 上报事件alarm到云端
 * @param devid 由调用IOT_Linkkit_Open返回的设备标示符
 * @param value 事件alarm的值，数据类型int32_t
 * @return 消息id:(>=1), 上报失败: <0
 */
int32_t app_post_event_alarm(uint32_t devid, int32_t value)
{
    int32_t res = -0x100;
    char *event_id = "alarm";
    char event_payload[64] = {0};

    res = HAL_Snprintf(event_payload, sizeof(event_payload), "{\"alarm\": %d}", value);
    if (res < 0)
    {
        return -0x10E;
    }

    res = IOT_Linkkit_TriggerEvent(EXAMPLE_MASTER_DEVID, event_id, strlen(event_id),
                                   event_payload, strlen(event_payload));
    return res;
}

/**
 * @brief 上报事件info到云端
 * @param devid 由调用IOT_Linkkit_Open返回的设备标示符
 * @param value 事件info的值，数据类型int32_t
 * @return 消息id:(>=1), 上报失败: <0
 */
int32_t app_post_event_info(uint32_t devid, int32_t value)
{
    int32_t res = -0x100;
    char *event_id = "info";
    char event_payload[64] = {0};

    res = HAL_Snprintf(event_payload, sizeof(event_payload), "{\"info\": %d}", value);
    if (res < 0)
    {
        return -0x10E;
    }

    res = IOT_Linkkit_TriggerEvent(EXAMPLE_MASTER_DEVID, event_id, strlen(event_id),
                                   event_payload, strlen(event_payload));
    return res;
}

//Just for reference
void user_post_property(void)
{
    static int count = 0;

    app_post_property_LightSwitch(EXAMPLE_MASTER_DEVID, living_platform_tsl_data.LightSwitch);
    app_post_property_WIFI_Band(EXAMPLE_MASTER_DEVID, living_platform_tsl_data.wifi.band);
    app_post_property_WiFI_RSSI(EXAMPLE_MASTER_DEVID, living_platform_tsl_data.wifi.rssi);
    app_post_property_WIFI_AP_BSSID(EXAMPLE_MASTER_DEVID, living_platform_tsl_data.wifi.bssid);
    app_post_property_WIFI_Channel(EXAMPLE_MASTER_DEVID, living_platform_tsl_data.wifi.Channel);
    app_post_property_WiFI_SNR(EXAMPLE_MASTER_DEVID, living_platform_tsl_data.wifi.SNR);
    app_post_property_NightLightSwitch(EXAMPLE_MASTER_DEVID, living_platform_tsl_data.NightLightSwitch);
    app_post_property_WorkMode(EXAMPLE_MASTER_DEVID, living_platform_tsl_data.WorkMode);
    app_post_property_Brightness(EXAMPLE_MASTER_DEVID, living_platform_tsl_data.Brightness);
    app_post_property_worktime(EXAMPLE_MASTER_DEVID, living_platform_tsl_data.WorkTime);
    app_post_property_RGB(EXAMPLE_MASTER_DEVID, living_platform_tsl_data.RGB.R, living_platform_tsl_data.RGB.G, living_platform_tsl_data.RGB.B);
    app_post_property_onlyread(EXAMPLE_MASTER_DEVID, living_platform_tsl_data.readonly);
    app_post_property_float(EXAMPLE_MASTER_DEVID, living_platform_tsl_data.f);
    app_post_property_double(EXAMPLE_MASTER_DEVID, living_platform_tsl_data.d);
    app_post_property_PropertyString(EXAMPLE_MASTER_DEVID, living_platform_tsl_data.PropertyString);

    if (count == 0)
    {
        app_post_event_Error(EXAMPLE_MASTER_DEVID, count);
    }
    else if (count == 1)
    {
        app_post_event_alarm(EXAMPLE_MASTER_DEVID, count);
    }
    else if (count == 2)
    {
        app_post_event_info(EXAMPLE_MASTER_DEVID, count);
    }

    if (++count > 2)
    {
        count = 0;
    }
}

//Just for reference
void user_deviceinfo_update(void)
{
    int res = 0;
    living_platform_ctx_t *living_platform_ctx = living_platform_get_ctx();
    char *device_info_update = "[{\"attrKey\":\"ct\",\"attrValue\":\"I am a ct device\"},{\"attrKey\":\"ct2\",\"attrValue\":\"I am a ct2\"}]";

    res = IOT_Linkkit_Report(living_platform_ctx->master_devid, ITM_MSG_DEVICEINFO_UPDATE,
                             (unsigned char *)device_info_update, strlen(device_info_update));
    living_platform_info("Device Info Update Message ID: %d", res);
}

//Just for reference
void user_deviceinfo_delete(void)
{
    int res = 0;
    living_platform_ctx_t *living_platform_ctx = living_platform_get_ctx();
    char *device_info_delete = "[{\"attrKey\":\"ct2\"}]";

    res = IOT_Linkkit_Report(living_platform_ctx->master_devid, ITM_MSG_DEVICEINFO_DELETE,
                             (unsigned char *)device_info_delete, strlen(device_info_delete));
    living_platform_info("Device Info Delete Message ID: %d", res);
}

void living_platform_ut_misc_process(uint64_t time_now_sec)
{
    /* Post Proprety Example */
    if (time_now_sec % 11 == 0)
    {
        user_post_property();
    }

    /* Device Info Update Example */
    if (time_now_sec % 23 == 0)
    {
        user_deviceinfo_update();
    }

    /* Device Info Delete Example */
    if (time_now_sec % 29 == 0)
    {
        user_deviceinfo_delete();
    }
}

int living_platform_ut_init(void)
{
    int ret = SUCCESS_RETURN;

    memset(&living_platform_tsl_data, 0, sizeof(living_platform_tsl_t));
    living_platform_tsl_data.PropertyString = (char *)HAL_Malloc(PROPERTY_STRING_MAX_LEN);
    if (living_platform_tsl_data.PropertyString == NULL)
    {
        living_platform_err("no mem");

        ret = FAIL_RETURN;
    }

    living_platform_tsl_data.LightSwitch = 1;
    living_platform_tsl_data.NightLightSwitch = 0;
    living_platform_tsl_data.Brightness = 88;
    living_platform_tsl_data.WorkMode = 3;
    HAL_Snprintf(living_platform_tsl_data.WorkTime, WORKTIME_MAX_LEN, "%s", "1582861307282");
    HAL_Snprintf(living_platform_tsl_data.PropertyString, PROPERTY_STRING_MAX_LEN, "%s", "This is a testing property string!");
    living_platform_tsl_data.f = 9.999999;
    living_platform_tsl_data.d = 88.888888;
    living_platform_tsl_data.RGB.R = 128;
    living_platform_tsl_data.RGB.G = 128;
    living_platform_tsl_data.RGB.B = 128;
    living_platform_tsl_data.readonly = 38;

    living_platform_tsl_data.wifi.Channel = 6;
    living_platform_tsl_data.wifi.SNR = -127;
    living_platform_tsl_data.wifi.rssi = -78;
    HAL_Snprintf(living_platform_tsl_data.wifi.bssid, AP_BSSID_MAX_LEN, "%s", "11:22:33:44:55:66");
    HAL_Snprintf(living_platform_tsl_data.wifi.band, WIFI_BAND_MAX_LEN, "%s", "2.4G");

    return ret;
}

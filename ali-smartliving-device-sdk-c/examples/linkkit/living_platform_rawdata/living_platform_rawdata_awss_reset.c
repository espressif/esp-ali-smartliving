/*
 * Copyright (C) 2019-2020 Alibaba Group Holding Limited
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "iot_export.h"
#include "iot_import.h"

#include "app_entry.h"
#include "living_platform_rawdata_main.h"
#include "living_platform_rawdata_ut.h"

/*
 * Note:
 * the linkkit_event_monitor must not block and should run to complete fast
 * if user wants to do complex operation with much time,
 * user should post one task to do this, not implement complex operation in
 * linkkit_event_monitor
 */
static void linkkit_event_monitor(int event)
{
    switch (event)
    {
    case IOTX_AWSS_START: // AWSS start without enbale, just supports device discover
        // operate led to indicate user
        living_platform_rawdata_info("IOTX_AWSS_START");
        break;
    case IOTX_AWSS_ENABLE: // AWSS enable, AWSS doesn't parse awss packet until AWSS is enabled.
        living_platform_rawdata_info("IOTX_AWSS_ENABLE");
        // operate led to indicate user
        break;
    case IOTX_AWSS_LOCK_CHAN: // AWSS lock channel(Got AWSS sync packet)
        living_platform_rawdata_info("IOTX_AWSS_LOCK_CHAN");
        // operate led to indicate user
        break;
    case IOTX_AWSS_PASSWD_ERR: // AWSS decrypt passwd error
        living_platform_rawdata_info("IOTX_AWSS_PASSWD_ERR");
        // operate led to indicate user
        break;
    case IOTX_AWSS_GOT_SSID_PASSWD:
        living_platform_rawdata_info("IOTX_AWSS_GOT_SSID_PASSWD");
        // operate led to indicate user
        break;
    case IOTX_AWSS_CONNECT_ADHA: // AWSS try to connnect adha (device
        // discover, router solution)
        living_platform_rawdata_info("IOTX_AWSS_CONNECT_ADHA");
        // operate led to indicate user
        break;
    case IOTX_AWSS_CONNECT_ADHA_FAIL: // AWSS fails to connect adha
        living_platform_rawdata_info("IOTX_AWSS_CONNECT_ADHA_FAIL");
        // operate led to indicate user
        break;
    case IOTX_AWSS_CONNECT_AHA: // AWSS try to connect aha (AP solution)
        living_platform_rawdata_info("IOTX_AWSS_CONNECT_AHA");
        // operate led to indicate user
        break;
    case IOTX_AWSS_CONNECT_AHA_FAIL: // AWSS fails to connect aha
        living_platform_rawdata_info("IOTX_AWSS_CONNECT_AHA_FAIL");
        // operate led to indicate user
        break;
    case IOTX_AWSS_SETUP_NOTIFY: // AWSS sends out device setup information
        // (AP and router solution)
        living_platform_rawdata_info("IOTX_AWSS_SETUP_NOTIFY");
        // operate led to indicate user
        break;
    case IOTX_AWSS_CONNECT_ROUTER: // AWSS try to connect destination router
        living_platform_rawdata_info("IOTX_AWSS_CONNECT_ROUTER");
        // operate led to indicate user
        break;
    case IOTX_AWSS_CONNECT_ROUTER_FAIL: // AWSS fails to connect destination
        // router.
        living_platform_rawdata_info("IOTX_AWSS_CONNECT_ROUTER_FAIL");
        // operate led to indicate user
        break;
    case IOTX_AWSS_GOT_IP: // AWSS connects destination successfully and got
        // ip address
        living_platform_rawdata_info("IOTX_AWSS_GOT_IP");
        // operate led to indicate user
        break;
    case IOTX_AWSS_SUC_NOTIFY: // AWSS sends out success notify (AWSS
        // sucess)
        living_platform_rawdata_info("IOTX_AWSS_SUC_NOTIFY");
        // operate led to indicate user
        break;
    case IOTX_AWSS_BIND_NOTIFY: // AWSS sends out bind notify information to
        // support bind between user and device
        living_platform_rawdata_info("IOTX_AWSS_BIND_NOTIFY");
        // operate led to indicate user
        break;
    case IOTX_AWSS_ENABLE_TIMEOUT: // AWSS enable timeout
        // user needs to enable awss again to support get ssid & passwd of router
        living_platform_rawdata_info("IOTX_AWSS_ENALBE_TIMEOUT");
        // operate led to indicate user
        break;
    case IOTX_CONN_CLOUD: // Device try to connect cloud
        living_platform_rawdata_info("IOTX_CONN_CLOUD");
        // operate led to indicate user
        break;
    case IOTX_CONN_CLOUD_FAIL: // Device fails to connect cloud, refer to
        // net_sockets.h for error code
        living_platform_rawdata_info("IOTX_CONN_CLOUD_FAIL");
        // operate led to indicate user
        break;
    case IOTX_CONN_CLOUD_SUC: // Device connects cloud successfully
        living_platform_rawdata_info("IOTX_CONN_CLOUD_SUC");
        // operate led to indicate user
        break;
    case IOTX_RESET: // Linkkit reset success (just got reset response from
        // cloud without any other operation)
        living_platform_rawdata_info("IOTX_RESET");
        break;
    case IOTX_CONN_REPORT_TOKEN_SUC:
        living_platform_rawdata_info("---- report token success ----");
        break;
    default:
        break;
    }
}

static void* awss_close_dev_ap(void *p)
{
    living_platform_rawdata_info("%s exit\n", __func__);
    awss_dev_ap_stop();
    return NULL;
}

static void* awss_open_dev_ap(void *p)
{
    awss_dev_ap_start();
    living_platform_rawdata_info("%s\n", __func__);
    return NULL;
}

static void* stop_smartconfig_awss(void *p)
{
    awss_stop();
    living_platform_rawdata_info("%s\n", __func__);
    return NULL;
}

extern int awss_config_press();
static void* start_smartconfig_awss(void *p)
{
    iotx_event_regist_cb(linkkit_event_monitor);
    awss_config_press();
    awss_start();

    return NULL;
}

static void linkkit_reset(void *p)
{
    iotx_sdk_reset_local();
    HAL_Reboot();
}

//User can call this function to start device AP of AWSS
void living_platform_rawdata_do_awss_dev_ap(void)
{
    void* stop_smartconfig_awss_thread = NULL;
    void* dev_ap_open_thread = NULL;
    hal_os_thread_param_t hal_os_thread_param;

    memset(&hal_os_thread_param, 0, sizeof(hal_os_thread_param_t));
    hal_os_thread_param.stack_size = 4096;
    hal_os_thread_param.name = "smartconfig_awss_stop";
    HAL_ThreadCreate(&stop_smartconfig_awss_thread, stop_smartconfig_awss, NULL, &hal_os_thread_param, NULL);
    memset(&hal_os_thread_param, 0, sizeof(hal_os_thread_param_t));
    hal_os_thread_param.stack_size = 4096;
    hal_os_thread_param.name = "dev_ap_open";
    HAL_ThreadCreate(&dev_ap_open_thread, awss_open_dev_ap, NULL, &hal_os_thread_param, NULL);
}

//User can call this function to start smartconfig of AWSS
void living_platform_rawdata_start_smartconfig_awss(void)
{
    void* close_dev_ap_thread = NULL;
    void* start_smartconfig_thread = NULL;
    hal_os_thread_param_t hal_os_thread_param;

    memset(&hal_os_thread_param, 0, sizeof(hal_os_thread_param_t));
    hal_os_thread_param.stack_size = 2048;
    hal_os_thread_param.name = "dap_close";
    HAL_ThreadCreate(&close_dev_ap_thread, awss_close_dev_ap, NULL, &hal_os_thread_param, NULL);
    memset(&hal_os_thread_param, 0, sizeof(hal_os_thread_param_t));
    hal_os_thread_param.stack_size = 4096;
    hal_os_thread_param.name = "smartconfig_awss";
    HAL_ThreadCreate(&start_smartconfig_thread, start_smartconfig_awss, NULL, &hal_os_thread_param, NULL);
}

//User can call this function for system reset
void living_platform_rawdata_awss_reset(void)
{
    void *reset_timer = NULL;
    void* reset_thread = NULL;
    hal_os_thread_param_t hal_os_thread_param;
    iotx_vendor_dev_reset_type_t reset_type = IOTX_VENDOR_DEV_RESET_TYPE_UNBIND_ONLY;

    memset(&hal_os_thread_param, 0, sizeof(hal_os_thread_param_t));
    hal_os_thread_param.stack_size = 4096;
    hal_os_thread_param.name = "reset";
    HAL_ThreadCreate(&reset_thread, (void* (*)(void *))iotx_sdk_reset, (void*)&reset_type, &hal_os_thread_param, NULL);

    reset_timer = HAL_Timer_Create("reset", linkkit_reset, NULL);
    HAL_Timer_Stop(reset_timer);
    HAL_Timer_Start(reset_timer, 3000);
}

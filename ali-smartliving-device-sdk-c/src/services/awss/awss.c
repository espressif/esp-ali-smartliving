/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include "awss.h"
#include "awss_main.h"
#include "zconfig_utils.h"
#include "awss_enrollee.h"
#include "awss_cmp.h"
#include "awss_info.h"
#include "awss_notify.h"
#include "awss_timer.h"
#include "awss_packet.h"
#include "awss_statis.h"
#include "awss_event.h"
#include "awss_adha.h"
#include "awss_aha.h"
#include "passwd.h"

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

#define AWSS_PRESS_TIMEOUT_MS  (60000)

extern int switch_ap_done;
static uint8_t awss_stopped = 1;
static uint8_t g_user_press = 0;
static void *press_timer = NULL;

static void awss_press_timeout(void);

int awss_success_notify(void)
{
    g_user_press = 0;
    awss_press_timeout();

    awss_cmp_local_init(AWSS_LC_INIT_SUC);
    awss_suc_notify_stop();
    awss_suc_notify();
    awss_start_connectap_monitor();
    AWSS_DISP_STATIS();
    return 0;
}

int awss_start(void)
{
    if (awss_stopped == 0) {
        dump_awss_status(STATE_WIFI_IN_PROGRESS, "awss already running");
        return STATE_WIFI_IN_PROGRESS;
    }

    awss_stopped = 0;
    awss_event_post(IOTX_AWSS_START);

    do {
        __awss_start();
#if defined(AWSS_SUPPORT_ADHA) || defined(AWSS_SUPPORT_AHA)
        do {
            char ssid[PLATFORM_MAX_SSID_LEN + 1] = {0};
#ifdef AWSS_SUPPORT_ADHA
            while (1) {
                memset(ssid, 0, sizeof(ssid));
                os_wifi_get_ap_info(ssid, NULL, NULL);
                awss_debug("start, ssid:%s, strlen:%d\n", ssid, strlen(ssid));
                if (strlen(ssid) > 0 && strcmp(ssid, ADHA_SSID)) { // not adha AP
                    break;
                }

                if (os_sys_net_is_ready()) { // skip the adha failed
                    awss_cmp_local_init(AWSS_LC_INIT_ROUTER);

                    awss_open_adha_monitor();
                    while (!awss_is_ready_switch_next_adha()) {
                        if (awss_stopped) {
                            break;
                        }
                        os_msleep(50);
                    }
                    awss_cmp_local_deinit(0);
                }

                if (switch_ap_done || awss_stopped) {
                    break;
                }
                __awss_start();
            }
#endif
            if (awss_stopped) {
                break;
            }

            if (switch_ap_done) {
                break;
            }

            os_wifi_get_ap_info(ssid, NULL, NULL);
            if (strlen(ssid) > 0 && strcmp(ssid, DEFAULT_SSID)) { // not AHA
                break;
            }

            if (os_sys_net_is_ready()) {
                awss_open_aha_monitor();

                awss_cmp_local_init(AWSS_LC_INIT_PAP);
                char dest_ap = 0;
                while (!awss_aha_monitor_is_timeout()) {
                    memset(ssid, 0, sizeof(ssid));
                    os_wifi_get_ap_info(ssid, NULL, NULL);
                    if (os_sys_net_is_ready() &&
                        strlen(ssid) > 0 && strcmp(ssid, DEFAULT_SSID)) {  // not AHA
                        dest_ap = 1;
                        break;
                    }
                    if (awss_stopped) {
                        break;
                    }						
                    os_msleep(50);
                }

                awss_cmp_local_deinit(0);

                if (switch_ap_done || awss_stopped) {
                    break;
                }

                if (dest_ap == 1) {
                    break;
                }
            }
            awss_event_post(IOTX_AWSS_ENABLE_TIMEOUT);
            __awss_start();
        } while (1);
#endif
        if (awss_stopped) {
            break;
        }

        if (os_sys_net_is_ready()) {
            break;
        }
    } while (1);

    if (awss_stopped) {
        dump_awss_status(STATE_WIFI_FORCE_STOPPED, "awss stopped in %s", __func__);
        return STATE_WIFI_FORCE_STOPPED;
    }

#ifdef AWSS_SUPPORT_AHA
    awss_close_aha_monitor();
#endif
#ifdef AWSS_SUPPORT_ADHA
    awss_close_adha_monitor();
#endif

    awss_success_notify();
    awss_stopped = 1;
    return 0;
}

int awss_stop(void)
{
    awss_stopped = 1;
#ifdef AWSS_SUPPORT_AHA
    awss_close_aha_monitor();
#endif
#ifdef AWSS_SUPPORT_ADHA
    awss_close_adha_monitor();
#endif
    awss_stop_connectap_monitor();
    g_user_press = 0;
    awss_press_timeout();

    __awss_stop();

    return 0;
}

static void awss_press_timeout(void)
{
    if (NULL != press_timer) {
        awss_stop_timer(press_timer);
        press_timer = NULL;
    }
    
    if (g_user_press) {
        awss_event_post(IOTX_AWSS_ENABLE_TIMEOUT);
    }
    g_user_press = 0;
}

int awss_config_press(void)
{
    int timeout = os_awss_get_timeout_interval_ms();

    awss_trace("enable awss\r\n");

    g_user_press = 1;

    awss_event_post(IOTX_AWSS_ENABLE);

    #ifdef DEV_STATEMACHINE_ENABLE
    dev_awss_state_set(AWSS_PATTERN_DEV_AP_CONFIG, AWSS_STATE_START);
    #endif
    
    if (press_timer == NULL) {
        press_timer = HAL_Timer_Create("press", (void (*)(void *))awss_press_timeout, NULL);
    }
    if (press_timer == NULL) {
        return STATE_SYS_DEPEND_TIMER_CREATE;
    }

    HAL_Timer_Stop(press_timer);

    if (timeout < AWSS_PRESS_TIMEOUT_MS) {
        timeout = AWSS_PRESS_TIMEOUT_MS;
    }
    HAL_Timer_Start(press_timer, timeout);

    return STATE_SUCCESS;
}

uint8_t awss_get_config_press(void)
{
    return g_user_press;
}

void awss_set_config_press(uint8_t press)
{
    g_user_press = press;
}

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif

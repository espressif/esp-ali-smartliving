/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include <string.h>
#include <stdio.h>
#include "aws_lib.h"
#include "awss_aha.h"
#include "awss_adha.h"
#include "awss_aplist.h"
#include "zconfig_lib.h"
#include "zconfig_utils.h"
#include "zconfig_protocol.h"
#include "zconfig_ieee80211.h"
#include "awss_info_notify.h"
#include "awss_enrollee.h"
#include "awss_event.h"
#include "awss_timer.h"
#include "awss_main.h"
#include "awss.h"
#include "os.h"

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif
/* aws state machine */
enum {
    /* used by aws_state */
    AWS_SCANNING,
    AWS_CHN_LOCKED,
    AWS_SUCCESS,
    AWS_TIMEOUT,

    /* used by aws_stop */
    AWS_STOPPING,
    AWS_STOPPED
};


struct aws_info {
    uint8_t state;

    uint8_t cur_chn; /* current working channel */
    uint8_t chn_index;

    uint8_t locked_chn;

#define AWS_MAX_CHN_NUMS             (2 * 13 + 5)    /* +5 for safety gap */
    uint8_t chn_list[AWS_MAX_CHN_NUMS];
    uint8_t  stop;

    uint32_t chn_timestamp;/* channel start time */
    uint32_t start_timestamp;/* aws start time */
    uint32_t p2p_received_timestamp ;/* aws start time */
} *aws_info;

#define aws_state                    (aws_info->state)
#define aws_locked_chn               (aws_info->locked_chn)
#define aws_cur_chn                  (aws_info->cur_chn)
#define aws_chn_index                (aws_info->chn_index)
#define aws_chn_list                 (aws_info->chn_list)
#define aws_chn_timestamp            (aws_info->chn_timestamp)
#define aws_start_timestamp          (aws_info->start_timestamp)
#define aws_stop                     (aws_info->stop)
#define aws_p2p_received_timestamp   (aws_info->p2p_received_timestamp)

#define aws_channel_lock_timeout_ms  (4 * 1000)

#ifdef AWSS_BATCH_DEVAP_ENABLE
extern uint8_t g_fixed_chan;
#endif

static void *rescan_timer = NULL;

static void rescan_monitor(void);

#define RESCAN_MONITOR_TIMEOUT_MS     (5 * 60 * 1000)
static uint8_t rescan_available = 0;

/*
 * sniffer result/storage
 * use global variable/buffer to keep it usable after zconfig_destroy
 */
uint8_t aws_result_ssid[ZC_MAX_SSID_LEN + 1];
uint8_t aws_result_passwd[ZC_MAX_PASSWD_LEN + 1];
uint8_t aws_result_bssid[ETH_ALEN];/* mac addr */
uint8_t aws_result_token[ZC_MAX_TOKEN_LEN];/* bind token */
uint8_t aws_result_token_type = 0;
uint8_t aws_result_channel = 0;
uint8_t aws_result_encry;
uint8_t aws_result_auth;
int aws_80211_frame_handler(char *, int, enum AWSS_LINK_TYPE, int, signed char);

uint8_t zconfig_get_lock_chn(void)
{
    return aws_locked_chn;
}

void zconfig_force_rescan(void)
{
    if (aws_info) {
        aws_state = AWS_SCANNING;
    }
}

void zconfig_channel_locked_callback(uint8_t primary_channel,
                                     uint8_t secondary_channel, uint8_t *bssid)
{
    aws_locked_chn = primary_channel;

    if (aws_state == AWS_SCANNING) {
        aws_state = AWS_CHN_LOCKED;
    }

    awss_event_post(IOTX_AWSS_LOCK_CHAN);
    #ifdef DEV_STATEMACHINE_ENABLE
    dev_awss_state_set(AWSS_PATTERN_SMART_CONFIG, AWSS_STATE_COLLECTING_SSID);
    #endif
}

void zconfig_got_ssid_passwd_callback(uint8_t *ssid, uint8_t *passwd,
                                      uint8_t *bssid, uint8_t *token, 
                                      uint8_t auth, uint8_t encry, uint8_t channel, uint8_t token_type)
{
    if (bssid) {
        dump_awss_status(STATE_WIFI_PASSWD_DECODE_SUCCESS, "ssid:%s, bssid:%02x%02x%02x%02x%02x%02x, %d",
                         ssid, bssid[0], bssid[1], bssid[2],
                         bssid[3], bssid[4], bssid[5], channel);
    } else {
        dump_awss_status(STATE_WIFI_PASSWD_DECODE_SUCCESS, "ssid:%s, bssid:--, %d",
                         ssid, channel);
    }

    if (token) {
        memcpy(aws_result_token, token, ZC_MAX_TOKEN_LEN);
    }
    aws_result_token_type = token_type;
    memset(aws_result_ssid, 0, sizeof(aws_result_ssid));
    memset(aws_result_passwd, 0, sizeof(aws_result_passwd));
    strncpy((char *)aws_result_ssid, (const char *)ssid, ZC_MAX_SSID_LEN - 1);
    strncpy((char *)aws_result_passwd, (const char *)passwd, ZC_MAX_PASSWD_LEN - 1);

    if (bssid) {
        memcpy(aws_result_bssid, bssid, ETH_ALEN);
    }
    aws_result_auth = auth;
    aws_result_encry = encry;
    aws_result_channel = channel;

    aws_state = AWS_SUCCESS;

    awss_event_post(IOTX_AWSS_GOT_SSID_PASSWD);
    #ifdef DEV_STATEMACHINE_ENABLE
    dev_awss_state_set(AWSS_PATTERN_DEV_AP_CONFIG, AWSS_STATE_SSID_GOT);
    #endif

    //TODO:Please change it when smartconfig can got regionid
    iotx_guider_set_dynamic_region(IOTX_CLOUD_REGION_INVALID);
}

uint8_t aws_next_channel(void)
{
    /* aws_chn_index start from -1 */
    while (1) {
        aws_chn_index ++;
        if (aws_chn_index >= AWS_MAX_CHN_NUMS) {
            aws_chn_index = 0;    // rollback to start
        }

        if (aws_chn_list[aws_chn_index]) { // valid channel
            break;
        }
    }

    aws_cur_chn = aws_chn_list[aws_chn_index];

    return aws_cur_chn;
}

static void aws_switch_dst_chan(int channel);
static int aws_amend_dst_chan = 0;
void aws_switch_channel(void)
{
    os_mutex_lock(zc_mutex);
    if (aws_amend_dst_chan != 0) {
        aws_switch_dst_chan(aws_amend_dst_chan);
        aws_amend_dst_chan = 0;
        os_mutex_unlock(zc_mutex);
        return;
    }

    if (aws_state == AWS_CHN_LOCKED) {
        os_mutex_unlock(zc_mutex);
        return;
    }

    do {
        uint8_t channel;
#ifdef AWSS_BATCH_DEVAP_ENABLE
        uint8_t valid_chan = 0;
        if (g_fixed_chan == 0xFF) {
            // no fix channel set, use channel list to switch channel
            channel = aws_next_channel();
        } else {
            // fix channel set, should validate the fix channel
            uint8_t i = 0;
            for (i = 0; i < AWS_MAX_CHN_NUMS; i ++) {
                if (aws_chn_list[i] == 0) {
                    continue;
                }
                if (aws_chn_list[i] == g_fixed_chan) {
                    valid_chan = 1;
                    break;
                }
            }
            if (valid_chan) {
                // fix channel was set and valid
                channel = g_fixed_chan;
            } else {
                // fix channel invalid, use channel list to switch channel
                channel = aws_next_channel();
            }
        }
#else
        channel = aws_next_channel();
#endif
        aws_chn_timestamp = os_get_time_ms();
        os_awss_switch_channel(channel, 0, NULL);
        awss_trace("chan %d\r\n", channel);
    } while (0);
    os_mutex_unlock(zc_mutex);
}

void aws_set_dst_chan(int channel)
{
    os_mutex_lock(zc_mutex);
    aws_amend_dst_chan = channel;
    os_mutex_unlock(zc_mutex);
}

static void aws_switch_dst_chan(int channel)
{
    int i = aws_chn_index;
    for (; i < AWS_MAX_CHN_NUMS; i ++) {
        if (aws_chn_list[i] == 0) {
            continue;
        }
        if (aws_chn_list[i] == channel) {
            break;
        }
    }

    if (i >= AWS_MAX_CHN_NUMS) {
        for (i = 0; i < aws_chn_index; i ++) {
            if (aws_chn_list[i] == 0) {
                continue;
            }
            if (aws_chn_list[i] == channel) {
                break;
            }
        }
    }

    if (i == aws_chn_index) { // no need to switch channel.
        return;
    }

    aws_chn_index = i;
    aws_locked_chn = channel;
    aws_cur_chn = channel;
    aws_chn_timestamp = os_get_time_ms();
    if (aws_state == AWS_SCANNING) {
        aws_state = AWS_CHN_LOCKED;
    }
    os_awss_switch_channel(channel, 0, NULL);

    awss_trace("adjust chan %d\r\n", channel);
}

enum {
    CHNSCAN_ONGOING,  /* no timeout, continue */
    CHNSCAN_NEXT_CHN, /* should swith to next channel */
    CHNSCAN_TIMEOUT   /* aws timeout */
};

int aws_is_chnscan_timeout(void)
{
    if (aws_stop == AWS_STOPPING) {
        awss_debug("aws will stop...\r\n");
        return CHNSCAN_TIMEOUT;
    }

    if (time_elapsed_ms_since(aws_chn_timestamp) > os_awss_get_channelscan_interval_ms()) {
        if ((0 != os_awss_get_timeout_interval_ms()) &&
            (time_elapsed_ms_since(aws_start_timestamp) > os_awss_get_timeout_interval_ms())) {
            return CHNSCAN_TIMEOUT;
        } else {
            return CHNSCAN_NEXT_CHN;
        }
    }

    return CHNSCAN_ONGOING;
}

int zconfig_add_active_channel(int channel)
{
    int fixed_channel_nums = sizeof(wlan_fixed_scanning_channels);

    if (!zconfig_is_valid_channel(channel)) {
        return -1;
    }

    aws_chn_list[fixed_channel_nums + channel] = channel;
    return 0;
}

/*
 * platform like mc300, 雄迈 depend on auth & encry type
 * so keep scanning if auth & encry is incomplete
 */
int aws_force_scanning(void)
{
#ifdef WITH_AUTH_ENCRY
    int timeout = sizeof(wlan_fixed_scanning_channels) / sizeof(uint8_t)
                  * os_awss_get_timeout_interval_ms() * 2; /* 2 round */

    /* force scanning useful only when aws is success */
    if (aws_state != AWS_SUCCESS) {
        return 0;
    }

    //channel scanning at most 2 round
    if (time_elapsed_ms_since(aws_start_timestamp) >= timeout) {
        return 0;//timeout
    } else {
        /*
         * for platform which need auth & encry, retry to get auth info
         */
        int found = zconfig_get_auth_info(aws_result_ssid, aws_result_bssid,
                                          &aws_result_auth, &aws_result_encry,
                                          &aws_result_channel);
        if (found) {
            return 0;
        } else {
            return 1;    /* keep scanning */
        }
    }
#else
    //no need scanning a round
    return 0;
#endif
}

#ifdef AWSS_SUPPORT_SMARTCONFIG_MCAST
int wait_for_mcast_done = 0;
int delay_p2p()
{
#define MCAST_LOCK_TIMEOUT  5000
#define MCAST_DELAY_TIMEOUT 30000
    extern int mcast_locked_channel;
    /* 1. if p2p does not got anything, do nothing ---- return 0 */
    if (0 == zc_got_ssid_passwd_from_p2p) {
        return 0;
    }

    /* record the 1st time p2p received */
    if (0 == aws_p2p_received_timestamp) {
        aws_p2p_received_timestamp = os_get_time_ms();
    }

    /* check if we got mcast packs in 5s afterwards */
    if (time_elapsed_ms_since(aws_p2p_received_timestamp) < MCAST_LOCK_TIMEOUT) {
       awss_debug("p2p received time is %u, elapsed is %u", aws_p2p_received_timestamp, time_elapsed_ms_since(aws_p2p_received_timestamp));
        if (-1 != mcast_locked_channel) {
            awss_debug("p2p wait for mcast");
            wait_for_mcast_done = 1;
        }
        return 0;
    }

    /* 2.if p2p got ssid/passwd, but failed to recived mcast in 5s, connnect ap directly */
    if (0 == wait_for_mcast_done) {
        zconfig_set_state(STATE_RCV_DONE, 1, 1);
        awss_debug("switch to p2p in case 2\n");
        return 1;
    }

    /* 3.if p2p got ssid/passwd, and recived mcast in 5s, wait for 30s, in 30s do not triger p2p */
    if (time_elapsed_ms_since(aws_p2p_received_timestamp) < MCAST_LOCK_TIMEOUT + MCAST_DELAY_TIMEOUT) {
        return 0;
    }

    /* 4.if p2p got ssid/passwd, and recived mcast in 5s, wait for 30s, faild to to done mcast, connect directly */
    zconfig_set_state(STATE_RCV_DONE, 1, 1);
    awss_debug("switch to p2p in case 4\n");
    return 1;
}
#endif

/*
 * channel scanning/re-scanning control
 * Note: 修改该函数时，需考虑到各平台差异
 * 庆科平台：
 * --aws_switch_channel() 为空
 * --zconfig_destroy()会被调用两次，一次被aws_main_thread_fun()，一次被庆科驱动
 * linux/rtos平台差异
 * --vendor_recv_80211_frame()有实现，rtos平台该函数通常为空，通过注册callback方式收包
 */
void aws_main_thread_func(void)
{
    aws_start_timestamp = os_get_time_ms();

    /* channel switch init */
    aws_switch_channel();

rescanning:
    // start scaning channel
    memset(zc_bssid, 0, ETH_ALEN);
    while (aws_amend_dst_chan != 0 || aws_state == AWS_SCANNING || aws_force_scanning()) {
        switch (aws_is_chnscan_timeout()) {
            case CHNSCAN_ONGOING:
                break;
            case CHNSCAN_NEXT_CHN:
                aws_switch_channel();
                break;
            case CHNSCAN_TIMEOUT:
                goto timeout_scanning;
            default:
                break;
        }

        if (aws_stop == AWS_STOPPING) { /* interrupt by user */
            goto timeout_scanning;
        }
#ifdef AWSS_SUPPORT_SMARTCONFIG_MCAST
        if (delay_p2p()) {
            goto success;
        }
#endif

        if (aws_state != AWS_SCANNING) {
            break;
        }
#ifdef AWSS_SUPPORT_SMARTCONFIG_NOTIFY
        int interval = (os_awss_get_channelscan_interval_ms() + 2) / 4;
#else
        int interval = (os_awss_get_channelscan_interval_ms() + 2) / 3;
#endif
        if (interval < 1) {
            interval = 1;
        }

        /* 80211 frame handled by callback */
        os_msleep(interval);
#ifndef AWSS_DISABLE_ENROLLEE
        awss_enrollee_broadcast_info();
#endif
        os_msleep(interval);
#ifdef AWSS_SUPPORT_ADHA
        aws_send_adha_probe_req();
#endif
        os_msleep(interval);
#ifdef AWSS_SUPPORT_SMARTCONFIG_NOTIFY
        aws_send_info_notify();
        os_msleep(interval);
#endif
#ifdef AWSS_SUPPORT_AHA
        aws_send_aha_probe_req();
#endif
    }

    // channel lock
    awss_debug("[channel scanning] %d ms\r\n",
               time_elapsed_ms_since(aws_start_timestamp));

    /*
     * make sure switch to locked channel,
     * in case of inconsistent with aws_cur_chn
     */
#ifdef AWSS_SUPPORT_APLIST
    aws_try_adjust_chan();
#endif
    awss_debug("final channel %d\r\n", aws_locked_chn);

    while (aws_state != AWS_SUCCESS) {
        /* 80211 frame handled by callback */
        os_msleep(300);
#ifdef AWSS_SUPPORT_SMARTCONFIG_MCAST
        if (delay_p2p()) {
            goto success;
        }
#endif

        if (aws_stop == AWS_STOPPING) {
            goto timeout_recving;
        }


#ifdef AWSS_SUPPORT_APLIST
        aws_try_adjust_chan();
#endif
        if (aws_is_chnscan_timeout() == CHNSCAN_TIMEOUT) {
            goto timeout_recving;
        }

        if (aws_state == AWS_SCANNING) {
            awss_debug("channel rescanning...\n");
            if (zconfig_data != NULL) {
                void *temp_mutex = zc_mutex;
                memset(zconfig_data, 0, sizeof(struct zconfig_data));
                zc_mutex = temp_mutex;
            }
            goto rescanning;
        }
    }

    awss_debug("[channel recving] %d ms\r\n",
               time_elapsed_ms_since(aws_start_timestamp));

    goto success;

timeout_scanning:
    awss_debug("aws timeout scanning!\r\n");
timeout_recving:
    awss_debug("aws timeout recving!\r\n");
#ifdef AWSS_SUPPORT_SMARTCONFIG_MCAST
    if (delay_p2p()) {
        goto success;
    }
#endif

    do {
        if (aws_stop == AWS_STOPPING) {
            break;
        }
        if (rescan_timer == NULL) {
            rescan_timer = HAL_Timer_Create("rescan", (void(*)(void *))rescan_monitor, NULL);
        }
        HAL_Timer_Stop(rescan_timer);
        HAL_Timer_Start(rescan_timer, RESCAN_MONITOR_TIMEOUT_MS);
        os_awss_close_monitor();
        while (rescan_available == 0) {
            if (awss_get_config_press() ||
                aws_stop == AWS_STOPPING) {  // user interrupt sleep
                HAL_Timer_Stop(rescan_timer);
                break;
            }
            os_msleep(200);
        }
        rescan_available = 0;
    } while (0);

    if (aws_stop == AWS_STOPPING) {  /* interrupt by user */
        aws_stop = AWS_STOPPED;
        goto success;
    }

    aws_state = AWS_SCANNING;
#ifdef AWSS_SUPPORT_APLIST
    if (awss_is_ready_clr_aplist()) {
        awss_clear_aplist();
    }
#endif

    aws_start_timestamp = os_get_time_ms();
    os_awss_open_monitor(aws_80211_frame_handler);
    goto rescanning;

success:
    awss_stop_timer(rescan_timer);
    rescan_timer = NULL;
    // don't destroy zconfig_data until monitor_cb is finished.
    os_mutex_lock(zc_mutex);
    os_mutex_unlock(zc_mutex);
    dump_awss_status(STATE_WIFI_DESTROY, "ready to call zconfig_destroy to release mem");
    /*
     * zconfig_destroy() after os_awss_monitor_close() beacause
     * zconfig_destroy will release mem/buffer that
     * zconfig_recv_callback will use
     *
     * Note: hiflying will reboot after calling this func, so
     *    aws_get_ssid_passwd() was called in os_awss_monitor_close()
     */
    if (aws_stop == AWS_STOPPED) {
        dump_awss_status(STATE_WIFI_DESTROY, "zconfig mem released");
        zconfig_force_destroy();
    }
#if defined(AWSS_SUPPORT_ADHA) || defined(AWSS_SUPPORT_AHA)
    else if (strcmp((const char *)aws_result_ssid, (const char *)zc_adha_ssid) == 0 ||
             strcmp((const char *)aws_result_ssid, (const char *)zc_default_ssid) == 0) {
        zconfig_destroy();
    }
#endif
    else {
        zconfig_force_destroy();
    }
}

static void rescan_monitor(void)
{
    rescan_available = 1;
}

int aws_80211_frame_handler(char *buf, int length, enum AWSS_LINK_TYPE link_type, int with_fcs, signed char rssi)
{
    static uint32_t lock_start;

    int ret = zconfig_recv_callback(buf, length, aws_cur_chn, link_type, with_fcs, rssi);

    if (aws_state == AWS_CHN_LOCKED) {
        switch (ret) {
            case PKG_START_FRAME:
            case PKG_DATA_FRAME:
            case PKG_GROUP_FRAME:
            case PKG_MCAST_FRAME:
                lock_start = os_get_time_ms();
                break;
            default:
                /* set to rescanning */
                if (time_elapsed_ms_since(lock_start) > aws_channel_lock_timeout_ms) {
                    aws_state = AWS_SCANNING;
                }
                break;
        }
    }

    return ret;
}

void aws_start(char *pk, char *dn, char *ds, char *ps)
{
    aws_info = os_zalloc(sizeof(struct aws_info));
    if (!aws_info) {
        return;
    }

    aws_state = AWS_SCANNING;

    /* start from -1 */
    aws_chn_index = 0xff;
    memcpy(aws_chn_list, wlan_fixed_scanning_channels,
           sizeof(wlan_fixed_scanning_channels));

    memset(aws_result_ssid, 0, sizeof(aws_result_ssid));
    memset(aws_result_passwd, 0, sizeof(aws_result_passwd));
    memset(aws_result_bssid, 0, sizeof(aws_result_bssid));
    aws_result_auth = ZC_AUTH_TYPE_INVALID;
    aws_result_encry = ZC_ENC_TYPE_INVALID;
    aws_result_channel = 0;

    zconfig_init();
#ifdef AWSS_SUPPORT_APLIST
    awss_open_aplist_monitor();
#endif

    os_awss_open_monitor(aws_80211_frame_handler);

#ifndef AWSS_DISABLE_ENROLLEE
    awss_enrollee_init_info();
#endif

    aws_main_thread_func();
}

static void *aws_mutex = NULL;

void aws_destroy(void)
{
    if (aws_mutex == NULL) {
        aws_mutex = HAL_MutexCreate();
    }
    if (aws_mutex) {
        HAL_MutexLock(aws_mutex);
    }

    if (aws_info == NULL) {
        HAL_MutexUnlock(aws_mutex);
        return;
    }

    if (aws_stop == AWS_STOPPED) {
        HAL_MutexUnlock(aws_mutex);
        return;
    }

    aws_stop = AWS_STOPPING;

    os_awss_close_monitor();
    dump_awss_status(STATE_WIFI_DESTROY, "aws_destroy");

    while (aws_stop != AWS_STOPPED) {
        if (aws_state == AWS_SUCCESS) {
            break;
        }
        os_msleep(100);
    }

    os_free(aws_info);
    aws_info = NULL;
#ifndef AWSS_DISABLE_ENROLLEE
    awss_enrollee_destroy_info();
#endif

    if (aws_mutex) {
        HAL_MutexUnlock(aws_mutex);
    }
}

void aws_release_mutex()
{
    if (aws_mutex) {
        HAL_MutexDestroy(aws_mutex);
        aws_mutex = NULL;
    }
}

int aws_get_ssid_passwd(char *ssid, char *passwd, uint8_t *bssid, uint8_t *token,
                        char *auth, char *encry, uint8_t *channel, uint8_t *token_type)
{
    if (aws_state != AWS_SUCCESS) {
        return 0;
    }
    if (ssid) {
        strncpy((char *)ssid, (const char *)aws_result_ssid, ZC_MAX_SSID_LEN - 1);
    }
    if (passwd) {
        strncpy((char *)passwd, (const char *)aws_result_passwd, ZC_MAX_PASSWD_LEN - 1);
    }
    if (bssid) {
        memcpy(bssid, aws_result_bssid, ETH_ALEN);
    }
    if (token) {
        memcpy(token, aws_result_token, ZC_MAX_TOKEN_LEN);
    }
    if (auth) {
        *auth = aws_result_auth;
    }
    if (encry) {
        *encry = aws_result_encry;
    }
    if (channel) {
        *channel = aws_result_channel;
    }
    if (token_type) {
        *token_type = aws_result_token_type;
    }
    return 1;
}

#if defined(AWSS_SUPPORT_SMARTCONFIG_MCAST) || defined(AWSS_SUPPORT_SMARTCONFIG)
const uint8_t zconfig_fixed_offset[ZC_ENC_TYPE_MAX + 1][2] = {
    {  /* open, none, ip(20) + udp(8) + 8(LLC) */
        36, 36
    },
    {  /* wep, + iv(4) + data + ICV(4) */
        44, 44  /* feixun, wep64(10byte), wep128(26byte) */
    },
    {  /* tkip, + iv/keyID(4) + Ext IV(4) + data + MIC(8) + ICV(4) */
        56, 56  /* tkip(10byte, 20byte), wpa2+tkip(20byte) */
    },
    {  /* aes, + ccmp header(8) + data + MIC(8) + ICV(4) */
        52, 52
    },
    {  /* tkip-aes */
        56, 52  /* fromDs==tkip,toDs==aes */
    }
};
#endif

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif

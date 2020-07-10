/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <stdint.h>
#include "iot_import.h"
#include "os.h"
#include "awss.h"
#include "awss_ap_scan.h"
#include "zconfig_ieee80211.h"
#include "zconfig_lib.h"
#include "awss_log.h"

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C"
{
#endif

/* designated ap scan timing related definition */
#define APSCAN_DEFAULT_CHN_SCAN_TIME    (200)

/* probe request definition which be sent to designated ap */
#define APSCAN_PROBE_REQ_HEAD_LEN       (26)
#define APSCAN_PROBE_REQ_TAIL_LEN       (20)
#define APSCAN_SA_OFFSET                (10)

/* local static variables */
static uint8_t g_apscan_chan_idx = 0;
static ap_scan_info_t g_apscan_info;

static const uint8_t apscan_probe_req_frame_head[APSCAN_PROBE_REQ_HEAD_LEN] = {
    0x40, 0x00,  // mgnt type, frame control
    0x00, 0x00,  // duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // DA
    0x28, 0xC2, 0xDD, 0x61, 0x68, 0x83,  // SA, to be replaced with wifi mac
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // BSSID
    0xC0, 0x79,  // seq
    0x00, 0x03   // type(ssid), ssid len(variable)
}; 

static const uint8_t apscan_probe_req_frame_tail[APSCAN_PROBE_REQ_TAIL_LEN] = {
    0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x8C, 0x92, 0x98, 0xA4,  // supported rates
    0x32, 0x04, 0xB0, 0x48, 0x60, 0x6C,  // extended supported rates
    0x3F, 0x84, 0x10, 0x9E  // FCS
}; 

static uint8_t apscan_next_scan_chan(void)
{
    uint8_t chan = wlan_fixed_scanning_channels[g_apscan_chan_idx];
    g_apscan_chan_idx++;
    if ( g_apscan_chan_idx > (sizeof(wlan_fixed_scanning_channels) - 1) ) {
        g_apscan_chan_idx = 0;
    }
    return chan;
}

static int apscan_send_probe_req(void)
{
    uint8_t probe[APSCAN_PROBE_REQ_HEAD_LEN + OS_MAX_SSID_LEN + APSCAN_PROBE_REQ_TAIL_LEN];
    uint8_t ssid_len = strlen(g_apscan_info.ssid);

    if (ssid_len == 0) {
        return -1;
    }

    memcpy(probe, apscan_probe_req_frame_head, APSCAN_PROBE_REQ_HEAD_LEN);
    os_wifi_get_mac(&probe[APSCAN_SA_OFFSET]);
    probe[APSCAN_PROBE_REQ_HEAD_LEN - 1] = ssid_len;
    strncpy((char *)(probe + APSCAN_PROBE_REQ_HEAD_LEN), g_apscan_info.ssid, ssid_len);
    memcpy(probe + APSCAN_PROBE_REQ_HEAD_LEN + ssid_len, apscan_probe_req_frame_tail, APSCAN_PROBE_REQ_TAIL_LEN);
    os_wifi_send_80211_raw_frame(FRAME_PROBE_REQ, probe, sizeof(probe));

    return 0;
}

static int apscan_80211_frame_handler(char *buf, int length, enum AWSS_LINK_TYPE link_type, int with_fcs, signed char rssi)
{
    uint8_t ssid[OS_MAX_SSID_LEN] = {0}, bssid[OS_ETH_ALEN] = {0};
    uint16_t fc;
    uint8_t channel;
    uint8_t auth, pairwise_cipher, group_cipher;
    int ret;
    struct ieee80211_hdr *hdr;

    /* remove FCS filed */
    if (with_fcs) {
        length -= 4;
    }
    /* useless, will be removed */
    if (ieee80211_is_invalid_pkg(buf, length)) {
        return -1;
    }
    /* link type transfer for supporting linux system. */
    hdr = (struct ieee80211_hdr *)zconfig_remove_link_header((uint8_t **)&buf, &length, link_type);
    if (length <= 0) {
        return -1;
    }

    /* search ssid and bssid in management frame */
    fc = hdr->frame_control;
    if (!ieee80211_is_beacon(fc) && !ieee80211_is_probe_resp(fc)) {
        return -1;
    }
    ret = ieee80211_get_bssid((uint8_t *)hdr, bssid);
    if (ret < 0) {
        return -1;
    }
    ret = ieee80211_get_ssid((uint8_t *)hdr, length, ssid);
    if (ret < 0) {
        return -1;
    }

    /* skip ap which is not designated ap */
    if (strcmp((const char *)ssid, g_apscan_info.ssid)) {
        return -1;
    }

    rssi = rssi > 0 ? rssi - 256 : rssi;

    // designated ap found, get ap detail information
    channel = cfg80211_get_bss_channel((uint8_t *)hdr, length);
    if (channel > ZC_MAX_CHANNEL || channel < ZC_MIN_CHANNEL) {
        channel = 0;
    }
    cfg80211_get_cipher_info((uint8_t *)hdr, length, &auth,
                             &pairwise_cipher, &group_cipher);
    if (auth > ZC_AUTH_TYPE_MAX) {
        auth = ZC_AUTH_TYPE_INVALID;
    }
    if (pairwise_cipher > ZC_ENC_TYPE_MAX) {
        pairwise_cipher = ZC_ENC_TYPE_INVALID;
    }
    if (group_cipher > ZC_ENC_TYPE_MAX) {
        group_cipher = ZC_ENC_TYPE_INVALID;
    }
    if (pairwise_cipher == ZC_ENC_TYPE_TKIPAES) {
        pairwise_cipher = ZC_ENC_TYPE_AES;
    }
    // copy ap detail information to g_apscan_info
    g_apscan_info.auth = auth;
    g_apscan_info.channel = channel;
    g_apscan_info.encry[0] = group_cipher;
    g_apscan_info.encry[1] = pairwise_cipher;
    memcpy(g_apscan_info.mac, bssid, OS_ETH_ALEN);
    g_apscan_info.rssi = rssi;
    g_apscan_info.found = 1;

    awss_debug("apscan ssid: %s, mac:%02x%02x%02x%02x%02x%02x, rssi:%d, chan:%d", 
                g_apscan_info.ssid, g_apscan_info.mac[0], g_apscan_info.mac[1],
                g_apscan_info.mac[2], g_apscan_info.mac[3], g_apscan_info.mac[4],
                g_apscan_info.mac[5], g_apscan_info.rssi, g_apscan_info.channel);
    return 0;
}

int awss_apscan_process(uint32_t *p_scan_time, char *p_scan_ssid, ap_scan_info_t *p_scan_result)
{
    int result = -1;
    uint32_t apscan_total_time;
    uint32_t next_chn_start_time = 0;
    uint32_t cur_chn_start_time = 0;
    uint8_t cur_scan_chan = wlan_fixed_scanning_channels[0];
    uint32_t apscan_start_time = os_get_time_ms();

    // Parameters check
    if ( (strlen(p_scan_ssid) == 0) || strlen(p_scan_ssid) > OS_MAX_SSID_LEN ) {
        awss_debug("apscan start fail, params invalid");
        result = -1;
        return result;
    }

    // Device WiFi mode check, not in SoftAP mode and Connected mode
    if (HAL_Sys_Net_Is_Ready()) {
        awss_debug("apscan start fail, wifi mode invalid");
        result = -1;
        return result;
    }

    // Initiate
    apscan_total_time = (sizeof(wlan_fixed_scanning_channels) / sizeof(uint8_t) + 1) * APSCAN_DEFAULT_CHN_SCAN_TIME;
    if (p_scan_time != NULL) {
        if (*p_scan_time > apscan_total_time) {
            apscan_total_time = *p_scan_time;
        }
    }
    memset(&g_apscan_info, 0, sizeof(ap_scan_info_t));
    strncpy(g_apscan_info.ssid, p_scan_ssid, strlen(p_scan_ssid));

    // start scaning channel
    cur_chn_start_time = apscan_start_time;
    next_chn_start_time = apscan_start_time;
    // open wifi monitor, start scan on the first channel
    g_apscan_chan_idx = 0;
    os_awss_open_monitor(apscan_80211_frame_handler);

    while( ((next_chn_start_time - apscan_start_time) < apscan_total_time)
        && (g_apscan_info.found == 0) ) {
        os_msleep(50);
        next_chn_start_time = os_get_time_ms();
        if(next_chn_start_time - cur_chn_start_time >= APSCAN_DEFAULT_CHN_SCAN_TIME){
            cur_scan_chan = apscan_next_scan_chan();
            awss_debug("apscan switch to chan %d", cur_scan_chan);
            os_awss_switch_channel(cur_scan_chan, 0, NULL);
            cur_chn_start_time = next_chn_start_time;
        }
        if ( (next_chn_start_time - cur_chn_start_time) >= ((APSCAN_DEFAULT_CHN_SCAN_TIME + 2) / 3)) {
            // maybe send more than once
            apscan_send_probe_req();
        }
    }

    awss_debug("apscan %d ms", time_elapsed_ms_since(apscan_start_time));
    os_awss_close_monitor();

    if (g_apscan_info.found) {
        // apscan found
        p_scan_result->found = g_apscan_info.found;
        p_scan_result->auth = g_apscan_info.auth;
        p_scan_result->channel = g_apscan_info.channel;
        memcpy(p_scan_result->encry, g_apscan_info.encry, 2);
        memcpy(p_scan_result->mac, g_apscan_info.mac, OS_ETH_ALEN);
        memcpy(p_scan_result->ssid, g_apscan_info.ssid, OS_MAX_SSID_LEN);
        p_scan_result->rssi = g_apscan_info.rssi;        
        result = 0;
    } else {
        // apscan not found
        result = -1;
    }

    return result;
}

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif

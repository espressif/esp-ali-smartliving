/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifdef MANUFACT_AP_FIND_ENABLE
#include <stdio.h>
#include <stdint.h>
#include "iot_import.h"
#include "os.h"
#include "awss.h"
#include "awss_manufact_ap_find.h"
#include "zconfig_ieee80211.h"
#include "awss_log.h"

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C"
{
#endif

/* manufact self-def ap info related definition */
#define MANUFACT_AP_SSID_PREFIX         "ali_mprov_"

/* manufact self-def ap scan timing related definition */
#define MANUFACT_AP_TOTAL_SCAN_TIME     (3000)
#define MANUFACT_AP_CHN_SCAN_TIME       (200)

/* probe request related definition which be sent to manufact ap */
#define MANUFACT_AP_PROBE_HEAD_LEN      (26)
#define MANUFACT_AP_PROBE_TAIL_LEN      (20)
#define MANUFACT_AP_SA_OFFSET           (10)

/* external functions used in manufact ap module */
extern uint8_t *zconfig_remove_link_header(uint8_t **in, int *len, int link_type);

/* manufact ap fixed scanning channel list */
static const uint8_t manufact_ap_fixed_scan_channels[] = {
    11, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13
};
static uint8_t g_manu_chan_idx = 0;

/* local static variables */
static char g_manufact_ap_ssid[OS_MAX_SSID_LEN + 1] = {0};
static char g_manufact_ap_pwd[OS_MAX_PASSWD_LEN + 1] = {0};
static uint8_t g_manufact_ap_bssid[OS_ETH_ALEN] = {0};
static uint8_t g_manufact_ap_found = 0;       // 0-not found, 1-success found 
static uint8_t g_cur_scan_chan = 0xFF;

static const uint8_t manufact_probe_req_frame_head[MANUFACT_AP_PROBE_HEAD_LEN] = {
    0x40, 0x00,  // mgnt type, frame control
    0x00, 0x00,  // duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // DA
    0x28, 0xC2, 0xDD, 0x61, 0x68, 0x83,  // SA, to be replaced with wifi mac
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // BSSID
    0xC0, 0x79,  // seq
    0x00, 0x03   // type(ssid), ssid len(variable)
}; 

static const uint8_t manufact_probe_req_frame_tail[MANUFACT_AP_PROBE_TAIL_LEN] = {
    0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x8C, 0x92, 0x98, 0xA4,  // supported rates
    0x32, 0x04, 0xB0, 0x48, 0x60, 0x6C,  // extended supported rates
    0x3F, 0x84, 0x10, 0x9E  // FCS
}; 


int manufact_ap_info_set(char *p_ssid_manu, char *p_pwd)
{
    if ((strlen(p_ssid_manu) == 0) || (strlen(p_ssid_manu) + strlen(MANUFACT_AP_SSID_PREFIX) > OS_MAX_SSID_LEN)) {
        awss_warn("Invalid manufact ssid in %s", __func__);
        return -1;
    }
    if ((strlen(p_pwd) < 8) || (strlen(p_pwd) > OS_MAX_PASSWD_LEN)) {
        awss_warn("Invalid manufact pwd in %s", __func__);
        return -1;
    }
    memset(g_manufact_ap_ssid, 0, sizeof(g_manufact_ap_ssid));
    memset(g_manufact_ap_pwd, 0, sizeof(g_manufact_ap_pwd));
    // manufact ssid must be "ali_mprov_xxxx"
    strncpy(g_manufact_ap_ssid, MANUFACT_AP_SSID_PREFIX, strlen(MANUFACT_AP_SSID_PREFIX));
    strncpy(g_manufact_ap_ssid + strlen(MANUFACT_AP_SSID_PREFIX), p_ssid_manu, strlen(p_ssid_manu));
    // manufact pwd length must be > 8
    strncpy(g_manufact_ap_pwd, p_pwd, strlen(p_pwd));
    return 0;
}

static uint8_t manufact_ap_next_scan_chan(void)
{
    uint8_t chan = manufact_ap_fixed_scan_channels[g_manu_chan_idx];
    g_manu_chan_idx++;
    if ( g_manu_chan_idx > (sizeof(manufact_ap_fixed_scan_channels) - 1) ) {
        g_manu_chan_idx = 0;
    }
    return chan;
}

static int manufact_ap_send_probe_req(void)
{
    uint8_t probe[MANUFACT_AP_PROBE_HEAD_LEN + OS_MAX_SSID_LEN + MANUFACT_AP_PROBE_TAIL_LEN];
    uint8_t manu_ssid_len = strlen(g_manufact_ap_ssid);

    if (manu_ssid_len == 0) {
        return -1;
    }

    memcpy(probe, manufact_probe_req_frame_head, MANUFACT_AP_PROBE_HEAD_LEN);
    os_wifi_get_mac(&probe[MANUFACT_AP_SA_OFFSET]);
    probe[MANUFACT_AP_PROBE_HEAD_LEN - 1] = manu_ssid_len;
    strncpy((char *)(probe + MANUFACT_AP_PROBE_HEAD_LEN), g_manufact_ap_ssid, manu_ssid_len);
    memcpy(probe + MANUFACT_AP_PROBE_HEAD_LEN + manu_ssid_len, manufact_probe_req_frame_tail, MANUFACT_AP_PROBE_TAIL_LEN);
    os_wifi_send_80211_raw_frame(FRAME_PROBE_REQ, probe, sizeof(probe));

    return 0;
}

static int manufact_ap_80211_frame_handler(char *buf, int length, enum AWSS_LINK_TYPE link_type, int with_fcs, signed char rssi)
{
    uint8_t ssid[OS_MAX_SSID_LEN] = {0}, bssid[OS_ETH_ALEN] = {0};
    uint16_t fc;
    int ret;
    struct ieee80211_hdr *hdr;

    /* remove FCS filed */
    if (with_fcs) {
        length -= 4;
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

    /* skip ap which is not manufact self-def ap */
    if (strcmp((const char *)ssid, g_manufact_ap_ssid)) {
        return -1;
    }

    rssi = rssi > 0 ? rssi - 256 : rssi;
    memcpy(g_manufact_ap_bssid, bssid, OS_ETH_ALEN);

    awss_debug("found manufact ssid: %s, mac:%02x%02x%02x%02x%02x%02x, rssi:%d\r\n", 
                g_manufact_ap_ssid, g_manufact_ap_bssid[0], g_manufact_ap_bssid[1],
                g_manufact_ap_bssid[2], g_manufact_ap_bssid[3], g_manufact_ap_bssid[4],
                g_manufact_ap_bssid[5], rssi);
    g_manufact_ap_found = 1;
    return 0;
}

int manufact_ap_find(char *p_ssid, char *p_pwd, uint8_t *p_bssid)
{
    int result = -1;
    uint32_t cur_chn_time = 0;
    uint32_t pre_chn_time = 0;
    uint32_t manuap_find_start_time = os_get_time_ms();

    // manufact ap module params init
    g_manufact_ap_found = 0;

    if ( (strlen(g_manufact_ap_ssid) == 0) || (strlen(g_manufact_ap_pwd) == 0) ) {
        // manufact ap info not set, no self-ap to find
        awss_debug("manufact ap find not start\r\n");
        result = -1;
        return result;
    }

    // start scaning channel
    pre_chn_time = manuap_find_start_time;
    cur_chn_time = manuap_find_start_time;
    // open wifi monitor, auto start scan on channel 6
    g_cur_scan_chan = 6;
    g_manu_chan_idx = 0;
    os_awss_open_monitor(manufact_ap_80211_frame_handler);

    while( ((cur_chn_time - manuap_find_start_time) < MANUFACT_AP_TOTAL_SCAN_TIME)
        && (g_manufact_ap_found == 0) ) {
        os_msleep(50);
        cur_chn_time = os_get_time_ms();
        if(cur_chn_time - pre_chn_time >= MANUFACT_AP_CHN_SCAN_TIME){
            g_cur_scan_chan = manufact_ap_next_scan_chan();
            awss_debug("manufact switch to chan %d\r\n", g_cur_scan_chan);
            os_awss_switch_channel(g_cur_scan_chan, 0, NULL);
            pre_chn_time = cur_chn_time;
        }
        if ( (cur_chn_time - pre_chn_time) >= ((MANUFACT_AP_CHN_SCAN_TIME + 2) / 3)) {
            // maybe send more than once
            manufact_ap_send_probe_req();
        }
    }

    awss_debug("manufact ap scan %d ms\r\n",
               time_elapsed_ms_since(manuap_find_start_time));
    os_awss_close_monitor();

    if (g_manufact_ap_found) {
        // manufact ap success found
        strncpy(p_ssid, g_manufact_ap_ssid, strlen(g_manufact_ap_ssid));
        strncpy(p_pwd, g_manufact_ap_pwd, strlen(g_manufact_ap_pwd));
        memcpy(p_bssid ,g_manufact_ap_bssid, sizeof(g_manufact_ap_bssid));
        result = 0;
    } else {
        // manufact ap not found
        result = -1;
    }

    // Only find manuap once when dev init set the self-def ssid.
    memset(g_manufact_ap_ssid, 0, sizeof(g_manufact_ap_ssid));
    memset(g_manufact_ap_pwd, 0, sizeof(g_manufact_ap_pwd));
    memset(g_manufact_ap_bssid, 0, sizeof(g_manufact_ap_bssid));

    return result;
}

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif
#endif

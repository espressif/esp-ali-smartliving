/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include <string.h>
#include <stdio.h>
#include "aws_lib.h"
#include "awss_aplist.h"
#include "zconfig_lib.h"
#include "zconfig_utils.h"
#include "zconfig_protocol.h"
#include "zconfig_ieee80211.h"
#include "awss_main.h"
#include "awss_smartconfig.h"
#include "passwd.h"
#include "awss_utils.h"
#include "awss_packet.h"
#include "awss_notify.h"
#include "awss_cmp.h"
#include "os.h"
#include "awss_log.h"
#include "awss_crypt.h"
#include <stdlib.h>
#include "awss_aplist.h"
#include "connect_ap.h"

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

int awss_complete_token(char passwd[HAL_MAX_PASSWD_LEN], uint8_t *bssid, uint8_t bssid_len,
                        uint8_t *token_in, uint8_t token_len, uint8_t token_out[AWSS_TOKEN_LEN])
{
    /*need to complete the token*/
    int ret = STATE_SUCCESS;
    if (token_len != 0 && token_len < 16 && token_in != NULL) {
        int org_token_len = 0;
        unsigned char buff[128] = {0};
        unsigned char gen_token[32] = {0};
        uint8_t pwd_len = strlen(passwd);

        if(bssid != NULL) {
            memcpy(buff + org_token_len, bssid, bssid_len);
            org_token_len += bssid_len;
        }

        memcpy(buff + org_token_len, token_in, token_len);
        org_token_len += token_len;

        if(pwd_len != 0 && 128 >= pwd_len + org_token_len) {
            memcpy(buff + org_token_len, passwd, pwd_len);
            org_token_len += pwd_len;
        }

        utils_sha256(buff, org_token_len, gen_token);
        memcpy(token_out, gen_token, AWSS_TOKEN_LEN);

    } else if (token_len == AWSS_TOKEN_LEN && token_in != NULL) {
       memcpy(token_out, token_in, AWSS_TOKEN_LEN);
    } else {
        awss_warn("no token");
        ret = STATE_BIND_NO_APP_TOKEN;
    }

    return ret;
}

/**
 * @brief do AP diagnosis, to find out AP connection fail details
 * 
 * @param [in] p_ap_ssid: AP ssid to diagnosis
 *
 * @retval  0 : diagnosis done
 * @note
 *        after awss_connect invoked and AP connect fail, should invoke
 *        this function to do AP diagnosis
 */
int awss_ap_diagnosis(char *p_ap_ssid)
{
    ap_scan_info_t scan_result;
    int ap_scan_result = -1;
    memset(&scan_result, 0, sizeof(ap_scan_info_t));
    ap_scan_result = awss_apscan_process(NULL, p_ap_ssid, &scan_result);
    if ( (ap_scan_result == 0) && (scan_result.found) ) {
        if (scan_result.rssi < WIFI_RSSILEVEL_4) {
            dump_awss_status(STATE_WIFI_AP_RSSI_TOO_LOW, "connect %s fail rssi(%d) low", p_ap_ssid, scan_result.rssi);
        } else {
            dump_awss_status(STATE_WIFI_AP_CONN_IP_GET_FAIL, "connect %s fail", p_ap_ssid);
        }
    } else {
        dump_awss_status(STATE_WIFI_AP_DISCOVER_FAIL, "%s not found", p_ap_ssid);
    }
    return 0;
}

int awss_connect(char ssid[HAL_MAX_SSID_LEN], char passwd[HAL_MAX_PASSWD_LEN], uint8_t *bssid, uint8_t bssid_len,
                 uint8_t *token, uint8_t token_len, bind_token_type_t token_type)
{
    unsigned char final_token[AWSS_TOKEN_LEN] = {0};
    unsigned char final_bssid[6] = {0};

    uint8_t has_bssid = 1;
    int ret;

    /*need to complete the token*/
    ret = awss_complete_token(passwd, bssid, bssid_len, token, token_len, final_token);

    if (ret == STATE_SUCCESS) {
        awss_set_token(final_token, token_type);
		//awss_token_initial_lifetime();
    } else {
        dump_dev_bind_status(STATE_BIND_NO_APP_TOKEN, "bind: no app token");
    }

    /*need to complete the bssid */
    if(bssid_len > 0 && bssid_len < 6 && bssid != NULL) {
        if(zc_bssid != NULL) {
            memcpy(final_bssid, zc_bssid, 6);
        }else {
            has_bssid = 0;
        }
    } else if (bssid_len == 6 && bssid != NULL){
        memcpy(final_bssid, bssid, 6);
    } else {
        has_bssid = 0;
    }

    return HAL_Awss_Connect_Ap(WLAN_CONNECTION_TIMEOUT_MS, ssid, passwd, 0, 0, has_bssid ? final_bssid : NULL, 0);
}


#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif

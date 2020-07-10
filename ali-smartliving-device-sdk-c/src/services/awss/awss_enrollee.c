/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include <stdlib.h>
#include "aws_lib.h"
#include "os.h"
#include "awss.h"
#include "awss_enrollee.h"
#include "awss_main.h"
#include "passwd.h"
#include "awss_cmp.h"
#include "awss_packet.h"
#include "awss_wifimgr.h"
#include "awss_statis.h"
#include "awss_crypt.h"
#include "zconfig_utils.h"

#ifndef AWSS_DISABLE_ENROLLEE

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C"
{
#endif

const uint8_t probe_req_frame[ZC_PROBE_LEN] = {
    0x40, 0x00,  // mgnt type, frame control
    0x00, 0x00,  // duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // DA
    0x28, 0xC2, 0xDD, 0x61, 0x68, 0x83,  // SA, to be replaced with wifi mac
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // BSSID
    0xC0, 0x79,  // seq
    0x00, 0x00,  // hide ssid,
    0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x8C, 0x92, 0x98, 0xA4,  // supported rates
    0x32, 0x04, 0xB0, 0x48, 0x60, 0x6C,  // extended supported rates
    0x3F, 0x84, 0x10, 0x9E  // FCS
};

static uint8_t *g_dev_sign; /* pointer to dev_name_len start pos */
static uint8_t *g_product_key; /* pointer to model_len start pos */
static uint8_t *enrollee_frame;
static uint16_t enrollee_frame_len;

static int awss_enrollee_decrypt_passwd(uint8_t *ie, uint8_t ie_len,
                               uint8_t out_ssid[OS_MAX_SSID_LEN],
                               uint8_t out_passwd[OS_MAX_PASSWD_LEN],
                               uint8_t out_bssid[ETH_ALEN],
                               uint8_t out_token[ZC_MAX_TOKEN_LEN],
                               uint8_t *out_token_type);

void awss_enrollee_init_info(void)// void enrollee_raw_frame_init(void)
{
    char *pk = NULL, *dev_name = NULL, *text = NULL;
    uint8_t sign[ENROLLEE_SIGN_SIZE + 1] = {0};
    char key[OS_DEVICE_SECRET_LEN + 1] = {0};
    int dev_name_len, pk_len;
    int len, ie_len;

    if (enrollee_frame_len) {
        awss_warn("enr_frame already inited");
        return;
    }

    dev_name = os_zalloc(OS_DEVICE_NAME_LEN + 1);
    pk = os_zalloc(OS_PRODUCT_KEY_LEN + 1);

    os_product_get_key(pk);
    pk_len = strlen(pk);

    os_device_get_name(dev_name);
    dev_name_len = strlen(dev_name);

    len = RANDOM_MAX_LEN + dev_name_len + pk_len;
    text = os_zalloc(len + 1); /* +1 for string print */

    awss_build_sign_src(text, &len);
    if (os_get_conn_encrypt_type() == 3) { // aes-key per product
        os_product_get_secret(key);
    } else { // aes-key per device
        os_device_get_secret(key);
    }
    produce_signature(sign, (uint8_t *)text, len, key);

    os_free(text);

    ie_len = pk_len + dev_name_len + ENROLLEE_IE_FIX_LEN;
    enrollee_frame_len = sizeof(probe_req_frame) + ie_len;

    enrollee_frame = os_zalloc(enrollee_frame_len);

    /* construct the enrollee frame right now */
    len = sizeof(probe_req_frame) - MGMT_FCS_SIZE;
    memcpy(enrollee_frame, probe_req_frame, len);

    enrollee_frame[len ++] = 221; //vendor ie
    enrollee_frame[len ++] = ie_len - 2; /* exclude 221 & len */
    enrollee_frame[len ++] = 0xD8;
    enrollee_frame[len ++] = 0x96;
    enrollee_frame[len ++] = 0xE0;
    enrollee_frame[len ++] = WLAN_OUI_TYPE_ENROLLEE;/* OUI type */
    enrollee_frame[len ++] = DEVICE_TYPE_VERSION_0;/* version & dev type */

    enrollee_frame[len ++] = dev_name_len;/* dev name len*/
    memcpy(&enrollee_frame[len], dev_name, dev_name_len);
    len += dev_name_len;

    enrollee_frame[len ++] = ENROLLEE_FRAME_TYPE;/* frame type */

    g_product_key = &enrollee_frame[len]; /* pointer to pk len, see decrypt func */
    enrollee_frame[len ++] = pk_len;
    memcpy(&enrollee_frame[len], pk, pk_len);
    len += pk_len;

    enrollee_frame[len ++] = RANDOM_MAX_LEN;
    memcpy(&enrollee_frame[len], g_aes_random, RANDOM_MAX_LEN);
    len += RANDOM_MAX_LEN;

    enrollee_frame[len ++] = os_get_conn_encrypt_type();  // encrypt type
    enrollee_frame[len ++] = 0;  // signature method, 0: hmacsha1, 1: hmacsha256
    enrollee_frame[len ++] = ENROLLEE_SIGN_SIZE;  // signature length
    g_dev_sign = &enrollee_frame[len];
    memcpy(&enrollee_frame[len], sign, ENROLLEE_SIGN_SIZE);
    len += ENROLLEE_SIGN_SIZE;

    memcpy(&enrollee_frame[len],
           &probe_req_frame[sizeof(probe_req_frame) - MGMT_FCS_SIZE], MGMT_FCS_SIZE);
    len += MGMT_FCS_SIZE;

    os_free(dev_name);
    os_free(pk);

    // make sure management frame not overflow
    if (len > enrollee_frame_len) {
        awss_err("enr_frame init overflow(%d)", len);
        return;
    }

    // update probe request frame src mac
    os_wifi_get_mac(enrollee_frame + MGMT_SA_POS);

    awss_debug("enr_frame init done(%d)", len);
#if ZERO_AWSS_VERBOSE_DBG
    zconfig_dump_hex(enrollee_frame, enrollee_frame_len, 24);
#endif
}

void awss_enrollee_destroy_info(void)
{
    if (enrollee_frame_len) {
        os_free(enrollee_frame);
        enrollee_frame_len = 0;
        enrollee_frame = NULL;
        g_dev_sign = NULL;
        g_product_key = NULL;
    }
}

void awss_enrollee_broadcast_info(void)
{
    if (enrollee_frame_len == 0 || enrollee_frame == NULL) {
        awss_warn("enr_frame not inited");
        return;
    }
    //awss_debug("enrollee send ProbReqA");
    os_wifi_send_80211_raw_frame(FRAME_PROBE_REQ, enrollee_frame,
                                 enrollee_frame_len);
}

/* return 0 for success, -1 dev_name not match, otherwise return -2 */
static int awss_enrollee_decrypt_passwd(
    uint8_t *ie, uint8_t ie_len,
    uint8_t out_ssid[OS_MAX_SSID_LEN],
    uint8_t out_passwd[OS_MAX_PASSWD_LEN],
    uint8_t out_bssid[ETH_ALEN],
    uint8_t out_token[ZC_MAX_TOKEN_LEN],
    uint8_t *out_token_type)
{
    uint8_t tmp_ssid[OS_MAX_SSID_LEN + 1] = {0}, tmp_passwd[OS_MAX_PASSWD_LEN + 1] = {0};
    uint8_t tmp_token[ZC_MAX_TOKEN_LEN] = {0};
    uint8_t *p_dev_name_sign = NULL, *p_ssid = NULL, *p_passwd = NULL, *p_bssid = NULL, *p_token = NULL;
    uint8_t dev_type_ver;
    uint8_t ie_idx = 0;
    uint8_t token_len = 0;
    uint8_t token_type = 0;
    uint8_t region_id;

    // ie[0] - Vendor Spec Element(221)
    // ie[1] - ie length
    // ie[2..4] - OUI
    // ie[5] - OUI type
    // ie[6] - Version&DevType
    // ie[7] - Length of Sign
    // ie[8..x] - Sign
    // ie[x+1] - Frame Type (0)
    // ie[x+2] - Length of SSID
    // ie[x+3..y] - SSID
    // ie[y+1] - Length of passwd
    // ie[y+2..z] - passwd
    // ie[z+1..z+6] - BSSID
    // ie[z+7] - Length of Token
    // ie[z+8..] - Token
    // ...... - RFU

    ie_idx += WLAN_VENDOR_IE_HDR_LEN;
    if ( (ie_len <= ie_idx) || ((ie[ie_idx] & 0x0F) != WLAN_VENDOR_DEVTYPE_ALINK_CLOUD) ) {
        dump_awss_status(STATE_WIFI_ZCONFIG_REGISTAR_PARAMS_ERROR, "enr_hdl_regi type=%d unmatch", ie[ie_idx]);
        return STATE_WIFI_ZCONFIG_REGISTAR_PARAMS_ERROR;
    }
    //awss_debug("ie_len %d > %d, to get devtype", ie_len, ie_idx);
    ie_idx++;                                   // skip version
    p_dev_name_sign = ie + ie_idx;

    if ( (ie_len <= ie_idx + ie[ie_idx]) || !g_dev_sign || memcmp(g_dev_sign, p_dev_name_sign + 1, p_dev_name_sign[0])) {
        p_dev_name_sign[p_dev_name_sign[0]] = '\0';
        dump_awss_status(STATE_WIFI_ZCONFIG_REGISTAR_PARAMS_ERROR, "enr_hdl_regi dn unmatch");
        //awss_debug("expect:");
        //if (g_dev_sign) zconfig_dump_hex(g_dev_sign, p_dev_name_sign[0], 16);
        //awss_debug("\r\nbut recv:");
        //zconfig_dump_hex(p_dev_name_sign + 1, p_dev_name_sign[0], 16);
        return STATE_WIFI_ZCONFIG_REGISTAR_PARAMS_ERROR;
    }
    //awss_debug("ie_len %d > %d, to get sign", ie_len, ie_idx + ie[ie_idx]);
    ie_idx += ie[ie_idx] + 1;                   // eating sign_len & sign[n]

    if ( (ie_len <= ie_idx) || (ie[ie_idx] != REGISTRAR_FRAME_TYPE) ) {
        dump_awss_status(STATE_WIFI_ZCONFIG_REGISTAR_PARAMS_ERROR, "enr_hdl_regi frametype=%d unmatch", ie[ie_idx]);
        return STATE_WIFI_ZCONFIG_REGISTAR_PARAMS_ERROR;
    }
    //awss_debug("ie_len %d > %d, to get frametype", ie_len, ie_idx);
    ie_idx++;                                   // eating frame type
    p_ssid = ie + ie_idx;
    if ( (ie_len <= ie_idx + ie[ie_idx]) || (ie[ie_idx] >= OS_MAX_SSID_LEN) ) {
        dump_awss_status(STATE_WIFI_ZCONFIG_REGISTAR_PARAMS_ERROR, "enr_hdl_regi ssidlen=%d out of range", ie[ie_idx]);
        return STATE_WIFI_ZCONFIG_REGISTAR_PARAMS_ERROR;
    }
    //awss_debug("ie_len %d > %d, to get ssid", ie_len, ie_idx + ie[ie_idx]);
    memcpy(tmp_ssid, &p_ssid[1], p_ssid[0]);
    awss_debug("enr_hdl_regi ssid:%s", tmp_ssid);

    ie_idx += ie[ie_idx] + 1;                   // eating ssid_len & ssid[n]

    p_passwd = ie + ie_idx;
    if ( (ie_len <= ie_idx + ie[ie_idx]) || p_passwd[0] >= OS_MAX_PASSWD_LEN) {
        dump_awss_status(STATE_WIFI_ZCONFIG_REGISTAR_PARAMS_ERROR, "enr_hdl_regi passwdlen=%d out of range", p_passwd[0]);
        return STATE_WIFI_ZCONFIG_REGISTAR_PARAMS_ERROR;
    }
    //awss_debug("ie_len %d > %d, to get pwd", ie_len, ie_idx + ie[ie_idx]);
    ie_idx += ie[ie_idx] + 1;                   // eating passwd_len & passwd
    if ( ie_len < ie_idx + ETH_ALEN) {
        dump_awss_status(STATE_WIFI_ZCONFIG_REGISTAR_PARAMS_ERROR, "enr_hdl_regi bssid out of range");
        return STATE_WIFI_ZCONFIG_REGISTAR_PARAMS_ERROR;
    }
    //awss_debug("ie_len %d >= %d, to get bssid", ie_len, ie_idx + ETH_ALEN);
    p_bssid = ie + ie_idx;
    ie_idx += ETH_ALEN;                         // eating bssid len

    AWSS_UPDATE_STATIS(AWSS_STATIS_ZCONFIG_IDX, AWSS_STATIS_TYPE_TIME_START);

    aes_decrypt_string((char *)p_passwd + 1, (char *)tmp_passwd, p_passwd[0],
            1, os_get_conn_encrypt_type(), 0, (const char *)g_aes_random); //aes128 cfb
    if (zconfig_is_utf8((const char *)tmp_passwd, p_passwd[0]) != 1) {
        AWSS_UPDATE_STATIS(AWSS_STATIS_ZCONFIG_IDX, AWSS_STATIS_TYPE_PASSWD_ERR);
        dump_awss_status(STATE_WIFI_ZCONFIG_REGISTAR_PARAMS_ERROR, "enr_hdl_regi(passwd invalid");
        return STATE_WIFI_ZCONFIG_REGISTAR_PARAMS_ERROR;
    }

    strncpy((char *)out_passwd, (const char *)tmp_passwd, OS_MAX_PASSWD_LEN - 1);
    strncpy((char *)out_ssid, (const char *)tmp_ssid, OS_MAX_SSID_LEN - 1);
    memcpy((char *)out_bssid, (char *)p_bssid, ETH_ALEN);

    if (ie_len <= ie_idx + ie[ie_idx]) {
        awss_debug("enr_hdl_regi:token out of range");
        return 0;
    }
    //awss_debug("ie_len %d > %d, to get token", ie_len, ie_idx + ie[ie_idx]);
    token_len = ie[ie_idx];
    if (token_len) {
        memcpy((char *)out_token, (char *)(ie + ie_idx + 1), token_len);
    }
    ie_idx += ie[ie_idx] + 1;                   // eating token

    if (ie_len <= ie_idx) {
        awss_debug("enr_hdl_regi:no token type");
        return 0;
    }
    //awss_debug("ie_len %d > %d, to get token type", ie_len, ie_idx);
    token_type = ie[ie_idx];
    *out_token_type = token_type;
    if (token_len) {
        awss_set_token(out_token, token_type);
    }
    ie_idx++;                                   // eating token type  
    if (ie_len <= ie_idx) {
        awss_debug("enr_hdl_regi:no region ID");
        iotx_guider_set_dynamic_region(IOTX_CLOUD_REGION_INVALID);
        return 0;
    }
    //awss_debug("ie_len %d > %d, to get region id", ie_len, ie_idx);
    region_id = ie[ie_idx];
    iotx_guider_set_dynamic_region(region_id);
    ie_idx++;                                   // eating region id

    return 0;/* success */
}

int awss_enrollee_ieee80211_process(uint8_t *mgmt_header, int len, int link_type, struct parser_res *res, signed char rssi)
{
    const uint8_t *registrar_ie = NULL;
    struct ieee80211_hdr *hdr;
    uint16_t ieoffset;
    int fc;

    /*
     * when device try to connect current router (include adha and aha)
     * skip the new aha and process the new aha in the next scope.
     */
    if (mgmt_header == NULL || zconfig_finished)
        return ALINK_INVALID;
    /*
     * we don't process zconfig used by enrollee until user press configure button
     */
    if (awss_get_config_press() == 0)
        return ALINK_INVALID;

    hdr = (struct ieee80211_hdr *)mgmt_header;
    fc = hdr->frame_control;

    if (!ieee80211_is_probe_req(fc) && !ieee80211_is_probe_resp(fc))
        return ALINK_INVALID;

    ieoffset = offsetof(struct ieee80211_mgmt, u.probe_resp.variable);
    if (ieoffset > len)
        return ALINK_INVALID;

    registrar_ie = (const uint8_t *)cfg80211_find_vendor_ie(WLAN_OUI_ALIBABA,
            WLAN_OUI_TYPE_REGISTRAR, mgmt_header + ieoffset, len - ieoffset);
    if (registrar_ie == NULL)
        return ALINK_INVALID;

    res->u.ie.alink_ie_len = len - (registrar_ie - mgmt_header);
    res->u.ie.alink_ie = (uint8_t *)registrar_ie;

    awss_debug("enr_hdl_regi: rx respA");
#if ZERO_AWSS_VERBOSE_DBG
    zconfig_dump_hex((uint8_t *)registrar_ie, len - (registrar_ie - mgmt_header), 24);
#endif
    return ALINK_ZERO_CONFIG;
}

int awss_enrollee_recv_callback(struct parser_res *res)
{
    uint8_t tods = res->tods;
    uint8_t channel = res->channel;

    uint8_t *ie = res->u.ie.alink_ie;
    uint8_t ie_len = ie[IE_POS_IE_LEN] + 2;    // Vendor Spec Element(1 Byte) & ie length(1 Byte)
    int ret;

    if (res->u.ie.alink_ie_len < ie_len)
        return PKG_INVALID;

    ret = awss_enrollee_decrypt_passwd(ie, ie_len, zc_ssid, zc_passwd, zc_bssid, zc_token, zc_token_type);
    if (ret)
        return PKG_INVALID;

    zconfig_set_state(STATE_RCV_DONE, tods, channel);

    AWSS_UPDATE_STATIS(AWSS_STATIS_ROUTE_IDX, AWSS_STATIS_TYPE_TIME_SUC);

    return PKG_END;
}
#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif

#endif

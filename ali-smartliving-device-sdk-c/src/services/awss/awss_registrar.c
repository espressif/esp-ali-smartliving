/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */


#include <stdlib.h>
#include "json_parser.h"
#include "awss_enrollee.h"
#include "awss_utils.h"
#include "awss_main.h"
#include "os.h"
#include "awss_cmp.h"
#include "awss_wifimgr.h"
#include "awss_timer.h"
#include "awss_packet.h"
#include "zconfig_utils.h"

#ifndef AWSS_DISABLE_REGISTRAR

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

#define AWSS_JSON_DEV_NAME          "deviceName"
#define AWSS_JSON_PK                "productKey"
#define AWSS_JSON_DEV_LIST          "data"
#define AWSS_JSON_PERIOD            "timeout"
#define AWSS_JSON_CIPHER            "secret"
#define AWSS_REPORT_PKT_LEN         (512)
#define AWSS_CHECK_IN_RSP_LEN       (64)
#define AWSS_REPORT_PARAM_FMT       "{\"awssVer\":%s,\"type\":0,\"ssid\":\"%s\",\"bssid\":\"%s\",\"rssi\":%d,\"payload\":[\"%s\"]}"
#define AWSS_DEV_CIPHER_FMT         "{\"awssVer\":%s,\"productKey\":\"%s\",\"deviceName\":\"%s\",\"cipherType\":%d, \"random\":\"%s\"}"

#define REGISTRAR_LEN (ENROLLEE_SIGN_SIZE + OS_MAX_SSID_LEN + OS_MAX_PASSWD_LEN + REGISTRAR_IE_FIX_LEN + RANDOM_MAX_LEN)
#define REGISTRAR_TIMEOUT           (60)        // default found and checkin timeout(ms)
#define REGISTRAR_INQ_RPT_TIME      (500)      // start report duration(ms) when new enr in queue
#define REGISTRAR_CHECH_START_TIME  (500)      // start check duration(ms) when checkin rx from cloud
#ifdef AWSS_REGISTRAR_LOWPOWER_EN
#define REGISTRAR_SUSTAIN_TIME  (15 * 60)   // 10->15 min
#endif

static registrar_enr_record_t registrar_enr_list[MAX_ENROLLEE_NUM];
static uint8_t registrar_frame[REGISTRAR_LEN + ZC_PROBE_LEN] = { 0 };
static int registrar_frame_len;
static char registrar_inited = 0;
static char registrar_id = 0;
static void *checkin_timer = NULL;
static void *enrollee_report_timer = NULL;

extern const uint8_t *cfg80211_find_vendor_ie(
            uint32_t oui, uint8_t oui_type,
            const uint8_t *ies, int len);
int awss_registrar_enr_inqueue(registrar_enr_record_t *in);

static void awss_registrar_mgnt_frame_callback(uint8_t *buffer, int length, signed char rssi, int buffer_type);
static void awss_registrar_raw_frame_init(registrar_enr_record_t *enr);
static void awss_registrar_raw_frame_send(void);
//static void registrar_raw_frame_destroy(void);
static void awss_registrar_enr_report(void);
static int awss_registrar_checking_enr(void);
static int awss_registrar_enr_checkin_enable(char *key, char *dev_name, int timeout, char *token, int token_len, uint8_t token_type);
static int awss_registrar_enr_parse_dev_info(char *payload, int payload_len, char *product_key,
                                      char *dev_name, char *cipher, int *timeout);

#ifdef AWSS_REGISTRAR_LOWPOWER_EN
static void *registrar_sustain_timer = NULL;        // registrar sustain for some time, then stop for saving power
static void awss_registrar_sustain_timout_hdl(void)
{
    if (registrar_inited) {
        awss_registrar_deinit();
    }
}
#endif

// find out p_enr in Registrar ENR Record List or not
// 
static uint8_t awss_registrar_is_enr_match(registrar_enr_record_t *p_enr1, registrar_enr_record_t *p_enr2)
{
    if (!p_enr1 || !p_enr2) {
        return IOT_FALSE;
    }

    if (p_enr1->dev_name_len == p_enr2->dev_name_len &&
        0 == memcmp(p_enr1->dev_name, p_enr2->dev_name, p_enr2->dev_name_len) &&
        p_enr1->pk_len == p_enr2->pk_len &&
        0 == memcmp(p_enr1->pk, p_enr2->pk, p_enr2->pk_len)) {
        return IOT_TRUE;
    } else {
        return IOT_FALSE;
    }
}

static uint8_t awss_registrar_is_found_timeout(registrar_enr_record_t *p_enr)
{
    return time_elapsed_ms_since(p_enr->report_timestamp) > p_enr->interval * 1000;
}

static uint8_t awss_registrar_is_checkin_timeout(registrar_enr_record_t *p_enr)
{
    return time_elapsed_ms_since(p_enr->checkin_timestamp) > p_enr->checkin_timeout * 1000;
}

int awss_registrar_enr_bind_monitor(void *ctx, void *resource, void *remote, void *request)
{
    uint8_t i;
    char *payload = NULL;
    int payload_len = 0, dev_info_len = 0;
    char *key = NULL, *dev_name = NULL, *dev_info = NULL;

    payload = awss_cmp_get_coap_payload(request, &payload_len);
    if (payload == NULL || payload_len == 0) {
        goto CONNECTAP_MONITOR_END;
    }

    dev_info = json_get_value_by_name(payload, payload_len, AWSS_JSON_PARAM, &dev_info_len, NULL);
    if (dev_info == NULL || dev_info_len == 0)
        goto CONNECTAP_MONITOR_END;

    dev_name = os_zalloc(MAX_DEV_NAME_LEN + 1);
    key = os_zalloc(MAX_PK_LEN + 1);

    if (!dev_name || !key)
        goto CONNECTAP_MONITOR_END;

    if (awss_registrar_enr_parse_dev_info(dev_info, dev_info_len, key, dev_name, NULL, NULL) < 0)
        goto CONNECTAP_MONITOR_END;

    for (i = 0; i < MAX_ENROLLEE_NUM; i++) {
        if (registrar_enr_list[i].state != ENR_CHECKIN_ONGOING)
            continue;

        if (strlen(dev_name) == registrar_enr_list[i].dev_name_len &&
            0 == memcmp(dev_name, registrar_enr_list[i].dev_name, registrar_enr_list[i].dev_name_len) &&
            strlen(key) == registrar_enr_list[i].pk_len &&
            0 == memcmp(key, registrar_enr_list[i].pk, registrar_enr_list[i].pk_len)) {
            registrar_enr_list[i].state = ENR_FREE;
            awss_debug("enr_bind_moni:dn:%s done", registrar_enr_list[i].dev_name);
        }
    }

CONNECTAP_MONITOR_END:
    if (dev_name) os_free(dev_name);
    if (key) os_free(key);
    return 0;
}

static int awss_registrar_enr_parse_dev_info(char *payload, int payload_len,
                                      char *product_key, char *dev_name,
                                      char *cipher, int *timeout)
{
    if (product_key == NULL || dev_name == NULL)
        return -1;

    char *elem = NULL;
    int len = 0;

    elem = json_get_value_by_name(payload, payload_len, AWSS_JSON_PK, &len, NULL);
    if (len > MAX_PK_LEN || elem == NULL)
        return -1;

    memcpy(product_key, elem, len);

    len = 0;
    elem = json_get_value_by_name(payload, payload_len, AWSS_JSON_DEV_NAME, &len, NULL);
    if (len > MAX_DEV_NAME_LEN || elem == NULL)
        return -1;

    memcpy(dev_name, elem, len);

    len = 0;
    elem = json_get_value_by_name(payload, payload_len, AWSS_JSON_PERIOD, &len, NULL);
    if (elem && timeout)
        *timeout = atoi(elem);

    len = 0;
    elem = json_get_value_by_name(payload, payload_len, AWSS_JSON_CIPHER, &len, NULL);
    if (elem && cipher && len <= RANDOM_MAX_LEN * 2)
        memcpy(cipher, elem, len);

    return 0;
}

static void awss_registrar_raw_frame_init(registrar_enr_record_t *enr)
{
    int len, ie_len;

    char passwd[OS_MAX_PASSWD_LEN + 1] = {0};
    char ssid[OS_MAX_SSID_LEN + 1] = {0};
    uint8_t bssid[OS_ETH_ALEN] = {0};
    int ssid_len, passwd_len;

    os_wifi_get_ap_info(ssid, passwd, bssid);
    ssid_len = strlen(ssid);
    if (ssid_len > OS_MAX_SSID_LEN - 1) {
        ssid_len = OS_MAX_SSID_LEN - 1;
    }

    passwd_len = strlen(passwd);
    if (passwd_len > OS_MAX_PASSWD_LEN - 1) {
        passwd_len = OS_MAX_PASSWD_LEN - 1;
    }

    ie_len = ENROLLEE_SIGN_SIZE + ssid_len + passwd_len + REGISTRAR_IE_FIX_LEN;

    if (enr->token_len == RANDOM_MAX_LEN) {
        ie_len += RANDOM_MAX_LEN;
    }

    registrar_frame_len = sizeof(probe_req_frame) + ie_len;

    /* construct the registrar frame right now */
    len = sizeof(probe_req_frame) - MGMT_FCS_SIZE;
    memcpy(registrar_frame, probe_req_frame, len);

    registrar_frame[len ++] = 221; //vendor ie
    registrar_frame[len ++] = ie_len - 2; /* exclude 221 & len */
    registrar_frame[len ++] = 0xD8;
    registrar_frame[len ++] = 0x96;
    registrar_frame[len ++] = 0xE0;
    registrar_frame[len ++] = WLAN_OUI_TYPE_REGISTRAR;/* OUI type */
    registrar_frame[len ++] = DEVICE_TYPE_VERSION_0;/* version & dev type */
    registrar_frame[len ++] = enr->sign_len;/* dev signature len*/
    memcpy(&registrar_frame[len], enr->sign, enr->sign_len);
    len += enr->sign_len;
    registrar_frame[len ++] = REGISTRAR_FRAME_TYPE;/* frame type */

    registrar_frame[len ++] = ssid_len;
    memcpy(&registrar_frame[len], ssid, ssid_len);
    len += ssid_len;

    registrar_frame[len ++] = passwd_len;

    {
        p_aes128_t aes = os_aes128_init(&enr->key[0], enr->random, PLATFORM_AES_ENCRYPTION);
        os_aes128_cfb_encrypt(aes, (uint8_t *)passwd, passwd_len, (uint8_t *)&registrar_frame[len]);
        os_aes128_destroy(aes);
    }

    len += passwd_len;

    memcpy(&registrar_frame[len], bssid, ETH_ALEN);
    len += ETH_ALEN;

    registrar_frame[len ++] = enr->token_len;
    if (enr->token_len == RANDOM_MAX_LEN) {
        memcpy(&registrar_frame[len], enr->token, RANDOM_MAX_LEN);
        len += RANDOM_MAX_LEN;
    }
    registrar_frame[len ++] = enr->token_type;
    registrar_frame[len ++] = enr->region_id;

    memcpy(&registrar_frame[len],
           &probe_req_frame[sizeof(probe_req_frame) - MGMT_FCS_SIZE], MGMT_FCS_SIZE);
    len += MGMT_FCS_SIZE;

    // make sure management frame not overflow
    if (len > registrar_frame_len) {
        awss_err("enr_respA init overflow(%d)", len);
        return;
    }

    /* update probe request frame src mac */
    os_wifi_get_mac(registrar_frame + MGMT_SA_POS);

    {
        //dump registrar info
        awss_debug("enr_respA init done(%d)", len);
#if ZERO_AWSS_VERBOSE_DBG
        zconfig_dump_hex(registrar_frame, registrar_frame_len, 24);
#endif
    }
}

/*
static void registrar_raw_frame_destroy(void)
{
    if (registrar_frame_len) {
        //os_free(registrar_frame);
        //registrar_frame = NULL;
        registrar_frame_len = 0;
    }
}
*/

static void awss_registrar_raw_frame_send(void)
{
    /* suppose registrar_frame was ready
     * @see awss_registrar_checking_enr()
     */
    awss_debug("enr_respA send");
    int ret = os_wifi_send_80211_raw_frame(FRAME_PROBE_REQ, registrar_frame,
                                           registrar_frame_len);
    if (ret) {
        awss_warn("enr_respA failed");
    }
}

static int awss_registrar_enr_cipher_enable(char *key, char *dev_name, char *cipher)
{
    int i;
    registrar_enr_record_t *temp_enr = NULL;

    awss_debug("enr_cipher_reply:key:%s, dn:%s, cipher:%s\r\n", key, dev_name, cipher);

    if (strlen(key) > MAX_PK_LEN ||
        strlen(dev_name) > MAX_DEV_NAME_LEN) {
        return 0;
    }

    for (i = 0; i < MAX_ENROLLEE_NUM; i++) {
        temp_enr = &registrar_enr_list[i];

        if (temp_enr->state != ENR_CHECKIN_CIPHER) {
            continue;
        }
        if (strlen(dev_name) == temp_enr->dev_name_len &&
            0 == memcmp(dev_name, temp_enr->dev_name, temp_enr->dev_name_len) &&
            strlen(key) == temp_enr->pk_len &&
            0 == memcmp(key, temp_enr->pk, temp_enr->pk_len)) {

            uint8_t *key_byte = os_zalloc(MAX_KEY_LEN + 1);
            utils_str_to_hex(cipher, strlen(cipher), key_byte, MAX_KEY_LEN);
            memcpy((char *)temp_enr->key, key_byte, AES_KEY_LEN);
            os_free(key_byte);

            temp_enr->state = ENR_CHECKIN_ONGOING;

            if (checkin_timer == NULL) {
                checkin_timer = HAL_Timer_Create("checkin", (void (*)(void *))awss_registrar_checking_enr, NULL);
            }
            HAL_Timer_Stop(checkin_timer);
            HAL_Timer_Start(checkin_timer, REGISTRAR_CHECH_START_TIME);
            awss_debug("enr_cipher_en: start");
            return 1;
        }
    }
    awss_debug("enr_cipher_en: mismatch");
    return 0;
}

void awss_registrar_enr_cipher_reply(void *pcontext, void *pclient, void *msg)
{
    int dev_info_len = 0;
    char *key = NULL, *dev_name = NULL, *dev_info = NULL, *cipher = NULL;
    uint32_t payload_len;
    char *payload;
    int ret;

    ret = awss_cmp_mqtt_get_payload(msg, &payload, &payload_len);

    if (ret != 0)
        goto CIPHER_ERR;

    if (payload == NULL || payload_len == 0)
        goto CIPHER_ERR;

    dev_name = os_zalloc(MAX_DEV_NAME_LEN + 1);
    cipher = os_zalloc(RANDOM_MAX_LEN * 2 + 1);
    key = os_zalloc(MAX_PK_LEN + 1);

    if (!dev_name || !key || !cipher)
        goto CIPHER_ERR;

    awss_debug("enr_cipher_reply len:%u, payload:%s", payload_len, payload);

    dev_info = json_get_value_by_name(payload, payload_len, AWSS_JSON_DEV_LIST, &dev_info_len, NULL);
    if (dev_info == NULL || dev_info_len == 0)
        goto CIPHER_ERR;

    if (awss_registrar_enr_parse_dev_info(dev_info, dev_info_len, key, dev_name, cipher, NULL) < 0)
        goto CIPHER_ERR;

    awss_registrar_enr_cipher_enable(key, dev_name, cipher);

    os_free(dev_name);
    os_free(cipher);
    os_free(key);

    return;
CIPHER_ERR:
    if (dev_name) os_free(dev_name);
    if (cipher) os_free(cipher);
    if (key) os_free(key);
    awss_warn("enr_cipher_reply rx failed");
    return;
}

/* 0 -- cipher get send success, -1 -- cipher get send fail */
static int awss_registrar_get_cipher(int i)
{
    int packet_len = AWSS_REPORT_PKT_LEN - 1;
    char topic[TOPIC_LEN_MAX] = {0};

    char *param = os_zalloc(AWSS_REPORT_PKT_LEN);
    char *packet = os_zalloc(AWSS_REPORT_PKT_LEN);
    if (param == NULL || packet == NULL)
        goto REQ_CIPHER_ERR;

    {
        char id[MSG_REQ_ID_LEN] = {0};
        char rand_str[(RANDOM_MAX_LEN << 1) + 1] = {0};

        utils_hex_to_str(registrar_enr_list[i].random, RANDOM_MAX_LEN, rand_str, sizeof(rand_str));
        snprintf(id, MSG_REQ_ID_LEN - 1, "\"%u\"", registrar_id ++);
        snprintf(param, AWSS_REPORT_PKT_LEN - 1, AWSS_DEV_CIPHER_FMT,
                 AWSS_VER, registrar_enr_list[i].pk, registrar_enr_list[i].dev_name, registrar_enr_list[i].security, rand_str);
        awss_build_packet(AWSS_CMP_PKT_TYPE_REQ, id, ILOP_VER, METHOD_EVENT_ZC_CIPHER, param, 0, packet, &packet_len);
        os_free(param);
    }

    awss_build_topic(TOPIC_ZC_CIPHER, topic, TOPIC_LEN_MAX);
    awss_cmp_mqtt_send(topic, packet, packet_len, 1);
    awss_debug("enr_cipher_get:send");

    os_free(packet);

    return 0;

REQ_CIPHER_ERR:
    if (param) os_free(param);
    if (packet) os_free(packet);
    awss_debug("enr_cipher_get:fail");

    return -1;
}

/* 1 -- checkin onging, 0 -- idle */
static int awss_registrar_checking_enr(void)
{
    int pri = 65536;
    uint8_t i;
    uint8_t need_send = IOT_FALSE;
    registrar_enr_record_t *temp_enr = NULL;

    for (i = 0; i < MAX_ENROLLEE_NUM; i++) {
        temp_enr = &registrar_enr_list[i];
        if ((ENR_CHECKIN_ENABLE == temp_enr->state) ||
            (ENR_CHECKIN_CIPHER == temp_enr->state) ||
            (ENR_CHECKIN_ONGOING == temp_enr->state)) {
            // eliminate the checkin timeout element imediate
            if (awss_registrar_is_checkin_timeout(temp_enr)) {
                memset(temp_enr, 0, sizeof(registrar_enr_list[0]));
                temp_enr->state = ENR_FREE;
            }

            if (ENR_CHECKIN_ENABLE == temp_enr->state) {
                if (pri > temp_enr->checkin_priority) {
                    pri = temp_enr->checkin_priority;
                    if (awss_registrar_get_cipher(i) >= 0) {
                        temp_enr->state = ENR_CHECKIN_CIPHER;
                    } else {
                        // do nothing, cipher get send fail, wait for next process
                    }
                }
            } else if (ENR_CHECKIN_CIPHER == temp_enr->state) {
                // wait for cipher get response
            } else if (ENR_CHECKIN_ONGOING == temp_enr->state) {
                awss_registrar_raw_frame_init(temp_enr);
                awss_registrar_raw_frame_send();
                need_send = IOT_TRUE;
            } else {
                // do nothing
            }
        }
    }
    
    // undergoing
    if (need_send) {
        awss_debug("checking_enr continue");
        if (checkin_timer == NULL) {
            checkin_timer = HAL_Timer_Create("checkin", (void (*)(void *))awss_registrar_checking_enr, NULL);
        }
        HAL_Timer_Stop(checkin_timer);
        HAL_Timer_Start(checkin_timer, os_awss_get_channelscan_interval_ms() * 15 / 16);
        return 1;
    } else {
        awss_debug("checking_enr idle");
        return 0;
    }
}

static int awss_registrar_enr_checkin_enable(char *key, char *dev_name, int timeout, char *token, int token_len, uint8_t token_type)
{
    int i;
    registrar_enr_record_t *temp_enr = NULL;

    awss_debug("enr_checkin_en:key:%s, dn:%s, timeout:%u", key, dev_name, timeout);
    if (strlen(key) > MAX_PK_LEN ||
        strlen(dev_name) > MAX_DEV_NAME_LEN) {
        return 0;
    }

    for (i = 0; i < MAX_ENROLLEE_NUM; i++) {
        temp_enr = &registrar_enr_list[i];

        if (ENR_FOUND != temp_enr->state) {
            continue;
        }

        if (strlen(dev_name) == temp_enr->dev_name_len &&
            0 == memcmp(dev_name, temp_enr->dev_name, temp_enr->dev_name_len) &&
            strlen(key) == temp_enr->pk_len &&
            0 == memcmp(key, temp_enr->pk, temp_enr->pk_len)) {

            temp_enr->state = ENR_CHECKIN_ENABLE;
            temp_enr->checkin_priority = 1;
            temp_enr->checkin_timeout = timeout <= 0 ? REGISTRAR_TIMEOUT : timeout;
            temp_enr->checkin_timestamp = os_get_time_ms();

            temp_enr->token_len = token_len / 2;
            if ( (token != NULL) && (token_len == RANDOM_MAX_LEN * 2) ) {
                temp_enr->token_len = RANDOM_MAX_LEN;
                utils_str_to_hex(token, token_len, (unsigned char *)(temp_enr->token), RANDOM_MAX_LEN);
            }
            temp_enr->token_type = token_type;
            temp_enr->region_id = (uint8_t)iotx_guider_get_region_id();

            if (checkin_timer == NULL) {
                checkin_timer = HAL_Timer_Create("checkin", (void (*)(void *))awss_registrar_checking_enr, NULL);
            }
            HAL_Timer_Stop(checkin_timer);
            HAL_Timer_Start(checkin_timer, REGISTRAR_CHECH_START_TIME);
            awss_debug("enr_checkin_en: start");
            return 1;
        }
    }
    awss_debug("enr_checkin_en: mismatch");
    return 0;
}

void awss_registrar_cloud_checkin(void *pcontext, void *pclient, void *msg)
{
    char *packet = NULL;
    int len = 0, timeout = 0;
    int packet_len = AWSS_CHECK_IN_RSP_LEN, dev_info_len = 0;
    char *key = NULL, *dev_name = NULL, *dev_info = NULL;
    int token_len = 0;
    char *p_token = NULL;
    uint8_t token_type = 0;
    char *ext = NULL;
    int ext_len = 0;
    char *elem = NULL;
    int elem_len = 0;
    uint32_t payload_len;
    char *payload;
    int ret;

    ret = awss_cmp_mqtt_get_payload(msg, &payload, &payload_len);

    if (ret != 0)
        goto CHECKIN_FAIL;

    if (payload == NULL || payload_len == 0)
        goto CHECKIN_FAIL;

    dev_name = os_zalloc(MAX_DEV_NAME_LEN + 1);
    packet = os_zalloc(AWSS_CHECK_IN_RSP_LEN + 1);
    key = os_zalloc(MAX_PK_LEN + 1);
    if (!dev_name || !key || !packet)
        goto CHECKIN_FAIL;

    awss_debug("enr_checkin len:%u, payload:%s", payload_len, payload);

    dev_info = json_get_value_by_name(payload, payload_len, AWSS_JSON_PARAM, &dev_info_len, NULL);
    if (dev_info == NULL || dev_info_len == 0)
        goto CHECKIN_FAIL;

    if (awss_registrar_enr_parse_dev_info(dev_info, dev_info_len, key, dev_name, NULL, &timeout) < 0)
        goto CHECKIN_FAIL;

    p_token = json_get_value_by_name(dev_info, dev_info_len, AWSS_JSON_TOKEN, &token_len, NULL);
    awss_debug("enr_checkin: token(%d) %.*s", token_len, token_len, p_token);

    ext = json_get_value_by_name(dev_info, dev_info_len, AWSS_JSON_EXT, &ext_len, NULL);
    if (ext && (ext_len > 0)) {
        elem = json_get_value_by_name(ext, ext_len, AWSS_JSON_TOKEN_TYPE, &elem_len, NULL);
        if (elem) {
            token_type = atoi(elem);
        }
    }

    awss_registrar_enr_checkin_enable(key, dev_name, timeout, p_token, token_len, token_type);

    {
        char *id = NULL;
        char id_str[MSG_REQ_ID_LEN] = {0};
        id = json_get_value_by_name(payload, payload_len, AWSS_JSON_ID, &len, NULL);
        memcpy(id_str, id, len > MSG_REQ_ID_LEN - 1 ? MSG_REQ_ID_LEN - 1 : len);
        awss_build_packet(AWSS_CMP_PKT_TYPE_RSP, id_str, ILOP_VER, METHOD_EVENT_ZC_CHECKIN, "{}", 200, packet, &packet_len);
    }
    char reply[TOPIC_LEN_MAX] = {0};
    awss_build_topic(TOPIC_ZC_CHECKIN_REPLY, reply, TOPIC_LEN_MAX);
    awss_cmp_mqtt_send(reply, packet, packet_len, 1);

    os_free(dev_name);
    os_free(packet);
    os_free(key);
    return;

CHECKIN_FAIL:
    if (dev_name) os_free(dev_name);
    if (packet) os_free(packet);
    if (key) os_free(key);

    awss_warn("enr_checkin failed");
    return;
}

static int awss_registrar_enr_set_intvl(char *key, char *dev_name, int interval)
{
    int i;
    registrar_enr_record_t *temp_enr = NULL;

    awss_debug("enr_found_reply:key:%s, dn:%s, intvl:%u", key, dev_name, interval);
    if (strlen(key) > MAX_PK_LEN ||
        strlen(dev_name) > MAX_DEV_NAME_LEN) {
        awss_warn("enr_found_reply:key or dn overflow");
        return -1;
    }

    for (i = 0; i < MAX_ENROLLEE_NUM; i++) {
        temp_enr = &registrar_enr_list[i];
        if (ENR_FOUND == temp_enr->state) {
            if (strlen(dev_name) == temp_enr->dev_name_len &&
                0 == memcmp(dev_name, temp_enr->dev_name, temp_enr->dev_name_len) &&
                strlen(key) == temp_enr->pk_len &&
                0 == memcmp(key, temp_enr->pk, temp_enr->pk_len)) {

                temp_enr->interval = interval <= 0 ? REGISTRAR_TIMEOUT : interval;
                break;
            }
        }
    }

    if (i >= MAX_ENROLLEE_NUM) {
        awss_warn("enr_found_reply:dn not found");
    }
    
    return 0;
}

void awss_registrar_enr_found_reply(void *pcontext, void *pclient, void *msg)
{
    int interval = 0;
    int dev_list_len = 0;
    char *dev_list = NULL;
    char *key = NULL, *dev_name = NULL;
    uint32_t payload_len;
    char *payload;
    int ret;

    ret = awss_cmp_mqtt_get_payload(msg, &payload, &payload_len);

    if (ret != 0)
        goto REPORT_REPLY_FAIL;

    if (payload == NULL || payload_len == 0)
        goto REPORT_REPLY_FAIL;

    awss_debug("enr_found_reply:%s", payload);
    dev_name = os_zalloc(MAX_DEV_NAME_LEN + 1);
    key = os_zalloc(MAX_PK_LEN + 1);

    if (!dev_name || !key)
        goto REPORT_REPLY_FAIL;

    dev_list = json_get_value_by_name(payload, payload_len, AWSS_JSON_DEV_LIST, &dev_list_len, NULL);
    if (dev_list == NULL)
        goto REPORT_REPLY_FAIL;

    char *str_pos, *entry;
    int entry_len, type;
    json_array_for_each_entry(dev_list, dev_list_len, str_pos, entry, entry_len, type) {
        memset(dev_name, 0,  MAX_DEV_NAME_LEN + 1);
        memset(key, 0, MAX_PK_LEN + 1);
        if (awss_registrar_enr_parse_dev_info(entry, entry_len, key, dev_name, NULL, &interval) < 0)
            continue;

        awss_registrar_enr_set_intvl(key, dev_name, interval);
    }

    os_free(dev_name);
    os_free(key);
    return;

REPORT_REPLY_FAIL:
    if (dev_name) os_free(dev_name);
    if (key) os_free(key);

    awss_warn("enr_found_reply rx failed");
    return;
}

static int awss_registrar_enr_report_send(uint8_t *payload, int payload_len, signed char rssi)
{
    int i;
    char *payload_str = NULL;
    char *param = NULL, *packet = NULL;
    int packet_len = AWSS_REPORT_PKT_LEN - 1;

    payload_str = os_zalloc(payload_len * 2 + 1);
    param = os_zalloc(AWSS_REPORT_PKT_LEN);
    packet = os_zalloc(AWSS_REPORT_PKT_LEN);
    if (!payload_str || !param || !packet)
        goto REPORT_FAIL;

    {
        char id[MSG_REQ_ID_LEN] = {0};
        uint8_t bssid[OS_ETH_ALEN] = {0};
        char ssid[OS_MAX_SSID_LEN + 1] = {0};
        char bssid_str[OS_ETH_ALEN * 2 + 6] = {0};

        os_wifi_get_ap_info(ssid, NULL, bssid);
        sprintf(bssid_str, "%02X:%02X:%02X:%02X:%02X:%02X", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);

        for (i = 0; i < payload_len; i ++)
            sprintf(&payload_str[i * 2], "%02X", payload[i]);

        payload_str[payload_len * 2] = '\0'; /* sprintf not add '\0' in the end of string in qcom */

        snprintf(id, MSG_REQ_ID_LEN - 1, "\"%u\"", registrar_id ++);

        snprintf(param, AWSS_REPORT_PKT_LEN - 1, AWSS_REPORT_PARAM_FMT,
                 AWSS_VER, ssid, bssid_str, rssi > 0 ? rssi - 256 : rssi, payload_str);
        os_free(payload_str);
        awss_build_packet(AWSS_CMP_PKT_TYPE_REQ, id, ILOP_VER, METHOD_EVENT_ZC_ENROLLEE, param, 0, packet, &packet_len);
        os_free(param);
    }

    char topic[TOPIC_LEN_MAX] = {0};
    awss_build_topic(TOPIC_ZC_ENROLLEE, topic, TOPIC_LEN_MAX);
    awss_debug("enr_report:topic:%s, packet:%s, method:%s", topic, packet, METHOD_EVENT_ZC_ENROLLEE);

    awss_cmp_mqtt_send(topic, packet, packet_len, 1);

    os_free(packet);
    return 0;

REPORT_FAIL:
    if (payload_str) os_free(payload_str);
    if (packet) os_free(packet);
    if (param) os_free(param);
    awss_warn("enr_report:send fail");

    return -1;
}

/* Enrollee report consumer */
static void awss_registrar_enr_report(void)
{
    int i;
    registrar_enr_record_t *temp_enr = NULL;
#if defined(AWSS_SUPPORT_ADHA) || defined(AWSS_SUPPORT_AHA)
    char ssid[OS_MAX_SSID_LEN + 1] = {0};
    os_wifi_get_ap_info(ssid, NULL, NULL);
    if (!strcmp(ssid, DEFAULT_SSID) || !strcmp(ssid, ADHA_SSID)) {
        awss_warn("enr_report:ignore 'aha'/'adha'");
        return;
    }
#endif

    // evict timeout enrollee
    for (i = 0; i < MAX_ENROLLEE_NUM; i++) {
        temp_enr = &registrar_enr_list[i];
        if (ENR_FOUND == temp_enr->state) {
            if (awss_registrar_is_found_timeout(temp_enr)) {
                memset(temp_enr, 0, sizeof(registrar_enr_list[0]));
                temp_enr->state = ENR_FREE;
            }
        } else if (ENR_IN_QUEUE == temp_enr->state) {
            uint16_t idx = 0;
            uint16_t payload_len = 1 + temp_enr->dev_name_len + 1 + temp_enr->pk_len +
                                    1 + temp_enr->rand_len + 3 + temp_enr->sign_len;
            uint8_t *payload = os_malloc(payload_len + 1);
            if (payload == NULL) {
                awss_warn("enr_report:payload alloc fail");
                break;
            }

            payload[idx ++] = temp_enr->dev_name_len;
            memcpy(&payload[idx], temp_enr->dev_name, temp_enr->dev_name_len);
            idx += temp_enr->dev_name_len;

            payload[idx ++] = temp_enr->pk_len;
            memcpy(&payload[idx], temp_enr->pk, temp_enr->pk_len);
            idx += temp_enr->pk_len;

            payload[idx ++] = temp_enr->rand_len;
            memcpy(&payload[idx], temp_enr->random, temp_enr->rand_len);
            idx += temp_enr->rand_len;

            payload[idx ++] = temp_enr->security;
            payload[idx ++] = temp_enr->sign_method;
            payload[idx ++] = temp_enr->sign_len;
            memcpy(&payload[idx], temp_enr->sign, temp_enr->sign_len);
            idx += temp_enr->sign_len;

            int ret = awss_registrar_enr_report_send(payload, idx, temp_enr->rssi);
            if (ret == 0) {
                temp_enr->state = ENR_FOUND;
                temp_enr->report_timestamp = os_get_time_ms();
            }

            awss_trace("enr_report:%s, dn:%s period:%dms",
                        ret == 0 ? "success" : "failed",
                        temp_enr->dev_name,
                        temp_enr->interval * 1000);
            os_free(payload);
        } else {
            // do nothing, other state processed in checkin stage
        }
    }
}

/* Enrollee found producer */
/*
 * 1: already saved, update timestamp
 * 0: new saved
 * -1: no slot to save, drop
 */
int awss_registrar_enr_inqueue(registrar_enr_record_t *in)
{
    uint8_t i, empty_slot = MAX_ENROLLEE_NUM;
    registrar_enr_record_t *temp_enr = NULL;
    uint8_t match = IOT_FALSE;
    uint8_t need_inqueue = IOT_TRUE;
    int ret = -1;
    do {
        // reduce stack used
        if (in == NULL || !os_sys_net_is_ready()) {
            awss_warn("enr_inqueue:net unready");
            return -1;
        }
#if defined(AWSS_SUPPORT_ADHA) || defined(AWSS_SUPPORT_AHA)
        char ssid[OS_MAX_SSID_LEN + 1] = {0};
        os_wifi_get_ap_info(ssid, NULL, NULL);
        if (!strcmp(ssid, DEFAULT_SSID) || !strcmp(ssid, ADHA_SSID)) {
            awss_warn("enr_inqueue:ignore 'aha'/'adha'");
            return -1;
        }
#endif
    } while (0);

    // if new in_dev not in list, should add to list
    // if new in_dev in list, should find and update it
    for (i = 0; i < MAX_ENROLLEE_NUM; i++) {
        temp_enr = &registrar_enr_list[i];
        if (ENR_FREE == temp_enr->state) {
            // list element is empty, findout first empty slot
            if (empty_slot >= MAX_ENROLLEE_NUM) {
                empty_slot = i;
            }
        } else {
            // list element not empty:
            // case a: new enr match in list, update element
            // case b: not match, check element timeout
            match = awss_registrar_is_enr_match(in, temp_enr);
            if (ENR_IN_QUEUE == temp_enr->state) {
                if (match) {
                    // enrollee found before, update rssi
                    memcpy(temp_enr, in, ENROLLEE_INFO_HDR_SIZE);
                    temp_enr->rssi = (2 * temp_enr->rssi + in->rssi) / 3;
                    need_inqueue = IOT_FALSE;
                } else {
                    // do nothing, enr in queue must wait for reporting, if queue full, should discard
                }
            } else if (ENR_FOUND == temp_enr->state) {
                if (awss_registrar_is_found_timeout(temp_enr)) {
                    memset(temp_enr, 0, sizeof(registrar_enr_list[0]));
                    temp_enr->state = ENR_FREE;
                    if (match) {
                        empty_slot = i;
                    }
                } else {
                    if (match) {
                        need_inqueue = IOT_FALSE;
                    }
                }
            } else {
                if (match) {
                    need_inqueue = IOT_FALSE;
                }
            }
        }
    }

    if (need_inqueue) {
        if (empty_slot < MAX_ENROLLEE_NUM) {
            // add new enrollee to list, and push report procedure
            memset(&registrar_enr_list[empty_slot], 0, sizeof(registrar_enr_record_t));
            memcpy(&registrar_enr_list[empty_slot], in, ENROLLEE_INFO_HDR_SIZE);
            registrar_enr_list[empty_slot].rssi = in->rssi;
            registrar_enr_list[empty_slot].state = ENR_IN_QUEUE;
            registrar_enr_list[empty_slot].checkin_priority = 1; /* smaller means high pri */
            registrar_enr_list[empty_slot].interval = REGISTRAR_TIMEOUT;
            registrar_enr_list[empty_slot].checkin_timeout = REGISTRAR_TIMEOUT;
            awss_debug("enr_inqueue:slot[%d] dn:%s", empty_slot, in->dev_name);
            ret = 0;
            if (enrollee_report_timer == NULL) {
                enrollee_report_timer = HAL_Timer_Create("enrollee", (void (*)(void *))awss_registrar_enr_report, NULL);
            }
            HAL_Timer_Stop(enrollee_report_timer);
            HAL_Timer_Start(enrollee_report_timer, REGISTRAR_INQ_RPT_TIME);
        } else {
            awss_debug("enr_inqueue:no slot to save");
            ret = -1;
        }
    }
    else {
        awss_debug("enr_inqueue:already in queue");
        ret = 1;
    }
    
    return ret;
}

static int awss_registrar_enr_ie_process(const uint8_t *ie, signed char rssi)
{
    registrar_enr_record_t tmp_enrollee = {0};
    int ie_length = ie[IE_POS_IE_LEN] + 2;
    int ie_pos = 0;
    
    // ie[0] - Vendor Spec Element(221)
    // ie[1] - ie length
    // ie[2..4] - OUI
    // ie[5] - OUI type
    // ie[6] - Version&DevType
    // ie[7] - Length of DN
    // ie[8..x] - DN
    // ie[x+1] - Frame Type (0)
    // ie[x+2] - Length of PK
    // ie[x+3..y] - PK
    // ie[y+1] - Length of Random
    // ie[y+2..z] - Random
    // ie[z+1] - Sec type
    // ie[z+2] - Sign method
    // ie[z+3] - Length of Sign
    // ie[z+3..] - Sign
    // ...... - RFU
    ie_pos += WLAN_VENDOR_IE_HDR_LEN;

    if ( (ie_length <= ie_pos) || ((ie[ie_pos] & 0x0F) != WLAN_VENDOR_DEVTYPE_ALINK_CLOUD) ) {
        awss_warn("regi_hdl_enr type/ver=%d not match", ie[ie_pos]);
        return -1;
    }
    tmp_enrollee.dev_type_ver = ie[ie_pos];
    ie_pos ++;                                          // eating dev_type_ver

    if ( (ie_length <= ie_pos + ie[ie_pos]) || (ie[ie_pos] > MAX_DEV_NAME_LEN) ) {
        awss_warn("regi_hdl_enr dn_len=%d out of range", ie[ie_pos]);
        return -1;
    }
    tmp_enrollee.dev_name_len = ie[ie_pos];
    memcpy(tmp_enrollee.dev_name, &ie[ie_pos + 1], ie[ie_pos]);
    ie_pos += ie[ie_pos] + 1;                           // eating dev_name[n], dev_name_len

    if ( (ie_length <= ie_pos) || (ie[ie_pos] != ENROLLEE_FRAME_TYPE) ) {
        awss_warn("regi_hdl_enr frametype=%d not match", ie[ie_pos]);
        return -1;
    }
    tmp_enrollee.frame_type = ie[ie_pos];
    ie_pos ++;                                          // eating frame type

    if ( (ie_length <= ie_pos + ie[ie_pos]) || (ie[ie_pos] > MAX_PK_LEN) ) {
        awss_warn("regi_hdl_enr pk_len=%d out of range", ie[ie_pos]);
        return -1;
    }
    tmp_enrollee.pk_len = ie[ie_pos];
    memcpy(tmp_enrollee.pk, &ie[ie_pos + 1], ie[ie_pos]);
    ie_pos += ie[ie_pos] + 1;                           // eating pk[n], pk_len

    if ( (ie_length <= ie_pos + ie[ie_pos]) || ie[ie_pos] != RANDOM_MAX_LEN) {
        awss_warn("regi_hdl_enr rand_len=%d out of range", ie[ie_pos]);
        return -1;
    }
    tmp_enrollee.rand_len = ie[ie_pos];
    memcpy(tmp_enrollee.random, &ie[ie_pos + 1], RANDOM_MAX_LEN);
    ie_pos += ie[ie_pos] + 1;                           // eating random[n], rand_len

    if ( (ie_length <= ie_pos) || ie[ie_pos] > 5 || ie[ie_pos] < 3) {
        awss_warn("regi_hdl_enr sec=%d invalid", ie[ie_pos]);
        return -1;
    }
    tmp_enrollee.security = ie[ie_pos];
    ie_pos ++;                                          // eating sec type

    if ( (ie_length <= ie_pos) || ie[ie_pos] > 1) {
        awss_warn("regi_hdl_enr sign_method=%d invalid", ie[ie_pos]);
        return -1;
    }
    tmp_enrollee.sign_method = ie[ie_pos];
    ie_pos ++;                                          // eating sign method

    if ( (ie_length <= ie_pos + ie[ie_pos]) || ie[ie_pos] != ENROLLEE_SIGN_SIZE) {
        awss_warn("regi_hdl_enr sign_len=%d out of range", ie[ie_pos]);
        return -1;
    }
    tmp_enrollee.sign_len = ie[ie_pos];

    memcpy(tmp_enrollee.sign, &ie[ie_pos + 1], ie[ie_pos]);
    ie_pos += ie[ie_pos] + 1;                           // eating signature[n], sign_len

    tmp_enrollee.rssi = rssi;

    awss_registrar_enr_inqueue(&tmp_enrollee);

    return 0;
}

/**
 * @brief management frame handler
 *
 * @param[in] buffer @n 80211 raw frame or ie(information element) buffer
 * @param[in] len @n buffer length
 * @param[in] buffer_type @n 0 when buffer is a 80211 frame,
 *                          1 when buffer only contain IE info
 * @return None.
 * @see None.
 * @note None.
 */
static void awss_registrar_mgnt_frame_callback(uint8_t *buffer, int length, signed char rssi, int buffer_type)
{
    uint8_t type = buffer[0], eid;
    uint8_t need_find_ie = 0;            // 0 - no need find ie, 1 - need find ie
    int len = 0;
    int ie_max_len = length;
    const uint8_t *ie = NULL;
    if (buffer_type) {
        // ie has been filtered and found by lower layer
        ie = buffer;
    } else {
        // ie should be pased here
        switch (type) {
            case MGMT_BEACON:
                buffer += MGMT_HDR_LEN + 12;  // hdr(24) + 12(timestamp, beacon_interval, cap)
                length -= MGMT_HDR_LEN + 12;
                eid = buffer[0];
                len = buffer[1];
                if (eid != 0) {
                    //awss_warn("error eid, should be 0!");
                    return;
                }
                // skip ssid
                buffer += 2;
                buffer += len;
                length -= len;
                need_find_ie = 1;
                break;
            case MGMT_PROBE_REQ:
                buffer += MGMT_HDR_LEN;
                length -= MGMT_HDR_LEN;
                need_find_ie = 1;
                break;
            default:
                break;
        }
    }

    if (need_find_ie) {
        // mgmt frame received, should find ie
        ie = cfg80211_find_vendor_ie((uint32_t)WLAN_OUI_ALIBABA,
                                     (uint8_t)WLAN_OUI_TYPE_ENROLLEE,
                                     (const uint8_t *)buffer, (int)length);
        ie_max_len = length - (int)(ie - buffer);
    }
    // If ie found, ie buffer must include ie fix length, try to parse valid ie
    if (ie && (ie_max_len >= ie[IE_POS_IE_LEN] + 2) && ie[IE_POS_IE_LEN] + 2 >= WLAN_VENDOR_IE_HDR_LEN) {
        awss_debug("regi_mgnt rx enr frame(%d)", WLAN_OUI_TYPE_ENROLLEE);
#if ZERO_AWSS_VERBOSE_DBG
        zconfig_dump_hex((uint8_t *)ie, ie[IE_POS_IE_LEN] + 2 + MGMT_FCS_SIZE, 24);
#endif
        awss_registrar_enr_ie_process(ie, rssi);
    }
}

void awss_registrar_init(void)
{
    if (registrar_inited) {
        awss_warn("regi_init already init");
        return;
    }

    uint8_t alibaba_oui[3] = WLAN_OUI_ALIBABA_ARRAY;
    memset(registrar_enr_list, 0, sizeof(registrar_enr_list));
    registrar_inited = 1;
    os_wifi_enable_mgnt_frame_filter(FRAME_BEACON_MASK | FRAME_PROBE_REQ_MASK,
                                     (uint8_t *)alibaba_oui, awss_registrar_mgnt_frame_callback);
#ifdef AWSS_REGISTRAR_LOWPOWER_EN
    if (registrar_sustain_timer == NULL) {
        registrar_sustain_timer = HAL_Timer_Create("registrar_sustain", (void (*)(void *))awss_registrar_sustain_timout_hdl, NULL);
    }
    HAL_Timer_Stop(registrar_sustain_timer);
    HAL_Timer_Start(registrar_sustain_timer, 1000 * REGISTRAR_SUSTAIN_TIME);
#endif
    awss_debug("regi_init done");
}

void awss_registrar_deinit(void)
{
    uint8_t alibaba_oui[3] = WLAN_OUI_ALIBABA_ARRAY;
    os_wifi_enable_mgnt_frame_filter(FRAME_BEACON_MASK | FRAME_PROBE_REQ_MASK,
                                     (uint8_t *)alibaba_oui, NULL);

    registrar_inited = 0;

    awss_stop_timer(checkin_timer);
    checkin_timer = NULL;
    awss_stop_timer(enrollee_report_timer);
    enrollee_report_timer = NULL;
#ifdef AWSS_REGISTRAR_LOWPOWER_EN
    if (registrar_sustain_timer != NULL) {
        awss_stop_timer(registrar_sustain_timer);
        registrar_sustain_timer = NULL;
    }
#endif
    awss_debug("regi_deinit");
}


#ifdef AWSS_BATCH_DEVAP_ENABLE
#define REGISTRAR_MODESWITCH_PROB_MAX    60      // continue send modeswitch prob-req times after recv indication
#define REGISTRAR_MODESWITCH_PROB_FREQ   85      // modeswitch prob repeat frequency, ms
#define REGISTRAR_MODESWITCH_LOOP_CNT    2       // modeswitch prob req continue counter
#define REGISTRAR_MODESWITCH_CHAN_NUM    3
static uint8_t g_probreq_chanlist[REGISTRAR_MODESWITCH_CHAN_NUM] = {1, 6, 11};
static uint8_t *gp_registrar_switchmode_frame;
static int g_registrar_switchmode_frame_len;
static void *p_do_switchmode_timer = NULL;
static int g_cur_channel;
static uint8_t g_probreq_channum = 0;
static uint8_t g_probreq_counter = 0;

static int registrar_switchmode_frame_init(char *p_productkey, int pk_len, uint8_t tomode)
{
    int len, ie_len;

    if (g_registrar_switchmode_frame_len) {
        awss_warn("regi_swm already inited");
        return 0;
    }

    ie_len = pk_len + REGISTRAR_SWITCHMODE_IE_FIX_LEN;
    g_registrar_switchmode_frame_len = sizeof(probe_req_frame) + ie_len;
    awss_debug("regi_swm_init len %d, FIX_LEN %d", g_registrar_switchmode_frame_len, REGISTRAR_SWITCHMODE_IE_FIX_LEN);

    gp_registrar_switchmode_frame = os_zalloc(g_registrar_switchmode_frame_len);

    /* construct the enrollee frame right now */
    len = sizeof(probe_req_frame) - MGMT_FCS_SIZE;
    memcpy(gp_registrar_switchmode_frame, probe_req_frame, len);

    // joint vendor spec element
    gp_registrar_switchmode_frame[len ++] = 221; //vendor ie
    gp_registrar_switchmode_frame[len ++] = ie_len - 2; /* exclude 221 & len */
    gp_registrar_switchmode_frame[len ++] = 0xD8;
    gp_registrar_switchmode_frame[len ++] = 0x96;
    gp_registrar_switchmode_frame[len ++] = 0xE0;
    gp_registrar_switchmode_frame[len ++] = WLAN_OUI_TYPE_MODESWITCH;/* OUI type */
    gp_registrar_switchmode_frame[len ++] = DEVICE_TYPE_VERSION;/* version & dev type */
    gp_registrar_switchmode_frame[len ++] = AWSSMODE_SWITCH_FRAME_TYPE;/* frame type */
    gp_registrar_switchmode_frame[len ++] = tomode;/* switch to awss mode: 0 - zero config */
    gp_registrar_switchmode_frame[len ++] = 12;    // 120s, switch to new mode timeout
    gp_registrar_switchmode_frame[len ++] = (uint8_t)g_cur_channel;/* AP channel */
    
    gp_registrar_switchmode_frame[len ++] = pk_len;
    if (pk_len && p_productkey) {
        memcpy(&gp_registrar_switchmode_frame[len], p_productkey, pk_len);
        len += pk_len;
    }
    
    // joint FCS
    memcpy(&gp_registrar_switchmode_frame[len],
           &probe_req_frame[sizeof(probe_req_frame) - MGMT_FCS_SIZE], MGMT_FCS_SIZE);
    len += MGMT_FCS_SIZE;

    // make sure management frame not overflow
    if (len > g_registrar_switchmode_frame_len) {
        awss_err("regi_swm_init overflow(%d)", len);
        return -1;
    }

    /* update probe request frame src mac */
    os_wifi_get_mac(gp_registrar_switchmode_frame + MGMT_SA_POS);

    awss_debug("regi_swm_init done(%d)", len);
#if ZERO_AWSS_VERBOSE_DBG
    zconfig_dump_hex(gp_registrar_switchmode_frame, g_registrar_switchmode_frame_len, 24);
#endif
    return 0;
}

static void registrar_switchmode_frame_destroy(void)
{
    if (g_registrar_switchmode_frame_len) {
        os_free(gp_registrar_switchmode_frame);
        gp_registrar_switchmode_frame = NULL;
        g_registrar_switchmode_frame_len = 0;
    }
}

static void registrar_switchmode_frame_send(void)
{
    uint8_t loop_cnt;
    int ret;
    for (loop_cnt = 0; loop_cnt < REGISTRAR_MODESWITCH_LOOP_CNT; loop_cnt++) {
        ret = os_wifi_send_80211_raw_frame(FRAME_PROBE_REQ, gp_registrar_switchmode_frame,
                                           g_registrar_switchmode_frame_len);
        if (ret) {
            awss_warn("regi_swm send fail");
            return;
        }
    }
}

static void registrar_switchmode_repeat(void)
{
    uint8_t sending_chan = g_probreq_counter % REGISTRAR_MODESWITCH_CHAN_NUM;
    awss_debug("regi_swm repeat chan(%d)", g_probreq_chanlist[sending_chan]);
    os_awss_switch_channel(g_probreq_chanlist[sending_chan], 0, NULL);
    registrar_switchmode_frame_send();
    os_awss_switch_channel((char)g_cur_channel, 0, NULL);
    g_probreq_counter++;
    
    if (g_probreq_counter >= REGISTRAR_MODESWITCH_PROB_MAX) {
        // do not repeat swtchmode probe request anymore
        registrar_switchmode_frame_destroy();
        if (p_do_switchmode_timer) {
            HAL_Timer_Stop(p_do_switchmode_timer);
            HAL_Timer_Delete(p_do_switchmode_timer);
            p_do_switchmode_timer = NULL;
        }
        return;
    }

    if (p_do_switchmode_timer == NULL) {
        p_do_switchmode_timer = HAL_Timer_Create("do_switchmode", (void (*)(void *))registrar_switchmode_repeat, NULL);
    }
    HAL_Timer_Stop(p_do_switchmode_timer);
    HAL_Timer_Start(p_do_switchmode_timer, REGISTRAR_MODESWITCH_PROB_FREQ);
}

void registrar_switchmode_start(char *p_productkey, int pk_len, uint8_t awss_mode)
{
    int rssi = 0;
    int ret = 0;
    uint8_t sending_chan = 0xFF;
    g_cur_channel = -1;
    g_probreq_counter = 0;
    
    os_get_conn_link_stat(&rssi, &g_cur_channel);
    if (g_cur_channel == -1) {
        // no current channel get, should not start batch provision mode
        awss_err("regi_swm net unready");
        return;
    }

    ret = registrar_switchmode_frame_init(p_productkey, pk_len, awss_mode);
    if (ret < 0) {
        awss_err("regi_swm init fail");
        return;
    }

    sending_chan = g_probreq_counter % REGISTRAR_MODESWITCH_CHAN_NUM;
    awss_debug("regi_swm chan(%d), ap_chan(%d)", 
                                               g_probreq_chanlist[sending_chan], 
                                               g_cur_channel);

    os_awss_switch_channel((char)g_probreq_chanlist[sending_chan], 0, NULL);
    registrar_switchmode_frame_send();
    os_awss_switch_channel((char)g_cur_channel, 0, NULL);
    g_probreq_counter++;

    if (p_do_switchmode_timer == NULL) {
        p_do_switchmode_timer = HAL_Timer_Create("do_switchmode", (void (*)(void *))registrar_switchmode_repeat, NULL);
    }
    HAL_Timer_Stop(p_do_switchmode_timer);
    HAL_Timer_Start(p_do_switchmode_timer, REGISTRAR_MODESWITCH_PROB_FREQ);
}
#endif

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif

#endif

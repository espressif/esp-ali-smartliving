/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <string.h>
#include "os.h"
#include "iot_import.h"
#include "iot_export.h"
#include "passwd.h"
#include "awss_log.h"
#include "awss_cmp.h"
#include "awss_utils.h"
#include "awss_notify.h"
#include "awss_info.h"
#include "awss_dev_ap.h"
#include "json_parser.h"
#include "awss_packet.h"
#include "awss_crypt.h"
#include "awss_statis.h"
#include "zconfig_utils.h"
#include "connect_ap.h"
#include "awss_security.h"
#include "awss_event.h"

#ifdef AWSS_BATCH_DEVAP_ENABLE
#include "awss_enrollee.h"
#endif

#ifdef AWSS_SUPPORT_DEV_AP

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

#define TIMEOUT_CNT   4

typedef struct {
    char ssid[PLATFORM_MAX_SSID_LEN + 1];
    char passwd[PLATFORM_MAX_PASSWD_LEN + 1];
    uint8_t bssid[ETH_ALEN];
    uint8_t token[RANDOM_MAX_LEN + 1];
    uint16_t msgid;
    uint8_t cnt;
    uint8_t token_found;
    uint8_t got_msg;
} ap_info_t;

static int start_connect_ap(char *ssid, char *pwd, uint8_t *bssid, uint8_t *token, uint16_t msgid);
static void do_connect_ap(void);

static ap_info_t  *ap_info_ptr = NULL;
static void *g_awss_dev_ap_mutex = NULL;
static char awss_dev_ap_switchap_done = 0;
static char awss_dev_ap_switchap_resp_suc = 0;
static char awss_dev_ap_ongoing = 0;

#ifdef AWSS_BATCH_DEVAP_ENABLE
extern const uint8_t *cfg80211_find_vendor_ie(
            uint32_t oui, uint8_t oui_type,
            const uint8_t *ies, int len);

static awss_modeswitch_cb_t g_modeswitch_cb = NULL;

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
void awss_dev_ap_mgnt_frame_cb(uint8_t *buffer, int length, signed char rssi, int buffer_type)
{
    int type = buffer[0], len = 0, eid;
    const uint8_t *ie;

    if (buffer_type) {
        ie = buffer;
    }

    switch (type) {
        case MGMT_PROBE_REQ:
            //awss_debug("dev_ap mgmt probe req recv");
            buffer += MGMT_HDR_LEN;
            length -= MGMT_HDR_LEN;

            ie = cfg80211_find_vendor_ie((uint32_t)WLAN_OUI_ALIBABA,
                                         (uint8_t)WLAN_OUI_TYPE_MODESWITCH,
                                         (const uint8_t *)buffer, (int)length);
            if (ie) {
                // ie[6] - Version&DevType
                // ie[7] - Frame Type (2)
                // ie[8] - Switch to Mode
                // ie[9] - AP Channel
                // ie[10] - Length of PK
                // ie[11...] - PK
                awss_debug("ProbReqB from Registrar");
                //process_enrollee_ie(ie, rssi);
                //dump_hex((uint8_t *)ie, ie[1] + 2 + 4, 24);
                // Confirm registrar mode switch mgmt frame
                if ((ie[6] == DEVICE_TYPE_VERSION_1) && (ie[7] == AWSSMODE_SWITCH_FRAME_TYPE)) {
                    if (ie[11] != 0) {
                        // must compare productKey, because user need to restrict PK
                        char pk[OS_PRODUCT_KEY_LEN + 1] = {0};
                        os_product_get_key(pk);
                        if ((ie[11] == strlen(pk)) 
                            && !memcmp(ie + 12, pk, ie[11])) {
                            // valid productKey with me(enrollee)
                            if (g_modeswitch_cb) {
                                g_modeswitch_cb(ie[8], ie[9], ie[10]);
                            }
                        }
                    } else {
                        // do not care about productKey, just switch to enrollee
                        if (g_modeswitch_cb) {
                            g_modeswitch_cb(ie[8], ie[9], ie[10]);
                        }
                    }
                }
            }
            break;
        default:
            break;
    }
}
#endif

static int awss_dev_ap_setup()
{
    char ssid[PLATFORM_MAX_SSID_LEN + 1] = {0};
    char passwd[PLATFORM_MAX_PASSWD_LEN + 1] = {0};

    do {  // reduce stack used
        char pk[OS_PRODUCT_KEY_LEN + 1] = {0};
        char mac_str[OS_MAC_LEN + 1] = {0};

        os_product_get_key(pk);
        os_wifi_get_mac_str(mac_str);
        memcpy(mac_str + 11, mac_str + 12, 2);
        memcpy(mac_str + 13, mac_str + 15, 2);
        mac_str[15] = '\0';
        snprintf(ssid, PLATFORM_MAX_SSID_LEN, "adh_%s_%s", pk, &mac_str[9]);
    } while (0);

    awss_trace("ssid:%s\n", ssid);

    return os_awss_open_ap(ssid, passwd, 100, 0);
}

#define ALIBABA_OUI                     {0xD8, 0x96, 0xE0}

#ifdef AWSS_BATCH_DEVAP_ENABLE
int awss_dev_ap_reg_modeswit_cb(awss_modeswitch_cb_t callback)
{
    if (callback) {
        g_modeswitch_cb = callback;
    }
    return 0;
}
#endif

int awss_dev_ap_start(void)
{
    int ret = STATE_SUCCESS;
    ap_info_t dev_ap_info;
    if (g_awss_dev_ap_mutex || awss_dev_ap_ongoing) {
        dump_awss_status(STATE_WIFI_DEV_AP_ALREADY_RUN, "dev ap already running");
        return STATE_WIFI_DEV_AP_ALREADY_RUN;
    }

    if (g_awss_dev_ap_mutex == NULL) {
        g_awss_dev_ap_mutex = HAL_MutexCreate();
    }
    if (g_awss_dev_ap_mutex == NULL) {
        dump_awss_status(STATE_WIFI_DEV_AP_START_FAIL, "mutex create is null");
        goto AWSS_DEV_AP_FAIL;
    }

    memset(&dev_ap_info, 0, sizeof(dev_ap_info));
    ap_info_ptr = &dev_ap_info;
    HAL_MutexLock(g_awss_dev_ap_mutex);

    awss_dev_ap_ongoing = 1;
    awss_dev_ap_switchap_done = 0;
    awss_dev_ap_switchap_resp_suc = 0;

    ret = awss_dev_ap_setup();
    if (STATE_SUCCESS != ret) {
        dump_awss_status(STATE_WIFI_DEV_AP_START_FAIL, "dev ap setup fail");
        goto AWSS_DEV_AP_FAIL;
    }
#ifdef AWSS_BATCH_DEVAP_ENABLE
    {
        uint8_t alibaba_oui[3] = ALIBABA_OUI;
        os_wifi_enable_mgnt_frame_filter(FRAME_BEACON_MASK | FRAME_PROBE_REQ_MASK,
                                        (uint8_t *)alibaba_oui, awss_dev_ap_mgnt_frame_cb);
    }
#endif

    os_msleep(1000);  // wait for dev ap to work well
    awss_event_post(IOTX_AWSS_START);
    awss_cmp_local_init(AWSS_LC_INIT_DEV_AP);
    awss_event_post(IOTX_AWSS_ENABLE);
    #ifdef DEV_STATEMACHINE_ENABLE
    dev_awss_state_set(AWSS_PATTERN_DEV_AP_CONFIG, AWSS_STATE_START);
    #endif

    while (awss_dev_ap_ongoing) {
        os_msleep(200);
        if (awss_dev_ap_switchap_done) {
            break;
        }
        do_connect_ap();
    }
    HAL_MutexUnlock(g_awss_dev_ap_mutex);

    ret = awss_dev_ap_switchap_done == 0 ? -1 : 0;

    if (awss_dev_ap_ongoing == 0) {  // interrupt by user
        os_msleep(1000);
        return -1;
    }

    awss_dev_ap_ongoing = 0;
    extern int awss_success_notify(void);
    awss_success_notify();

AWSS_DEV_AP_FAIL:
    if (g_awss_dev_ap_mutex) {
        HAL_MutexUnlock(g_awss_dev_ap_mutex);
        HAL_MutexDestroy(g_awss_dev_ap_mutex);
    }
    g_awss_dev_ap_mutex = NULL;
    return ret;
}

int awss_dev_ap_stop(void)
{
    if (awss_dev_ap_ongoing == 0) {
        return 0;
    }

    awss_dev_ap_ongoing = 0;

    awss_trace("%s", __func__);

    if (g_awss_dev_ap_mutex) {
        HAL_MutexLock(g_awss_dev_ap_mutex);
    }

    os_awss_close_ap();
#ifdef AWSS_BATCH_DEVAP_ENABLE
    {
        uint8_t alibaba_oui[3] = ALIBABA_OUI;
        if (g_modeswitch_cb) {
            g_modeswitch_cb = NULL;
        }
        os_wifi_enable_mgnt_frame_filter(FRAME_BEACON_MASK | FRAME_PROBE_REQ_MASK,
                                        (uint8_t *)alibaba_oui, NULL);
    }
#endif

    awss_cmp_local_deinit(1);

    if (g_awss_dev_ap_mutex) {
        HAL_MutexUnlock(g_awss_dev_ap_mutex);
        HAL_MutexDestroy(g_awss_dev_ap_mutex);
        g_awss_dev_ap_mutex = NULL;
    }

    awss_dev_ap_switchap_done = 0;
    awss_dev_ap_switchap_resp_suc = 0;

    awss_trace("%s exit", __func__);

    return 0;
}

static int awss_dev_ap_switchap_resp(void *context, int result,
                                     void *userdata, void *remote,
                                     void *message)
{
    if (result == 2) { /* success */
        awss_dev_ap_switchap_resp_suc = 1;
    }
    return 0;
}

#ifdef DEV_ERRCODE_ENABLE
static int awss_dev_errcode_resp(void *context, int result,
                                     void *userdata, void *remote,
                                     void *message)
{
    if (result == 2) { /* success */
        awss_trace("dev errcode resp sucess, close soft_ap\r\n");
        awss_dev_ap_stop();
    } else {
        awss_trace("dev errcode resp fail, keep soft_ap\r\n");
    }
    return 0;
}
#endif

int wifimgr_process_dev_ap_switchap_request(void *ctx, void *resource, void *remote, void *request)
{
#define AWSS_DEV_AP_SWITCHA_RSP_LEN (512)
    char ssid[PLATFORM_MAX_SSID_LEN * 2 + 1] = {0}, passwd[PLATFORM_MAX_PASSWD_LEN + 1] = {0};
    int str_len = 0, success = 1, len = 0;
    char req_msg_id[MSG_REQ_ID_LEN] = {0};
    char random[RANDOM_MAX_LEN + 1] = {0};
    char *msg = NULL, *dev_info = NULL;
    char *str = NULL, *buf = NULL;
    char bssid[ETH_ALEN] = {0};
    char ssid_found = 0;
    uint8_t token[RANDOM_MAX_LEN + 1];
    char token_found = 0;
    uint8_t isRandomKey = 0;
    const char *p_ranodm_str = NULL;
    int ret = -1;

    static char dev_ap_switchap_parsed = 0;

    #ifdef DEV_STATEMACHINE_ENABLE
    dev_awss_state_set(AWSS_PATTERN_DEV_AP_CONFIG, AWSS_STATE_COLLECTING_SSID);
    #endif

    if (0 == awss_dev_ap_ongoing) {
        dump_awss_status(STATE_WIFI_DEV_AP_RECV_IN_WRONG_STATE, "not in awss mode");
        return -1;
    }
    if (dev_ap_switchap_parsed != 0) {
        goto DEV_AP_SWITCHAP_END;
    }
    dev_ap_switchap_parsed = 1;

    AWSS_UPDATE_STATIS(AWSS_STATIS_DAP_IDX, AWSS_STATIS_TYPE_TIME_START);

    msg = os_zalloc(AWSS_DEV_AP_SWITCHA_RSP_LEN);
    if (msg == NULL) {
        dump_awss_status(STATE_WIFI_DEV_AP_PARSE_PKT_FAIL, "switchap resp alloc fail");
        goto DEV_AP_SWITCHAP_END;
    }
    dev_info = os_zalloc(AWSS_DEV_AP_SWITCHA_RSP_LEN);
    if (dev_info == NULL) {
        dump_awss_status(STATE_WIFI_DEV_AP_PARSE_PKT_FAIL, "switchap resp alloc fail");
        goto DEV_AP_SWITCHAP_END;
    }

    buf = awss_cmp_get_coap_payload(request, &len);
    str = json_get_value_by_name(buf, len, "id", &str_len, 0);
    memcpy(req_msg_id, str, str_len > MSG_REQ_ID_LEN - 1 ? MSG_REQ_ID_LEN - 1 : str_len);
    awss_trace("dev ap, len:%u, %s\r\n", len, buf);
    buf = json_get_value_by_name(buf, len, "params", &len, 0);
    if (buf == NULL) {
        dump_awss_status(STATE_WIFI_DEV_AP_RECV_PKT_INVALID, "switchap req param fail");
        goto DEV_AP_SWITCHAP_END;
    }

    do {
        /* get security version */
        str_len = 0;
        str = json_get_value_by_name(buf, len, "security", &str_len, 0);
        if (str && str_len == 3 && !memcmp("2.0", str, str_len)) {
            awss_trace("security ver = %.*s\r\n", str_len, str);
            isRandomKey = 1;
        }

        str_len = 0;
        str = json_get_value_by_name(buf, len, "ssid", &str_len, 0);
        awss_trace("ssid, len:%u, %s\r\n", str_len, str != NULL ? str : "NULL");
        if (str && (str_len < PLATFORM_MAX_SSID_LEN)) {
            memcpy(ssid, str, str_len);
            ssid_found = 1;
        }

        if (!ssid_found) {
            str_len = 0;
            str = json_get_value_by_name(buf, len, "xssid", &str_len, 0);
            if (str && (str_len < PLATFORM_MAX_SSID_LEN * 2 - 1)) {
                memcpy(ssid, str, str_len);
                uint8_t decoded[OS_MAX_SSID_LEN] = {0};
                int len = str_len / 2;
                utils_str_to_hex(ssid, str_len, decoded, OS_MAX_SSID_LEN);
                memcpy(ssid, (const char *)decoded, len);
                ssid[len] = '\0';
            } else {
                dump_awss_status(STATE_WIFI_DEV_AP_RECV_PKT_INVALID, "witchap req ssid err");
                snprintf(msg, AWSS_DEV_AP_SWITCHA_RSP_LEN, AWSS_ACK_FMT, req_msg_id, -1, "\"ssid error\"");
                awss_event_post(IOTX_AWSS_CS_ERR);
                success = 0;
                break;
            }
        }

        str_len = 0;
        str = json_get_value_by_name(buf, len, "random", &str_len, 0);
        if (str && str_len ==  RANDOM_MAX_LEN * 2) {
            utils_str_to_hex(str, str_len, (unsigned char *)random, RANDOM_MAX_LEN);
            p_ranodm_str = str;
        } else {
            dump_awss_status(STATE_WIFI_DEV_AP_RECV_PKT_INVALID, "switchap req random len err");
            snprintf(msg, AWSS_DEV_AP_SWITCHA_RSP_LEN, AWSS_ACK_FMT, req_msg_id, -4, "\"random len error\"");
            awss_event_post(IOTX_AWSS_CS_ERR);
            success = 0;
            break;
        }

        str_len = 0;
        str = json_get_value_by_name(buf, len, "token", &str_len, 0);
        if (str && str_len ==  RANDOM_MAX_LEN * 2) {  /* token len equal to random len */
            utils_str_to_hex(str, str_len, (unsigned char *)token, RANDOM_MAX_LEN);
            token_found = 1;
        }

        str_len = 0;
        str = json_get_value_by_name(buf, len, "bssid", &str_len, 0);
        if (str) {
            os_wifi_str2mac(str, bssid);
        }

        str_len = 0;
        str = json_get_value_by_name(buf, len, "passwd", &str_len, 0);

        if (str_len < (PLATFORM_MAX_PASSWD_LEN * 2) - 1) {
            char encoded[PLATFORM_MAX_PASSWD_LEN * 2 + 1] = {0};
            memcpy(encoded, str, str_len);
			// setup random first
			//awss_set_token((uint8_t *)random);  // set in lk230
			// decrypt the password(two ways by security version)
            if (isRandomKey) {
                if (softap_decrypt_password(encoded, (const uint8_t*)p_ranodm_str, passwd) < 0) {
                    success = 0;
                    dump_awss_status(STATE_WIFI_DEV_AP_PASSWD_DECODE_FAILED, "randomkey passwd decode fail");
                    awss_event_post(IOTX_AWSS_PASSWD_ERR);
                }
            }
            else {
                if (aes_decrypt_string(encoded, passwd, str_len, 0, os_get_encrypt_type(), 1, random) < 0) {
                    /* 64bytes=2x32bytes */
                    success = 0;
                    dump_awss_status(STATE_WIFI_DEV_AP_PASSWD_DECODE_FAILED, "non-random passwd decode");
                    awss_event_post(IOTX_AWSS_PASSWD_ERR);
                }
            }
        } else {
            dump_awss_status(STATE_WIFI_DEV_AP_PASSWD_DECODE_FAILED, "passwd len err");
            snprintf(msg, AWSS_DEV_AP_SWITCHA_RSP_LEN, AWSS_ACK_FMT, req_msg_id, -3, "\"passwd len error\"");
            awss_event_post(IOTX_AWSS_PASSWD_ERR);
            success = 0;
            AWSS_UPDATE_STATIS(AWSS_STATIS_DAP_IDX, AWSS_STATIS_TYPE_PASSWD_ERR);
        }

        if (success && is_utf8(passwd, strlen(passwd)) == 0) {
            dump_awss_status(STATE_WIFI_DEV_AP_PASSWD_DECODE_FAILED, "passwd content err");
            snprintf(msg, AWSS_DEV_AP_SWITCHA_RSP_LEN, AWSS_ACK_FMT, req_msg_id, -3, "\"passwd content error\"");
            awss_event_post(IOTX_AWSS_PASSWD_ERR);
            success = 0;
            AWSS_UPDATE_STATIS(AWSS_STATIS_DAP_IDX, AWSS_STATIS_TYPE_PASSWD_ERR);
        }
    } while (0);


	if (success == 1) {
		if (token_found == 0) {
			// no token found in switchap request, produce new token by dev itself
			produce_random(aes_random, sizeof(aes_random));
		} else {
			// token found in switchap request, no need to produce dev token
			awss_set_token((uint8_t *)token);
		}
        dev_info[0] = '{';
        awss_build_dev_info(token_found == 1 ? AWSS_NOTIFY_TYPE_MAX : AWSS_NOTIFY_DEV_BIND_TOKEN, dev_info + 1,
                            AWSS_DEV_AP_SWITCHA_RSP_LEN - 1);
        dev_info[strlen(dev_info)] = '}';
        dev_info[AWSS_DEV_AP_SWITCHA_RSP_LEN - 1] = '\0';
        snprintf(msg, AWSS_DEV_AP_SWITCHA_RSP_LEN, AWSS_ACK_FMT, req_msg_id, 200, dev_info);
	}

    awss_trace("Sending message to app: %s\r\n", msg);
    awss_trace("switch to ap: '%s'\r\n", ssid);
    char topic[TOPIC_LEN_MAX] = {0};
    uint16_t msgid = -1;
    awss_build_topic((const char *)TOPIC_AWSS_DEV_AP_SWITCHAP, topic, TOPIC_LEN_MAX);
    int result = awss_cmp_coap_send_resp(msg, strlen(msg), remote, topic, request, awss_dev_ap_switchap_resp, &msgid, 1);
    if (0 != result) {
        dump_awss_status(STATE_WIFI_DEV_AP_SEND_PKT_FAIL, "send switchap resp fail");
    }

	if (success == 1) {
		awss_event_post(IOTX_AWSS_GOT_SSID_PASSWD);
	    #ifdef DEV_STATEMACHINE_ENABLE
	    dev_awss_state_set(AWSS_PATTERN_DEV_AP_CONFIG, AWSS_STATE_SSID_GOT);
	    #endif
	    ret = start_connect_ap(ssid, passwd, (uint8_t *)bssid, token_found ? token : NULL, msgid);
	    if (STATE_SUCCESS == ret) {
	        // no need to report fail result to upper layer, because reported in start_connect_ap
	        awss_trace("ready connect ap '%s'\r\n", ssid);
	    }
	}

DEV_AP_SWITCHAP_END:
    dev_ap_switchap_parsed = 0;
    if (dev_info) {
        os_free(dev_info);
    }
    if (msg) {
        os_free(msg);
    }
    return ret;
}

#ifdef DEV_ERRCODE_ENABLE
int wifimgr_process_dev_errcode_request(void *ctx, void *resource, void *remote, void *request)
{
    int str_len = 0;
    int len = 0;
    int data_len = 0;
    char req_msg_id[MSG_REQ_ID_LEN] = {0};
    char *msg = NULL;
    char *str = NULL;
    char *buf = NULL;
    char *err_data = NULL;
    int ret = -1;
    uint16_t err_code = 0;
    char err_msg[DEV_ERRCODE_MSG_MAX_LEN] = {0};

    msg = os_zalloc(DEV_ERRCODE_TOPIC_RSP_MAX_LEN);
    if (msg == NULL) {
        awss_err("dev errcode resp os alloc fail!\r\n");
        return ret;
    }

    err_data = os_zalloc(DEV_ERRCODE_TOPIC_RSP_MAX_LEN);
    if (err_data == NULL) {
        awss_err("dev errcode resp os alloc fail!\r\n");
        return ret;
    }

    // Parse request from peer dev, to confirm request format correct
    buf = awss_cmp_get_coap_payload(request, &len);
    str = json_get_value_by_name(buf, len, "id", &str_len, 0);
    memcpy(req_msg_id, str, str_len > MSG_REQ_ID_LEN - 1 ? MSG_REQ_ID_LEN - 1 : str_len);
    awss_trace("dev errcode, len:%u, %s, req_msg_id(%s)\r\n", len, buf, req_msg_id);
    buf = json_get_value_by_name(buf, len, "params", &len, 0);
    if (buf == NULL) {
        awss_err("dev errcode json param parse fail!\r\n");
        if (msg) {
            os_free(msg);
        }
        if (err_data) {
            os_free(err_data);
        }
        return ret;
    }
    awss_trace("dev errcode rec request from app\r\n");

    ret = dev_errcode_kv_get(&err_code, err_msg);
    if (ret != 0) {
        err_code = 0;
    }

    err_data[0] = '{';
    data_len++;

    data_len += snprintf((char*)err_data + data_len, 
                         DEV_ERRCODE_TOPIC_RSP_MAX_LEN, 
                         DEV_ERRCODE_TOPIC_RSP_FMT, 
                         DEV_ERRCODE_VERSION,
                         1,
                         err_code,
                         err_msg);
    err_data[strlen(err_data)] = '}';
    err_data[DEV_ERRCODE_TOPIC_RSP_MAX_LEN - 1] = '\0';
    snprintf(msg, DEV_ERRCODE_TOPIC_RSP_MAX_LEN, AWSS_ACK_FMT, req_msg_id, 200, err_data);

    awss_trace("Sending errcode to app: %s", msg);
    char topic[TOPIC_LEN_MAX] = {0};
    uint16_t msgid = -1;
    awss_build_topic((const char *)TOPIC_AWSS_DEV_ERRCODE_GET_REPLY, topic, TOPIC_LEN_MAX);
    int result = awss_cmp_coap_send_resp(msg, strlen(msg), remote, topic, request, awss_dev_errcode_resp, &msgid, 1);
    (void)result;  /* remove complier warnings */
    awss_trace("sending %s.", result == 0 ? "success" : "fail");

    if (msg) {
        os_free(msg);
    }
    if (err_data) {
        os_free(err_data);
    }
    return ret;
}

int wifimgr_process_dev_ap_mcast_get_dev_info(void *ctx, void *resource, void *remote, void *request)
{
    return process_get_device_info(ctx, resource, remote, request, 1, AWSS_NOTIFY_DEV_RAND_SIGN);
}
#endif

static void do_connect_ap(void)
{
    int ret;
    if (ap_info_ptr == NULL) {
        return;
    }

    if (ap_info_ptr->got_msg == 0) {
        return;
    }

    if (awss_dev_ap_ongoing == 0) {
        AWSS_UPDATE_STATIS(AWSS_STATIS_CONN_ROUTER_IDX, AWSS_STATIS_TYPE_TIME_START);
        awss_cmp_coap_cancel_packet(ap_info_ptr->msgid);
        return;
    }

    if (awss_dev_ap_switchap_resp_suc || ++ap_info_ptr->cnt == TIMEOUT_CNT) {
        awss_cmp_coap_cancel_packet(ap_info_ptr->msgid);
        AWSS_UPDATE_STATIS(AWSS_STATIS_CONN_ROUTER_IDX, AWSS_STATIS_TYPE_TIME_START);
        if (0 != os_awss_close_ap()) {
            dump_awss_status(STATE_WIFI_DEV_AP_CLOSE_FAIL, "stop dev ap fail");
        }
#ifdef AWSS_BATCH_DEVAP_ENABLE
        {
            uint8_t alibaba_oui[3] = ALIBABA_OUI;
            os_wifi_enable_mgnt_frame_filter(FRAME_BEACON_MASK | FRAME_PROBE_REQ_MASK,
                                            (uint8_t *)alibaba_oui, NULL);
        }
#endif

        awss_event_post(IOTX_AWSS_CONNECT_ROUTER);
        #ifdef DEV_STATEMACHINE_ENABLE
        dev_state_set(DEV_STATE_CONNECT_AP);
        #endif

        /*ret = os_awss_connect_ap(WLAN_CONNECTION_TIMEOUT_MS, info->ssid, info->passwd, 0, 0, info->bssid, 0);*/
        ret = awss_connect(ap_info_ptr->ssid, ap_info_ptr->passwd, ap_info_ptr->bssid, ETH_ALEN,
                           ap_info_ptr->token_found == 1 ? ap_info_ptr->token : NULL,
                           ap_info_ptr->token_found == 1 ? RANDOM_MAX_LEN : 0);
        if (ret == 0) {
            awss_event_post(IOTX_AWSS_GOT_IP);
            #ifdef DEV_STATEMACHINE_ENABLE
            dev_state_set(DEV_STATE_CONNECT_CLOUD);
            #endif
            AWSS_UPDATE_STATIS(AWSS_STATIS_CONN_ROUTER_IDX, AWSS_STATIS_TYPE_TIME_SUC);
            awss_dev_ap_switchap_done = 1;
            AWSS_UPDATE_STATIS(AWSS_STATIS_DAP_IDX, AWSS_STATIS_TYPE_TIME_SUC);
            awss_trace("connect '%s' success\r\n", ap_info_ptr->ssid);
        } else {
            dump_awss_status(STATE_WIFI_CONNECT_AP_FAILED, "connect '%s' fail", ap_info_ptr->ssid);
            awss_event_post(IOTX_AWSS_CONNECT_ROUTER_FAIL);
            ret = awss_dev_ap_setup();
            if (STATE_SUCCESS != ret) {
                dump_awss_status(STATE_WIFI_DEV_AP_START_FAIL, "dev ap setup fail");
                return;
            }
#ifdef AWSS_BATCH_DEVAP_ENABLE
            {
                uint8_t alibaba_oui[3] = ALIBABA_OUI;
                os_wifi_enable_mgnt_frame_filter(FRAME_BEACON_MASK | FRAME_PROBE_REQ_MASK,
                                                (uint8_t *)alibaba_oui, awss_dev_ap_mgnt_frame_cb);
            }
#endif
        }
        return;
    }

    awss_info("dev ap: wait switchap resp ack,cnt = %d\r\n", ap_info_ptr->cnt);

}

static int start_connect_ap(char *ssid, char *pwd, uint8_t *bssid, uint8_t *token, uint16_t msgid)
{
    if (ap_info_ptr == NULL) {
        dump_awss_status(STATE_USER_INPUT_NULL_POINTER, "conn ap ap_info_ptr null");
        return STATE_USER_INPUT_NULL_POINTER;
    }

    memset(ap_info_ptr, 0, sizeof(ap_info_t));
    if (token != NULL) {
        memcpy(ap_info_ptr->token, token, sizeof(ap_info_ptr->token));
        ap_info_ptr->token_found = 1;
    }
    strncpy(ap_info_ptr->ssid, ssid, sizeof(ap_info_ptr->ssid) - 1);
    strncpy(ap_info_ptr->passwd, pwd, sizeof(ap_info_ptr->passwd) - 1);
    memcpy(ap_info_ptr->bssid, bssid, sizeof(ap_info_ptr->bssid));
    ap_info_ptr->msgid = msgid;
    ap_info_ptr->got_msg = 1;
    return STATE_SUCCESS;
}

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif
#endif

/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include <stdlib.h>
#include "iot_export.h"
#include "json_parser.h"
#include "awss_packet.h"
#include "awss_notify.h"
#include "awss_event.h"
#include "awss_timer.h"
#include "awss_utils.h"
#include "awss_cmp.h"
#include "awss_log.h"
#include "awss_reset.h"
#include "platform.h"
#include "passwd.h"
#include "os.h"

#if defined(__cplusplus) /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

#define AWSS_CHECK_RESP_TIME (300)
#define AWSS_NOTIFY_PORT     (5683)
#define AWSS_NOTIFY_HOST     "255.255.255.255"
#define AWSS_DEV_NOTIFY_FMT  "{\"id\":\"%u\",\"version\":\"1.0\",\"method\":\"%s\",\"params\":{%s}}"

struct notify_map_t {
    uint8_t notify_type;
    char *notify_method;
    char *notify_topic;
    void *cb;
};

static uint8_t g_notify_id;
static char awss_notify_resp[AWSS_NOTIFY_TYPE_MAX] = {0};
static uint16_t g_notify_msg_id[AWSS_NOTIFY_TYPE_MAX] = {0};

#ifdef WIFI_PROVISION_ENABLED
static void *success_notify_timer = NULL;
static void *devinfo_notify_timer = NULL;
static void *success_notify_mutex = NULL;
static void *devinfo_notify_mutex = NULL;
#endif
static void *dev_bind_notify_timer = NULL;
static void *get_devinfo_timer  = NULL;
static void *dev_bind_notify_mutex = NULL;

extern char awss_report_token_suc;
extern char awss_report_token_cnt;

static int awss_dev_bind_notify_resp(void *context, int result,
                                     void *userdata, void *remote,
                                     void *message);
#ifdef WIFI_PROVISION_ENABLED
static int awss_devinfo_notify_resp(void *context, int result,
                                    void *userdata, void *remote,
                                    void *message);
static int awss_suc_notify_resp(void *context, int result,
                                void *userdata, void *remote,
                                void *message);
int awss_devinfo_notify();
int awss_suc_notify();
#endif
static int awss_notify_response(int type, int result, void *message);
static int awss_process_get_devinfo();
int awss_dev_bind_notify();

static const struct notify_map_t notify_map[] = {
    {AWSS_NOTIFY_DEV_BIND_TOKEN, METHOD_DEV_INFO_NOTIFY,       TOPIC_NOTIFY,                awss_dev_bind_notify_resp},
#ifdef WIFI_PROVISION_ENABLED
    {AWSS_NOTIFY_DEV_RAND_SIGN,  METHOD_AWSS_DEV_INFO_NOTIFY,  TOPIC_AWSS_NOTIFY,           awss_devinfo_notify_resp},
    {AWSS_NOTIFY_SUCCESS,        METHOD_AWSS_CONNECTAP_NOTIFY, TOPIC_AWSS_CONNECTAP_NOTIFY, awss_suc_notify_resp}
#endif
};

/*
 * {
 *  "id": "123",
 *  "code": 200,
 *  "data": {}
 * }
 */
static int awss_dev_bind_notify_resp(void *context, int result,
                                     void *userdata, void *remote,
                                     void *message)
{
    int res = awss_notify_response(AWSS_NOTIFY_DEV_BIND_TOKEN, result, message);
    if (res == 1) {
        awss_update_token();
#ifdef DEV_BIND_TEST
        os_reboot();
#endif
    }
    return res;
}

#ifdef WIFI_PROVISION_ENABLED
static int awss_devinfo_notify_resp(void *context, int result,
                                    void *userdata, void *remote,
                                    void *message)
{
    return awss_notify_response(AWSS_NOTIFY_DEV_RAND_SIGN, result, message);
}

static int awss_suc_notify_resp(void *context, int result,
                                void *userdata, void *remote,
                                void *message)
{
    return awss_notify_response(AWSS_NOTIFY_SUCCESS, result, message);
}
#endif

static int awss_notify_response(int type, int result, void *message)
{
    uint8_t i = 0;
    uint8_t code;

    awss_flow("%s, type:%d,result:%u\r\n", __func__, type, result);

    if (message == NULL) {
        return STATE_WIFI_COAP_RSP_INVALID;
    }

    if (result != 0) {
        //awss_err("result = %d", result);
        return STATE_WIFI_COAP_RSP_INVALID;
    }

    code = awss_cmp_get_coap_code(message);
    if (code >= 0x60) {
        //awss_err("code:%02x", code);
        return STATE_WIFI_COAP_RSP_INVALID;
    }

    do {
        int val = 0;
        int len = 0, mlen = 0;
        char *payload = NULL, *elem = NULL;

        if ((payload = awss_cmp_get_coap_payload(message, &len)) == NULL || len > 0x40 || len == 0) {
            awss_err("payload invalid , len =%d", len);
            return STATE_WIFI_COAP_RSP_INVALID;
        }

        awss_debug("payload:%s\r\n", payload);

        elem = json_get_value_by_name(payload, len, AWSS_JSON_ID, &mlen, 0);
        if (elem == NULL) {
            awss_err("no id in payload");
            return STATE_WIFI_COAP_RSP_INVALID;
        }

        val = atoi(elem);
        if (val != 123 && val > g_notify_id) {
            return STATE_WIFI_COAP_RSP_INVALID;
        }

        elem = json_get_value_by_name(payload, len, AWSS_JSON_CODE, &mlen, 0);
        if (elem == NULL) {
            awss_err("no code in payload");
            return STATE_WIFI_COAP_RSP_INVALID;
        }

        val = atoi(elem);
        if (val != 200) {
            awss_err("code = %s", val);
            return STATE_WIFI_COAP_RSP_INVALID;
        }
    } while (0);

    for (i = 0; i < sizeof(notify_map) / sizeof(notify_map[0]); i ++) {
        if (notify_map[i].notify_type != type) {
            continue;
        }

        awss_notify_resp[type] = 1;
        break;
    }

    return awss_notify_resp[type];
}

int awss_notify_dev_info(int type, int count)
{
    char *buf = NULL;
    char *dev_info = NULL;
    int i;
    platform_netaddr_t notify_sa;
    memset(&notify_sa, 0, sizeof(notify_sa));

    do {
        void *cb = NULL;
        char *method = NULL, *topic = NULL;
        char rand_str[RANDOM_MAX_LEN * 2 + 1] = {0};
        for (i = 0; i < sizeof(notify_map) / sizeof(notify_map[0]); i ++) {
            if (notify_map[i].notify_type != type) {
                continue;
            }

            method = notify_map[i].notify_method;
            topic = notify_map[i].notify_topic;
            cb = notify_map[i].cb;
            break;
        }
        if (method == NULL || topic == NULL) {
            awss_err("parametes invalid");
            break;
        }

        buf = os_zalloc(DEV_INFO_LEN_MAX);
        dev_info = os_zalloc(DEV_INFO_LEN_MAX);
        if (buf == NULL || dev_info == NULL) {
            awss_err("alloc mem fail");
            break;
        }

        memset(&notify_sa, 0, sizeof(notify_sa));
        memcpy(notify_sa.host, AWSS_NOTIFY_HOST, strlen(AWSS_NOTIFY_HOST));
        notify_sa.port = AWSS_NOTIFY_PORT;

        awss_build_dev_info(type, dev_info, DEV_INFO_LEN_MAX);

        snprintf(buf, DEV_INFO_LEN_MAX - 1, AWSS_DEV_NOTIFY_FMT, ++ g_notify_id, method, dev_info);
        utils_hex_to_str(g_aes_random, RANDOM_MAX_LEN, rand_str, sizeof(rand_str));
        if (type == AWSS_NOTIFY_SUCCESS) {
            dump_awss_status(STATE_WIFI_SENT_CONNECTAP_NOTIFY, "connect ap notify");
        } else if (type == AWSS_NOTIFY_DEV_RAND_SIGN) {

        }
        awss_info("topic:%s\n", topic);
        awss_debug("payload:%s\n", buf);
        for (i = 0; i < count; i ++) {
            int ret = awss_cmp_coap_send(buf, strlen(buf), &notify_sa, topic, cb, &g_notify_msg_id[type]);
            awss_info("coap send notify %s", ret == 0 ? "success" : "fail");
            if (count > 1)
                os_msleep(200 + 100 * i);

            if (awss_notify_resp[type])
                break;
        }
    } while (0);

    if (buf) {
        os_free(buf);
    }
    if (dev_info) {
        os_free(dev_info);
    }

    return awss_notify_resp[type];
}

#define AWSS_NOTIFY_CNT_MAX (30)

static void *coap_session_ctx = NULL;

static int awss_process_get_devinfo()
{
    char *buf = NULL;
    char *dev_info = NULL;
    int ret;
    if (awss_report_token_suc == 0) {
        awss_debug("try to report token to cloud");
        HAL_Timer_Start(get_devinfo_timer, AWSS_CHECK_RESP_TIME);
        return 0;
    }

    if (coap_session_ctx == NULL) {
        awss_debug("no get req");
        return STATE_USER_INPUT_NULL_POINTER;
    }

    do {
        int len = 0, id_len = 0;
        char *msg = NULL, *id = NULL;
        char req_msg_id[MSG_REQ_ID_LEN + 1];
        char rand_str[RANDOM_MAX_LEN * 2 + 1] = {0};
        struct coap_session_ctx_t *ctx = (struct coap_session_ctx_t *)coap_session_ctx;

        buf = os_zalloc(DEV_INFO_LEN_MAX);
        if (buf == NULL) {
            ret = STATE_SYS_DEPEND_MALLOC;
            goto GET_DEV_INFO_ERR;
        }
        dev_info = os_zalloc(DEV_INFO_LEN_MAX);
        if (dev_info == NULL) {
            ret = STATE_SYS_DEPEND_MALLOC;
            goto GET_DEV_INFO_ERR;
        }
        msg = awss_cmp_get_coap_payload(ctx->request, &len);
        if (msg == NULL) {
            ret = STATE_BIND_COAP_MSG_INVALID;
            goto GET_DEV_INFO_ERR;
        }

        id = json_get_value_by_name(msg, len, "id", &id_len, 0);
        if (id_len > MSG_REQ_ID_LEN) {
            ret = STATE_BIND_COAP_MSG_INVALID;
            goto GET_DEV_INFO_ERR;
        }

        memset(req_msg_id, 0, sizeof(req_msg_id));
        memcpy(req_msg_id, id, id_len);

        awss_build_dev_info(AWSS_NOTIFY_DEV_BIND_TOKEN, buf, DEV_INFO_LEN_MAX);
        snprintf(dev_info, DEV_INFO_LEN_MAX - 1, "{%s}", buf);
        memset(buf, 0x00, DEV_INFO_LEN_MAX);
        snprintf(buf, DEV_INFO_LEN_MAX - 1, AWSS_ACK_FMT, req_msg_id, 200, dev_info);
        os_free(dev_info);

        utils_hex_to_str(g_aes_random, RANDOM_MAX_LEN, rand_str, sizeof(rand_str));
        dump_dev_bind_status(STATE_BIND_SENT_TOKEN_RESP, dev_info);
        awss_info("sending message to app: %s", buf);
        char topic[TOPIC_LEN_MAX] = { 0 };
        if (ctx->is_mcast) {
            awss_build_topic((const char *)TOPIC_GETDEVICEINFO_MCAST, topic, TOPIC_LEN_MAX);
        } else {
            awss_build_topic((const char *)TOPIC_GETDEVICEINFO_UCAST, topic, TOPIC_LEN_MAX);
        }

        /*before tx to app, clear token suc flag*/
        awss_update_token();

        if ((ret = awss_cmp_coap_send_resp(buf, strlen(buf), ctx->remote, topic, ctx->request, NULL, NULL, 0)) < 0) {
            dump_dev_bind_status(STATE_BIND_APP_GET_TOKEN_RESP_FAIL, topic);
            awss_err("sending failed.");
        }

        os_free(buf);
        awss_release_coap_ctx(coap_session_ctx);
        coap_session_ctx = NULL;
        awss_stop_timer(get_devinfo_timer);
        get_devinfo_timer = NULL;
    } while (0);

    return 0;

GET_DEV_INFO_ERR:
    dump_dev_bind_status(STATE_BIND_APP_GET_TOKEN_RESP_FAIL, "get token response fail");
    awss_release_coap_ctx(coap_session_ctx);
    coap_session_ctx = NULL;
    awss_stop_timer(get_devinfo_timer);
    get_devinfo_timer = NULL;

    if (buf) {
        os_free(buf);
    }
    if (dev_info) {
        os_free(dev_info);
    }

    return ret;
}

static int online_get_device_info(void *ctx, void *resource, void *remote,
                                  void *request, char is_mcast)
{
    int timeout = 0;
    /*
     * if cloud is not ready, don't response token
     */
    dump_dev_bind_status(STATE_BIND_RECV_TOKEN_QUERY, "recv token query");
#ifdef DEVICE_MODEL_ENABLED
    if (awss_check_reset(NULL)) {
        dump_dev_bind_status(STATE_BIND_RST_IN_PROGRESS, "need do reset");
        return STATE_BIND_RST_IN_PROGRESS;
    }
#endif
    /*
     * if the last one is not finished, drop current request
     */
    if (coap_session_ctx != NULL) {
        dump_dev_bind_status(STATE_BIND_COAP_INIT_FAIL, "recv get dev info fail");
        return STATE_BIND_COAP_INIT_FAIL;
    }
    /*
     * copy coap session context
     */
    coap_session_ctx = awss_cpy_coap_ctx(request, remote, is_mcast);
    if (coap_session_ctx == NULL) {
        dump_dev_bind_status(STATE_BIND_COAP_INIT_FAIL, "cpy req ctx fail");
        return STATE_BIND_COAP_INIT_FAIL;
    }

    timeout = awss_token_timeout();
    if (timeout) {
        produce_random(g_aes_random, sizeof(g_aes_random));
        awss_report_token();
    }

    if (get_devinfo_timer == NULL)
        get_devinfo_timer = HAL_Timer_Create("get_devinfo", (void (*)(void *))awss_process_get_devinfo, NULL);
    HAL_Timer_Stop(get_devinfo_timer);
    HAL_Timer_Start(get_devinfo_timer, timeout ? AWSS_CHECK_RESP_TIME : 1);

    return 0;
}

int online_mcast_get_device_info(void *ctx, void *resource, void *remote, void *request)
{
    return online_get_device_info(ctx, resource, remote, request, 1);
}

int online_ucast_get_device_info(void *ctx, void *resource, void *remote, void *request)
{
    return online_get_device_info(ctx, resource, remote, request, 0);
}

static int dev_bind_interval = 0;
static char dev_sync_token = 0;
static char dev_bind_cnt = 0;
static int __awss_dev_bind_notify()
{
    /*
     * wait for token is sent to cloud and rx reply from cloud
     */
    if (awss_report_token_suc == 0) {
        if (dev_bind_notify_timer == NULL)
            dev_bind_notify_timer = HAL_Timer_Create("dev_bind", (void (*)(void *))__awss_dev_bind_notify, NULL);
        HAL_Timer_Stop(dev_bind_notify_timer);
        HAL_Timer_Start(dev_bind_notify_timer, AWSS_CHECK_RESP_TIME);
        return 0;
    }

    if (dev_bind_notify_mutex == NULL) {
        dev_bind_notify_mutex = HAL_MutexCreate();
        if (dev_bind_notify_mutex == NULL) {
            return STATE_USER_INPUT_NULL_POINTER;
        }
    }

    if (dev_bind_cnt == 0)
        awss_event_post(IOTX_AWSS_BIND_NOTIFY);

    HAL_MutexLock(dev_bind_notify_mutex);

    do {
        uint8_t i = 0;

        if (awss_notify_resp[AWSS_NOTIFY_DEV_BIND_TOKEN] != 0)
            break;

        for (i = 0; i < RANDOM_MAX_LEN; i ++)
            if (g_aes_random[i] != 0x00)
                break;

        if (i >= RANDOM_MAX_LEN)
            produce_random(g_aes_random, sizeof(g_aes_random));

        if (awss_token_timeout() == 0) {
            awss_notify_dev_info(AWSS_NOTIFY_DEV_BIND_TOKEN, 1);
            dev_bind_interval += 100;
            dev_bind_cnt ++;
            dev_sync_token = 0;
        } else if (dev_sync_token == 0) {
            dev_sync_token = 1;
            awss_update_token();
            if (dev_bind_cnt == 0)
                dev_bind_cnt ++;
        }
#ifdef DEV_BIND_TEST
        if (dev_bind_cnt > 3)
            os_reboot();
#endif

        if (dev_bind_cnt < AWSS_NOTIFY_CNT_MAX &&
            awss_notify_resp[AWSS_NOTIFY_DEV_BIND_TOKEN] == 0) {
            if (dev_bind_notify_timer == NULL)
                dev_bind_notify_timer = HAL_Timer_Create("dev_bind", (void (*)(void *))awss_dev_bind_notify, NULL);
            HAL_Timer_Stop(dev_bind_notify_timer);
            HAL_Timer_Start(dev_bind_notify_timer, awss_report_token_suc == 0 ? AWSS_CHECK_RESP_TIME : dev_bind_interval);
            HAL_MutexUnlock(dev_bind_notify_mutex);
            return 0;
        }
    } while (0);

    awss_cmp_coap_cancel_packet(g_notify_msg_id[AWSS_NOTIFY_DEV_BIND_TOKEN]);
    g_notify_msg_id[AWSS_NOTIFY_DEV_BIND_TOKEN] = 0;
    awss_notify_resp[AWSS_NOTIFY_DEV_BIND_TOKEN] = 0;
    dev_bind_interval = 0;
    dev_bind_cnt = 0;
    if (dev_bind_notify_timer) {
        awss_stop_timer(dev_bind_notify_timer);
        dev_bind_notify_timer = NULL;
    }
    if (dev_bind_notify_mutex) {
        HAL_MutexUnlock(dev_bind_notify_mutex);
        HAL_MutexDestroy(dev_bind_notify_mutex);
        dev_bind_notify_mutex = NULL;
    }
    return 1;
}

int awss_dev_bind_notify()
{
    dev_bind_cnt = 0;
    dev_sync_token = 0;
    dev_bind_interval = 0;
    awss_notify_resp[AWSS_NOTIFY_DEV_BIND_TOKEN] = 0;

    return __awss_dev_bind_notify();
}

int awss_dev_bind_notify_stop()
{
    if (dev_bind_notify_mutex)
        HAL_MutexLock(dev_bind_notify_mutex);

    do {
        dev_sync_token = 0;
        awss_notify_resp[AWSS_NOTIFY_DEV_BIND_TOKEN] = 1;
        dev_bind_cnt = AWSS_NOTIFY_CNT_MAX;
        if (dev_bind_notify_timer == NULL)
            break;

        awss_stop_timer(dev_bind_notify_timer);
        dev_bind_notify_timer = NULL;
    } while (0);

    awss_cmp_coap_cancel_packet(g_notify_msg_id[AWSS_NOTIFY_DEV_BIND_TOKEN]);
    g_notify_msg_id[AWSS_NOTIFY_DEV_BIND_TOKEN] = 0;

    if (dev_bind_notify_mutex) {
        HAL_MutexUnlock(dev_bind_notify_mutex);
        HAL_MutexDestroy(dev_bind_notify_mutex);
        dev_bind_notify_mutex = NULL;
    }
    return 0;
}

#ifdef WIFI_PROVISION_ENABLED
static int suc_interval = 0;
static char suc_cnt = 0;
static int __awss_suc_notify()
{
    awss_debug("awss notify resp:%d\r\n", awss_notify_resp[AWSS_NOTIFY_SUCCESS]);

    if (success_notify_mutex == NULL) {
        success_notify_mutex = HAL_MutexCreate();
        if (success_notify_mutex == NULL) {
            return STATE_SYS_DEPEND_MUTEX_CREATE;
        }
    }

    if (suc_cnt == 0)
        awss_event_post(IOTX_AWSS_SUC_NOTIFY);

    HAL_MutexLock(success_notify_mutex);

    do {
        if (awss_notify_resp[AWSS_NOTIFY_SUCCESS] != 0)
            break;

        awss_notify_dev_info(AWSS_NOTIFY_SUCCESS, 1);

        suc_interval += 100;
        if (suc_cnt ++ < AWSS_NOTIFY_CNT_MAX &&
            awss_notify_resp[AWSS_NOTIFY_SUCCESS] == 0) {
            if (success_notify_timer == NULL)
                success_notify_timer = HAL_Timer_Create("awss_suc", (void (*)(void *))__awss_suc_notify, NULL);
            HAL_Timer_Stop(success_notify_timer);
            HAL_Timer_Start(success_notify_timer, suc_interval);
            HAL_MutexUnlock(success_notify_mutex);
            return 0;
        }
    } while (0);

    if (awss_notify_resp[AWSS_NOTIFY_SUCCESS] == 0) {
        dump_awss_status(STATE_WIFI_SENT_CONNECTAP_NOTI_TIMEOUT, "__awss_suc_notify %d timeout", suc_cnt);
    }

    awss_cmp_coap_cancel_packet(g_notify_msg_id[AWSS_NOTIFY_SUCCESS]);
    g_notify_msg_id[AWSS_NOTIFY_SUCCESS] = 0;

    awss_notify_resp[AWSS_NOTIFY_SUCCESS] = 0;
    suc_interval = 0;
    suc_cnt = 0;
    if (success_notify_timer) {
        awss_stop_timer(success_notify_timer);
        success_notify_timer = NULL;
    }

    if (success_notify_mutex) {
        HAL_MutexUnlock(success_notify_mutex);
        HAL_MutexDestroy(success_notify_mutex);
        success_notify_mutex = NULL;
    }
    return 1;
}

int awss_suc_notify()
{
    suc_cnt = 0;
    suc_interval = 0;
    awss_notify_resp[AWSS_NOTIFY_SUCCESS] = 0;
    return __awss_suc_notify();
}

int awss_suc_notify_stop()
{
    if (success_notify_mutex)
        HAL_MutexLock(success_notify_mutex);

    do {
        awss_notify_resp[AWSS_NOTIFY_SUCCESS] = 1;
        suc_cnt = AWSS_NOTIFY_CNT_MAX;
        if (success_notify_timer == NULL)
            break;

        awss_stop_timer(success_notify_timer);
        success_notify_timer = NULL;
    } while (0);

    awss_cmp_coap_cancel_packet(g_notify_msg_id[AWSS_NOTIFY_SUCCESS]);
    g_notify_msg_id[AWSS_NOTIFY_SUCCESS] = 0;

    if (success_notify_mutex) {
        HAL_MutexUnlock(success_notify_mutex);
        HAL_MutexDestroy(success_notify_mutex);
        success_notify_mutex = NULL;
    }
    return 0;
}


static int devinfo_interval = 0;
static char devinfo_cnt = 0;
static int __awss_devinfo_notify()
{
    if (devinfo_notify_mutex == NULL) {
        devinfo_notify_mutex = HAL_MutexCreate();
        if (devinfo_notify_mutex == NULL) {
            return STATE_SYS_DEPEND_MUTEX_CREATE;
        }
    }
    HAL_MutexLock(devinfo_notify_mutex);

    do {
        if (awss_notify_resp[AWSS_NOTIFY_DEV_RAND_SIGN] != 0)
            break;

        awss_notify_dev_info(AWSS_NOTIFY_DEV_RAND_SIGN, 1);

        devinfo_interval += 100;
        if (devinfo_cnt ++ < AWSS_NOTIFY_CNT_MAX &&
            awss_notify_resp[AWSS_NOTIFY_DEV_RAND_SIGN] == 0) {
            if (devinfo_notify_timer == NULL)
                devinfo_notify_timer = HAL_Timer_Create("devinfo", (void (*)(void *))__awss_devinfo_notify, NULL);
            HAL_Timer_Stop(devinfo_notify_timer);
            HAL_Timer_Start(devinfo_notify_timer, devinfo_interval);
            HAL_MutexUnlock(devinfo_notify_mutex);
            return 0;
        }
    } while (0);

    awss_cmp_coap_cancel_packet(g_notify_msg_id[AWSS_NOTIFY_DEV_RAND_SIGN]);
    g_notify_msg_id[AWSS_NOTIFY_DEV_RAND_SIGN] = 0;

    awss_notify_resp[AWSS_NOTIFY_DEV_RAND_SIGN] = 0;
    devinfo_interval = 0;
    devinfo_cnt = 0;
    if (devinfo_notify_timer) {
        awss_stop_timer(devinfo_notify_timer);
        devinfo_notify_timer = NULL;
    }
    if (devinfo_notify_mutex) {
        HAL_MutexUnlock(devinfo_notify_mutex);
        HAL_MutexDestroy(devinfo_notify_mutex);
        devinfo_notify_mutex = NULL;
    }
    return 1;
}

int awss_devinfo_notify()
{
    devinfo_cnt = 0;
    devinfo_interval = 0;
    awss_notify_resp[AWSS_NOTIFY_DEV_RAND_SIGN] = 0;
    return __awss_devinfo_notify();
}

int awss_devinfo_notify_stop()
{
    if (devinfo_notify_mutex)
        HAL_MutexLock(devinfo_notify_mutex);

    do {
        awss_notify_resp[AWSS_NOTIFY_DEV_RAND_SIGN] = 1;
        devinfo_cnt = AWSS_NOTIFY_CNT_MAX;
        if (devinfo_notify_timer == NULL)
            break;

        awss_stop_timer(devinfo_notify_timer);
        devinfo_notify_timer = NULL;
    } while (0);

    awss_cmp_coap_cancel_packet(g_notify_msg_id[AWSS_NOTIFY_DEV_RAND_SIGN]);
    g_notify_msg_id[AWSS_NOTIFY_DEV_RAND_SIGN] = 0;

    if (devinfo_notify_mutex) {
        HAL_MutexUnlock(devinfo_notify_mutex);
        HAL_MutexDestroy(devinfo_notify_mutex);
        devinfo_notify_mutex = NULL;
    }
    return 0;
}

#endif

#if defined(__cplusplus) /* If this is a C++ compiler, use C linkage */
}
#endif

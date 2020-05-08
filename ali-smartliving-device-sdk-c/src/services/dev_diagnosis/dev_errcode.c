/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifdef DEV_ERRCODE_ENABLE
#include "dev_diagnosis_log.h"
#include "dev_errcode.h"

static uint16_t g_last_errcode = 0;

static uint16_t dev_errcode_sdk_filter(const int state_code);

void dev_errcode_module_init()
{
    int ret = 0;
    int errcode_len = sizeof(uint16_t);
    /* device errcode service init */ 
    ret = HAL_Kv_Get(DEV_ERRCODE_KEY, (void *)&g_last_errcode, &errcode_len);
    if (ret != 0) {
        diagnosis_info("no history err_code found");
        g_last_errcode = 0;
    }
}

int dev_errcode_handle(const int state_code, const char *state_message)
{
    uint16_t err_code = 0;
    char err_msg[DEV_ERRCODE_MSG_MAX_LEN + 8] = {0};
    err_code = dev_errcode_sdk_filter(state_code);
    if (err_code > 0) 
    {
        diagnosis_err("err_code %d, state_code:-0x%04x, str_msg=%s", err_code, -state_code, state_message == NULL ? "NULL" : state_message);
        if (err_code != g_last_errcode) {
            HAL_Snprintf(err_msg, DEV_ERRCODE_MSG_MAX_LEN + 8, "-0x%04x,%s",-state_code , state_message == NULL ? "NULL" : state_message);
            if (0 == dev_errcode_kv_set(err_code, err_msg)) {
                g_last_errcode = err_code;
            }
        }
    }
    return 0;
}

static uint16_t dev_errcode_sdk_filter(const int state_code)
{
    uint16_t err_code = 0;
#ifdef DEV_STATEMACHINE_ENABLE
    dev_state_t dev_state = DEV_STATE_MAX;
    dev_state = dev_state_get();
#endif
    
    switch(state_code) 
    {
        case STATE_USER_INPUT_NULL_POINTER:
        case STATE_USER_INPUT_OUT_RANGE:
        case STATE_USER_INPUT_PK:
        case STATE_USER_INPUT_PS:
        case STATE_USER_INPUT_DN:
        case STATE_USER_INPUT_DS:
        case STATE_USER_INPUT_META_INFO:
        case STATE_USER_INPUT_DEVID:
        case STATE_USER_INPUT_DEVICE_TYPE:
        case STATE_USER_INPUT_MSG_TYPE:
        case STATE_SYS_DEPEND_MALLOC:
        case STATE_SYS_DEPEND_MUTEX_CREATE:
        case STATE_SYS_DEPEND_MUTEX_LOCK:
        case STATE_SYS_DEPEND_MUTEX_UNLOCK:
        case STATE_SYS_DEPEND_SEMAPHORE_CREATE:
        case STATE_SYS_DEPEND_SEMAPHORE_WAIT:
        case STATE_SYS_DEPEND_TIMER_CREATE:
#ifdef DEV_STATEMACHINE_ENABLE
            if ((dev_state == DEV_STATE_WIFI_MONITOR) || (dev_state == DEV_STATE_INIT)) {
                err_code = DEV_ERRCODE_WIFI_DRV_FAIL;
            }
#endif
            break;
        /* WIFI monitor state */

        /* AWSS state */
        // smart-config
        // dev-ap
        case STATE_WIFI_DEV_AP_START_FAIL:
            err_code = DEV_ERRCODE_DA_DEV_AP_START_FAIL;
            break;
        case STATE_WIFI_DEV_AP_RECV_IN_WRONG_STATE:
        case STATE_WIFI_DEV_AP_SEND_PKT_FAIL:
            err_code = DEV_ERRCODE_DA_SSID_PWD_GET_TIMEOUT;
            break;
        case STATE_WIFI_DEV_AP_RECV_PKT_INVALID:
            err_code = DEV_ERRCODE_DA_VERSION_ERR;
            break;
        case STATE_WIFI_DEV_AP_PARSE_PKT_FAIL:
            err_code = DEV_ERRCODE_DA_PKT_CHECK_ERR;
            break;
        case STATE_WIFI_DEV_AP_PASSWD_DECODE_FAILED:
            err_code = DEV_ERRCODE_DA_SSID_PWD_PARSE_ERR;
            break;
        case STATE_WIFI_DEV_AP_CLOSE_FAIL:
            err_code = DEV_ERRCODE_DA_SWITCH_STA_FAIL;
            break;
        // zero-config
        // ble-config
        // phone-ap

        /* Router Connect */
        case STATE_WIFI_CONNECT_AP_FAILED:
            err_code = DEV_ERRCODE_IP_ADDR_GET_FAIL;
            break;
        case STATE_WIFI_SENT_CONNECTAP_NOTI_TIMEOUT:
            err_code = DEV_ERRCODE_AP_CONN_LOCAL_NOTI_FAIL;
            break;

        /* Cloud Connect */
        case STATE_HTTP_NWK_INIT_FAIL:
            err_code = DEV_ERRCODE_HTTPS_INIT_FAIL;
            break;
        case STATE_USER_INPUT_HTTP_DOMAIN:
        case STATE_HTTP_PREAUTH_DNS_FAIL:
            err_code = DEV_ERRCODE_HTTPS_DNS_FAIL;
            break;
        case STATE_USER_INPUT_HTTP_TIMEOUT:
        case STATE_USER_INPUT_HTTP_PORT:
        case STATE_HTTP_PREAUTH_TIMEOUT_FAIL:
            err_code = DEV_ERRCODE_HTTPS_PREAUTH_TIMEOUT;
            break;
        case STATE_HTTP_PREAUTH_IDENT_AUTH_FAIL:
            err_code = DEV_ERRCODE_HTTPS_DEVAUTH_FAIL;
            break;
        case STATE_USER_INPUT_MQTT_DOMAIN:
        case STATE_MQTT_INIT_FAIL:
            err_code = DEV_ERRCODE_MQTT_INIT_FAIL;
            break;
        case STATE_MQTT_CERT_VERIFY_FAIL:
        case STATE_MQTT_CONNACK_VERSION_UNACCEPT:
        case STATE_MQTT_CONNACK_IDENT_REJECT:
        case STATE_MQTT_CONNACK_NOT_AUTHORIZED:
        case STATE_MQTT_CONNACK_BAD_USERDATA:
        case STATE_MQTT_CONNECT_UNKNOWN_FAIL:
            err_code = DEV_ERRCODE_MQTT_AUTH_FAIL;
            break;
        case STATE_MQTT_NETWORK_CONNECT_ERROR:
        case STATE_MQTT_CONNECT_PKT_SEND_FAIL:
        case STATE_MQTT_CONNACK_SERVICE_NA:
            err_code = DEV_ERRCODE_MQTT_CONN_TIMEOUT;
            break;
        // dev bind
        case STATE_BIND_COAP_INIT_FAIL:
            err_code = DEV_ERRCODE_COAP_INIT_FAIL;
            break;
        case STATE_BIND_REPORT_TOKEN_TIMEOUT:
            err_code = DEV_ERRCODE_TOKEN_RPT_CLOUD_TIMEOUT;
            break;
        case STATE_BIND_MQTT_MSG_INVALID:
            err_code = DEV_ERRCODE_TOKEN_RPT_CLOUD_ACK_ERR;
            break;
        case STATE_BIND_COAP_MSG_INVALID:
            err_code = DEV_ERRCODE_TOKEN_GET_LOCAL_PKT_ERR;
            break;
        case STATE_BIND_APP_GET_TOKEN_RESP_FAIL:
            err_code = DEV_ERRCODE_TOKEN_GET_LOCAL_RSP_ERR;
            break;
        default:
            break;
    }

    return err_code;
}

int dev_errcode_kv_set(uint16_t err_code, char *p_msg)
{
    int ret = 0;
    ret = HAL_Kv_Set(DEV_ERRCODE_KEY, (void *)&err_code, sizeof(err_code), 1);
    if (ret == 0) {
        ret = HAL_Kv_Set(DEV_ERRCODE_MSG_KEY, (void *)p_msg, strlen(p_msg), 1);
    } else {
        diagnosis_err("err_code set failed(%d)!\r\n", ret);
    }
    return ret;
}

int dev_errcode_kv_get(uint16_t *p_errcode, char *p_msg)
{
    int ret = 0;
    int errcode_len = sizeof(uint16_t);
    int msg_len = DEV_ERRCODE_MSG_MAX_LEN;
    ret = HAL_Kv_Get(DEV_ERRCODE_KEY, (void *)p_errcode, &errcode_len);
    if (ret == 0) {
        ret = HAL_Kv_Get(DEV_ERRCODE_MSG_KEY, (void *)p_msg, &msg_len);
    } else {
        diagnosis_err("get err_code failed(%d)!\r\n", ret);
    }
    return ret;
}

int dev_errcode_kv_del()
{
    int ret = 0;
    ret = HAL_Kv_Del(DEV_ERRCODE_KEY);
    if (ret == 0) {
        ret = HAL_Kv_Del(DEV_ERRCODE_MSG_KEY);
    } else {
        diagnosis_err("del err_code failed(%d)!\r\n", ret);
    }
    return ret;
}

#endif


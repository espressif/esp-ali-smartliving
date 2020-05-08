/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifdef DEV_OFFLINE_OTA_ENABLE
#include <stdio.h>
#include <string.h>
#include "iot_export.h"
#include "dev_diagnosis_log.h"
#include "dev_offline_ota.h"
#include "awss_cmp.h"
#include "awss_packet.h"
#include "awss_log.h"
#include "json_parser.h"

#define DEFAULT_NOTIFY_PORT     (5683)
#define DEFAULT_NOTIFY_HOST     "255.255.255.255"

static platform_netaddr_t g_networkaddr;
static void* g_ota_service_ctx = NULL;
static OFFLINE_OTA_UPGRADE_CB g_offline_upgrate_callback = NULL;
static char topic[TOPIC_LEN_MAX];
static char resp_data[DEV_OFFLINE_OTA_TOPIC_RSP_MAX_LEN];

void dev_offline_ota_module_init(void* ota_service_ctx,OFFLINE_OTA_UPGRADE_CB cb)
{
    g_ota_service_ctx = ota_service_ctx;
    g_offline_upgrate_callback = cb;
    memset(&g_networkaddr, 0, sizeof(platform_netaddr_t));
    memcpy(g_networkaddr.host, DEFAULT_NOTIFY_HOST, strlen(DEFAULT_NOTIFY_HOST));
    g_networkaddr.port = DEFAULT_NOTIFY_PORT;

    memset(topic, 0, sizeof(char)*TOPIC_LEN_MAX);
    memset(resp_data, 0, sizeof(char)*DEV_OFFLINE_OTA_TOPIC_RSP_MAX_LEN);
}

static int dev_offline_ota_resp(void *context, int result,
                                     void *userdata, void *remote,
                                     void *message)
{
    if (result == 2) { /* success */
        awss_trace("dev offline ota resp/notify sucess\r\n");
    } else {
        awss_trace("dev offline ota resp/notify failed\r\n");
    }
    return 0;
}

static void prepare_resp_payload(int resp_code,char* id)
{
    memset(topic, 0, sizeof(char)*TOPIC_LEN_MAX);
    memset(resp_data, 0, sizeof(char)*DEV_OFFLINE_OTA_TOPIC_RSP_MAX_LEN);

    int data_len = 0;
    resp_data[0] = '{';
    data_len++;
    data_len += snprintf((char*)resp_data + data_len,
                         DEV_OFFLINE_OTA_TOPIC_RSP_MAX_LEN - 2,
                         DEV_OFFLINE_OTA_TOPIC_RSP_FMT,
                         id,
                         resp_code);
    resp_data[strlen(resp_data)] = '}';
    resp_data[DEV_OFFLINE_OTA_TOPIC_RSP_MAX_LEN - 1] = '\0';
    awss_trace("Sending offline ota Resp to app: %s", resp_data);
}

int wifimgr_process_dev_offline_ota_request(void *ctx, void *resource, void *remote, void *request)
{
    int str_len = 0;
    int len = 0;

    char req_msg_id[MSG_REQ_ID_LEN] = {0};
    char *str = NULL;
    char *str_data = NULL;
    char *json = NULL;
    int resp_code = 0;

    if(AWSS_STATE_START != dev_awss_state_get(AWSS_PATTERN_DEV_AP_CONFIG))
        return -1;

    // Parse request from peer dev, to confirm request format correct
    json = awss_cmp_get_coap_payload(request, &len);
    str = (char*)json_get_value_by_name(json, len, "id", &str_len, (int*)NULL);
    if (str != NULL)
        memcpy(req_msg_id, str, str_len > MSG_REQ_ID_LEN - 1 ? MSG_REQ_ID_LEN - 1 : str_len);

    awss_trace("dev offline ota, len:%u, %s, req_msg_id(%s)\r\n", len, json, req_msg_id);

    str_data = (char*)json_get_value_by_name(json, len, "params", &str_len, (int*)NULL);
    if (str_data == NULL) {
        awss_err("dev offline ota json data parse fail!\r\n");
        return -1;
    }

    awss_trace("dev offline ota rec request from app\r\n");
    //save ip and port
    g_networkaddr = *(platform_netaddr_t*)remote;

    /*callback to upgrate*/
    resp_code = g_offline_upgrate_callback(g_ota_service_ctx, json);

    //prepare resp and send
    prepare_resp_payload(resp_code,req_msg_id);
    awss_build_topic((const char *)TOPIC_DEV_OFFLINE_OTA_REPLY, topic, TOPIC_LEN_MAX);
    awss_trace("dev offline ota resp topic:%s\r\n",topic);
    //send
    uint16_t msgid = -1;
    int result = awss_cmp_coap_send_resp(resp_data, strlen(resp_data), remote, topic, request, dev_offline_ota_resp, &msgid, 1);
    (void)result;  /* remove complier warnings */
    awss_trace("coap send resp %s.", result == 0 ? "success" : "fail");

    return 0;
}

int dev_notify_offline_ota_result(int resp_code)
{
    awss_trace("dev offline ota sending notify,code=%d.\r\n",resp_code);
    //prepare resp and send
    prepare_resp_payload(resp_code,"123456");
    awss_build_topic((const char *)TOPIC_DEV_OFFLINE_OTA_FINISH_NOTIFY, topic, TOPIC_LEN_MAX);
    awss_trace("dev offline ota notify topic:%s\r\n",topic);
    //send
    uint16_t msgid = -1;
    int result = awss_cmp_coap_send(resp_data, strlen(resp_data), &g_networkaddr, topic, dev_offline_ota_resp, &msgid);
    (void)result;  /* remove complier warnings */
    awss_info("coap send notify %s", result == 0 ? "success" : "fail");

    return 0;
}

#endif

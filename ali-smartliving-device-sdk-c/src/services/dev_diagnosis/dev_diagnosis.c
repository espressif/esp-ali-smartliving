/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */
#include "iotx_utils.h"
#include "awss_cmp.h"
#include "awss_packet.h"

#include "dev_diagnosis_log.h"
#include "dev_state_machine.h"
#include "dev_errcode.h"
#include "dev_diagnosis.h"

#define MEM_FLAG "diagnosis"
#define DIAGNOSIS_MALLOC(size) LITE_malloc(size, MEM_MAGIC, MEM_FLAG)
#define DIAGNOSIS_FREE(ptr) LITE_free(ptr)

static int dev_diagnosis_statecode_handler(const int state_code, const char *state_message)
{
    diagnosis_debug("state_code:-0x%04x, str_msg=%s", -state_code, state_message == NULL ? "NULL" : state_message);
#ifdef DEV_ERRCODE_ENABLE
    dev_errcode_handle(state_code, state_message);
#endif

#ifdef DEV_OFFLINE_LOG_ENABLE
    diagnosis_offline_log_state_code_handle(state_code, state_message);
#endif

    return 0;
}

// success:0, fail:-1
int dev_diagnosis_module_init()
{
    int ret = 0;
#ifdef DEV_ERRCODE_ENABLE
    /* device errcode service init */
    dev_errcode_module_init();
#endif
    /* device diagnosis sdk state code handler register */
    ret = IOT_RegisterCallback(ITE_STATE_EVERYTHING, dev_diagnosis_statecode_handler);
    return ret;
}

#ifdef DEV_ERRCODE_ENABLE
static int diagnosis_finish_reply(void *context, int result,
                                  void *userdata, void *remote,
                                  void *message)
{
    int ret = 0;

    if (result == 2)
    {                      /* success */
        HAL_SleepMs(1000); //Wait response done
        diagnosis_info("finish diagnosis reboot");
        HAL_SleepMs(1000); //Wait log output done
        HAL_Reboot();
    }
    else
    {
        diagnosis_err("finish disgnosis fail");
    }

    return 0;
}

int diagnosis_finish(void *ctx, void *resource, void *remote, void *request)
{
    int ret = 0;
    char *id = NULL;
    char *method = NULL;

    int code = 200;
    char *topic = NULL;
    char *payload = NULL;
    int payload_len = 0;
    char *reply_payload = NULL;

    payload = awss_cmp_get_coap_payload(request, &payload_len);
    if (!payload || payload_len < 1)
    {
        diagnosis_err("no payload");
        code = RESPONSE_CODE_NO_PAYLOAD;
        goto REPLY;
    }

    diagnosis_info("payload:%s", payload);

    id = LITE_json_value_of(RESPONSE_ID, payload, MEM_MAGIC, MEM_FLAG);
    if (NULL == id)
    {
        diagnosis_err("id err");
        code = RESPONSE_CODE_PARSE_JSON_FAILED;
        goto REPLY;
    }

    method = LITE_json_value_of(RESPONSE_METHOD, payload, MEM_MAGIC, MEM_FLAG);
    if (NULL == id)
    {
        diagnosis_err("method err");
        code = RESPONSE_CODE_PARSE_JSON_FAILED;
        goto REPLY;
    }

    if (strcmp(method, DIAGNOSIS_FINISH_METHOD) != 0)
    {
        diagnosis_err("method not match");
        code = RESPONSE_CODE_METHOD_NOT_MATCH;
        goto REPLY;
    }

REPLY:
    reply_payload = DIAGNOSIS_MALLOC(REPLAY_FINISH_PAYLOAD_LEN);
    if (!reply_payload)
    {
        diagnosis_err("no mem");
        return -1;
    }

    memset(reply_payload, '\0', REPLAY_FINISH_PAYLOAD_LEN);
    HAL_Snprintf(reply_payload, REPLAY_FINISH_PAYLOAD_LEN, GET_REPLY_FMT, id, code, "{}");

    topic = DIAGNOSIS_MALLOC(TOPIC_URL_LEN);
    if (NULL == topic)
    {
        diagnosis_err("no mem");
        goto ERROR;
    }

    awss_build_topic((const char *)TOPIC_DEV_DIAGNOSIS_FINISH_REPLY, topic, TOPIC_URL_LEN);

    diagnosis_info("diagnosis send to APP:%s", reply_payload);
    ret = awss_cmp_coap_send_resp(reply_payload, strlen(reply_payload), remote, topic, request, diagnosis_finish_reply, NULL, 1);

ERROR:
    if (id)
        DIAGNOSIS_FREE(id);

    if (method)
        DIAGNOSIS_FREE(method);

    if (reply_payload)
        DIAGNOSIS_FREE(reply_payload);

    if (topic)
        DIAGNOSIS_FREE(topic);

    return (code == 200) ? ret : -1;
}
#endif

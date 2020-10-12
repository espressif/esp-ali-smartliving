/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifndef __DEV_DIAGNOSIS_H__
#define __DEV_DIAGNOSIS_H__

#define RESPONSE_ID "id"
#define RESPONSE_CODE "code"
#define RESPONSE_MESSAGE "message"
#define RESPONSE_METHOD "method"

#define DIAGNOSIS_FINISH_METHOD "device.diagonsis.finish"
#define TOPIC_DEV_DIAGNOSIS_FINISH_REPLY "/sys/device/diagonsis/finish_reply"

#define REPLAY_FINISH_PAYLOAD_LEN (64)
#define REPLAY_PAYLOAD_LEN (256)

#define TOPIC_URL_LEN (128)

#define GET_REPLY_FMT "{\"id\":%s,\"code\":%d,\"data\":%s}"

typedef enum _respose_code_e
{
    RESPONSE_CODE_OK = 200,
    RESPONSE_CODE_NO_PAYLOAD = 10000,
    RESPONSE_CODE_PARSE_JSON_FAILED,
    RESPONSE_CODE_METHOD_NOT_MATCH
} respose_code_e;

#include "iot_export.h"

#endif /* __DEV_DIAGNOSIS_H__ */
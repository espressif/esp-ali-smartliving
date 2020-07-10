/*
 * Copyright (C) 2015-2019 Alibaba Group Holding Limited
 */

#ifndef __GUIDER_INTERNAL_H__
#define __GUIDER_INTERNAL_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#include "iot_import.h"

#include "iotx_log.h"
#include "iotx_utils.h"
#include "utils_md5.h"
#include "utils_base64.h"
#include "utils_hmac.h"
#include "utils_httpc.h"
#include "iotx_system.h"

#ifdef DEFAULT_LOG_LEVEL_DEBUG
#define GUIDER_SUPPORT_KV_SET_ENV
#endif

#define GUIDER_BOOTSTRAP_DONE (-2)
#define GUIDER_MAX_DIRECT_CONNECT_COUNT (6)

#define GUIDER_IOT_ID_LEN (64)
#define GUIDER_IOT_TOKEN_LEN (64)
#define GUIDER_DEFAULT_TS_STR "2524608000000"

#define GUIDER_SIGN_LEN (48)
#define GUIDER_SIGN_SOURCE_LEN (256)

#define GUIDER_TS_LEN (16)
#define GUIDER_URL_LEN (128)
#define GUIDER_DYNAMIC_URL_LEN (256)
#define GUIDER_RESET_AND_TOKEN_LEN (64)

#define GUIDER_PREAUTH_REQUEST_LEN (256)
#define GUIDER_PREAUTH_RESPONSE_LEN (512)

#define SHA_METHOD "hmacsha1"
#define MD5_METHOD "hmacmd5"

#define GUIDER_PREAUTH_URL_FMT "https://%s/auth/bootstrap"
#define GUIDER_PREAUTH_GET_URL_FMT "https://%s/auth/bootstrap/regionId/%d"

#define sys_emerg(...) log_emerg("sys", __VA_ARGS__)
#define sys_crit(...) log_crit("sys", __VA_ARGS__)
#define sys_err(...) log_err("sys", __VA_ARGS__)
#define sys_warning(...) log_warning("sys", __VA_ARGS__)
#define sys_info(...) log_info("sys", __VA_ARGS__)
#define sys_debug(...) log_debug("sys", __VA_ARGS__)

#define KV_MQTT_URL_KEY "mqtt_url"
#define KV_REGION_ID_KEY "regionid"
#define KV_REGION_ID_VALUE_LEN (6)

typedef enum _secure_mode_e
{
    MODE_TLS_GUIDER = -1,
    MODE_TCP_GUIDER_PLAIN = 0,
    MODE_TCP_GUIDER_ID2_ENCRYPT = 1,
    MODE_TLS_DIRECT = 2,
    MODE_TCP_DIRECT_PLAIN = 3,
    MODE_TCP_DIRECT_ID2_ENCRYPT = 4,
    MODE_TLS_GUIDER_ID2_ENCRYPT = 5,
    MODE_TLS_DIRECT_ID2_ENCRYPT = 7,
    MODE_ITLS_DNS_ID2 = 8,
} secure_mode_e;

typedef enum _connect_method_e
{
    CONNECT_PREAUTH = 0,
    CONNECT_DIRECT,
    CONNECT_METHOD_MAX
} connect_method_e;

typedef enum _ext_params_e
{
    EXT_PLAIN_ROUTE = 0,
    EXT_SMART_ROUTE,
    EXT_PARAM_MAX
} ext_params_e;

#endif /* __GUIDER_INTERNAL_H__ */

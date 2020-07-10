/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifndef __SDK_IMPL_INTERNAL_H__
#define __SDK_IMPL_INTERNAL_H__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "iot_import.h"
#include "iot_export.h"

#include "iotx_utils.h"
#include "iotx_system.h"
#ifndef MAL_ENABLED
#ifdef MQTT_COMM_ENABLED
    #include "iotx_mqtt.h"
#endif
#else
    #include "mal.h"
#endif

#define sdk_emerg(...)          log_emerg("sdk", __VA_ARGS__)
#define sdk_crit(...)           log_crit("sdk", __VA_ARGS__)
#define sdk_err(...)            log_err("sdk", __VA_ARGS__)
#define sdk_warning(...)        log_warning("sdk", __VA_ARGS__)
#define sdk_info(...)           log_info("sdk", __VA_ARGS__)
#define sdk_debug(...)          log_debug("sdk", __VA_ARGS__)

#define sdk_malloc(size)        LITE_malloc(size, MEM_MAGIC, "impl")
#define sdk_free                LITE_free

#define DYNAMIC_REGISTER_REGION_SHANGHAI            "https://iot-auth.cn-shanghai.aliyuncs.com/auth/register/device"     /* shanghai */
#define DYNAMIC_REGISTER_REGION_SOUTHEAST           "https://iot-auth.ap-southeast-1.aliyuncs.com/auth/register/device"  /* singapore */
#define DYNAMIC_REGISTER_REGION_NORTHEAST           "https://iot-auth.ap-northeast-1.aliyuncs.com/auth/register/device"  /* japan */
#define DYNAMIC_REGISTER_REGION_US_WEST             "https://iot-auth.us-west-1.aliyuncs.com/auth/register/device"       /* us west */
#define DYNAMIC_REGISTER_REGION_US_EAST             "https://iot-auth.us-east-1.aliyuncs.com/auth/register/device"       /* us east */
#define DYNAMIC_REGISTER_REGION_EU_CENTRAL          "https://iot-auth.eu-central-1.aliyuncs.com/auth/register/device"    /* german */

#define DYNAMIC_REGISTER_RANDOM_KEY_LENGTH          (15)
#define DYNAMIC_REGISTER_SIGN_LENGTH                (65)
#define DYNAMIC_REGISTER_SIGN_METHOD_HMACMD5        "hmacmd5"
#define DYNAMIC_REGISTER_SIGN_METHOD_HMACSHA1       "hmacsha1"
#define DYNAMIC_REGISTER_SIGN_METHOD_HMACSHA256     "hmacsha256"

typedef struct {
    int domain_type;
    int mqtt_port_num;
    int env;
    int dynamic_register;
} sdk_impl_ctx_t;

typedef enum {
    IMPL_LINKKIT_IOCTL_SWITCH_PROPERTY_POST_REPLY,           /* only for master device, choose whether you need receive property post reply message */
    IMPL_LINKKIT_IOCTL_SWITCH_EVENT_POST_REPLY,              /* only for master device, choose whether you need receive event post reply message */
    IMPL_LINKKIT_IOCTL_SWITCH_PROPERTY_SET_REPLY,            /* only for master device, choose whether you need send property set reply message */
    IMPL_LINKKIT_IOCTL_SWITCH_EVENT_NOTIFY_REPLY,            /* only for master device, choose whether you need send event notify reply message */
    IMPL_LINKKIT_IOCTL_MAX
} impl_linkkit_ioctl_cmd_t;

sdk_impl_ctx_t *sdk_impl_get_ctx(void);

int perform_dynamic_register(_IN_ char product_key[PRODUCT_KEY_MAXLEN],
                             _IN_ char product_secret[PRODUCT_SECRET_MAXLEN],
                             _IN_ char device_name[DEVICE_NAME_MAXLEN],
                             _OU_ char device_secret[DEVICE_SECRET_MAXLEN]);

#endif  /* __SDK_IMPL_INTERNAL_H__ */

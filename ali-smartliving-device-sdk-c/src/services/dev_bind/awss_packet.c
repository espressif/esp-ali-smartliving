/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */



#include <stdint.h>
#include "os.h"
#include "passwd.h"
#include "awss_cmp.h"
#include "awss_notify.h"
#include "awss_packet.h"
#include "awss_utils.h"
#include "iot_import_product.h"
#include "iot_export.h"
#include "iotx_utils.h"

#define AWSS_DEV_RAND_SIGN_FMT  ",\"random\":\"%s\",\"signMethod\":%d,\"sign\":\"%s\""
#define AWSS_DEV_BIND_TOKEN_FMT ",\"token\":\"%s\",\"tokenType\":%d,\"remainTime\":%d,\"type\":%d"
#define AWSS_SUCCESS_FMT        ",\"type\":%d"
#define AWSS_DEV_INFO_FMT       "\"awssVer\":%s,\"productKey\":\"%s\",\"deviceName\":\"%s\",\"mac\":\"%s\",\"ip\":\"%s\",\"cipherType\":%d,\"fwVersion\":\"%s\",\"service\":%d,\"serviceVer\":%s"

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C"
{
#endif

char *build_service_version(void)
{
    char *version_str = NULL;
    lite_cjson_item_t *lite_object = NULL;

    lite_object = lite_cjson_create_object();
    if (lite_object == NULL)
    {
        return NULL;
    }

    if (DEV_DIAGNOSIS_SUPPORTED_SERVICE & DEV_SUPPORT_ERRCODE)
    {
        lite_cjson_add_string_to_object(lite_object, "ErrCode", "1.0");
    }

    if (DEV_DIAGNOSIS_SUPPORTED_SERVICE & DEV_SUPPORT_OFFLINE_OTA)
    {
        lite_cjson_add_string_to_object(lite_object, "OfflineOTA", "1.0");
    }

    if (DEV_DIAGNOSIS_SUPPORTED_SERVICE & DEV_SUPPORT_OFFLINE_LOG)
    {
        lite_cjson_add_string_to_object(lite_object, "OfflineLog", "1.0");
    }

    if (DEV_DIAGNOSIS_SUPPORTED_SERVICE & DEV_SUPPORT_DEVAP_BATCH_PROV)
    {
        lite_cjson_add_string_to_object(lite_object, "BatchEnrollee", "1.0");
    }

    version_str = lite_cjson_print_unformatted(lite_object);
    lite_cjson_delete(lite_object);

    return version_str;
}

static void * awss_get_dev_info(void *dev_info, int len)
{
    char version[FIRMWARE_VERSION_MAXLEN] = {0};
    int ret = 0;
    char *service_ver = NULL;

    if (dev_info == NULL || len <= 0) {
        dump_awss_status(STATE_USER_INPUT_NULL_POINTER, "get dev info input null");
        return NULL;
    }

    char dev_name[OS_DEVICE_NAME_LEN + 1] = {0};
    char mac_str[OS_MAC_LEN + 1] = {0};
    char pk[OS_PRODUCT_KEY_LEN + 1] = {0};
    char ip_str[OS_IP_LEN + 1] = {0};

    os_product_get_key(pk);
    os_device_get_name(dev_name);
    os_wifi_get_mac_str(mac_str);
    os_wifi_get_ip(ip_str, NULL);

    ret = HAL_GetFirmwareVersion(version);
    if (ret <= 0) {
        dump_awss_status(STATE_OTA_FIRMWARE_VER_READ_FAIL, "FW Version get failed");
    }

    service_ver = build_service_version();
    if (service_ver)
    {
        snprintf(dev_info, len - 1, AWSS_DEV_INFO_FMT, AWSS_VER, pk, dev_name, mac_str, ip_str, os_get_conn_encrypt_type(), version, DEV_DIAGNOSIS_SUPPORTED_SERVICE, service_ver);
        HAL_Free(service_ver);
    }

    return dev_info;
}

void *awss_build_dev_info(int type, void *dev_info, int info_len)
{
    int len = 0;
    char *buf = NULL;

    if (dev_info == NULL || info_len <= 0) {
        dump_awss_status(STATE_USER_INPUT_NULL_POINTER, "build dev info input null!");
        return NULL;
    }

    buf = os_zalloc(DEV_INFO_LEN_MAX);
    if (buf == NULL) {
        dump_awss_status(STATE_SYS_DEPEND_MALLOC, "build dev info alloc fail");
        return NULL;
    }

    len += snprintf((char*)dev_info + len, info_len - len - 1, "%s", (char *)awss_get_dev_info(buf, DEV_INFO_LEN_MAX));
    os_free(buf);
    buf = NULL;

    switch (type) {
        case AWSS_NOTIFY_DEV_BIND_TOKEN:
        {
            unsigned char token_str[RANDOM_STR_MAX_LEN] = {0};
            bind_token_type_t token_type;
            awss_get_token(token_str, RANDOM_STR_MAX_LEN, &token_type);
            len += snprintf((char*)dev_info + len, info_len - len - 1, AWSS_DEV_BIND_TOKEN_FMT, 
                                                token_str, token_type, awss_token_remain_time(), 0);
            break;
        }
#ifdef WIFI_PROVISION_ENABLED
        case AWSS_NOTIFY_SUCCESS: {
            len += snprintf((char *)dev_info + len, info_len - len - 1, AWSS_SUCCESS_FMT, 0);
            break;
        }
        case AWSS_NOTIFY_DEV_RAND_SIGN: {

            char sign_str[DEV_SIGN_SIZE * 2 + 1] = {0};
            {
                int txt_len = 80;
                char txt[80] = {0};
                char key[OS_DEVICE_SECRET_LEN + 1] = {0};
                uint8_t sign[DEV_SIGN_SIZE + 1] = {0};

                if (os_get_conn_encrypt_type() == 3) { // aes-key per product
                    os_product_get_secret(key);
                } else { // aes-key per device
                    os_device_get_secret(key);
                }
                awss_build_sign_src(txt, &txt_len);
                produce_signature(sign, (uint8_t *)txt, txt_len, key);
                utils_hex_to_str(sign, DEV_SIGN_SIZE, sign_str, sizeof(sign_str));
            }
            char rand_str[(RANDOM_MAX_LEN << 1) + 1] = {0};
            utils_hex_to_str(g_aes_random, RANDOM_MAX_LEN, rand_str, sizeof(rand_str));
            len += snprintf((char *)dev_info + len, info_len - len - 1, AWSS_DEV_RAND_SIGN_FMT, rand_str, 0, sign_str);
            break;
        }
#endif
        default:
            break;
    }

    return dev_info;
}

#ifdef WIFI_PROVISION_ENABLED
char *awss_build_sign_src(char *sign_src, int *sign_src_len)
{
    char *pk = NULL, *dev_name = NULL;
    int dev_name_len, pk_len, text_len;

    if (sign_src == NULL || sign_src_len == NULL) {
        goto build_sign_src_err;
    }

    pk = os_zalloc(OS_PRODUCT_KEY_LEN + 1);
    dev_name = os_zalloc(OS_DEVICE_NAME_LEN + 1);
    if (pk == NULL || dev_name == NULL) {
        goto build_sign_src_err;
    }

    os_product_get_key(pk);
    os_device_get_name(dev_name);

    pk_len = strlen(pk);
    dev_name_len = strlen(dev_name);

    text_len = RANDOM_MAX_LEN + dev_name_len + pk_len;
    if (*sign_src_len < text_len) {
        goto build_sign_src_err;
    }

    *sign_src_len = text_len;

    memcpy(sign_src, g_aes_random, RANDOM_MAX_LEN);
    memcpy(sign_src + RANDOM_MAX_LEN, dev_name, dev_name_len);
    memcpy(sign_src + RANDOM_MAX_LEN + dev_name_len, pk, pk_len);

    os_free(pk);
    os_free(dev_name);

    return sign_src;

build_sign_src_err:
    if (pk) {
        os_free(pk);
    }
    if (dev_name) {
        os_free(dev_name);
    }
    return NULL;
}
#endif
const char *awss_build_topic(const char *topic_fmt, char *topic, uint32_t tlen)
{
    if (topic == NULL || topic_fmt == NULL || tlen == 0) {
        return NULL;
    }

    char pk[OS_PRODUCT_KEY_LEN + 1] = {0};
    char dev_name[OS_DEVICE_NAME_LEN + 1] = {0};

    os_product_get_key(pk);
    os_device_get_name(dev_name);

    snprintf(topic, tlen - 1, topic_fmt, pk, dev_name);

    return topic;
}

int awss_build_packet(int type, void *id, void *ver, void *method, void *data, int code, void *packet, int *packet_len)
{

    if (packet_len == NULL || data == NULL || packet == NULL) {
        return STATE_USER_INPUT_NULL_POINTER;
    }

    int len = *packet_len;
    if (len <= 0) {
        return STATE_USER_INPUT_NULL_POINTER;
    }

    if (type == AWSS_CMP_PKT_TYPE_REQ) {
        if (ver == NULL || method == NULL) {
            return STATE_USER_INPUT_NULL_POINTER;
        }

        len = snprintf(packet, len - 1, AWSS_REQ_FMT, (char *)id, (char *)ver, (char *)method, (char *)data);
        return 0;
    } else if (type == AWSS_CMP_PKT_TYPE_RSP) {
        len = snprintf(packet, len - 1, AWSS_ACK_FMT, (char *)id, code, (char *)data);
        return 0;
    }
    return STATE_USER_INPUT_OUT_RANGE;
}

void produce_random(uint8_t *random, uint32_t len)
{
    int i = 0;
    int time = HAL_UptimeMs();
    HAL_Srandom(time);
    for (i = 0; i < len; i ++) {
        random[i] = HAL_Random(0xFF);
    }
    // random produced by device, set bind token type to device token
    g_token_type = TOKEN_TYPE_NOT_CLOUD;
}

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif

/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */



#include <stdio.h>
#include "iot_import.h"
#include "iot_export.h"

#include "json_parser.h"
#include "iotx_utils.h"
#include "CoAPExport.h"
#include "alcs_api.h"
#include "alcs_adapter.h"
#include "alcs_mqtt.h"
#include "utils_md5.h"
#include "alcs_adapter.h"
#include "CoAPPlatform.h"

static alcs_mqtt_ctx_t g_alcs_mqtt_ctx;
static int b_prefixkey = 0;

static alcs_mqtt_ctx_t *__alcs_mqtt_get_ctx(void)
{
    return &g_alcs_mqtt_ctx;
}

static alcs_mqtt_status_e __alcs_mqtt_publish(char *topic, int qos, void *data, int len)
{
    return (IOT_MQTT_Publish_Simple(NULL, topic, qos, data, len) < 0) ? ALCS_MQTT_STATUS_ERROR : ALCS_MQTT_STATUS_SUCCESS;
}

static alcs_mqtt_status_e __alcs_mqtt_send_response(char *topic, int id, int code, char *data)
{
    char *msg_pub = NULL;
    uint16_t msg_len = 0;
    alcs_mqtt_status_e status = ALCS_MQTT_STATUS_SUCCESS;

    if (data == NULL || strlen(data) == 0) {
        data = "{}";
    }

    msg_len = strlen(ALCS_MQTT_THING_LAN_PREFIX_RESPONSE_FMT) + 20 + strlen(data) + 1;

    if ((msg_pub = ALCS_ADAPTER_malloc(msg_len)) == NULL) {
        return ALCS_MQTT_STATUS_ERROR;
    }

    snprintf(msg_pub, msg_len, ALCS_MQTT_THING_LAN_PREFIX_RESPONSE_FMT, id, code, data);

    status =  __alcs_mqtt_publish(topic, 1, msg_pub, strlen(msg_pub));

    LITE_free(msg_pub);

    return status;
}

static alcs_mqtt_status_e __alcs_mqtt_kv_set(const char *key, const void *val, int len, int sync)
{
    if (HAL_Kv_Set(key, val, len, sync) != 0) {
        return ALCS_MQTT_STATUS_ERROR;
    }

    COAP_INFO("ALCS KV Set, Key: %s, Len: %d", key, len);
    return ALCS_MQTT_STATUS_SUCCESS;
}

static alcs_mqtt_status_e __alcs_mqtt_kv_get(const char *key, void *buffer, int *buffer_len)
{
    if (HAL_Kv_Get(key, buffer, buffer_len) != 0) {
        return ALCS_MQTT_STATUS_ERROR;
    }

    COAP_INFO("ALCS KV Get, Key: %s", key);

    return ALCS_MQTT_STATUS_SUCCESS;
}

static alcs_mqtt_status_e __alcs_mqtt_kv_del(const char *key)
{
    if (HAL_Kv_Del(key) != 0) {
        return ALCS_MQTT_STATUS_ERROR;
    }

    COAP_INFO("ALCS KV Del, Key: %s", key);

    return ALCS_MQTT_STATUS_SUCCESS;
}

alcs_mqtt_status_e __alcs_mqtt_prefix_secret_save(const char *pk, uint16_t pk_len,
        const char *dn, uint16_t dn_len,
        const char *prefix, uint16_t prefix_len,
        const char *secret, uint16_t secret_len)
{
    char *key_source = NULL;
    uint8_t key_md5[16] = {0};
    char key_md5_hexstr[33] = {0};
    char *value = NULL;

    if (pk == NULL || pk_len >= PRODUCT_KEY_MAXLEN ||
        dn == NULL || dn_len >= DEVICE_NAME_MAXLEN ||
        prefix == NULL || secret == NULL) {
        COAP_ERR("Invalid Parameter");
        return ALCS_MQTT_STATUS_ERROR;
    }

    //Calculate Key
    key_source = ALCS_ADAPTER_malloc(pk_len + dn_len + 1);
    if (key_source == NULL) {
        COAP_ERR("No Enough Memory");
        return ALCS_MQTT_STATUS_ERROR;
    }
    memset(key_source, 0, pk_len + dn_len + 1);

    HAL_Snprintf(key_source, pk_len + dn_len + 1, "%.*s%.*s", pk_len, pk, dn_len, dn);

    utils_md5((const unsigned char *)key_source, strlen(key_source), key_md5);
    utils_md5_hexstr(key_md5, (unsigned char *)key_md5_hexstr);

    //Calculate Value
    value = ALCS_ADAPTER_malloc(prefix_len + secret_len + 3);
    if (value == NULL) {
        COAP_ERR("No Enough Memory");
        LITE_free(key_source);
        return ALCS_MQTT_STATUS_ERROR;
    }
    memset(value, 0, prefix_len + secret_len + 3);

    value[0] = prefix_len;
    value[1] = secret_len;
    HAL_Snprintf(&value[2], prefix_len + secret_len + 1, "%.*s%.*s", prefix_len, prefix, secret_len, secret);
#ifndef DEVICE_MODEL_GATEWAY 
    __alcs_mqtt_kv_del(key_md5_hexstr);
    if (ALCS_MQTT_STATUS_SUCCESS != __alcs_mqtt_kv_set(ALCS_KEY, value, prefix_len + secret_len + 3, 1)) {
#else
    if (ALCS_MQTT_STATUS_SUCCESS != __alcs_mqtt_kv_set(key_md5_hexstr, value, prefix_len + secret_len + 3, 1)) {
#endif
        COAP_ERR("ALCS KV Set Prefix And Secret Fail");
        LITE_free(key_source);
        LITE_free(value);
        return ALCS_MQTT_STATUS_ERROR;
    }

    LITE_free(key_source);
    LITE_free(value);
    return ALCS_MQTT_STATUS_SUCCESS;
}

alcs_mqtt_status_e alcs_mqtt_prefix_secret_load(const char *pk, uint16_t pk_len,
        const char *dn, uint16_t dn_len,
        char *prefix, char *secret)
{
    char *key_source = NULL;
    uint8_t key_md5[16] = {0};
    char key_md5_hexstr[33] = {0};
    char value[128] = {0};
    int value_len = sizeof(value);

    if (pk == NULL || strlen(pk) >= PRODUCT_KEY_MAXLEN ||
        dn == NULL || strlen(dn) >= DEVICE_NAME_MAXLEN ||
        prefix == NULL || secret == NULL) {
        COAP_ERR("Invalid Parameter");
        return ALCS_MQTT_STATUS_ERROR;
    }

    //Calculate Key
    key_source = ALCS_ADAPTER_malloc(pk_len + dn_len + 1);
    if (key_source == NULL) {
        COAP_ERR("No Enough Memory");
        return ALCS_MQTT_STATUS_ERROR;
    }
    memset(key_source, 0, pk_len + dn_len + 1);

    HAL_Snprintf(key_source, pk_len + dn_len + 1, "%.*s%.*s", pk_len, pk, dn_len, dn);

    utils_md5((const unsigned char *)key_source, strlen(key_source), key_md5);
    utils_md5_hexstr(key_md5, (unsigned char *)key_md5_hexstr);

    //Get Value
#ifndef DEVICE_MODEL_GATEWAY 
    if (ALCS_MQTT_STATUS_SUCCESS != __alcs_mqtt_kv_get(ALCS_KEY, value, &value_len)) {
#else
    if (ALCS_MQTT_STATUS_SUCCESS != __alcs_mqtt_kv_get(key_md5_hexstr, value, &value_len)) {
#endif
        COAP_ERR("ALCS KV Get Prefix And Secret Fail");
        LITE_free(key_source);
        return ALCS_MQTT_STATUS_ERROR;
    }

    memcpy(prefix, &value[2], value[0]);
    memcpy(secret, &value[2 + value[0]], value[1]);
    LITE_free(key_source);

    return ALCS_MQTT_STATUS_SUCCESS;
}

alcs_mqtt_status_e alcs_mqtt_prefix_secret_del(const char *pk, uint16_t pk_len,
        const char *dn, uint16_t dn_len)
{
    char *key_source = NULL;
    uint8_t key_md5[16] = {0};
    char key_md5_hexstr[33] = {0};

    if (pk == NULL || strlen(pk) >= PRODUCT_KEY_MAXLEN ||
        dn == NULL || strlen(dn) >= DEVICE_NAME_MAXLEN) {
        COAP_ERR("Invalid Parameter");
        return ALCS_MQTT_STATUS_ERROR;
    }

    //Calculate Key
    key_source = ALCS_ADAPTER_malloc(pk_len + dn_len + 1);
    if (key_source == NULL) {
        COAP_ERR("No Enough Memory");
        return ALCS_MQTT_STATUS_ERROR;
    }
    memset(key_source, 0, pk_len + dn_len + 1);

    HAL_Snprintf(key_source, pk_len + dn_len + 1, "%.*s%.*s", pk_len, pk, dn_len, dn);

    utils_md5((const unsigned char *)key_source, strlen(key_source), key_md5);
    utils_md5_hexstr(key_md5, (unsigned char *)key_md5_hexstr);

#ifndef DEVICE_MODEL_GATEWAY 
    if (ALCS_MQTT_STATUS_SUCCESS != __alcs_mqtt_kv_del(ALCS_KEY)) {
#else 
    if (ALCS_MQTT_STATUS_SUCCESS != __alcs_mqtt_kv_del(key_md5_hexstr)) {
#endif
        COAP_ERR("ALCS KV Get Prefix And Secret Fail");
        LITE_free(key_source);
        return ALCS_MQTT_STATUS_ERROR;
    }

    LITE_free(key_source);
    return ALCS_MQTT_STATUS_SUCCESS;
}
#ifdef ALCS_GROUP_COMM_ENABLE
static char *lg_kv_key = "ALCS_LG";
static void __alcs_update_group_info(CoAPContext *handle){
    char *ptr0 = NULL;
    char gid[ALCS_GROUP_GID_SIZE+1] = {0}, gak[ALCS_GROUP_GAK_SIZE+1] = {0}, gas[ALCS_GROUP_GAS_SIZE+1] = {0}, gbl[ALCS_GROUP_GBL_MAXSIZE+1] = {0};
    int localgroup_kv_len = ALCS_GROUP_KV_MAXSIZE;// (8+8+10+30+1)*2 ->gId gAc gAs bl
    char localgroup_kv[ALCS_GROUP_KV_MAXSIZE] = {0}; 
    memset(localgroup_kv, 0, sizeof(localgroup_kv));
    if(ALCS_MQTT_STATUS_SUCCESS == __alcs_mqtt_kv_get(lg_kv_key, localgroup_kv, &localgroup_kv_len)){
        memcpy(gid, localgroup_kv, ALCS_GROUP_GID_SIZE);
        memcpy(gak, &localgroup_kv[ALCS_GROUP_GID_SIZE], ALCS_GROUP_GAK_SIZE);
        memcpy(gas, &localgroup_kv[ALCS_GROUP_GID_SIZE+ALCS_GROUP_GAK_SIZE], ALCS_GROUP_GAS_SIZE);
        memcpy(gbl, &localgroup_kv[ALCS_GROUP_GID_SIZE+ALCS_GROUP_GAK_SIZE+ALCS_GROUP_GAS_SIZE], ALCS_GROUP_GBL_MAXSIZE);

        alcs_add_svr_group(handle, gid, gak, gas);
        alcs_set_group_revocation(handle, gid, gbl);
        ptr0 = strchr(localgroup_kv, ',');
        if(ptr0 != NULL){
            ptr0++;
            memcpy(gid, ptr0, ALCS_GROUP_GID_SIZE);
            ptr0 = ptr0 + ALCS_GROUP_GID_SIZE;
            memcpy(gak, ptr0, ALCS_GROUP_GAK_SIZE);
            ptr0 = ptr0 + ALCS_GROUP_GAK_SIZE;
            memcpy(gas, ptr0, ALCS_GROUP_GAS_SIZE);
            ptr0 = ptr0 + ALCS_GROUP_GAS_SIZE;
            memset(gbl, 0, sizeof(gbl));
            memcpy(gbl, ptr0, ALCS_GROUP_GBL_MAXSIZE);

            alcs_add_svr_group(handle, gid, gak, gas);
            alcs_set_group_revocation(handle, gid, gbl);
        }
    }
}
#endif
static void __alcs_mqtt_subscribe_callback(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg)
{
    char topic_compare[ALCS_MQTT_TOPIC_MAX_LEN] = {0};
    char reqid[16]   = {0};
    char *topic;
    int topic_len;
    void *payload;
    int payload_len;

    if (msg == NULL) {
        return;
    }
    alcs_mqtt_ctx_t *alcs_mqtt_ctx = (alcs_mqtt_ctx_t *)pcontext;
    iotx_mqtt_topic_info_pt ptopic_info = (iotx_mqtt_topic_info_pt) msg->msg;

    switch (msg->event_type) {
        case IOTX_MQTT_EVENT_SUBCRIBE_SUCCESS:
            return;
        case IOTX_MQTT_EVENT_SUBCRIBE_TIMEOUT:
            return;
        case IOTX_MQTT_EVENT_SUBCRIBE_NACK:
            return;
        case IOTX_MQTT_EVENT_PUBLISH_RECEIVED:
            topic = (char *)ptopic_info->ptopic;
            topic_len = ptopic_info->topic_len;
            payload = (char *)ptopic_info->payload;
            payload_len = ptopic_info->payload_len;
            break;
        default:
            return;
    }

    if (topic == NULL || payload == NULL || topic_len == 0 || payload_len == 0) {
        return;
    }

    memset(topic_compare, 0, ALCS_MQTT_TOPIC_MAX_LEN);
    snprintf(topic_compare, ALCS_MQTT_TOPIC_MAX_LEN, ALCS_MQTT_PREFIX ALCS_MQTT_THING_LAN_PREFIX_GET_REPLY_FMT,
             alcs_mqtt_ctx->product_key, alcs_mqtt_ctx->device_name);

    COAP_INFO("Receivce Message, Topic: %.*s\n", topic_len, topic);
    /* COAP_INFO("Receivce Message, Payload: %.*s\n", payload_len, payload); */

    if ((strlen(topic_compare) == topic_len) && (strncmp(topic_compare, topic, topic_len) == 0)) {
        int data_len = 0, prefix_len = 0, secret_len = 0, productKey_len = 0, deviceName_len = 0;
        char *data = NULL, *prefix = NULL, *secret = NULL, *productKey = NULL, *deviceName = NULL;
        data = json_get_value_by_name((char *)payload, payload_len, "data", &data_len, NULL);
        /* COAP_INFO("Data: %.*s\n", data_len, data); */

        if (NULL != data && 0 != data_len) {
            char back1, back2;
            prefix = json_get_value_by_name(data, data_len, ALCS_MQTT_JSON_KEY_PREFIX, &prefix_len, NULL);
            secret = json_get_value_by_name(data, data_len, ALCS_MQTT_JSON_KEY_SECRET, &secret_len, NULL);
            productKey = json_get_value_by_name(data, data_len, ALCS_MQTT_JSON_KEY_PRODUCT_KEY, &productKey_len, NULL);
            deviceName = json_get_value_by_name(data, data_len, ALCS_MQTT_JSON_KEY_DEVICE_NAME, &deviceName_len, NULL);

            COAP_INFO("Get Reply, Product Key: %.*s, Device Name: %.*s, PrefixKey: %.*s\n", productKey_len, productKey, deviceName_len, deviceName, prefix_len, prefix);

            if (NULL != alcs_mqtt_ctx->coap_ctx && prefix && secret) {
                back1 = prefix[prefix_len];
                prefix[prefix_len] = 0;
                back2 = secret[secret_len];
                secret[secret_len] = 0;
                alcs_add_svr_key(alcs_mqtt_ctx->coap_ctx, prefix, secret, FROMCLOUDSVR);
                prefix[prefix_len] = back1;
                secret[secret_len] = back2;
                b_prefixkey = 1;

#ifdef DEVICE_MODEL_GATEWAY 
                if (productKey && deviceName) {
                    if (__alcs_mqtt_prefix_secret_save(productKey, productKey_len, deviceName, deviceName_len, prefix, prefix_len, secret,
                                                       secret_len) == ALCS_MQTT_STATUS_SUCCESS) {
                        iotx_alcs_subdev_item_t subdev_item;
                        memset(&subdev_item, 0, sizeof(iotx_alcs_subdev_item_t));

                        memcpy(subdev_item.product_key, productKey, productKey_len);
                        memcpy(subdev_item.device_name, deviceName, deviceName_len);
                        subdev_item.stage = IOTX_ALCS_SUBDEV_CONNECT_CLOUD;

                        iotx_alcs_subdev_update_stage(&subdev_item);
                    }
                } else {
                    iotx_alcs_subdev_remove(alcs_mqtt_ctx->product_key, alcs_mqtt_ctx->device_name);
                    if (ALCS_MQTT_STATUS_SUCCESS != __alcs_mqtt_kv_set(ALCS_MQTT_JSON_KEY_PREFIX, prefix, prefix_len, 1)) {
                        COAP_ERR("ALCS KV Set Prefix Fail");
                    }
                    if (ALCS_MQTT_STATUS_SUCCESS != __alcs_mqtt_kv_set(ALCS_MQTT_JSON_KEY_SECRET, secret, secret_len, 1)) {
                        COAP_ERR("ALCS KV Set Secret Fail");
                    }
                }
#else
                __alcs_mqtt_prefix_secret_save(productKey, productKey_len, deviceName, deviceName_len, prefix, prefix_len, secret, secret_len);
#endif
            }
        } else {
            if (ALCS_MQTT_STATUS_SUCCESS == __alcs_mqtt_kv_get(ALCS_MQTT_JSON_KEY_PREFIX, prefix, &prefix_len) &&
                ALCS_MQTT_STATUS_SUCCESS == __alcs_mqtt_kv_get(ALCS_MQTT_JSON_KEY_SECRET, secret, &secret_len)) {
                if (NULL != alcs_mqtt_ctx->coap_ctx && prefix_len && secret_len) {
                    alcs_add_svr_key(alcs_mqtt_ctx->coap_ctx, prefix, secret, FROMCLOUDSVR);
                }
            }
        }
        return;
    }

    memset(topic_compare, 0, ALCS_MQTT_TOPIC_MAX_LEN);
    snprintf(topic_compare, ALCS_MQTT_TOPIC_MAX_LEN, ALCS_MQTT_PREFIX ALCS_MQTT_THING_LAN_PREFIX_UPDATE_FMT,
             alcs_mqtt_ctx->product_key, alcs_mqtt_ctx->device_name);

    if ((strlen(topic_compare) == topic_len) && (strncmp(topic_compare, topic, topic_len) == 0)) {
        int param_len = 0, prefix_len = 0, id_len = 0;
        char *param = NULL, *prefix = NULL;
        char *id = NULL;
        id = json_get_value_by_name((char *)payload, payload_len, "id", &id_len, NULL);

        if (NULL != id && 0 != id_len) {
            strncpy(reqid, id, sizeof(reqid) - 1);
        }
        param = json_get_value_by_name((char *)payload, payload_len, "params", &param_len, NULL);
        if (NULL != param && 0 != param_len) {
            prefix = json_get_value_by_name(param, param_len, ALCS_MQTT_JSON_KEY_PREFIX, &prefix_len, NULL);
            if (NULL != alcs_mqtt_ctx->coap_ctx && prefix) {
                char mprefix[ALCS_MQTT_PREFIX_MAX_LEN + 1] = {0};
                char msecret[ALCS_MQTT_SECRET_MAX_LEN + 1] = {0};
                char mpk[PRODUCT_KEY_LEN + 1] = {0};
                char mdn[DEVICE_NAME_LEN + 1] = {0};
                uint16_t mpk_len = 0, mdn_len = 0;
                HAL_GetProductKey(mpk);
                HAL_GetDeviceName(mdn);
                mpk_len = strlen(mpk);
                mdn_len = strlen(mdn);
                if (alcs_mqtt_prefix_secret_load(mpk, mpk_len, mdn, mdn_len, mprefix, msecret) == ALCS_MQTT_STATUS_SUCCESS) {
                    char back1 = prefix[prefix_len];
                    prefix[prefix_len] = 0;
                    alcs_add_svr_key(alcs_mqtt_ctx->coap_ctx, prefix, msecret, FROMCLOUDSVR);
                    prefix[prefix_len] = back1;
                    if (__alcs_mqtt_prefix_secret_save(mpk, mpk_len, mdn, mdn_len, prefix, prefix_len, msecret,
                                                       strlen(msecret)) == ALCS_MQTT_STATUS_SUCCESS) {
                        COAP_INFO("prefix saved\n");
                    } else {
                        COAP_ERR("prefix save failed\n");
                    }
                } else {
                    COAP_ERR("update prefix_secret_load failed\n");
                }      
            } else {
                COAP_ERR("prefix not found, prefix update failed\n");
            }

            char reply_topic[ALCS_MQTT_TOPIC_MAX_LEN] = {0};
            snprintf(reply_topic, ALCS_MQTT_TOPIC_MAX_LEN, ALCS_MQTT_PREFIX ALCS_MQTT_THING_LAN_PREFIX_UPDATE_REPLY_FMT,
                     alcs_mqtt_ctx->product_key, alcs_mqtt_ctx->device_name);
            __alcs_mqtt_send_response(reply_topic, atoi(reqid), 200, NULL);
        }
        return;
    }

    memset(topic_compare, 0, ALCS_MQTT_TOPIC_MAX_LEN);
    snprintf(topic_compare, ALCS_MQTT_TOPIC_MAX_LEN, ALCS_MQTT_PREFIX ALCS_MQTT_THING_LAN_PREFIX_BLACKLIST_UPDATE_FMT,
             alcs_mqtt_ctx->product_key, alcs_mqtt_ctx->device_name);

    if ((strlen(topic_compare) == topic_len) && (strncmp(topic_compare, topic, topic_len) == 0)) {
        int param_len = 0, blacklist_len = 0, id_len = 0;
        char *param = NULL, *blacklist = NULL, *id = NULL;
        id = json_get_value_by_name((char *)payload, payload_len, "id", &id_len, NULL);

        if (NULL != id && 0 != id_len) {
            strncpy(reqid, id, sizeof(reqid) - 1);
        }
        param = json_get_value_by_name((char *)payload, payload_len, "params", &param_len, NULL);
        if (NULL != param && 0 != param_len) {
            blacklist = json_get_value_by_name(param, param_len, ALCS_MQTT_JSON_KEY_BLACK, &blacklist_len, NULL);
            if (NULL != alcs_mqtt_ctx->coap_ctx && blacklist) {
                alcs_set_revocation(alcs_mqtt_ctx->coap_ctx, blacklist);
                if (ALCS_MQTT_STATUS_SUCCESS != __alcs_mqtt_kv_set(ALCS_MQTT_JSON_KEY_BLACK, blacklist, blacklist_len, 1)) {
                    COAP_ERR("aos_kv_set set blacklist fail");
                }
            }

            char reply_topic[ALCS_MQTT_TOPIC_MAX_LEN] = {0};
            snprintf(reply_topic, ALCS_MQTT_TOPIC_MAX_LEN, ALCS_MQTT_PREFIX ALCS_MQTT_THING_LAN_PREFIX_BLACKLIST_UPDATE_REPLY_FMT,
                     alcs_mqtt_ctx->product_key, alcs_mqtt_ctx->device_name);
            __alcs_mqtt_send_response(reply_topic, atoi(reqid), 200, NULL);
        } else {
            if (ALCS_MQTT_STATUS_SUCCESS == __alcs_mqtt_kv_get(ALCS_MQTT_JSON_KEY_BLACK, blacklist, &blacklist_len)) {
                if (NULL != alcs_mqtt_ctx->coap_ctx) {
                    alcs_set_revocation(alcs_mqtt_ctx->coap_ctx, blacklist);
                }
            }
        }
        return;
    }
}

#ifdef ALCS_GROUP_COMM_ENABLE
    #ifdef DM_UNIFIED_SERVICE_POST
    int iotx_alcs_localgroup_rsp(const char *payload, int payload_len, int msg_from)
    {
        int localgroup_topic = 0;
        int param_len = 0, data_len = 0, groups_len = 0;
        char *param = NULL, *groups = NULL, *data = NULL;
        CoAPContext *coap_ctx = alcs_get_context();
        if (1 == msg_from) { // from post_reply
            param = json_get_value_by_name((char *)payload, payload_len, "serviceResult", &param_len, NULL);
        }
        else {// from _thing
            param = json_get_value_by_name((char *)payload, payload_len, "value", &param_len, NULL);
        }
        groups = json_get_value_by_name((char *)param, param_len, "groups", &groups_len, NULL);
        if (NULL != groups && 0 != groups_len) {
            int res = 0, index = 0, message_len = 0, devid = 0;
            lite_cjson_t lite, lite_list, lite_item;
            int localgroup_kv_len = ALCS_GROUP_KV_MAXSIZE;    // (8+8+10+30+1)*2   ->gId gAc gAs bl
            char localgroup_kv[ALCS_GROUP_KV_MAXSIZE] = {0}; 
            char localgroup_tmp[ALCS_GROUP_KV_MAXSIZE] = {0}; 
            res = lite_cjson_parse(groups, groups_len, &lite);
            if (res != SUCCESS_RETURN || !lite_cjson_is_array(&lite) || lite.size > ALCS_GROUP_ARRAY_SIZE) {
                COAP_ERR("ALCS_LG json err");
                return -1;
            }
            if (lite.size == 0){
                __alcs_mqtt_kv_del(lg_kv_key);
                if (NULL != coap_ctx)
                    alcs_clear_svr_group(coap_ctx);
            } else {
                for (index = 0; index < lite.size; index++) {
                    memset(&lite_list, 0, sizeof(lite_cjson_t));
                    memset(&lite_item, 0, sizeof(lite_cjson_t));
                    res = lite_cjson_array_item(&lite, index, &lite_list);
                    if (res != SUCCESS_RETURN || !lite_cjson_is_object(&lite_list)) {
                        continue;
                    }
                    res = lite_cjson_object_item(&lite_list, "gId", strlen("gId"), &lite_item);
                    if (res != SUCCESS_RETURN || !lite_cjson_is_string(&lite_item)) {
                        continue;
                    }
                    COAP_INFO("gId: %.*s", lite_item.value_length, lite_item.value);
                    if(lite_item.value_length == ALCS_GROUP_GID_SIZE)
                        strncat(localgroup_tmp, lite_item.value, lite_item.value_length);
                    else 
                        break;
                    memset(&lite_item, 0, sizeof(lite_cjson_t));
                    res = lite_cjson_object_item(&lite_list, "gAc", strlen("gAc"), &lite_item);
                    if (res != SUCCESS_RETURN || !lite_cjson_is_string(&lite_item)) {
                        continue;
                    }
                    COAP_INFO("gAc: %.*s", lite_item.value_length, lite_item.value);
                    if(lite_item.value_length == ALCS_GROUP_GAK_SIZE)
                        strncat(localgroup_tmp, lite_item.value, lite_item.value_length);
                    else 
                        break;
                    memset(&lite_item, 0, sizeof(lite_cjson_t));
                    res = lite_cjson_object_item(&lite_list, "gAs", strlen("gAs"), &lite_item);
                    if (res != SUCCESS_RETURN || !lite_cjson_is_string(&lite_item)) {
                        continue;
                    }
                    COAP_INFO("gAs: %.*s", lite_item.value_length, lite_item.value);
                    if(lite_item.value_length == ALCS_GROUP_GAS_SIZE)
                        strncat(localgroup_tmp, lite_item.value, lite_item.value_length);
                    else 
                        break;
                    memset(&lite_item, 0, sizeof(lite_cjson_t));
                    res = lite_cjson_object_item(&lite_list, "gBlacklist", strlen("gBlacklist"), &lite_item);
                    if (res != SUCCESS_RETURN || !lite_cjson_is_string(&lite_item)) {
                        continue;
                    }
                    if(lite_item.value_length > ALCS_GROUP_GBL_MAXSIZE)
                        break;
                        
                    if(lite_item.value_length > 0)
                        strncat(localgroup_tmp, lite_item.value, lite_item.value_length);
                    if(index < lite.size -1)
                        strcat(localgroup_tmp, ",");
                }
                printf("ALCS_LG: %s\n", localgroup_tmp);
                if(ALCS_MQTT_STATUS_SUCCESS != __alcs_mqtt_kv_get(lg_kv_key, localgroup_kv, &localgroup_kv_len) || 
                    strcmp(localgroup_tmp, localgroup_kv) != 0){
                    __alcs_mqtt_kv_set(lg_kv_key, localgroup_tmp, strlen(localgroup_tmp), 1);
                    if (NULL != coap_ctx){
                        alcs_clear_svr_group(coap_ctx);
                        __alcs_update_group_info(coap_ctx);
                    }
                }
            }
        }
        return 0;
    }
    #endif
#endif

static alcs_mqtt_status_e __alcs_mqtt_subscribe(void *ctx, char *topic)
{
#ifdef MQTT_AUTO_SUBSCRIBE
    return (IOT_MQTT_Subscribe(NULL, topic, IOTX_MQTT_QOS3_SUB_LOCAL, __alcs_mqtt_subscribe_callback,
                               ctx) < 0) ? ALCS_MQTT_STATUS_ERROR : ALCS_MQTT_STATUS_SUCCESS;
#else
    return (IOT_MQTT_Subscribe_Sync(NULL, topic, IOTX_MQTT_QOS0, __alcs_mqtt_subscribe_callback,		
                               ctx, 6000) < 0) ? ALCS_MQTT_STATUS_ERROR : ALCS_MQTT_STATUS_SUCCESS;
#endif /* #ifdef MQTT_AUTO_SUBSCRIBE */
}

#if 0
static alcs_mqtt_status_e __alcs_mqtt_unsubscribe(void *ctx, char *topic)
{
    return (mqtt_unsubscribe(topic) != 0) ? ALCS_MQTT_STATUS_ERROR : ALCS_MQTT_STATUS_SUCCESS;
}
#endif
static uint64_t b_retry_ms = 0;
void iotx_alcs_get_prefixkey() {
    if (b_prefixkey == 0) {
        uint64_t time_now = HAL_UptimeMs();
        if (((time_now > b_retry_ms) && (time_now - b_retry_ms >= 10000)) ||
            ((time_now <= b_retry_ms) && ((0xFFFFFFFFFFFFFFFF - b_retry_ms) + time_now >= 10000))) {
            char product_key[PRODUCT_KEY_MAXLEN] = {0};
            char device_name[DEVICE_NAME_MAXLEN] = {0};
            HAL_GetProductKey(product_key);
            HAL_GetDeviceName(device_name);
            alcs_prefixkey_get(product_key, device_name);
            b_retry_ms = time_now;
        }
    }
}
alcs_mqtt_status_e alcs_mqtt_init(void *handle, char *product_key, char *device_name)
{
    char topic[ALCS_MQTT_TOPIC_MAX_LEN] = {0};
    alcs_mqtt_status_e status = ALCS_MQTT_STATUS_SUCCESS;
    alcs_mqtt_ctx_t *ctx =  __alcs_mqtt_get_ctx();

    if (handle == NULL || product_key == NULL || strlen(product_key) > PRODUCT_KEY_LEN ||
        device_name == NULL || strlen(device_name) > DEVICE_NAME_LEN) {
        return ALCS_MQTT_STATUS_ERROR;
    }

    memset(ctx, 0, sizeof(alcs_mqtt_ctx_t));
    ctx->coap_ctx = (CoAPContext *)handle;
    memcpy(ctx->product_key, product_key, strlen(product_key));
    memcpy(ctx->device_name, device_name, strlen(device_name));

    memset(topic, 0, ALCS_MQTT_TOPIC_MAX_LEN);
    snprintf(topic, ALCS_MQTT_TOPIC_MAX_LEN, ALCS_MQTT_PREFIX ALCS_MQTT_THING_LAN_PREFIX_GET_REPLY_FMT,
             ctx->product_key, ctx->device_name);
    if (__alcs_mqtt_subscribe((void *)ctx, topic) != ALCS_MQTT_STATUS_SUCCESS) {
        COAP_ERR("ALCS Subscribe Failed, Topic: %s", topic);
        status = ALCS_MQTT_STATUS_ERROR;
    }

    memset(topic, 0, ALCS_MQTT_TOPIC_MAX_LEN);
    snprintf(topic, ALCS_MQTT_TOPIC_MAX_LEN, ALCS_MQTT_PREFIX ALCS_MQTT_THING_LAN_PREFIX_UPDATE_FMT,
             ctx->product_key, ctx->device_name);
    if (__alcs_mqtt_subscribe((void *)ctx, topic) != ALCS_MQTT_STATUS_SUCCESS) {
        COAP_ERR("ALCS Subscribe Failed, Topic: %s", topic);
        status = ALCS_MQTT_STATUS_ERROR;
    }

    memset(topic, 0, ALCS_MQTT_TOPIC_MAX_LEN);
    snprintf(topic, ALCS_MQTT_TOPIC_MAX_LEN, ALCS_MQTT_PREFIX ALCS_MQTT_THING_LAN_PREFIX_BLACKLIST_UPDATE_FMT,
             ctx->product_key, ctx->device_name);
    if (__alcs_mqtt_subscribe((void *)ctx, topic) != ALCS_MQTT_STATUS_SUCCESS) {
        COAP_ERR("ALCS Subscribe Failed, Topic: %s", topic);
        status = ALCS_MQTT_STATUS_ERROR;
    }

    alcs_mqtt_prefixkey_update((void *)ctx->coap_ctx);
    alcs_mqtt_blacklist_update((void *)ctx->coap_ctx);

#ifdef ALCS_GROUP_COMM_ENABLE
    __alcs_update_group_info(ctx->coap_ctx);
#endif
    alcs_prefixkey_get(ctx->product_key, ctx->device_name);

    return status;
}


alcs_mqtt_status_e alcs_mqtt_deinit(void *handle, char *product_key, char *device_name)
{
#if 0
    char topic[ALCS_MQTT_TOPIC_MAX_LEN] = {0};
    alcs_mqtt_status_e status = ALCS_MQTT_STATUS_SUCCESS;
    alcs_mqtt_ctx_t *ctx =  __alcs_mqtt_get_ctx();

    ARGUMENT_SANITY_CHECK(product_key && strlen(product_key), FAIL_RETURN);
    ARGUMENT_SANITY_CHECK(device_name && strlen(device_name), FAIL_RETURN);

    if (handle == NULL || product_key == NULL || strlen(product_key) > PRODUCT_KEY_LEN ||
        device_name == NULL || strlen(device_name) > DEVICE_NAME_LEN || ctx == NULL) {
        return ALCS_MQTT_STATUS_ERROR;
    }

    memset(topic, 0, ALCS_MQTT_TOPIC_MAX_LEN);
    snprintf(topic, ALCS_MQTT_TOPIC_MAX_LEN, ALCS_MQTT_PREFIX ALCS_MQTT_THING_LAN_PREFIX_GET_REPLY_FMT,
             ctx->product_key, ctx->device_name);
    if (__alcs_mqtt_unsubscribe((void *)ctx, topic) != ALCS_MQTT_STATUS_SUCCESS) {
        COAP_ERR("ALCS Subscribe Failed, Topic: %s", topic);
        status = ALCS_MQTT_STATUS_ERROR;
    }

    memset(topic, 0, ALCS_MQTT_TOPIC_MAX_LEN);
    snprintf(topic, ALCS_MQTT_TOPIC_MAX_LEN, ALCS_MQTT_PREFIX ALCS_MQTT_THING_LAN_PREFIX_UPDATE_FMT,
             ctx->product_key, ctx->device_name);
    if (__alcs_mqtt_unsubscribe((void *)ctx, topic) != ALCS_MQTT_STATUS_SUCCESS) {
        COAP_ERR("ALCS Subscribe Failed, Topic: %s", topic);
        status = ALCS_MQTT_STATUS_ERROR;
    }

    memset(topic, 0, ALCS_MQTT_TOPIC_MAX_LEN);
    snprintf(topic, ALCS_MQTT_TOPIC_MAX_LEN, ALCS_MQTT_PREFIX ALCS_MQTT_THING_LAN_PREFIX_BLACKLIST_UPDATE_FMT,
             ctx->product_key, ctx->device_name);
    if (__alcs_mqtt_unsubscribe((void *)ctx, topic) != ALCS_MQTT_STATUS_SUCCESS) {
        COAP_ERR("ALCS Subscribe Failed, Topic: %s", topic);
        status = ALCS_MQTT_STATUS_ERROR;
    }

    return status;
#endif
    return ALCS_MQTT_STATUS_SUCCESS;
}

void alcs_mqtt_add_srv_key(const char *prefix, const char *secret)
{
    alcs_mqtt_ctx_t *alcs_mqtt_ctx = __alcs_mqtt_get_ctx();
    alcs_add_svr_key(alcs_mqtt_ctx->coap_ctx, prefix, secret, FROMCLOUDSVR);
}
void alcs_mqtt_remove_srv_key(const char *prefix)
{
    alcs_mqtt_ctx_t *alcs_mqtt_ctx = __alcs_mqtt_get_ctx();
    alcs_remove_svr_key(alcs_mqtt_ctx->coap_ctx, prefix);
}

alcs_mqtt_status_e alcs_mqtt_blacklist_update(void *ctx)
{
    CoAPContext *context = (CoAPContext *)ctx;
    char blacklist[ALCS_MQTT_BLACK_MAX_LEN] = {0};
    int blacklist_len = ALCS_MQTT_BLACK_MAX_LEN;

    if (NULL == context) {
        return -1;
    }

    if (ALCS_MQTT_STATUS_SUCCESS == __alcs_mqtt_kv_get(ALCS_MQTT_JSON_KEY_BLACK, blacklist, &blacklist_len)) {
        COAP_INFO("The blacklist is %.*s", blacklist_len, blacklist);
        if (blacklist_len) {
            alcs_set_revocation(context, blacklist);
            return ALCS_MQTT_STATUS_SUCCESS;
        }
    }

    return ALCS_MQTT_STATUS_ERROR;
}

alcs_mqtt_status_e alcs_mqtt_prefixkey_update(void *ctx)
{
    CoAPContext *context = (CoAPContext *)ctx;
    char prefix[ALCS_MQTT_PREFIX_MAX_LEN + 1] = {0};
    char secret[ALCS_MQTT_SECRET_MAX_LEN + 1] = {0};
    char product_key[PRODUCT_KEY_LEN + 1] = {0};
    char device_name[DEVICE_NAME_LEN + 1] = {0};
    uint16_t prodkey_len = 0, devname_len = 0;

    if (NULL == context) {
        return ALCS_MQTT_STATUS_ERROR;
    }

    COAP_INFO("start alcs_prefixkey_update\n");
    HAL_GetProductKey(product_key);
    HAL_GetDeviceName(device_name);
    prodkey_len = strlen(product_key);
    devname_len = strlen(device_name);
    if (alcs_mqtt_prefix_secret_load(product_key, prodkey_len, device_name, devname_len, prefix, secret) == ALCS_MQTT_STATUS_SUCCESS) {
        alcs_add_svr_key(context, prefix, secret, FROMCLOUDSVR);
        return ALCS_MQTT_STATUS_SUCCESS;
    } else {
        COAP_INFO("alcs_prefixkey_update failed\n");
    }
    return ALCS_MQTT_STATUS_ERROR;
}

alcs_mqtt_status_e alcs_prefixkey_get(const char *product_key, const char *device_name)
{
    //int ret = 0;
    char *msg_pub = NULL;
    uint16_t msg_len = 0;
    char topic[ALCS_MQTT_TOPIC_MAX_LEN] = {0};
    alcs_mqtt_ctx_t *ctx =  __alcs_mqtt_get_ctx();
    alcs_mqtt_status_e status = ALCS_MQTT_STATUS_SUCCESS;
    int id = ctx->send_id++;

    if (product_key == NULL || strlen(product_key) > PRODUCT_KEY_LEN ||
        device_name == NULL || strlen(device_name) > DEVICE_NAME_LEN) {
        return ALCS_MQTT_STATUS_ERROR;
    }
    snprintf(topic, ALCS_MQTT_TOPIC_MAX_LEN, ALCS_MQTT_PREFIX ALCS_MQTT_THING_LAN_PREFIX_GET_FMT,
             product_key, device_name);

    msg_len = strlen(ALCS_MQTT_THING_ALCS_REQUEST) + 10 + 1;
    if ((msg_pub = ALCS_ADAPTER_malloc(msg_len)) == NULL) {
        return ALCS_MQTT_STATUS_ERROR;
    }

    snprintf(msg_pub, msg_len, ALCS_MQTT_THING_ALCS_REQUEST, id);

    COAP_INFO("ALCS Prefix Get, Topic: %s, Payload: %s", topic, msg_pub);
    status = __alcs_mqtt_publish(topic, 0, msg_pub, strlen(msg_pub));

    LITE_free(msg_pub);

    return status;
}

alcs_mqtt_status_e alcs_mqtt_subdev_prefix_get(const char *product_key, const char *device_name)
{
    //int ret = 0;
    char *msg_pub = NULL;
    uint16_t msg_len = 0;
    char topic[ALCS_MQTT_TOPIC_MAX_LEN] = {0};
    alcs_mqtt_ctx_t *ctx =  __alcs_mqtt_get_ctx();
    alcs_mqtt_status_e status = ALCS_MQTT_STATUS_SUCCESS;
    int id = ctx->send_id++;

    if (product_key == NULL || strlen(product_key) > PRODUCT_KEY_LEN ||
        device_name == NULL || strlen(device_name) > DEVICE_NAME_LEN) {
        return ALCS_MQTT_STATUS_ERROR;
    }

    COAP_INFO("Subdevice, PK: %s, DN: %s\n", product_key, device_name);
    snprintf(topic, ALCS_MQTT_TOPIC_MAX_LEN, ALCS_MQTT_PREFIX ALCS_MQTT_THING_LAN_PREFIX_GET_FMT,
             ctx->product_key, ctx->device_name);

    msg_len = strlen(ALCS_MQTT_THING_ALCS_SUBDEV_REQUEST) + 10 + strlen(product_key) + strlen(device_name) + 1;
    if ((msg_pub = ALCS_ADAPTER_malloc(msg_len)) == NULL) {
        return ALCS_MQTT_STATUS_ERROR;
    }

    snprintf(msg_pub, msg_len, ALCS_MQTT_THING_ALCS_SUBDEV_REQUEST, id,
             (int)strlen(product_key), product_key, (int)strlen(device_name), device_name);

    COAP_ERR("ALCS Prefix Get, Topic: %s, Payload: %s", topic, msg_pub);
    status = __alcs_mqtt_publish(topic, 1, msg_pub, strlen(msg_pub));

    LITE_free(msg_pub);

    return status;
}


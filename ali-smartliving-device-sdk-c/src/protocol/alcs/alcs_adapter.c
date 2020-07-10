/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */



#include <stddef.h>
#include <string.h>

#include "iot_import.h"
#include "iot_export.h"
#include "alcs_api.h"
#include "alcs_coap.h"
#include "alcs_mqtt.h"
#include "CoAPInternal.h"
#include "CoAPExport.h"
#include "CoAPServer.h"
#include "alcs_adapter.h"
#include "alcs_mqtt.h"
#include "alcs_localsetup.h"
#include "CoAPPlatform.h"
#include "alcs_api_internal.h"
#include "CoAPResource.h"

static iotx_alcs_adapter_t g_alcs_adapter;

static void alcs_heartbeat(void *handle);

static iotx_alcs_adapter_t *__iotx_alcs_get_ctx(void)
{
    return &g_alcs_adapter;
}

iotx_alcs_adapter_t *iotx_alcs_get_ctx(void)
{
    return &g_alcs_adapter;
}

static char *iotx_alcs_topic_parse_pk(char *topic, uint16_t *length)
{
    if (topic == NULL || length == NULL) {
        COAP_ERR("Invalid Parameter");
        return NULL;
    }

    char *pos = NULL;
    uint8_t slash_count = 0;
    uint16_t idx = 0;
    uint16_t topic_len = strlen(topic);

    while (idx < topic_len) {
        if (topic[idx] == '/') {
            slash_count++;
            if (slash_count == 2) {
                pos = topic + idx + 1;
            }
            if (slash_count == 3) {
                *length = topic + idx - pos;
            }
        }
        idx++;
    }

    return pos;
}

static char *iotx_alcs_topic_parse_dn(char *topic, uint16_t *length)
{
    if (topic == NULL || length == NULL) {
        COAP_ERR("Invalid Parameter");
        return NULL;
    }

    char *pos = NULL;
    uint8_t slash_count = 0;
    uint16_t idx = 0;
    uint16_t topic_len = strlen(topic);

    while (idx < topic_len) {
        if (topic[idx] == '/') {
            slash_count++;
            if (slash_count == 3) {
                pos = topic + idx + 1;
            }
            if (slash_count == 4) {
                *length = topic + idx - pos;
            }
        }
        idx++;
    }

    return pos;
}

static int _iotx_alcs_send_list_search_and_remove(iotx_alcs_adapter_t *adapter, CoAPMessage *message,
        iotx_alcs_send_msg_t **send_msg)
{
    iotx_alcs_send_msg_t *node = NULL;
    iotx_alcs_send_msg_t *next = NULL;

    list_for_each_entry_safe(node, next, &adapter->alcs_send_list, linked_list, iotx_alcs_send_msg_t) {
        if (message->header.tokenlen == node->token_len &&
            memcmp(message->token, node->token, node->token_len) == 0) {
            *send_msg = node;
            list_del(&node->linked_list);
            return SUCCESS_RETURN;
        }
    }

    return FAIL_RETURN;
}

void iotx_alcs_coap_adapter_send_msg_handle(CoAPContext *context,
        CoAPReqResult result,
        void *userdata,
        NetworkAddr *remote,
        CoAPMessage *message)
{
    int res = 0;
    iotx_alcs_adapter_t *adapter = (iotx_alcs_adapter_t *)userdata;
    iotx_alcs_event_msg_t event;
    memset(&event, 0, sizeof(iotx_alcs_event_msg_t));

    switch (result) {
        case COAP_REQUEST_SUCCESS: {
            iotx_alcs_transfer_msg_t transfer_msg;
            iotx_alcs_send_msg_t *send_msg = NULL;

            memset(&transfer_msg, 0, sizeof(iotx_alcs_transfer_msg_t));

            transfer_msg.ip = (char *)remote->addr;
            transfer_msg.port = remote->port;
            HAL_MutexLock(adapter->mutex);
            res = _iotx_alcs_send_list_search_and_remove(adapter, message, &send_msg);
            HAL_MutexUnlock(adapter->mutex);

            if (res < SUCCESS_RETURN) {
                return;
            }

            transfer_msg.uri = send_msg->uri;
            transfer_msg.token_len = send_msg->token_len;
            transfer_msg.token = send_msg->token;
            transfer_msg.payload_len = message->payloadlen;
            transfer_msg.payload = message->payload;

            event.event_type = IOTX_ALCS_EVENT_MSG_SEND_MESSAGE_SUCCESS;
            event.msg = &transfer_msg;

            adapter->alcs_event_handle->h_fp(adapter->alcs_event_handle->pcontext, (void *)adapter, &event);

            LITE_free(send_msg->token);
            LITE_free(send_msg->uri);
            LITE_free(send_msg);
        }
        break;
        case COAP_RECV_RESP_TIMEOUT: {
            iotx_alcs_transfer_msg_t transfer_msg;
            iotx_alcs_send_msg_t *send_msg = NULL;

            memset(&transfer_msg, 0, sizeof(iotx_alcs_transfer_msg_t));

            transfer_msg.ip = (char *)remote->addr;
            transfer_msg.port = remote->port;
            HAL_MutexLock(adapter->mutex);
            res = _iotx_alcs_send_list_search_and_remove(adapter, message, &send_msg);
            HAL_MutexUnlock(adapter->mutex);

            if (res < SUCCESS_RETURN) {
                return;
            }

            transfer_msg.uri = send_msg->uri;
            transfer_msg.token_len = send_msg->token_len;
            transfer_msg.token = send_msg->token;
            transfer_msg.payload_len = 0;
            transfer_msg.payload = NULL;

            event.event_type = IOTX_ALCS_EVENT_MSG_SEND_MESSAGE_RESP_TIMEOUT;
            event.msg = &transfer_msg;

            adapter->alcs_event_handle->h_fp(adapter->alcs_event_handle->pcontext, (void *)adapter, &event);

            LITE_free(send_msg->token);
            LITE_free(send_msg->uri);
            LITE_free(send_msg);
        }
        break;
        default:
            COAP_WRN("Unknown Coap Request Result: %d", result);
            break;
    }
}

void iotx_alcs_coap_adapter_event_notifier(unsigned int event, NetworkAddr *remote, void *message)
{
    COAP_INFO("ALCS Coap Event: %d, Remote Device Address: %s, Remote Device Port: %d",
              event, remote->addr, remote->port);
}

int iotx_alcs_adapter_list_init(iotx_alcs_adapter_t *adapter)
{
    //initialze send list
    INIT_LIST_HEAD(&adapter->alcs_send_list);
#ifdef DEVICE_MODEL_GATEWAY 
    INIT_LIST_HEAD(&adapter->alcs_subdev_list);
#endif
    return SUCCESS_RETURN;
}

static void _iotx_alcs_adapter_send_list_destroy(iotx_alcs_adapter_t *adapter)
{
    iotx_alcs_send_msg_t *node = NULL;
    iotx_alcs_send_msg_t *next = NULL;

    list_for_each_entry_safe(node, next, &adapter->alcs_send_list, linked_list, iotx_alcs_send_msg_t) {
        list_del(&node->linked_list);
        LITE_free(node->token);
        LITE_free(node->uri);
        LITE_free(node);
    }
}

#ifdef DEVICE_MODEL_GATEWAY 
static void _iotx_alcs_adapter_subdev_list_destroy(iotx_alcs_adapter_t *adapter)
{
    iotx_alcs_subdev_item_t *node = NULL;
    iotx_alcs_subdev_item_t *next = NULL;

    list_for_each_entry_safe(node, next, &adapter->alcs_subdev_list, linked_list, iotx_alcs_subdev_item_t) {
        list_del(&node->linked_list);
        LITE_free(node);
    }
}
#endif
int iotx_alcs_adapter_deinit(void)
{
    char product_key[PRODUCT_KEY_MAXLEN] = {0};
    char device_name[DEVICE_NAME_MAXLEN] = {0};
    iotx_alcs_adapter_t *adapter = __iotx_alcs_get_ctx();

    HAL_GetProductKey(product_key);
    HAL_GetDeviceName(device_name);

    HAL_MutexLock(adapter->mutex);
    _iotx_alcs_adapter_send_list_destroy(adapter);
#ifdef DEVICE_MODEL_GATEWAY 
    _iotx_alcs_adapter_subdev_list_destroy(adapter);
#endif
    HAL_MutexUnlock(adapter->mutex);

    if (adapter->alcs_event_handle) {
        LITE_free(adapter->alcs_event_handle);
    }

    HAL_MutexDestroy(adapter->mutex);

    alcs_mqtt_deinit(adapter->coap_ctx, product_key, device_name);

    //if (adapter->coap_ctx) CoAPContext_free(adapter->coap_ctx);

    alcs_context_deinit();
    alcs_deinit();
    alcs_auth_deinit();

    return SUCCESS_RETURN;
}

int iotx_alcs_adapter_init(iotx_alcs_adapter_t *adapter, iotx_alcs_param_t *param)
{
    COAP_INFO("iotx_alcs_adapter_init");

    int res;
    CoAPInitParam coap_param;
    CoAPContext *coap_ctx = NULL;
    char product_key[PRODUCT_KEY_MAXLEN] = {0};
    char device_name[DEVICE_NAME_MAXLEN] = {0};

    memset(&coap_param, 0, sizeof(CoAPInitParam));

    adapter->mutex = HAL_MutexCreate();
    if (adapter->mutex == NULL) {
        COAP_ERR("Mutex Init Failed");
        return FAIL_RETURN;
    }

    coap_param.send_maxcount = param->send_maxcount;
    coap_param.obs_maxcount = param->obs_maxcount;
    coap_param.port = param->port;
    coap_param.group = param->group;
    coap_param.waittime = param->waittime;
    coap_param.res_maxcount = param->res_maxcount;
    coap_param.appdata = NULL;
    coap_param.notifier = iotx_alcs_coap_adapter_event_notifier;

    coap_ctx = alcs_context_init(&coap_param);
    if (coap_ctx == NULL) {
        COAP_ERR("Coap Context Init Failed");
        HAL_MutexDestroy(adapter->mutex);
        return FAIL_RETURN;
    }
    adapter->coap_ctx = coap_ctx;

    res = HAL_GetProductKey(product_key);
    if (res <= 0 || res > PRODUCT_KEY_MAXLEN - 1) {
        iotx_alcs_adapter_deinit();
        COAP_ERR("Get Product Key Failed");
        return FAIL_RETURN;
    }

    res = HAL_GetDeviceName(device_name);
    if (res <= 0 || res > DEVICE_NAME_MAXLEN - 1) {
        iotx_alcs_adapter_deinit();
        COAP_ERR("Get Device Name Failed");
        return FAIL_RETURN;
    }

    alcs_init();

    res = alcs_auth_init(coap_ctx, product_key, device_name, param->role);
    if (res != COAP_SUCCESS) {
        iotx_alcs_adapter_deinit();
        COAP_ERR("ALCS Auth Init Failed");
        return FAIL_RETURN;
    }
    adapter->role = param->role;
#ifdef ALCS_SERVER_ENABLED
    extern void on_svr_auth_timer(CoAPContext *);
    if (adapter->role & IOTX_ALCS_ROLE_SERVER) {
        adapter->alcs_server_auth_timer_func = on_svr_auth_timer;
    }
#endif

#ifdef ALCS_CLIENT_ENABLED
    extern void on_client_auth_timer(CoAPContext *);
    if (adapter->role & IOTX_ALCS_ROLE_CLIENT) {
        adapter->alcs_client_auth_timer_func = on_client_auth_timer;
    }
#endif

    adapter->alcs_event_handle = (iotx_alcs_event_handle_t *)ALCS_ADAPTER_malloc(sizeof(iotx_alcs_event_handle_t));
    if (adapter->alcs_event_handle == NULL) {
        iotx_alcs_adapter_deinit();
        COAP_ERR("ALCS Event Handle Init Failed");
        return FAIL_RETURN;
    }
    memcpy(adapter->alcs_event_handle, param->handle_event, sizeof(iotx_alcs_event_handle_t));

    if (iotx_alcs_adapter_list_init(adapter) != SUCCESS_RETURN) {
        iotx_alcs_adapter_deinit();
        COAP_ERR("ALCS Linked List Init Failed");
        return FAIL_RETURN;
    }

    alcs_localsetup_init(adapter, coap_ctx, product_key, device_name);

    return SUCCESS_RETURN;
}

#ifdef DEVICE_MODEL_GATEWAY 
static int _iotx_alcs_subdev_list_search(const char *pk, const char *dn, iotx_alcs_subdev_item_t **subdev_item)
{
    iotx_alcs_adapter_t *adapter = __iotx_alcs_get_ctx();
    iotx_alcs_subdev_item_t *node = NULL;

    if (pk == NULL || dn == NULL) {
        COAP_ERR("Invalid Parameter");
        return FAIL_RETURN;
    }

    list_for_each_entry(node, &adapter->alcs_subdev_list, linked_list, iotx_alcs_subdev_item_t) {
        if (strlen(node->product_key) == strlen(pk) &&
            memcmp(node->product_key, pk, strlen(pk)) == 0 &&
            strlen(node->device_name) == strlen(dn) &&
            memcmp(node->device_name, dn, strlen(dn)) == 0) {
            *subdev_item = node;
            return SUCCESS_RETURN;
        }
    }

    return FAIL_RETURN;
}

int iotx_alcs_subdev_remove(const char *pk, const char *dn)
{
    int res = 0;
    iotx_alcs_adapter_t *adapter = __iotx_alcs_get_ctx();
    iotx_alcs_subdev_item_t *subdev_item = NULL;

    if (pk == NULL || dn == NULL) {
        COAP_ERR("Invalid Parameter");
        return FAIL_RETURN;
    }

    HAL_MutexLock(adapter->mutex);

    list_for_each_entry(subdev_item, &adapter->alcs_subdev_list, linked_list, iotx_alcs_subdev_item_t) {
        if (strlen(subdev_item->product_key) == strlen(pk) &&
            memcmp(subdev_item->product_key, pk, strlen(pk)) == 0 &&
            strlen(subdev_item->device_name) == strlen(dn) &&
            memcmp(subdev_item->device_name, dn, strlen(dn)) == 0) {
                char prefix[ALCS_MQTT_PREFIX_MAX_LEN] = {0};
                char secret[ALCS_MQTT_SECRET_MAX_LEN] = {0};
                alcs_mqtt_prefix_secret_load(pk, strlen(pk), dn, strlen(dn), prefix, secret);
                alcs_mqtt_remove_srv_key(prefix);
                list_del(&subdev_item->linked_list);
                LITE_free(subdev_item);
        }
    }
    HAL_MutexUnlock(adapter->mutex);

    return SUCCESS_RETURN;
}

int iotx_alcs_subdev_update_stage(iotx_alcs_subdev_item_t *item)
{
    int res = 0;
    iotx_alcs_adapter_t *adapter = __iotx_alcs_get_ctx();
    iotx_alcs_subdev_item_t *subdev_item = NULL;

    if (item == NULL) {
        COAP_ERR("Invalid Parameter");
        return FAIL_RETURN;
    }

    HAL_MutexLock(adapter->mutex);
    res = _iotx_alcs_subdev_list_search(item->product_key, item->device_name, &subdev_item);

    if (res < SUCCESS_RETURN) {
        COAP_WRN("No Matched Item");
        HAL_MutexUnlock(adapter->mutex);
        return FAIL_RETURN;
    }

    subdev_item->stage = item->stage;

    HAL_MutexUnlock(adapter->mutex);
    return SUCCESS_RETURN;
}

void iotx_alcs_subdev_stage_check(void)
{
    iotx_alcs_adapter_t *adapter = __iotx_alcs_get_ctx();
    iotx_alcs_subdev_item_t *node = NULL;
    uint64_t time_now = HAL_UptimeMs();

    HAL_MutexLock(adapter->mutex);
    list_for_each_entry(node, &adapter->alcs_subdev_list, linked_list, iotx_alcs_subdev_item_t) {
        if (node->stage == IOTX_ALCS_SUBDEV_DISCONNCET_CLOUD) {
            if (((time_now > node->retry_ms) &&
                 (time_now - node->retry_ms >= IOTX_ALCS_SUBDEV_RETRY_INTERVAL_MS)) ||
                ((time_now <= node->retry_ms) &&
                 ((0xFFFFFFFFFFFFFFFF - node->retry_ms) + time_now >= IOTX_ALCS_SUBDEV_RETRY_INTERVAL_MS))) {
                //Get Prefix And Secret From Cloud
                alcs_mqtt_subdev_prefix_get(node->product_key, node->device_name);
                node->retry_ms = time_now;
            }
        }
    }
    HAL_MutexUnlock(adapter->mutex);
}
#endif
void *iotx_alcs_construct(iotx_alcs_param_t *params)
{
    COAP_INFO("iotx_alcs_construct enter");

    int res = 0;
    iotx_alcs_adapter_t *adapter = __iotx_alcs_get_ctx();

    POINTER_SANITY_CHECK(params, NULL);
    STRING_PTR_SANITY_CHECK(params->group, NULL);

    memset(adapter, 0, sizeof(iotx_alcs_adapter_t));

    res = iotx_alcs_adapter_init(adapter, params);
    if (res != SUCCESS_RETURN) {
        COAP_ERR("Adapter Init Failed");
        return NULL;
    }

    return (void *)adapter;
}

int iotx_alcs_cloud_init(void *handle)
{
    COAP_INFO("Start ALCS Cloud Init");
    int res = 0;
    iotx_alcs_adapter_t *adapter = __iotx_alcs_get_ctx();
    char product_key[PRODUCT_KEY_MAXLEN] = {0};
    char device_name[DEVICE_NAME_MAXLEN] = {0};

    if (adapter->local_cloud_inited == 1) {
        return SUCCESS_RETURN;
    }

    if (handle == NULL) {
        return FAIL_RETURN;
    }

    res = HAL_GetProductKey(product_key);
    if (res <= 0 || res > PRODUCT_KEY_MAXLEN - 1) {
        iotx_alcs_adapter_deinit();
        COAP_ERR("Get Product Key Failed");
        return FAIL_RETURN;
    }

    res = HAL_GetDeviceName(device_name);
    if (res <= 0 || res > DEVICE_NAME_MAXLEN - 1) {
        iotx_alcs_adapter_deinit();
        COAP_ERR("Get Device Name Failed");
        return FAIL_RETURN;
    }

    if (alcs_mqtt_init(adapter->coap_ctx, product_key, device_name) != ALCS_MQTT_STATUS_SUCCESS) {
        /*solve the prpblem of hard fault when mqtt connection fails once*/
        COAP_ERR("ALCS MQTT Init Failed");
        return FAIL_RETURN;
    }

    adapter->local_cloud_inited = 1;

    return SUCCESS_RETURN;
}

int iotx_alcs_destroy(void **phandle)
{
    POINTER_SANITY_CHECK(phandle, NULL_VALUE_ERROR);
    POINTER_SANITY_CHECK(*phandle, NULL_VALUE_ERROR);

    iotx_alcs_adapter_deinit();

    return SUCCESS_RETURN;
}

static void alcs_heartbeat(void *handle)
{
    iotx_alcs_adapter_t *adapter = (iotx_alcs_adapter_t *)handle;

    if (adapter->role & IOTX_ALCS_ROLE_SERVER && adapter->alcs_server_auth_timer_func != NULL) {
        adapter->alcs_server_auth_timer_func(adapter->coap_ctx);
    }

    if (adapter->role & IOTX_ALCS_ROLE_CLIENT && adapter->alcs_client_auth_timer_func != NULL) {
        adapter->alcs_client_auth_timer_func(adapter->coap_ctx);
    }
}
int iotx_alcs_yield(void *handle)
{
    int res = 0;
    iotx_alcs_adapter_t *adapter = (iotx_alcs_adapter_t *)handle;

    POINTER_SANITY_CHECK(adapter, NULL_VALUE_ERROR);
    POINTER_SANITY_CHECK(adapter->coap_ctx, NULL_VALUE_ERROR);

#ifndef DEV_BIND_ENABLED
    res = (CoAPMessage_cycle(adapter->coap_ctx) != COAP_SUCCESS) ? (FAIL_RETURN) : (SUCCESS_RETURN);
    CoAPServer_thread_leave();
#endif
    alcs_heartbeat(handle);

#ifdef DEVICE_MODEL_GATEWAY 
    iotx_alcs_subdev_stage_check();
#endif

    iotx_alcs_get_prefixkey();
    return res;
}

int iotx_alcs_send(void *handle, iotx_alcs_msg_t *msg)
{
#ifdef ALCS_CLIENT_ENABLED
    int res = 0;
    iotx_alcs_adapter_t *adapter = (iotx_alcs_adapter_t *)handle;
    CoAPMessage coap_msg;
    CoAPLenString coap_payload;
    NetworkAddr network_addr;

    POINTER_SANITY_CHECK(adapter, NULL_VALUE_ERROR);
    POINTER_SANITY_CHECK(adapter->coap_ctx, NULL_VALUE_ERROR);
    POINTER_SANITY_CHECK(msg, NULL_VALUE_ERROR);
    POINTER_SANITY_CHECK(msg->payload, NULL_VALUE_ERROR);

    STRING_PTR_SANITY_CHECK(msg->ip, FAIL_RETURN);
    STRING_PTR_SANITY_CHECK(msg->uri, FAIL_RETURN);


    if (strlen(msg->ip) > NETWORK_ADDR_LEN) {
        COAP_ERR("Invalid Ip Address Length");
        return FAIL_RETURN;
    }

    memset(&coap_msg, 0, sizeof(CoAPMessage));
    memset(&coap_payload, 0, sizeof(CoAPLenString));

    coap_payload.len = msg->payload_len;
    coap_payload.data = msg->payload;

    alcs_msg_init(adapter->coap_ctx, &coap_msg, msg->msg_code, msg->msg_type, 0, &coap_payload, (void *)adapter);

    res = alcs_msg_setAddr(&coap_msg, msg->uri, NULL);
    if (res != COAP_SUCCESS) {
        COAP_ERR("ALCS Message Set URI Failed");
        return FAIL_RETURN;
    }

    memset(&network_addr, 0, sizeof(NetworkAddr));
    memcpy(network_addr.addr, msg->ip, strlen(msg->ip));
    network_addr.port = msg->port;

    //Get Product Key And Device Name
    AlcsDeviceKey devKey;
    char productKey[PRODUCT_KEY_MAXLEN] = {0};
    char deviceName[DEVICE_NAME_MAXLEN] = {0};
    char *uri_pk = NULL;
    char *uri_dn = NULL;
    uint16_t uri_pk_len = 0;
    uint16_t uri_dn_len = 0;

    memset(&devKey, 0, sizeof(AlcsDeviceKey));
    memcpy(&devKey.addr, &network_addr, sizeof(NetworkAddr));

    uri_pk = iotx_alcs_topic_parse_pk(msg->uri, &uri_pk_len);
    uri_dn = iotx_alcs_topic_parse_dn(msg->uri, &uri_dn_len);

    if (uri_pk == NULL || uri_pk_len >= PRODUCT_KEY_MAXLEN ||
        uri_dn == NULL || uri_dn_len >= DEVICE_NAME_MAXLEN) {
        COAP_ERR("Invalid Parameter");
        return FAIL_RETURN;
    }
    memcpy(productKey, uri_pk, uri_pk_len);
    memcpy(deviceName, uri_dn, uri_dn_len);

    devKey.pk = productKey;
    devKey.dn = deviceName;

    res = alcs_sendmsg_secure(adapter->coap_ctx, &devKey, &coap_msg, 2, iotx_alcs_coap_adapter_send_msg_handle);
    alcs_msg_deinit(&coap_msg);

    if (res != COAP_SUCCESS) {
        COAP_ERR("ALCS Message Send Message Failed");
        return FAIL_RETURN;
    }

    iotx_alcs_send_msg_t *alcs_send_msg =
                (iotx_alcs_send_msg_t *)ALCS_ADAPTER_malloc(sizeof(iotx_alcs_send_msg_t));
    if (alcs_send_msg == NULL) {
        COAP_WRN("Not Enough Memory");
        return FAIL_RETURN;
    }
    memset(alcs_send_msg, 0, sizeof(iotx_alcs_send_msg_t));

    alcs_send_msg->token = (uint8_t *)ALCS_ADAPTER_malloc(coap_msg.header.tokenlen + 1);
    if (alcs_send_msg->token == NULL) {
        LITE_free(alcs_send_msg);
        COAP_WRN("Not Enough Memory");
        return FAIL_RETURN;
    }
    alcs_send_msg->token_len = coap_msg.header.tokenlen;

    memset(alcs_send_msg->token, 0, alcs_send_msg->token_len + 1);
    memcpy(alcs_send_msg->token, coap_msg.token, alcs_send_msg->token_len);

    alcs_send_msg->uri = (char *)ALCS_ADAPTER_malloc(strlen(msg->uri) + 1);
    if (alcs_send_msg->uri == NULL) {
        LITE_free(alcs_send_msg->token);
        LITE_free(alcs_send_msg);
        COAP_WRN("ALCS Message Buffer Failed");
        return FAIL_RETURN;
    }
    memset(alcs_send_msg->uri, 0, strlen(msg->uri) + 1);
    memcpy(alcs_send_msg->uri, msg->uri, strlen(msg->uri));
    INIT_LIST_HEAD(&alcs_send_msg->linked_list);

    HAL_MutexLock(adapter->mutex);
    //list_add_tail(&adapter->alcs_send_list, &alcs_send_msg->linked_list);
    list_add_tail(&alcs_send_msg->linked_list, &adapter->alcs_send_list);
    HAL_MutexUnlock(adapter->mutex);
#endif
    return SUCCESS_RETURN;
}

int iotx_alcs_send_Response(void *handle, iotx_alcs_msg_t *msg, uint8_t token_len, uint8_t *token)
{
    int res = 0;
    iotx_alcs_adapter_t *adapter = (iotx_alcs_adapter_t *)handle;
    CoAPMessage coap_msg;
    CoAPLenString coap_payload;
    CoAPLenString token_payload;
    NetworkAddr network_addr;

    POINTER_SANITY_CHECK(adapter, NULL_VALUE_ERROR);
    POINTER_SANITY_CHECK(adapter->coap_ctx, NULL_VALUE_ERROR);
    POINTER_SANITY_CHECK(msg, NULL_VALUE_ERROR);
    POINTER_SANITY_CHECK(msg->payload, NULL_VALUE_ERROR);

    STRING_PTR_SANITY_CHECK(msg->ip, FAIL_RETURN);
    STRING_PTR_SANITY_CHECK(msg->uri, FAIL_RETURN);
    if (token_len == 0 || token == NULL) {
        return FAIL_RETURN;
    }


    if (strlen(msg->ip) > NETWORK_ADDR_LEN) {
        COAP_ERR("Invalid Ip Address Length");
        return FAIL_RETURN;
    }

    memset(&coap_msg, 0, sizeof(CoAPMessage));
    memset(&coap_payload, 0, sizeof(CoAPLenString));
    memset(&token_payload, 0, sizeof(CoAPLenString));

    coap_payload.len = msg->payload_len;
    coap_payload.data = msg->payload;

    alcs_msg_init(adapter->coap_ctx, &coap_msg, msg->msg_code, msg->msg_type, 0, &coap_payload, (void *)adapter);

    res = alcs_msg_setAddr(&coap_msg, msg->uri, NULL);
    if (res != COAP_SUCCESS) {
        COAP_ERR("ALCS Message Set URI Failed");
        return FAIL_RETURN;
    }

    memset(&network_addr, 0, sizeof(NetworkAddr));
    memcpy(network_addr.addr, msg->ip, strlen(msg->ip));
    network_addr.port = msg->port;

    token_payload.len = token_len;
    token_payload.data = token;

    //Get Product Key And Device Name
    AlcsDeviceKey devKey;
    char productKey[PRODUCT_KEY_MAXLEN] = {0};
    char deviceName[DEVICE_NAME_MAXLEN] = {0};
    char *uri_pk = NULL;
    char *uri_dn = NULL;
    uint16_t uri_pk_len = 0;
    uint16_t uri_dn_len = 0;

    memset(&devKey, 0, sizeof(AlcsDeviceKey));
    memcpy(&devKey.addr, &network_addr, sizeof(NetworkAddr));

    uri_pk = iotx_alcs_topic_parse_pk(msg->uri, &uri_pk_len);
    uri_dn = iotx_alcs_topic_parse_dn(msg->uri, &uri_dn_len);

    if (uri_pk == NULL || uri_pk_len >= PRODUCT_KEY_MAXLEN ||
        uri_dn == NULL || uri_dn_len >= DEVICE_NAME_MAXLEN) {
        COAP_ERR("Invalid Parameter");
        return FAIL_RETURN;
    }
    memcpy(productKey, uri_pk, uri_pk_len);
    memcpy(deviceName, uri_dn, uri_dn_len);

    devKey.pk = productKey;
    devKey.dn = deviceName;


    if (alcs_resource_need_auth(adapter->coap_ctx, msg->uri)) {
        res = alcs_sendrsp_secure(adapter->coap_ctx, &devKey, &coap_msg, 0, 0, &token_payload);
    } else {
#ifdef ALCS_SERVER_ENABLED
        extern const char DM_URI_DEV_CORE_SERVICE_DEV[];
        if (strcmp(msg->uri, DM_URI_DEV_CORE_SERVICE_DEV) == 0) {
            char ck[PK_DN_CHECKSUM_LEN] = {0};
            char path[100] = {0};
            HAL_GetProductKey(productKey);
            HAL_GetDeviceName(deviceName);
            snprintf (path, sizeof(path), "%s%s", productKey, deviceName);
            CoAPPathMD5_sum (path, strlen(path), ck, PK_DN_CHECKSUM_LEN);
            struct list_head* sessions1 = get_svr_session_list();
            session_item* node1 = get_session_by_checksum (sessions1, &network_addr, ck);
            if (node1 && node1->sessionId) {
                node1->heart_time = HAL_UptimeMs();
                COAP_INFO("%s, %p", path, node1);
            }
        }
#endif
        res = alcs_sendrsp(adapter->coap_ctx, &network_addr, &coap_msg, 0, 0, &token_payload);
    }

    alcs_msg_deinit(&coap_msg);

    if (res != COAP_SUCCESS) {
        COAP_ERR("ALCS Message Send Failed %d", res);
        return FAIL_RETURN;
    }

    return SUCCESS_RETURN;
}

int iotx_alcs_register_resource(void *handle, iotx_alcs_res_t *resource)
{
    int res = 0;
    iotx_alcs_adapter_t *adapter = (iotx_alcs_adapter_t *)handle;
    char productKey[PRODUCT_KEY_MAXLEN] = {0};
    char deviceName[DEVICE_NAME_MAXLEN] = {0};
    char *uri_pk = NULL;
    char *uri_dn = NULL;
    uint16_t uri_pk_len = 0;
    uint16_t uri_dn_len = 0;

    POINTER_SANITY_CHECK(adapter, NULL_VALUE_ERROR);
    POINTER_SANITY_CHECK(adapter->coap_ctx, NULL_VALUE_ERROR);

    STRING_PTR_SANITY_CHECK(resource->uri, FAIL_RETURN);

    uri_pk = iotx_alcs_topic_parse_pk(resource->uri, &uri_pk_len);
    uri_dn = iotx_alcs_topic_parse_dn(resource->uri, &uri_dn_len);

    if (uri_pk == NULL || uri_pk_len >= PRODUCT_KEY_MAXLEN ||
        uri_dn == NULL || uri_dn_len >= DEVICE_NAME_MAXLEN) {
        COAP_ERR("Invalid Parameter");
        return FAIL_RETURN;
    }
    memcpy(productKey, uri_pk, uri_pk_len);
    memcpy(deviceName, uri_dn, uri_dn_len);

    COAP_INFO("alcs register resource, uri:%s", resource->uri);
    int needAuth = resource->need_auth; // strcmp (resource->uri, "/dev/core/service/dev");

    res = alcs_resource_register(adapter->coap_ctx,
                                 productKey,
                                 deviceName,
                                 resource->uri,
                                 resource->msg_perm,
                                 resource->msg_ct,
                                 resource->maxage,
                                 needAuth,
                                 (void (*)(CoAPContext * context, const char *paths, NetworkAddr * remote,
                                           CoAPMessage * message))resource->callback);

    if (res != COAP_SUCCESS) {
        COAP_ERR("ALCS Register Resource Failed, Code: %d", res);
        return FAIL_RETURN;
    }

    return SUCCESS_RETURN;
}

int iotx_alcs_observe_notify(void *handle, const char *uri, uint32_t payload_len, uint8_t *payload)
{
    int res = 0;
    iotx_alcs_adapter_t *adapter = (iotx_alcs_adapter_t *)handle;
    CoAPLenString coap_payload;

    coap_payload.len = (int32_t)payload_len;
    coap_payload.data = payload;

    res = alcs_observe_notify(adapter->coap_ctx, uri, &coap_payload);
    if (res != COAP_SUCCESS) {
        COAP_ERR("ALCS Observe Notify Failed, Code: %d", res);
        return FAIL_RETURN;
    }

    return SUCCESS_RETURN;
}


#ifdef DEVICE_MODEL_GATEWAY 
int iotx_alcs_unregister_resource(void* handle, const char *uri)
{
    iotx_alcs_adapter_t *adapter = (iotx_alcs_adapter_t *)handle;
    alcs_resource_unregister_secure(adapter->coap_ctx, uri);
    return SUCCESS_RETURN;
}

int iotx_alcs_add_sub_device(void *handle, const char *pk, const char *dn)
{
    if (handle == NULL || pk == NULL || strlen(pk) >= PRODUCT_KEY_MAXLEN ||
        dn == NULL || strlen(dn) >= DEVICE_NAME_MAXLEN) {
        COAP_ERR("Invalid Argument");
        return FAIL_RETURN;
    }

    int res = 0;
    iotx_alcs_adapter_t *adapter = (iotx_alcs_adapter_t *)handle;
    iotx_alcs_subdev_item_t *subdev_item = NULL;

    if (adapter->coap_ctx != NULL) {
        alcs_auth_subdev_init(adapter->coap_ctx, pk, dn);
    }

    //Search Subdev In Linked List
    HAL_MutexLock(adapter->mutex);
    res = _iotx_alcs_subdev_list_search(pk, dn, &subdev_item);
    if (res == SUCCESS_RETURN) {
        COAP_INFO("This Product Key And Device Name Have Been Added");
        HAL_MutexUnlock(adapter->mutex);
        return SUCCESS_RETURN;
    }
    HAL_MutexUnlock(adapter->mutex);

    //Insert New Subdev Into Linked List
    subdev_item = (iotx_alcs_subdev_item_t *)ALCS_ADAPTER_malloc(sizeof(iotx_alcs_subdev_item_t));
    if (subdev_item == NULL) {
        COAP_ERR("No Enough Memory");
        return FAIL_RETURN;
    }
    memset(subdev_item, 0, sizeof(iotx_alcs_subdev_item_t));

    //Set Product Key And Device Name
    memcpy(subdev_item->product_key, pk, strlen(pk));
    memcpy(subdev_item->device_name, dn, strlen(dn));
    subdev_item->stage = IOTX_ALCS_SUBDEV_DISCONNCET_CLOUD;
    subdev_item->retry_ms = HAL_UptimeMs();
    INIT_LIST_HEAD(&subdev_item->linked_list);

    HAL_MutexLock(adapter->mutex);
    list_add_tail(&subdev_item->linked_list, &adapter->alcs_subdev_list);
    // COAP_INFO("point=%x",&subdev_item);
    HAL_MutexUnlock(adapter->mutex);

    alcs_localsetup_add_sub_device(adapter, subdev_item->product_key, subdev_item->device_name);

    //Get Prefix And Secret From KV
    char prefix[ALCS_MQTT_PREFIX_MAX_LEN] = {0};
    char secret[ALCS_MQTT_SECRET_MAX_LEN] = {0};

    res = alcs_mqtt_prefix_secret_load(pk, strlen(pk), dn, strlen(dn), prefix, secret);
    if (res == SUCCESS_RETURN) {
        memcpy(subdev_item->prefix, prefix, strlen(prefix));
        memcpy(subdev_item->secret, secret, strlen(secret));
        // COAP_INFO("prefix=%s",prefix);
        alcs_mqtt_add_srv_key(prefix, secret);
    }

    //Get Prefix And Secret From Cloud
    alcs_mqtt_subdev_prefix_get(pk, dn);
    return SUCCESS_RETURN;
}

int iotx_alcs_remove_sub_device(void *handle, const char *pk, const char *dn)
{
    if (handle == NULL || pk == NULL || strlen(pk) >= PRODUCT_KEY_MAXLEN ||
        dn == NULL || strlen(dn) >= DEVICE_NAME_MAXLEN) {
        COAP_ERR("Invalid Parameter");
        return FAIL_RETURN;
    }

    int res = 0;
    res = iotx_alcs_subdev_remove(pk, dn);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }
    alcs_resource_unregister(handle, pk, dn);
    //Remove Subdev Item From KV
    alcs_mqtt_prefix_secret_del(pk, strlen(pk), dn, strlen(dn));
    return SUCCESS_RETURN;
}
#endif

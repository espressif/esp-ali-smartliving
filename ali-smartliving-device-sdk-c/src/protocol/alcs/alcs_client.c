/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */



#include "alcs_api_internal.h"
#include "json_parser.h"
#include "CoAPPlatform.h"
#include "utils_hmac.h"
#include "CoAPResource.h"

#ifdef ALCS_CLIENT_ENABLED
static int default_heart_interval = 30000;

int do_auth (CoAPContext *ctx, NetworkAddr* addr, ctl_key_item* ctl_item, void *userdata, AuthHandler handler);
bool res_parse (const char* payload, int len, int* seq, ResponseMsg* res_msg, char** data, int* datalen)
{
    if (!payload || !len || !seq || !res_msg || !data) {
        return 0;
    }

    COAP_DEBUG ("payload:%.*s", len, payload);

    int tmplen;
    char* tmp;

    tmp = json_get_value_by_name((char*)payload, len, "id", &tmplen, NULL);
    if (!tmp) {
        return 0;
    }

    char back;
    backup_json_str_last_char (tmp, tmplen, back);
    *seq = atoi (tmp);
    restore_json_str_last_char (tmp, tmplen, back);

    tmp = json_get_value_by_name((char*)payload, len, "code", &tmplen, NULL);
    if (!tmp) {
        return 0;
    }

    backup_json_str_last_char (tmp, tmplen, back);
    res_msg->code = atoi (tmp);
    restore_json_str_last_char (tmp, tmplen, back);

    tmp = json_get_value_by_name((char*)payload, len, "msg", &tmplen, NULL);
    if (tmp && tmplen) {
        res_msg->msg = (char*)coap_malloc (tmplen);
        memcpy (res_msg->msg, tmp, tmplen);
    } else {
        res_msg->msg = NULL;
    }

    *data = json_get_value_by_name((char*)payload, len, "data", datalen, NULL);
    return 1;
}

static int CoAPServerPath_2_option(char *uri, CoAPMessage *message)
{
    char *ptr     = NULL;
    char *pstr    = NULL;
    char  path[COAP_MSG_MAX_PATH_LEN]  = {0};

    if (NULL == uri || NULL == message) {
        COAP_ERR("Invalid paramter p_path %p, p_message %p", uri, message);
        return COAP_ERROR_INVALID_PARAM;
    }
    if (256 < strlen(uri)) {
        COAP_ERR("The uri length is too long,len = %d", (int)strlen(uri));
        return COAP_ERROR_INVALID_LENGTH;
    }
    COAP_DEBUG("The uri is %s", uri);
    ptr = pstr = uri;
    while ('\0' != *ptr) {
        if ('/' == *ptr) {
            if (ptr != pstr) {
                memset(path, 0x00, sizeof(path));
                strncpy(path, pstr, ptr - pstr);
                COAP_DEBUG("path: %s,len=%d", path, (int)(ptr - pstr));
                CoAPStrOption_add(message, COAP_OPTION_URI_PATH,
                                  (unsigned char *)path, (int)strlen(path));
            }
            pstr = ptr + 1;

        }
        if ('\0' == *(ptr + 1) && '\0' != *pstr) {
            memset(path, 0x00, sizeof(path));
            strncpy(path, pstr, sizeof(path) - 1);
            COAP_DEBUG("path: %s,len=%d", path, (int)strlen(path));
            CoAPStrOption_add(message, COAP_OPTION_URI_PATH,
                              (unsigned char *)path, (int)strlen(path));
        }
        ptr ++;
    }
    return COAP_SUCCESS;
}

void  auth_cb(CoAPContext *ctx, CoAPReqResult result, void *userdata, NetworkAddr *remote, CoAPMessage *message)
{
    AlcsDeviceKey devKey;
    COAP_DEBUG("recv auth_cb response message");

    AuthParam* auth_param = (AuthParam*)userdata;
    memset(&devKey, 0x00, sizeof(AlcsDeviceKey));
    memcpy (&devKey.addr, remote, sizeof(NetworkAddr));
    devKey.pk = auth_param->productKey;
    devKey.dn = auth_param->deviceName;
    session_item* session = get_ctl_session (ctx, &devKey);

    if (!session) {
        COAP_INFO ("receive unknown auth_cb response, pk:%s, dn:%s", devKey.pk, devKey.dn);
        ResponseMsg msg = {-1, "no session found!"};
        auth_param->handler (ctx, remote, auth_param->user_data, &msg);
    } else if (COAP_RECV_RESP_TIMEOUT == result){
        COAP_ERR("response time!");
        ResponseMsg msg = {-1, "response time!"};
        auth_param->handler (ctx, remote, auth_param->user_data, &msg);
        remove_session (ctx, session);
    } else {
        int seq, datalen;
        ResponseMsg msg;
        char* data;

        res_parse ((const char *)message->payload, message->payloadlen, &seq, &msg, &data, &datalen);
        if (msg.code == 200) {
            do {
                int tmplen;
                char* tmp;

                tmp = json_get_value_by_name(data, datalen, "sessionId", &tmplen, NULL);
                if (!tmp) {
                    msg.code = -1;
                    msg.msg = "sessionid = NULL!";
                    COAP_ERR ("sessionid = NULL!");
                    auth_param->handler (ctx, remote, auth_param->user_data, &msg);
                    break;
                }
                char back;
                backup_json_str_last_char (tmp, tmplen, back);
                session->sessionId = atoi (tmp);
                restore_json_str_last_char (tmp, tmplen, back);
                COAP_INFO ("sessionId:%d", session->sessionId);

                tmp = json_get_value_by_name(data, datalen, "randomKey", &tmplen, NULL);
                if (!tmp) {
                    msg.code = -1;
                    msg.msg = "randomKey = NULL!";
                    COAP_ERR ("randomKey = NULL!");
                    auth_param->handler (ctx, remote, auth_param->user_data, &msg);
                    break;
                }

                char buf[32];
                snprintf (buf, sizeof(buf), "%s%.*s", session->randomKey, tmplen, tmp);
                utils_hmac_sha1_raw (buf,strlen(buf), session->sessionKey, auth_param->accessToken, strlen(auth_param->accessToken));
                session->authed_time = HAL_UptimeMs ();
                session->heart_time = session->authed_time;
                session->interval = default_heart_interval;
                COAP_INFO("sessionKey is created");
            } while (0);
        } else {
            remove_session (ctx, session);
            COAP_ERR("message code :%d", msg.code);
        }
        auth_param->handler (ctx, remote, auth_param->user_data, &msg);
    }

    coap_free (auth_param->productKey);
    coap_free (auth_param->deviceName);
    coap_free (auth_param->accessToken);
    coap_free (auth_param);
}

#define auth_payload_format "{\"version\":\"1.0\",\"method\":\"core/service/auth\",\"id\":%d,\"params\":{\"prodKey\":\"%s\", \"deviceName\":\"%s\",\"encrypt\":\"payload\",\"randomKey\":\"%s\",\"sign\":\"%s\",\"accessKey\":\"%s\"}}"

int do_auth (CoAPContext *ctx, NetworkAddr* addr, ctl_key_item* ctl_item, void *user_data, AuthHandler handler)
{
    int ret = COAP_SUCCESS;
    AlcsDeviceKey devKey;
    device_auth_list* dev = get_device (ctx);
    if (!dev) {
        return COAP_ERROR_INVALID_PARAM;
    }

    memset(&devKey, 0x00, sizeof(AlcsDeviceKey));
    memcpy (&devKey.addr, addr, sizeof(NetworkAddr));
    devKey.pk = ctl_item->productKey;
    devKey.dn = ctl_item->deviceName;

    session_item* session = get_ctl_session (ctx, &devKey);
    if (session) {
        if (session->sessionId) {
            COAP_INFO ("no need to reauth!");
            ResponseMsg res = {COAP_SUCCESS, NULL};
            handler (ctx, addr, user_data, &res);
            return COAP_SUCCESS;
        } else {
           COAP_INFO ("is authing, no need to reauth!");
           return ALCS_ERR_AUTH_AUTHING;
        }
    }

    //create&save session item
    {
        session = (session_item*)coap_malloc(sizeof(session_item));
        memset (session, 0, sizeof(session_item));

        char path[100] = {0};
        strncpy(path, ctl_item->productKey, sizeof(path) - 1);
        strncat(path, ctl_item->deviceName, sizeof(path)-strlen(path)-1);
        CoAPPathMD5_sum (path, strlen(path), session->pk_dn, PK_DN_CHECKSUM_LEN);
        COAP_INFO ("pk:%s, dn:%s, checksum:%s", devKey.pk, devKey.dn, session->pk_dn);
        memcpy (&session->addr, addr, sizeof(NetworkAddr));
        gen_random_key((unsigned char *)session->randomKey, RANDOMKEY_LEN);

        struct list_head* ctl_head = get_ctl_session_list (ctx);
        list_add_tail(&session->lst, ctl_head);
    }

    char sign[64]={0};
    int sign_len = sizeof(sign);
    utils_hmac_sha1_base64(session->randomKey, RANDOMKEY_LEN, ctl_item->accessToken,
        strlen(ctl_item->accessToken), sign, &sign_len);
    COAP_INFO ("calc randomKey:%s,token:%s,sign:%.*s", session->randomKey, ctl_item->accessToken, sign_len, sign);

    char payloadbuf[512];
    sprintf (payloadbuf, auth_payload_format, ++dev->seq, ctl_item->productKey, ctl_item->deviceName, session->randomKey, sign, ctl_item->accessKey);
    COAP_INFO("payload:%s", payloadbuf);

    CoAPLenString payload;
    payload.data = (unsigned char *)payloadbuf;
    payload.len = strlen(payloadbuf);
    CoAPMessage message;
    alcs_msg_init (ctx, &message, COAP_MSG_CODE_GET, COAP_MESSAGE_TYPE_CON, 0, &payload, NULL);

    char path[120];
    sprintf (path, "/dev/%s/%s/core/service/auth", ctl_item->productKey, ctl_item->deviceName);
    CoAPServerPath_2_option (path, &message);

    AuthParam* authParam = (AuthParam*) coap_malloc (sizeof(AuthParam));
    authParam->handler = handler;
    authParam->user_data = user_data;
    authParam->productKey = (char*) coap_malloc (strlen(ctl_item->productKey) + 1);
    strcpy (authParam->productKey, ctl_item->productKey);
    authParam->deviceName = (char*) coap_malloc (strlen(ctl_item->deviceName) + 1);
    strcpy (authParam->deviceName, ctl_item->deviceName);
    authParam->accessToken = (char*) coap_malloc (strlen(ctl_item->accessToken) + 1);
    strcpy (authParam->accessToken, ctl_item->accessToken);
    message.user = authParam;
    message.handler = auth_cb;

    ret = CoAPMessage_send (ctx, addr, &message);
    CoAPMessage_destory(&message);

    return ret;
}

void alcs_auth_has_key (CoAPContext *ctx, NetworkAddr* addr, AuthParam* auth_param)
{
    ctl_key_item item;
    item.accessKey = auth_param->accessKey;
    item.deviceName = auth_param->deviceName;
    item.productKey = auth_param->productKey;
    item.accessToken = auth_param->accessToken;//(char*) coap_malloc (strlen(auth_param->accessToken) + 1);
    //strcpy (item.accessToken, auth_param->accessToken);
    do_auth (ctx, addr, &item, auth_param->user_data, auth_param->handler);
}

bool alcs_device_online (CoAPContext *ctx, AlcsDeviceKey* devKey)
{
    session_item* session = get_ctl_session (ctx, devKey);
    return session && session->sessionId? 1 : 0;
}

void heart_beat_cb(CoAPContext *ctx, CoAPReqResult result, void *userdata, NetworkAddr *remote, CoAPMessage *message)
{
    COAP_DEBUG ("heart_beat_cb, message addr:%p, networkaddr:%p!", message, remote);

    struct list_head* ctl_head = get_ctl_session_list (ctx);
    if (!ctl_head || list_empty(ctl_head)) {
        return;
    }

    if (result == COAP_RECV_RESP_TIMEOUT) {
        COAP_ERR ("heart beat timeout");
        session_item *node = NULL, *next = NULL;
        list_for_each_entry_safe(node, next, ctl_head, lst, session_item) {
            if (node->sessionId && is_networkadd_same(&node->addr, remote)) {
                remove_session (ctx, node);
            }
        }
    } else {
        session_item *node = NULL, *next = NULL;
        list_for_each_entry_safe(node, next, ctl_head, lst, session_item) {

            if(node->sessionId && is_networkadd_same(&node->addr, remote)) {
                unsigned int sessionId = 0;
                CoAPUintOption_get (message, COAP_OPTION_SESSIONID, &sessionId);

                if (node->sessionId != sessionId) {
                    COAP_INFO ("receive stale heart beat response");
                    remove_session (ctx, node);
                } else {
                    node->heart_time = HAL_UptimeMs();
                }
            }
        }
    }
}

void on_client_auth_timer (CoAPContext* ctx)
{
    struct list_head* ctl_head = get_ctl_session_list (ctx);
    if (!ctl_head || list_empty(ctl_head)) {
        return;
    }
    COAP_DEBUG ("on_client_auth_timer:%d", (int)HAL_UptimeMs());

    device_auth_list* dev = get_device (ctx);
    char payloadbuf[64];
    sprintf (payloadbuf, "{\"id\":%d,\"version\":\"1.0\",\"params\":{\"delayTime\":%d}}", ++dev->seq, 5000);

    CoAPLenString payload;
    payload.data = (unsigned char *)payloadbuf;
    payload.len = strlen(payloadbuf);
    int tick = HAL_UptimeMs();

    session_item *node = NULL, *next = NULL;
    list_for_each_entry_safe(node, next, ctl_head, lst, session_item) {
        if (!node->sessionId) {
            continue;
        }

        if(node->heart_time + node->interval > tick) {
            CoAPMessage message;
            alcs_msg_init (ctx, &message, COAP_MSG_CODE_GET, COAP_MESSAGE_TYPE_CON, 0, &payload, NULL);
            CoAPServerPath_2_option ("/dev/core/service/heartBeat", &message);
            message.handler = heart_beat_cb;
            CoAPMessage_send (ctx, &node->addr, &message);
            COAP_DEBUG ("send heartbeat to :%s", node->addr.addr);
            CoAPMessage_destory(&message);
        }
    }
}

#endif



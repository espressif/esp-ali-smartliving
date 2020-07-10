/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <string.h>
#include "CoAPExport.h"
#include "CoAPSerialize.h"
#include "CoAPDeserialize.h"
#include "CoAPResource.h"
#include "CoAPObserve.h"
#include "iot_import.h"
#include "CoAPPlatform.h"
#include "CoAPInternal.h"
#include "lite-list.h"

//#define DEBUG_OPEN_COAP_MSG_LOG

#define COAPAckMsg(header) \
    ((header.code == COAP_MSG_CODE_EMPTY_MESSAGE) \
     &&(header.type == COAP_MESSAGE_TYPE_ACK))

#define CoAPRespMsg(header)\
    ((header.code >= 0x40) && (header.code < 0xc0))

#define CoAPPingMsg(header)\
    ((header.code == COAP_MSG_CODE_EMPTY_MESSAGE)\
     && (header.type == COAP_MESSAGE_TYPE_CON))

#define CoAPResetMsg(header)\
    (header.type == COAP_MESSAGE_TYPE_RST)

#define CoAPCONRespMsg(header)\
    ((header.code == COAP_MSG_CODE_205_CONTENT) \
     && (header.type == COAP_MESSAGE_TYPE_CON))

#define CoAPReqMsg(header)\
    ((1 <= header.code) && (32 > header.code))

#define CoAPConMsg(header) (header.type == COAP_MESSAGE_TYPE_CON)
#define CoAPNonMsg(header) (header.type == COAP_MESSAGE_TYPE_NON)

#define NOKEEP 0
#define KEEPING 1

#define COAP_MAX_MESSAGE_ID     65535
#define COAP_MAX_RETRY_COUNT    4
#define COAP_ACK_TIMEOUT        600
#define COAP_ACK_RANDOM_FACTOR  1

int CoAPMessage_print_sendlist(CoAPContext *context);

int CoAPOption_sort(CoAPMessage *message)
{
    int opt_count = message->optcount;
    CoAPMsgOption *options = message->options;
    CoAPMsgOption temp;
    int i, j;

    if (opt_count <= 1) {
        return COAP_SUCCESS;
    }

    for (i = 1; i < opt_count; i++) {
        if (options[i].num < options[i-1].num) {
            memcpy((void *)&temp, (void *)&options[i], sizeof(CoAPMsgOption));
            for (j = i - 1; j >= 0 && options[j].num > temp.num; j--) {
                memcpy((void *)&options[j + 1], (void *)&options[j], sizeof(CoAPMsgOption));
            }
            memcpy((void *)&options[j + 1], (void *)&temp, sizeof(CoAPMsgOption));
        }
    }

    return COAP_SUCCESS;
}

int CoAPStrOption_add(CoAPMessage *message, unsigned short optnum, unsigned char *data, unsigned short datalen)
{
    unsigned char *ptr = NULL;
    if (COAP_MSG_MAX_OPTION_NUM <= message->optcount) {
        return COAP_ERROR_INVALID_PARAM;
    }

    /* coap options will be sorted in coap send message */
    message->options[message->optcount].num = optnum;
    message->options[message->optcount].len = datalen;
    
    if (datalen) {
        ptr = (unsigned char *)coap_malloc(datalen);
        if (NULL == ptr) {
            return COAP_ERROR_MALLOC;
        }
        memcpy(ptr, data, datalen);
    }
    message->options[message->optcount].val = ptr;
    message->optcount ++;

    return COAP_SUCCESS;

}

int CoAPStrOption_get(CoAPMessage *message, unsigned short optnum, unsigned char *data, unsigned short *datalen)
{
    unsigned char index = 0;

    for (index = 0; index < message->optcount; index++) {
        if (message->options[index].num == optnum) {
            if (*datalen >= message->options[index].len) {
                memcpy(data, message->options[index].val, message->options[index].len);
                *datalen = message->options[index].len;
                return COAP_SUCCESS;
            } else {
                return COAP_ERROR_INVALID_LENGTH;
            }
        }
    }

    return COAP_ERROR_NOT_FOUND;

}


int CoAPUintOption_add(CoAPMessage *message, unsigned short  optnum, unsigned int data)
{
    unsigned char buf[4];
    unsigned short datalen = 0;
    
    if (data & 0xFFFF0000) {
        datalen = 4;
        buf[0] = (unsigned char)((data & 0xFF000000) >> 24);
        buf[1] = (unsigned char)((data & 0x00FF0000) >> 16);
        buf[2] = (unsigned char)((data & 0x0000FF00) >> 8);
        buf[3] = (unsigned char)(data & 0x000000FF);
    } else if (data & 0x0000FF00) {
        datalen = 2;
        buf[0] = (unsigned char)((data & 0xFF00) >> 8);
        buf[1] = (unsigned char)(data & 0x00FF);
    } else if (data) {
        data = 1;
        buf[0] = (unsigned char)data;
    }
    
    return CoAPStrOption_add (message, optnum, buf, datalen);
}

int CoAPUintOption_get(CoAPMessage *message,
                       unsigned short  optnum,
                       unsigned int *data)
{

    unsigned char index = 0;

    for (index = 0; index < message->optcount; index++) {
        if (message->options[index].num == optnum) {
            int byte = 0;
            switch (message->options[index].len) {
                case 1:
                    *data |= message->options[index].val[byte++];
                    break;
                case 2:
                    *data |= (message->options[index].val[byte++] << 8);
                    *data |= message->options[index].val[byte++];
                    break;
                case 3:
                    *data |= (message->options[index].val[byte++] << 16);
                    *data |= (message->options[index].val[byte++] << 8);
                    *data |= message->options[index].val[byte++];
                    break;
                case 4:
                    *data |= (message->options[index].val[byte++] << 24);
                    *data |= (message->options[index].val[byte++] << 16);
                    *data |= (message->options[index].val[byte++] << 8);
                    *data |= message->options[index].val[byte++];
                    break;
                default:
                    *data = 0;
                    break;
            }
            return COAP_SUCCESS;
        }
    }

    return COAP_ERROR_NOT_FOUND;
}


int CoAPOption_present(CoAPMessage *message, unsigned short option)
{
    unsigned char index = 0;


    for (index = 0; index < message->optcount; index++) {
        if (message->options[index].num == option) {
            return COAP_SUCCESS;
        }
    }
    return COAP_ERROR_NOT_FOUND;
}

unsigned short CoAPMessageId_gen(CoAPContext *context)
{
    unsigned short msg_id = 0;
    if (!context) {
        return msg_id;
    }
    CoAPIntContext *ctx = (CoAPIntContext *)context;
    HAL_MutexLock(ctx->mutex);
    msg_id = ((COAP_MAX_MESSAGE_ID == ctx->message_id)  ? (ctx->message_id = 1) : ctx->message_id++);
    HAL_MutexUnlock(ctx->mutex);
    return msg_id;
}


int CoAPMessageId_set(CoAPMessage *message, unsigned short msgid)
{
    if (NULL == message) {
        return COAP_ERROR_NULL;
    }
    message->header.msgid = msgid;
    return COAP_SUCCESS;
}

int CoAPMessageType_set(CoAPMessage *message, unsigned char type)
{
    if (NULL == message) {
        return COAP_ERROR_NULL;
    }
    if (COAP_MESSAGE_TYPE_NON > type || COAP_MESSAGE_TYPE_RST < type) {
        return COAP_ERROR_INVALID_PARAM;
    }

    message->header.type = type;
    return COAP_SUCCESS;
}

int CoAPMessageCode_set(CoAPMessage *message, CoAPMessageCode code)
{
    if (NULL == message) {
        return COAP_ERROR_NULL;
    }
    message->header.code  = code;
    return COAP_SUCCESS;
}

int CoAPMessageCode_get(CoAPMessage *message, CoAPMessageCode *code)
{
    if (NULL == message || NULL == code) {
        return COAP_ERROR_NULL;
    }
    *code = message->header.code;
    return COAP_SUCCESS;
}

int CoAPMessageToken_set(CoAPMessage *message, unsigned char *token,
                         unsigned char tokenlen)
{
    if (NULL == message || NULL == token) {
        return COAP_ERROR_NULL;
    }
    if (COAP_MSG_MAX_TOKEN_LEN < tokenlen) {
        return COAP_ERROR_INVALID_LENGTH;
    }
    memcpy(message->token, token, tokenlen);
    message->header.tokenlen = tokenlen;

    return COAP_SUCCESS;
}

int CoAPMessageUserData_set(CoAPMessage *message, void *userdata)
{
    if (NULL == message || NULL == userdata) {
        return COAP_ERROR_NULL;
    }
    message->user = userdata;
    return COAP_SUCCESS;
}

int CoAPMessageKeep_Set(CoAPMessage *message, int keep)
{
    if (NULL == message || keep < 0) {
        return COAP_ERROR_NULL;
    }
    message->keep = keep;
    return COAP_SUCCESS;
}

int CoAPMessagePayload_set(CoAPMessage *message, unsigned char *payload,
                           unsigned short payloadlen)
{
    if (NULL == message || (0 < payloadlen && NULL == payload)) {
        return COAP_ERROR_NULL;
    }
    message->payload = payload;
    message->payloadlen = payloadlen;

    return COAP_SUCCESS;
}

int CoAPMessageHandler_set(CoAPMessage *message, CoAPSendMsgHandler handler)
{
    if (NULL == message) {
        return COAP_ERROR_NULL;
    }
    message->handler = handler;
    return COAP_SUCCESS;
}

int CoAPMessage_init(CoAPMessage *message)
{
    int count = 0;

    if (NULL == message) {
        return COAP_ERROR_NULL;
    }
    memset(message, 0x00, sizeof(CoAPMessage));
    message->header.version    = COAP_CUR_VERSION;
    message->header.type       = COAP_MESSAGE_TYPE_ACK;
    message->header.code       = COAP_MSG_CODE_EMPTY_MESSAGE;
    message->keep              = NOKEEP;
    return COAP_SUCCESS;
}

int CoAPMessage_destory(CoAPMessage *message)
{
    int count = 0;
    if (NULL == message) {
        return COAP_ERROR_NULL;
    }

    for (count = 0; count < COAP_MSG_MAX_OPTION_NUM; count++) {
        if (NULL != message->options[count].val) {
            coap_free(message->options[count].val);
            message->options[count].val = NULL;
        }
    }

    return COAP_SUCCESS;
}

int CoAPMessageCheckDup(CoAPMessage *message, CoAPPreventDuplicate* preventDup)
{
    unsigned char checksum[16];
    int i;

    if (message == NULL || preventDup == NULL) {
        return 0;
    }
    uint64_t tick = HAL_UptimeMs ();
    if (tick > preventDup->last_tick + 60000) {
        memset (preventDup, 0, sizeof(CoAPPreventDuplicate));
        preventDup->last_tick = tick;
    }
    
    utils_md5 ((unsigned char*)&message->header, sizeof(CoAPMsgHeader), checksum);
    
    for (i = 0; i < DUP_CHECKSUM_COUNT; ++i) {
        if (memcmp(preventDup->checksum_list + i * DUP_CHECKSUM_LEN, checksum, DUP_CHECKSUM_LEN) == 0){
            COAP_DEBUG("receive repeat data");
            return 1;
        }
    }
    
    memcpy (preventDup->checksum_list + preventDup->write_index * DUP_CHECKSUM_LEN, checksum, DUP_CHECKSUM_LEN);
    preventDup->write_index = (preventDup->write_index + 1) % DUP_CHECKSUM_COUNT;
    return 0;
}

static int CoAPMessageList_add(CoAPContext *context, NetworkAddr *remote,
                               CoAPMessage *message, unsigned char *buffer, int len)
{
    CoAPIntContext *ctx = (CoAPIntContext *)context;
    CoAPSendNode *node = NULL;
    CoAPSendNode *next = NULL;
    int no_response = 0;
    int keep = NOKEEP;
   
    if(COAP_SUCCESS == CoAPOption_present(message, COAP_OPTION_NO_RESPONSE)){
       no_response = 1;
    }
    if (no_response && CoAPNonMsg(message->header)) {
        COAP_DEBUG("The message %d don't add to list", message->header.msgid);
        return COAP_ERROR_NULL;
    }
   
    HAL_MutexLock(ctx->sendlist.list_mutex);
    list_for_each_entry_safe(node, next, &ctx->sendlist.list, sendlist, CoAPSendNode) {
        if (NULL != node && node->keep == KEEPING){
            if (node->header.msgid == message->header.msgid) {
                COAP_INFO("message already present!");
                HAL_MutexUnlock(ctx->sendlist.list_mutex);
                return COAP_SUCCESS;
            }
        }
    }
    HAL_MutexUnlock(ctx->sendlist.list_mutex);

    if(platform_is_multicast((const char *)remote->addr) || 1 == message->keep){
        keep = KEEPING;
    }
   
    node = coap_malloc(sizeof(CoAPSendNode));
    if (NULL != node) {
        memset(node, 0x00, sizeof(CoAPSendNode));
        node->acked        = 0;
        node->user         = message->user;
        node->header       = message->header;
        node->handler      = message->handler;
        node->msglen       = len;
        node->message      = buffer;
        node->timeout_val   = COAP_ACK_TIMEOUT * COAP_ACK_RANDOM_FACTOR;
        node->no_response = no_response;
        node->keep = keep;
        memcpy(&node->remote, remote, sizeof(NetworkAddr));
        memcpy(node->token, message->token, message->header.tokenlen);

        uint64_t tick = HAL_UptimeMs ();
        if (CoAPConMsg(message->header)) {
            node->timeout = node->timeout_val + tick;
            node->retrans_count = COAP_MAX_RETRY_COUNT;
        } else {
            node->timeout = node->timeout_val * 4 + tick;
            node->retrans_count = 0;
        }

        if(keep == KEEPING){
            COAP_DEBUG("The message %d need keep", message->header.msgid);
        }

        HAL_MutexLock(ctx->sendlist.list_mutex);
        if (ctx->sendlist.count >= ctx->sendlist.maxcount) {
            HAL_MutexUnlock(ctx->sendlist.list_mutex);
            coap_free(node);
            COAP_INFO("The send list is full");
            return COAP_ERROR_DATA_SIZE;
        } else {
            list_add_tail(&node->sendlist, &ctx->sendlist.list);
            ctx->sendlist.count ++;
            HAL_MutexUnlock(ctx->sendlist.list_mutex);
            return COAP_SUCCESS;
        }
    } else {
        return COAP_ERROR_NULL;
    }
}

void CoAPMessageToken_dump(unsigned char *token, unsigned char tokenlen)
{
    int index = 0, count = 0;
    int total = 2 * COAP_MSG_MAX_TOKEN_LEN;
    char   buff[2 * COAP_MSG_MAX_TOKEN_LEN + 1] = {0}, *ptr = NULL;

    ptr = buff;
    for (index = 0; index < tokenlen; index++) {
        count = HAL_Snprintf(ptr, total, "%02X", token[index]);
        ptr += count;
        total -= count;
    }

    COAP_FLOW("Token Len   : %d", tokenlen);
    COAP_FLOW("Token       : %s", buff);
}

void CoAPMessage_dump(NetworkAddr *remote, CoAPMessage *message)
{
    int ret = COAP_SUCCESS;
    unsigned int ctype;
    unsigned char code, msgclass, detail;

    if (NULL == remote || NULL == message) {
        return;
    }
    code = (unsigned char)message->header.code;
    msgclass = code >> 5;
    detail = code & 0x1F;
#ifdef DEBUG_OPEN_COAP_MSG_LOG
    COAP_FLOW("*********Message Info**********");
    COAP_FLOW("Version     : %d", message->header.version);
    COAP_FLOW("Code        : %d.%02d(0x%x)", msgclass, detail, code);
    COAP_FLOW("Type        : 0x%x", message->header.type);
    COAP_FLOW("Msgid       : %d", message->header.msgid);
    COAP_FLOW("Option      : %d", message->optcount);
    COAP_FLOW("Payload Len : %d", message->payloadlen);
#endif
    (void)msgclass;
    (void)detail;
#ifdef DEBUG_OPEN_COAP_MSG_LOG
    CoAPMessageToken_dump(message->token, message->header.tokenlen);
    COAP_FLOW("Remote      : %s:%d", remote->addr, remote->port);
#endif
    ret = CoAPUintOption_get(message, COAP_OPTION_CONTENT_FORMAT, &ctype);
    if (COAP_SUCCESS == ret && NULL != message->payload
        && (COAP_CT_APP_OCTET_STREAM != ctype && COAP_CT_APP_CBOR != ctype)) {
        //     COAP_FLOW("Payload     : %s", message->payload);
    }
#ifdef DEBUG_OPEN_COAP_MSG_LOG
    COAP_FLOW("********************************");
#endif
}

int CoAPMessage_send(CoAPContext *context, NetworkAddr *remote, CoAPMessage *message)
{
    int   ret              = COAP_SUCCESS;
    unsigned short msglen  = 0;
    unsigned char  *buff   = NULL;
    unsigned short readlen = 0;
    CoAPIntContext *ctx    = NULL;

    if (NULL == message || NULL == context) {
        return (COAP_ERROR_INVALID_PARAM);
    }

    ctx = (CoAPIntContext *)context;
    /* sort coap options */
    CoAPOption_sort(message);

    msglen = CoAPSerialize_MessageLength(message);
    if (COAP_MSG_MAX_PDU_LEN < msglen) {
        COAP_INFO("The message length %d is too long", msglen);
        return COAP_ERROR_DATA_SIZE;
    }

    buff = (unsigned char *)coap_malloc(msglen);
    if (NULL == buff) {
        COAP_INFO("Malloc memory failed");
        return COAP_ERROR_NULL;
    }
    memset(buff, 0x00, msglen);
    msglen = CoAPSerialize_Message(message, buff, msglen);

#ifndef COAP_OBSERVE_CLIENT_DISABLE
    CoAPObsClient_delete(ctx, message);
#endif
    readlen = CoAPNetwork_write(ctx->p_network, remote,
                                buff, (unsigned int)msglen, ctx->waittime);
    if (msglen == readlen) {/*Send message success*/
        if (CoAPReqMsg(message->header) || CoAPCONRespMsg(message->header)) {
            COAP_FLOW("The message id %d len %d send success, add to the list",
                      message->header.msgid, msglen);
            ret = CoAPMessageList_add(ctx, remote, message, buff, msglen);
            if (COAP_SUCCESS != ret) {
                coap_free(buff);
                COAP_ERR("Add the message %d to list failed", message->header.msgid);
                return ret;
            }
        } else {
            coap_free(buff);
            COAP_FLOW("The message %d isn't CON msg, needless to be retransmitted",
                      message->header.msgid);
        }
    } else {
        coap_free(buff);
        COAP_ERR("CoAP transport write failed, send message %d return %d", message->header.msgid, ret);
        return COAP_ERROR_WRITE_FAILED;
    }

    CoAPMessage_dump(remote, message);
    return COAP_SUCCESS;
}

int CoAPMessage_cancel(CoAPContext *context, CoAPMessage *message)
{
    CoAPSendNode *node = NULL, *next = NULL;
    CoAPIntContext *ctx = (CoAPIntContext *)context;

    if (NULL == context || NULL == message) {
        return COAP_ERROR_NULL;
    }


    HAL_MutexLock(ctx->sendlist.list_mutex);
    list_for_each_entry_safe(node, next, &ctx->sendlist.list, sendlist, CoAPSendNode) {
        if (node->header.msgid == message->header.msgid) {
            list_del(&node->sendlist);
            ctx->sendlist.count--;
            COAP_INFO("Cancel message %d from list, cur count %d",
                      node->header.msgid, ctx->sendlist.count);
            coap_free(node->message);
            coap_free(node);
        }
    }
    HAL_MutexUnlock(ctx->sendlist.list_mutex);
    return COAP_SUCCESS;
}

int CoAPMessage_print_sendlist(CoAPContext *context)
{
#ifdef ALCS_COAP_SENDLIST_DEBUG
    CoAPSendNode *node = NULL, *next = NULL;
    CoAPIntContext *ctx = (CoAPIntContext *)context;

    if (NULL == context || NULL == ctx->sendlist.list_mutex) {
        return COAP_ERROR_NULL;
    }

    //HAL_MutexLock(ctx->sendlist.list_mutex);
    COAP_INFO("-------------------------------------");
    COAP_INFO("sendlist.count %d",ctx->sendlist.count);
    list_for_each_entry_safe(node, next, &ctx->sendlist.list, sendlist, CoAPSendNode) {
        if (NULL != node) {
            COAP_INFO("message id %d, ack:%d, keep:%d, type:%d, code:%d",
                    node->header.msgid, node->acked, node->keep,
                    node->header.type, node->header.code);
        }
    }
    COAP_INFO("-------------------------------------");
    //HAL_MutexUnlock(ctx->sendlist.list_mutex);
#endif
    return COAP_SUCCESS;
}

int CoAPMessageId_cancel(CoAPContext *context, unsigned short msgid)
{
    CoAPSendNode *node = NULL, *next = NULL;
    CoAPIntContext *ctx = (CoAPIntContext *)context;

    if (NULL == context || NULL == ctx->sendlist.list_mutex) {
        return COAP_ERROR_NULL;
    }

    HAL_MutexLock(ctx->sendlist.list_mutex);
    list_for_each_entry_safe(node, next, &ctx->sendlist.list, sendlist, CoAPSendNode) {
        if (NULL != node) {
            if (node->header.msgid == msgid) {
                list_del(&node->sendlist);
                ctx->sendlist.count--;
                COAP_FLOW("Cancel message id %d from list, cur count %d",
                          node->header.msgid, ctx->sendlist.count);
                coap_free(node->message);
                coap_free(node);
                CoAPMessage_print_sendlist(context);
            }
        }
    }
    HAL_MutexUnlock(ctx->sendlist.list_mutex);

    return COAP_SUCCESS;
}

static int CoAPAckMessage_handle(CoAPContext *context, CoAPMessage *message)
{
    CoAPSendNode *node = NULL, *next;
    CoAPIntContext *ctx = (CoAPIntContext *)context;

    HAL_MutexLock(ctx->sendlist.list_mutex);
    list_for_each_entry_safe(node, next, &ctx->sendlist.list, sendlist, CoAPSendNode) {
        if (node->header.msgid == message->header.msgid) {
            CoAPSendMsgHandler handler = node->handler;
            void *user_data = node->user;
            NetworkAddr remote = {0};
            memcpy(&remote, &node->remote, sizeof(remote));
            node->acked = 1;
            if (CoAPRespMsg(node->header)) { //CON response message
                list_del(&node->sendlist);
                coap_free(node->message);
                coap_free(node);
                ctx->sendlist.count --;
                COAP_DEBUG("The CON response message %d receive ACK, remove it, cur:%d",
                        message->header.msgid, ctx->sendlist.count);
            }
            CoAPMessage_print_sendlist(context);
            HAL_MutexUnlock(ctx->sendlist.list_mutex);
            if (handler) handler(ctx, COAP_RECV_RESP_SUC, user_data, &remote, NULL);
            return COAP_SUCCESS;
        }
    }
    HAL_MutexUnlock(ctx->sendlist.list_mutex);

    return COAP_SUCCESS;
}

static int CoAPAckMessage_send(CoAPContext *context, NetworkAddr *remote, unsigned short msgid)
{
    int ret   = COAP_SUCCESS;
    CoAPMessage message;
    CoAPIntContext *ctx = (CoAPIntContext *)context;

    CoAPMessage_init(&message);
    CoAPMessageId_set(&message, msgid);
    COAP_DEBUG("Send Ack Response Message");
    ret = CoAPMessage_send(ctx, remote, &message);
    CoAPMessage_destory(&message);
    return ret;
}

static int CoAPRestMessage_send(CoAPContext *context, NetworkAddr *remote, unsigned short msgid)
{
    int ret   = COAP_SUCCESS;
    CoAPMessage message;
    CoAPIntContext *ctx = (CoAPIntContext *)context;

    CoAPMessage_init(&message);
    CoAPMessageType_set(&message, COAP_MESSAGE_TYPE_RST);
    CoAPMessageId_set(&message, msgid);
    COAP_DEBUG("Send Rest Pong Message");
    ret = CoAPMessage_send(ctx, remote, &message);
    CoAPMessage_destory(&message);
    return ret;
}

static int CoAPErrRespMessage_send(CoAPContext *context, NetworkAddr *remote, CoAPMessage *message,
                                   unsigned char err_code)
{
    CoAPMessage response;
    int ret   = COAP_SUCCESS;
    CoAPIntContext *ctx = (CoAPIntContext *)context;

    CoAPMessage_init(&response);
    CoAPMessageCode_set(&response, err_code);
    CoAPMessageId_set(&response, message->header.msgid);
    CoAPMessageToken_set(&response, message->token, message->header.tokenlen);
    if (COAP_MESSAGE_TYPE_CON == message->header.type) {
        CoAPMessageType_set(&response, COAP_MESSAGE_TYPE_ACK);
    } else {
        CoAPMessageType_set(&response, message->header.type);
    }
    COAP_FLOW("Send Error Response Message");
    ret = CoAPMessage_send(ctx, remote, &response);
    CoAPMessage_destory(&response);
    return ret;
}

static int CoAPRespMessage_handle(CoAPContext *context, NetworkAddr *remote, CoAPMessage *message)
{
    char                found = 0;
    CoAPSendNode       *node = NULL, *next = NULL;
    CoAPIntContext     *ctx = (CoAPIntContext *)context;
    CoAPSendNode       targetNode;

    if (COAP_MESSAGE_TYPE_CON == message->header.type) {
        CoAPAckMessage_send(ctx, remote, message->header.msgid);
    }

    HAL_MutexLock(ctx->sendlist.list_mutex);
    list_for_each_entry_safe(node, next, &ctx->sendlist.list, sendlist, CoAPSendNode) {
        if (0 != node->header.tokenlen && node->header.tokenlen == message->header.tokenlen
                && 0 == memcmp(node->token, message->token, message->header.tokenlen)){
            
            found = 1;
            memcpy(&targetNode, node, sizeof(CoAPSendNode));
            CoAPMessage_print_sendlist(context);
            break;
        }
    }
    HAL_MutexUnlock(ctx->sendlist.list_mutex);
    
#ifndef COAP_OBSERVE_CLIENT_DISABLE
    CoAPObsClient_add(ctx, message, remote, found? &targetNode : NULL);
#endif

    if(found){
        message->user  = targetNode.user;

        if (COAP_MSG_CODE_400_BAD_REQUEST <= message->header.code) {
            if (NULL != ctx->notifier) {
                ctx->notifier(message->header.code, remote, message);
            }
        }

        if (NULL != targetNode.handler) {
            targetNode.handler(ctx, COAP_REQUEST_SUCCESS, targetNode.user, remote, message);
            COAP_FLOW("Call the response message callback");
        }
    }

    HAL_MutexLock(ctx->sendlist.list_mutex);
    list_for_each_entry_safe(node, next, &ctx->sendlist.list, sendlist, CoAPSendNode) {
        if (0 != node->header.tokenlen && node->header.tokenlen == message->header.tokenlen
            && 0 == memcmp(node->token, message->token, message->header.tokenlen)){
            if(node->keep == NOKEEP){
                list_del_init(&node->sendlist);
                ctx->sendlist.count--;
                if (NULL != node->message) {
                    coap_free(node->message);
                }
                coap_free(node);
                COAP_FLOW("Remove the message id %d from list", node->header.msgid);                
            }
            else{
                COAP_FLOW("Find the message id %d, It need keep", node->header.msgid);
            }
            break;
        }
    }
    HAL_MutexUnlock(ctx->sendlist.list_mutex);

    return COAP_ERROR_NOT_FOUND;
}

#define PACKET_INTERVAL_THRE_MS     1
#define PACKET_TRIGGER_NUM          100

static int CoAPRequestMessage_handle(CoAPContext *context, NetworkAddr *remote, CoAPMessage *message)
{
    int             index = 0;
    int             ret   = COAP_SUCCESS;
    CoAPResource   *resource = NULL;
    unsigned char   path[COAP_MSG_MAX_PATH_LEN] = {0};
    unsigned char  *tmp = path;
    CoAPIntContext *ctx = (CoAPIntContext *)context;
    COAP_FLOW("CoAPRequestMessage_handle: %p", ctx);

    // TODO: if need only one callback
    for (index = 0; index < message->optcount; index++) {
        if (COAP_OPTION_URI_PATH == message->options[index].num) {
            if ((COAP_MSG_MAX_PATH_LEN - 1) >= (tmp - path + message->options[index].len)) {
                *tmp = '/';
                tmp += 1;
                strncpy((char *)tmp, (const char *)message->options[index].val, message->options[index].len);
                tmp += message->options[index].len;
            }
        }
    }

    COAP_DEBUG("Request path is %s", path);

    resource = CoAPResourceByPath_get(ctx, (char *)path);
    if (NULL != resource) {
        if (NULL != resource->callback) {
            if (((resource->permission) & (1 << ((message->header.code) - 1))) > 0) {
                /* Option for No Server Response, rfc7967*/
                if (CoAPConMsg(message->header)){
                        /* Send the Ack message */
                    CoAPAckMessage_send(ctx, remote, message->header.msgid);
                }
                resource->callback(ctx, (char *)path, remote, message);
            } else {
                COAP_FLOW("The resource %s isn't allowed", resource->path);
                ret = CoAPErrRespMessage_send(ctx, remote, message, COAP_MSG_CODE_405_METHOD_NOT_ALLOWED);
            }
        } else {
            COAP_FLOW("The resource %s handler isn't exist", resource->path);
            ret = CoAPErrRespMessage_send(ctx, remote, message, COAP_MSG_CODE_405_METHOD_NOT_ALLOWED);
        }
    } else {
        COAP_FLOW("The resource %s isn't found", path);
        ret = CoAPErrRespMessage_send(ctx, remote, message, COAP_MSG_CODE_404_NOT_FOUND);
    }

    return ret;
}


static void CoAPMessage_handle(CoAPContext *context,
                               NetworkAddr       *remote,
                               unsigned char     *buf,
                               unsigned short     datalen)
{
    int                 ret  = COAP_SUCCESS;
    CoAPMessage         message;
    CoAPIntContext     *ctx = (CoAPIntContext *)context;

    COAP_FLOW("CoAPMessage_handle: %p", ctx);
    memset(&message, 0x00, sizeof(CoAPMessage));

    ret = CoAPDeserialize_Message(&message, buf, datalen);
    if (COAP_SUCCESS != ret) {
        if (NULL != ctx->notifier) {
            /* TODO: */
            /* context->notifier(context, event); */
        }
    }

    message.timestamp = HAL_UptimeMs();
#ifdef DEBUG_OPEN_COAP_MSG_LOG
    COAP_FLOW("--------Receive a Message------");
#endif
    CoAPMessage_dump(remote, &message);

    if (COAPAckMsg(message.header) || CoAPResetMsg(message.header)) {
        // TODO: implement handle client observe

        // TODO: if need call response callback
        CoAPAckMessage_handle(ctx, &message);

    } else if (CoAPRespMsg(message.header)) {
        CoAPRespMessage_handle(ctx, remote, &message);
    } else if (CoAPPingMsg(message.header)) {
        CoAPRestMessage_send(ctx, remote, message.header.msgid);
    } else if (CoAPReqMsg(message.header)) {
        CoAPRequestMessage_handle(ctx, remote, &message);
    } else {
        COAP_INFO("Weird packet,drop it");
    }

}

int CoAPMessage_process(CoAPContext *context, unsigned int timeout)
{
    int len = 0;
    NetworkAddr remote;
    char ip_addr[17] = {0};
    CoAPIntContext *ctx = (CoAPIntContext *)context;

    if (NULL == context) {
        return COAP_ERROR_NULL;
    }

    HAL_Wifi_Get_IP(ip_addr, NULL);

    //while (1) {
        memset(&remote, 0x00, sizeof(NetworkAddr));
        memset(ctx->recvbuf, 0x00, COAP_MSG_MAX_PDU_LEN);
        len = CoAPNetwork_read(ctx->p_network,
                               &remote,
                               ctx->recvbuf,
                               COAP_MSG_MAX_PDU_LEN, timeout);
        if (strlen(ip_addr) > 0 && strncmp((const char *)ip_addr, (const char *)remote.addr, sizeof(ip_addr)) == 0) /* drop the packet from itself*/
            return 0;
        if (len > 0) {
            CoAPMessage_handle(ctx, &remote, ctx->recvbuf, len);
        } else {
            return len;
        }
    //}
    return 0;
}



static void Check_timeout (void *context)
{
    //COAP_DEBUG("enter Check_timeout");
    CoAPIntContext *ctx = (CoAPIntContext *)context;
    CoAPSendNode *node = NULL, *next = NULL, *timeout_node = NULL;
    uint64_t tick = HAL_UptimeMs ();
    do {
        timeout_node = NULL;
        HAL_MutexLock(ctx->sendlist.list_mutex);
        list_for_each_entry_safe(node, next, &ctx->sendlist.list, sendlist, CoAPSendNode) {

            if (node->keep != NOKEEP) {
                continue;
            }
            if ((node->retrans_count > 0) || (node->timeout >= tick)) {
                continue;
            }

            /*Remove the node from the list*/
            list_del_init(&node->sendlist);
            ctx->sendlist.count--;
            COAP_INFO("Retransmit timeout,remove the message id %d count %d",
                              node->header.msgid, ctx->sendlist.count);
            CoAPMessage_print_sendlist(context);
            #ifndef COAP_OBSERVE_SERVER_DISABLE
                CoapObsServerAll_delete(ctx, &node->remote);
            #endif
            timeout_node = node;
            break;
        }
        HAL_MutexUnlock(ctx->sendlist.list_mutex);

        if (timeout_node) {
            if(NULL != timeout_node->handler){
                timeout_node->handler(ctx, COAP_RECV_RESP_TIMEOUT, timeout_node->user, &timeout_node->remote, NULL);
            }
            coap_free(timeout_node->message);
            coap_free(timeout_node);
        }
    } while (timeout_node);
}

static void Retansmit (void *context)
{
    //COAP_DEBUG("enter Retansmit");
    CoAPIntContext *ctx = (CoAPIntContext *)context;
    CoAPSendNode *node = NULL, *next = NULL;
    unsigned int ret = 0;

    uint64_t tick = HAL_UptimeMs (); 
    HAL_MutexLock(ctx->sendlist.list_mutex);
    list_for_each_entry_safe(node, next, &ctx->sendlist.list, sendlist, CoAPSendNode) {
        if (NULL == node || node->timeout > tick ) {
            continue;
        }    

        if (node->retrans_count > 0) {
            /*If has received ack message, don't resend the message*/
            if(0 == node->acked){
                COAP_DEBUG("Retansmit the message id %d len %d", node->header.msgid, node->msglen);
                ret = CoAPNetwork_write(ctx->p_network, &node->remote, node->message, node->msglen, ctx->waittime);
                if (ret != COAP_SUCCESS) {
                }    
            }
            node->timeout_val = node->timeout_val * 3 / 2;
            -- node->retrans_count;
            if (node->retrans_count == 0) {
                node->timeout = tick + COAP_ACK_TIMEOUT;
            } else {
                node->timeout = tick + node->timeout_val;
            }

            COAP_FLOW("node->timeout_val = %d , node->timeout=%d ,tick=%d", node->timeout_val,node->timeout,tick);
            CoAPMessage_print_sendlist(context);
        }
    }
    HAL_MutexUnlock(ctx->sendlist.list_mutex);
}

extern void *coap_yield_mutex;

int CoAPMessage_cycle(CoAPContext *context)
{
   // unsigned int ret = 0;
    int res = 0;

    CoAPIntContext *ctx = (CoAPIntContext *)context;

    if (NULL == context) {
        return COAP_ERROR_NULL;
    }

    if (coap_yield_mutex != NULL) {
        HAL_MutexLock(coap_yield_mutex);
    }


    res = CoAPMessage_process(ctx, ctx->waittime);
    Retansmit (ctx);
    Check_timeout (ctx);
    // ret = CoAPMessage_retransmit(ctx);

    if (coap_yield_mutex != NULL) {
        HAL_MutexUnlock(coap_yield_mutex);
    }

    if (res < 0) {
        HAL_SleepMs(20);
    }

    return res;
}


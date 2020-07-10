/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifndef __ALCS_API_INTERNAL_H__
#define __ALCS_API_INTERNAL_H__
#include "CoAPExport.h"
#include "CoAPMessage.h"
#include "alcs_api.h"
#include "lite-list.h"

#define KEY_MAXCOUNT 10
#define RANDOMKEY_LEN 16
#define KEYSEQ_LEN 3
#define COAP_OPTION_SESSIONID 71
#define COAP_OPTION_SEQID 72
#define COAP_OPTION_GROUPID 73
#define SEQ_WINDOW_SIZE 8

#define Group_Sign_len 4
#define Group_Seq_len 4
#define Group_AK_LEN 13
#define Group_MIN_ID_len 4
#define Group_MAX_ID_len 19
#define MAXNUM_CHECKSUM 15
#define GROUP_CHECKSNUM_LEN 4

#ifdef ALCS_CLIENT_ENABLED
typedef struct {
    char             *accessKey;
    char             *accessToken;
    char             *deviceName;
    char             *productKey;
    struct list_head  lst;
} ctl_key_item;
#endif

#ifdef ALCS_SERVER_ENABLED

typedef struct {
    char              keyprefix[KEYPREFIX_LEN + 1];
    char             *secret;
    ServerKeyPriority priority;
} svr_key_info;

typedef struct {
    svr_key_info keyInfo;
    struct list_head  lst;
} svr_key_item;

typedef struct {
    int tag;
    char* groupId;
    char *revocation;
    svr_key_info keyInfo;
    CoAPPreventDuplicate   preventDup;
    struct list_head  lst;
} svr_group_item;
#endif

typedef struct {
    char *id;
    char *accessKey;
    char *accessToken;
    struct list_head  lst;
} ctl_group_item;

#define PK_DN_CHECKSUM_LEN 6
#define ALCS_OPT_HEART_V1 0x1
#define ALCS_OPT_SUPPORT_SEQWINDOWS 0x2
#define ALCS_OPT_PAYLOAD_CHECKSUM 0x4
#define SESSIONKEYLEN 20

typedef struct
{
    char seqMap[(SEQ_WINDOW_SIZE + 7) / 8];
    unsigned short mapPos;
} seq_window_item;

typedef struct {
    int sessionId;
    char randomKey[RANDOMKEY_LEN + 1];
    char sessionKey[32];
    char pk_dn[PK_DN_CHECKSUM_LEN];
    int  seqStart;
    seq_window_item* seqWindow;
    int authed_time;
    int data_rec_time;
    int heart_time;
    int interval;
    NetworkAddr addr;
    int opt;
    struct list_head  lst;
} session_item;

#define GROUPKEYLEN 20
typedef struct
{
    unsigned char  token[COAP_MSG_MAX_TOKEN_LEN];
    int sessionId;
    char isGroup;
    char observe;
    uint64_t recTime;
    NetworkAddr addr;
    struct list_head  lst;
    int opt;
    char groupKey[1];
} request_item;

#define ROLE_SERVER 2
#define ROLE_CLIENT 1

typedef struct {
    CoAPContext *context;
    int seq;

    void                    *list_mutex;
#ifdef ALCS_CLIENT_ENABLED
    struct list_head         lst_ctl;
    unsigned char            ctl_count;
#endif
#ifdef ALCS_SERVER_ENABLED
    struct list_head         lst_svr;
    unsigned char            svr_count;
    char                    *revocation;
#endif
#ifdef ALCS_GROUP_COMM_ENABLE
    struct list_head         lst_svr_group;
    int                      svr_group_count;
#endif

#ifdef ALCS_SERVER_ENABLED
    struct list_head lst_svr_sessions;
#endif
#ifdef ALCS_CLIENT_ENABLED
    struct list_head lst_ctl_sessions;
#endif
    struct list_head lst_requests;

    char role;
} device_auth_list;

extern device_auth_list _device;
#define get_device() (&_device)

#ifdef ALCS_SERVER_ENABLED
    #define get_svr_session_list() (_device.role&ROLE_SERVER? &_device.lst_svr_sessions : NULL)
#endif
#ifdef ALCS_CLIENT_ENABLED
    #define get_ctl_session_list() (_device.role&ROLE_CLIENT? &_device.lst_ctl_sessions : NULL)
#endif

void remove_session_safe (CoAPContext *ctx, struct list_head* sessions, AlcsDeviceKey* devKey);
void remove_session(CoAPContext *ctx, session_item *session);
void add_request_to_list (request_item *requst);
void remove_request (request_item *requst);

#ifdef ALCS_CLIENT_ENABLED
    session_item *get_ctl_session(CoAPContext *ctx, AlcsDeviceKey *key);
#endif

#ifdef ALCS_SERVER_ENABLED
unsigned int get_message_sessionid (CoAPMessage *message, int opt, char checksum[4]);
void add_message_sessionid(CoAPMessage *message, int sessionid, int opt, CoAPLenString* payload);
int seqwindow_accept (CoAPMessage *message, session_item* session);

session_item *get_svr_session(AlcsDeviceKey *key);
session_item *get_session_by_checksum(struct list_head *sessions, NetworkAddr *addr, char ck[PK_DN_CHECKSUM_LEN]);
unsigned int get_message_group_info (CoAPMessage *message, int* seq, char ak[], char group_id[]);
void add_message_group_info (CoAPMessage *message, int seq, char ak[], char group_id[]);

#define MAX_PATH_CHECKSUM_LEN (5)


typedef struct {
    char              path[MAX_PATH_CHECKSUM_LEN];
    char              pk_dn[PK_DN_CHECKSUM_LEN];
    char              *filter_path;
    path_type_t       path_type;
    CoAPRecvMsgHandler cb;
    struct list_head   lst;
} secure_resource_cb_item;

extern struct list_head secure_resource_cb_head;
#endif

int alcs_encrypt(const char *src, int len, const char *key, void *out);
int alcs_decrypt(const char *src, int len, const char *key, void *out);
int observe_data_encrypt(CoAPContext *ctx, const char *paths, NetworkAddr *addr,
                         CoAPMessage *message, CoAPLenString *src, CoAPLenString *dest);

bool is_networkadd_same(NetworkAddr *addr1, NetworkAddr *addr2);
void gen_random_key(unsigned char random[], int len);
bool req_payload_parser(const char *payload, int len, char **seq, int *seqlen, char **data, int *datalen);
int internal_secure_send(CoAPContext *ctx, session_item *session, NetworkAddr *addr,
                         CoAPMessage *message);

int alcs_resource_register_secure(CoAPContext *context, const char *pk, const char *dn, const char *path,
                                  unsigned short permission,
                                  unsigned int ctype, unsigned int maxage, CoAPRecvMsgHandler callback);
#ifdef DEVICE_MODEL_GATEWAY 
int alcs_resource_unregister_secure(CoAPContext *context, const char *path);
#endif
void alcs_resource_cb_deinit(void);
void alcs_auth_list_deinit(void);

#endif

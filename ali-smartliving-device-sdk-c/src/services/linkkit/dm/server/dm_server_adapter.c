#ifdef ALCS_ENABLED
#include "iotx_dm_internal.h"

#include "CoAPServer.h"
#include "dm_msg_process.h"

#define ALCS_NOTIFY_PORT     (5683)
#define ALCS_NOTIFY_HOST     "255.255.255.255"
#define ALCS_NOTIFY_METHOD   "core.service.dev.notify"

const char DM_URI_DEV_CORE_SERVICE_DEV_NOTIFY[] DM_READ_ONLY = "/dev/core/service/dev/notify";

extern const char DM_MSG_REQUEST[]; 

static dm_server_ctx_t g_dm_server_ctx = {0};

static dm_server_ctx_t *dm_server_get_ctx(void)
{
    return &g_dm_server_ctx;
}

static int _dm_server_dev_notify(void *handle)
{
    int ret, i;
    char * data = NULL;
    char * payload = NULL;
    int data_len = 0;
    int payload_len = 0;
    NetworkAddr notify_sa;
    CoAPContext  *g_coap_ctx = CoAPServer_init();    

    dm_msg_dev_core_service_dev(&data, &data_len);

    payload_len = strlen(DM_MSG_REQUEST) + 10 + strlen(DM_MSG_VERSION) + data_len + strlen(
                              ALCS_NOTIFY_METHOD) + 1;

    payload = DM_malloc(payload_len);
    if (payload == NULL) {
        DM_free(data);
        return DM_MEMORY_NOT_ENOUGH;
    }
    memset(payload, 0, payload_len);
    HAL_Snprintf(payload, payload_len, DM_MSG_REQUEST, iotx_report_id(),
                 DM_MSG_VERSION, data_len, data, ALCS_NOTIFY_METHOD);
    
    memset(&notify_sa, 0, sizeof(notify_sa));
    memcpy(notify_sa.addr, ALCS_NOTIFY_HOST, strlen(ALCS_NOTIFY_HOST));
    notify_sa.port = ALCS_NOTIFY_PORT;

    dm_log_info("notify path:%s; payload = %s", DM_URI_DEV_CORE_SERVICE_DEV_NOTIFY, payload);
    
    for (i = 0; i < 2; i++) {
        ret = CoAPServerMultiCast_send(g_coap_ctx, &notify_sa, DM_URI_DEV_CORE_SERVICE_DEV_NOTIFY, (uint8_t *)payload,
                                    (uint16_t)payload_len, NULL, NULL);
    }
    DM_free(payload);
    DM_free(data);
    return ret;
}

int dm_server_open(void)
{
    dm_server_ctx_t *ctx = dm_server_get_ctx();
    iotx_alcs_param_t alcs_param;
    iotx_alcs_event_handle_t event_handle;

    memset(&alcs_param, 0x0, sizeof(iotx_alcs_param_t));
    memset(&event_handle, 0x0, sizeof(iotx_alcs_event_handle_t));

    alcs_param.group = (char *)DM_SERVER_ALCS_ADDR;
    alcs_param.port = DM_SERVER_ALCS_PORT;
    alcs_param.send_maxcount = DM_SERVER_ALCS_SEND_MAXCOUNT;
    alcs_param.waittime = DM_SERVER_ALCS_WAITTIME;
    alcs_param.obs_maxcount = DM_SERVER_ALCS_OBS_MAXCOUNT;
    alcs_param.res_maxcount = DM_SERVER_ALCS_RES_MAXCOUNT;
    alcs_param.role = IOTX_ALCS_ROLE_CLIENT | IOTX_ALCS_ROLE_SERVER;
    event_handle.h_fp = dm_server_alcs_event_handler;
    event_handle.pcontext = NULL;

    alcs_param.handle_event = &event_handle;

    ctx->conn_handle  = iotx_alcs_construct(&alcs_param);
    if (ctx->conn_handle == NULL) {
        return FAIL_RETURN;
    }
    _dm_server_dev_notify(ctx->conn_handle);

    return SUCCESS_RETURN;
}

int dm_server_connect(void)
{

    dm_server_ctx_t *ctx = dm_server_get_ctx();

    return iotx_alcs_cloud_init(ctx->conn_handle);
}

int dm_server_close(void)
{
    dm_server_ctx_t *ctx = dm_server_get_ctx();

    return iotx_alcs_destroy(&ctx->conn_handle);
}

int dm_server_send(char *uri, unsigned char *payload, int payload_len, void *context)
{
    int res = 0;
    dm_server_ctx_t *ctx = dm_server_get_ctx();
    iotx_alcs_msg_t alcs_msg;
    dm_server_alcs_context_t *alcs_context = (dm_server_alcs_context_t *)context;

    memset(&alcs_msg, 0, sizeof(iotx_alcs_msg_t));

    alcs_msg.group_id = 0;
    alcs_msg.ip = alcs_context ? alcs_context->ip : NULL;
    alcs_msg.port = alcs_context ? alcs_context->port : 0;
    alcs_msg.msg_code = (alcs_context && alcs_context->token_len
                         && alcs_context->token) ? ITOX_ALCS_COAP_MSG_CODE_205_CONTENT : ITOX_ALCS_COAP_MSG_CODE_GET;
    if (strstr(uri, DM_URI_DEV_CORE_SERVICE_DEV) == NULL)
        alcs_msg.msg_type = IOTX_ALCS_MESSAGE_TYPE_CON;
    else
        alcs_msg.msg_type = IOTX_ALCS_MESSAGE_TYPE_NON;
    alcs_msg.uri = uri;
    alcs_msg.payload = payload;
    alcs_msg.payload_len = payload_len;

    if (alcs_context == NULL) {
        res = iotx_alcs_observe_notify(ctx->conn_handle, alcs_msg.uri, alcs_msg.payload_len, alcs_msg.payload);
        dm_log_info("Send Observe Notify Result %d", res);
    } else if (alcs_context->ip && alcs_context->port && NULL == alcs_context->token) {
        res = iotx_alcs_send(ctx->conn_handle, &alcs_msg);
        dm_log_info("Send Result %d", res);
    } else if (alcs_context->ip && alcs_context->port && alcs_context->token_len && alcs_context->token) {
        res = iotx_alcs_send_Response(ctx->conn_handle, &alcs_msg, (uint8_t)alcs_context->token_len,
                                      (uint8_t *)alcs_context->token);
        dm_log_info("Send Response Result %d", res);
    }

    return res;
}

int dm_server_subscribe(char *uri, CoAPRecvMsgHandler callback, int auth_type)
{
    int res = 0;
    dm_server_ctx_t *ctx = dm_server_get_ctx();
    iotx_alcs_res_t alcs_res;

    memset(&alcs_res, 0, sizeof(iotx_alcs_res_t));

    alcs_res.uri = uri;
    alcs_res.msg_ct = IOTX_ALCS_MESSAGE_CT_APP_JSON;
    alcs_res.msg_perm = IOTX_ALCS_MESSAGE_PERM_GET;
    alcs_res.maxage = 60;
    alcs_res.need_auth = auth_type;
    alcs_res.callback = callback;

    res = iotx_alcs_register_resource(ctx->conn_handle, &alcs_res);

    dm_log_info("Register Resource Result: %d", res);

    return res;
}
#ifdef DEVICE_MODEL_GATEWAY 
int dm_server_unsubscribe(const char *uri)
{
    dm_server_ctx_t *ctx = dm_server_get_ctx();
    iotx_alcs_unregister_resource(ctx->conn_handle, uri);
    return 0;
}
#endif
int dm_server_add_device(char product_key[PRODUCT_KEY_MAXLEN], char device_name[DEVICE_NAME_MAXLEN])
{
    int res = 0;
#ifdef DEVICE_MODEL_GATEWAY 
    dm_server_ctx_t *ctx = dm_server_get_ctx();

    res = iotx_alcs_add_sub_device(ctx->conn_handle, (const char *)product_key, (const char *)device_name);
    dm_log_info("Add Device Result: %d, Product Key: %s, Device Name: %s", res, product_key, device_name);
#endif
    return res;
}

int dm_server_del_device(char product_key[PRODUCT_KEY_MAXLEN], char device_name[DEVICE_NAME_MAXLEN])
{
    int res = 0;
#ifdef DEVICE_MODEL_GATEWAY 
    dm_server_ctx_t *ctx = dm_server_get_ctx();

    res = iotx_alcs_remove_sub_device(ctx->conn_handle, (const char *)product_key, (const char *)device_name);
    dm_log_info("Del Device Result: %d, Product Key: %s, Device Name: %s", res, product_key, device_name);
#endif
    return res;
}

int dm_server_yield(void)
{
    dm_server_ctx_t *ctx = dm_server_get_ctx();

    return iotx_alcs_yield(ctx->conn_handle);
}
#endif

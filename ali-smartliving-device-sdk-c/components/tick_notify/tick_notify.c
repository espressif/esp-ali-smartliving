#ifdef ALCS_ENABLED
#include "cJSON.h"
#include "iot_import.h"
#include "CoAPExport.h"
#include "CoAPServer.h"
#include "iotx_alcs.h"
#include "alcs_api_internal.h"
#include "iotx_log.h"

#define TICK_NOTIFY_ADDR    "255.255.255.255"
#define TICK_NOTIFY_PORT  (5683)
#define TICK_NOTIFY_INTERVAL    (1 * 60 * 1000)

#define ALCS_TICK_NOTIFY_URI    "/dev/core/service/dev/tick_notify"
#define ALCS_TICK_NOTIFY_MSG_FMT "{\"id\":0,\"version\":\"1.0\",\"params\":{\"tick\":\"%s\",\"mode\":%d,\"seqnum\":%d,\"synced\":%d}}"


#define TICK_NOTIFY_MODE_BROADCAST (1)
#define TICK_NOTIFY_MODE_REQUEST  (2)
#define TICK_NOTIFY_MODE_RESPONSE (3)
#define TICK_NOTIFY_MODE_SYNCED   (4)

#define TICK_NOTIFY_MSG_MAX_LEN (90)
#define TICK_NOTIFY_MAX_DELAY   (50)

#define TICK_NOTIFY_DEBUG_ENABLE

#ifdef TICK_NOTIFY_DEBUG_ENABLE
#define TICK_NOTIFY_DEBUG(...)   log_debug("tick_notify", __VA_ARGS__)
#define TICK_NOTIFY_INFO(...)    log_info("tick_notify", __VA_ARGS__)
#define TICK_NOTIFY_WRN(...)     log_warning("tick_notify", __VA_ARGS__)
#define TICK_NOTIFY_ERR(...)     log_err("tick_notify", __VA_ARGS__)
#else
#define TICK_NOTIFY_DEBUG(...)
#define TICK_NOTIFY_INFO(...)
#define TICK_NOTIFY_WRN(...)
#define TICK_NOTIFY_ERR(...)
#endif

typedef struct {
    void *timer;
    uint64_t tick_ms_base;//获取外部sync tick时本机的tick参考
    uint64_t tick_ms_sync;//保存获取的外部syn tick
    uint64_t tick_ms_send_request;//收到广播后对外发送的tick
    uint64_t tick_ms_recv_request;//收到外部request时本地tick
    uint64_t tick_ms_send_response;//收到request后对外发送后的本地tick
    uint64_t tick_ms_received_resp;//保存获取resp的时间
    int32_t local_seq_num;
    int32_t remote_seq_num;
    char inited;
    char is_synced;//是否同步过外部tick
    NetworkAddr remote;
    int status;
    char is_master;
    int delay;
    char tick_changing_flag;
} TickNotify_Context;

static uint64_t strtouint64(char *inputstr, uint64_t *intnum)
{
    uint64_t i = 0, res = 0;
    uint64_t val = 0;

    for (i = 0;i < 21;i++){
        if (inputstr[i] == '\0'){
            *intnum = val;
            res = SUCCESS_RETURN;
            break;
        }
        else if ((inputstr[i] >= '0') && (inputstr[i] <= '9')){
            val = val * 10 + (inputstr[i] - '0');
        }
        else{
            res = FAIL_RETURN;
            break;
        }
    }

    if (i >= 21){
        res = FAIL_RETURN;
    }

    return res;
}

static void* uint64toa(int64_t uint64num, char str[])
{
    uint64_t i = 0, res = 0;
    uint64_t val = 0;
    uint64_t temp64 = 0;
    uint8_t numlen = 0;

    temp64 = uint64num;
    do{
        str[i++] = temp64 % 10;
    }while((temp64/=10) > 0);
    numlen = i;

    temp64 = uint64num;
    str[numlen] = '\0';
    do{
        str[--numlen] = temp64 % 10 + '0';

    }while((temp64/=10) > 0);

    return SUCCESS_RETURN;
}

static TickNotify_Context g_ticknotify_ctx;

void* iotx_tick_notify_get_context()
{
    return &g_ticknotify_ctx;
}

int32_t iotx_tick_notify_new_local_seqnum()
{
    TickNotify_Context *ctx = iotx_tick_notify_get_context();

    return ++ctx->local_seq_num;
}

int iotx_get_notify_time(uint64_t *tick)
{
    TickNotify_Context *ctx = iotx_tick_notify_get_context();
    int ret = -1;

    if(ctx->inited == 0){
        return -1;
    }

    if(ctx == NULL){
        ret = -1;
    }else if(ctx->is_synced == 1){
        if(ctx->tick_changing_flag == 1){
            return -1;
        }

        *tick = ctx->tick_ms_sync + ((int)HAL_UptimeMs() - (int)ctx->tick_ms_base);
        ret = 0;
    }else if(ctx->is_synced == 0){
        *tick = HAL_UptimeMs();
        ret = -2;
    }

    return ret;
}

void iotx_tick_notify(void *ticknotify_ctx, NetworkAddr *remote, int mode, uint64_t tick, int seqnum)
{
    int res = 0;
    TickNotify_Context *tick_ctx = ticknotify_ctx;
    iotx_alcs_msg_t alcs_msg;
    char str[20] = {0};

    if(tick_ctx == NULL){
        return;
    }

    memset(&alcs_msg, 0, sizeof(iotx_alcs_msg_t));

    alcs_msg.group_id = 0;
    alcs_msg.ip = TICK_NOTIFY_ADDR;
    alcs_msg.port = TICK_NOTIFY_PORT;
    alcs_msg.msg_code = ITOX_ALCS_COAP_MSG_CODE_POST;
    alcs_msg.msg_type = IOTX_ALCS_MESSAGE_TYPE_NON;
    alcs_msg.uri = ALCS_TICK_NOTIFY_URI;

    uint64toa(tick, str);
    alcs_msg.payload = HAL_Malloc(TICK_NOTIFY_MSG_MAX_LEN);

    if(alcs_msg.payload == NULL){
        return;
    }
    memset(alcs_msg.payload, 0, TICK_NOTIFY_MSG_MAX_LEN);

    HAL_Snprintf((char *)alcs_msg.payload, TICK_NOTIFY_MSG_MAX_LEN, ALCS_TICK_NOTIFY_MSG_FMT, str, mode, seqnum, tick_ctx->is_synced);

    alcs_msg.payload_len = strlen((char *)alcs_msg.payload) + 1;

    NetworkAddr notify_sa;
    CoAPContext  *coap_ctx = CoAPServer_init();

    if(NULL == remote){
        memset(&notify_sa, 0, sizeof(notify_sa));
        memcpy(notify_sa.addr, TICK_NOTIFY_ADDR, strlen(TICK_NOTIFY_ADDR));
        notify_sa.port = TICK_NOTIFY_PORT;
    }else{
        memcpy(&notify_sa, remote, sizeof(NetworkAddr));
    }

    CoAPServerMultiCast_send(coap_ctx, &notify_sa, alcs_msg.uri, (uint8_t *)alcs_msg.payload,
                                    (uint16_t)alcs_msg.payload_len, NULL, NULL);

    if(alcs_msg.payload){
        HAL_Free(alcs_msg.payload);
    }
}

void iotx_tick_notify_timer_change(int interval)
{
    TickNotify_Context *tick_ctx = iotx_tick_notify_get_context();

    if(tick_ctx == NULL){
        return;
    }

    HAL_Timer_Stop(tick_ctx->timer);
    HAL_Timer_Start(tick_ctx->timer, interval);
}

static int random_num(void)
{
    HAL_Srandom(HAL_UptimeMs());
    return HAL_Random(0xFF)%20 + 1;
}

void iotx_tick_notify_send_broadcast()
{
    TickNotify_Context *ctx = iotx_tick_notify_get_context();
    uint64_t tick = 0;
    int32_t seqnum = 0;

    iotx_get_notify_time(&tick);
    seqnum = iotx_tick_notify_new_local_seqnum();
    iotx_tick_notify((void *)ctx, NULL, TICK_NOTIFY_MODE_BROADCAST, tick, seqnum);
}


void iotx_tick_notify_send_request()
{
    TickNotify_Context *ctx = iotx_tick_notify_get_context();
    uint64_t tick = 0;
    int32_t seqnum = 0;

    iotx_get_notify_time(&tick);
    seqnum = iotx_tick_notify_new_local_seqnum();
    iotx_tick_notify((void *)ctx, &ctx->remote, TICK_NOTIFY_MODE_REQUEST, tick, seqnum);

    ctx->tick_ms_send_request = HAL_UptimeMs();
    ctx->is_master = 0;
}

void iotx_tick_notify_send_response()
{
    TickNotify_Context *ctx = iotx_tick_notify_get_context();
    uint64_t tick = 0;

    iotx_get_notify_time(&tick);
    iotx_tick_notify((void *)ctx, &ctx->remote, TICK_NOTIFY_MODE_RESPONSE, tick, ctx->remote_seq_num);
    ctx->tick_ms_send_response = HAL_UptimeMs();
    ctx->is_master = 1;
}

void iotx_tick_notify_send_synced()
{
    TickNotify_Context *ctx = iotx_tick_notify_get_context();
    uint64_t tick = 0;

    iotx_get_notify_time(&tick);
    iotx_tick_notify((void *)ctx, &ctx->remote, TICK_NOTIFY_MODE_SYNCED, tick, ctx->remote_seq_num);
}

void tick_process_cycle(void *context)
{
    TickNotify_Context *ctx = context;

    if(ctx == NULL){
        return;
    }

    switch(ctx->status){
        case TICK_NOTIFY_MODE_BROADCAST:
            iotx_tick_notify_send_broadcast();
            iotx_tick_notify_timer_change(TICK_NOTIFY_INTERVAL + ctx->delay * 1000);
        break;
        case TICK_NOTIFY_MODE_REQUEST:
            iotx_tick_notify_send_request();
            iotx_tick_notify_timer_change(TICK_NOTIFY_INTERVAL * 2 + ctx->delay * 1000);
            ctx->status = TICK_NOTIFY_MODE_BROADCAST;
        break;
        case TICK_NOTIFY_MODE_SYNCED:
            iotx_tick_notify_send_synced();
            iotx_tick_notify_timer_change(TICK_NOTIFY_INTERVAL * 2 + ctx->delay * 1000);
            ctx->status = TICK_NOTIFY_MODE_BROADCAST;
        default:
        break;
    }
}

void iotx_tick_notify_msg_handle(CoAPContext *context, const char *paths, NetworkAddr *remote,
        CoAPMessage *message)
{
    int res = 0;
    TickNotify_Context *ctx = iotx_tick_notify_get_context();
    cJSON *json_item_JSON = NULL;
    cJSON *json_param = NULL;
    cJSON *json_tick = NULL;
    cJSON *json_mode = NULL;
    cJSON *json_seq = NULL;
    cJSON *json_synced = NULL;
    uint64_t pasttime = 0;

    json_item_JSON = cJSON_Parse((const char *)message->payload);

    if (json_item_JSON == NULL) {
        return;
    }

    if (!cJSON_IsObject(json_item_JSON)){
        goto func_exit;
    }

    json_param = cJSON_GetObjectItem(json_item_JSON, "params");
    if (json_param == NULL) {
        goto func_exit;
    }

    json_tick = cJSON_GetObjectItem(json_param, "tick");
    if (json_tick == NULL || !cJSON_IsString(json_tick)) {
        goto func_exit;
    }

    json_mode = cJSON_GetObjectItem(json_param, "mode");
    if (json_mode == NULL || !cJSON_IsNumber(json_mode)) {
        goto func_exit;
    }

    json_seq = cJSON_GetObjectItem(json_param, "seqnum");
    if (json_seq == NULL || !cJSON_IsNumber(json_seq)) {
        goto func_exit;
    }

    json_synced = cJSON_GetObjectItem(json_param, "synced");
    if (json_synced == NULL || !cJSON_IsNumber(json_synced)) {
        goto func_exit;
    }

    switch(json_mode->valueint){
        /* received broadcast */
        case TICK_NOTIFY_MODE_BROADCAST:
            TICK_NOTIFY_INFO("received broadcast.");
            if(json_synced->valueint == 1){
                //ctx->remote_seq_num = json_seq->valueint;
                memcpy(&ctx->remote, remote, sizeof(NetworkAddr));
                ctx->status = TICK_NOTIFY_MODE_REQUEST;
                iotx_tick_notify_timer_change(random_num() * 1000);
                TICK_NOTIFY_INFO("ready to send request.");
            }else if(json_synced->valueint == 0 && ctx->is_synced == 0){
                //ctx->remote_seq_num = json_seq->valueint;
                memcpy(&ctx->remote, remote, sizeof(NetworkAddr));
                ctx->status = TICK_NOTIFY_MODE_REQUEST;
                iotx_tick_notify_timer_change(10000 + random_num() * 1000);
                TICK_NOTIFY_INFO("ready to send request.");
            }else if(json_synced->valueint == 0 && ctx->is_synced == 1 && ctx->is_master == 1){
                ctx->status = TICK_NOTIFY_MODE_BROADCAST;
                iotx_tick_notify_timer_change(2000);
                TICK_NOTIFY_INFO("ready to send broadcast.");
            }
        break;

        /* received request*/
        case TICK_NOTIFY_MODE_REQUEST:
            ctx->remote_seq_num = json_seq->valueint;
			memcpy(&ctx->remote, remote, sizeof(NetworkAddr));
            iotx_tick_notify_send_response();
        break;

        /* received response */     
        case TICK_NOTIFY_MODE_RESPONSE: 
		    if(json_seq->valueint == ctx->local_seq_num && !memcmp(remote, &ctx->remote, sizeof(NetworkAddr))){
	            ctx->tick_ms_received_resp = message->timestamp;
	            ctx->delay = ((int)ctx->tick_ms_received_resp - (int)ctx->tick_ms_send_request)/2;

				if(ctx->delay > TICK_NOTIFY_MAX_DELAY){
                    HAL_Printf("tick_notify:discard tick delay %d\n", ctx->delay);
                    ctx->delay = TICK_NOTIFY_MAX_DELAY;
					break;
				}

                ctx->tick_changing_flag = 1;
                ctx->tick_ms_base = ctx->tick_ms_received_resp;
                strtouint64(json_tick->valuestring, &(ctx->tick_ms_sync));
                ctx->tick_ms_sync = ctx->tick_ms_sync + ctx->delay + ((int)HAL_UptimeMs() - (int)ctx->tick_ms_base);
                ctx->is_synced = 1;
                ctx->tick_changing_flag = 0;

                if(json_synced->valueint == 0){
                    ctx->status = TICK_NOTIFY_MODE_SYNCED;
                    iotx_tick_notify_timer_change(random_num() * 1000);
                }else{
                    iotx_tick_notify_timer_change(TICK_NOTIFY_INTERVAL * 2 + ctx->delay * 1000);
                }

                HAL_Printf("tick_notify: tick synced, delay is %d\n", ctx->delay);
			}
        break;

        case TICK_NOTIFY_MODE_SYNCED:
            if(json_synced->valueint == 1){
                ctx->is_synced = 1;
            }
        break;

        default:
            HAL_Printf("mode not support");
        break;
    }

func_exit:
    cJSON_Delete(json_item_JSON);
}

void iotx_tick_notify_register_resource()
{
    iotx_alcs_res_t alcs_res;
    CoAPContext  *coap_ctx = CoAPServer_init();
    int res = 0;

    memset(&alcs_res, 0, sizeof(iotx_alcs_res_t));

    alcs_res.uri = ALCS_TICK_NOTIFY_URI;
    alcs_res.msg_ct = IOTX_ALCS_MESSAGE_CT_APP_JSON;
    alcs_res.msg_perm = IOTX_ALCS_MESSAGE_PERM_POST;
    alcs_res.maxage = 60;
    alcs_res.need_auth = 0;
    alcs_res.callback = iotx_tick_notify_msg_handle;

    alcs_resource_register(coap_ctx,
                                 NULL,
                                 NULL,
                                 alcs_res.uri,
                                 alcs_res.msg_perm,
                                 alcs_res.msg_ct,
                                 alcs_res.maxage,
                                 alcs_res.need_auth,
                                 alcs_res.callback);
}

void iotx_tick_get_register_resource()
{
    iotx_alcs_res_t alcs_res;
    CoAPContext  *coap_ctx = CoAPServer_init();
    int res = 0;

    memset(&alcs_res, 0, sizeof(iotx_alcs_res_t));

    alcs_res.uri = ALCS_TICK_NOTIFY_URI;
    alcs_res.msg_ct = IOTX_ALCS_MESSAGE_CT_APP_JSON;
    alcs_res.msg_perm = IOTX_ALCS_MESSAGE_PERM_GET;
    alcs_res.maxage = 60;
    alcs_res.need_auth = 0;
    alcs_res.callback = iotx_tick_notify_msg_handle;

    alcs_resource_register(coap_ctx,
                                 NULL,
                                 NULL,
                                 alcs_res.uri,
                                 alcs_res.msg_perm,
                                 alcs_res.msg_ct,
                                 alcs_res.maxage,
                                 alcs_res.need_auth,
                                 alcs_res.callback);
}

void *iotx_tick_notify_init()
{
    if(g_ticknotify_ctx.inited == 1){
        return &g_ticknotify_ctx;
    }
    memset(&g_ticknotify_ctx,0,sizeof(TickNotify_Context));

    g_ticknotify_ctx.timer = HAL_Timer_Create("tick_notify", tick_process_cycle, &g_ticknotify_ctx);
    g_ticknotify_ctx.status = TICK_NOTIFY_MODE_BROADCAST;
    iotx_tick_notify_register_resource();
    iotx_tick_get_register_resource();
    iotx_tick_notify_send_broadcast();
    iotx_tick_notify_timer_change(TICK_NOTIFY_INTERVAL + random_num() * 1000);

    g_ticknotify_ctx.inited = 1;
    return &g_ticknotify_ctx;
}

int iotx_tick_notify_deinit()
{
    if(g_ticknotify_ctx.timer){
        HAL_Timer_Stop(g_ticknotify_ctx.timer);
        HAL_Timer_Delete(g_ticknotify_ctx.timer);
    }

    memset(&g_ticknotify_ctx,0,sizeof(TickNotify_Context));

    return 0;
}
#endif
#ifdef MQTT_COMM_ENABLED

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include "iot_import.h"
#include "iot_export.h"

#include "iotx_utils.h"
#include "iotx_log.h"
#include "string_utils.h"
#include "iotx_mqtt_config.h"
#include "iotx_system_internal.h"

static int redirect_region_retry_cnt = 0;

//#define REDIRECT_DEBUG
//#define REDIRECT_DEBUG_TOPIC

#define TOPIC_LENGTH (128)
#define DATA_LENGTH (48)
#define REDIRECT_IOT_ID_LEN (128)
#define REDIRECT_IOT_TOKEN_LEN (64)
#define REDIRECT_MAX_RETRY_CNT (3)

#ifdef REDIRECT_DEBUG_TOPIC
#define REDIRECT_SUB_TOPIC "/%s/%s/user/thing/bootstrap/config/push"
#define REDIRECT_PUB_TOPIC "/%s/%s/user/thing/bootstrap/config/push_reply"
#define RECONNECT_SUB_TOPIC "/%s/%s/user/thing/bootstrap/notify"
#define RECONNECT_PUB_TOPIC "/%s/%s/user/thing/bootstrap/notify_reply"
#else
#define REDIRECT_SUB_TOPIC "/sys/%s/%s/thing/bootstrap/config/push"
#define REDIRECT_PUB_TOPIC "/sys/%s/%s/thing/bootstrap/config/push_reply"
#define RECONNECT_SUB_TOPIC "/sys/%s/%s/thing/bootstrap/notify"
#define RECONNECT_PUB_TOPIC "/sys/%s/%s/thing/bootstrap/notify_reply"
#endif
#define REDIRECT_MSG_ID "id"
#define REDIRECT_MSG_HOST "params.endpoint.mqtt.host"
#define REDIRECT_MSG_PORT "params.endpoint.mqtt.port"

#define RECONNECT_MSG_METHOD "method"
#define RECONNECT_METHOD "thing.bootstrap.notify"

#define RECONNECT_MSG_PARAM_CMD "params.cmd"
#define RECONNECT_CMD_RECONNECT "0"

#define PUB_DATA_STR "{\"id\":%d,\"code\":%d,\"data\":{}}"

#define redirect_err(...) log_err("redirect", __VA_ARGS__)
#define redirect_warn(...) log_warning("redirect", __VA_ARGS__)
//#ifdef REDIRECT_DEBUG
#define redirect_info(...) log_info("redirect", __VA_ARGS__)
// #else
// #define redirect_info(...)
// #endif

enum _response_code
{
    SUCCESS = 200,
    PARAM_ERROR = 2000,
    JSON_PARSE_ERROR
};

/*
static int _response_cloud(int id, int code)
{
    int ret = 0;
    char *p_topic = NULL;
    char data[DATA_LENGTH] = {0};
    iotx_device_info_t *p_device = NULL;

    p_device = LITE_malloc(sizeof(iotx_device_info_t));
    if (!p_device)
    {
        redirect_err("no mem");
        goto ERROR;
    }

    ret = iotx_device_info_get(p_device);
    if (ret < 0)
    {
        redirect_err("get device info err");
        goto ERROR;
    }

    p_topic = LITE_malloc(TOPIC_LENGTH);
    if (!p_topic)
    {
        redirect_err("no mem");
        goto ERROR;
    }

    memset(p_topic, 0, TOPIC_LENGTH);
    snprintf(p_topic, TOPIC_LENGTH, REDIRECT_PUB_TOPIC, p_device->product_key, p_device->device_name);
    redirect_info("pub p_topic:%s", p_topic);

    memset(data, 0, DATA_LENGTH);
    snprintf(data, DATA_LENGTH, PUB_DATA_STR, id, code);

    ret = IOT_MQTT_Publish_Simple(NULL, p_topic, IOTX_MQTT_QOS1, data, strlen(data));
ERROR:
    if (p_topic)
        LITE_free(p_topic);
    if (p_device)
        LITE_free(p_device);

    return ret;        
}
*/
static void redirect_msg_cb(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg)
{
    int id = 0;
    char *id_str = NULL;
    int code = 200;
    iotx_mqtt_topic_info_pt ptopic_info = NULL;

    int port = -1;
    char *port_str = NULL;
    char *host = NULL;
    char *payload = NULL;
    void *callback = NULL;
    char *p_mqtt_url = NULL;

    redirect_info("redirect_msg_cb called");
    if (msg == NULL)
    {
        redirect_err("params error");
        code = PARAM_ERROR;
        goto ERROR;
    }

    ptopic_info = (iotx_mqtt_topic_info_pt)msg->msg;

    if (ptopic_info == NULL)
    {
        redirect_err("params error");
        code = PARAM_ERROR;
        goto ERROR;
    }

    payload = (char *)ptopic_info->payload;
    if (payload == NULL)
    {
        redirect_err("params error");
        goto ERROR;
    }

    // print topic name and topic message
    redirect_info("Event(%d)", msg->event_type);
    if (msg->event_type != IOTX_MQTT_EVENT_PUBLISH_RECEIVED)
    {
        redirect_info("do nothing");
        return;
    }

#ifdef REDIRECT_DEBUG
    redirect_info("Topic: '%.*s' (Length: %d)",
                  ptopic_info->topic_len,
                  ptopic_info->ptopic,
                  ptopic_info->topic_len);
    redirect_info("Payload: '%.*s' (Length: %d)",
                  ptopic_info->payload_len,
                  ptopic_info->payload,
                  ptopic_info->payload_len);
#endif

    id_str = LITE_json_value_of(REDIRECT_MSG_ID, payload, MEM_MAGIC, "redirect");
    if (!id_str)
    {
        redirect_err("id parse error");
        code = JSON_PARSE_ERROR;
        goto ERROR;
    }

    id = atoi(id_str);
    redirect_info("id=%d", id);

    host = LITE_json_value_of(REDIRECT_MSG_HOST, payload, MEM_MAGIC, "redirect");
    if (NULL == host)
    {
        redirect_err("host err");
        code = JSON_PARSE_ERROR;
        goto ERROR;
    }
    redirect_info("host=%s", host);

    port_str = LITE_json_value_of(REDIRECT_MSG_PORT, payload, MEM_MAGIC, "redirect");
    if (NULL == port_str)
    {
        redirect_err("port err");
        code = JSON_PARSE_ERROR;
        goto ERROR;
    }

    redirect_info("port=%s", port_str);
    port = atoi(port_str);

    p_mqtt_url = HAL_Malloc(GUIDER_DYNAMIC_URL_LEN);
    if (!p_mqtt_url)
    {
        sys_err("no mem");
        goto ERROR;
    }

    memset(p_mqtt_url, '\0', GUIDER_DYNAMIC_URL_LEN);
    HAL_Snprintf(p_mqtt_url, GUIDER_DYNAMIC_URL_LEN, "%s:%d", host, port);

    iotx_guider_set_dynamic_mqtt_url(p_mqtt_url);

    callback = iotx_event_callback(ITE_REDIRECT);
    if (callback)
    {
        ((int (*)(void))callback)();
    }

ERROR:
    if (code != 200)
    {
        redirect_err("redirect parse error");
    }
    if (id_str)
    {
        HAL_Free(id_str);
    }
    if (port_str)
    {
        HAL_Free(port_str);
    }
    if (host)
    {
        HAL_Free(host);
    }
    if (p_mqtt_url)
    {
        HAL_Free(p_mqtt_url);
    }
}

int iotx_redirect_region_subscribe(void)
{
    int ret = 0;
    char *p_topic = NULL;
    iotx_device_info_t p_device;

    ret = iotx_device_info_get(&p_device);
    if (ret < 0)
    {
        redirect_err("get device info err");
        goto ERROR;
    }

    p_topic = LITE_malloc(TOPIC_LENGTH);
    if (p_topic == NULL)
    {
        redirect_err("no mem");
        ret = -1;
        goto ERROR;
    }

    memset(p_topic, 0, TOPIC_LENGTH);
    snprintf(p_topic, TOPIC_LENGTH, REDIRECT_SUB_TOPIC, p_device.product_key, p_device.device_name);
    redirect_info("p_topic:%s", p_topic);

#ifdef MQTT_AUTO_SUBSCRIBE
    ret = IOT_MQTT_Subscribe(NULL, p_topic, IOTX_MQTT_QOS3_SUB_LOCAL, redirect_msg_cb, NULL);
#else
    ret = IOT_MQTT_Subscribe(NULL, p_topic, IOTX_MQTT_QOS0, redirect_msg_cb, NULL);
#endif

    if (ret < 0)
    {
        redirect_err("sub failed");
    }
    else
    {
        redirect_info("sub success");
    }

ERROR:
    if (p_topic)
    {
        LITE_free(p_topic);
    }

    return ret;
}

/*
{
    "id": 123,
    "version": "1.0",
    "method": "thing.bootstrap.notify",
    "params": {
      "cmd": 0    //0:Means need device reconnect cloud
    }
}
{
    "id" : "123",
    "code":200,
    "data" : {}
}
*/
static void reconnect_msg_cb(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg)
{
    int id = 0;
    int code = 200;
    char *p_method = NULL;
    char *p_param_cmd = NULL;

    char *payload = NULL;
    void *callback = NULL;
    iotx_mqtt_topic_info_pt ptopic_info = NULL;

    redirect_info("reconnect_msg_cb called");
    if (msg == NULL)
    {
        redirect_err("params error");
        return;
    }

    ptopic_info = (iotx_mqtt_topic_info_pt)msg->msg;

    if (ptopic_info == NULL)
    {
        redirect_err("no msg");
        return;
    }

    payload = (char *)ptopic_info->payload;
    if (payload == NULL)
    {
        redirect_err("no payload");
        return;
    }

    if (msg->event_type != IOTX_MQTT_EVENT_PUBLISH_RECEIVED)
    {
        redirect_info("event type:%d err", msg->event_type);
        return;
    }

#ifdef REDIRECT_DEBUG
    redirect_info("Topic: '%.*s' (Length: %d)",
                  ptopic_info->topic_len,
                  ptopic_info->ptopic,
                  ptopic_info->topic_len);
    redirect_info("Payload: '%.*s' (Length: %d)",
                  ptopic_info->payload_len,
                  ptopic_info->payload,
                  ptopic_info->payload_len);
#endif

    p_method = LITE_json_value_of(RECONNECT_MSG_METHOD, payload, MEM_MAGIC, "reconnect");
    if (!p_method)
    {
        redirect_err("no method");
        code = JSON_PARSE_ERROR;
        goto ERROR;
    }

    if (strncmp(p_method, RECONNECT_METHOD, strlen(RECONNECT_METHOD)))
    {
        redirect_err("method:%s err", p_method);
        code = JSON_PARSE_ERROR;
        goto ERROR;
    }

    p_param_cmd = LITE_json_value_of(RECONNECT_MSG_PARAM_CMD, payload, MEM_MAGIC, "reconnect");
    if (!p_param_cmd)
    {
        redirect_err("no cmd");
        code = JSON_PARSE_ERROR;
        goto ERROR;
    }

    if (strncmp(p_param_cmd, RECONNECT_CMD_RECONNECT, strlen(RECONNECT_CMD_RECONNECT)))
    {
        redirect_err("cmd:%s err", p_param_cmd);
        code = JSON_PARSE_ERROR;
        goto ERROR;
    }

    iotx_guider_clear_dynamic_url();

    callback = iotx_event_callback(ITE_REDIRECT);
    if (callback)
    {
        ((int (*)(void))callback)();
    }

ERROR:
    if (code != 200)
    {
        redirect_err("reconnect parse err");
    }
    if (p_method)
    {
        HAL_Free(p_method);
    }
    if (p_param_cmd)
    {
        HAL_Free(p_param_cmd);
    }
}

int iotx_reconnect_region_subscribe(void)
{
    int ret = 0;
    char *p_topic = NULL;
    iotx_device_info_t p_device;

    ret = iotx_device_info_get(&p_device);
    if (ret < 0)
    {
        redirect_err("get device info err");
        goto ERROR;
    }

    p_topic = LITE_malloc(TOPIC_LENGTH);
    if (p_topic == NULL)
    {
        redirect_err("no mem");
        ret = -1;
        goto ERROR;
    }

    memset(p_topic, 0, TOPIC_LENGTH);
    snprintf(p_topic, TOPIC_LENGTH, RECONNECT_SUB_TOPIC, p_device.product_key, p_device.device_name);
    redirect_info("p_topic:%s", p_topic);

#ifdef MQTT_AUTO_SUBSCRIBE
    ret = IOT_MQTT_Subscribe(NULL, p_topic, IOTX_MQTT_QOS3_SUB_LOCAL, reconnect_msg_cb, NULL);
#else
    ret = IOT_MQTT_Subscribe(NULL, p_topic, IOTX_MQTT_QOS0, reconnect_msg_cb, NULL);
#endif

    if (ret < 0)
    {
        redirect_err("sub failed");
    }
    else
    {
        redirect_info("sub success");
    }

ERROR:
    if (p_topic)
    {
        LITE_free(p_topic);
    }

    return ret;
}

#endif

/*
 * Copyright (C) 2015-2019 Alibaba Group Holding Limited
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "cJSON.h"
#include "iot_import.h"
#include "iot_export_linkkit.h"

#include "iotx_log.h"

#include "gateway_main.h"
#include "gateway_entry.h"
#include "gateway_api.h"
#include "gateway_ut.h"

#ifdef GATEWAY_UT_TESTING
static char is_forbidden_auto_add_subdev = 0;
static int subdev_index = 0;

static aos_queue_t gateway_queue_t;
static char gateway_queue_buf[MAX_QUEUE_SIZE];
static gw_topo_get_reason_e topo_get_reason = GW_TOPO_GET_REASON_MAX;

static int gateway_find_subdev_by_pk_dn(iotx_linkkit_dev_meta_info_t *subdev_meta);

static int aos_queue_new(aos_queue_t *queue, void *buf, unsigned int size, int max_msg)
{
    ssize_t ret = 0;
    struct queue *q = malloc(sizeof(*q));

    ret = pipe(q->fds);
    q->buf = buf;
    q->size = size;
    q->msg_size = max_msg;
    queue->hdl = q;

    return ret;
}

static int aos_queue_send(aos_queue_t *queue, void *msg, unsigned int size)
{
    ssize_t ret = 0;

    struct queue *q = queue->hdl;
    ret = write(q->fds[1], msg, size);

    return ret;
}

static int aos_queue_recv(aos_queue_t *queue, unsigned int ms, void *msg,
                          unsigned int *size)
{
    struct queue *q = queue->hdl;
    struct pollfd rfd = {
        .fd = q->fds[0],
        .events = POLLIN,
    };

    poll(&rfd, 1, ms);
    if (rfd.revents & POLLIN)
    {
        int len = read(q->fds[0], msg, q->msg_size);
        *size = len;
        return len < 0 ? -1 : 0;
    }

    return -1;
}

//For cmds call send msg to linkkit_main
int gateway_ut_send_msg(gateway_msg_t *msg, int len)
{
    if (msg && len == QUEUE_MSG_SIZE)
    {
        gateway_info("send msg type(%d)", msg->msg_type);
        return aos_queue_send(&gateway_queue_t, msg, len);
    }

    gateway_err("param err");

    return -1;
}

//This example sub dev mate mainly for CI
iotx_linkkit_dev_meta_info_t subdevArr[GATEWAY_SUBDEV_MAX_NUM] = {
#ifdef REGION_SINGAPORE
    {"PK_XXXX",
     "PS_XXXX",
     "DN_XXXX",
     "DS_XXXX"},
    {"PK_XXXX",
     "PS_XXXX",
     "DN_XXXX",
     "DS_XXXX"},
#else /* Mainland(Shanghai) for default */
    {"PK_XXXX",
     "PS_XXXX",
     "DN_XXXX",
     "DS_XXXX"},
    {"PK_XXXX",
     "PS_XXXX",
     "DN_XXXX",
     "DS_XXXX"},
#endif
};

static int gateway_connect_cloud(char *payload, int payload_len)
{
    int index = 0;
    int subdev_id = 0;
    int subdev_total = 0;
    int subdev_num = 0;
    gateway_msg_t msg;
    cJSON *topo_list = NULL, *subdev = NULL;
    cJSON *pk = NULL, *dn = NULL;
    gateway_ctx_t *p_gateway_ctx = gateway_get_ctx();

    iotx_linkkit_dev_meta_info_t *p_subdev_mate = NULL;
    iotx_linkkit_dev_meta_info_t *p_subdev_mate_index = NULL;

    if (payload == NULL || payload_len < 1)
    {
        gateway_err("param err");
        return -1;
    }
    /* Parse Request */
    topo_list = cJSON_Parse(payload);
    if (topo_list == NULL || !cJSON_IsArray(topo_list))
    {
        gateway_err("topo list json format err");
        return -1;
    }

    subdev_total = cJSON_GetArraySize(topo_list);
    if (subdev_total < 1)
    {
        gateway_err("topo is empty");
        return -1;
    }

    p_subdev_mate = HAL_Malloc(sizeof(iotx_linkkit_dev_meta_info_t) * subdev_total);
    if (p_subdev_mate == NULL)
    {
        gateway_err("no mem");
        return -1;
    }

    memset(p_subdev_mate, 0, sizeof(iotx_linkkit_dev_meta_info_t) * subdev_total);
    for (index = 0; index < subdev_total; index++)
    {
        subdev = cJSON_GetArrayItem(topo_list, index);
        if (subdev == NULL || !cJSON_IsObject(subdev))
        {
            gateway_err("subdev json err");
            continue;
        }

        pk = cJSON_GetObjectItem(subdev, TOPO_LIST_PK);
        dn = cJSON_GetObjectItem(subdev, TOPO_LIST_DN);
        if (cJSON_IsString(pk) && cJSON_IsString(dn))
        {
            p_subdev_mate_index = p_subdev_mate + subdev_num;
            subdev_num++;
            HAL_Snprintf(p_subdev_mate_index->product_key, PRODUCT_KEY_MAXLEN, "%s", pk->valuestring);
            HAL_Snprintf(p_subdev_mate_index->device_name, DEVICE_NAME_MAXLEN, "%s", dn->valuestring);
        }
    }

    cJSON_Delete(topo_list);

    gateway_add_multi_subdev(p_gateway_ctx->master_devid, p_subdev_mate, subdev_num);
    if (p_subdev_mate)
        HAL_Free(p_subdev_mate);

    return 0;
}

gw_device_type_e gateway_get_device_type(void)
{
    int ret = 0;
    char dev_type[GATEWAY_DEVICE_TYPE_LEN] = {0};
    int len = GATEWAY_DEVICE_TYPE_LEN - 1;

    ret = HAL_Kv_Get(GATEWAY_DEVICE_TYPE_KEY, dev_type, &len);
    if (ret == 0)
    {
        if (!strcmp(dev_type, GATEWAY_DEVICE_TYPE_MASTER))
        {
            return GW_DEVICE_MASTER;
        }
        else if (!strcmp(dev_type, GATEWAY_DEVICE_TYPE_SLAVE))
        {
            return GW_DEVICE_SLAVE;
        }
    }

    return GW_DEVICE_INVALID;
}

static int gateway_get_forbidden_auto_add_subdev_flag(void)
{
    int ret = 0;
    char forbidden_flag[GATEWAY_FORBIDDEN_AUTO_ADD_SUBDEV_FLAG_LEN] = {0};
    int len = GATEWAY_FORBIDDEN_AUTO_ADD_SUBDEV_FLAG_LEN - 1;

    ret = HAL_Kv_Get(GATEWAY_FORBIDDEN_AUTO_ADD_SUBDEV_FLAG_KEY, forbidden_flag, &len);
    if (ret == 0)
    {
        if ((!strcmp(forbidden_flag, "Y")) || (!strcmp(forbidden_flag, "y")))
        {
            return 1;
        }
    }

    return 0;
}

//Just for reference
static void user_post_property(void)
{
    int res = 0;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    char *property_payload = "{\"LightSwitch\":1}";

    res = IOT_Linkkit_Report(gateway_ctx->master_devid, ITM_MSG_POST_PROPERTY,
                             (unsigned char *)property_payload, strlen(property_payload));

    gateway_info("Post Property Message ID: %d", res);
}

//Just for reference
static void user_post_sub_property(int subdev_id)
{
    int res = 0;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    char *property_payload = "{\"LightSwitch\":1}";

    res = IOT_Linkkit_Report(subdev_id, ITM_MSG_POST_PROPERTY,
                             (unsigned char *)property_payload, strlen(property_payload));

    gateway_info("Post Property Message ID: %d", res);
}

//Just for reference
static void user_post_event(void)
{
    int res = 0;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    char *event_id = "Error";
    char *event_payload = "{\"ErrorCode\":0}";

    res = IOT_Linkkit_TriggerEvent(gateway_ctx->master_devid, event_id, strlen(event_id),
                                   event_payload, strlen(event_payload));
    gateway_info("Post Event Message ID: %d", res);
}

//Just for reference
static void user_deviceinfo_update(void)
{
    int res = 0;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    char *device_info_update = "[{\"attrKey\":\"gateway\",\"attrValue\":\"I am a gateway\"},{\"attrKey\":\"subdev\",\"attrValue\":\"I am a subdev\"}]";

    res = IOT_Linkkit_Report(gateway_ctx->master_devid, ITM_MSG_DEVICEINFO_UPDATE,
                             (unsigned char *)device_info_update, strlen(device_info_update));
    gateway_info("Device Info Update Message ID: %d", res);
}

//Just for reference
static void user_deviceinfo_delete(void)
{
    int res = 0;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    char *device_info_delete = "[{\"attrKey\":\"subdev\"}]";

    res = IOT_Linkkit_Report(gateway_ctx->master_devid, ITM_MSG_DEVICEINFO_DELETE,
                             (unsigned char *)device_info_delete, strlen(device_info_delete));
    gateway_info("Device Info Delete Message ID: %d", res);
}

//Just for reference
static void user_post_raw_data(void)
{
    int res = 0;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    //raw_data is ASCII of [This is raw data.]
    unsigned char raw_data[] = {0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x72, 0x61, 0x77, 0x20, 0x64, 0x61, 0x74, 0x61, 0x2E};

    res = IOT_Linkkit_Report(gateway_ctx->master_devid, ITM_MSG_POST_RAW_DATA,
                             raw_data, sizeof(raw_data));

    gateway_info("Post Raw Data Message ID: %d", res);
}

int gateway_ut_handle_topolist_reply(const char *payload, const int payload_len)
{
    gateway_msg_t msg;

    if (topo_get_reason != GW_TOPO_GET_REASON_CONNECT_CLOUD)
    {
        return 0;
    }

    memset(&msg, 0, sizeof(gateway_msg_t));
    msg.payload = HAL_Malloc(payload_len + 1);

    if (msg.payload)
    {
        memset(msg.payload, '\0', payload_len + 1);
        memcpy(msg.payload, payload, payload_len);
        msg.msg_type = GATEWAY_MSG_TYPE_CLOUD_CONNECT;
        msg.devid = 1;
        msg.payload_len = payload_len;
        gateway_ut_send_msg(&msg, sizeof(gateway_msg_t));
    }

    return 0;
}

int gateway_ut_handle_permit_join(void)
{
    gateway_msg_t msg;

    msg.msg_type = GATEWAY_MSG_TYPE_PERMIT_JOIN;
    msg.devid = 1;
    gateway_ut_send_msg(&msg, sizeof(gateway_msg_t));

    return 0;
}

//get a sub dev mate info from KV,just for testing
static int get_one_device_mate(int devid, iotx_linkkit_dev_meta_info_t *p_subdev)
{
    int len = 0;
    char key_buf[MAX_KEY_LEN];

    if (!p_subdev)
        return -1;

    len = PRODUCT_KEY_MAXLEN;
    memset(key_buf, 0, MAX_KEY_LEN);
    memset(p_subdev->product_key, 0, PRODUCT_KEY_MAXLEN);
    HAL_Snprintf(key_buf, MAX_KEY_LEN, "%s_%d", KV_KEY_PK, devid);
    HAL_Kv_Get(key_buf, p_subdev->product_key, &len);

    len = PRODUCT_SECRET_MAXLEN;
    memset(key_buf, 0, MAX_KEY_LEN);
    memset(p_subdev->product_secret, 0, PRODUCT_SECRET_MAXLEN);
    HAL_Snprintf(key_buf, MAX_KEY_LEN, "%s_%d", KV_KEY_PS, devid);
    HAL_Kv_Get(key_buf, p_subdev->product_secret, &len);

    len = DEVICE_NAME_MAXLEN;
    memset(key_buf, 0, MAX_KEY_LEN);
    memset(p_subdev->device_name, 0, DEVICE_NAME_MAXLEN);
    HAL_Snprintf(key_buf, MAX_KEY_LEN, "%s_%d", KV_KEY_DN, devid);
    HAL_Kv_Get(key_buf, p_subdev->device_name, &len);

    len = DEVICE_SECRET_MAXLEN;
    memset(key_buf, 0, MAX_KEY_LEN);
    memset(p_subdev->device_secret, 0, DEVICE_SECRET_MAXLEN);
    HAL_Snprintf(key_buf, MAX_KEY_LEN, "%s_%d", KV_KEY_DS, devid);
    HAL_Kv_Get(key_buf, p_subdev->device_secret, &len);

    gateway_info("DevNum(%d) DN:%s", devid, p_subdev->device_name);

    return 0;
}

//Find sub device mate info from KV,just for testing
static int gateway_find_subdev_by_pk_dn(iotx_linkkit_dev_meta_info_t *subdev_meta)
{
    int index = 0;

    iotx_linkkit_dev_meta_info_t subdev;

    if (!subdev_meta)
        return -1;

    for (index = 1; index < MAX_DEVICES_META_NUM; index++)
    {
        get_one_device_mate(index, &subdev);
        if (!strcmp(subdev_meta->product_key, subdev.product_key) && !strcmp(subdev_meta->device_name, subdev.device_name))
        {
            return index;
        }
    }

    return -1;
}

//get multi sub devices mate info from KV,just for testing
static int get_all_subdev_mate(iotx_linkkit_dev_meta_info_t *subdev_meta)
{
    int index = 0;

    iotx_linkkit_dev_meta_info_t *p_subdev = NULL;

    if (!subdev_meta)
        return -1;

    for (index = 1; index < MAX_DEVICES_META_NUM; index++)
    {
        p_subdev = subdev_meta + (index - 1);

        get_one_device_mate(index, p_subdev);
    }

    return 0;
}

//get multi sub devices mate info from KV,just for testing
static int get_range_subdev_mate(iotx_linkkit_dev_meta_info_t *subdev_meta, int devid_start, int devid_end)
{
    int index = 0;

    iotx_linkkit_dev_meta_info_t *p_subdev = NULL;

    if (!subdev_meta)
        return -1;

    if (devid_start > 0 && devid_start < MAX_DEVICES_META_NUM &&
        devid_end > 0 && devid_end < MAX_DEVICES_META_NUM &&
        devid_start < devid_end)
    {
        for (index = devid_start; index <= devid_end; index++)
        {
            p_subdev = subdev_meta + (index - 1);

            get_one_device_mate(index, p_subdev);
        }
    }
    else
    {
        gateway_warn("devid err");
    }

    return 0;
}

//This is an example for get topolist info
//you can get topo list info in func:user_topolist_reply_handler
int gateway_ut_update_subdev(gw_topo_get_reason_e reason)
{
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();
    gateway_info("do update subdev");

    IOT_Linkkit_Query(gateway_ctx->master_devid, ITM_MSG_QUERY_TOPOLIST, NULL, 0);
    topo_get_reason = reason;

    return 0;
}

int gateway_ut_msg_process(int master_devid, int timeout)
{
    int ret = 0;
    unsigned int recv_size = 0;
    int subdev_id = -1;
    gateway_msg_t msg;
    gateway_ctx_t *gateway_ctx = gateway_get_ctx();

    ret = aos_queue_recv(&gateway_queue_t, timeout, &msg, &recv_size);
    if (ret == 0 && recv_size == QUEUE_MSG_SIZE)
    {
        gateway_info("msg.type:%d, devid:%d", msg.msg_type, msg.devid);
        if (msg.devid < 1 || msg.devid > MAX_DEVICES_META_NUM - 1)
        {
            gateway_warn("sub dev id(%d) err", msg.devid);
            return -1;
        }

        switch (msg.msg_type)
        {
        case GATEWAY_MSG_TYPE_ADD:
        {
            iotx_linkkit_dev_meta_info_t subdev_mate;
            memset(&subdev_mate, 0, sizeof(subdev_mate));
            get_one_device_mate(msg.devid, &subdev_mate);

            if (gateway_ctx->permit_join == 1 && strlen(gateway_ctx->permit_join_pk) > 0)
            {
                if (strcmp(subdev_mate.product_key, gateway_ctx->permit_join_pk))
                {
                    gateway_warn("permit join pk:%s is not found", gateway_ctx->permit_join_pk);
                    ret = -1;
                    break;
                }
            }

            ret = gateway_add_subdev(&subdev_mate);
        }
        break;
        case GATEWAY_MSG_TYPE_ADDALL:
        {
            iotx_linkkit_dev_meta_info_t *p_meta_info = NULL;

            p_meta_info = HAL_Malloc(sizeof(iotx_linkkit_dev_meta_info_t) * (MAX_DEVICES_META_NUM - 1));
            if (!p_meta_info)
            {
                gateway_err("no mem");
                return -1;
            }

            memset(p_meta_info, '\0', sizeof(iotx_linkkit_dev_meta_info_t) * (MAX_DEVICES_META_NUM - 1));
            get_all_subdev_mate(p_meta_info);
            ret = gateway_add_multi_subdev(master_devid, p_meta_info, MAX_DEVICES_META_NUM - 1);

            HAL_Free(p_meta_info);
        }
        break;
        case GATEWAY_MSG_TYPE_ADD_RANGE:
        {
            iotx_linkkit_dev_meta_info_t *p_meta_info = NULL;
            int subdev_num = msg.devid_end - msg.devid + 1;

            if (msg.devid < 1 || msg.devid >= MAX_DEVICES_META_NUM ||
                msg.devid_end < 1 || msg.devid_end >= MAX_DEVICES_META_NUM ||
                msg.devid >= msg.devid_end)
            {
                gateway_warn("sub dev id err");
                return -1;
            }

            p_meta_info = HAL_Malloc(sizeof(iotx_linkkit_dev_meta_info_t) * subdev_num);
            if (!p_meta_info)
            {
                gateway_err("no mem");
                return -1;
            }

            memset(p_meta_info, '\0', sizeof(iotx_linkkit_dev_meta_info_t) * subdev_num);
            get_range_subdev_mate(p_meta_info, msg.devid, msg.devid_end);
            ret = gateway_add_multi_subdev(master_devid, p_meta_info, subdev_num);

            HAL_Free(p_meta_info);
        }
        break;
        case GATEWAY_MSG_TYPE_DELALL:
        {
            iotx_linkkit_dev_meta_info_t subdev_mate;
            for (subdev_id = 1; subdev_id < MAX_DEVICES_META_NUM; subdev_id++)
            {

                memset(&subdev_mate, 0, sizeof(subdev_mate));
                get_one_device_mate(subdev_id, &subdev_mate);
                ret = gateway_del_subdev(&subdev_mate);
                gateway_info("del subdev id(%d) ret = %d", subdev_id, ret);
            }
        }
        break;
        case GATEWAY_MSG_TYPE_DEL:
        {
            iotx_linkkit_dev_meta_info_t subdev_mate;

            memset(&subdev_mate, 0, sizeof(subdev_mate));
            get_one_device_mate(msg.devid, &subdev_mate);
            ret = gateway_del_subdev(&subdev_mate);
        }
        break;

        case GATEWAY_MSG_TYPE_DEL_RANGE:
        {
            iotx_linkkit_dev_meta_info_t subdev_mate;

            if (msg.devid < 1 || msg.devid >= MAX_DEVICES_META_NUM ||
                msg.devid_end < 1 || msg.devid_end >= MAX_DEVICES_META_NUM ||
                msg.devid >= msg.devid_end)
            {
                gateway_warn("sub dev id err");
                return -1;
            }

            for (subdev_id = msg.devid; subdev_id <= msg.devid_end; subdev_id++)
            {

                memset(&subdev_mate, 0, sizeof(subdev_mate));
                get_one_device_mate(subdev_id, &subdev_mate);
                ret = gateway_del_subdev(&subdev_mate);
                gateway_info("del subdev id(%d) ret = %d", subdev_id, ret);
            }
        }
        break;
        case GATEWAY_MSG_TYPE_UPDATE:
        {
            ret = gateway_ut_update_subdev(GW_TOPO_GET_REASON_CLI_CMD);
        }
        break;
        case GATEWAY_MSG_TYPE_RESET:
        {
            iotx_linkkit_dev_meta_info_t subdev_mate;

            memset(&subdev_mate, 0, sizeof(subdev_mate));
            get_one_device_mate(msg.devid, &subdev_mate);
            ret = gateway_reset_subdev(&subdev_mate);
        }
        break;
        case GATEWAY_MSG_TYPE_QUERY_SUBDEV_ID:
        {
            iotx_linkkit_dev_meta_info_t subdev_mate;

            memset(&subdev_mate, 0, sizeof(subdev_mate));
            get_one_device_mate(msg.devid, &subdev_mate);
            ret = gateway_query_subdev_id(gateway_ctx->master_devid, &subdev_mate);
        }
        break;
        case GATEWAY_MSG_TYPE_CLOUD_CONNECT:
        {
            if (msg.payload)
            {
                gateway_connect_cloud(msg.payload, msg.payload_len);
                HAL_Free(msg.payload);
            }
        }
        break;
        case GATEWAY_MSG_TYPE_PERMIT_JOIN:
        {
            if (gateway_ctx->permit_join == 1)
            {
                int matched_subdev_num = 0;
                iotx_linkkit_dev_meta_info_t subdev_mate = {0};
                iotx_linkkit_dev_meta_info_t *p_subdev_mate = NULL;

                p_subdev_mate = HAL_Malloc(sizeof(iotx_linkkit_dev_meta_info_t) * MAX_DEVICES_META_NUM);
                if (p_subdev_mate == NULL)
                {
                    gateway_err("no mem");
                    return -1;
                }

                memset(p_subdev_mate, 0, sizeof(iotx_linkkit_dev_meta_info_t) * MAX_DEVICES_META_NUM);
                for (subdev_id = 1; subdev_id < MAX_DEVICES_META_NUM; subdev_id++)
                {
                    memset(&subdev_mate, 0, sizeof(subdev_mate));
                    if (0 == get_one_device_mate(subdev_id, &subdev_mate) && 0 == strcmp(gateway_ctx->permit_join_pk, subdev_mate.product_key))
                    {
                        memcpy(p_subdev_mate + matched_subdev_num, &subdev_mate, sizeof(iotx_linkkit_dev_meta_info_t));
                        matched_subdev_num++;
                    }
                    else
                    {
                        gateway_warn("permit join pk:%s found pk:%s dn:%s", gateway_ctx->permit_join_pk, subdev_mate.product_key, subdev_mate.device_name);
                    }
                }

                gateway_add_multi_subdev(gateway_ctx->master_devid, p_subdev_mate, matched_subdev_num);
                if (p_subdev_mate)
                {
                    HAL_Free(p_subdev_mate);
                }
            }
        }
        break;
        default:
            gateway_warn("unKnow msg type(%d)", msg.msg_type);
            return -1;
        }
    }

    return ret;
}

void gateway_ut_misc_process(uint64_t time_now_sec)
{
    /* Add subdev for CI*/
    if (is_forbidden_auto_add_subdev == 0 && (subdev_index < GATEWAY_SUBDEV_MAX_NUM))
    {
        /* Add next subdev */
        if (gateway_add_subdev(&subdevArr[subdev_index]) == SUCCESS_RETURN)
        {
            gateway_info("subdev DN:%s add succeed", subdevArr[subdev_index].device_name);
        }
        else
        {
            gateway_info("subdev DN:%s add failed", subdevArr[subdev_index].device_name);
        }

        subdev_index++;
    }

    /* Post Proprety Example */
    if (time_now_sec % 11 == 0)
    {
        user_post_property();
        user_post_sub_property(subdev_index);
    }

    /* Post Event Example */
    if (time_now_sec % 17 == 0)
    {
        user_post_event();
    }

    /* Device Info Update Example */
    if (time_now_sec % 23 == 0)
    {
        user_deviceinfo_update();
    }

    /* Device Info Delete Example */
    if (time_now_sec % 29 == 0)
    {
        user_deviceinfo_delete();
    }

    /* Post Raw Example */
    if (time_now_sec % 37 == 0)
    {
        user_post_raw_data();
    }
}

int gateway_ut_init(void)
{
    int ret = SUCCESS_RETURN;

    ret = aos_queue_new(&gateway_queue_t, gateway_queue_buf, sizeof(gateway_queue_buf), QUEUE_MSG_SIZE);
    if (FAIL_RETURN == ret)
    {
        gateway_info("aos_queue_new failed");

        return ret;
    }

    if (gateway_get_forbidden_auto_add_subdev_flag())
    {
        gateway_info("gw forbiden auto add subdev");
        is_forbidden_auto_add_subdev = 1;
    }

    return ret;
}

#endif

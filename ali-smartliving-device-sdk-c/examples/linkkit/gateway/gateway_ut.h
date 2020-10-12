#ifndef __GATEWAY_UT_H__
#define __GATEWAY_UT_H__

// for demo only
#define KV_KEY_PK "pk"
#define KV_KEY_PS "ps"
#define KV_KEY_DN "dn"
#define KV_KEY_DS "ds"

#define MAX_KEY_LEN (6)
#define MAX_DEVICES_META_NUM (11) //support 10 sub devices

#define AOS_WAIT_FOREVER 0xffffffffu
#define AOS_NO_WAIT 0x0

#define PRODUCT_KEY "PK_XXXXX"
#define PRODUCT_SECRET "PS_XXXXX"
#define DEVICE_NAME "DN_XXXXX"
#define DEVICE_SECRET "DS_XXXXX"

#define TOPO_LIST_PK "productKey"
#define TOPO_LIST_DN "deviceName"

#define TOPO_CHANGE_STATUS "status"
#define TOPO_CHANGE_SUBLIST "subList"

#define GATEWAY_SUBDEV_MAX_NUM (2)

#define QUEUE_MSG_SIZE sizeof(gateway_msg_t)
#define MAX_QUEUE_SIZE 10 * QUEUE_MSG_SIZE

//You should undefine this Macro in your products
//#define GATEWAY_UT_TESTING

//KV config gw type,VALUE:master mean it is gateway,slave is subdev
#define GATEWAY_DEVICE_TYPE_KEY "gwtype"
#define GATEWAY_DEVICE_TYPE_MASTER "master"
#define GATEWAY_DEVICE_TYPE_SLAVE "slave"
#define GATEWAY_DEVICE_TYPE_LEN (7)

#define GATEWAY_FORBIDDEN_AUTO_ADD_SUBDEV_FLAG_KEY "gwf"
#define GATEWAY_FORBIDDEN_AUTO_ADD_SUBDEV_FLAG_LEN 2

typedef struct
{
    void *hdl;
} aos_hdl_t;

typedef aos_hdl_t aos_queue_t;

struct queue
{
    int fds[2];
    void *buf;
    int size;
    int msg_size;
};

typedef enum _gw_topo_change_status_e
{
    GW_TOPO_CHANGE_STATUS_ADD = 0,
    GW_TOPO_CHANGE_STATUS_DELETE = 1,
    GW_TOPO_CHANGE_STATUS_ENABLE = 2,
    GW_TOPO_CHANGE_STATUS_DISABLE = 8,
    GW_TOPO_CHANGE_STATUS_INVALID
} gw_topo_change_status_e;

typedef enum _gw_device_type_e
{
    GW_DEVICE_MASTER = 0,
    GW_DEVICE_SLAVE,
    GW_DEVICE_INVALID
} gw_device_type_e;

typedef enum _gw_topo_get_reason_e
{
    GW_TOPO_GET_REASON_CONNECT_CLOUD = 0,
    GW_TOPO_GET_REASON_CLI_CMD,
    GW_TOPO_GET_REASON_MAX
} gw_topo_get_reason_e;

typedef enum _gateway_msg_type_e
{
    GATEWAY_MSG_TYPE_ADD,
    GATEWAY_MSG_TYPE_ADD_RANGE,
    GATEWAY_MSG_TYPE_DEL,
    GATEWAY_MSG_TYPE_DEL_RANGE,
    GATEWAY_MSG_TYPE_RESET,
    GATEWAY_MSG_TYPE_UPDATE,
    GATEWAY_MSG_TYPE_ADDALL,
    GATEWAY_MSG_TYPE_DELALL,
    GATEWAY_MSG_TYPE_QUERY_SUBDEV_ID,
    GATEWAY_MSG_TYPE_CLOUD_CONNECT,
    GATEWAY_MSG_TYPE_PERMIT_JOIN,
    GATEWAY_MSG_TYPE_MAX
} gateway_msg_type_e;

typedef struct _gateway_msg_s
{
    gateway_msg_type_e msg_type;
    int devid;
    int devid_end;
    char *payload;
    int payload_len;
} gateway_msg_t;

extern int gateway_ut_init(void);
extern int gateway_ut_handle_permit_join(void);
extern int gateway_ut_handle_topolist_reply(const char *payload, const int payload_len);
extern int gateway_ut_send_msg(gateway_msg_t *, int);
extern int gateway_ut_msg_process(int master_devid, int timeout);
extern void gateway_ut_misc_process(uint64_t time_now_sec);
extern int gateway_ut_update_subdev(gw_topo_get_reason_e reason);

#endif

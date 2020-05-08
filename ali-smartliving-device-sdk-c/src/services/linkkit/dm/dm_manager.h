/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */



#ifndef _DM_MANAGER_H_
#define _DM_MANAGER_H_

#include "iotx_dm_internal.h"

typedef struct {
    int devid;
    int dev_type;
    char product_key[PRODUCT_KEY_MAXLEN];
    char device_name[DEVICE_NAME_MAXLEN];
    char device_secret[DEVICE_SECRET_MAXLEN];
    iotx_dm_dev_avail_t status;
    iotx_dm_dev_status_t dev_status;
    struct list_head linked_list;
} dm_mgr_dev_node_t;

typedef struct {
    void *mutex;
    int global_devid;
    struct list_head dev_list;
} dm_mgr_ctx;

int dm_mgr_init(void);
int dm_mgr_deinit(void);
int dm_mgr_device_create(_IN_ int dev_type, _IN_ char product_key[PRODUCT_KEY_MAXLEN],
                         _IN_ char device_name[DEVICE_NAME_MAXLEN], _IN_ char device_secret[DEVICE_SECRET_MAXLEN], _OU_ int *devid);
int dm_mgr_device_destroy(_IN_ int devid);
int dm_mgr_device_number(void);
int dm_mgr_get_devid_by_index(_IN_ int index, _OU_ int *devid);
int dm_mgr_get_next_devid(_IN_ int devid, _OU_ int *devid_next);
int dm_mgr_search_device_by_devid(_IN_ int devid, _OU_ char product_key[PRODUCT_KEY_MAXLEN],
                                  _OU_ char device_name[DEVICE_NAME_MAXLEN], _OU_ char device_secret[DEVICE_SECRET_MAXLEN]);
int dm_mgr_search_device_by_pkdn(_IN_ char product_key[PRODUCT_KEY_MAXLEN], _IN_ char device_name[DEVICE_NAME_MAXLEN],
                                 _OU_ int *devid);
int dm_mgr_search_device_node_by_devid(_IN_ int devid, _OU_ void **node);

int dm_mgr_get_dev_type(_IN_ int devid, _OU_ int *dev_type);
int dm_mgr_set_dev_enable(_IN_ int devid);
int dm_mgr_set_dev_disable(_IN_ int devid);
int dm_mgr_get_dev_avail(_IN_ char product_key[PRODUCT_KEY_MAXLEN], _IN_ char device_name[DEVICE_NAME_MAXLEN],
                         _OU_ iotx_dm_dev_avail_t *status);
int dm_mgr_set_dev_status(_IN_ int devid, _IN_ iotx_dm_dev_status_t status);
int dm_mgr_get_dev_status(_IN_ int devid, _OU_ iotx_dm_dev_status_t *status);
int dm_mgr_set_device_secret(_IN_ int devid, _IN_ char device_secret[DEVICE_SECRET_MAXLEN]);
int dm_mgr_dev_initialized(int devid);

#ifdef DEVICE_MODEL_GATEWAY
    int dm_mgr_upstream_thing_sub_register(_IN_ int devid);
    int dm_mgr_upstream_thing_sub_unregister(_IN_ int devid);
    int dm_mgr_upstream_thing_topo_add(_IN_ int devid);
    int dm_mgr_upstream_thing_topo_delete(_IN_ int devid);
    int dm_mgr_upstream_thing_subdev_reset(_IN_ int devid);
    int dm_mgr_upstream_thing_topo_get(void);
    int dm_mgr_upstream_thing_list_found(_IN_ int devid);
    int dm_mgr_upstream_combine_login(_IN_ int devid);
    int dm_mgr_upstream_combine_logout(_IN_ int devid);

#ifdef DM_SUBDEV_NEW_CONNECT
int dm_mgr_subdev_connect(int devid, const char *params, int params_len);
int dm_mgr_all_subdev_connect(_IN_ int devid);
#endif

#endif
int dm_mgr_upstream_thing_model_up_raw(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len);
#if !defined(DEVICE_MODEL_RAWDATA_SOLO)
int dm_mgr_upstream_thing_property_post(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len);

#ifdef DM_UNIFIED_SERVICE_POST
int dm_mgr_unified_service_post(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len);
#endif

#ifdef LOG_REPORT_TO_CLOUD
    int dm_mgr_upstream_thing_log_post(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len, int force_update);
#endif
int dm_mgr_upstream_thing_event_post(_IN_ int devid, _IN_ char *identifier, _IN_ int identifier_len, _IN_ char *method,
                                     _IN_ char *payload, _IN_ int payload_len);
int dm_mgr_upstream_thing_deviceinfo_update(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len);
int dm_mgr_upstream_thing_deviceinfo_delete(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len);
int dm_mgr_upstream_thing_dsltemplate_get(_IN_ int devid);
int dm_mgr_upstream_thing_dynamictsl_get(_IN_ int devid);
int dm_mgr_upstream_ntp_request(void);
#ifndef LINK_VISUAL_ENABLE
int dm_mgr_upstream_thing_service_response(_IN_ int devid, _IN_ char *msgid, _IN_ int msgid_len,
        _IN_ iotx_dm_error_code_t code,
        _IN_ char *identifier, _IN_ int identifier_len, _IN_ char *payload, _IN_ int payload_len, void *ctx);
#else
int dm_mgr_upstream_thing_service_response(_IN_ int devid, _IN_ char *msgid, _IN_ int msgid_len,
        _IN_ iotx_dm_error_code_t code,
        _IN_ char *identifier, _IN_ int identifier_len, _IN_ char *payload, _IN_ int payload_len);
#endif
int dm_mgr_upstream_thing_property_get_response(_IN_ int devid, _IN_ char *msgid, _IN_ int msgid_len,
        _IN_ iotx_dm_error_code_t code,
        _IN_ char *payload, _IN_ int payload_len, _IN_ void *ctx);
int dm_mgr_upstream_rrpc_response(_IN_ int devid, _IN_ char *msgid, _IN_ int msgid_len, _IN_ iotx_dm_error_code_t code,
                                  _IN_ char *rrpcid, _IN_ int rrpcid_len, _IN_ char *payload, _IN_ int payload_len);

int dm_mgr_upstream_thing_event_notify_reply(_IN_ int devid, _IN_ char *payload, _IN_ int payload_len);
#endif
#endif

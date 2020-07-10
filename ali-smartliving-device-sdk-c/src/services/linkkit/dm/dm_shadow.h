/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */



#ifndef _DM_SHADOW_H_
#define _DM_SHADOW_H_

typedef struct {
    void *handle;
    char product_key[PRODUCT_KEY_MAXLEN];
    char device_name[DEVICE_NAME_MAXLEN];
} dm_shadow_ctx_t;

int dm_shadow_init(void);
int dm_shadow_connect(void);
int dm_shadow_deinit(void);
int dm_shadow_update(void);
int dm_shadow_yield(int timeout_ms);
int dm_shadow_get_handle(void **handle);
int dm_shadow_register_attr(iotx_shadow_attr_pt pattr);

#endif
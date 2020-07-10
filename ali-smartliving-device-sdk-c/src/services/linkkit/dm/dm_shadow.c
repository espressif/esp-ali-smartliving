/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */
#if defined(MQTT_SHADOW)
#include "iotx_dm_internal.h"
#include "shadow.h"

static dm_shadow_ctx_t g_dm_shadow_ctx;
static iotx_shadow_para_t g_shadow_para;

dm_shadow_ctx_t *_dm_shadow_get_ctx(void)
{
    return &g_dm_shadow_ctx;
}

int dm_shadow_yield(int timeout_ms)
{
    dm_shadow_ctx_t *ctx = _dm_shadow_get_ctx();
    int ret = 0;

    if (ctx->handle == NULL) {
        return FAIL_RETURN;
    }

    IOT_Shadow_Yield(ctx->handle, 200);

    return SUCCESS_RETURN;
}

int dm_shadow_update(void)
{
    dm_shadow_ctx_t *ctx = _dm_shadow_get_ctx();
    int ret = 0;

    if (ctx->handle == NULL) {
        return FAIL_RETURN;
    }

    return IOT_Shadow_Pull(ctx->handle);;
}


int dm_shadow_init(void)
{
    dm_shadow_ctx_t *ctx = _dm_shadow_get_ctx();
    memset(ctx, 0, sizeof(dm_shadow_ctx_t));
    memset(&g_shadow_para, 0 , sizeof(iotx_shadow_para_t));

    return SUCCESS_RETURN;
}

int dm_shadow_connect(void)
//int dm_shadow_sub(char product_key[PRODUCT_KEY_MAXLEN], char device_name[DEVICE_NAME_MAXLEN])
{
    dm_shadow_ctx_t *ctx = _dm_shadow_get_ctx();
    void *handle = NULL;

    /* Init Shadow Handle */
    handle = IOT_Shadow_Construct(&g_shadow_para);
    if (handle == NULL) {
        return FAIL_RETURN;
    }

    ctx->handle = handle;

    return SUCCESS_RETURN;
}

int dm_shadow_register_attr(iotx_shadow_attr_pt pattr)
{
    dm_shadow_ctx_t *ctx = _dm_shadow_get_ctx();

    if (ctx->handle) {
        if(pattr != NULL){
            return IOT_Shadow_RegisterAttribute(ctx->handle, pattr);
        }
    }
    
    return FAIL_RETURN;
}

int dm_shadow_deinit(void)
{
    dm_shadow_ctx_t *ctx = _dm_shadow_get_ctx();

    if (ctx->handle) {
        IOT_Shadow_Destroy(ctx->handle);
        ctx->handle = NULL;
    }

    return SUCCESS_RETURN;
}

int dm_shadow_get_handle(void **handle)
{
    dm_shadow_ctx_t *ctx = _dm_shadow_get_ctx();

    if (handle == NULL || *handle != NULL) {
        return FAIL_RETURN;
    }

    if (ctx->handle == NULL) {
        return FAIL_RETURN;
    }

    *handle = ctx->handle;

    return SUCCESS_RETURN;
}
#endif
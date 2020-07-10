#if defined(CLOUD_OFFLINE_RESET)
#include "iot_export.h"
#include "dm_shadow.h"
#include "iotx_system_internal.h"

iotx_shadow_attr_t shadow_attr_reset;

void offline_reset_handle_callback(struct iotx_shadow_attr_st *pattr)
{
    void *user_callback = NULL;

    log_info("[RST]", "offline_reset_handle called.");

    if(pattr == NULL || pattr->pattr_data == NULL){
        return;
    }

//    if(0 == strncmp(pattr->pattr_data, "1", strlen("1")) && pattr->method_type == SHADOW_DOWNSTREAM_METHOD_REPLY){
    if(0 == strncmp(pattr->pattr_data, "1", strlen("1"))){
        user_callback = iotx_event_callback(ITE_OFFLINE_RESET);
        if (user_callback){
            ((int (*)(void))user_callback)();
        }
        log_info("[RST]", "cloud offline reset command.");
    }
}

int offline_reset_init(void)
{
    memset(&shadow_attr_reset, 0, sizeof(shadow_attr_reset));

    shadow_attr_reset.pattr_data = LITE_malloc(10);
    if(shadow_attr_reset.pattr_data == NULL){
        return FAIL_RETURN;
    }

    shadow_attr_reset.pattr_name = "restore_factory";
    shadow_attr_reset.attr_type = IOTX_SHADOW_STRING;
    shadow_attr_reset.callback = offline_reset_handle_callback;

    return dm_shadow_register_attr(&shadow_attr_reset); 
}

int offline_reset_deinit(void)
{
    if(shadow_attr_reset.pattr_data != NULL){
        LITE_free(shadow_attr_reset.pattr_data);
    }

    memset(&shadow_attr_reset, 0, sizeof(shadow_attr_reset));

    return SUCCESS_RETURN;
}

#endif
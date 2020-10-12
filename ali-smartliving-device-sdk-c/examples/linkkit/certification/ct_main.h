#ifndef __CT_MAIN_H__
#define __CT_MAIN_H__

#include <iotx_log.h>

//#define CT_PRODUCT_DYNAMIC_REGISTER_AND_USE_RAWDATA

//if your fy sdk is V1.0.0 or V 1.1.0
//#define CT_FY_SDK_VERSION_1_0_OR_1_1

//if your fy sdk is V1.3.0 or V 1.4.0
#define CT_FY_SDK_VERSION_1_3_OR_1_4

//if your fy sdk is V1.5.0
//#define CT_FY_SDK_VERSION_1_5

#define ct_debug(...) log_debug("ct", __VA_ARGS__)
#define ct_info(...) log_info("ct", __VA_ARGS__)
#define ct_warn(...) log_warning("ct", __VA_ARGS__)
#define ct_err(...) log_err("ct", __VA_ARGS__)
#define ct_crit(...) log_crit("ct", __VA_ARGS__)

#define CT_YIELD_TIMEOUT_MS (200)
#define CT_OTA_BUFFER_LEN (512 + 1) //Have to +1 or else ota SHA256 will crash

typedef struct
{
    int master_devid;
    int cloud_connected;
    int master_initialized;
    void *g_user_dispatch_thread;
    int g_user_dispatch_thread_running;
} ct_ctx_t;

extern int ct_main(void *paras);
extern ct_ctx_t *ct_get_ctx(void);

#endif

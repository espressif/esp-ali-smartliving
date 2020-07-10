#ifndef __LIVING_PLATFORM_MAIN_H__
#define __LIVING_PLATFORM_MAIN_H__

#include <iotx_log.h>

//#define LIVING_PLATFORM_PRODUCT_DYNAMIC_REGISTER

/*
Note:You can test some function to define LIVING_PLATFORM_USE_UT_FOR_TESTING
*/
//#define LIVING_PLATFORM_USE_UT_FOR_TESTING

#define living_platform_debug(...) log_debug("ct", __VA_ARGS__)
#define living_platform_info(...) log_info("ct", __VA_ARGS__)
#define living_platform_warn(...) log_warning("ct", __VA_ARGS__)
#define living_platform_err(...) log_err("ct", __VA_ARGS__)
#define living_platform_crit(...) log_crit("ct", __VA_ARGS__)

#define LIVING_PLATFORM_YIELD_TIMEOUT_MS (200)
#define LIVING_PLATFORM_OTA_BUFFER_LEN (512 + 1)

typedef struct
{
    int master_devid;
    int cloud_connected;
    int master_initialized;
    void *g_user_dispatch_thread;
    int g_user_dispatch_thread_running;
} living_platform_ctx_t;

extern int living_platform_main(void *paras);
extern living_platform_ctx_t *living_platform_get_ctx(void);

#endif

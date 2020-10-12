#ifndef __LIVING_PLATFORM_RAWDATA_MAIN_H__
#define __LIVING_PLATFORM_RAWDATA_MAIN_H__

#include <iotx_log.h>

//#define LIVING_PLATFORM_RAWDATA_PRODUCT_DYNAMIC_REGISTER

/*
Note:You can test some function to define LIVING_PLATFORM_RAWDATA_USE_UT_FOR_TESTING
*/
//#define LIVING_PLATFORM_RAWDATA_USE_UT_FOR_TESTING

#define living_platform_rawdata_debug(...) log_debug("ct", __VA_ARGS__)
#define living_platform_rawdata_info(...) log_info("ct", __VA_ARGS__)
#define living_platform_rawdata_warn(...) log_warning("ct", __VA_ARGS__)
#define living_platform_rawdata_err(...) log_err("ct", __VA_ARGS__)
#define living_platform_rawdata_crit(...) log_crit("ct", __VA_ARGS__)

#define LIVING_PLATFORM_RAWDATA_YIELD_TIMEOUT_MS (200)
#define LIVING_PLATFORM_RAWDATA_OTA_BUFFER_LEN (512 + 1) //Have to +1 or else ota SHA256 will crash

typedef struct
{
    int master_devid;
    int cloud_connected;
    int master_initialized;
    void *g_user_dispatch_thread;
    int g_user_dispatch_thread_running;
} living_platform_rawdata_ctx_t;

extern int living_platform_rawdata_main(void *paras);
extern living_platform_rawdata_ctx_t *living_platform_rawdata_get_ctx(void);

#endif

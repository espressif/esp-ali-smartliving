#ifndef __GATEWAY_MAIN_H__
#define __GATEWAY_MAIN_H__

#include <iotx_log.h>

#define gateway_debug(...) log_debug("gateway", __VA_ARGS__)
#define gateway_info(...) log_info("gateway", __VA_ARGS__)
#define gateway_warn(...) log_warning("gateway", __VA_ARGS__)
#define gateway_err(...) log_err("gateway", __VA_ARGS__)
#define gateway_crit(...) log_crit("gateway", __VA_ARGS__)

#define GATEWAY_YIELD_THREAD_NAME "linkkit_yield"
#define GATEWAY_YIELD_THREAD_STACKSIZE (8 * 1024)
#define GATEWAY_YIELD_TIMEOUT_MS (200)
#define GATEWAY_OTA_BUFFER_LEN (512)

//#define GATEWAY_SUPPORT_TOPO_CHANGE

typedef struct
{
    int master_devid;
    int cloud_connected;
    int master_initialized;
    int permit_join;
    char permit_join_pk[PRODUCT_KEY_MAXLEN];
    void *g_user_dispatch_thread;
    int g_user_dispatch_thread_running;
} gateway_ctx_t;

extern int gateway_main(void *paras);
extern gateway_ctx_t *gateway_get_ctx(void);

#endif

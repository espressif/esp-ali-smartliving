/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifndef __AWSS_DEV_AP_H__
#define __AWSS_DEV_AP_H__

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C"
{
#endif

typedef enum AWSS_MODE_t {
    AWSS_MODE_ZERO_CONFIG = 0,
    AWSS_MODE_DEVAP_CONFIG,
    AWSS_MODE_ONKEY_CONFIG,
    AWSS_MODE_BLE_CONFIG,
    AWSS_MODE_PHONEAP_CONFIG,
    AWSS_MODE_MAX
}awss_mode_t;

int awss_dev_ap_stop(void);
int awss_dev_ap_start(void);
int wifimgr_process_dev_ap_switchap_request(void *ctx, void *resource, void *remote, void *request);
int wifimgr_process_dev_errcode_request(void *ctx, void *resource, void *remote, void *request);
int wifimgr_process_dev_ap_mcast_get_dev_info(void *ctx, void *resource, void *remote, void *request);

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif

#endif


/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifndef __DEV_OFFLINE_OTA_H__
#define __DEV_OFFLINE_OTA_H__

#if defined(__cplusplus)
extern "C" {
#endif

#ifdef DEV_OFFLINE_OTA_ENABLE
#include "iot_export.h"

extern int wifimgr_process_dev_offline_ota_request(void *ctx, void *resource, void *remote, void *request);

#endif

#if defined(__cplusplus)
}       /* extern "C" */
#endif
#endif  /* __DEV_OFFLINE_OTA_H__ */

/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifndef _IOTX_AUTH_H_
#define _IOTX_AUTH_H_

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdio.h>
#include "iot_import.h"
#include "iot_export.h"
#include "utils_sysinfo.h"
#include "report.h"

/* domain type define */
typedef enum _DOMAIN_TYPE {
    GUIDER_DOMAIN_MQTT,
    GUIDER_DOMAIN_HTTP,
    GUIDER_DOMAIN_DYNAMIC_REGISTER_HTTP,
    GUIDER_DOMAIN_MAX
} domain_type_t;

int     iotx_guider_authenticate(iotx_conn_info_t *conn);
int     iotx_guider_set_custom_domain(int domain_type, const char *domain);
iotx_conn_info_pt iotx_conn_info_get(void);
int     iotx_facility_json_print(const char *str, int level, ...);

const char     *iotx_guider_get_domain(domain_type_t domain_type);

int iotx_device_info_get(iotx_device_info_t *device_info);

const char *iotx_ca_get(void);

iotx_conn_info_pt iotx_conn_info_get(void);
void iotx_conn_info_release(void);
iotx_conn_info_pt iotx_conn_info_reload(void);

void *iotx_event_callback(int evt);

#if defined(__cplusplus)
}
#endif
#endif

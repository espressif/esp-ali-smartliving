/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifndef __AWSS_MANUFACT_AP_FIND_H__
#define __AWSS_MANUFACT_AP_FIND_H__

#include <stdint.h>
#include "os.h"
#include "zconfig_ieee80211.h"

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C"
{
#endif

#ifdef MANUFACT_AP_FIND_ENABLE
int manufact_ap_info_set(char *p_ssid_manu, char *p_pwd);
int manufact_ap_find(char *p_ssid, char *p_pwd, uint8_t *p_bssid);
#endif

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif
#endif

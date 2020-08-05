/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifdef MANUFACT_AP_FIND_ENABLE
#include <stdio.h>
#include <stdint.h>
#include "iot_import.h"
#include "os.h"
#include "awss.h"
#include "awss_ap_scan.h"
#include "awss_manufact_ap_find.h"
#include "awss_log.h"

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C"
{
#endif

/* manufact self-def ap info related definition */
#define MANUFACT_AP_SSID_PREFIX         "ali_mprov_"

/* local static variables */
static char g_manufact_ap_ssid[OS_MAX_SSID_LEN + 1] = {0};
static char g_manufact_ap_pwd[OS_MAX_PASSWD_LEN + 1] = {0};

int manufact_ap_info_set(char *p_ssid_manu, char *p_pwd)
{
    if ((strlen(p_ssid_manu) == 0) || (strlen(p_ssid_manu) + strlen(MANUFACT_AP_SSID_PREFIX) > OS_MAX_SSID_LEN)) {
        awss_warn("Invalid manufact ssid in %s", __func__);
        return -1;
    }
    if ((strlen(p_pwd) < 8) || (strlen(p_pwd) > OS_MAX_PASSWD_LEN)) {
        awss_warn("Invalid manufact pwd in %s", __func__);
        return -1;
    }
    memset(g_manufact_ap_ssid, 0, sizeof(g_manufact_ap_ssid));
    memset(g_manufact_ap_pwd, 0, sizeof(g_manufact_ap_pwd));
    // manufact ssid must be "ali_mprov_xxxx"
    strncpy(g_manufact_ap_ssid, MANUFACT_AP_SSID_PREFIX, strlen(MANUFACT_AP_SSID_PREFIX));
    strncpy(g_manufact_ap_ssid + strlen(MANUFACT_AP_SSID_PREFIX), p_ssid_manu, strlen(p_ssid_manu));
    // manufact pwd length must be > 8
    strncpy(g_manufact_ap_pwd, p_pwd, strlen(p_pwd));
    return 0;
}

int manufact_ap_find(char *p_ssid, char *p_pwd, uint8_t *p_bssid)
{
    int result = -1;
    ap_scan_info_t scan_result;

    memset(&scan_result, 0, sizeof(ap_scan_info_t));

    result = awss_apscan_process(NULL, g_manufact_ap_ssid, &scan_result);

    if ( (result == 0) && (scan_result.found) ) {
        // manufact ap success found
        strncpy(p_ssid, g_manufact_ap_ssid, strlen(g_manufact_ap_ssid));
        strncpy(p_pwd, g_manufact_ap_pwd, strlen(g_manufact_ap_pwd));
        memcpy(p_bssid ,scan_result.mac, sizeof(scan_result.mac));
    }

    // Only find manuap once when dev init set the self-def ssid.
    memset(g_manufact_ap_ssid, 0, sizeof(g_manufact_ap_ssid));
    memset(g_manufact_ap_pwd, 0, sizeof(g_manufact_ap_pwd));

    return result;
}

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif
#endif

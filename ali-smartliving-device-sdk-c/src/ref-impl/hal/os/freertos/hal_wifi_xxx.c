#include <string.h>

#include "iot_import.h"

int HAL_Wifi_Enable_Mgmt_Frame_Filter(
    _IN_ uint32_t filter_mask,
    _IN_OPT_ uint8_t vendor_oui[3],
    _IN_ awss_wifi_mgmt_frame_cb_t callback)
{
    return 0;
}

int HAL_Wifi_Get_Ap_Info(char ssid[HAL_MAX_SSID_LEN], char passwd[HAL_MAX_PASSWD_LEN], uint8_t bssid[ETH_ALEN])
{
    return 0;
}

uint32_t HAL_Wifi_Get_IP(char ip_str[NETWORK_ADDR_LEN], const char *ifname)
{
    return 0;
}

char *HAL_Wifi_Get_Mac(char mac_str[HAL_MAC_LEN])
{
    return (char *)NULL;
}

int HAL_Wifi_Scan(awss_wifi_scan_result_cb_t cb)
{
    return 0;
}

int HAL_Wifi_Send_80211_Raw_Frame(_IN_ enum HAL_Awss_Frame_Type type,
                                  _IN_ uint8_t *buffer, _IN_ int len)
{
    return 0;
}

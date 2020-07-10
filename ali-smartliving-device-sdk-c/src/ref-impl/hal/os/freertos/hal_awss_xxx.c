#include <stdio.h>

#include "iot_import.h"

void HAL_Awss_Open_Monitor(_IN_ awss_recv_80211_frame_cb_t cb)
{
    if (!cb)
    {
        return;
    }
}

void HAL_Awss_Close_Monitor(void)
{
}

int HAL_Awss_Connect_Ap(
    _IN_ uint32_t connection_timeout_ms,
    _IN_ char ssid[HAL_MAX_SSID_LEN],
    _IN_ char passwd[HAL_MAX_PASSWD_LEN],
    _IN_OPT_ enum AWSS_AUTH_TYPE auth,
    _IN_OPT_ enum AWSS_ENC_TYPE encry,
    _IN_OPT_ uint8_t bssid[ETH_ALEN],
    _IN_OPT_ uint8_t channel)
{
    return FAIL_RETURN;
}
/*
range 0 1000
default 200
*/
int HAL_Awss_Get_Channelscan_Interval_Ms(void)
{
    return 200;
}
/*
range 0 1800000
default 180000
*/
int HAL_Awss_Get_Timeout_Interval_Ms(void)
{
    return 180000;
}

int HAL_Awss_Get_Encrypt_Type(void)
{
    return 3;
}

int HAL_Awss_Get_Conn_Encrypt_Type(void)
{
    char invalid_ds[DEVICE_SECRET_LEN + 1] = {0};
    char ds[DEVICE_SECRET_LEN + 1] = {0};

    HAL_GetDeviceSecret(ds);

    if (memcmp(invalid_ds, ds, sizeof(ds)) == 0)
        return 3;

    memset(invalid_ds, 0xff, sizeof(invalid_ds));
    if (memcmp(invalid_ds, ds, sizeof(ds)) == 0)
        return 3;

    return 4;
}

int HAL_Awss_Open_Ap(const char *ssid, const char *passwd, int beacon_interval, int hide)
{
    return (int)1;
}

int HAL_Awss_Close_Ap(void)
{
    return (int)1;
}

void HAL_Awss_Switch_Channel(char primary_channel, char secondary_channel, uint8_t bssid[ETH_ALEN])
{
}
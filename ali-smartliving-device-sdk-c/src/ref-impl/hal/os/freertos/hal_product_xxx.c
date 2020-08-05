#include <stdio.h>
#include <string.h>

#include "iot_import.h"

/**
 * @brief Get device name from user's system persistent storage
 *
 * @param [ou] device_name: array to store device name, max length is IOTX_DEVICE_NAME_LEN
 * @return the actual length of device name
 */
int HAL_GetDeviceName(char device_name[DEVICE_NAME_MAXLEN])
{
    //return actual length,must > 0
    return 0;
}

/**
 * @brief Get device secret from user's system persistent storage
 *
 * @param [ou] device_secret: array to store device secret, max length is IOTX_DEVICE_SECRET_LEN
 * @return the actual length of device secret
 */
int HAL_GetDeviceSecret(char device_secret[DEVICE_SECRET_MAXLEN])
{
    //return actual length,must > 0
    return 0;
}

/**
 * @brief Get product key from user's system persistent storage
 *
 * @param [ou] product_key: array to store product key, max length is IOTX_PRODUCT_KEY_LEN
 * @return  the actual length of product key
 */
int HAL_GetProductKey(char product_key[PRODUCT_KEY_MAXLEN])
{
    //return actual length,must > 0
    return 0;
}

int HAL_GetProductSecret(char product_secret[PRODUCT_SECRET_MAXLEN])
{
    //return actual length,must > 0
    return 0;
}

/**
 * @brief Get firmware version
 *
 * @param [ou] version: array to store firmware version, max length is IOTX_FIRMWARE_VER_LEN
 * @return the actual length of firmware version
 */
int HAL_GetFirmwareVersion(char *version)
{
    char firmware_ver[FIRMWARE_VERSION_MAXLEN];

    if (!version)
    {
        return 0;
    }

    memset(version, 0, FIRMWARE_VERSION_MAXLEN);
    HAL_Snprintf(firmware_ver, FIRMWARE_VERSION_MAXLEN, "app-1.6.0-%s-%s", __DATE__, __TIME__);

    memcpy(version, firmware_ver, strlen(firmware_ver));

    return strlen(firmware_ver);
}

int HAL_SetDeviceName(char *device_name)
{
    return 0;
}

int HAL_SetDeviceSecret(char *device_secret)
{
    return 0;
}

int HAL_SetProductKey(char *product_key)
{
    return 0;
}

int HAL_SetProductSecret(char *product_secret)
{
    return 0;
}

#define __DEMO__

int HAL_GetPartnerID(char *pid_str)
{
    memset(pid_str, 0x0, PID_STRLEN_MAX);
#ifdef __DEMO__
    strcpy(pid_str, "Your company name");
#endif
    return strlen(pid_str);
}

int HAL_GetModuleID(char *mid_str)
{
    memset(mid_str, 0x0, MID_STRLEN_MAX);
#ifdef __DEMO__
    strcpy(mid_str, "Your module name");
#endif
    return strlen(mid_str);
}

char *HAL_GetChipID(_OU_ char *cid_str)
{
    memset(cid_str, 0x0, HAL_CID_LEN);
#ifdef __DEMO__
    strncpy(cid_str, "12345678", HAL_CID_LEN);
    cid_str[HAL_CID_LEN - 1] = '\0';
#endif
    return cid_str;
}

int HAL_GetDeviceID(_OU_ char *device_id)
{
    char pk[PRODUCT_KEY_MAXLEN];
    char dn[DEVICE_NAME_MAXLEN];

    memset(device_id, 0x0, DEVICE_ID_LEN);
    memset(pk, 0x0, PRODUCT_KEY_MAXLEN);
    memset(dn, 0x0, DEVICE_NAME_MAXLEN);

    HAL_GetProductKey(pk);
    HAL_GetDeviceName(dn);

    HAL_Snprintf(device_id, DEVICE_ID_LEN, "%s.%s", pk, dn);

    return strlen(device_id);
}

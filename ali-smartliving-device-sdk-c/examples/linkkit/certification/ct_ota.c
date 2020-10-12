#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "iot_import.h"
#include "iotx_log.h"

#include "ct_main.h"
#include "ct_entry.h"
#include "ct_ut.h"

#ifdef OTA_ENABLED
#ifdef BUILD_AOS
#include "ota_service.h"
#else
#include "dm_ota.h"
#endif
#endif

#include "ct_ota.h"

#ifdef OTA_ENABLED

static int ota_get_kv_size(void)
{
    int ret = 0;
    char ota_size[OTA_DESC_KV_KEY_SIZE_LEN] = {0};
    int len = OTA_DESC_KV_KEY_SIZE_LEN - 1;

    ret = HAL_Kv_Get(OTA_DESC_KV_KEY_SIZE, ota_size, &len);
    if (ret == 0)
    {
        return atoi(ota_size);
    }

    return -1;
}

static int ota_get_kv_version(char version[OTA_DESC_KV_KEY_VERSION_LEN])
{
    int ret = 0;
    char ota_ver[OTA_DESC_KV_KEY_VERSION_LEN] = {0};
    int len = OTA_DESC_KV_KEY_VERSION_LEN - 1;

    ret = HAL_Kv_Get(OTA_DESC_KV_KEY_VERSION, ota_ver, &len);
    if (ret == 0)
    {
        memcpy(version, ota_ver, strlen(ota_ver));
    }

    return ret;
}

static int ota_get_kv_md5(char md5[OTA_DESC_KV_KEY_MD5_LEN])
{
    int ret = 0;
    char ota_md5[OTA_DESC_KV_KEY_MD5_LEN] = {0};
    int len = OTA_DESC_KV_KEY_MD5_LEN - 1;

    ret = HAL_Kv_Get(OTA_DESC_KV_KEY_MD5, ota_md5, &len);
    if (ret == 0)
    {
        memcpy(md5, ota_md5, strlen(ota_md5));
    }

    return ret;
}

static int ota_get_kv_url(char url[OTA_DESC_KV_KEY_URL_LEN])
{
    int ret = 0;
    char ota_url[OTA_DESC_KV_KEY_URL_LEN] = {0};
    int len = OTA_DESC_KV_KEY_URL_LEN - 1;

    ret = HAL_Kv_Get(OTA_DESC_KV_KEY_URL, ota_url, &len);
    if (ret == 0)
    {
        memcpy(url, ota_url, strlen(ota_url));
    }

    return ret;
}

#ifdef BUILD_AOS
int ct_ota_download(ota_service_t *p_ota_ctx)
{
    int ret = 0;
    char *p_ota_desc_data = NULL;
    int size = 0;
    char version[OTA_DESC_KV_KEY_VERSION_LEN] = {0};
    char md5[OTA_DESC_KV_KEY_MD5_LEN] = {0};
    char url[OTA_DESC_KV_KEY_URL_LEN] = {0};

    if (p_ota_ctx == NULL)
    {
        ct_err("param err");
        return -1;
    }

    size = ota_get_kv_size();
    ota_get_kv_version(version);
    ota_get_kv_md5(md5);
    ota_get_kv_url(url);

    if (strlen(md5) < 32 || strlen(version) < 1 ||
        strlen(url) < 10 || size < 1)
    {
        ct_err("err ota:size(%d) version(%s) md5(%s) url(%s)", size, version, md5, url);
        return -1;
    }

    ct_info("ct ota:size(%d) version(%s) md5(%s) url(%s)", size, version, md5, url);
    p_ota_desc_data = HAL_Malloc(OTA_DESC_DATA_LEN);
    if (!p_ota_desc_data)
    {
        ct_err("no mem");
        return -1;
    }

    HAL_Snprintf(p_ota_desc_data, OTA_DESC_DATA_LEN,
                 OTA_DESC_DATA_FMT, size, md5,
                 version, url, md5);

    ret = p_ota_ctx->upgrade_cb(p_ota_ctx, p_ota_desc_data);

    if (p_ota_desc_data)
    {
        HAL_Free(p_ota_desc_data);
    }

    return ret;
}
#else
int ct_ota_download(void)
{
    int ret = 0;
    char *p_ota_desc_data = NULL;
    int size = 0;
    char version[OTA_DESC_KV_KEY_VERSION_LEN] = {0};
    char md5[OTA_DESC_KV_KEY_MD5_LEN] = {0};
    char url[OTA_DESC_KV_KEY_URL_LEN] = {0};

    size = ota_get_kv_size();
    ota_get_kv_version(version);
    ota_get_kv_md5(md5);
    ota_get_kv_url(url);

    if (strlen(md5) < 32 || strlen(version) < 1 ||
        strlen(url) < 10 || size < 1)
    {
        ct_err("param err");
        return -1;
    }

    ct_info("ct ota:size(%d) version(%s) md5(%s) url(%s)", size, version, md5, url);
    p_ota_desc_data = HAL_Malloc(OTA_DESC_DATA_LEN);
    if (!p_ota_desc_data)
    {
        ct_err("no mem");
        return -1;
    }

    HAL_Snprintf(p_ota_desc_data, OTA_DESC_DATA_LEN,
                 OTA_DESC_DATA_FMT, size, md5,
                 version, url, md5);

//If not fy 1.5.0 or larger version,please add dm_ota_download to dm_ota.c
#ifdef CT_FY_SDK_VERSION_1_5
    ret = dm_ota_download(p_ota_desc_data, strlen(p_ota_desc_data));
#endif

    if (p_ota_desc_data)
    {
        HAL_Free(p_ota_desc_data);
    }

    return ret;
}
#endif
#endif

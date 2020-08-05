#ifndef __CT_OTA_H__
#define __CT_OTA_H__

//#define CT_DOWNLOAD_OTA_WHEN_CONNECT_CLOUD

#ifdef OTA_ENABLED

#define OTA_DESC_DATA_LEN (1024)
#define OTA_DESC_DATA_FMT "{\"code\":\"1000\",\"data\":{\"size\":%d,\"sign\":\"%s\",\"version\":\"%s\",\"url\":\"%s\",\"signMethod\":\"Md5\",\"md5\":\"%s\"},\"id\":1583301049684,\"message\":\"success\"}"

#define OTA_DESC_KV_KEY_SIZE "ct_ota_size"
#define OTA_DESC_KV_KEY_VERSION "ct_ota_ver"
#define OTA_DESC_KV_KEY_MD5 "ct_ota_md5"
#define OTA_DESC_KV_KEY_URL "ct_ota_url"

#define OTA_DESC_KV_KEY_SIZE_LEN (16)
#define OTA_DESC_KV_KEY_VERSION_LEN (64)
#define OTA_DESC_KV_KEY_MD5_LEN (33)
#define OTA_DESC_KV_KEY_URL_LEN (1024)

#ifdef BUILD_AOS
#include "ota_service.h"
int ct_ota_download(ota_service_t *p_ota_ctx);
#else
int ct_ota_download(void);
#endif
#endif

#endif

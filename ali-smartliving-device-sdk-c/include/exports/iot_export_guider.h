#ifndef __IOT_EXPORT_GUIDER_H__
#define __IOT_EXPORT_GUIDER_H__

#define GUIDER_ENV_LEN (10)
#define GUIDER_ENV_KEY "env"

typedef enum _region_type_e
{
    REGION_TYPE_ID = 0,
    REGION_TYPE_MQTTURL,
    REGION_TYPE_MAX
} region_type_e;

typedef enum _guider_env_e
{
    GUIDER_ENV_DAILY = 1,
    GUIDER_ENV_PRERELEASE,
    GUIDER_ENV_ONLINE,
    GUIDER_ENV_MAX
} guider_env_e;

DLL_IOT_API int iotx_guider_set_dynamic_mqtt_url(char *p_mqtt_url);
DLL_IOT_API int iotx_guider_set_dynamic_region(int region);
DLL_IOT_API int iotx_guider_clear_dynamic_url(void);
DLL_IOT_API int iotx_guider_fill_conn_string(char *dst, int len, const char *fmt, ...);
DLL_IOT_API int iotx_redirect_region_subscribe(void);
DLL_IOT_API int iotx_reconnect_region_subscribe(void);
DLL_IOT_API int iotx_guider_get_kv_env(void);
DLL_IOT_API guider_env_e iotx_guider_get_env(void);
DLL_IOT_API iotx_cloud_region_types_t iotx_guider_get_region(void);
DLL_IOT_API int iotx_guider_get_region_id(void);
DLL_IOT_API int guider_set_direct_connect_count(unsigned char count);
#endif

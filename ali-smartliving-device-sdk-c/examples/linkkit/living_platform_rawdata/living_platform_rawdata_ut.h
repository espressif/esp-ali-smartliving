#ifndef __LIVING_PLATFORM_RAWDATA_UT_H__
#define __LIVING_PLATFORM_RAWDATA_UT_H__

#define KV_KEY_PK "pk"
#define KV_KEY_PS "ps"
#define KV_KEY_DN "dn"
#define KV_KEY_DS "ds"

#define MAX_KEY_LEN (6)

#define PRODUCT_KEY "PK_XXXXXX"
#define PRODUCT_SECRET "PS_XXXXXX"
#define DEVICE_NAME "DN_XXXXXX"
#define DEVICE_SECRET "DS_XXXXXX"

#define EXAMPLE_MASTER_DEVID (0)

typedef struct _living_platform_rawdata_tsl_s
{
    char LightSwitch;
} living_platform_rawdata_tsl_t;

extern int living_platform_rawdata_ut_init(void);
extern void living_platform_rawdata_ut_misc_process(uint64_t time_now_sec);
extern living_platform_rawdata_tsl_t* living_platform_rawdata_ut_get_tsl_data(void);
extern int living_platform_rawdata_ut_set_LightSwitch(char LightSwitch);
extern int living_platform_rawdata_ut_get_LightSwitch(void);
#endif

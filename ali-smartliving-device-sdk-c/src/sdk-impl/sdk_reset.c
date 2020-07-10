#include "iot_import.h"

#ifdef BUILD_AOS
extern void netmgr_clear_ap_config(void);
#endif

int iotx_sdk_reset_cloud(iotx_vendor_dev_reset_type_t *reset_type)
{
    return awss_report_reset(reset_type);
}

int iotx_sdk_reset_local(void)
{
    int ret = 0;

#ifdef BUILD_AOS
    netmgr_clear_ap_config();
#endif

    ret = iotx_guider_clear_dynamic_url();

#if defined(SUPPORT_TLS) && defined(BUILD_AOS)
    ret |= HAL_SSL_Del_KV_Session_Ticket();
#endif

    return ret;
}

int iotx_sdk_reset(iotx_vendor_dev_reset_type_t *reset_type)
{
    iotx_sdk_reset_cloud(reset_type);
    iotx_sdk_reset_local();

    return 0;
}

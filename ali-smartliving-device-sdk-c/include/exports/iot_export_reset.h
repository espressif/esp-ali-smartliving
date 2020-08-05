#ifndef __IOT_EXPORT_RESET_H__
#define __IOT_EXPORT_RESET_H__

extern int iotx_sdk_reset_local(void);
extern int iotx_sdk_reset_cloud(iotx_vendor_dev_reset_type_t *reset_type);
extern int iotx_sdk_reset(iotx_vendor_dev_reset_type_t *reset_type);

#endif

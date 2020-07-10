/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifndef __IOT_EXPORT_AWSS_H__
#define __IOT_EXPORT_AWSS_H__

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

typedef enum {
    IOTX_VENDOR_DEV_RESET_TYPE_UNBIND_ONLY         = 0,
    IOTX_VENDOR_DEV_RESET_TYPE_UNBIND_SHADOW_CLEAR = 1,
    IOTX_VENDOR_DEV_RESET_TYPE_UNBIND_ALL_CLEAR    = 2,
	IOTX_VENDOR_DEV_RESET_TYPE_INVALID
} iotx_vendor_dev_reset_type_t;

/* AP information scaned by device */
typedef struct {
    uint8_t found;                        // AP found or not, 0-not found, 1-designated AP success found 
	uint8_t auth;
	uint8_t channel;
	uint8_t encry[2];
	uint8_t mac[6];
	char ssid[33];
	signed char rssi;
} ap_scan_info_t;

/**
 * @brief   start wifi setup service
 *
 * @retval  -1 : wifi setup fail
 * @retval  0 : sucess
 * @note: awss_report_cloud must been called to enable wifi setup service
 */
DLL_IOT_API int awss_start();

/**
 * @brief   stop wifi setup service
 *
 * @retval  -1 : failure
 * @retval  0 : sucess
 * @note
 *      if awss_stop is called before exit of awss_start, awss and notify will stop.
 *      it may cause failutre of awss and device bind.
 */
DLL_IOT_API int awss_stop();

/**
 * @brief   make sure user touches device belong to themselves
 *
 * @retval  -1 : failure
 * @retval  0 : sucess
 * @note: AWSS dosen't parse awss packet until user touch device using this api.
 */
DLL_IOT_API int awss_config_press();

/**
 * @brief   report token to cloud after wifi setup success
 *
 * @retval  -1 : failure
 * @retval  0 : sucess
 */
DLL_IOT_API int awss_report_cloud();

/**
 * @brief   report reset to cloud.
 *
 * @retval  -1 : failure
 * @retval  0 : sucess
 * @note
 *      device will save reset flag if device dosen't connect cloud, device will fails to send reset to cloud.
 *      when connection between device and cloud is ready, device will retry to report reset to cloud.
 */
DLL_IOT_API int awss_report_reset(iotx_vendor_dev_reset_type_t *reset_type);

/**
 * @brief start wifi provision through device softap
 *
 * @retval  -1 : failure
 * @retval  0 : sucess
 * @note
 *      1. if awss_stop or awss_dev_ap_stop is called before exit of awss_dev_ap_start
 *         awss with device ap and notify will stop, it may cause failutre of device ap
 *         and device bind.
 *      2. awss_dev_ap_start doesn't need to call awss_config_press to been enabled.
 */
DLL_IOT_API int awss_dev_ap_start(void);

/**
 * @brief stop wifi provision through device softap
 *
 * @retval  -1 : failure
 * @retval  0 : sucess
 * @note
 *      if awss_dev_ap_stop is called before exit of awss_dev_ap_start
 *      awss with device ap and notify will stop, it may cause failutre of device ap
 */
DLL_IOT_API int awss_dev_ap_stop(void);

#ifdef AWSS_BATCH_DEVAP_ENABLE
/**
 * @brief callback registered for listening "awss mode switch" command
 *
 * @param [in] awss_new_mode: parsed from "awss mode switch" command, switch to other provision mode
 * @param [in] new_mode_timeout: switch to other provision mode for x(10s), unit is 10 seconds
 * @param [in] fix_channel: if not 0, awss_new_mode must work on fix_channel
 */
typedef int (*awss_modeswitch_cb_t)(uint8_t awss_new_mode, uint8_t new_mode_timeout, uint8_t fix_channel);

/**
 * @brief register awss mode switch listener when in device softap wifi provision mode
 *
 * @param [in] callback registered for listening "awss mode switch" command
 *
 * @retval  -1 : failure
 * @retval  0 : sucess
 * @note
 *      used for device softap wifi provision to support "Wifi batch provision"
 *      when device in softap wifi provision mode, and "Wifi batch provision" feature is 
 *      enabled, device listening "awss mode switch" command over the air, when 
 *      "awss mode switch" command received, registered callback will be invoked to 
 *      inform device to stop softap provision mode, and switch to "awss_new_mode" provision
 *      mode for "new_mode_timeout" time, when "new_mode_timeout" timeout and awss_new_mode
 *      provision is not processing, device will switch back to softap wifi provision mode
 */
DLL_IOT_API int awss_dev_ap_reg_modeswit_cb(awss_modeswitch_cb_t callback);
#endif

/**
 * @brief do AP scan for a time, and get the detail AP info in scan result
 * 
 * @param [in] p_scan_time: AP scanning takes time
 * @param [in] p_scan_ssid: ssid of AP to scan
 * @param [in] p_scan_result: detail AP info in scan result
 *
 * @retval  -1 : failure
 * @retval  0 : sucess
 * @note
 *      this function can only be called in station(not connected with AP) mode
 */
DLL_IOT_API int awss_apscan_process(uint32_t *p_scan_time, char *p_scan_ssid, ap_scan_info_t *p_scan_result);

DLL_IOT_API int awss_check_reset(iotx_vendor_dev_reset_type_t *reset_type);

DLL_IOT_API int awss_clear_reset(void);

DLL_IOT_API int awss_handle_reset_cloud_reply(void);

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif

#endif

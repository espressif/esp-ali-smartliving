/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifndef __IOT_EXPORT_AWSS_H__
#define __IOT_EXPORT_AWSS_H__

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

#define AWSS_KV_RST_FLAG                "awss.rst.flag"

/**
 * @brief   start wifi setup service
 *
 * @retval  -1 : wifi setup fail
 * @retval  0 : sucess
 * @note: awss_config_press must been called to enable wifi setup service
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

typedef int (*awss_modeswitch_cb_t)(uint8_t awss_new_mode, uint8_t new_mode_timeout, uint8_t fix_channel);
DLL_IOT_API int awss_dev_ap_reg_modeswit_cb(awss_modeswitch_cb_t callback);

/**
 * @brief   start wifi setup service with device ap
 *
 * @retval  -1 : failure
 * @retval  0 : sucess
 * @note
 *      1. if awss_stop or awss_dev_ap_stop is called before exit of awss_dev_ap_start
 *         awss with device ap and notify will stop, it may cause failutre of device ap
 *         and device bind.
 *      2. awss_dev_ap_start doesn't need to call awss_config_press to been enabled.
 */
DLL_IOT_API int awss_dev_ap_start();

/**
 * @brief   stop wifi setup service with device ap
 *
 * @retval  -1 : failure
 * @retval  0 : sucess
 * @note
 *      if awss_dev_ap_stop is called before exit of awss_dev_ap_start
 *      awss with device ap and notify will stop, it may cause failutre of device ap
 */
DLL_IOT_API int awss_dev_ap_stop();

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
DLL_IOT_API int awss_report_reset();

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif

#endif

#ifndef __AWSS_RESET__
#define __AWSS_RESET__

#define AWSS_RESET_PKT_LEN         (256)
#define AWSS_RESET_TOPIC_LEN       (128)
#define AWSS_RESET_MSG_ID_LEN      (16)

#define TOPIC_RESET_REPORT         "/sys/%s/%s/thing/reset"
#define TOPIC_RESET_REPORT_REPLY   "/sys/%s/%s/thing/reset_reply"
#define METHOD_RESET_REPORT        "thing.reset"

#define AWSS_RESET_REQ_FMT         "{\"id\":%s, \"version\":\"1.0\", \"method\":\"%s\", \"params\":{\"resetKey\":{\"devReset\":\"%d\"}}}"

#define AWSS_KV_RST                "awss.rst"
#define AWSS_KV_RST_TYPE           "awss.rst.type"

/**
 * @brief   stop to report reset to cloud.
 *
 * @retval  -1 : failure
 * @retval  0 : sucess
 * @note
 *      just stop report reset to cloud without any touch reset flag in flash.
 */
int awss_stop_report_reset();
int awss_report_reset_to_cloud(iotx_vendor_dev_reset_type_t* reset_type);
#ifdef CLOUD_OFFLINE_RESET
void offline_reset_init();
void offline_reset_deinit();
#endif

#endif

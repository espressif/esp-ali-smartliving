#ifndef __DIAGNOSIS_OFFLINE_LOG_H__
#define __DIAGNOSIS_OFFLINE_LOG_H__

#define OFFLINE_LOG_VERSION "1.0"

//#define DO_BASE64_ENCODE_WHEN_NOT_UTF8

#define TOPIC_URL_LEN (128)
#define LOG_NAME_LEN (128)
#define HTTP_SERVER_URL_LEN (64)
#define TOKEN_LEN (33)

#define LOG_HEAD_LEN (16)
#define LOG_BUFFER_SIZE (256)
#define LOG_BUFFER_MAX_SIZE (2 * 1024)

#define DIGEST_LEN (64)
#define MESSAGE_LEN (256)

#define PORT_MAX_LEN (6)
#define OFFLINE_LOG_PARTITION HAL_PARTITION_PARAMETER_3

#define UPLOAD_RETRY_MAX_COUNT (3)
#define HTTP_TIMEOUT (5000)
#define HTTP_REQUEST_PAYLOAD_LEN (256)
#define HTTP_RESPONSE_PAYLOAD_LEN (128)

#define REQUEST_PAYLOAD_FMT "{\"logName\":\"%s\",\"sign\":\"%s\",\"index\":%d,\"rawSize\":%d,\"data\":\"%s\"}"
#define TOPIC_OFFLINE_LOG_GET_REPLY "/sys/%s/%s/device/log/get_reply"
#define TOPIC_DEV_OFFLINE_LOG_FINISH_REPLY "/sys/%s/%s/device/log/get/finish_reply"
#define OFFLINE_LOG_FINISH_METHOD "device.log.get.finish"

#define REPLAY_FINISH_PAYLOAD_LEN (64)
#define REPLAY_PAYLOAD_LEN (256)

#define GET_REPLY_FMT "{\"id\":%s,\"code\":%d,\"data\":%s}"
#define GET_REPLY_DATA_FLASH_FMT "{\"version\":\"%s\",\"signSecretType\":%d,\"logNameSign\":\"%s\",\"logMode\":%d,\"logSize\":%d,\"fragmentCount\":%d}"
#define GET_REPLY_DATA_MEM_FMT "{\"version\":\"%s\",\"signSecretType\":%d,\"logNameSign\":\"%s\",\"logMode\":%d}"

#define PARAMS_HTTPSERVERURL "params.httpServerURL"
#define PARAMS_LOGNAME "params.logName"
#define PARAMS_TOKEN "params.token"
#define PARAMS_LOGMODE "params.logMode"

#define OFFLINE_LOG_WORKING_TIME (5 * 60 * 1000)

typedef enum _log_respose_code_e
{
    LOG_RESPONSE_CODE_OK = 200,
    LOG_RESPONSE_CODE_NOT_FOUND = 404,
    LOG_RESPONSE_CODE_FAILED = 10000
} log_respose_code_e;

typedef enum _respose_code_e
{
    RESPONSE_CODE_OK = 200,
    RESPONSE_CODE_NO_PAYLOAD = 10000,
    RESPONSE_CODE_PARSE_JSON_FAILED,
    RESPONSE_CODE_METHOD_NOT_MATCH
} respose_code_e;

typedef enum _upload_log_mode_e
{
    UPLOAD_LOG_MODE_FLASH = 0,
    UPLOAD_LOG_MODE_MEM = 1,
    UPLOAD_LOG_MODE_INVALID
} upload_log_mode_e;

typedef enum _oll_status_e
{
    OLL_UNINITED = 0,
    OLL_INITED = 1,
    OLL_STOPPED
} oll_status_e;

typedef struct _log_flash_desc_s
{
    unsigned int total_size;
    unsigned int crc;
} __attribute__((packed, aligned(1))) log_flash_desc_t;

typedef struct _diagnosis_offline_log_s
{
    char logName[LOG_NAME_LEN];
    char httpServerURL[HTTP_SERVER_URL_LEN];
    char token[TOKEN_LEN];
    char log_mode;
    int port;

    char *p_log_buffer;
    unsigned int log_buffer_pos;

    unsigned char has_flash_log;
    unsigned char mem_log_index;
    log_flash_desc_t log_flash_desc;

    aos_mutex_t offline_log_mutex;
} diagnosis_offline_log_t;

#ifdef OFFLINE_LOG_UT_TEST
extern int diagnosis_offline_log_upload(const char *host, int port);
extern int diagnosis_offline_log_read_all(upload_log_mode_e log_mode);
#endif
#endif

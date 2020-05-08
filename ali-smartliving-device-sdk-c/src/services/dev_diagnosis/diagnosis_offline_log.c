#ifdef DEV_OFFLINE_LOG_ENABLE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <hal/soc/flash.h>

#include "iotx_system.h"
#include "iot_import.h"
#include "iot_export.h"
#include "iotx_utils.h"
#include "awss_cmp.h"

#include "dev_diagnosis_log.h"
#include "diagnosis_offline_log.h"
#include "iot_export_diagnosis.h"

#define CRC32_SEED 0xFFFFFFFF
#define POLY32 0x04C11DB7

#define MEM_FLAG "offline.log"
#define OFFLINE_LOG_MALLOC(size) LITE_malloc(size, MEM_MAGIC, MEM_FLAG)
#define OFFLINE_LOG_FREE(ptr) LITE_free(ptr)

#define RESPONSE_ID "id"
#define RESPONSE_CODE "code"
#define RESPONSE_MESSAGE "message"

static diagnosis_offline_log_t *p_log_ctx = NULL;
static char is_inited = 0;
static char no_mem_err[] = "no mem";
static int offline_log_http_upload(int index, char *payload, int payload_len);

static int log_flash_read(uint32_t pos, void *buf, size_t nbytes)
{
    uint32_t offset = pos;

    return hal_flash_read((hal_partition_t)OFFLINE_LOG_PARTITION, &offset, buf, nbytes);
}

static int log_flash_write(uint32_t pos, const void *buf, size_t nbytes)
{
    uint32_t offset = pos;

    return hal_flash_write((hal_partition_t)OFFLINE_LOG_PARTITION, &offset, buf, nbytes);
}

static int log_flash_erase(uint32_t pos, uint32_t size)
{
    uint32_t offset = pos;

    return hal_flash_erase((hal_partition_t)OFFLINE_LOG_PARTITION, offset, size);
}

static uint32_t utils_crc32(uint8_t *buf, uint32_t length)
{
    uint8_t i;
    uint32_t crc = CRC32_SEED; // Initial value

    while (length--)
    {
        crc ^= (uint32_t)(*buf++) << 24; // crc ^=(uint32_t)(*data)<<24; data++;
        for (i = 0; i < 8; ++i)
        {
            if (crc & 0x80000000)
            {
                crc = (crc << 1) ^ POLY32;
            }
            else
            {
                crc <<= 1;
            }
        }
    }

    return crc;
}

int diagnosis_offline_log_init(void)
{
    int ret = 0;

    if (is_inited == 1)
    {
        diagnosis_warn("inited");
        return 0;
    }

    p_log_ctx = (diagnosis_offline_log_t *)OFFLINE_LOG_MALLOC(sizeof(diagnosis_offline_log_t));
    if (!p_log_ctx)
    {
        diagnosis_err("%s", no_mem_err);
        return -1;
    }

    memset(p_log_ctx, 0, sizeof(diagnosis_offline_log_t));

    p_log_ctx->p_log_buffer = (char *)OFFLINE_LOG_MALLOC(LOG_BUFFER_MAX_SIZE); //Malloc for first fragment
    if (!p_log_ctx->p_log_buffer)
    {
        diagnosis_err("%s", no_mem_err);
        return -1;
    }

    p_log_ctx->log_buffer_pos = 0;
    memset(p_log_ctx->p_log_buffer, '\0', LOG_BUFFER_MAX_SIZE);

    if ((ret = aos_mutex_new(&p_log_ctx->offline_log_mutex)) != 0)
    {
        diagnosis_err("%s", no_mem_err);
        return ret;
    }

    is_inited = 1;

    return 0;
}

int diagnosis_offline_log_deinit(void)
{
    if (is_inited == 0)
    {
        diagnosis_warn("no init");
        return -1;
    }

    if (p_log_ctx)
    {
        OFFLINE_LOG_FREE(p_log_ctx);
        p_log_ctx = NULL;
    }

    aos_mutex_free(&p_log_ctx->offline_log_mutex);

    is_inited = 0;

    return 0;
}

static int offline_log_write_buffer(const char *log_level, const char *fmt, va_list *ap)
{
    int writed_len = 0;
    char uptime[LOG_HEAD_LEN];
    char log_head[LOG_HEAD_LEN];

    if (is_inited == 0)
    {
        diagnosis_offline_log_init();
    }

    if (p_log_ctx->log_buffer_pos == LOG_BUFFER_MAX_SIZE - 1)
    {
        diagnosis_warn("buf full");
        return -1;
    }

    memset(log_head, '\0', sizeof(log_head));
    HAL_Snprintf(uptime, LOG_HEAD_LEN, "[%06d]", (unsigned)HAL_UptimeMs());
    HAL_Snprintf(log_head, LOG_HEAD_LEN, "%s%s ", uptime, log_level);

    if (p_log_ctx->log_buffer_pos + strlen(log_head) > LOG_BUFFER_MAX_SIZE)
    {
        diagnosis_warn("buf full");
        memcpy(p_log_ctx->p_log_buffer + p_log_ctx->log_buffer_pos, log_head, LOG_BUFFER_MAX_SIZE - 1 - p_log_ctx->log_buffer_pos);
        p_log_ctx->log_buffer_pos = LOG_BUFFER_MAX_SIZE - 1;

        return -1;
    }

    memcpy(p_log_ctx->p_log_buffer + p_log_ctx->log_buffer_pos, log_head, strlen(log_head));
    p_log_ctx->log_buffer_pos += strlen(log_head);

    writed_len = HAL_Vsnprintf(p_log_ctx->p_log_buffer + p_log_ctx->log_buffer_pos, LOG_BUFFER_MAX_SIZE - p_log_ctx->log_buffer_pos, fmt, *ap);

    if (writed_len > LOG_BUFFER_MAX_SIZE - p_log_ctx->log_buffer_pos)
    {
        p_log_ctx->log_buffer_pos = LOG_BUFFER_MAX_SIZE - 1;
    }
    else
    {
        p_log_ctx->log_buffer_pos += writed_len;
    }

    //upload memory log
    if (p_log_ctx->is_diagnosising == 1 && p_log_ctx->has_flash_log == 0)
    {
        if (p_log_ctx->log_buffer_pos > LOG_BUFFER_SIZE)
        {
            if (0 == offline_log_http_upload(p_log_ctx->mem_log_index++, p_log_ctx->p_log_buffer, p_log_ctx->log_buffer_pos))
            {
                memset(p_log_ctx->p_log_buffer, '\0', p_log_ctx->log_buffer_pos);
                p_log_ctx->log_buffer_pos = 0;
            }
        }
    }

    return writed_len;
}

int diagnosis_offline_log(log_level_e level, const char *fmt, ...)
{
    char *p_level = NULL;
    va_list ap;
    va_start(ap, fmt);

    switch (level)
    {
    case LOG_LEVEL_D:
        p_level = "<D>";
        break;
    case LOG_LEVEL_I:
        p_level = "<I>";
        break;
    case LOG_LEVEL_W:
        p_level = "<W>";
        break;
    case LOG_LEVEL_E:
        p_level = "<E>";
        break;
    default:
        p_level = "<I>";
        break;
    }

    offline_log_write_buffer(p_level, fmt, &ap);

    va_end(ap);

    return 0;
}

int diagnosis_offline_log_save_all(void)
{
    if (is_inited == 0)
    {
        diagnosis_warn("no init");
        return -1;
    }

    if (aos_mutex_lock(&p_log_ctx->offline_log_mutex, AOS_WAIT_FOREVER) != 0)
    {
        diagnosis_err("lock fail");
        return -1;
    }

    log_flash_erase(0, LOG_BUFFER_MAX_SIZE + sizeof(log_flash_desc_t)); //erase flash before write

    log_flash_write(0, p_log_ctx->p_log_buffer, p_log_ctx->log_buffer_pos);

    p_log_ctx->log_flash_desc.total_size = p_log_ctx->log_buffer_pos;
    p_log_ctx->log_flash_desc.crc = utils_crc32((uint8_t *)p_log_ctx->p_log_buffer, p_log_ctx->log_buffer_pos);

    log_flash_write(LOG_BUFFER_MAX_SIZE, &p_log_ctx->log_flash_desc, sizeof(log_flash_desc_t));

    if (aos_mutex_unlock(&p_log_ctx->offline_log_mutex) != 0)
    {
        diagnosis_err("unlock fail");
        return -1;
    }

    diagnosis_info("\nSave Total:%d CRC:0x%x\n", p_log_ctx->log_flash_desc.total_size, p_log_ctx->log_flash_desc.crc);
    
    return 0;
}

static int offline_log_upload_by_http(const char *url, int port, char *request_payload, int request_payload_len, char *response_payload, int response_payload_len)
{
    int ret = 0;
    httpclient_t http_client;
    httpclient_data_t http_client_data;
    lite_cjson_t lite, lite_item_code, lite_item_data, lite_item_ds;

    memset(&http_client, 0, sizeof(httpclient_t));
    memset(&http_client_data, 0, sizeof(httpclient_data_t));

    http_client.header = "Accept:*/*\r\n";

    http_client_data.post_content_type = "application/json;charset=utf-8";
    http_client_data.post_buf = request_payload;
    http_client_data.post_buf_len = request_payload_len;
    http_client_data.response_buf = response_payload;
    http_client_data.response_buf_len = response_payload_len;

    /* 
    if (strstr(url, "https://"))
    {
        ret = httpclient_common(&http_client, url, port, iotx_ca_get(), HTTPCLIENT_POST, HTTP_TIMEOUT, &http_client_data);
    }
    else
    {
        ret = httpclient_common(&http_client, url, port, NULL, HTTPCLIENT_POST, HTTP_TIMEOUT, &http_client_data);
        //iotx_post(&http_client, url, port, NULL, &http_client_data);
    }*/

    //Use http
    ret = httpclient_common(&http_client, url, port, NULL, HTTPCLIENT_POST, HTTP_TIMEOUT, &http_client_data);
    //httpclient_close(&http_client);

    return ret;
}

static int offline_log_http_upload(int index, char *payload, int payload_len)
{
    int ret = 0;
    char *id = NULL;
    char *code = NULL;
    char *message = NULL;
    char *digest = NULL;
    char *digest_source = NULL;
    char *request_payload = NULL;
    char *response_payload = NULL;

    if (is_inited == 0 || !p_log_ctx)
    {
        diagnosis_warn("no init");
        return -1;
    }

    request_payload = (char *)OFFLINE_LOG_MALLOC(payload_len + HTTP_RESPONSE_PAYLOAD_LEN);
    if (!request_payload)
    {
        diagnosis_err("%s", no_mem_err);
        ret = -1;
        goto EXIT;
    }
    memset(request_payload, '\0', payload_len + HTTP_RESPONSE_PAYLOAD_LEN);
    response_payload = (char *)OFFLINE_LOG_MALLOC(HTTP_RESPONSE_PAYLOAD_LEN);
    if (!response_payload)
    {
        diagnosis_err("%s", no_mem_err);
        ret = -1;
        goto EXIT;
    }
    memset(response_payload, '\0', HTTP_RESPONSE_PAYLOAD_LEN);

    digest = OFFLINE_LOG_MALLOC(DIGEST_LEN);
    if (!digest)
    {
        diagnosis_err("%s", no_mem_err);
        ret = -1;
        goto EXIT;
    }
    memset(digest, '\0', DIGEST_LEN);

    digest_source = OFFLINE_LOG_MALLOC(MESSAGE_LEN);
    if (!digest_source)
    {
        diagnosis_err("%s", no_mem_err);
        ret = -1;
        goto EXIT;
    }
    memset(digest_source, '\0', MESSAGE_LEN);
    HAL_Snprintf(digest_source, MESSAGE_LEN, "%s_%d_%d", p_log_ctx->logName, index, payload_len);
    utils_hmac_sha1(digest_source, strlen(digest_source), digest, p_log_ctx->token, strlen(p_log_ctx->token));

    HAL_Snprintf(request_payload, payload_len + HTTP_RESPONSE_PAYLOAD_LEN, REQUEST_PAYLOAD_FMT, p_log_ctx->logName, digest, index, payload_len, payload);
    ret = offline_log_upload_by_http(p_log_ctx->httpServerURL, p_log_ctx->port, payload, payload_len, response_payload, HTTP_RESPONSE_PAYLOAD_LEN);
    if (ret != 0)
    {
        diagnosis_err("fail:%d", ret);
        ret = -1;
        goto EXIT;
    }

    message = LITE_json_value_of(RESPONSE_MESSAGE, response_payload, MEM_MAGIC, MEM_FLAG);
    if (message)
    {
        diagnosis_err("fail:%s", message);
        ret = -1;
    }

EXIT:
    if (response_payload)
        OFFLINE_LOG_FREE(response_payload);
    if (id)
        OFFLINE_LOG_FREE(id);
    if (code)
        OFFLINE_LOG_FREE(code);
    if (message)
        OFFLINE_LOG_FREE(message);
    if (digest)
        OFFLINE_LOG_FREE(digest);
    if (digest_source)
        OFFLINE_LOG_FREE(digest_source);

    return ret;
}

static int offline_log_has_flash_data(void)
{
    p_log_ctx->has_flash_log = 0;

    log_flash_read(LOG_BUFFER_MAX_SIZE, &p_log_ctx->log_flash_desc, sizeof(log_flash_desc_t));

    if (p_log_ctx->log_flash_desc.total_size < LOG_BUFFER_MAX_SIZE)
    {
        log_flash_read(0, p_log_ctx->p_log_buffer, p_log_ctx->log_flash_desc.total_size);
        uint32_t crc32 = utils_crc32((uint8_t *)p_log_ctx->p_log_buffer, p_log_ctx->log_flash_desc.total_size);

        if (p_log_ctx->log_flash_desc.crc == crc32)
        {
            diagnosis_info("Flash log");
            p_log_ctx->has_flash_log = 1;
        }
        else
        {
            diagnosis_err("T:%d Crc1:0x%x Crc2:0x%x", p_log_ctx->log_flash_desc.total_size, p_log_ctx->log_flash_desc.crc, crc32);
        }
    }

    //diagnosis_info("Total:%d CRC:0x%x", p_log_ctx->log_flash_desc.total_size, p_log_ctx->log_flash_desc.crc);
    return p_log_ctx->has_flash_log;
}

static int offline_log_upload_flash(void)
{
    int index = 0;
    int retry_count = 0;
    int fragment_count = 0;
    char log_buff[LOG_BUFFER_SIZE + 1] = {0};

    fragment_count = p_log_ctx->log_flash_desc.total_size / LOG_BUFFER_SIZE;
    fragment_count = (p_log_ctx->log_flash_desc.total_size % LOG_BUFFER_SIZE) ? fragment_count + 1 : fragment_count;

    while (index < fragment_count && retry_count < UPLOAD_RETRY_MAX_COUNT)
    {
        int send_len = 0;

        if (aos_mutex_lock(&p_log_ctx->offline_log_mutex, AOS_WAIT_FOREVER) != 0)
        {
            diagnosis_err("lock fail");
            return -1;
        }

        memset(log_buff, '\0', LOG_BUFFER_SIZE + 1);
        if (p_log_ctx->log_flash_desc.total_size % LOG_BUFFER_SIZE && index == fragment_count - 1)
        {
            send_len = p_log_ctx->log_flash_desc.total_size - index * LOG_BUFFER_SIZE;
        }
        else
        {
            send_len = LOG_BUFFER_SIZE;
        }

        log_flash_read(index * LOG_BUFFER_SIZE, log_buff, send_len);

        if (offline_log_http_upload(index, log_buff, send_len) < 0)
        {
            diagnosis_warn("fail id(%d)", index);
            retry_count++;
        }
        else
        {
            index++;
        }

        if (aos_mutex_unlock(&p_log_ctx->offline_log_mutex) != 0)
        {
            diagnosis_err("unlock fail");
            return -1;
        }
    }

    if (index == fragment_count) //Upload success
    {
        diagnosis_info("Upload flash log success");
        log_flash_erase(LOG_BUFFER_MAX_SIZE, sizeof(log_flash_desc_t)); //Clear flash log desc
    }

    return 0;
}

static int offline_log_upload(void)
{
    if (p_log_ctx->has_flash_log)
    {
        return offline_log_upload_flash();
    }

    return -1;
}

static int offline_log_get_reply(void *context, int result,
                                 void *userdata, void *remote,
                                 void *message)
{
    if (result == 2)
    { /* success */
        offline_log_upload();
        p_log_ctx->is_diagnosising = 1;
    }
    else
    {
        diagnosis_err("fail");
    }

    return 0;
}

int diagnosis_offline_log_get(void *ctx, void *resource, void *remote, void *request)
{
    int ret = 0;
    char *id = NULL;
    char *method = NULL;
    char *httpServerURL = NULL;
    char *port = NULL;
    char *logName = NULL;
    char *token = NULL;

    int code = 200;
    char *payload = NULL;
    int payload_len = 0;
    char *reply_payload = NULL;

    int is_dynamic_register = 0;
    char *digest = NULL;
    char *msg = NULL;

    payload = awss_cmp_get_coap_payload(request, &payload_len);
    if (!payload || payload_len < 1)
    {
        diagnosis_err("no pl");
        code = RESPONSE_CODE_NO_PAYLOAD;
        goto REPLY;
    }

    id = LITE_json_value_of(RESPONSE_ID, payload, MEM_MAGIC, MEM_FLAG);
    if (NULL == id)
    {
        diagnosis_err("id err");
        code = RESPONSE_CODE_PARSE_JSON_FAILED;
        goto REPLY;
    }
    httpServerURL = LITE_json_value_of(PARAMS_HTTPSERVERURL, payload, MEM_MAGIC, MEM_FLAG);
    if (NULL == httpServerURL)
    {
        diagnosis_err("url err");
        code = RESPONSE_CODE_PARSE_JSON_FAILED;
        goto REPLY;
    }
    port = LITE_json_value_of(PARAMS_PORT, payload, MEM_MAGIC, MEM_FLAG);
    if (NULL == port)
    {
        diagnosis_err("port err");
        code = RESPONSE_CODE_PARSE_JSON_FAILED;
        goto REPLY;
    }
    logName = LITE_json_value_of(PARAMS_LOGNAME, payload, MEM_MAGIC, MEM_FLAG);
    if (NULL == logName)
    {
        diagnosis_err("name err");
        code = RESPONSE_CODE_PARSE_JSON_FAILED;
        goto REPLY;
    }
    token = LITE_json_value_of(PARAMS_TOKEN, payload, MEM_MAGIC, MEM_FLAG);
    if (NULL == token)
    {
        diagnosis_err("token err");
        code = RESPONSE_CODE_PARSE_JSON_FAILED;
        goto REPLY;
    }

    if (is_inited == 0)
    {
        diagnosis_offline_log_init();
    }

    if (p_log_ctx) //Save data
    {
        strncpy(p_log_ctx->httpServerURL, httpServerURL, HTTP_SERVER_URL_LEN - 1);
        strncpy(p_log_ctx->logName, logName, LOG_NAME_LEN - 1);
        strncpy(p_log_ctx->token, token, TOKEN_LEN - 1);
        p_log_ctx->port = atoi(port);
    }

    if (httpServerURL)
        OFFLINE_LOG_FREE(httpServerURL);

    if (port)
        OFFLINE_LOG_FREE(port);

    if (logName)
        OFFLINE_LOG_FREE(logName);

    if (token)
        OFFLINE_LOG_FREE(token);

REPLY:
    reply_payload = OFFLINE_LOG_MALLOC(REPLAY_PAYLOAD_LEN);
    if (!reply_payload)
    {
        diagnosis_err("%s", no_mem_err);
        return -1;
    }

    memset(reply_payload, '\0', REPLAY_PAYLOAD_LEN);
    if (code == 200)
    {
        char pk[PRODUCT_KEY_LEN];
        char dn[DEVICE_NAME_LEN];
        char ps[PRODUCT_SECRET_LEN];
        char ds[DEVICE_SECRET_LEN];

        HAL_GetProductKey(pk);
        HAL_GetProductSecret(ps);
        HAL_GetDeviceName(dn);
        HAL_GetDeviceSecret(ds);

        digest = OFFLINE_LOG_MALLOC(DIGEST_LEN);
        if (!digest)
        {
            diagnosis_err("%s", no_mem_err);
            goto ERROR;
        }
        memset(digest, '\0', DIGEST_LEN);

        msg = OFFLINE_LOG_MALLOC(MESSAGE_LEN);
        if (!msg)
        {
            diagnosis_err("%s", no_mem_err);
            goto ERROR;
        }
        memset(msg, '\0', MESSAGE_LEN);

        HAL_Snprintf(msg, sizeof(msg), "%s%s%s%s%s%s", "credibleFileName",
                     p_log_ctx->logName, "deviceName", dn, "productKey", pk);

        IOT_Ioctl(IOTX_IOCTL_GET_DYNAMIC_REGISTER, &is_dynamic_register);
        if (is_dynamic_register)
        {
            utils_hmac_sha1(msg, strlen(msg), digest, ps, strlen(ps));
        }
        else
        {
            utils_hmac_sha1(msg, strlen(msg), digest, ds, strlen(ds));
        }

        memset(msg, '\0', MESSAGE_LEN);

        if (offline_log_has_flash_data())
        {
            int fragment_count = 0;

            fragment_count = p_log_ctx->log_flash_desc.total_size / LOG_BUFFER_SIZE;
            fragment_count = (p_log_ctx->log_flash_desc.total_size % LOG_BUFFER_SIZE) ? fragment_count + 1 : fragment_count;

            HAL_Snprintf(msg, sizeof(msg), GET_REPLY_DATA_FLASH_FMT, OFFLINE_LOG_VERSION, is_dynamic_register,
                         digest, 0, p_log_ctx->log_flash_desc.total_size, fragment_count);
        }
        else
        {
            HAL_Snprintf(msg, sizeof(msg), GET_REPLY_DATA_MEM_FMT, OFFLINE_LOG_VERSION, is_dynamic_register,
                         digest, 1);
        }

        HAL_Snprintf(reply_payload, REPLAY_PAYLOAD_LEN, GET_REPLY_FMT, id, code, msg);
    }
    else
    {
        HAL_Snprintf(reply_payload, REPLAY_PAYLOAD_LEN, GET_REPLY_FMT, id, code, "{}");
    }

    ret = awss_cmp_coap_send_resp(reply_payload, strlen(reply_payload), remote, TOPIC_OFFLINE_LOG_GET_REPLY, request, offline_log_get_reply, NULL, 1);

ERROR:
    if (id)
        OFFLINE_LOG_FREE(id);

    if (reply_payload)
        OFFLINE_LOG_FREE(reply_payload);

    if (digest)
        OFFLINE_LOG_FREE(digest);

    if (msg)
        OFFLINE_LOG_FREE(msg);

    return (code == 200) ? ret : -1;
}

#ifdef OFFLINE_LOG_UT_TEST
int diagnosis_offline_log_ut_test(void)
{
    int write_count = 100;
    int index = 0;

    char *ut_log = "This is diagnosis offline ut log data!!!!";
    char ut_log_buff[LOG_BUFFER_SIZE + 1] = {0};

    diagnosis_offline_log(0, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(1, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(2, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(3, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(0, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(1, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(2, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(3, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(0, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(1, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(2, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(3, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(0, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(1, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(2, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(3, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(0, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(1, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(2, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(3, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(0, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(1, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(2, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(3, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(0, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(1, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(2, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(3, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(0, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(1, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(2, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(3, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(0, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(1, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(2, "%s:%d\n", ut_log, __LINE__);
    diagnosis_offline_log(3, "%s:%d\n", ut_log, __LINE__);
    
    HAL_Printf("ALL LOG:(%d) %s\n", p_log_ctx->log_buffer_pos, p_log_ctx->p_log_buffer);

    strcpy(p_log_ctx->httpServerURL, "http://192.168.232.138/upload");
    p_log_ctx->port = 8080;

    diagnosis_offline_log_save_all();
    offline_log_has_flash_data();

    diagnosis_info("========================= offline_log_upload ============================");
    offline_log_upload();
    diagnosis_info("========================= offline_log_upload ============================");

    return 0;
}
#endif
#endif

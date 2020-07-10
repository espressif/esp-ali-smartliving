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
#include "awss_packet.h"
#include "zconfig_utils.h"

#include "dev_errcode.h"
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
#define RESPONSE_METHOD "method"

static diagnosis_offline_log_t *p_log_ctx = NULL;
static void *upload_mem_timer = NULL;
static void *oll_working_timer = NULL;
static oll_status_e oll_status = OLL_UNINITED;
static char no_mem_err[] = "no mem";
static uint32_t last_state_msg_crc = 0;
static int offline_log_http_upload(int index, char *payload, int payload_len);
extern int mbedtls_base64_encode(unsigned char *dst, size_t dlen, size_t *olen,
                                 const unsigned char *src, size_t slen);

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

static int offline_working_timer_cb(void)
{
    diagnosis_offline_log_deinit();

    if (oll_working_timer)
    {
        HAL_Timer_Delete(oll_working_timer);
        oll_working_timer = NULL;
    }

    return 0;
}

int diagnosis_offline_log_init(void)
{
    int ret = 0;

    if (oll_status == OLL_INITED)
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

    if (oll_working_timer == NULL)
    {
        oll_working_timer = HAL_Timer_Create("oll_working", (void (*)(void *))offline_working_timer_cb, NULL);

        if (oll_working_timer)
        {
            HAL_Timer_Stop(oll_working_timer);
            HAL_Timer_Start(oll_working_timer, OFFLINE_LOG_WORKING_TIME);
        }
    }

    oll_status = OLL_INITED;

    return 0;
}

int diagnosis_offline_log_deinit(void)
{
    if (!p_log_ctx)
    {
        diagnosis_err("p_log_ctx is NULL,line:%d", __LINE__);
        return -1;
    }

    if (oll_status == OLL_UNINITED || oll_status == OLL_STOPPED)
    {
        diagnosis_warn("no init");

        return -1;
    }

    if (aos_mutex_lock(&p_log_ctx->offline_log_mutex, AOS_WAIT_FOREVER) != 0)
    {
        diagnosis_err("lock fail");
        return -1;
    }

    if (p_log_ctx)
    {
        if (p_log_ctx->p_log_buffer)
        {
            OFFLINE_LOG_FREE(p_log_ctx->p_log_buffer);
            p_log_ctx->p_log_buffer = NULL;
        }

        if (upload_mem_timer)
        {
            HAL_Timer_Stop(upload_mem_timer);
            HAL_Timer_Delete(upload_mem_timer);
            upload_mem_timer = NULL;
        }

        if (oll_working_timer)
        {
            HAL_Timer_Stop(oll_working_timer);
            HAL_Timer_Delete(oll_working_timer);
            oll_working_timer = NULL;
        }

        aos_mutex_free(&p_log_ctx->offline_log_mutex);
        OFFLINE_LOG_FREE(p_log_ctx);
        p_log_ctx = NULL;
    }

    oll_status = OLL_STOPPED;

    diagnosis_info("oll deinited");

    return 0;
}

static int offline_log_write_buffer(const char *log_level, const char *fmt, va_list *ap)
{
    int writed_len = 0;
    char uptime[LOG_HEAD_LEN];
    char log_head[LOG_HEAD_LEN];

    if (!p_log_ctx)
    {
        diagnosis_err("p_log_ctx is NULL,line:%d", __LINE__);
        return -1;
    }

#ifdef DO_BASE64_ENCODE_WHEN_NOT_UTF8
    unsigned int base64_encode_len = 0;
    int base64_encode_buf_len = 0;
    char *base64_encode_buf = NULL;
#endif
    //flash log mode and has flash log can not write log
    if (p_log_ctx->has_flash_log && p_log_ctx->log_mode == UPLOAD_LOG_MODE_FLASH)
    {
        diagnosis_warn("flash log mode");
        return -1;
    }

    if (p_log_ctx->log_buffer_pos >= LOG_BUFFER_MAX_SIZE - 1)
    {
        diagnosis_info("offline log buf full");
        p_log_ctx->log_buffer_pos = LOG_BUFFER_MAX_SIZE - 1;
        return -1;
    }

    memset(log_head, '\0', sizeof(log_head));
    HAL_Snprintf(uptime, LOG_HEAD_LEN, "[%06d]", (unsigned)HAL_UptimeMs());
    HAL_Snprintf(log_head, LOG_HEAD_LEN, "%s%s ", uptime, log_level);

    if (p_log_ctx->log_buffer_pos + strlen(log_head) > LOG_BUFFER_MAX_SIZE)
    {
        diagnosis_info("offline log buf is full");
        memcpy(p_log_ctx->p_log_buffer + p_log_ctx->log_buffer_pos, log_head, LOG_BUFFER_MAX_SIZE - 1 - p_log_ctx->log_buffer_pos);
        p_log_ctx->log_buffer_pos = LOG_BUFFER_MAX_SIZE - 1;

        return -1;
    }

    memcpy(p_log_ctx->p_log_buffer + p_log_ctx->log_buffer_pos, log_head, strlen(log_head));
    p_log_ctx->log_buffer_pos += strlen(log_head);

    writed_len = HAL_Vsnprintf(p_log_ctx->p_log_buffer + p_log_ctx->log_buffer_pos, LOG_BUFFER_MAX_SIZE - p_log_ctx->log_buffer_pos, fmt, *ap);
#ifdef DO_BASE64_ENCODE_WHEN_NOT_UTF8
    if (zconfig_is_utf8(p_log_ctx->p_log_buffer + p_log_ctx->log_buffer_pos, writed_len) == 0)
    {
        base64_encode_buf_len = writed_len * 4 / 3 + 4;
        base64_encode_buf = OFFLINE_LOG_MALLOC(base64_encode_buf_len);
        if (!base64_encode_buf)
        {
            diagnosis_err("%s", no_mem_err);
            return -1;
        }
        memset(base64_encode_buf, '\0', base64_encode_buf_len);
        mbedtls_base64_encode((unsigned char *)base64_encode_buf, base64_encode_buf_len, &base64_encode_len, (unsigned char *)(p_log_ctx->p_log_buffer + p_log_ctx->log_buffer_pos), writed_len);

        memcpy(p_log_ctx->p_log_buffer + p_log_ctx->log_buffer_pos, base64_encode_buf, base64_encode_len);
        OFFLINE_LOG_FREE(base64_encode_buf);
        writed_len = base64_encode_len;
        diagnosis_info("Len:%d B64:%s\r\n", base64_encode_len, p_log_ctx->p_log_buffer + p_log_ctx->log_buffer_pos);
    }
#endif
    if (writed_len > LOG_BUFFER_MAX_SIZE - p_log_ctx->log_buffer_pos)
    {
        p_log_ctx->log_buffer_pos = LOG_BUFFER_MAX_SIZE - 1;
    }
    else
    {
        p_log_ctx->log_buffer_pos += writed_len;
    }

    return writed_len;
}

int diagnosis_offline_log(log_level_e level, const char *fmt, ...)
{
    char *p_level = NULL;
    va_list ap;
    va_start(ap, fmt);

    if (oll_status == OLL_STOPPED)
    {
        diagnosis_info("oll stopped");
        return 0;
    }
    else if (oll_status == OLL_UNINITED || !p_log_ctx)
    {
        diagnosis_offline_log_init();
    }

    if (aos_mutex_lock(&p_log_ctx->offline_log_mutex, AOS_WAIT_FOREVER) != 0)
    {
        diagnosis_err("lock fail");
        return -1;
    }

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

    if (aos_mutex_unlock(&p_log_ctx->offline_log_mutex) != 0)
    {
        diagnosis_err("unlock fail");
        return -1;
    }

    return 0;
}

int diagnosis_offline_log_save_all(void)
{
    if (oll_status == OLL_UNINITED || oll_status == OLL_STOPPED)
    {
        diagnosis_warn("no init");
        return -1;
    }

    if (!p_log_ctx)
    {
        diagnosis_err("p_log_ctx is NULL");
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

int diagnosis_offline_log_erase_flash_desc(void)
{
    oll_status_e oll_status_backup = oll_status;

    if (!p_log_ctx)
    {
        diagnosis_err("oll no erase");
        return -1;
    }

    if (oll_status == OLL_UNINITED || oll_status == OLL_STOPPED)
    {
        diagnosis_offline_log_init();
    }

    if (aos_mutex_lock(&p_log_ctx->offline_log_mutex, AOS_WAIT_FOREVER) != 0)
    {
        diagnosis_err("lock fail");
        return -1;
    }

    log_flash_erase(LOG_BUFFER_MAX_SIZE, sizeof(log_flash_desc_t)); //erase flash desc
    HAL_SleepMs(200);                                               //Wait flash sync

    if (aos_mutex_unlock(&p_log_ctx->offline_log_mutex) != 0)
    {
        diagnosis_err("unlock fail");
        return -1;
    }

    if (oll_status_backup == OLL_STOPPED)
    {
        diagnosis_offline_log_deinit();
    }

    diagnosis_info("oll erase desc");

    return 0;
}

static int offline_log_upload_by_http(const char *url, int port, char *request_payload, int request_payload_len, char *response_payload, int response_payload_len)
{
    int ret = 0;
    httpclient_t http_client;
    httpclient_data_t http_client_data;

    memset(&http_client, 0, sizeof(httpclient_t));
    memset(&http_client_data, 0, sizeof(httpclient_data_t));

    http_client.header = "Accept:*/*\r\n";

    http_client_data.post_content_type = "application/json;charset=utf-8";
    http_client_data.post_buf = request_payload;
    http_client_data.post_buf_len = request_payload_len;
    http_client_data.response_buf = response_payload;
    http_client_data.response_buf_len = response_payload_len;

    diagnosis_info("url:%s\r\n oll_payload:%s\r\n", url, request_payload);

    ret = httpclient_common(&http_client, url, port, NULL, HTTPCLIENT_POST, HTTP_TIMEOUT, &http_client_data);

    return ret;
}

static int offline_log_http_upload(int index, char *payload, int payload_len)
{
    int ret = 0;
    char *code = NULL;
    char *message = NULL;
    char *digest = NULL;
    char *request_payload = NULL;
    char *response_payload = NULL;
    unsigned int base64_encode_len = 0;
    int base64_encode_buf_len = 0;
    char *base64_encode_buf = NULL;

    if (!p_log_ctx)
    {
        diagnosis_err("p_log_ctx is NULL,line:%d", __LINE__);
        return -1;
    }

    if (oll_status == OLL_UNINITED || oll_status == OLL_STOPPED)
    {
        diagnosis_warn("no init");
        return -1;
    }

    base64_encode_buf_len = payload_len * 4 / 3 + 4;
    request_payload = (char *)OFFLINE_LOG_MALLOC(base64_encode_buf_len + HTTP_REQUEST_PAYLOAD_LEN);
    if (!request_payload)
    {
        diagnosis_err("%s", no_mem_err);
        ret = -1;
        goto EXIT;
    }
    memset(request_payload, '\0', base64_encode_buf_len + HTTP_REQUEST_PAYLOAD_LEN);
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

    base64_encode_buf = OFFLINE_LOG_MALLOC(base64_encode_buf_len);
    if (!base64_encode_buf)
    {
        diagnosis_err("%s", no_mem_err);
        return -1;
    }
    memset(base64_encode_buf, '\0', base64_encode_buf_len);
#ifdef SUPPORT_TLS
    mbedtls_base64_encode((unsigned char *)base64_encode_buf, base64_encode_buf_len, &base64_encode_len, (unsigned char *)payload, payload_len);
#endif
    utils_hmac_sha1(base64_encode_buf, strlen(base64_encode_buf), digest, p_log_ctx->token, strlen(p_log_ctx->token));

    HAL_Snprintf(request_payload, base64_encode_buf_len + HTTP_REQUEST_PAYLOAD_LEN, REQUEST_PAYLOAD_FMT, p_log_ctx->logName, digest, index, payload_len, base64_encode_buf);

    ret = offline_log_upload_by_http(p_log_ctx->httpServerURL, p_log_ctx->port, request_payload, strlen(request_payload), response_payload, HTTP_RESPONSE_PAYLOAD_LEN);
    if (ret != 0)
    {
        diagnosis_err("upload fail:%d", ret);
        ret = -1;
        goto EXIT;
    }

    code = LITE_json_value_of(RESPONSE_CODE, response_payload, MEM_MAGIC, MEM_FLAG);
    if (strcmp(code, "200"))
    {
        message = LITE_json_value_of(RESPONSE_MESSAGE, response_payload, MEM_MAGIC, MEM_FLAG);
        if (message)
        {
            diagnosis_err("mesg:%s", message);
        }

        ret = -1;
    }

EXIT:
    if (digest)
        OFFLINE_LOG_FREE(digest);
    if (request_payload)
        OFFLINE_LOG_FREE(request_payload);
    if (response_payload)
        OFFLINE_LOG_FREE(response_payload);
    if (code)
        OFFLINE_LOG_FREE(code);
    if (message)
        OFFLINE_LOG_FREE(message);
    if (base64_encode_buf)
        OFFLINE_LOG_FREE(base64_encode_buf);

    return ret;
}

static int offline_log_has_flash_data(void)
{
    uint32_t crc32 = 0;

    if (!p_log_ctx)
    {
        diagnosis_err("p_log_ctx is NULL,line:%d", __LINE__);
        return -1;
    }

    p_log_ctx->has_flash_log = 0;

    log_flash_read(LOG_BUFFER_MAX_SIZE, &p_log_ctx->log_flash_desc, sizeof(log_flash_desc_t));

    if (p_log_ctx->log_flash_desc.total_size < LOG_BUFFER_MAX_SIZE)
    {
        log_flash_read(0, p_log_ctx->p_log_buffer, p_log_ctx->log_flash_desc.total_size);
        crc32 = utils_crc32((uint8_t *)p_log_ctx->p_log_buffer, p_log_ctx->log_flash_desc.total_size);

        if (p_log_ctx->log_flash_desc.crc == crc32)
        {
            diagnosis_info("Flash log");
            p_log_ctx->has_flash_log = 1;
            p_log_ctx->log_buffer_pos = p_log_ctx->log_flash_desc.total_size;
            *(p_log_ctx->p_log_buffer + p_log_ctx->log_buffer_pos + 1) = '\0';
        }
        else
        {
            diagnosis_err("T:%d Crc1:0x%x Crc2:0x%x", p_log_ctx->log_flash_desc.total_size, p_log_ctx->log_flash_desc.crc, crc32);
        }
    }

    diagnosis_info("Total:%d CRC:0x%x", p_log_ctx->log_flash_desc.total_size, p_log_ctx->log_flash_desc.crc);
    return p_log_ctx->has_flash_log;
}

static int offline_log_load_flash_log_to_mem(void)
{
    int ret = 0;

    if (!p_log_ctx)
    {
        diagnosis_err("p_log_ctx is NULL,line:%d", __LINE__);
        return -1;
    }

    if (aos_mutex_lock(&p_log_ctx->offline_log_mutex, AOS_WAIT_FOREVER) != 0)
    {
        diagnosis_err("lock fail");
        return -1;
    }

    ret = log_flash_read(0, p_log_ctx->p_log_buffer, p_log_ctx->log_flash_desc.total_size);

    if (aos_mutex_unlock(&p_log_ctx->offline_log_mutex) != 0)
    {
        diagnosis_err("unlock fail");
        return -1;
    }

    return ret;
}

static int offline_log_upload_mem(void)
{
    int index = 0;
    int need_send_len = 0;
    int have_send_len = 0;
    int retry_count = 0;
    int fragment_count = 0;
    char *log_buff = NULL;

    if (!p_log_ctx)
    {
        diagnosis_err("p_log_ctx is NULL,line:%d", __LINE__);
        return -1;
    }

    if (!p_log_ctx || oll_status == OLL_STOPPED)
    {
        diagnosis_warn("oll stopped");
        return -1;
    }

    if (p_log_ctx->log_buffer_pos == 0)
    {
        diagnosis_warn("no mem log");
        return -1;
    }

    if (aos_mutex_lock(&p_log_ctx->offline_log_mutex, AOS_WAIT_FOREVER) != 0)
    {
        diagnosis_err("lock fail");
        return -1;
    }

    fragment_count = p_log_ctx->log_buffer_pos / LOG_BUFFER_SIZE;
    fragment_count = (p_log_ctx->log_buffer_pos % LOG_BUFFER_SIZE) ? fragment_count + 1 : fragment_count;

    log_buff = OFFLINE_LOG_MALLOC(LOG_BUFFER_SIZE + 1);
    if (!log_buff)
    {
        diagnosis_err("%s", no_mem_err);
        return -1;
    }

    while (index < fragment_count && retry_count < UPLOAD_RETRY_MAX_COUNT)
    {
        memset(log_buff, '\0', LOG_BUFFER_SIZE + 1);
        if ((p_log_ctx->log_buffer_pos % LOG_BUFFER_SIZE) && (index == (fragment_count - 1)))
        {
            need_send_len = p_log_ctx->log_buffer_pos - index * LOG_BUFFER_SIZE;
        }
        else
        {
            need_send_len = LOG_BUFFER_SIZE;
        }

        memcpy(log_buff, p_log_ctx->p_log_buffer + have_send_len, need_send_len);
        if (offline_log_http_upload(p_log_ctx->mem_log_index, log_buff, need_send_len) < 0)
        {
            diagnosis_warn("fail id(%d)", index);
            retry_count++;
        }
        else
        {
            index++;
            p_log_ctx->mem_log_index++;
            have_send_len += need_send_len;
        }
    }

    if (index == fragment_count) //Upload success
    {
        diagnosis_info("Upload mem log success");
        p_log_ctx->log_buffer_pos = 0;
    }
    else if (have_send_len > 0 && have_send_len < p_log_ctx->log_buffer_pos) //Upload some
    {
        for (index = 0; index < p_log_ctx->log_buffer_pos - have_send_len; index++)
        {
            *(p_log_ctx->p_log_buffer + index) = *(p_log_ctx->p_log_buffer + have_send_len + index);
        }

        *(p_log_ctx->p_log_buffer + index) = '\0'; //Add end char
        p_log_ctx->log_buffer_pos = p_log_ctx->log_buffer_pos - have_send_len;
    }

    if (log_buff)
    {
        OFFLINE_LOG_FREE(log_buff);
    }

    if (aos_mutex_unlock(&p_log_ctx->offline_log_mutex) != 0)
    {
        diagnosis_err("unlock fail");
        return -1;
    }

    return 0;
}

static int offline_upload_mem_log_timer_cb(void)
{
    offline_log_upload_mem();

    if (upload_mem_timer) //restart
    {
        HAL_Timer_Stop(upload_mem_timer);
        HAL_Timer_Start(upload_mem_timer, 2000);
    }

    return 0;
}

static int offline_log_upload(void)
{
    if (oll_status != OLL_INITED)
    {
        diagnosis_warn("oll uninited");
        return -1;
    }

    if (!p_log_ctx)
    {
        diagnosis_err("p_log_ctx is NULL,line:%d", __LINE__);
        return -1;
    }

    if (p_log_ctx->log_mode == UPLOAD_LOG_MODE_FLASH && p_log_ctx->has_flash_log)
    {
        offline_log_load_flash_log_to_mem();
        return offline_log_upload_mem();
    }
    else if (p_log_ctx->log_mode == UPLOAD_LOG_MODE_MEM)
    {
        if (upload_mem_timer == NULL)
        {
            upload_mem_timer = HAL_Timer_Create("oll_upload", (void (*)(void *))offline_upload_mem_log_timer_cb, NULL);
        }

        if (upload_mem_timer)
        {
            HAL_Timer_Stop(upload_mem_timer);
            HAL_Timer_Start(upload_mem_timer, 10);
        }
    }
    else
    {
        diagnosis_warn("oll no upload");
    }

    return 0;
}

static int offline_log_get_reply(void *context, int result,
                                 void *userdata, void *remote,
                                 void *message)
{
    if (result == 2)
    { /* success */
        HAL_SleepMs(1000);

        offline_log_upload();
    }
    else
    {
        diagnosis_err("log get reply fail");
    }

    return 0;
}

static int offline_log_finish_reply(void *context, int result,
                                    void *userdata, void *remote,
                                    void *message)
{
    int ret = 0;

    if (result == 2)
    { /* success */
        diagnosis_info("finish offline log");
        diagnosis_offline_log_deinit();
    }
    else
    {
        diagnosis_err("finish fail");
    }

    return 0;
}

int diagnosis_offline_log_get(void *ctx, void *resource, void *remote, void *request)
{
    int ret = 0;
    char *id = NULL;
    char *method = NULL;
    char *httpServerURL = NULL;
    char *logName = NULL;
    char *token = NULL;
    char *logMode = NULL;

    int code = 200;
    char *payload = NULL;
    int payload_len = 0;
    char *reply_payload = NULL;

    int is_dynamic_register = 0;
    char *digest = NULL;
    char *msg = NULL;
    char *topic = NULL;

    payload = awss_cmp_get_coap_payload(request, &payload_len);
    if (!payload || payload_len < 1)
    {
        diagnosis_err("no pl");
        code = RESPONSE_CODE_NO_PAYLOAD;
        goto REPLY;
    }

    diagnosis_info("payload:%s", payload);

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
    logMode = LITE_json_value_of(PARAMS_LOGMODE, payload, MEM_MAGIC, MEM_FLAG);
    if (NULL == logMode)
    {
        diagnosis_err("logMode err");
        code = RESPONSE_CODE_PARSE_JSON_FAILED;
        goto REPLY;
    }

    if (oll_status == OLL_UNINITED || oll_status == OLL_STOPPED || !p_log_ctx)
    {
        diagnosis_offline_log_init();
    }

    if (p_log_ctx) //Save data
    {
        char *host_ptr = (char *)strstr(httpServerURL, "://");
        char *path_ptr = NULL;
        char *port_ptr = NULL;
        char port_buf[PORT_MAX_LEN] = {0};
        int port_len = 0;

        host_ptr += 3;
        port_ptr = strchr(host_ptr, ':');
        port_ptr += 1;
        path_ptr = strchr(port_ptr, '/');

        if (port_ptr && path_ptr)
        {
            port_len = path_ptr - port_ptr;

            if (port_len < PORT_MAX_LEN)
            {
                memset(port_buf, '\0', PORT_MAX_LEN);
                memcpy(port_buf, port_ptr, port_len);
                p_log_ctx->port = atoi(port_buf);
            }
        }

        //Allow only one APP connect device
        if (strlen(p_log_ctx->httpServerURL) > 0 && strcmp(p_log_ctx->httpServerURL, httpServerURL))
        {
            diagnosis_warn("being diagnosising");
            goto ERROR;
        }

        memset(p_log_ctx->httpServerURL, '\0', HTTP_SERVER_URL_LEN);
        memset(p_log_ctx->logName, '\0', LOG_NAME_LEN);
        memset(p_log_ctx->token, '\0', TOKEN_LEN);

        strncpy(p_log_ctx->httpServerURL, httpServerURL, strlen(httpServerURL) > (HTTP_SERVER_URL_LEN - 1) ? (HTTP_SERVER_URL_LEN - 1) : strlen(httpServerURL));
        strncpy(p_log_ctx->logName, logName, strlen(logName) > (LOG_NAME_LEN - 1) ? (LOG_NAME_LEN - 1) : strlen(logName));
        strncpy(p_log_ctx->token, token, strlen(token) > (TOKEN_LEN - 1) ? (TOKEN_LEN - 1) : strlen(token));
        p_log_ctx->log_mode = atoi(logMode);
        diagnosis_info("logmode:%d", p_log_ctx->log_mode);
    }

REPLY:
    reply_payload = OFFLINE_LOG_MALLOC(REPLAY_PAYLOAD_LEN);
    if (!reply_payload)
    {
        diagnosis_err("%s", no_mem_err);
        goto ERROR;
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

        HAL_Snprintf(msg, MESSAGE_LEN, "%s%s%s%s%s%s", "credibleFileName",
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

        if (p_log_ctx->log_mode == UPLOAD_LOG_MODE_FLASH)
        {
            if (offline_log_has_flash_data())
            {
                int fragment_count = 0;

                fragment_count = p_log_ctx->log_flash_desc.total_size / LOG_BUFFER_SIZE;
                fragment_count = (p_log_ctx->log_flash_desc.total_size % LOG_BUFFER_SIZE) ? fragment_count + 1 : fragment_count;

                HAL_Snprintf(msg, MESSAGE_LEN, GET_REPLY_DATA_FLASH_FMT, OFFLINE_LOG_VERSION, is_dynamic_register,
                             digest, 0, p_log_ctx->log_flash_desc.total_size, fragment_count);
            }
            else
            {
                HAL_Snprintf(msg, MESSAGE_LEN, GET_REPLY_DATA_FLASH_FMT, OFFLINE_LOG_VERSION, is_dynamic_register,
                             digest, 0, 0, 0);
            }
        }
        else
        {
            HAL_Snprintf(msg, MESSAGE_LEN, GET_REPLY_DATA_MEM_FMT, OFFLINE_LOG_VERSION, is_dynamic_register,
                         digest, 1);
        }

        HAL_Snprintf(reply_payload, REPLAY_PAYLOAD_LEN, GET_REPLY_FMT, id, code, msg);
    }
    else
    {
        HAL_Snprintf(reply_payload, REPLAY_PAYLOAD_LEN, GET_REPLY_FMT, id, code, "{}");
    }

    diagnosis_info("OLL send to APP:%s", reply_payload);

    topic = OFFLINE_LOG_MALLOC(TOPIC_URL_LEN);
    if (NULL == topic)
    {
        diagnosis_err("%s", no_mem_err);
        goto ERROR;
    }

    memset(topic, '\0', TOPIC_URL_LEN);
    awss_build_topic((const char *)TOPIC_OFFLINE_LOG_GET_REPLY, topic, TOPIC_URL_LEN);

    ret = awss_cmp_coap_send_resp(reply_payload, strlen(reply_payload), remote, topic, request, offline_log_get_reply, NULL, 1);

ERROR:
    if (id)
        OFFLINE_LOG_FREE(id);

    if (reply_payload)
        OFFLINE_LOG_FREE(reply_payload);

    if (digest)
        OFFLINE_LOG_FREE(digest);

    if (msg)
        OFFLINE_LOG_FREE(msg);

    if (topic)
        OFFLINE_LOG_FREE(topic);

    if (httpServerURL)
        OFFLINE_LOG_FREE(httpServerURL);

    if (logName)
        OFFLINE_LOG_FREE(logName);

    if (token)
        OFFLINE_LOG_FREE(token);

    if (logMode)
        OFFLINE_LOG_FREE(logMode);

    return (code == 200) ? ret : -1;
}

int diagnosis_offline_log_finish(void *ctx, void *resource, void *remote, void *request)
{
    int ret = 0;
    char *id = NULL;
    char *method = NULL;

    int code = 200;
    char *topic = NULL;
    char *payload = NULL;
    int payload_len = 0;
    char *reply_payload = NULL;

    payload = awss_cmp_get_coap_payload(request, &payload_len);
    if (!payload || payload_len < 1)
    {
        diagnosis_err("no pl");
        code = RESPONSE_CODE_NO_PAYLOAD;
        goto REPLY;
    }

    diagnosis_info("payload:%s", payload);

    id = LITE_json_value_of(RESPONSE_ID, payload, MEM_MAGIC, MEM_FLAG);
    if (NULL == id)
    {
        diagnosis_err("id err");
        code = RESPONSE_CODE_PARSE_JSON_FAILED;
        goto REPLY;
    }

    method = LITE_json_value_of(RESPONSE_METHOD, payload, MEM_MAGIC, MEM_FLAG);
    if (NULL == id)
    {
        diagnosis_err("method err");
        code = RESPONSE_CODE_PARSE_JSON_FAILED;
        goto REPLY;
    }

    if (strcmp(method, OFFLINE_LOG_FINISH_METHOD) != 0)
    {
        diagnosis_err("method not match");
        code = RESPONSE_CODE_METHOD_NOT_MATCH;
        goto REPLY;
    }

REPLY:
    reply_payload = OFFLINE_LOG_MALLOC(REPLAY_FINISH_PAYLOAD_LEN);
    if (!reply_payload)
    {
        diagnosis_err("%s", no_mem_err);
        return -1;
    }

    memset(reply_payload, '\0', REPLAY_FINISH_PAYLOAD_LEN);
    HAL_Snprintf(reply_payload, REPLAY_FINISH_PAYLOAD_LEN, GET_REPLY_FMT, id, code, "{}");

    topic = OFFLINE_LOG_MALLOC(TOPIC_URL_LEN);
    if (NULL == topic)
    {
        diagnosis_err("%s", no_mem_err);
        goto ERROR;
    }

    awss_build_topic((const char *)TOPIC_DEV_OFFLINE_LOG_FINISH_REPLY, topic, TOPIC_URL_LEN);

    diagnosis_info("OLL send to APP:%s", reply_payload);
    ret = awss_cmp_coap_send_resp(reply_payload, strlen(reply_payload), remote, topic, request, offline_log_finish_reply, NULL, 1);

ERROR:
    if (id)
        OFFLINE_LOG_FREE(id);

    if (method)
        OFFLINE_LOG_FREE(method);

    if (reply_payload)
        OFFLINE_LOG_FREE(reply_payload);

    if (topic)
        OFFLINE_LOG_FREE(topic);

    return (code == 200) ? ret : -1;
}

int diagnosis_offline_log_state_code_handle(const int state_code, const char *state_message)
{
    uint16_t err_code = 0;
    uint8_t *crc_buff = NULL;
    uint32_t crc_len = 0;
    uint32_t crc_value = 0;

    if (STATE_WIFI_CHAN_SCAN == state_code)
        return 0;

    crc_len = sizeof(int) + strlen(state_message) + 1;
    crc_buff = OFFLINE_LOG_MALLOC(crc_len);
    if (!crc_buff)
        return -1;

    memset(crc_buff, '\0', crc_len);
    HAL_Snprintf((char *)crc_buff, crc_len, "%d%s", state_code, state_message);

    crc_value = utils_crc32(crc_buff, (unsigned int)strlen((char *)crc_buff));
    if (last_state_msg_crc == crc_value) //not save duplicated state msg
    {
        diagnosis_info("same state msg");
        if (crc_buff)
            OFFLINE_LOG_FREE(crc_buff);
        return 0;
    }
    last_state_msg_crc = crc_value;

    err_code = dev_errcode_sdk_filter(state_code);
    if (err_code > 0)
    {
        if (NULL == state_message)
        {
            diagnosis_offline_log(LOG_LEVEL_E, "EC(0x%04x) SC(-0x%04x)\r\n", err_code, -state_code);
        }
        else
        {
            diagnosis_offline_log(LOG_LEVEL_E, "EC(0x%04x) SC(-0x%04x) SM(%s)\r\n", err_code, -state_code, state_message);
        }
    }
    else
    {
        if (NULL == state_message)
        {
            diagnosis_offline_log(LOG_LEVEL_I, "SC(-0x%04x)\r\n", -state_code);
        }
        else
        {
            diagnosis_offline_log(LOG_LEVEL_I, "SC(-0x%04x) SM(%s)\r\n", -state_code, state_message);
        }
    }

    if (crc_buff)
        OFFLINE_LOG_FREE(crc_buff);

    return 0;
}

#ifdef OFFLINE_LOG_UT_TEST
int diagnosis_offline_log_upload(const char *host, int port)
{
    if (oll_status == OLL_UNINITED || oll_status == OLL_STOPPED)
    {
        diagnosis_offline_log_init();
    }

    if (p_log_ctx)
    {
        memset(p_log_ctx->httpServerURL, '\0', HTTP_SERVER_URL_LEN);
        HAL_Snprintf(p_log_ctx->httpServerURL, HTTP_SERVER_URL_LEN, "%s", host);
        p_log_ctx->port = port;

        return offline_log_upload();
    }

    return -1;
}

int diagnosis_offline_log_read_all(upload_log_mode_e log_mode)
{
    if (oll_status == OLL_UNINITED || !p_log_ctx)
    {
        diagnosis_warn("no init");
        return -1;
    }

    if (aos_mutex_lock(&p_log_ctx->offline_log_mutex, AOS_WAIT_FOREVER) != 0)
    {
        diagnosis_err("lock fail");
        return -1;
    }

    if (UPLOAD_LOG_MODE_MEM == log_mode)
    {
        if (p_log_ctx && p_log_ctx->log_buffer_pos > 0 && p_log_ctx->p_log_buffer)
        {
            HAL_Printf("Mem log Size(%d)\r\n%s\r\n", p_log_ctx->log_buffer_pos, p_log_ctx->p_log_buffer);
        }
    }
    else
    {
        offline_log_has_flash_data();
        if (p_log_ctx && p_log_ctx->has_flash_log == 1 && p_log_ctx->log_buffer_pos > 0 && p_log_ctx->p_log_buffer)
        {
            HAL_Printf("Flash log Size(%d)\r\n%s\r\n", p_log_ctx->log_buffer_pos, p_log_ctx->p_log_buffer);
        }
    }

    if (aos_mutex_unlock(&p_log_ctx->offline_log_mutex) != 0)
    {
        diagnosis_err("unlock fail");
        return -1;
    }

    return 0;
}
#endif
#endif

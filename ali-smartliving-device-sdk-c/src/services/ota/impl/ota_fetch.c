/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include "iotx_ota_internal.h"

/* ofc, OTA fetch channel */

typedef struct {

    const char *url;
    httpclient_t http;              /* http client */
    httpclient_data_t http_data;    /* http client data */

} otahttp_Struct_t, *otahttp_Struct_pt;

extern int httpclient_common(httpclient_t *client,
                             const char *url,
                             int port,
                             const char *ca_crt,
                             HTTPCLIENT_REQUEST_TYPE method,
                             uint32_t timeout_ms,
                             httpclient_data_t *client_data);

extern const char *iotx_ca_get(void);


void *ofc_Init(char *url)
{
    otahttp_Struct_pt h_odc;

    if (NULL == (h_odc = OTA_MALLOC(sizeof(otahttp_Struct_t)))) {
        OTA_LOG_ERROR("allocate for h_odc failed");
        return NULL;
    }

    memset(h_odc, 0, sizeof(otahttp_Struct_t));

    /* set http request-header parameter */
    h_odc->http.header = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";

#if defined(SUPPORT_ITLS)
    char *s_ptr = strstr(url, "://");
    if (strlen("https") == (s_ptr - url) && (0 == strncmp(url, "https", strlen("https")))) {
        strncpy(url + 1, url, strlen("http"));
        url++;
    }
#endif
    h_odc->url = url;

    return h_odc;
}


int32_t ofc_Fetch(void *handle, char *buf, uint32_t buf_len, uint32_t timeout_s)
{
    int diff;
    int port =0;
    otahttp_Struct_pt h_odc = (otahttp_Struct_pt)handle;

    h_odc->http_data.response_buf = buf;
    h_odc->http_data.response_buf_len = buf_len;
    diff = h_odc->http_data.response_content_len - h_odc->http_data.retrieve_len;
#if defined(SUPPORT_ITLS)
    port = 80;
#else
    port = 443;
#endif

    //try to get port from url
    #define port_str_max_len 5  /* port max:65535 */
    const char *host_ptr = (const char *) strstr(h_odc->url, "://");
    char *path_ptr;
    char *port_ptr;
    char port_str[port_str_max_len+1];
    int8_t port_str_len = 0;

    if (host_ptr == NULL) {
        OTA_LOG_ERROR("Could not find host");
        return -1; /* URL is invalid */
    }

    host_ptr += 3; /* sizeof("://") */

    path_ptr = strchr(host_ptr, '/');
    port_ptr = strchr(host_ptr, ':');

    if(port_ptr++) {
        port_str_len = path_ptr - port_ptr;
        port_str_len = port_str_len > port_str_max_len?port_str_max_len:port_str_len;
        memcpy(port_str, port_ptr, port_str_len);
        port_str[port_str_len] = '\0';
        port = atoi(port_str);
        OTA_LOG_INFO("http:port=%d.",port);
    }

    const char* ca = iotx_ca_get();

    //not use ssl for local http transfer
    if((port != 80)&&(port != 443)) {
        ca =NULL;
    }
    if (0 != httpclient_common(&h_odc->http, h_odc->url, port,ca, HTTPCLIENT_GET, timeout_s * 1000,
                               &h_odc->http_data)) {
        OTA_LOG_ERROR("fetch firmware failed");
        return -1;
    }

    return h_odc->http_data.response_content_len - h_odc->http_data.retrieve_len - diff;
}


int ofc_Deinit(void *handle)
{
    if (NULL != handle) {
        OTA_FREE(handle);
    }

    return 0;
}

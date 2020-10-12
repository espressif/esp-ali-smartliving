#include <stdio.h>
#include <string.h>

#include "iot_import.h"

/**
 * @brief Set malloc/free function.
 *
 * @param [in] hooks: @n Specify malloc/free function you want to use
 *
 * @retval DTLS_SUCCESS : Success.
   @retval        other : Fail.
 * @see None.
 * @note If connect cloud by CoAP,you need realize it.
 */
DLL_HAL_API int HAL_DTLSHooks_set(dtls_hooks_t *hooks)
{
    return (int)1;
}

/**
 * @brief Establish a DSSL connection.
 *
 * @param [in] p_options: @n Specify paramter of DTLS
   @verbatim
           p_host : @n Specify the hostname(IP) of the DSSL server
             port : @n Specify the DSSL port of DSSL server
    p_ca_cert_pem : @n Specify the root certificate which is PEM format.
   @endverbatim
 * @return DSSL handle.
 * @see None.
 * @note If connect cloud by CoAP,you need realize it..
 */
DLL_HAL_API DTLSContext *HAL_DTLSSession_create(coap_dtls_options_t *p_options)
{
    return (DTLSContext *)1;
}

/**
 * @brief Destroy the specific DSSL connection.
 *
 * @param[in] context: @n Handle of the specific connection.
 *
 * @return The result of free dtls session
 * @retval DTLS_SUCCESS : Read success.
 * @retval DTLS_INVALID_PARAM : Invalid parameter.
 * @retval DTLS_INVALID_CA_CERTIFICATE : Invalid CA Certificate.
 * @retval DTLS_HANDSHAKE_IN_PROGRESS : Handshake in progress.
 * @retval DTLS_HANDSHAKE_FAILED : Handshake failed.
 * @retval DTLS_FATAL_ALERT_MESSAGE : Recv peer fatal alert message.
 * @retval DTLS_PEER_CLOSE_NOTIFY : The DTLS session was closed by peer.
 * @retval DTLS_SESSION_CREATE_FAILED : Create session fail.
 * @retval DTLS_READ_DATA_FAILED : Read data fail.
 * @note If connect cloud by CoAP,you need realize it.
 */
DLL_HAL_API unsigned int HAL_DTLSSession_free(DTLSContext *context)
{
    return (unsigned)1;
}

/**
 * @brief Read data from the specific DSSL connection with timeout parameter.
 *        The API will return immediately if len be received from the specific DSSL connection.
 *
 * @param [in] context @n A descriptor identifying a DSSL connection.
 * @param [in] p_data @n A pointer to a buffer to receive incoming data.
 * @param [in] p_datalen @n The length, in bytes, of the data pointed to by the 'p_data' parameter.
 * @param [in] timeout_ms @n Specify the timeout value in millisecond. In other words, the API block 'timeout_ms' millisecond maximumly.
 * @return The result of read data from DSSL connection
 * @retval DTLS_SUCCESS : Read success.
 * @retval DTLS_FATAL_ALERT_MESSAGE : Recv peer fatal alert message.
 * @retval DTLS_PEER_CLOSE_NOTIFY : The DTLS session was closed by peer.
 * @retval DTLS_READ_DATA_FAILED : Read data fail.
 * @note If connect cloud by CoAP,you need realize it..
 */
DLL_HAL_API unsigned int HAL_DTLSSession_read(DTLSContext *context,
                                              unsigned char *p_data,
                                              unsigned int *p_datalen,
                                              unsigned int timeout_ms)
{
    return (unsigned)1;
}

/**
 * @brief Write data into the specific DSSL connection.
 *
 * @param [in] context @n A descriptor identifying a connection.
 * @param [in] p_data @n A pointer to a buffer containing the data to be transmitted.
 * @param [in] p_datalen @n The length, in bytes, of the data pointed to by the 'p_data' parameter.
 * @retval DTLS_SUCCESS : Success.
   @retval        other : Fail.
 * @note If connect cloud by CoAP,you need realize it..
 */
DLL_HAL_API unsigned int HAL_DTLSSession_write(DTLSContext *context,
                                               const unsigned char *p_data,
                                               unsigned int *p_datalen)
{
    return (unsigned)1;
}

extern void *HAL_Malloc(uint32_t size);
extern void HAL_Free(void *ptr);

static ssl_hooks_t g_ssl_hooks = {HAL_Malloc, HAL_Free};

int32_t HAL_SSL_Destroy(uintptr_t handle)
{
    return 0;
}

uintptr_t HAL_SSL_Establish(const char *host, uint16_t port, const char *ca_crt, uint32_t ca_crt_len)
{
    return (uintptr_t)0;
}

int HAL_SSLHooks_set(ssl_hooks_t *hooks)
{
    if (hooks == NULL || hooks->malloc == NULL || hooks->free == NULL)
    {
        return -1;
    }

    g_ssl_hooks.malloc = hooks->malloc;
    g_ssl_hooks.free = hooks->free;

    return 0;
}

static void HAL_utils_ms_to_timeval(int timeout_ms, struct timeval *tv)
{
    tv->tv_sec = timeout_ms / 1000;
    tv->tv_usec = (timeout_ms - (tv->tv_sec * 1000)) * 1000;
}

int HAL_SSL_Read(uintptr_t handle, char *buf, int len, int timeout_ms)
{
    return 0;
}

int HAL_SSL_Write(uintptr_t handle, const char *buf, int len, int timeout_ms)
{
    return 0;
}

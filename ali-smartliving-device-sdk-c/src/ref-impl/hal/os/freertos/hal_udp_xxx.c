#include <stdio.h>
#include <string.h>

#include "iot_import.h"

int HAL_UDP_close_without_connect(intptr_t sockfd)
{
    return close((int)sockfd);
}

intptr_t HAL_UDP_create(char *host, unsigned short port)
{
    return 0;
}

intptr_t HAL_UDP_create_without_connect(const char *host, unsigned short port)
{
    return (intptr_t)0;
}

int HAL_UDP_joinmulticast(intptr_t sockfd,
                          char *p_group)
{
    return 0;
}

/**
 * @brief Read data from the specific UDP connection by blocked
 *
 * @param [in] p_socket @n A descriptor identifying a UDP connection.
 * @param [in] p_data @n A pointer to a buffer to receive incoming data.
 * @param [out] datalen @n The length, in bytes, of the data pointed to by the 'p_data' parameter.
 * @return
 *
 * @retval < 0 : UDP connect error occur.
 * @retval = 0 : End of file.
 * @retval > 0 : The number of byte read.
 * @see None.
 */
int HAL_UDP_read(intptr_t p_socket,
                 unsigned char *p_data,
                 unsigned int datalen)
{
    return 0;
}

int HAL_UDP_readTimeout(intptr_t p_socket,
                        unsigned char *p_data,
                        unsigned int datalen,
                        unsigned int timeout)
{
    return 0;
}

int HAL_UDP_recvfrom(intptr_t sockfd,
                     NetworkAddr *p_remote,
                     unsigned char *p_data,
                     unsigned int datalen,
                     unsigned int timeout_ms)
{
    return 0;
}

int HAL_UDP_sendto(intptr_t sockfd,
                   const NetworkAddr *p_remote,
                   const unsigned char *p_data,
                   unsigned int datalen,
                   unsigned int timeout_ms)
{
    return 0;
}

int HAL_UDP_write(intptr_t p_socket,
                  const unsigned char *p_data,
                  unsigned int datalen)
{
    return 0;
}

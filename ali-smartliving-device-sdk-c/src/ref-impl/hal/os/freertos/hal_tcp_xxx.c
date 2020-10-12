#include <stdio.h>
#include <string.h>

#include "iot_import.h"

uintptr_t HAL_TCP_Establish(const char *host, uint16_t port)
{
    int fd = -1;

    return (uintptr_t)fd;
}

int HAL_TCP_Destroy(uintptr_t fd)
{
    return 0;
}

int32_t HAL_TCP_Write(uintptr_t fd, const char *buf, uint32_t len, uint32_t timeout_ms)
{
    uint32_t len_sent;

    return len_sent;
}

int32_t HAL_TCP_Read(uintptr_t fd, char *buf, uint32_t len, uint32_t timeout_ms)
{
    int err_code = 0;
    int len_recv = 0;

    /* priority to return data bytes if any data be received from TCP connection. */
    /* It will get error code on next calling */
    return (0 != len_recv) ? len_recv : err_code;
}

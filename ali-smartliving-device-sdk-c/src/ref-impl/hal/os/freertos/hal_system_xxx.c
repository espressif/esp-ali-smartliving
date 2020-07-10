#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "iot_import.h"

extern int HAL_Fclose(void *stream)
{
    return (int)1;
}

extern void *HAL_Fopen(const char *path, const char *mode)
{
    return (void *)1;
}

extern uint32_t HAL_Fread(void *buff, uint32_t size, uint32_t count, void *stream)
{
    return (uint32_t)1;
}

extern int HAL_Fseek(void *stream, long offset, int framewhere)
{
    return (int)1;
}

extern long HAL_Ftell(void *stream)
{
    return (long)1;
}

extern uint32_t HAL_Fwrite(const void *ptr, uint32_t size, uint32_t count, void *stream)
{
    return (uint32_t)1;
}

extern void *HAL_Realloc(void *ptr, uint32_t size)
{
    return realloc(ptr, size);
}

/**
 * @brief Writes formatted data to stream.
 *
 * @param [in] fmt: @n String that contains the text to be written, it can optionally contain embedded format specifiers
     that specifies how subsequent arguments are converted for output.
 * @param [in] ...: @n the variable argument list, for formatted and inserted in the resulting string replacing their respective specifiers.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_Printf(const char *fmt, ...)
{

}
/**
 * @brief Writes formatted data to string.
 *
 * @param [out] str: @n String that holds written text.
 * @param [in] len: @n Maximum length of character will be written
 * @param [in] fmt: @n Format that contains the text to be written, it can optionally contain embedded format specifiers
     that specifies how subsequent arguments are converted for output.
 * @param [in] ...: @n the variable argument list, for formatted and inserted in the resulting string replacing their respective specifiers.
 * @return bytes of character successfully written into string.
 * @see None.
 * @note None.
 */
int HAL_Snprintf(char *str, const int len, const char *fmt, ...)
{
    va_list args;
    int rc;

    va_start(args, fmt);
    rc = vsnprintf(str, len, fmt, args);
    va_end(args);

    return rc;
}

int HAL_Vsnprintf(char *str, const int len, const char *format, va_list ap)
{
    return vsnprintf(str, len, format, ap);
}

uint32_t HAL_Random(uint32_t region)
{
    return (region != 0) ? (rand() % region) : 0;
}

void HAL_Srandom(uint32_t seed)
{
    srand(seed);
    return;
}

void HAL_Reboot()
{
    //reboot your system
}

/**
 * @brief check system network is ready(get ip address) or not.
 *
 * @param None.
 * @return 0, net is not ready; 1, net is ready.
 * @see None.
 * @note None.
 */
int HAL_Sys_Net_Is_Ready()
{
    return 0;
}

int HAL_GetNetifInfo(char *nif_str)
{
    memset(nif_str, 0x0, NIF_STRLEN_MAX);
#ifdef __DEMO__
    /* if the device have only WIFI, then list as follow, note that the len MUST NOT exceed NIF_STRLEN_MAX */
    const char *net_info = "WiFi|03ACDEFF0032";
    strncpy(nif_str, net_info, strlen(net_info));
    /* if the device have ETH, WIFI, GSM connections, then list all of them as follow, note that the len MUST NOT exceed NIF_STRLEN_MAX */
    // const char *multi_net_info = "ETH|0123456789abcde|WiFi|03ACDEFF0032|Cellular|imei_0123456789abcde|iccid_0123456789abcdef01234|imsi_0123456789abcde|msisdn_86123456789ab");
    // strncpy(nif_str, multi_net_info, strlen(multi_net_info));
#endif
    return strlen(nif_str);
}

void HAL_UTC_Set(long long ms)
{
    //Update your system time by cloud time
}

int HAL_CRC_32(const unsigned char* crc_data, unsigned int crc_len)
{
    return 0;
}

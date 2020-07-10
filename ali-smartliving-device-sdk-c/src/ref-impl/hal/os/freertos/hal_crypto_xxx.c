#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iot_import.h"

//Used in ALCS
int HAL_Aes128_Cbc_Decrypt(
    p_HAL_Aes128_t aes,
    const void *src,
    size_t blockNum,
    void *dst)
{
    return 0;
}

//Used in ALCS
int HAL_Aes128_Cbc_Encrypt(
    p_HAL_Aes128_t aes,
    const void *src,
    size_t blockNum,
    void *dst)
{
    return 0;
}

//Used in cloud CoAP
DLL_HAL_API int HAL_Aes128_Cfb_Decrypt(
    _IN_ p_HAL_Aes128_t aes,
    _IN_ const void *src,
    _IN_ size_t length,
    _OU_ void *dst)
{
    return 0;
}

DLL_HAL_API int HAL_Aes128_Cfb_Encrypt(
    _IN_ p_HAL_Aes128_t aes,
    _IN_ const void *src,
    _IN_ size_t length,
    _OU_ void *dst)
{
    return 0;
}

int HAL_Aes128_Destroy(p_HAL_Aes128_t aes)
{
    return 0;
}

p_HAL_Aes128_t HAL_Aes128_Init(
    const uint8_t *key,
    const uint8_t *iv,
    AES_DIR_t dir)
{
    return NULL;
}

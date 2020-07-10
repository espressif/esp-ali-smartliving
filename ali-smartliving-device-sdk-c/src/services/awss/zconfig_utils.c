/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */



#include <string.h>
#include <time.h>
#include "zconfig_lib.h"
#include "zconfig_utils.h"
#include "awss_main.h"

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

void zconfig_dump_hex(uint8_t *data, int len, int tab_num)
{
#if (CONFIG_BLDTIME_MUTE_DBGLOG)

#else
    int i;
    for (i = 0; i < len; i++) {
        os_printf("%02x ", data[i]);

        if (!((i + 1) % tab_num)) {
            os_printf("\r\n");
        }
    }

    os_printf("\r\n");
#endif
}
#if 0
void zconfig_dump_ascii(uint8_t *data, int len, int tab_num)
{
    int i;
    for (i = 0; i < len; i++) {
        os_printf("%-2c ", data[i]);

        if (!((i + 1) % tab_num)) {
            os_printf("  ");
        }
    }

    os_printf("\r\n");
}

void zconfig_dump_mac(uint8_t *src, uint8_t *dst)
{
    uint8_t *mac;

    mac = src;
    os_printf("%02x:%02x:%02x:%02x:%02x:%02x > ",
              mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    mac = dst;
    os_printf("%02x:%02x:%02x:%02x:%02x:%02x\r\n",
              mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    /* elimite compiler warning */
    mac = mac;
}
#endif
/* for smartconfig with encrypt */
uint16_t zconfig_checksum_v3(uint8_t *data, uint8_t len)
{
    uint8_t i;
    uint16_t sum = 0, res;

    for (i = 0; i < len; i++) {
        sum += data[i];
    }

    res = sum & (0x3F << 0);
    res |= (sum & (0x3F << 6)) << 2;

    if (!(res & 0x00FF)) {
        res |= 0x0001;
    }
    if (!(res & 0xFF00)) {
        res |= 0x0100;
    }

    return res;
}

static const char *zc_auth_str[] = {
    "open",
    "shared",
    "wpa-psk",
    "wpa-8021x",
    "wpa2-psk",
    "wpa2-8021x",
    "wpa-psk - wpa2-psk",
};

const char *zconfig_auth_str(uint8_t auth)
{
    if (auth <= ZC_AUTH_TYPE_MAX) {
        return zc_auth_str[auth];
    } else {
        return "invalid auth";
    }
}

static const char *zc_encry_str[] = {
    "none",
    "wep",
    "tkip",
    "aes",
    "tkip-aes"
};

const char *zconfig_encry_str(uint8_t encry)
{
    if (encry <= ZC_ENC_TYPE_MAX) {
        return zc_encry_str[encry];
    } else {
        return "invalid encry";
    }
}

uint16_t zconfig_checksum_v5(uint8_t *data, uint8_t len)
{
    uint8_t i;
    uint16_t sum = 0, res;

    for (i = 0; i < len; i++) {
        sum += data[i];
    }

    res = sum ;
    return res;
}

char zconfig_is_utf8(const char *ansi_str, int length)
{
    int i = 0;
    char utf8 = 1;
    while (i < length) {
        if ((0x80 & ansi_str[i]) == 0) { // ASCII
            i++;
            continue;
        } else if ((0xE0 & ansi_str[i]) == 0xC0) { // 110xxxxx
            if (ansi_str[i + 1] == '\0') {
                utf8 = 0;
                break;
            }
            if ((0xC0 & ansi_str[i + 1]) == 0x80) { // 10xxxxxx
                i += 2;
                continue;
            } else {
                utf8 = 0;
                break;
            }
        } else if ((0xF0 & ansi_str[i]) == 0xE0) { // 1110xxxx
            if (ansi_str[i + 1] == '\0') {
                utf8 = 0;
                break;
            }
            if (ansi_str[i + 2] == '\0') {
                utf8 = 0;
                break;
            }
            if (((0xC0 & ansi_str[i + 1]) == 0x80) && ((0xC0 & ansi_str[i + 2]) == 0x80)) { // 10xxxxxx 10xxxxxx
                i += 3;
                continue;
            } else {
                utf8 = 0;
                break;
            }
        } else {
            utf8 = 0;
            break;
        }
    }
    return utf8;
}

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif

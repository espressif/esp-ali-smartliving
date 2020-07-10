/*
 * Copyright (C) 2015-2019 Alibaba Group Holding Limited
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "iot_import.h"
#include "iot_export_linkkit.h"
#include "iotx_log.h"

#include "app_entry.h"
#include "living_platform_rawdata_main.h"
#include "living_platform_rawdata_ut.h"

static living_platform_rawdata_tsl_t living_platform_rawdata_tsl_data;

living_platform_rawdata_tsl_t *living_platform_rawdata_ut_get_tsl_data(void)
{
    return &living_platform_rawdata_tsl_data;
}

int living_platform_rawdata_ut_set_LightSwitch(char LightSwitch)
{
    living_platform_rawdata_tsl_data.LightSwitch = LightSwitch;
    living_platform_rawdata_info("set LightSwitch:%s", (LightSwitch == 0) ? "off" : "on");

    return 0;
}

int living_platform_rawdata_ut_get_LightSwitch(void)
{
    return living_platform_rawdata_tsl_data.LightSwitch;
}

//Just for reference
void user_post_raw_data(void)
{
    static int id = 0;
    int res = 0;
    unsigned char payload[6] = {0};
    living_platform_rawdata_ctx_t *living_platform_rawdata_ctx = living_platform_rawdata_get_ctx();

    id += 1;
    payload[0] = 0x01;
    payload[1] = (id >> 24) & 0xFF;
    payload[2] = (id >> 16) & 0xFF;
    payload[3] = (id >> 8) & 0xFF;
    payload[4] = id & 0xFF;
    payload[5] = living_platform_rawdata_tsl_data.LightSwitch;

    res = IOT_Linkkit_Report(living_platform_rawdata_ctx->master_devid, ITM_MSG_POST_RAW_DATA,
                             payload, 6);

    living_platform_rawdata_info("Post Raw Data Message ID: %d", res);
}

void living_platform_rawdata_ut_misc_process(uint64_t time_now_sec)
{
    /* Post Proprety Example */
    if (time_now_sec % 11 == 0)
    {
        user_post_raw_data();
    }
}

int living_platform_rawdata_ut_init(void)
{
    int ret = SUCCESS_RETURN;

    memset(&living_platform_rawdata_tsl_data, 0, sizeof(living_platform_rawdata_tsl_t));

    living_platform_rawdata_tsl_data.LightSwitch = 1;

    return ret;
}

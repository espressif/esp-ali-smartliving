/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifdef DEV_STATEMACHINE_ENABLE
#include "dev_diagnosis_log.h"
#include "dev_state_machine.h"

static dev_state_t g_dev_state = DEV_STATE_INIT;
static dev_awss_state_t g_awss_state[AWSS_PATTERN_MAX] = {AWSS_STATE_STOP};

dev_state_t dev_state_get()
{
    return g_dev_state;
}

void dev_state_set(dev_state_t state)
{
    g_dev_state = state;
    if (g_dev_state != DEV_STATE_AWSS) {
	uint8_t i = 0;
        for (; i < AWSS_PATTERN_MAX; i++) {
            g_awss_state[i] = AWSS_STATE_STOP;
        }
    }
}

dev_awss_state_t dev_awss_state_get(dev_awss_pattern_t pattern)
{
    return g_awss_state[pattern];
}

void dev_awss_state_set(dev_awss_pattern_t pattern, dev_awss_state_t awss_state)
{
    if (g_dev_state != DEV_STATE_AWSS) {
        g_dev_state = DEV_STATE_AWSS;
    }
    g_awss_state[pattern] = awss_state;
}

#endif
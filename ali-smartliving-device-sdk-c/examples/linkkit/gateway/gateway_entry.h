/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */
#ifndef __APP_ENTRY_H__
#define __APP_ENTRY_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define LOG_LEVEL_DEBUG

typedef struct
{
    int argc;
    char **argv;
} gateway_main_params_t;

#endif
#ifndef __CT_ENTRY_H__
#define __CT_ENTRY_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define LOG_LEVEL_DEBUG

typedef struct
{
    int argc;
    char **argv;
} ct_main_params_t;

extern void user_event_monitor(int event);

#endif

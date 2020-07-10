#ifndef _TICK_NOTIFY_H
#define _TICK_NOTIFY_H	1

#include "stdint.h"

void *iotx_tick_notify_init();
int iotx_tick_notify_deinit();
int iotx_get_notify_time(uint64_t *tick);

#endif
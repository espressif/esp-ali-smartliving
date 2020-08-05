/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifndef __COAP_PLATFORM_OS_H__
#define __COAP_PLATFORM_OS_H__

#include <stdio.h>
#include "iotx_utils.h"
#include "iotx_log.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define COAP_ERR(...)           log_err("coap_local", __VA_ARGS__)
#define COAP_WRN(...)           log_warning("coap_local", __VA_ARGS__)
#define COAP_INFO(...)          log_info("coap_local", __VA_ARGS__)

#define COAP_TRC(...)           log_debug("coap_local", __VA_ARGS__)
#define COAP_DUMP(...)          log_debug("coap_local", __VA_ARGS__)
#define COAP_DEBUG(...)         log_debug("coap_local", __VA_ARGS__)
#define COAP_FLOW(...)          log_debug("coap_local", __VA_ARGS__)


#ifdef TEST_COAP_MEMORY
extern void* mymalloc(int size, char* file, int line);
extern void myfree(void* ptr, char* file, int line);
#define coap_malloc(size)  mymalloc(size,__FILE__,__LINE__) 
#define coap_free(ptr) myfree(ptr,__FILE__,__LINE__)
#else
#define coap_malloc(size)       LITE_malloc(size, MEM_MAGIC, "coap.local")
#define coap_free(ptr)          LITE_free(ptr)
#endif

int platform_is_multicast(const char *ip_str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

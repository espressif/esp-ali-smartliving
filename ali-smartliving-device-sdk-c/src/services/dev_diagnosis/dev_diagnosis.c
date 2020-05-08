/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include "dev_diagnosis_log.h"
#include "dev_state_machine.h"
#include "dev_errcode.h"
#include "dev_diagnosis.h"

static int dev_diagnosis_statecode_handler(const int state_code, const char *state_message)
{
    diagnosis_debug("state_code:-0x%04x, str_msg=%s", -state_code, state_message == NULL ? "NULL" : state_message);
#ifdef DEV_ERRCODE_ENABLE
    dev_errcode_handle(state_code, state_message);
#endif
    return 0;
}

// success:0, fail:-1
int dev_diagnosis_module_init()
{
    int ret = 0;
#ifdef DEV_ERRCODE_ENABLE
    /* device errcode service init */ 
    dev_errcode_module_init();
#endif
    /* device diagnosis sdk state code handler register */
    ret = IOT_RegisterCallback(ITE_STATE_EVERYTHING, dev_diagnosis_statecode_handler);
    return ret;
}

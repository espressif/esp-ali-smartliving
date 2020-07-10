/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifndef _DM_OPT_H
#define _DM_OPT_H

typedef enum {
    DM_OPT_DOWNSTREAM_PROPERTY_POST_REPLY,
    DM_OPT_DOWNSTREAM_EVENT_POST_REPLY,
    DM_OPT_UPSTREAM_PROPERTY_SET_REPLY,
    DM_OPT_UPSTREAM_EVENT_NOTIFY_REPLY
} dm_opt_t;

typedef struct {
    int prop_post_reply_opt;
    int event_post_reply_opt;
    int prop_set_reply_opt;
    int event_notify_reply_opt;
} dm_opt_ctx;

int dm_opt_set(dm_opt_t opt, void *data);
int dm_opt_get(dm_opt_t opt, void *data);

#endif

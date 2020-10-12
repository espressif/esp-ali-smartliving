/*
 * Copyright (C) 2015-2020 Alibaba Group Holding Limited
 */

#include "cJSON.h"
#include "iotx_log.h"
#include "iot_import.h"
#include "iot_export_linkkit.h"
#include "gateway_main.h"
#include "gateway_api.h"

/*
[params]
subdev_mate:one subdev meta info

[return]
SUCCESS_RETURN:success 
FAIL_RETURN:failed
*/
GATEWAY_API int gateway_add_subdev(iotx_linkkit_dev_meta_info_t *subdev_mate)
{
    int res = SUCCESS_RETURN;
    int devid = -1;

    devid = IOT_Linkkit_Open(IOTX_LINKKIT_DEV_TYPE_SLAVE, subdev_mate);
    if (devid == FAIL_RETURN)
    {
        gateway_info("subdev open Failed");
        return FAIL_RETURN;
    }
    gateway_info("subdev open susseed, devid = %d", devid);

    res = IOT_Linkkit_Connect(devid);
    if (res == FAIL_RETURN)
    {
        gateway_info("subdev connect Failed");
        return res;
    }
    gateway_info("subdev connect success: devid = %d", devid);

    res = IOT_Linkkit_Report(devid, ITM_MSG_LOGIN, NULL, 0);
    if (res == FAIL_RETURN)
    {
        gateway_info("subdev login Failed");
        return res;
    }

    return res;
}

/*
[params]
master_devid:master device id
subdev_list:one or more subdev meta info
subdev_num:subdev total

[return]
SUCCESS_RETURN:success 
FAIL_RETURN:failed
*/
GATEWAY_API int gateway_add_multi_subdev(int master_devid, iotx_linkkit_dev_meta_info_t *subdev_list, int subdev_num)
{
    int res = SUCCESS_RETURN;
    int subdev_id = 0;
    int index = 0;
    int inner_index = 0;
    int connect_times = 0;
    int cur_subdev_num = 0;
    iotx_linkkit_dev_meta_info_t *p_cur_subdev = NULL;

    if (!subdev_list || subdev_num < 1)
    {
        gateway_err("add multi subdev Failed\n");
        return FAIL_RETURN;
    }

    connect_times = subdev_num / GATEWAY_SUBDEV_ONE_TIME_CONNECT_MAX_NUM + (((subdev_num % GATEWAY_SUBDEV_ONE_TIME_CONNECT_MAX_NUM) == 0) ? 0 : 1);

    for (index = 0; index < connect_times; index++)
    {
        p_cur_subdev = subdev_list + (index * GATEWAY_SUBDEV_ONE_TIME_CONNECT_MAX_NUM);
        if ((index == (connect_times - 1)) && ((subdev_num % GATEWAY_SUBDEV_ONE_TIME_CONNECT_MAX_NUM) != 0))
        {
            cur_subdev_num = subdev_num - (index * GATEWAY_SUBDEV_ONE_TIME_CONNECT_MAX_NUM);
        }
        else
        {
            cur_subdev_num = GATEWAY_SUBDEV_ONE_TIME_CONNECT_MAX_NUM;
        }

        res = IOT_Linkkit_Report(master_devid, ITM_MSG_CONNECT_SUBDEV, (unsigned char *)p_cur_subdev, sizeof(iotx_linkkit_dev_meta_info_t) * cur_subdev_num);
        if (res == FAIL_RETURN)
        {
            gateway_err("add multi subdev index:%d Failed\n", index);
        }
        else
        {
            gateway_info("add multi subdev index:%d success\n", index);

            iotx_linkkit_dev_meta_info_t *p_subdev_mate = NULL;

            for (inner_index = 0; inner_index < cur_subdev_num; inner_index++)
            {
                p_subdev_mate = p_cur_subdev + inner_index;
                subdev_id = gateway_query_subdev_id(master_devid, p_subdev_mate);
                if (subdev_id > 0)
                {
                    res = IOT_Linkkit_Report(subdev_id, ITM_MSG_LOGIN, NULL, 0);
                    if (res == FAIL_RETURN)
                    {
                        gateway_err("login subdev dn:%s failed", p_subdev_mate->device_name);
                    }
                    else
                    {
                        gateway_debug("login subdev dn:%s success", p_subdev_mate->device_name);
                    }
                }
                else
                {
                    gateway_err("connect subdev dn:%s failed", p_subdev_mate->device_name);
                }
            }
        }
    }

    return res;
}

/*
[params]
subdev_mate:one subdev meta info

[return]
SUCCESS_RETURN:success 
FAIL_RETURN:failed
*/
GATEWAY_API int gateway_del_subdev(iotx_linkkit_dev_meta_info_t *subdev_mate)
{
    int subdev_id = 1000; //set an not exist subdev id
    int ret = SUCCESS_RETURN;

    gateway_info("do del subdev");

    //Here pk and dn of subdev is priorior than subdev id
    ret = IOT_Linkkit_Report(subdev_id, ITM_MSG_DELETE_TOPO, (unsigned char *)subdev_mate, sizeof(iotx_linkkit_dev_meta_info_t));
    if (SUCCESS_RETURN != ret)
    {
        gateway_err("del subdev failed");
    }

    return 0;
}

/*
[params]
subdev_mate:one subdev meta info

[return]
SUCCESS_RETURN:success 
FAIL_RETURN:failed
*/
GATEWAY_API int gateway_reset_subdev(iotx_linkkit_dev_meta_info_t *subdev_mate)
{
    int subdev_id = 1000; //set an not exist subdev id
    int ret = SUCCESS_RETURN;

    gateway_info("do reset subdev");

    //Here pk and dn of subdev is priorior than subdev id
    ret = IOT_Linkkit_Report(subdev_id, ITM_MSG_SUBDEV_RESET, (unsigned char *)subdev_mate, sizeof(iotx_linkkit_dev_meta_info_t));
    if (SUCCESS_RETURN != ret)
    {
        gateway_err("reset subdev failed");
    }

    return ret;
}

/*
[params]
master_devid:master device id
subdev_mate:one subdev meta info

[return]
subdev_id:>0 success <=0 failed
*/
GATEWAY_API int gateway_query_subdev_id(int master_devid, iotx_linkkit_dev_meta_info_t *subdev_mate)
{
    int subdev_id = -1; //set an not exist subdev id

    gateway_info("query subdev id");

    subdev_id = IOT_Linkkit_Query(master_devid, ITM_MSG_QUERY_SUBDEV_ID, (unsigned char *)subdev_mate, sizeof(iotx_linkkit_dev_meta_info_t));
    if (subdev_id < 0)
    {
        gateway_err("subdev not exist");
    }
    else
    {
        gateway_info("got subdev id is %d", subdev_id);
    }

    return subdev_id;
}

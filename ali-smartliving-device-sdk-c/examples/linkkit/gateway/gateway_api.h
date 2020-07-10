#ifndef __GATEWAY_API_H__
#define __GATEWAY_API_H__

#ifndef GATEWAY_API
#define GATEWAY_API
#endif

#define GATEWAY_SUBDEV_ONE_TIME_CONNECT_MAX_NUM (5)

/*
[params]
subdev_mate:one subdev meta info

[return]
SUCCESS_RETURN:success 
FAIL_RETURN:failed
*/
extern GATEWAY_API int gateway_add_subdev(iotx_linkkit_dev_meta_info_t *subdev_mate);

/*
[params]
master_devid:master device id
subdev_list:one or more subdev meta info
subdev_num:subdev total

[return]
SUCCESS_RETURN:success 
FAIL_RETURN:failed
*/
extern GATEWAY_API int gateway_add_multi_subdev(int master_devid, iotx_linkkit_dev_meta_info_t *subdev_list, int subdev_num);

/*
[params]
subdev_mate:one subdev meta info

[return]
SUCCESS_RETURN:success 
FAIL_RETURN:failed
*/
extern GATEWAY_API int gateway_del_subdev(iotx_linkkit_dev_meta_info_t *subdev_mate);

/*
[params]
subdev_mate:one subdev meta info

[return]
SUCCESS_RETURN:success 
FAIL_RETURN:failed
*/
extern GATEWAY_API int gateway_reset_subdev(iotx_linkkit_dev_meta_info_t *subdev_mate);

/*
[params]
master_devid:master device id
subdev_mate:one subdev meta info

[return]
subdev_id:>0 success <=0 failed
*/
extern GATEWAY_API int gateway_query_subdev_id(int master_devid, iotx_linkkit_dev_meta_info_t *subdev_mate);

#endif

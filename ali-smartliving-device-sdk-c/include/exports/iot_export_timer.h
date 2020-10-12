/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifndef __IOT_EXPORT_TIMER_H__
#define __IOT_EXPORT_TIMER_H__

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

#define NUM_OF_CONTROL_TARGETS 30
#define NUM_OF_TARGETS_FLOAT 10
#define NUM_OF_TARGETS_STRING 3
#define NUM_OF_TSL_TYPES 3  /*   1:int/enum/bool; 2:float/double; 3:text/date   */

#define STRING_MAX_LEN  80
#define DAYS_OF_WEEK    7
// #define ENABLE_LED_HSV
// #define ENABLE_LED_RGB
// #define ENABLE_LED_HSL

void timer_service_clear(void);

typedef void (*callback_fun)(const char *report_data, const char *property_name, int i_value, 
							 double d_value, const char * s_value, int prop_idx);
typedef void (*callback_ntp_fun)();

int timer_service_init(const char **control_list, uint8_t num_control_list, 
                                    const char **countdownlist_target, uint8_t num_countdownlist_target, 
                                    const char **localtimer_list, uint8_t num_localtimer_list, 
                                    callback_fun timer_service_cb, int *num_of_tsl_type, callback_ntp_fun timer_ntp_cb);
int timer_service_property_set(const char* data);
char *timer_service_property_get(const char *request);
void timer_service_clear();
#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif

#endif

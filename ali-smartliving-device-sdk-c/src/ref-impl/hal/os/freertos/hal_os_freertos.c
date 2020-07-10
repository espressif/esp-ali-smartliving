/*
 * Copyright (C) 2015-2020 Alibaba Group Holding Limited
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/timers.h"

#include "iot_import.h"

#define HAL_SEM_MAX_COUNT (10)
#define HAL_SEM_INIT_COUNT (0)

#define DEFAULT_THREAD_NAME "linkkit_task"
#define DEFAULT_THREAD_SIZE (1024)
#define DEFAULT_THREAD_PRORITY (5)
#define TASK_STACK_ALIGN_SIZE (4)

typedef void *Mutex_t;
typedef void *Semaphore_t;
/**
 * @brief Deallocate memory block
 *
 * @param[in] ptr @n Pointer to a memory block previously allocated with platform_malloc.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_Free(void *ptr)
{
    vPortFree(ptr);
}

/**
 * @brief Allocates a block of size bytes of memory, returning a pointer to the beginning of the block.
 *
 * @param [in] size @n specify block size in bytes.
 * @return A pointer to the beginning of the block.
 * @see None.
 * @note Block value is indeterminate.
 */
void *HAL_Malloc(uint32_t size)
{
    return pvPortMalloc(size);
}

/**
 * @brief Create a mutex.
 *
 * @retval NULL : Initialize mutex failed.
 * @retval NOT_NULL : The mutex handle.
 * @see None.
 * @note None.
 */
void *HAL_MutexCreate(void)
{
    Mutex_t sem;

    sem = xSemaphoreCreateMutex();
    if (0 == sem)
    {
        return NULL;
    }

    return sem;
}

/**
 * @brief Destroy the specified mutex object, it will release related resource.
 *
 * @param [in] mutex @n The specified mutex.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_MutexDestroy(void *mutex)
{
    Mutex_t sem;
    if (mutex == NULL)
    {
        return;
    }
    sem = (Mutex_t)mutex;
    vSemaphoreDelete(sem);
}

/**
 * @brief Waits until the specified mutex is in the signaled state.
 *
 * @param [in] mutex @n the specified mutex.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_MutexLock(void *mutex)
{
    BaseType_t ret;
    Mutex_t sem;
    if (mutex == NULL)
    {
        return;
    }

    sem = (Mutex_t)mutex;
    ret = xSemaphoreTake(sem, 0xffffffff);
    while (pdPASS != ret)
    {
        ret = xSemaphoreTake(sem, 0xffffffff);
    }
}

/**
 * @brief Releases ownership of the specified mutex object..
 *
 * @param [in] mutex @n the specified mutex.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_MutexUnlock(void *mutex)
{
    Mutex_t sem;
    if (mutex == NULL)
    {
        return;
    }
    sem = (Mutex_t)mutex;
    (void)xSemaphoreGive(sem);
}

/**
 * @brief   create a semaphore
 *
 * @return semaphore handle.
 * @see None.
 * @note The recommended value of maximum count of the semaphore is 255.
 */
void *HAL_SemaphoreCreate(void)
{
    Semaphore_t sem = 0;
    sem = xSemaphoreCreateCounting(HAL_SEM_MAX_COUNT, HAL_SEM_INIT_COUNT);
    if (0 == sem)
    {
        return NULL;
    }

    return sem;
}

/**
 * @brief   destory a semaphore
 *
 * @param[in] sem @n the specified sem.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_SemaphoreDestroy(void *sem)
{
    Semaphore_t queue;

    if (sem == NULL)
    {
        return;
    }
    queue = (Semaphore_t)sem;

    vSemaphoreDelete(queue);
}

/**
 * @brief   signal thread wait on a semaphore
 *
 * @param[in] sem @n the specified semaphore.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_SemaphorePost(void *sem)
{
    Semaphore_t queue;
    if (sem == NULL)
    {
        return;
    }
    queue = (Semaphore_t)sem;
    (void)xSemaphoreGive(queue);
}

/**
 * @brief   wait on a semaphore
 *
 * @param[in] sem @n the specified semaphore.
 * @param[in] timeout_ms @n timeout interval in millisecond.
     If timeout_ms is PLATFORM_WAIT_INFINITE, the function will return only when the semaphore is signaled.
 * @return
   @verbatim
   =  0: The state of the specified object is signaled.
   =  -1: The time-out interval elapsed, and the object's state is nonsignaled.
   @endverbatim
 * @see None.
 * @note None.
 */
int HAL_SemaphoreWait(void *sem, uint32_t timeout_ms)
{
    BaseType_t ret = 0;
    Semaphore_t queue;
    if (sem == NULL)
    {
        return -1;
    }

    queue = (Semaphore_t)sem;
    ret = xSemaphoreTake(queue, timeout_ms);
    if (pdPASS != ret)
    {
        return -1;
    }
    return 0;
}

/**
 * @brief Sleep thread itself.
 *
 * @param [in] ms @n the time interval for which execution is to be suspended, in milliseconds.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_SleepMs(uint32_t ms)
{
    if ((ms > 0) && (ms < portTICK_RATE_MS))
    {
        ms = portTICK_RATE_MS;
    }

    vTaskDelay(ms / portTICK_RATE_MS);
}

/**
 * @brief  create a thread
 *
 * @param[out] thread_handle @n The new thread handle, memory allocated before thread created and return it, free it after thread joined or exit.
 * @param[in] start_routine @n A pointer to the application-defined function to be executed by the thread.
        This pointer represents the starting address of the thread.
 * @param[in] arg @n A pointer to a variable to be passed to the start_routine.
 * @param[in] hal_os_thread_param @n A pointer to stack params.
 * @param[out] stack_used @n if platform used stack buffer, set stack_used to 1, otherwise set it to 0.
 * @return
   @verbatim
     = 0: on success.
     = -1: error occur.
   @endverbatim
 * @see None.
 * @note None.
 */
int HAL_ThreadCreate(
    void **thread_handle,
    void *(*work_routine)(void *),
    void *arg,
    hal_os_thread_param_t *hal_os_thread_param,
    int *stack_used)
{
    int ret = 0;
    char *name = NULL;
    TaskHandle_t xHandle;
    UBaseType_t priority;
    uint16_t stacksize;

    if (thread_handle == NULL)
    {
        return -1;
    }

    if (work_routine == NULL)
    {
        return -1;
    }

    if (hal_os_thread_param == NULL)
    {
        name = DEFAULT_THREAD_NAME;
        stacksize = DEFAULT_THREAD_SIZE;
    }

    if (stack_used == NULL)
    {
        return -1;
    }

    if (stack_used != NULL)
    {
        *stack_used = 0;
    }

    if (hal_os_thread_param && hal_os_thread_param->name)
    {
        name = hal_os_thread_param->name;
    }
    else
    {
        name = DEFAULT_THREAD_NAME;
    }

    if (hal_os_thread_param && hal_os_thread_param->stack_size > 0)
    {
        stacksize = hal_os_thread_param->stack_size / sizeof(portSTACK_TYPE);
    }
    else
    {
        stacksize = DEFAULT_THREAD_SIZE;
    }

    if (hal_os_thread_param && hal_os_thread_param->priority > 0)
    {
        priority = (UBaseType_t)hal_os_thread_param->priority;
    }
    else
    {
        priority = (UBaseType_t)DEFAULT_THREAD_PRORITY;
    }

    xHandle = (TaskHandle_t)(*thread_handle);

    ret = xTaskCreate(work_routine, name, stacksize, arg, priority, &xHandle);
    *thread_handle = (void *)xHandle;

    return ret;
}

void HAL_ThreadDetach(_IN_ void *thread_handle)
{
    (void)thread_handle;
}

void HAL_ThreadDelete(_IN_ void *thread_handle)
{
    vTaskDelete((TaskHandle_t)thread_handle);
}

/**
 * @brief Retrieves the number of milliseconds that have elapsed since the system was boot.
 *
 * @return the number of milliseconds.
 * @see None.
 * @note None.
 */
uint64_t HAL_UptimeMs(void)
{
    return (uint64_t)xTaskGetTickCount() * portTICK_RATE_MS;
}

void *HAL_Timer_Create_Ex(const char *name, void (*func)(void *), void *user_data, char repeat)
{
    TimerHandle_t timer_handle = NULL;
    timer_handle = xTimerCreate(name, portMAX_DELAY, repeat, NULL, (TimerCallbackFunction_t)func);

    return (void *)timer_handle;
}

void *HAL_Timer_Create(const char *name, void (*func)(void *), void *user_data)
{
    TimerHandle_t timer_handle = NULL;
    timer_handle = xTimerCreate(name, portMAX_DELAY, pdFALSE, NULL, (TimerCallbackFunction_t)func);

    return (void *)timer_handle;
}

int HAL_Timer_Delete(void *timer)
{
    if (!timer)
    {
        return FAIL_RETURN;
    }

    if (pdTRUE == xTimerDelete((TimerHandle_t)timer, portMAX_DELAY))
    {
        return SUCCESS_RETURN;
    }

    return FAIL_RETURN;
}

int HAL_Timer_Start(void *timer, int ms)
{
    if (!timer)
    {
        return FAIL_RETURN;
    }

    uint32_t ticks = ms / portTICK_PERIOD_MS;
    if (ticks == 0)
    {
        ticks = 1;
    }

    if (xTimerChangePeriod(timer, ticks, portMAX_DELAY) != pdTRUE)
    {
        return FAIL_RETURN;
    }
    if (xTimerStart((TimerHandle_t)timer, portMAX_DELAY) != pdTRUE)
    {
        return FAIL_RETURN;
    }

    return SUCCESS_RETURN;
}

int HAL_Timer_Stop(void *timer)
{
    if (!timer)
    {
        return FAIL_RETURN;
    }

    if (pdTRUE == xTimerStop((TimerHandle_t)timer, portMAX_DELAY))
    {
        return SUCCESS_RETURN;
    }

    return FAIL_RETURN;
}

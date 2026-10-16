#pragma once
#include "freertos/FreeRTOS.h"
typedef struct host_semaphore *SemaphoreHandle_t;
SemaphoreHandle_t xSemaphoreCreateBinary(void);
void vSemaphoreDelete(SemaphoreHandle_t semaphore);
int xSemaphoreGive(SemaphoreHandle_t semaphore);
int xSemaphoreTake(SemaphoreHandle_t semaphore, TickType_t ticks);

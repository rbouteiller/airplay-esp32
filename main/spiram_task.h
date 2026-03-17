/**
 * Helpers for creating FreeRTOS tasks.
 *
 * On ESP32 with SPIRAM, task stacks must remain in internal RAM because
 * SPI flash operations disable the cache, making SPIRAM inaccessible.
 * Placing stacks there causes esp_task_stack_is_sane_cache_disabled()
 * asserts.  These wrappers keep the call-site API stable regardless.
 *
 * Usage:
 *   Permanent tasks (never deleted):
 *     task_create_spiram(fn, "name", depth, param, prio, &handle, NULL);
 *
 *   Transient tasks (deleted later):
 *     spiram_task_mem_t mem;
 *     task_create_spiram(fn, "name", depth, param, prio, &handle, &mem);
 *     // ... later, after the task has exited:
 *     task_free_spiram(&mem);
 */
#pragma once

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

typedef struct {
  void *stack;
  void *tcb;
} spiram_task_mem_t;

static inline BaseType_t task_create_spiram(TaskFunction_t fn, const char *name,
                                            uint32_t depth, void *param,
                                            UBaseType_t prio,
                                            TaskHandle_t *handle,
                                            spiram_task_mem_t *mem) {
  if (mem) {
    mem->stack = NULL;
    mem->tcb = NULL;
  }
  return xTaskCreate(fn, name, depth, param, prio, handle);
}

static inline BaseType_t
task_create_pinned_spiram(TaskFunction_t fn, const char *name, uint32_t depth,
                          void *param, UBaseType_t prio, TaskHandle_t *handle,
                          BaseType_t core, spiram_task_mem_t *mem) {
  if (mem) {
    mem->stack = NULL;
    mem->tcb = NULL;
  }
  return xTaskCreatePinnedToCore(fn, name, depth, param, prio, handle, core);
}

static inline void task_free_spiram(spiram_task_mem_t *mem) {
  (void)mem;
}

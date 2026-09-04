#include "audio_decode_worker.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include "esp_heap_caps.h"
#include "esp_log.h"

#include "audio_receiver_internal.h"

#define AUDIO_DECODE_QUEUE_DEPTH 16U
#define AUDIO_DECODE_MAX_PAYLOAD 8192U
#define AUDIO_DECODE_TASK_STACK  6144U

/* Sits above the buffered TCP reader (5) so decoded PCM keeps draining ahead
 * of ingress, and below the RTP/control receivers (7/8) and the I2S playback
 * task (9) so bulk AAC decoding can never delay them.  Deliberately not
 * pinned: the AAC decode it takes over used to run inline on the unpinned
 * "buff_audio" task, and on ESP32 core 0 is already shared with WiFi, BT and
 * lwIP. */
#define AUDIO_DECODE_TASK_PRIORITY 6

typedef struct audio_decode_job {
  uint32_t generation;
  audio_encoded_packet_t packet;
  uint8_t payload[];
} audio_decode_job_t;

struct audio_decode_worker {
  audio_receiver_state_t *state;
  QueueHandle_t queue;
  TaskHandle_t task;
  volatile bool running;
  volatile uint32_t cancel_generation;
};

static const char *TAG = "audio_decode";

static audio_decode_job_t *job_alloc(size_t payload_len) {
  if (payload_len == 0U || payload_len > AUDIO_DECODE_MAX_PAYLOAD ||
      payload_len > SIZE_MAX - sizeof(audio_decode_job_t)) {
    return NULL;
  }

  const size_t bytes = sizeof(audio_decode_job_t) + payload_len;
  audio_decode_job_t *job = NULL;
#ifdef CONFIG_SPIRAM
  job = heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
#endif
  if (!job) {
    job = malloc(bytes);
  }
  return job;
}

static void job_free(audio_decode_job_t *job) {
  free(job);
}

static void decode_task(void *arg) {
  audio_decode_worker_t *worker = (audio_decode_worker_t *)arg;

  for (;;) {
    audio_decode_job_t *job = NULL;
    if (xQueueReceive(worker->queue, &job, portMAX_DELAY) != pdTRUE) {
      continue;
    }

    /* NULL is the shutdown sentinel. */
    if (!job) {
      if (!worker->running) {
        break;
      }
      continue;
    }

    (void)__atomic_add_fetch(&worker->state->engine_v2.diag_dequeued, 1U,
                             __ATOMIC_RELAXED);

    const uint32_t current_generation =
        __atomic_load_n(&worker->cancel_generation, __ATOMIC_ACQUIRE);

    /* Each queued job owns its payload and records the generation at enqueue
     * time.  A flush invalidates all old jobs without touching any shared slot
     * pool, so ownership cannot be lost between two queues. */
    if (worker->running && job->generation == current_generation &&
        audio_epoch_matches(&worker->state->engine_v2.epoch,
                            job->packet.epoch)) {
      if (!audio_stream_decode_encoded_packet(worker->state, &job->packet)) {
        worker->state->stats.packets_dropped++;
      }
    } else {
      worker->state->stats.packets_dropped++;
      (void)__atomic_add_fetch(&worker->state->engine_v2.diag_epoch_drops, 1U,
                               __ATOMIC_RELAXED);
    }

    job_free(job);
  }

  worker->task = NULL;
  vTaskDelete(NULL);
}

esp_err_t audio_decode_worker_create(audio_receiver_state_t *state,
                                     audio_decode_worker_t **out_worker) {
  if (!state || !out_worker) {
    return ESP_ERR_INVALID_ARG;
  }

  audio_decode_worker_t *worker = calloc(1, sizeof(*worker));
  if (!worker) {
    return ESP_ERR_NO_MEM;
  }
  worker->state = state;
  worker->queue =
      xQueueCreate(AUDIO_DECODE_QUEUE_DEPTH, sizeof(audio_decode_job_t *));
  if (!worker->queue) {
    free(worker);
    return ESP_ERR_NO_MEM;
  }

  worker->running = true;
  BaseType_t ok =
      xTaskCreate(decode_task, "audio_decode", AUDIO_DECODE_TASK_STACK, worker,
                  AUDIO_DECODE_TASK_PRIORITY, &worker->task);
  if (ok != pdPASS || !worker->task) {
    worker->running = false;
    vQueueDelete(worker->queue);
    free(worker);
    return ESP_ERR_NO_MEM;
  }

  ESP_LOGI(
      TAG, "DQ1 pointer-job queue ready: depth=%u max_payload=%u ownership=job",
      (unsigned)AUDIO_DECODE_QUEUE_DEPTH, (unsigned)AUDIO_DECODE_MAX_PAYLOAD);
  *out_worker = worker;
  return ESP_OK;
}

void audio_decode_worker_discard_pending(audio_decode_worker_t *worker) {
  if (!worker || !worker->queue) {
    return;
  }

  /* Invalidate a job that the decoder task may already have removed from the
   * queue, then free every job that is still queued.  There is no reusable
   * slot/free-queue accounting to reconstruct after a flush. */
  const uint32_t generation =
      __atomic_add_fetch(&worker->cancel_generation, 1U, __ATOMIC_ACQ_REL);

  size_t discarded = 0U;
  audio_decode_job_t *job = NULL;
  while (xQueueReceive(worker->queue, &job, 0) == pdTRUE) {
    if (job) {
      job_free(job);
      discarded++;
    }
  }

  if (discarded > 0U) {
    ESP_LOGI(TAG, "DQ1 flush: generation=%lu discarded=%u",
             (unsigned long)generation, (unsigned)discarded);
  }
}

void audio_decode_worker_destroy(audio_decode_worker_t *worker) {
  if (!worker) {
    return;
  }

  if (worker->queue) {
    audio_decode_worker_discard_pending(worker);
  }

  if (worker->task) {
    worker->running = false;
    audio_decode_job_t *stop = NULL;
    (void)xQueueSend(worker->queue, &stop, 0);
    for (int i = 0; i < 100 && worker->task; ++i) {
      vTaskDelay(1);
    }
  }

  if (worker->task) {
    ESP_LOGE(TAG, "DQ1 destroy timeout: decoder task still running");
    /* Do not delete the queue or free worker memory underneath a live task. */
    return;
  }

  if (worker->queue) {
    audio_decode_job_t *job = NULL;
    while (xQueueReceive(worker->queue, &job, 0) == pdTRUE) {
      if (job) {
        job_free(job);
      }
    }
    vQueueDelete(worker->queue);
  }
  free(worker);
}

audio_decode_enqueue_result_t
audio_decode_worker_enqueue(audio_decode_worker_t *worker,
                            const audio_encoded_packet_t *packet,
                            uint32_t timeout_ms) {
  if (!worker || !worker->running || !worker->queue || !packet ||
      !packet->payload || packet->payload_len == 0U ||
      packet->payload_len > AUDIO_DECODE_MAX_PAYLOAD) {
    return AUDIO_DECODE_ENQUEUE_DROP;
  }

  const uint32_t generation =
      __atomic_load_n(&worker->cancel_generation, __ATOMIC_ACQUIRE);

  if (!audio_epoch_matches(&worker->state->engine_v2.epoch, packet->epoch)) {
    return AUDIO_DECODE_ENQUEUE_DROP;
  }

  audio_decode_job_t *job = job_alloc(packet->payload_len);
  if (!job) {
    ESP_LOGW(TAG, "DQ1 allocation drop: payload=%u pending=%u",
             (unsigned)packet->payload_len,
             (unsigned)uxQueueMessagesWaiting(worker->queue));
    return AUDIO_DECODE_ENQUEUE_DROP;
  }

  job->generation = generation;
  job->packet = *packet;
  memcpy(job->payload, packet->payload, packet->payload_len);
  job->packet.payload = job->payload;

  /* Close the race with a concurrent flush after allocation/copy. */
  if (!worker->running ||
      generation !=
          __atomic_load_n(&worker->cancel_generation, __ATOMIC_ACQUIRE) ||
      !audio_epoch_matches(&worker->state->engine_v2.epoch, packet->epoch)) {
    job_free(job);
    return AUDIO_DECODE_ENQUEUE_DROP;
  }

  TickType_t timeout = timeout_ms == 0U ? 0 : pdMS_TO_TICKS(timeout_ms);
  if (timeout_ms > 0U && timeout == 0) {
    timeout = 1;
  }
  if (xQueueSend(worker->queue, &job, timeout) != pdTRUE) {
    job_free(job);
    return AUDIO_DECODE_ENQUEUE_RETRY;
  }

  return AUDIO_DECODE_ENQUEUE_OK;
}

size_t audio_decode_worker_pending(const audio_decode_worker_t *worker) {
  if (!worker || !worker->queue) {
    return 0;
  }
  return (size_t)uxQueueMessagesWaiting(worker->queue);
}

bool audio_decode_worker_is_nearly_full(const audio_decode_worker_t *worker) {
  return audio_decode_worker_pending(worker) >= (AUDIO_DECODE_QUEUE_DEPTH - 4U);
}

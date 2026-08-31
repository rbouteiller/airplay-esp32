#include "audio_timeline.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "freertos/task.h"

static const char *TAG = "audio_timeline";

static inline int32_t rtp_diff(uint32_t a, uint32_t b) {
  return (int32_t)(a - b);
}

static inline int16_t *slot_pcm(const audio_timeline_t *t, uint16_t index) {
  return &t->pcm_pool[(size_t)index * t->slot_pcm_samples];
}

/* Each valid frame start advances by exactly `frame_samples` RTP samples, so
 * every start in an epoch shares one phase relative to base_rtp.  Physical
 * ring addressing is relative to base_rtp so it stays sequential across RTP
 * wrap.  ALAC's 352-sample frame is not a power of two, so this is real
 * division rather than a mask. */
static inline uint16_t slot_index_for_start(const audio_timeline_t *t,
                                            uint32_t block_start) {
  /* rtp_diff() gives the short signed distance across 32-bit RTP wrap.  Every
   * valid frame start has the same phase, so the distance is an exact multiple
   * of frame_samples.  Normalize negative (out-of-order older) frames into the
   * ring. */
  const int32_t delta_samples = rtp_diff(block_start, t->base_rtp);
  const int32_t delta_blocks = delta_samples / (int32_t)t->frame_samples;
  int32_t index = delta_blocks % (int32_t)t->capacity;
  if (index < 0) {
    index += t->capacity;
  }
  return (uint16_t)index;
}

/* Round `cursor` down to the start of the frame containing it.  C division
 * truncates toward zero, so negative distances need an explicit floor step;
 * the multiply back is done unsigned so it wraps modulo 2^32 like RTP does. */
static inline uint32_t block_start_for_cursor(const audio_timeline_t *t,
                                              uint32_t cursor) {
  const int32_t frame = (int32_t)t->frame_samples;
  const int32_t delta = rtp_diff(cursor, t->base_rtp);
  int32_t blocks = delta / frame;
  if (delta % frame != 0 && delta < 0) {
    blocks--;
  }
  return t->base_rtp + (uint32_t)blocks * t->frame_samples;
}

static inline bool desc_ready_exact(const audio_timeline_desc_t *desc,
                                    uint32_t epoch, uint32_t start) {
  return desc->used && !desc->writing && desc->epoch == epoch &&
         desc->rtp_start == start;
}

/* Returns the descriptor index of the READY block whose exact start is
 * `start`, or UINT16_MAX when there is none. */
static uint16_t ready_index_for_start(const audio_timeline_t *t, uint32_t epoch,
                                      uint32_t start) {
  const uint16_t index = slot_index_for_start(t, start);
  return desc_ready_exact(&t->desc[index], epoch, start) ? index : UINT16_MAX;
}

static bool ensure_base_locked(audio_timeline_t *t, uint32_t epoch,
                               uint32_t frame_start) {
  if (!t->base_valid || t->base_epoch != epoch) {
    t->base_valid = true;
    t->base_epoch = epoch;
    t->base_rtp = frame_start;
    return true;
  }
  /* All frame starts in one epoch must share the same phase. */
  if (rtp_diff(frame_start, t->base_rtp) % (int32_t)t->frame_samples == 0) {
    return true;
  }
  /* A gapless track change can shift RTP phase without ending the epoch: the
   * sender simply steps by a value that is not a whole number of frames.  Once
   * the ring is empty no descriptor is addressed relative to the old base, so
   * adopt the new phase instead of rejecting every write for the rest of the
   * epoch.  While blocks are still outstanding the old phase must stand, so
   * the new track only lands after the outgoing one has played out. */
  if (t->count == 0U && t->writing_count == 0U) {
    t->base_rtp = frame_start;
    return true;
  }
  return false;
}

/* Find the READY block covering target, or the first READY block after it.
 * Returns the sample position to start at: target when covered, otherwise the
 * next block's first RTP.  At most one physical ring revolution is searched. */
static bool find_covering_or_next_locked(audio_timeline_t *t, uint32_t epoch,
                                         uint32_t target, uint32_t *start_out) {
  if (!t->base_valid || t->base_epoch != epoch || t->count == 0U) {
    return false;
  }

  uint32_t block_start = block_start_for_cursor(t, target);
  if (ready_index_for_start(t, epoch, block_start) != UINT16_MAX &&
      rtp_diff(target, block_start) >= 0 &&
      rtp_diff(block_start + t->frame_samples, target) > 0) {
    *start_out = target;
    return true;
  }

  uint32_t next = block_start + t->frame_samples;
  for (uint16_t i = 0; i < t->capacity; ++i, next += t->frame_samples) {
    if (ready_index_for_start(t, epoch, next) != UINT16_MAX) {
      *start_out = next;
      return true;
    }
  }
  return false;
}

esp_err_t audio_timeline_init(audio_timeline_t *t, uint16_t capacity,
                              uint32_t frame_samples) {
  if (!t || capacity == 0U || frame_samples == 0U ||
      frame_samples > AUDIO_PCM_BLOCK_MAX_SAMPLES) {
    return ESP_ERR_INVALID_ARG;
  }
  memset(t, 0, sizeof(*t));

  t->frame_samples = frame_samples;
  t->slot_pcm_samples = frame_samples * AUDIO_V2_MAX_CHANNELS;
  t->pool_pcm_samples = (size_t)capacity * t->slot_pcm_samples;
  /* Enough descriptors for the pool re-cut into the smallest supported frame,
   * so switching codecs never has to reallocate under a live stream. */
  t->max_capacity =
      (uint16_t)(t->pool_pcm_samples /
                 (AUDIO_TIMELINE_RT_FRAME_SAMPLES * AUDIO_V2_MAX_CHANNELS));

  /* Descriptors must stay in internal RAM: they are walked under a spinlock. */
  t->desc = calloc(t->max_capacity, sizeof(*t->desc));
  if (!t->desc) {
    audio_timeline_deinit(t);
    return ESP_ERR_NO_MEM;
  }

  const size_t pcm_bytes = t->pool_pcm_samples * sizeof(int16_t);
#ifdef CONFIG_SPIRAM
  t->pcm_pool =
      heap_caps_malloc(pcm_bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
#endif
  if (!t->pcm_pool) {
    t->pcm_pool = malloc(pcm_bytes);
  }
  if (!t->pcm_pool) {
    audio_timeline_deinit(t);
    return ESP_ERR_NO_MEM;
  }

  t->space_available = xSemaphoreCreateBinary();
  if (!t->space_available) {
    audio_timeline_deinit(t);
    return ESP_ERR_NO_MEM;
  }

  t->capacity = capacity;
  t->lock = (portMUX_TYPE)portMUX_INITIALIZER_UNLOCKED;
  return ESP_OK;
}

void audio_timeline_deinit(audio_timeline_t *t) {
  if (!t) {
    return;
  }
  if (t->space_available) {
    vSemaphoreDelete(t->space_available);
  }
  free(t->desc);
  free(t->pcm_pool);
  memset(t, 0, sizeof(*t));
}

void audio_timeline_clear_slots(audio_timeline_t *t) {
  if (!t || !t->desc) {
    return;
  }
  portENTER_CRITICAL(&t->lock);

  /* READY blocks disappear immediately.  WRITING reservations and slots being
   * copied out deliberately remain private until their owner revalidates the
   * epoch and releases them. */
  for (uint16_t i = 0; i < t->capacity; ++i) {
    t->desc[i].used = false;
  }
  t->count = 0U;
  t->base_valid = false;
  t->playback_floor_valid = false;

  portEXIT_CRITICAL(&t->lock);
}

void audio_timeline_signal_space(audio_timeline_t *t) {
  /* A producer blocked on a full timeline must observe the flush promptly. */
  if (t && t->space_available) {
    xSemaphoreGive(t->space_available);
  }
}

void audio_timeline_clear(audio_timeline_t *t) {
  audio_timeline_clear_slots(t);
  audio_timeline_signal_space(t);
}

/* True once no task can still be holding a raw slot pointer: no reservation is
 * open and nothing is being copied out. */
static bool timeline_slots_idle(audio_timeline_t *t) {
  portENTER_CRITICAL(&t->lock);
  bool idle = (t->writing_count == 0U);
  for (uint16_t i = 0; idle && i < t->capacity; ++i) {
    if (t->desc[i].reading) {
      idle = false;
    }
  }
  portEXIT_CRITICAL(&t->lock);
  return idle;
}

bool audio_timeline_set_frame_samples(audio_timeline_t *t,
                                      uint32_t frame_samples) {
  if (!t || !t->desc || frame_samples == 0U ||
      frame_samples > AUDIO_PCM_BLOCK_MAX_SAMPLES) {
    return false;
  }
  const uint32_t slot_pcm_samples = frame_samples * AUDIO_V2_MAX_CHANNELS;
  const size_t slots = t->pool_pcm_samples / slot_pcm_samples;
  if (slots == 0U || slots > t->max_capacity) {
    return false;
  }
  if (t->frame_samples == frame_samples) {
    return true;
  }

  audio_timeline_clear(t);

  /* Slot addresses are derived from the stride, so re-cutting under a task
   * that is still copying through a pointer it took under the old one lets
   * that straggler land on a slot the new layout has already handed out.  The
   * caller bumps the epoch first, which stops new reservations, so this only
   * has to outlast the copies already running -- a few microseconds each. */
  bool idle = false;
  for (int i = 0; i < 50; ++i) {
    idle = timeline_slots_idle(t);
    if (idle) {
      break;
    }
    vTaskDelay(1);
  }
  if (!idle) {
    ESP_LOGW(TAG, "re-cut to frame=%" PRIu32 " with copies still in flight",
             frame_samples);
  }

  portENTER_CRITICAL(&t->lock);
  /* Wipe every descriptor, not just the ones the old capacity covered: growing
   * the slot count exposes stale flags above it, and shrinking it strands any
   * writer above the new one.  Both are safe to drop here because commit() and
   * cancel() no-op once `writing` is clear. */
  memset(t->desc, 0, (size_t)t->max_capacity * sizeof(*t->desc));
  t->writing_count = 0U;
  t->frame_samples = frame_samples;
  t->slot_pcm_samples = slot_pcm_samples;
  t->capacity = (uint16_t)slots;
  portEXIT_CRITICAL(&t->lock);
  return true;
}

size_t audio_timeline_count(audio_timeline_t *t) {
  if (!t || !t->desc) {
    return 0U;
  }
  portENTER_CRITICAL(&t->lock);
  const size_t n = t->count;
  portEXIT_CRITICAL(&t->lock);
  return n;
}

size_t audio_timeline_discard_from(audio_timeline_t *t, uint32_t epoch,
                                   uint32_t rtp) {
  if (!t || !t->desc) {
    return 0U;
  }

  size_t dropped = 0U;
  portENTER_CRITICAL(&t->lock);

  for (uint16_t i = 0; i < t->capacity; ++i) {
    audio_timeline_desc_t *d = &t->desc[i];
    if (!d->used || d->epoch != epoch) {
      continue;
    }
    /* Drop any block that extends past the cut point.  Blocks that end at or
     * before it belong to the outgoing track and must still play out. */
    if (rtp_diff(d->rtp_start + t->frame_samples, rtp) > 0) {
      d->used = false;
      if (t->count > 0U) {
        t->count--;
      }
      dropped++;
    }
  }

  /* The origin stays valid: the surviving blocks and the replacement content
   * share it, which is what keeps the outgoing track playing seamlessly into
   * the new one. */
  portEXIT_CRITICAL(&t->lock);

  if (dropped > 0U && t->space_available) {
    xSemaphoreGive(t->space_available);
  }
  return dropped;
}

size_t audio_timeline_trim_before(audio_timeline_t *t, uint32_t epoch,
                                  uint32_t rtp) {
  if (!t || !t->desc) {
    return 0U;
  }

  size_t dropped = 0U;
  portENTER_CRITICAL(&t->lock);

  for (uint16_t i = 0; i < t->capacity; ++i) {
    audio_timeline_desc_t *d = &t->desc[i];
    if (!d->used || d->reading || d->epoch != epoch) {
      continue;
    }
    if (rtp_diff(d->rtp_start + t->frame_samples, rtp) <= 0) {
      d->used = false;
      if (t->count > 0U) {
        t->count--;
      }
      dropped++;
    }
  }

  portEXIT_CRITICAL(&t->lock);

  if (dropped > 0U && t->space_available) {
    xSemaphoreGive(t->space_available);
  }
  return dropped;
}

size_t audio_timeline_free_slots(audio_timeline_t *t) {
  if (!t || !t->desc) {
    return 0U;
  }
  portENTER_CRITICAL(&t->lock);
  const size_t occupied = (size_t)t->count + (size_t)t->writing_count;
  const size_t n = occupied < t->capacity ? t->capacity - occupied : 0U;
  portEXIT_CRITICAL(&t->lock);
  return n;
}

bool audio_timeline_is_nearly_full(audio_timeline_t *t) {
  return t && audio_timeline_free_slots(t) < 8U;
}

bool audio_timeline_phase_blocked(audio_timeline_t *t, uint32_t epoch,
                                  uint32_t rtp_start) {
  if (!t || !t->desc) {
    return false;
  }
  portENTER_CRITICAL(&t->lock);
  const bool blocked =
      t->base_valid && t->base_epoch == epoch &&
      (rtp_diff(rtp_start, t->base_rtp) % (int32_t)t->frame_samples) != 0 &&
      (t->count != 0U || t->writing_count != 0U);
  portEXIT_CRITICAL(&t->lock);
  return blocked;
}

bool audio_timeline_wait_for_space(audio_timeline_t *t, uint32_t timeout_ms) {
  if (!t || !t->space_available) {
    return false;
  }
  TickType_t ticks = pdMS_TO_TICKS(timeout_ms);
  if (timeout_ms > 0U && ticks == 0) {
    ticks = 1;
  }
  return xSemaphoreTake(t->space_available, ticks) == pdTRUE;
}

void audio_timeline_set_playback_floor(audio_timeline_t *t, uint32_t epoch,
                                       uint32_t floor_rtp) {
  if (!t || !t->desc) {
    return;
  }
  portENTER_CRITICAL(&t->lock);
  t->playback_floor_valid = true;
  t->playback_floor_epoch = epoch;
  t->playback_floor_rtp = floor_rtp;
  portEXIT_CRITICAL(&t->lock);
}

bool audio_timeline_reserve(audio_timeline_t *t, uint32_t epoch,
                            uint32_t rtp_start,
                            audio_timeline_reservation_t *reservation,
                            int16_t **pcm_out) {
  if (!t || !t->desc || !reservation || !pcm_out) {
    return false;
  }

  reservation->valid = false;
  reservation->duplicate = false;
  *pcm_out = NULL;

  portENTER_CRITICAL(&t->lock);

  if (!ensure_base_locked(t, epoch, rtp_start)) {
    portEXIT_CRITICAL(&t->lock);
    return false;
  }

  const uint16_t idx = slot_index_for_start(t, rtp_start);
  audio_timeline_desc_t *desc = &t->desc[idx];

  /* Same immutable READY block already exists: successful no-op. */
  if (desc->used && desc->epoch == epoch && desc->rtp_start == rtp_start) {
    reservation->duplicate = true;
    portEXIT_CRITICAL(&t->lock);
    return true;
  }

  /* Another owner holds this physical slot.  Never steal it, even when it has
   * the same RTP: only a committed, idle READY block is safe to recycle. */
  if (desc->writing || desc->reading) {
    portEXIT_CRITICAL(&t->lock);
    return false;
  }

  if (desc->used && desc->epoch == epoch) {
    /* Direct-ring collision: recycle only data the scheduler explicitly
     * jumped past. Unread/future PCM remains protected by backpressure. */
    const uint32_t old_end = desc->rtp_start + t->frame_samples;
    const bool stale = t->playback_floor_valid &&
                       t->playback_floor_epoch == epoch &&
                       rtp_diff(old_end, t->playback_floor_rtp) <= 0;
    if (!stale) {
      portEXIT_CRITICAL(&t->lock);
      return false;
    }
  }

  /* Obsolete-epoch or playback-floor-stale READY data is logically free. */
  if (desc->used) {
    desc->used = false;
    if (t->count > 0U) {
      t->count--;
    }
  }

  desc->epoch = epoch;
  desc->rtp_start = rtp_start;
  desc->used = false;
  desc->writing = true;
  t->writing_count++;

  reservation->slot_index = idx;
  reservation->valid = true;
  *pcm_out = slot_pcm(t, idx);

  portEXIT_CRITICAL(&t->lock);
  return true;
}

bool audio_timeline_commit(audio_timeline_t *t,
                           audio_timeline_reservation_t *reservation) {
  if (!t || !t->desc || !reservation || !reservation->valid ||
      reservation->slot_index >= t->capacity) {
    return false;
  }

  portENTER_CRITICAL(&t->lock);
  audio_timeline_desc_t *desc = &t->desc[reservation->slot_index];
  if (!desc->writing || desc->used) {
    reservation->valid = false;
    reservation->duplicate = false;
    portEXIT_CRITICAL(&t->lock);
    return false;
  }

  desc->writing = false;
  desc->used = true;
  if (t->writing_count > 0U) {
    t->writing_count--;
  }
  if (t->count < t->capacity) {
    t->count++;
  }

  reservation->valid = false;
  reservation->duplicate = false;
  portEXIT_CRITICAL(&t->lock);
  return true;
}

void audio_timeline_cancel(audio_timeline_t *t,
                           audio_timeline_reservation_t *reservation) {
  if (!t || !t->desc || !reservation || !reservation->valid ||
      reservation->slot_index >= t->capacity) {
    return;
  }

  portENTER_CRITICAL(&t->lock);
  audio_timeline_desc_t *desc = &t->desc[reservation->slot_index];
  if (desc->writing && !desc->used) {
    desc->writing = false;
    if (t->writing_count > 0U) {
      t->writing_count--;
    }
  }
  reservation->valid = false;
  reservation->duplicate = false;
  portEXIT_CRITICAL(&t->lock);
}

bool audio_timeline_find_contiguous_from(audio_timeline_t *t, uint32_t epoch,
                                         uint32_t target, uint32_t required,
                                         uint32_t max_future, uint32_t *out) {
  if (!t || !t->desc || !out || required == 0U) {
    return false;
  }
  bool ok = false;

  portENTER_CRITICAL(&t->lock);
  uint32_t start = 0U;
  if (!find_covering_or_next_locked(t, epoch, target, &start)) {
    goto done;
  }

  if (rtp_diff(start, target) >= 0 && (uint32_t)(start - target) > max_future) {
    goto done;
  }

  uint32_t cursor = start;
  uint32_t remaining = required;
  while (remaining > 0U) {
    const uint32_t block_start = block_start_for_cursor(t, cursor);
    if (ready_index_for_start(t, epoch, block_start) == UINT16_MAX) {
      break;
    }

    const uint32_t block_end = block_start + t->frame_samples;
    if (rtp_diff(cursor, block_start) < 0 || rtp_diff(block_end, cursor) <= 0) {
      break;
    }

    const uint32_t available = block_end - cursor;
    if (available >= remaining) {
      remaining = 0U;
      break;
    }

    remaining -= available;
    cursor = block_end;
    /* The next loop requires a READY block whose exact start is cursor. */
  }

  if (remaining == 0U) {
    *out = start;
    ok = true;
  }

done:
  portEXIT_CRITICAL(&t->lock);
  return ok;
}

bool audio_timeline_has_playable_from(audio_timeline_t *t, uint32_t epoch,
                                      uint32_t target) {
  if (!t || !t->desc) {
    return false;
  }
  uint32_t start = 0U;
  portENTER_CRITICAL(&t->lock);
  const bool ok = find_covering_or_next_locked(t, epoch, target, &start);
  portEXIT_CRITICAL(&t->lock);
  return ok;
}

/* Length of the hole starting at `cursor`, bounded by `limit`.  Caller holds
 * the timeline lock. */
static size_t conceal_span_locked(audio_timeline_t *t, uint32_t epoch,
                                  uint32_t cursor, uint32_t block_start,
                                  size_t limit) {
  uint32_t next = block_start + t->frame_samples;
  for (uint16_t i = 0; i < t->capacity; ++i, next += t->frame_samples) {
    if (ready_index_for_start(t, epoch, next) != UINT16_MAX) {
      const int32_t gap = rtp_diff(next, cursor);
      if (gap > 0 && (uint32_t)gap < limit) {
        return (size_t)(uint32_t)gap;
      }
      break;
    }
  }
  return limit;
}

size_t audio_timeline_read(audio_timeline_t *t, uint32_t epoch, uint32_t start,
                           int16_t *out, size_t requested, uint8_t channels,
                           bool conceal, size_t *concealed) {
  if (concealed) {
    *concealed = 0U;
  }
  if (!t || !t->desc || !out || requested == 0U || channels == 0U ||
      channels > AUDIO_V2_MAX_CHANNELS) {
    return 0U;
  }

  size_t produced = 0U;
  uint32_t cursor = start;
  bool released_slot = false;

  while (produced < requested) {
    uint16_t index = UINT16_MAX;
    uint32_t block_start = 0U;
    size_t off = 0U;
    size_t n = 0U;

    /* Phase 1: resolve the next block and take ownership of it.  Only
     * descriptor metadata is touched here, so the spinlock is held for a
     * bounded, cache-resident scan. */
    portENTER_CRITICAL(&t->lock);
    if (!t->base_valid || t->base_epoch != epoch) {
      portEXIT_CRITICAL(&t->lock);
      break;
    }

    block_start = block_start_for_cursor(t, cursor);
    index = ready_index_for_start(t, epoch, block_start);

    if (index == UINT16_MAX) {
      if (!conceal) {
        portEXIT_CRITICAL(&t->lock);
        break;
      }
      /* Conceal only the real hole up to the next READY AAC frame. */
      n = conceal_span_locked(t, epoch, cursor, block_start,
                              requested - produced);
      portEXIT_CRITICAL(&t->lock);

      memset(&out[produced * channels], 0, n * channels * sizeof(int16_t));
      produced += n;
      cursor += (uint32_t)n;
      if (concealed) {
        *concealed += n;
      }
      continue;
    }

    off = (size_t)(cursor - block_start);
    if (off >= t->frame_samples) {
      portEXIT_CRITICAL(&t->lock);
      break;
    }
    n = requested - produced;
    const size_t avail = t->frame_samples - off;
    if (n > avail) {
      n = avail;
    }
    t->desc[index].reading = true;
    portEXIT_CRITICAL(&t->lock);

    /* Phase 2: the PSRAM copy runs with interrupts enabled.  The slot is
     * pinned by `reading`, so no producer can recycle it underneath us. */
    memcpy(&out[produced * channels], &slot_pcm(t, index)[off * channels],
           n * channels * sizeof(int16_t));

    /* Phase 3: release ownership and retire the block once fully consumed. */
    portENTER_CRITICAL(&t->lock);
    audio_timeline_desc_t *desc = &t->desc[index];
    desc->reading = false;
    const bool still_valid = desc->used && desc->epoch == epoch &&
                             desc->rtp_start == block_start && t->base_valid &&
                             t->base_epoch == epoch;
    if (still_valid && off + n >= t->frame_samples) {
      desc->used = false;
      if (t->count > 0U) {
        t->count--;
      }
      released_slot = true;
    }
    portEXIT_CRITICAL(&t->lock);

    if (!still_valid) {
      /* A flush landed mid-copy: the samples belong to a discarded stream. */
      memset(&out[produced * channels], 0, n * channels * sizeof(int16_t));
      produced += n;
      if (concealed) {
        *concealed += n;
      }
      break;
    }

    produced += n;
    cursor += (uint32_t)n;
  }

  if (released_slot && t->space_available) {
    xSemaphoreGive(t->space_available);
  }
  return produced;
}

bool audio_timeline_get_diag(audio_timeline_t *t, uint32_t epoch,
                             uint32_t target, audio_timeline_diag_t *out) {
  if (!t || !t->desc || !out) {
    return false;
  }
  memset(out, 0, sizeof(*out));

  portENTER_CRITICAL(&t->lock);
  out->count = t->count;

  uint32_t oldest = 0U, newest = 0U;
  bool have_any = false;
  int32_t best_next_delta = INT32_MAX;

  for (uint16_t i = 0; i < t->capacity; ++i) {
    const audio_timeline_desc_t *desc = &t->desc[i];
    if (!desc->used || desc->epoch != epoch) {
      continue;
    }
    const uint32_t s = desc->rtp_start;
    const uint32_t e = s + t->frame_samples;

    if (!have_any) {
      oldest = newest = s;
      have_any = true;
    } else {
      if (rtp_diff(s, oldest) < 0) {
        oldest = s;
      }
      if (rtp_diff(s, newest) > 0) {
        newest = s;
      }
    }

    if (!out->target_covered && rtp_diff(target, s) >= 0 &&
        rtp_diff(e, target) > 0) {
      out->target_covered = true;
      out->covering_start_rtp = s;
      out->covering_end_rtp = e;
    }

    const int32_t delta = rtp_diff(s, target);
    if (delta > 0 && delta < best_next_delta) {
      best_next_delta = delta;
      out->has_next = true;
      out->next_rtp = s;
    }
  }

  if (have_any) {
    out->has_oldest = true;
    out->oldest_rtp = oldest;
    out->has_newest = true;
    out->newest_start_rtp = newest;
    out->newest_end_rtp = newest + t->frame_samples;
  }

  /* Count contiguous real PCM from target when covered, otherwise from the
   * first future block.  Fixed-size frame addressing makes this direct. */
  if (t->base_valid && t->base_epoch == epoch &&
      (out->target_covered || out->has_next)) {
    uint32_t cursor = out->target_covered ? target : out->next_rtp;
    for (uint16_t i = 0; i < t->capacity; ++i) {
      const uint32_t bs = block_start_for_cursor(t, cursor);
      if (ready_index_for_start(t, epoch, bs) == UINT16_MAX) {
        break;
      }
      const uint32_t end = bs + t->frame_samples;
      if (rtp_diff(cursor, bs) < 0 || rtp_diff(end, cursor) <= 0) {
        break;
      }
      out->contiguous_samples += end - cursor;
      cursor = end;
    }
  }

  portEXIT_CRITICAL(&t->lock);
  return true;
}

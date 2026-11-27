// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "audio_output_cursor.h"

#include <string.h>

/* The interrupt-side calls run from the I2S EOF interrupt, which may be
 * placed in IRAM (CONFIG_I2S_ISR_IRAM_SAFE). */
#ifdef ESP_PLATFORM
#include "esp_attr.h"
#define CURSOR_ISR IRAM_ATTR
#else
#define CURSOR_ISR
#endif

#define LOST    (1U << 31)
#define K_SHIFT 25
#define K_MAX   63U
#define K_MASK  (K_MAX << K_SHIFT)
#define TS_MASK ((1U << K_SHIFT) - 1U)

static inline uint32_t k_of(uint32_t state) {
  return (state & K_MASK) >> K_SHIFT;
}

static inline uint32_t with_k(uint32_t state, uint32_t k) {
  return (state & ~K_MASK) | (k << K_SHIFT);
}

void output_cursor_init(output_cursor_t *c, uint16_t desc_num,
                        uint16_t desc_frames) {
  memset(c, 0, sizeof(*c));
  c->desc_num = desc_num;
  c->desc_frames = desc_frames;
  /* k may run a few past N - 1 for a moment (see output_cursor_depth()),
   * and must stay clear of the lost bit. */
  if (desc_num < 2 || desc_num > 32 || desc_frames == 0) {
    c->desc_num = 0;
  }
  __atomic_store_n(&c->state, LOST, __ATOMIC_RELAXED);
}

void output_cursor_reset(output_cursor_t *c, int64_t now_us) {
  const uint32_t state = c->desc_num ? ((uint32_t)now_us & TS_MASK) : LOST;
  __atomic_store_n(&c->state, state, __ATOMIC_RELAXED);
}

void CURSOR_ISR output_cursor_on_sent(output_cursor_t *c, int64_t now_us) {
  uint32_t old = __atomic_load_n(&c->state, __ATOMIC_RELAXED);
  uint32_t next;
  do {
    uint32_t k = k_of(old);
    if (k < K_MAX) {
      k++;
    }
    next = (with_k(old, k) & ~TS_MASK) | ((uint32_t)now_us & TS_MASK);
  } while (!__atomic_compare_exchange_n(&c->state, &old, next, true,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED));
}

void CURSOR_ISR output_cursor_on_overflow(output_cursor_t *c) {
  __atomic_add_fetch(&c->overflows, 1, __ATOMIC_RELAXED);
  uint32_t old = __atomic_load_n(&c->state, __ATOMIC_RELAXED);
  uint32_t next;
  do {
    if (old & LOST) {
      /* Nobody has taken a buffer for N - 1 EOFs: the queue is full, and
       * whatever the last writer left half-done is about to be abandoned. */
      next = with_k(old & ~LOST, (uint32_t)c->desc_num - 1U);
    } else {
      const uint32_t k = k_of(old);
      next = with_k(old, k > 0 ? k - 1 : 0);
    }
  } while (!__atomic_compare_exchange_n(&c->state, &old, next, true,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED));
}

void output_cursor_wrote(output_cursor_t *c, uint32_t frames) {
  if (c->desc_num == 0 || frames % c->desc_frames != 0) {
    output_cursor_lost_track(c);
    return;
  }
  const uint32_t descs = frames / c->desc_frames;
  uint32_t old = __atomic_load_n(&c->state, __ATOMIC_RELAXED);
  uint32_t next;
  do {
    if (old & LOST) {
      break;
    }
    const uint32_t k = k_of(old);
    next = with_k(old, k > descs ? k - descs : 0);
  } while (!__atomic_compare_exchange_n(&c->state, &old, next, true,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED));

  const uint32_t overflows = __atomic_load_n(&c->overflows, __ATOMIC_RELAXED);
  if (c->writing && overflows != c->overflows_seen) {
    __atomic_add_fetch(&c->underruns, 1, __ATOMIC_RELAXED);
  }
  c->overflows_seen = overflows;
  c->writing = true;
}

void output_cursor_lost_track(output_cursor_t *c) {
  __atomic_or_fetch(&c->state, LOST, __ATOMIC_RELAXED);
}

void output_cursor_writer_started(output_cursor_t *c) {
  c->writing = false;
}

bool output_cursor_known(const output_cursor_t *c) {
  return (__atomic_load_n(&c->state, __ATOMIC_RELAXED) & LOST) == 0;
}

bool output_cursor_ring_drained(const output_cursor_t *c) {
  const uint32_t state = __atomic_load_n(&c->state, __ATOMIC_RELAXED);
  return (state & LOST) == 0 && k_of(state) + 1U >= c->desc_num;
}

bool output_cursor_depth(const output_cursor_t *c, uint32_t rate,
                         int64_t (*clock_us)(void), int64_t *now_us,
                         uint32_t *frames) {
  const uint32_t state = __atomic_load_n(&c->state, __ATOMIC_RELAXED);
  const int64_t now = clock_us();
  *now_us = now;
  if (state & LOST) {
    return false;
  }

  /* k can read N for an instant: between an EOF's on_sent and the drop it
   * then reports, or while the writer has taken a buffer it has not yet
   * counted.  The queue never holds more than N - 1. */
  uint32_t k = k_of(state);
  if (k > (uint32_t)c->desc_num - 1U) {
    k = (uint32_t)c->desc_num - 1U;
  }

  /* The interrupt fires once per descriptor, so the raw depth steps by F
   * frames (5.8 ms at 44.1 kHz).  The DMA drains at a fixed rate in between,
   * so charge off the time since the last EOF.  Past one descriptor the next
   * EOF is already due (an interrupt running late, or one landing after the
   * cursor was read), so stop there. */
  uint32_t elapsed_us = ((uint32_t)now - state) & TS_MASK;
  if (elapsed_us > TS_MASK / 2U) {
    elapsed_us = 0; /* stamped after the clock reading */
  }
  uint64_t drained = ((uint64_t)elapsed_us * rate) / 1000000U;
  if (drained > c->desc_frames) {
    drained = c->desc_frames;
  }
  *frames = ((uint32_t)c->desc_num - k) * c->desc_frames - (uint32_t)drained;
  return true;
}

uint32_t output_cursor_underruns(const output_cursor_t *c) {
  return __atomic_load_n(&c->underruns, __ATOMIC_RELAXED);
}

void output_stage_init(output_stage_t *s, void *buf, size_t desc_bytes) {
  s->buf = buf;
  s->desc_bytes = desc_bytes;
  s->len = 0;
}

bool output_stage_push(output_stage_t *s, const void *data, size_t bytes,
                       output_stage_write_fn write, void *ctx) {
  const uint8_t *p = data;
  while (bytes > 0) {
    if (s->len == 0 && bytes >= s->desc_bytes) {
      const size_t whole = bytes - bytes % s->desc_bytes;
      if (!write(ctx, p, whole)) {
        return false;
      }
      p += whole;
      bytes -= whole;
      continue;
    }
    size_t take = s->desc_bytes - s->len;
    if (take > bytes) {
      take = bytes;
    }
    memcpy(s->buf + s->len, p, take);
    s->len += take;
    p += take;
    bytes -= take;
    if (s->len == s->desc_bytes) {
      const bool ok = write(ctx, s->buf, s->desc_bytes);
      s->len = 0;
      if (!ok) {
        return false;
      }
    }
  }
  return true;
}

bool output_stage_pad(output_stage_t *s, output_stage_write_fn write,
                      void *ctx) {
  memset(s->buf + s->len, 0, s->desc_bytes - s->len);
  const bool ok = write(ctx, s->buf, s->desc_bytes);
  s->len = 0;
  return ok;
}

size_t output_stage_bytes(const output_stage_t *s) {
  return s->len;
}

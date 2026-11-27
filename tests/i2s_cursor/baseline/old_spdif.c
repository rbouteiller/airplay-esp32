// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * The S/PDIF backend's cursor before audio_output_cursor.c, behind the same
 * API.  Logic as in main/audio/audio_output_spdif.c before the change: the
 * preloaded ring counted as submitted, frames sent counted by on_sent (with
 * no stamp at the enable), and a dry ring re-based to zero depth.  Its encode buffer already wrote
 * whole descriptors, so the stage below stands in for it.
 */

#include "audio_output_cursor.h"

#include <string.h>

static uint64_t submitted, sent, lost;
static int64_t sent_us;
static uint32_t underruns;

void output_cursor_init(output_cursor_t *c, uint16_t desc_num,
                        uint16_t desc_frames) {
  memset(c, 0, sizeof(*c));
  c->desc_num = desc_num;
  c->desc_frames = desc_frames;
}

/* audio_output_init(): the preload, then the enable. */
void output_cursor_reset(output_cursor_t *c, int64_t now_us) {
  (void)now_us;
  submitted = (uint64_t)c->desc_num * c->desc_frames;
  sent = lost = 0;
  sent_us = 0;
  underruns = 0;
}

void output_cursor_on_sent(output_cursor_t *c, int64_t now_us) {
  sent += c->desc_frames;
  sent_us = now_us;
}

void output_cursor_on_overflow(output_cursor_t *c) {
  (void)c;
}

void output_cursor_wrote(output_cursor_t *c, uint32_t frames) {
  (void)c;
  submitted += frames;
}

void output_cursor_lost_track(output_cursor_t *c) {
  (void)c;
}

void output_cursor_writer_started(output_cursor_t *c) {
  (void)c;
}

bool output_cursor_known(const output_cursor_t *c) {
  (void)c;
  return true;
}

bool output_cursor_ring_drained(const output_cursor_t *c) {
  (void)c;
  return false;
}

static uint32_t queued_frames(const output_cursor_t *c) {
  if (sent > submitted + lost) {
    lost = sent - submitted;
    underruns++;
    return 0;
  }
  const uint64_t queued = submitted + lost - sent;
  const uint64_t ring = (uint64_t)c->desc_num * c->desc_frames;
  return queued > ring ? (uint32_t)ring : (uint32_t)queued;
}

bool output_cursor_depth(const output_cursor_t *c, uint32_t rate,
                         int64_t (*clock_us)(void), int64_t *now_us,
                         uint32_t *frames) {
  uint32_t queued = queued_frames(c);
  const int64_t stamp = sent_us;
  const int64_t now = clock_us();
  if (stamp > 0 && now > stamp) {
    uint64_t drained = ((uint64_t)(now - stamp) * rate) / 1000000ULL;
    if (drained > c->desc_frames) {
      drained = c->desc_frames;
    }
    queued = drained < queued ? queued - (uint32_t)drained : 0U;
  }
  *now_us = now;
  *frames = queued;
  return true;
}

uint32_t output_cursor_underruns(const output_cursor_t *c) {
  (void)c;
  return underruns;
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
    size_t take = s->desc_bytes - s->len;
    if (take > bytes) {
      take = bytes;
    }
    memcpy(s->buf + s->len, p, take);
    s->len += take;
    p += take;
    bytes -= take;
    if (s->len == s->desc_bytes) {
      s->len = 0;
      if (!write(ctx, s->buf, s->desc_bytes)) {
        return false;
      }
    }
  }
  return true;
}

bool output_stage_pad(output_stage_t *s, output_stage_write_fn write,
                      void *ctx) {
  memset(s->buf + s->len, 0, s->desc_bytes - s->len);
  s->len = 0;
  return write(ctx, s->buf, s->desc_bytes);
}

size_t output_stage_bytes(const output_stage_t *s) {
  return s->len;
}

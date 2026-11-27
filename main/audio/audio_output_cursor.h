// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file audio_output_cursor.h
 * @brief How much audio is queued ahead of the next write to an ESP-IDF I2S
 * TX channel, taken from the driver's own buffer queue.
 *
 * Plain C with no ESP-IDF dependency, so tests/i2s_cursor can compile it
 * against a model of the driver.  Used by the I2S and S/PDIF backends.
 *
 * How the driver hands out buffers (esp_driver_i2s/i2s_common.c, v6.1):
 *
 *  - The DMA plays a ring of N descriptors of F frames, round and round.
 *    i2s_channel_enable() starts it at desc[0].  i2s_channel_disable()
 *    empties the queue below and forgets the writer's buffer.
 *  - Each EOF interrupt (i2s_dma_tx_callback) calls on_sent, then pushes the
 *    descriptor just played onto a queue of N - 1.  If the queue is full it
 *    first drops the oldest entry and calls on_send_q_ovf.
 *  - i2s_channel_write() takes the oldest entry from that queue (waiting
 *    for one if it is empty) when its current buffer is full or unset, *or*
 *    when the queue has at most one space left: then it abandons a partly
 *    filled buffer, which plays with silence after what was written.
 *
 * A buffer taken from the queue next plays N descriptors after the EOF that
 * queued it, so with k entries in the queue the oldest plays (N - k)
 * descriptors after the last EOF.  A writer that only ever writes whole
 * descriptors takes exactly one entry per descriptor and never meets the
 * abandonment rule (its buffer is always full when it asks for the next).
 * The depth ahead of its next frame is then
 *
 *     (N - k) * F - (frames played since the last EOF)
 *
 * whatever came before: right after enable (k = 0, the whole ring of
 * silence first), a writer started on a ring that has run for a while
 * (k = N - 1, one descriptor), a quick restart, or a stall of any length.
 *
 * So the whole state is k, kept as one atomic word together with the time
 * of the last EOF: the interrupt adds one for each EOF and takes one back
 * when the driver reports a drop; the writer takes one off for each
 * descriptor it wrote.  Those are the driver's own pushes, drops and pops,
 * counted in whatever order they happen, so no interleaving can skew them.
 *
 * Anyone writing anything but whole descriptors (the Bluetooth and USB
 * sinks) puts the driver part-way through a buffer, and k no longer
 * describes the next write.  output_cursor_lost_track() records that.  The
 * next queue overflow, which only happens when nobody is writing, means the
 * queue is full again and the cursor knows where it stands.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  /* Bit 31: lost track.  Bits 25..30: k, entries in the driver's queue.
   * Bits 0..24: esp_timer microseconds of the last EOF, modulo 2^25. */
  uint32_t state;
  uint32_t overflows; /* driver queue overflows: the ring ran dry */
  /* Writer side. */
  uint32_t overflows_seen;
  uint32_t underruns;
  bool writing;
  uint16_t desc_num;
  uint16_t desc_frames;
} output_cursor_t;

/** Set up for a ring of @p desc_num descriptors of @p desc_frames frames.
 * The cursor starts out lost until output_cursor_reset(). */
void output_cursor_init(output_cursor_t *c, uint16_t desc_num,
                        uint16_t desc_frames);

/** Call just before i2s_channel_enable() (the DMA is stopped, so no EOF can
 * land first): the queue is empty and the DMA is about to start desc[0].
 * Also right for a ring filled with i2s_channel_preload_data(), which leaves
 * the queue empty and the writer holding a full buffer. */
void output_cursor_reset(output_cursor_t *c, int64_t now_us);

/** From the on_sent callback, with the current esp_timer time. */
void output_cursor_on_sent(output_cursor_t *c, int64_t now_us);

/** From the on_send_q_ovf callback. */
void output_cursor_on_overflow(output_cursor_t *c);

/** After i2s_channel_write() accepted @p frames, a whole number of
 * descriptors written from a descriptor boundary.  Anything else loses
 * track. */
void output_cursor_wrote(output_cursor_t *c, uint32_t frames);

/** After any other write to the channel. */
void output_cursor_lost_track(output_cursor_t *c);

/** A new writer is taking the ring over: overflows so far were idle time,
 * not underruns. */
void output_cursor_writer_started(output_cursor_t *c);

/** False until the cursor knows the driver's state, after a write that left
 * the driver part-way through a buffer.  A writer must wait meanwhile. */
bool output_cursor_known(const output_cursor_t *c);

/**
 * True when the queue is full: everything written has played or is playing.
 * The oldest entry is then dropped at the next EOF unless the writer takes it
 * first, so a frame rendered now could land in either of two descriptors.
 * Write a descriptor of silence first (output_stage_pad()); that leaves a
 * descriptor of margin for the next one.
 */
bool output_cursor_ring_drained(const output_cursor_t *c);

/**
 * Frames ahead of the next write, interpolated since the last EOF.
 *
 * @param rate     frames per second, for the interpolation
 * @param clock_us esp_timer_get_time() or a stand-in; read after the
 *                 cursor, so an EOF in between only makes the interpolation
 *                 stop at the descriptor boundary
 * @param now_us   out: the clock reading the depth belongs to
 * @param frames   out: the depth
 * @return false while the cursor has lost track (output_cursor_known())
 */
bool output_cursor_depth(const output_cursor_t *c, uint32_t rate,
                         int64_t (*clock_us)(void), int64_t *now_us,
                         uint32_t *frames);

/** Times the ring ran dry under an active writer. */
uint32_t output_cursor_underruns(const output_cursor_t *c);

/**
 * Holds what a writer has rendered until there is a whole descriptor of it,
 * so that every write the driver sees starts and ends on a descriptor
 * boundary.  What is held is part of the delay ahead of the next frame.
 */
typedef bool (*output_stage_write_fn)(void *ctx, const void *data,
                                      size_t bytes);

typedef struct {
  uint8_t *buf; /* one descriptor */
  size_t desc_bytes;
  size_t len;
} output_stage_t;

void output_stage_init(output_stage_t *s, void *buf, size_t desc_bytes);

/** Add @p bytes, writing every whole descriptor through @p write (several at
 * once, straight from @p data, when nothing is held).  False if a write
 * failed; what it carried is dropped. */
bool output_stage_push(output_stage_t *s, const void *data, size_t bytes,
                       output_stage_write_fn write, void *ctx);

/** Pad what is held to a whole descriptor with zeros and write it; with
 * nothing held, write a descriptor of zeros. */
bool output_stage_pad(output_stage_t *s, output_stage_write_fn write,
                      void *ctx);

/** Bytes held. */
size_t output_stage_bytes(const output_stage_t *s);

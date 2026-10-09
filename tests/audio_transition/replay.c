// Host-only, deterministic PCM replay. RTP values come from the capture;
// access-unit bytes and the surrounding schedules are synthetic.
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "audio_receiver_internal.h"

const audio_stream_ops_t audio_stream_realtime_ops = {0};
const audio_stream_ops_t audio_stream_buffered_ops = {0};

struct audio_decoder { int unused; };
struct host_semaphore { int signaled; };
static int64_t now_us = 1000;
static void (*wait_hook)(SemaphoreHandle_t semaphore, TickType_t ticks);
static bool release_test_reading_on_wait;
static uint16_t test_reading_slot;

int64_t esp_timer_get_time(void) { return now_us; }
void vTaskDelay(TickType_t ticks) { now_us += (int64_t)ticks * 1000; }
SemaphoreHandle_t xSemaphoreCreateBinary(void) { return calloc(1, sizeof(struct host_semaphore)); }
void vSemaphoreDelete(SemaphoreHandle_t semaphore) { free(semaphore); }
int xSemaphoreGive(SemaphoreHandle_t semaphore) { semaphore->signaled = 1; return pdTRUE; }
int xSemaphoreTake(SemaphoreHandle_t semaphore, TickType_t ticks) {
  if (semaphore->signaled) { semaphore->signaled = 0; return pdTRUE; }
  const int64_t deadline_us = now_us + (int64_t)ticks * 1000;
  if (wait_hook && ticks) wait_hook(semaphore, ticks);
  if (semaphore->signaled) { semaphore->signaled = 0; return pdTRUE; }
  if (now_us < deadline_us) now_us = deadline_us;
  return pdFALSE;
}

bool audio_decoder_is_aac(const audio_decoder_t *decoder) { (void)decoder; return true; }
int audio_decoder_decode(audio_decoder_t *decoder, const uint8_t *input,
                         size_t input_len, int16_t *output,
                         size_t capacity, audio_decode_info_t *info) {
  (void)decoder;
  if (!input || !input_len || capacity < 1024) return -1;
  info->channels = 2;
  const int16_t amp = input[0] == 1 ? 4200 : 7200;
  for (size_t i = 0; i < 1024; ++i) {
    output[2*i] = (i & 16) ? amp : -amp;
    output[2*i+1] = (i & 16) ? (int16_t)(amp/2) : (int16_t)(-amp/2);
  }
  return 1024;
}
int16_t *audio_buffer_get_decode_buffer(audio_buffer_t *buffer, size_t *capacity) {
  *capacity = buffer->decode_capacity_samples;
  return buffer->decode_buffer;
}
bool audio_timing_take_deferred_flush(audio_timing_t *timing, uint32_t timestamp,
                                      uint32_t *flush_until_ts) {
  if (!timing->deferred_flush_pending ||
      (int32_t)(timestamp - timing->flush_until_ts) < 0) return false;
  timing->deferred_flush_pending = false;
  *flush_until_ts = timing->flush_until_ts;
  return true;
}

enum { RATE = 44100, FRAME = 1024, QUANTUM = 352, MAX_OUTPUT = RATE * 20 };
typedef struct {
  const char *name;
  audio_receiver_state_t state;
  audio_stream_t stream;
  struct audio_decoder decoder;
  int16_t scratch[FRAME*2];
  int16_t *output;
  size_t output_frames;
  uint32_t epoch;
  uint32_t anchor;
  uint64_t received, blanket_drops, lower_drops, upper_drops, admitted;
  uint32_t queue_drops;
  uint64_t decoded, inserted, rendered, concealed, zero_windows;
  uint32_t first_insert_failure_rtp;
  uint32_t insert_failures;
  uint32_t max_pending_jobs;
  uint32_t reader_backpressure_guard_encounters;
  uint32_t first_usable_rtp;
  uint32_t continuation_packets;
  bool first_new_inserted;
  uint64_t nonzero_output_frames, producer_wait_render_frames;
  uint64_t post_transition_zero_windows, max_consecutive_post_transition_zero_windows;
  uint64_t initial_zero_windows, post_start_zero_windows;
  uint64_t transition_zero_run_frames, max_zero_run_frames;
  double old_rms, transition_rms, recovery_rms;
} replay_t;
static replay_t *active;

static void die(const char *why) { fprintf(stderr, "replay setup failed: %s\n", why); exit(2); }
static void write_u16(FILE *f, uint16_t value) {
  fputc(value & 255, f); fputc((value >> 8) & 255, f);
}
static void write_u32(FILE *f, uint32_t value) {
  write_u16(f, (uint16_t)value); write_u16(f, (uint16_t)(value >> 16));
}
static void wav(const char *path, const replay_t *r) {
  FILE *f = fopen(path, "wb"); if (!f) die("open wav");
  const uint32_t bytes = (uint32_t)(r->output_frames * 4);
  fwrite("RIFF", 1, 4, f); write_u32(f, bytes + 36); fwrite("WAVEfmt ", 1, 8, f);
  write_u32(f, 16); write_u16(f, 1); write_u16(f, 2); write_u32(f, RATE);
  write_u32(f, RATE*4); write_u16(f, 4); write_u16(f, 16);
  fwrite("data", 1, 4, f); write_u32(f, bytes);
  for (size_t i = 0; i < r->output_frames*2; ++i) write_u16(f, (uint16_t)r->output[i]);
  fclose(f);
}
static double rms(const replay_t *r, size_t from, size_t to) {
  if (to > r->output_frames) to = r->output_frames;
  if (from >= to) return 0;
  double sum = 0;
  for (size_t i = from*2; i < to*2; ++i) {
    double sample = r->output[i]; sum += sample*sample;
  }
  return sqrt(sum / (double)((to-from)*2));
}
static uint64_t max_zero_run(const replay_t *r, size_t from, size_t to) {
  if (to > r->output_frames) to = r->output_frames;
  if (from >= to) return 0;
  uint64_t run = 0, max_run = 0;
  for (size_t i = from; i < to; ++i) {
    const bool zero = r->output[2*i] == 0 && r->output[2*i+1] == 0;
    if (zero) {
      run++;
      if (run > max_run) max_run = run;
    } else {
      run = 0;
    }
  }
  return max_run;
}
static void render(replay_t *r, size_t quanta) {
  for (size_t q = 0; q < quanta; ++q) {
    if (r->output_frames + QUANTUM > MAX_OUTPUT) die("output overflow");
    int16_t *out = &r->output[r->output_frames*2];
    int64_t ns = 1000000000LL +
      (int64_t)r->output_frames * 1000000000LL / RATE;
    size_t before = r->state.engine_v2.scheduler.rendered_samples;
    size_t n = audio_engine_v2_render(&r->state.engine_v2, ns, out, QUANTUM);
    if (n != QUANTUM) die("short render");
    r->rendered += r->state.engine_v2.scheduler.rendered_samples - before;
    r->concealed = r->state.engine_v2.concealed_samples;
    bool all_zero = true;
    for (size_t i = 0; i < QUANTUM*2; ++i) {
      if (out[i] != 0) { all_zero = false; break; }
    }
    if (all_zero) r->zero_windows++;
    for (size_t i = 0; i < QUANTUM; ++i)
      if (out[2*i] || out[2*i+1]) r->nonzero_output_frames++;
    r->output_frames += QUANTUM;
  }
}
static void wait_and_render(SemaphoreHandle_t semaphore, TickType_t ticks) {
  if (release_test_reading_on_wait) {
    // Release the fixture's forced occupied flag during the wait and wake the
    // producer. This isolates the retry-after-reservation-failure behavior;
    // the scenario does not run a concurrent timeline reader.
    portENTER_CRITICAL(&active->state.engine_v2.timeline.lock);
    active->state.engine_v2.timeline.desc[test_reading_slot].reading = false;
    portEXIT_CRITICAL(&active->state.engine_v2.timeline.lock);
    release_test_reading_on_wait = false;
    xSemaphoreGive(semaphore);
    return;
  }
  // Simulate the concurrent I2S consumer while push_pcm_wait blocks.
  const int64_t deadline_us = now_us + (int64_t)ticks * 1000;
  while (now_us < deadline_us && !semaphore->signaled) {
    render(active, 1);
    active->producer_wait_render_frames += QUANTUM;
    now_us += ((int64_t)QUANTUM * 1000000 + RATE - 1) / RATE;
  }
}
static void init(replay_t *r, const char *name, uint32_t anchor) {
  memset(r, 0, sizeof(*r)); r->name = name; r->anchor = anchor;
  r->output = calloc(MAX_OUTPUT*2, sizeof(int16_t)); if (!r->output) die("output alloc");
  r->stream.format.sample_rate = RATE; r->stream.format.channels = 2;
  r->state.stream = &r->stream; r->state.decoder = &r->decoder;
  r->state.buffer.decode_buffer = r->scratch;
  r->state.buffer.decode_capacity_samples = FRAME;
  r->state.decoder_mutex = xSemaphoreCreateBinary();
  if (!r->state.decoder_mutex) die("mutex alloc");
  audio_format_t format = { .sample_rate = RATE, .channels = 2 };
  if (audio_engine_v2_init(&r->state.engine_v2, &format, FRAME, 192) != ESP_OK)
    die("engine init");
  r->state.engine_v2_ready = true;
  r->epoch = audio_epoch_get(&r->state.engine_v2.epoch);
  if (!audio_engine_v2_set_anchor(&r->state.engine_v2, anchor, 1000000000ULL, 0))
    die("anchor");
  audio_engine_v2_set_playing(&r->state.engine_v2, true);
  active = r; wait_hook = wait_and_render;
}
static bool admit(replay_t *r, uint32_t timestamp) {
  r->received++;
  bool blanket = r->state.discard_all_until_anchor;
  bool lower = r->state.discard_before_rtp_valid &&
    (int32_t)(timestamp-r->state.discard_before_rtp) < 0;
  bool upper = r->state.discard_above_rtp_valid &&
    (int32_t)(timestamp-r->state.discard_above_rtp) > 0;
  if (!audio_stream_accept_timestamp(&r->state, timestamp)) {
    if (blanket) r->blanket_drops++;
    else if (lower) r->lower_drops++;
    else if (upper) r->upper_drops++;
    else die("unclassified gate drop");
    return false;
  }
  r->admitted++;
  return true;
}
static void decode(replay_t *r, uint32_t timestamp, uint8_t tone) {
  const audio_encoded_packet_t encoded = {
    .epoch = r->epoch, .rtp_timestamp = timestamp,
    .payload = &tone, .payload_len = 1, .prime_mute = false
  };
  xSemaphoreGive(r->state.decoder_mutex);
  uint64_t decoded_before = r->state.engine_v2.diag_decode_ok;
  if (audio_stream_decode_encoded_packet(&r->state, &encoded)) {
    r->inserted++;
  } else {
    if (r->insert_failures == 0) r->first_insert_failure_rtp = timestamp;
    r->insert_failures++;
    fprintf(stderr, "INSERT FAIL %s rtp=%" PRIu32 " output=%zu timeline=%zu floor=%" PRIu32
            " phase_blocked=%d state=%s\n", r->name, timestamp, r->output_frames,
            audio_timeline_count(&r->state.engine_v2.timeline),
            r->state.engine_v2.timeline.playback_floor_rtp,
            audio_timeline_phase_blocked(&r->state.engine_v2.timeline, r->epoch, timestamp),
            audio_scheduler_state_name(r->state.engine_v2.scheduler.state));
  }
  r->decoded += r->state.engine_v2.diag_decode_ok - decoded_before;
}
static void packet(replay_t *r, uint32_t timestamp, uint8_t tone) {
  if (admit(r, timestamp)) decode(r, timestamp, tone);
}
static void finish(replay_t *r, const char *dir, size_t old_end,
                   size_t transition_end) {
  char path[512];
  r->old_rms = rms(r, 0, old_end);
  r->transition_rms = rms(r, old_end, transition_end);
  r->recovery_rms = rms(r, transition_end, r->output_frames);
  r->transition_zero_run_frames = max_zero_run(r, old_end, transition_end);
  r->max_zero_run_frames = max_zero_run(r, 0, r->output_frames);
  uint64_t consecutive = 0;
  bool started = false;
  for (size_t start = 0; start + QUANTUM <= r->output_frames; start += QUANTUM) {
    bool all_zero = true;
    for (size_t i = start*2; i < (start+QUANTUM)*2; ++i)
      if (r->output[i] != 0) { all_zero = false; break; }
    if (!started && all_zero) r->initial_zero_windows++;
    else if (!all_zero) started = true;
    else r->post_start_zero_windows++;
  }
  const size_t first_transition_window =
      ((old_end + QUANTUM-1U)/QUANTUM)*QUANTUM;
  for (size_t start = first_transition_window;
       start + QUANTUM <= r->output_frames; start += QUANTUM) {
    bool all_zero = true;
    for (size_t i = start*2; i < (start+QUANTUM)*2; ++i)
      if (r->output[i] != 0) { all_zero = false; break; }
    if (all_zero) {
      r->post_transition_zero_windows++;
      consecutive++;
      if (consecutive > r->max_consecutive_post_transition_zero_windows)
        r->max_consecutive_post_transition_zero_windows = consecutive;
    } else consecutive = 0;
  }
  snprintf(path, sizeof(path), "%s/%s.wav", dir, r->name); wav(path, r);
  snprintf(path, sizeof(path), "%s/%s.json", dir, r->name);
  FILE *f = fopen(path, "w"); if (!f) die("open json");
  fprintf(f, "{\n  \"scenario\": \"%s\",\n  \"payload\": \"synthetic deterministic stereo PCM\",\n", r->name);
  fprintf(f, "  \"received\": %" PRIu64 ", \"blanket_gate_drops\": %" PRIu64
          ", \"lower_gate_drops\": %" PRIu64 ", \"upper_gate_drops\": %" PRIu64
          ", \"queue_drops\": %" PRIu32 ",\n",
          r->received, r->blanket_drops, r->lower_drops, r->upper_drops, r->queue_drops);
  fprintf(f, "  \"admitted\": %" PRIu64 ", \"decoded\": %" PRIu64
          ", \"inserted\": %" PRIu64 ", \"rendered_samples\": %" PRIu64
          ", \"nonzero_output_frames\": %" PRIu64
          ", \"producer_wait_render_frames\": %" PRIu64
          ", \"insert_failures\": %" PRIu32 ", \"first_insert_failure_rtp\": %" PRIu32
          ", \"max_pending_jobs\": %" PRIu32 ", \"reader_backpressure_guard_encounters\": %" PRIu32
          ", \"first_usable_rtp\": %" PRIu32 ", \"continuation_packets\": %" PRIu32
          ", \"first_new_inserted\": %s,\n",
          r->admitted, r->decoded, r->inserted, r->rendered,
          r->nonzero_output_frames, r->producer_wait_render_frames,
          r->insert_failures, r->first_insert_failure_rtp,
          r->max_pending_jobs, r->reader_backpressure_guard_encounters,
          r->first_usable_rtp, r->continuation_packets,
          r->first_new_inserted ? "true" : "false");
  fprintf(f, "  \"concealed_samples\": %" PRIu64 ", \"zero_output_windows\": %" PRIu64
          ", \"post_transition_zero_windows\": %" PRIu64
          ", \"max_consecutive_post_transition_zero_windows\": %" PRIu64
          ", \"initial_zero_windows\": %" PRIu64
          ", \"post_start_zero_windows\": %" PRIu64 ",\n",
          r->concealed, r->zero_windows, r->post_transition_zero_windows,
          r->max_consecutive_post_transition_zero_windows,
          r->initial_zero_windows, r->post_start_zero_windows);
  fprintf(f, "  \"transition_zero_run_frames\": %" PRIu64
          ", \"max_zero_run_frames\": %" PRIu64 ",\n",
          r->transition_zero_run_frames, r->max_zero_run_frames);
  fprintf(f, "  \"old_rms\": %.3f, \"transition_rms\": %.3f, \"recovery_rms\": %.3f,\n",
          r->old_rms, r->transition_rms, r->recovery_rms);
  fprintf(f, "  \"output_frames\": %zu, \"scheduler_state\": \"%s\", \"timeline_blocks\": %zu\n}\n",
          r->output_frames, audio_scheduler_state_name(r->state.engine_v2.scheduler.state),
          audio_timeline_count(&r->state.engine_v2.timeline));
  fclose(f);
  audio_engine_v2_deinit(&r->state.engine_v2);
  vSemaphoreDelete(r->state.decoder_mutex); free(r->output);
  wait_hook = NULL; active = NULL;
}
static void forced_slot_retry(const char *dir) {
  replay_t r;
  const uint32_t first = 0x10203040U;
  init(&r, "forced_slot_retry", first);
  for (size_t i = 0; i < FRAME*2U; ++i) r.scratch[i] = (int16_t)(i & 1U ? 100 : -100);
  if (!audio_engine_v2_push_pcm(&r.state.engine_v2, r.epoch, first,
                                r.scratch, FRAME, 2)) {
    die("seed occupied slot");
  }

  uint16_t slot = UINT16_MAX;
  for (uint16_t i = 0; i < r.state.engine_v2.timeline.capacity; ++i) {
    audio_timeline_desc_t *desc = &r.state.engine_v2.timeline.desc[i];
    if (desc->used && desc->epoch == r.epoch && desc->rtp_start == first) {
      slot = i;
      break;
    }
  }
  if (slot == UINT16_MAX) die("find occupied slot");

  const uint32_t wrapped = first +
      (uint32_t)r.state.engine_v2.timeline.capacity * FRAME;
  audio_timeline_set_playback_floor(&r.state.engine_v2.timeline, r.epoch,
                                    wrapped);
  portENTER_CRITICAL(&r.state.engine_v2.timeline.lock);
  r.state.engine_v2.timeline.desc[slot].reading = true;
  portEXIT_CRITICAL(&r.state.engine_v2.timeline.lock);
  test_reading_slot = slot;
  release_test_reading_on_wait = true;
  r.received = r.admitted = r.decoded = 2;
  r.first_usable_rtp = wrapped;
  r.first_new_inserted = audio_engine_v2_push_pcm_wait(
      &r.state.engine_v2, r.epoch, wrapped, r.scratch, FRAME, 2, 100);
  r.inserted = r.first_new_inserted ? 2U : 1U;
  r.insert_failures = r.first_new_inserted ? 0U : 1U;
  release_test_reading_on_wait = false;
  finish(&r, dir, 0, 0);
}
static void gapless(const char *dir, const char *name, uint32_t next) {
  replay_t r;
  const uint32_t last_old = 1313966082U;
  const uint32_t first_old = last_old - 184U*FRAME;
  init(&r, name, first_old);
  for (unsigned i = 0; i < 185; ++i) packet(&r, first_old+i*FRAME, 1);
  const size_t old_end = 185U*FRAME;
  // The -1088 case uses the captured RTP step; +2405 is the existing
  // same-epoch phase regression. The cooperative reader mirrors the production
  // guards: stop reading at 12 pending decode jobs or a nearly-full timeline.
  // The decoder drains one job at a time; no admitted packet is discarded by
  // the host queue. 400 frames cross the 192-slot ring more than once.
  uint32_t pending[16]; size_t pending_count = 0; unsigned next_index = 0;
  while (next_index < 400 || pending_count) {
    while (next_index < 400 && pending_count < 12 &&
           !audio_engine_v2_is_nearly_full(&r.state.engine_v2)) {
      uint32_t timestamp = next + next_index*FRAME;
      next_index++;
      if (admit(&r, timestamp)) pending[pending_count++] = timestamp;
      if (pending_count > r.max_pending_jobs) r.max_pending_jobs = pending_count;
    }
    if (next_index < 400 && audio_engine_v2_is_nearly_full(&r.state.engine_v2))
      r.reader_backpressure_guard_encounters++;
    if (pending_count) {
      uint32_t timestamp = pending[0];
      memmove(pending, pending+1, (--pending_count)*sizeof(*pending));
      decode(&r, timestamp, 2);
    } else {
      render(&r, 1);
    }
  }
  size_t transition_end = old_end + 20U*FRAME;
  // End at the final new-phase packet, rounded to a complete I2S quantum.
  // The new RTP origin may precede or follow the old track's last frame.
  const size_t new_end = (size_t)(int32_t)(next + 400U*FRAME - first_old);
  const size_t expected_end = ((new_end + QUANTUM-1U)/QUANTUM)*QUANTUM;
  while (r.output_frames < expected_end) render(&r, 1);
  finish(&r, dir, old_end, transition_end);
}
static void stale_phase(const char *dir, const char *name, uint32_t next) {
  replay_t r;
  const uint32_t last_old = next + 1088U;
  const uint32_t first_old = last_old - 23U*FRAME;
  init(&r, name, first_old);
  // The captured buffer fell to about 24 blocks. Model those old-phase blocks
  // retained across a pause/reanchor without an immediate timeline flush.
  for (unsigned i = 0; i < 24; ++i) packet(&r, first_old+i*FRAME, 1);
  audio_engine_v2_set_playing(&r.state.engine_v2, false);
  if (!audio_engine_v2_set_anchor(&r.state.engine_v2, next+3U*FRAME,
                                  1000000000ULL, 0)) die("reanchor");
  audio_engine_v2_set_playing(&r.state.engine_v2, true);
  // Four 1024-sample frames after the modeled phase step, this above-anchor
  // packet still has the new phase. Earlier new frames are omitted because
  // they sit below this synthetic anchor. The 24 old blocks remain below
  // wanted_rtp; the unmodified PREROLL path leaves them at count<185.
  r.first_usable_rtp = next+4U*FRAME;
  const uint64_t inserted_before = r.inserted;
  packet(&r, r.first_usable_rtp, 2);
  r.first_new_inserted = r.inserted > inserted_before;
  if (r.first_new_inserted) {
    // A corrected first insertion unlocks a long enough continuation for
    // normal preroll and a measurable new-track recovery window. On the
    // baseline, stop after the first 6 s timeout instead of repeating it.
    for (unsigned i = 1; i <= 64; ++i) {
      packet(&r, r.first_usable_rtp+i*FRAME, 2);
      r.continuation_packets++;
    }
    while (r.output_frames < 64U*FRAME) render(&r, 1);
    finish(&r, dir, 0, 16U*FRAME);
  } else {
    finish(&r, dir, 0, r.output_frames/2);
  }
}
static void flush_case(const char *dir, bool passing, uint32_t anchor,
                       const char *name) {
  replay_t r;
  init(&r, name, anchor);
  audio_engine_v2_set_playing(&r.state.engine_v2, false); // PAUSE
  audio_engine_v2_begin_epoch(&r.state.engine_v2, now_us); // immediate FLUSHBUFFERED
  r.epoch = audio_epoch_get(&r.state.engine_v2.epoch);
  r.state.discard_all_until_anchor = true;
  packet(&r, anchor-4U*FRAME, 1);
  r.state.discard_before_rtp = anchor;
  r.state.discard_before_rtp_valid = true;
  r.state.discard_above_rtp = anchor+10U*RATE;
  r.state.discard_above_rtp_valid = true;
  r.state.discard_all_until_anchor = false;
  audio_engine_v2_set_anchor(&r.state.engine_v2, anchor, 1000000000ULL, 0);
  audio_engine_v2_set_playing(&r.state.engine_v2, true);
  for (unsigned i = 0; i < 12; ++i) packet(&r, anchor-(12U-i)*FRAME, 1);
  if (!passing) packet(&r, anchor+10U*RATE+FRAME, 1);
  if (passing) {
    // Advance the output clock to the first strictly above-anchor frame.
    render(&r, 3);
    r.first_usable_rtp = anchor+FRAME;
    for (unsigned i = 0; i < 20; ++i)
      packet(&r, r.first_usable_rtp+i*FRAME, 2);
  }
  render(&r, 45);
  finish(&r, dir, 0, 25U*QUANTUM);
}
int main(int argc, char **argv) {
  if (argc != 2) die("usage: replay ARTIFACT_DIR");
  gapless(argv[1], "gapless_minus_1088", 1313964994U);
  gapless(argv[1], "same_epoch_plus_2405", 1313966082U + 2405U);
  forced_slot_retry(argv[1]);
  stale_phase(argv[1], "stale_phase_reanchor", 1313964994U);
  stale_phase(argv[1], "stale_phase_reanchor_wrap", UINT32_MAX - 2047U);
  flush_case(argv[1], false, 2776599456U, "flush_all_stale");
  flush_case(argv[1], true, 2776599456U, "flush_after_anchor");
  flush_case(argv[1], true, UINT32_MAX - 1023U, "wrap_after_anchor");
  return 0;
}

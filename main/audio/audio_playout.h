#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

/* V22 I2S backend: two 256-frame DMA descriptors. Every application audio
 * block is tagged with its RTP/generation before it reaches DMA. The TX EOF
 * ISR records the local completion timestamp for that exact tag, allowing the
 * playout task to compare the physical DMA completion edge against AirPlay PTP.
 */

#define AUDIO_PLAYOUT_FRAMES 256U

typedef struct {
  uint32_t rtp;
  uint32_t generation;
  uint32_t frames;
  int64_t done_local_us;
} audio_playout_completion_t;

typedef struct {
  int32_t requested_ppm;
  int32_t actual_delta_mclk_hz;
  uint32_t curr_mclk_hz;
} audio_playout_tune_info_t;

typedef struct {
  uint64_t submitted_frames;
  uint64_t completed_frames;
  uint64_t tagged_completions;
  uint64_t untagged_completions;
  uint64_t completion_overflows;
  uint64_t write_calls;
  uint64_t write_total_us;
  uint32_t write_last_us;
  uint32_t write_max_us;
} audio_playout_diag_t;

esp_err_t audio_playout_init(void);
void audio_playout_flush(void);

/* Preload is valid only while the TX channel is disabled/READY. It is used for
 * the first two blocks of an epoch so the channel starts with known audio in
 * both DMA descriptors instead of clocking zero-filled descriptors first. */
esp_err_t audio_playout_preload_tagged(const int16_t *stereo, uint32_t frames,
                                       uint32_t rtp, uint32_t generation);

/* Enable after the first two blocks have been preloaded and the PTP start edge
 * has been reached. */
esp_err_t audio_playout_enable(void);

/* Normal steady-state write. The RTP tag is paired FIFO-wise with the TX EOF
 * callback for the descriptor that physically finished sending. */
esp_err_t audio_playout_write_tagged(const int16_t *stereo, uint32_t frames,
                                     uint32_t rtp, uint32_t generation);

/* Drain one completed tagged DMA block. done_local_us comes from
 * esp_timer_get_time() inside the TX ISR. */
bool audio_playout_poll_completion(audio_playout_completion_t *out);

bool audio_playout_is_enabled(void);
void audio_playout_get_diag(audio_playout_diag_t *out);
uint32_t audio_playout_hardware_latency_us(void);

/* Fine tune the active TX master clock. The ESP-IDF 5.5 API requires READY,
 * so this helper performs the same disable -> tune -> enable sequence used by
 * Espressif's dynamic I2S tuning example. Call only from the playout task
 * between writes. target_ppm is relative to the nominal MCLK measured at init. */
esp_err_t audio_playout_tune_ppm(int32_t target_ppm,
                                 audio_playout_tune_info_t *out);
int32_t audio_playout_get_tune_ppm(void);
uint32_t audio_playout_get_nominal_mclk_hz(void);

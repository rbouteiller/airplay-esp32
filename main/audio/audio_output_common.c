/**
 * @file audio_output_common.c
 * @brief Weak defaults for the optional half of the audio output API.
 *
 * Exactly one backend (audio_output.c, _spdif.c, _usb.c, ...) is compiled in,
 * chosen by Kconfig. Callers such as web_server.c and audio_timing.c reference
 * the full API unconditionally, so a backend that does not implement the
 * capability calls used to fail the link — which is why only the I2S build,
 * the one the CI matrix covers, kept working.
 *
 * The defaults below describe a backend with no channel routing and no
 * hardware completion cursor. A backend overrides one by defining it, the
 * same way boards override iot_board_*() in board_common.c. Only genuinely
 * optional entry points belong here: the core ones (init/start/write/...) are
 * deliberately left undefined so a backend missing them still fails loudly.
 */

#include "audio_output.h"

// ~5 ms of scheduling + write delay between this call and the samples
// reaching the backend.  Mirrors PIPELINE_LATENCY_US in audio_timing.c.
#define OUTPUT_PIPELINE_LATENCY_US 5000

// Not weak: every backend wants the same answer, and it is derived entirely
// from the capability calls each one already provides.
//
// Prefer the LIVE queue depth over the modelled constant, for the same reason
// compute_early_us() in audio_timing.c does: the model assumes the DMA ring
// sits at its steady-state occupancy, so when the playback task is briefly
// starved this call returns an instant that is too early and the caller reads
// the stream as late.  That artifact is one-sided -- a delayed call can only
// ever measure late -- so it biases any averaging filter downstream.  The live
// depth moves with the delay and leaves the measured error where it was.
int64_t audio_output_get_next_playout_time_ns(int64_t now_us) {
  int64_t sampled_us = 0;
  uint32_t pipeline_us = 0;
  if (!audio_output_get_pipeline_us(&sampled_us, &pipeline_us)) {
    sampled_us = now_us;
    pipeline_us = audio_output_get_hardware_latency_us();
  }
  return (sampled_us + (int64_t)pipeline_us + OUTPUT_PIPELINE_LATENCY_US) *
         1000LL;
}

__attribute__((weak)) bool audio_output_get_pipeline_us(int64_t *now_us,
                                                        uint32_t *pipeline_us) {
  (void)now_us;
  (void)pipeline_us;
  // No completion cursor: the timing engine falls back to the modelled
  // hardware latency.
  return false;
}

__attribute__((weak)) uint32_t audio_output_get_underruns(void) {
  return 0;
}

__attribute__((weak)) audio_channel_mode_t
audio_output_cycle_channel_mode(void) {
  return AUDIO_CHANNEL_STEREO;
}

__attribute__((weak)) void
audio_output_set_channel_mode(audio_channel_mode_t mode) {
  (void)mode;
}

__attribute__((weak)) audio_channel_mode_t audio_output_get_channel_mode(void) {
  return AUDIO_CHANNEL_STEREO;
}

// Routing is fixed at stereo, which is what "locked" reports to the web UI so
// it renders the control as unavailable rather than as a working toggle.
__attribute__((weak)) bool audio_output_channel_mode_locked(void) {
  return true;
}

__attribute__((weak)) bool audio_output_channel_mode_in_dsp(void) {
  return false;
}

// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

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

#include "audio_receiver.h"

// ~5 ms of scheduling + write delay between this call and the samples
// reaching the backend.  Mirrors PIPELINE_LATENCY_US in audio_timing.c.
#define OUTPUT_PIPELINE_LATENCY_US 5000

// Alternate renderer, or NULL for the AirPlay receiver.  Written by the
// arbitration path once the previous owner has been stopped and read once per
// refill by the playback task, so a plain pointer swap is enough: the worst
// interleaving costs one block of silence, not a torn read.
static audio_output_source_fn s_source = NULL;

void audio_output_set_source(audio_output_source_fn source) {
  s_source = source;
}

size_t audio_output_read_source(int16_t *buffer, size_t samples) {
  audio_output_source_fn source = s_source;
  if (source) {
    return source(buffer, samples);
  }
  return audio_receiver_read(buffer, samples);
}

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

// S/PDIF and USB start their playback task on the first audio_output_start()
// and leave it running: there is no channel to disable and nothing to hand
// over to, so the task simply renders silence once its source goes quiet.
// Only the I2S backend has a real stop, and it needs one because the DMA
// channel is shared with whoever takes the output next.
//
// Handing that difference to the linker used to mean any config that
// arbitrates between audio sources -- Bluetooth, the USB sink, Sendspin --
// failed to link against these two backends instead of just running them
// unchanged.
__attribute__((weak)) void audio_output_stop(void) {
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

// Backends without software processing pass the PCM straight through.
__attribute__((weak)) esp_err_t audio_output_write_pcm(const void *data,
                                                       size_t bytes,
                                                       int32_t volume_q15,
                                                       TickType_t wait) {
  (void)volume_q15;
  return audio_output_write(data, bytes, wait);
}

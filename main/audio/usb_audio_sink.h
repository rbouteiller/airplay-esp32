#pragma once

#include "esp_err.h"
#include <stdbool.h>

/**
 * USB Audio Class sink — the board enumerates as a USB speaker and plays
 * the host's audio through the same I2S DAC path AirPlay uses.
 */

/**
 * Called when the host's audio stream starts and stops.
 *
 * AirPlay and the USB sink cannot both drive I2S, so the owner of the
 * callback is expected to stop the AirPlay services on `true` and restart
 * them on `false`.  Invoked from the sink's writer task, so it may block.
 */
typedef void (*usb_audio_sink_state_cb_t)(bool streaming);

/**
 * Start the UAC device and the writer task that drains it into the DAC.
 */
esp_err_t usb_audio_sink_init(usb_audio_sink_state_cb_t state_cb);

/**
 * True while the host is actively sending audio.
 */
bool usb_audio_sink_is_streaming(void);

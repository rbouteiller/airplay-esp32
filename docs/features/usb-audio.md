# USB audio (UAC)

Boards with a USB OTG port can present themselves to an attached computer as a **stereo USB
speaker**. Audio sent by the host plays through the same output path AirPlay uses, sharing
the DAC's DSP, EQ and volume control.

!!! warning "Needs USB OTG and a device-role port"

    Only the ESP32-S2, S3 and P4 have a USB OTG peripheral. The D+/D- pins must also be
    routed to a connector wired for device role (CC pulldowns). The original ESP32 cannot
    do this at all.

The board enumerates as a composite device: a USB Audio Class speaker plus an HID
consumer-control interface that sends media keys back to the host.

## How it works

- AirPlay and USB audio are **mutually exclusive at runtime**, much like
  [Bluetooth](bluetooth.md)
- AirPlay is suspended as soon as the host starts streaming
- The output is handed back once the host stream has been idle for
  `CONFIG_USB_AUDIO_SINK_IDLE_MS`, 2000 ms by default
- Host volume and mute are applied to the DAC, so the computer's own volume slider works
- [Hardware buttons](buttons.md) send play/pause, track skip, volume and mute to the host
  over HID, since UAC itself carries no transport controls

## Sample rate

USB audio runs at **48 kHz**. `CONFIG_UAC_SAMPLE_RATE` must equal
`CONFIG_OUTPUT_SAMPLE_RATE_HZ`, because nothing resamples on this path and the descriptor
advertises a single fixed rate.

!!! danger "44100 Hz does not work"

    `usb_device_uac` derives its FIFO drain rate from `sample_rate / 1000`, an integer
    division. At 44100 that truncates 44.1 frames per millisecond to 44. The feedback
    endpoint uses `AUDIO_FEEDBACK_METHOD_FIFO_COUNT`, so that FIFO is the control variable
    and the host settles at 44000 frames/s while I2S consumes 44100. The resulting deficit
    of roughly 100 frames per second slowly drains the buffer and then glitches
    continuously. 48000 divides into 1 ms frames exactly.

TAS58xx boards default to 48 kHz for this reason, and because the driver's EQ coefficients
are computed for 48 kHz. AirPlay's 44.1 kHz stream is resampled on the way out.

## Build environments

| Environment | Board |
| --- | --- |
| `esp32s3-uac` | ESP32-S3 + PCM5102A |
| `esparagus-audio-brick-dual-uac` | [Esparagus Audio Brick rev D](../boards/esparagus-audio-brick-dual-dac.md), dual DAC |

USB audio is enabled by layering `config/sdkconfig.defaults.uac` onto a board's defaults. To
add it to a [custom board](../boards/custom.md), put that file **last** in your
`SDKCONFIG_DEFAULTS` chain so it can override the sample rate.

## Device name

`CONFIG_USB_AUDIO_SINK_PRODUCT` sets the name the host displays. It is used both for the
product string and for the audio interface, which is what Windows Device Manager shows for
a composite function.

!!! tip "Windows caches the name"

    Windows stores descriptor strings per VID/PID/revision, so after changing the name it
    may keep showing the old one. Bump `bcdDevice` in `main/usb/usb_descriptors.c` to force
    a re-read.

## Caveats

- **macOS** needs `CONFIG_UAC_SUPPORT_MACOS=y`. A single descriptor cannot satisfy macOS and
  Windows/Linux simultaneously, so this is a build-time choice.
- **No USB console.** TinyUSB claims the USB PHY, so USB-Serial-JTAG cannot also act as a
  console. Logs stay on UART0, and you must hold BOOT while resetting to reflash over USB.
  [OTA updates](../reference/ota.md) avoid the problem entirely.

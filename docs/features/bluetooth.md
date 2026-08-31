# Bluetooth A2DP

ESP32-based boards can receive audio over **Bluetooth Classic A2DP**, letting any phone,
tablet or laptop stream music without an Apple device. The receiver appears as a standard
Bluetooth speaker with AVRCP metadata and volume control.

!!! warning "ESP32 only"

    Bluetooth Classic exists only on the original ESP32. The ESP32-S3, S2 and C5 have
    Bluetooth LE or nothing at all, so A2DP is not available there. The generic `esp32s3`
    build contains no Bluetooth support.

The Bluedroid stack is used for A2DP. It is very tight on both RAM and flash, which is why
Bluetooth builds are separate environments rather than being enabled everywhere.

## How it works

- AirPlay and Bluetooth coexist in the firmware but are **mutually exclusive at runtime**
- When a Bluetooth device connects, AirPlay is suspended automatically
- When it disconnects, AirPlay resumes
- Bluetooth discoverability is disabled during an active AirPlay session, so a stray phone
  cannot interrupt playback
- AVRCP provides volume sync and track metadata (artist, title, album) for the display
- Bluetooth volume is saved to NVS and restored on reconnect

The [coexistence state diagram](../reference/architecture.md#runtime-coexistence-rules)
shows how the two protocols hand off to each other.

## Pairing

The device advertises the same name as your AirPlay device name, which you set in the web
interface. Pairing uses a fixed PIN, `05032026` by default, configurable under
**Bluetooth Configuration** in `menuconfig`.

Secure Simple Pairing (SSP) can optionally be enabled for Bluetooth 2.1+ devices, which
uses numeric confirmation instead of a PIN. SSP needs a display to show the confirmation
number, and that is not implemented yet.

## Build environments

| Environment | Board | Features |
| --- | --- | --- |
| `squeezeamp-bt` | SqueezeAMP | AirPlay + Bluetooth |
| `esparagus-audio-brick-bt` | Esparagus Audio Brick, ESP32 revision | AirPlay + Bluetooth + Ethernet |
| `esparagus-louder-bt` | Esparagus Louder | AirPlay + Bluetooth |
| `esp32wrover-dev` | Freenove ESP32-WROVER | AirPlay + Bluetooth, 4 MB flash |
| `smartamp` | SmartAmp | AirPlay + Bluetooth, 4 MB flash |

Bluetooth is enabled by layering `config/sdkconfig.defaults.bt` onto a board's defaults. To add it
to a [custom board](../boards/custom.md), include that file in your
`SDKCONFIG_DEFAULTS` chain.

Boards sold in both an ESP32 and an ESP32-S3 revision — the
[Esparagus Audio Brick](../boards/esparagus-audio-brick.md) and Louder — have a `-bt`
environment for the ESP32 one only. There is nothing to enable on the S3 revision.

## Buttons over Bluetooth

Unlike AirPlay, [hardware buttons](buttons.md) work fully over Bluetooth regardless of
protocol settings, because AVRCP passthrough carries play/pause and track-skip commands
natively.

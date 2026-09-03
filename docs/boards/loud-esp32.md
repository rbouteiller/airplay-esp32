# Loud-ESP32, Loud-Esparagus and Esparagus Echo

The Sonocotta [Loud-ESP32](https://github.com/sonocotta/esp32-audio-dock) boards drive
**MAX98357A** I2S amplifiers directly — no DAC in front, no I2C control port. Speakers
connect straight to the board.

A MAX98357A has exactly one control line: an active-high `SD_MODE` enable. The firmware
registers a minimal DAC driver whose only job is to drive that pin from RTSP playback
events, so the amplifier is held muted until a client actually presses play and drops
back to standby on pause. That is the same power-state handling the
[Esparagus Audio Brick](esparagus-audio-brick.md) does over I2C, reduced to one GPIO.

## Variants

| Environment | Chip | Amps | Ethernet | Display | Bluetooth | Prebuilt |
| --- | --- | :-: | :-: | :-: | :-: | :-: |
| `loud-esp32` | ESP32 | 1 | yes | SH1106 OLED | — | — |
| `loud-esp32-bt` | ESP32 | 1 | yes | SH1106 OLED | yes | yes |
| `loud-esparagus` | ESP32 | 2 | — | — | — | — |
| `loud-esparagus-bt` | ESP32 | 2 | — | — | yes | yes |
| `loud-esp32-s3` | ESP32-S3 | 2 | yes | SH1106 OLED | — | yes |
| `esparagus-echo` | ESP32-S3 | 2 | yes | — | — | yes |

Both amplifiers share the one enable pin, so a dual-amp board mutes and unmutes as a
unit. Bluetooth Classic exists only on the original ESP32, so neither S3 board has a
`-bt` build; on an ESP32 the published binary is the Bluetooth one.

[Esparagus Echo](https://github.com/sonocotta/esparagus-echo) is the same amplifier
arrangement on the Echo's S3 board — Ethernet, an RGB status LED and no display header.

## Features

- One or two MAX98357A Class-D amplifiers, speakers connected directly
- Amplifier held muted until playback starts, standby on pause, off on disconnect
- Software volume control — the MAX98357A has no volume register
- 8 MB flash
- [Bluetooth A2DP](../features/bluetooth.md) on the ESP32 variants
- [W5500 SPI Ethernet](../features/ethernet.md) with automatic WiFi failover, except on
  Loud-Esparagus
- [SH1106 OLED](../features/oled-display.md) over SPI, sharing the Ethernet bus, on
  Loud-ESP32 and Loud-ESP32-S3

## Flashing

=== "Browser"

    Use the Loud or Esparagus Echo installer on the
    [flashing page](../getting-started/flashing.md).

=== "PlatformIO"

    ```bash
    # ESP32 — AirPlay + Bluetooth + Ethernet + OLED
    pio run -e loud-esp32-bt -t upload
    pio run -e loud-esp32-bt -t uploadfs

    # ESP32 — Esparagus variant, dual amp over WiFi
    pio run -e loud-esparagus-bt -t upload
    pio run -e loud-esparagus-bt -t uploadfs

    # ESP32-S3 — dual amp, Ethernet + OLED
    pio run -e loud-esp32-s3 -t upload
    pio run -e loud-esp32-s3 -t uploadfs

    # ESP32-S3 — Esparagus Echo
    pio run -e esparagus-echo -t upload
    pio run -e esparagus-echo -t uploadfs
    ```

=== "ESP-IDF"

    ```bash
    idf.py set-target esp32
    idf.py -DSDKCONFIG_DEFAULTS="config/sdkconfig.defaults;config/sdkconfig.defaults.loud-esp32;config/sdkconfig.defaults.bt" build
    idf.py -p /dev/ttyUSB0 flash
    ```

    Swap in `config/sdkconfig.defaults.loud-esp32-s3` or
    `config/sdkconfig.defaults.esparagus-echo` after `idf.py set-target esp32s3` for the
    S3 boards.

## Default GPIO assignments

| Function | Loud-ESP32 | Loud-Esparagus | Loud-ESP32-S3 | Esparagus Echo |
| --- | :-: | :-: | :-: | :-: |
| I2S BCK | 26 | 26 | 14 | 18 |
| I2S WS | 25 | 25 | 15 | 8 |
| I2S DO | 22 | 22 | 16 | 17 |
| Amp enable (`SD_MODE`) | 13 | 13 | 17 | 9 |
| Status LED | — | 33 | — | 42 |
| SPI SCLK | 18 | — | 12 | 12 |
| SPI MOSI | 23 | — | 11 | 11 |
| SPI MISO | 19 | — | 13 | 13 |
| Ethernet CS | 5 | — | 10 | 10 |
| Ethernet INT | 35 | — | 6 | 6 |
| Ethernet RST | 14 | — | 5 | 5 |
| Display CS | 15 | — | 39 | — |
| Display DC | 4 | — | 40 | — |
| Display RST | 32 | — | 38 | — |

!!! warning "The Loud-ESP32-S3 enable pin moved"

    `CONFIG_DAC_ENABLE_GPIO` is GPIO 17 for rev G and later hardware. Rev F used GPIO 8.
    On a rev F board, override it in a
    [custom configuration](custom.md) or nothing will ever unmute.

## Related

- [HiFi-ESP32](hifi-esp32.md) — the same layout with a line-level PCM5100 instead
- [Amped-ESP32](amped-esp32.md) — PCM5100 with a TPA31xx amplifier
- [Bluetooth A2DP](../features/bluetooth.md)
- [Ethernet (W5500)](../features/ethernet.md)
- [Build environments](../reference/build-environments.md)

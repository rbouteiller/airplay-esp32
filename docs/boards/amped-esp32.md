# Amped-ESP32 and Amped-Esparagus

The Sonocotta [Amped-ESP32](https://github.com/sonocotta/esp32-audio-dock) boards put a
**PCM5100** I2S DAC in front of a **TPA3110** or **TPA3128** Class-D amplifier. Speakers
connect directly to the board, but unlike the [Loud](loud-esp32.md) boards the signal
passes through a real DAC first.

Neither part has an I2C control port. The amplifier's only control line is an active-high
`UNMUTE` pin, driven from RTSP playback events by the same board support code the Loud
boards use: muted until a client presses play, standby on pause, off on disconnect.

## Variants

| Environment | Chip | Ethernet | Display | Controls | Bluetooth | Prebuilt |
| --- | --- | :-: | :-: | --- | :-: | :-: |
| `amped-esp32` | ESP32 | yes | SH1106 OLED | — | — | — |
| `amped-esp32-bt` | ESP32 | yes | SH1106 OLED | — | yes | yes |
| `amped-esparagus` | ESP32 | yes | — | rotary encoder | — | — |
| `amped-esparagus-bt` | ESP32 | yes | — | rotary encoder | yes | yes |
| `amped-esp32-s3` | ESP32-S3 | yes | SH1106 OLED | — | — | yes |

Bluetooth Classic exists only on the original ESP32, so there is no `-bt` build for the
S3 board. On an ESP32 the published binary is the Bluetooth one.

!!! warning "Amped-Esparagus is rev M only"

    `config/sdkconfig.defaults.amped-esparagus` describes **rev M** hardware. Earlier
    revisions use a different pinout.

    Its ILI9342 TFT is not a supported driver — the firmware speaks
    [SSD1306/SH1106/SSD1309 OLED](../features/oled-display.md) and
    [ST7789 TFT](../features/tft-display.md) — so display support is commented out in the
    board configuration and the board ships without a screen. The rotary encoder works:
    turning it changes volume, clicking it toggles play/pause.

## Features

- PCM5100 DAC into a TPA3110 or TPA3128 Class-D amplifier
- Amplifier held muted until playback starts, standby on pause, off on disconnect
- Software volume control — neither part has a volume register
- 8 MB flash
- [Bluetooth A2DP](../features/bluetooth.md) on the ESP32 variants
- [W5500 SPI Ethernet](../features/ethernet.md) with automatic WiFi failover
- [SH1106 OLED](../features/oled-display.md) over SPI on Amped-ESP32 and Amped-ESP32-S3;
  a [rotary encoder](../features/buttons.md) on Amped-Esparagus

## Flashing

=== "Browser"

    Use the Amped installer for your board on the
    [flashing page](../getting-started/flashing.md).

=== "PlatformIO"

    ```bash
    # ESP32 — AirPlay + Bluetooth + Ethernet + OLED
    pio run -e amped-esp32-bt -t upload
    pio run -e amped-esp32-bt -t uploadfs

    # ESP32 — Esparagus rev M, rotary encoder
    pio run -e amped-esparagus-bt -t upload
    pio run -e amped-esparagus-bt -t uploadfs

    # ESP32-S3
    pio run -e amped-esp32-s3 -t upload
    pio run -e amped-esp32-s3 -t uploadfs
    ```

=== "ESP-IDF"

    ```bash
    idf.py set-target esp32
    idf.py -DSDKCONFIG_DEFAULTS="config/sdkconfig.defaults;config/sdkconfig.defaults.amped-esp32;config/sdkconfig.defaults.bt" build
    idf.py -p /dev/ttyUSB0 flash
    ```

    Swap in `config/sdkconfig.defaults.amped-esp32-s3` after `idf.py set-target esp32s3`
    for the S3 revision.

## Default GPIO assignments

| Function | Amped-ESP32 | Amped-Esparagus | Amped-ESP32-S3 |
| --- | :-: | :-: | :-: |
| I2S BCK | 26 | 26 | 14 |
| I2S WS | 25 | 25 | 15 |
| I2S DO | 22 | 22 | 16 |
| Amp `UNMUTE` | 13 | 13 | 17 |
| Status LED | — | 12 | — |
| Rotary A | — | 33 | — |
| Rotary B | — | 27 | — |
| Encoder click | — | 34 | — |
| SPI SCLK | 18 | 18 | 12 |
| SPI MOSI | 23 | 23 | 11 |
| SPI MISO | 19 | 19 | 13 |
| Ethernet CS | 5 | 5 | 10 |
| Ethernet INT | 35 | 35 | 6 |
| Ethernet RST | 14 | 14 | 5 |
| Display CS | 15 | — | 47 |
| Display DC | 4 | — | 38 |
| Display RST | 32 | — | 48 |

## Related

- [Loud-ESP32](loud-esp32.md) — MAX98357A amplifiers, no DAC in front
- [HiFi-ESP32](hifi-esp32.md) — the same PCM5100 at line level, no amplifier
- [Buttons and rotary encoders](../features/buttons.md)
- [Build environments](../reference/build-environments.md)

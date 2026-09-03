# HiFi-ESP32 and HiFi-Esparagus

The Sonocotta [HiFi-ESP32](https://github.com/sonocotta/esp32-audio-dock) boards pair an
ESP32 or ESP32-S3 with a TI **PCM5100** I2S DAC and a line-level output. There is no
amplifier on board, so these feed an existing amp or a pair of active speakers.

The PCM5100 is a plain I2S DAC: no I2C control port, no mute pin and no hardware volume
register. The firmware therefore does volume in software and the board support code has
nothing to do beyond bringing up the SPI bus that Ethernet and the display share.

## Variants

| Environment | Chip | Ethernet | Display | Bluetooth | Prebuilt |
| --- | --- | :-: | :-: | :-: | :-: |
| `hifi-esp32` | ESP32 | yes | SH1106 OLED | — | — |
| `hifi-esp32-bt` | ESP32 | yes | SH1106 OLED | yes | yes |
| `hifi-esparagus` | ESP32 | — | — | — | — |
| `hifi-esparagus-bt` | ESP32 | — | — | yes | yes |
| `hifi-esp32-s3` | ESP32-S3 | yes | SH1106 OLED | — | yes |
| `hifi-esparagus-s3` | ESP32-S3 | — | — | — | yes |

The **Esparagus** variants are the same audio design without the Ethernet jack and the
display header; they carry a WS2812 status LED instead. Bluetooth Classic exists only on
the original ESP32, so there is no `-bt` build for either S3 variant.

On an ESP32 the published binary is the Bluetooth one. Build `hifi-esp32` or
`hifi-esparagus` yourself if you would rather have the RAM and flash back.

## Features

- PCM5100 line-level DAC, all 8 MB flash
- Software volume control — the DAC has no volume register
- [Bluetooth A2DP](../features/bluetooth.md) on the ESP32 variants
- [W5500 SPI Ethernet](../features/ethernet.md) with automatic WiFi failover, on the
  non-Esparagus variants
- [SH1106 OLED](../features/oled-display.md) over SPI, sharing the Ethernet bus, on the
  non-Esparagus variants

## Flashing

=== "Browser"

    Use the HiFi installer for your board on the
    [flashing page](../getting-started/flashing.md).

=== "PlatformIO"

    ```bash
    # ESP32 — AirPlay + Bluetooth + Ethernet + OLED
    pio run -e hifi-esp32-bt -t upload
    pio run -e hifi-esp32-bt -t uploadfs

    # ESP32 — Esparagus variant, AirPlay + Bluetooth over WiFi
    pio run -e hifi-esparagus-bt -t upload
    pio run -e hifi-esparagus-bt -t uploadfs

    # ESP32-S3 — AirPlay + Ethernet + OLED
    pio run -e hifi-esp32-s3 -t upload
    pio run -e hifi-esp32-s3 -t uploadfs

    # ESP32-S3 — Esparagus variant
    pio run -e hifi-esparagus-s3 -t upload
    pio run -e hifi-esparagus-s3 -t uploadfs
    ```

=== "ESP-IDF"

    ```bash
    idf.py set-target esp32
    idf.py -DSDKCONFIG_DEFAULTS="config/sdkconfig.defaults;config/sdkconfig.defaults.hifi-esp32;config/sdkconfig.defaults.bt" build
    idf.py -p /dev/ttyUSB0 flash
    ```

    Swap in `config/sdkconfig.defaults.hifi-esp32-s3` after `idf.py set-target esp32s3`
    for the S3 revision, and drop `config/sdkconfig.defaults.bt` for a build without
    Bluetooth.

## Default GPIO assignments

| Function | ESP32 | ESP32-S3 | Notes |
| --- | :-: | :-: | --- |
| I2S BCK | 26 | 14 | Bit clock |
| I2S WS | 25 | 15 | Word select (LRCLK) |
| I2S DO | 22 | 16 | Serial audio data |
| I2S MCLK | — | — | Not used; the PCM5100 recovers its own clock |
| Status LED | 33 | 9 | Addressable RGB, Esparagus variants only |
| SPI SCLK | 18 | 12 | Shared by Ethernet and display |
| SPI MOSI | 23 | 11 | Shared by Ethernet and display |
| SPI MISO | 19 | 13 | Ethernet only |
| Ethernet CS | 5 | 10 | W5500 |
| Ethernet INT | 35 | 6 | W5500 |
| Ethernet RST | 14 | 5 | W5500 |
| Display CS | 15 | 39 | SH1106 OLED |
| Display DC | 4 | 40 | SH1106 OLED |
| Display RST | 32 | 38 | SH1106 OLED |

The Esparagus variants use the same I2S pins and leave the SPI block unconfigured.

## Related

- [Loud-ESP32](loud-esp32.md) — the same layout with MAX98357A amplifiers on board
- [Amped-ESP32](amped-esp32.md) — a PCM5100 with a TPA31xx amplifier behind it
- [Bluetooth A2DP](../features/bluetooth.md)
- [Ethernet (W5500)](../features/ethernet.md)
- [Build environments](../reference/build-environments.md)

# Louder-ESP32 and Louder-ESP32-Plus

The Sonocotta [Louder-ESP32](https://github.com/sonocotta/esp32-audio-dock) boards carry a
TI **TAS58xx** combined DAC and Class-D amplifier, the same family the
[Esparagus Audio Brick](esparagus-audio-brick.md) uses. Speakers connect directly.

The **Plus** boards are fitted with a **TAS5825M**; the plain boards with a **TAS5805M**.
Both are driven by the same driver, which reads the die ID at startup, so the difference
is what the part can do rather than which build you flash:

- Volume, mute and the 15-band parametric [Equaliser](esparagus-audio-brick.md#equaliser)
  work on both parts.
- Process flows and full PPC3 dumps are a **TAS5825M** feature. A TAS5805M has no
  flow-select register, so the driver skips a dump rather than write it to the wrong
  place. See [TAS5805M boards](esparagus-audio-brick.md#tas5805m-boards).

Volume is done in the amplifier (`CONFIG_DAC_CONTROLS_VOLUME`) rather than in software.

## Variants

| Environment | Chip | Amplifier | Bluetooth | Prebuilt |
| --- | --- | --- | :-: | :-: |
| `louder-esp32` | ESP32 | TAS5805M | — | — |
| `louder-esp32-bt` | ESP32 | TAS5805M | yes | yes |
| `louder-esp32-plus` | ESP32 | TAS5825M | — | — |
| `louder-esp32-plus-bt` | ESP32 | TAS5825M | yes | yes |
| `louder-esp32-s3` | ESP32-S3 | TAS5805M | — | yes |
| `louder-esp32-s3-plus` | ESP32-S3 | TAS5825M | — | yes |

Bluetooth Classic exists only on the original ESP32, so neither S3 board has a `-bt`
build. On an ESP32 the published binary is the Bluetooth one.

!!! note "Esparagus Louder is a separate board"

    The [Esparagus Louder](esparagus-audio-brick.md#esparagus-louder) is the same
    amplifier family on Sonocotta's Esparagus form factor and has its own environments
    (`esparagus-louder`, `-bt`, `-s3`). Its ESP32 build differs from `louder-esp32` in
    pinout: it has a FAULTZ line and an RGB LED, and no `PDN` pin.

## Features

- TAS5825M or TAS5805M with on-chip DSP and a 15-band parametric EQ (25 Hz – 16 kHz)
- Hardware volume control with a configurable maximum level
- Automatic power state management driven by AirPlay session state
- 8 MB flash
- [Bluetooth A2DP](../features/bluetooth.md) on the ESP32 variants
- [W5500 SPI Ethernet](../features/ethernet.md) with automatic WiFi failover
- [SH1106 OLED](../features/oled-display.md) over SPI, sharing the Ethernet bus

## Flashing

=== "Browser"

    Use the Louder installer for your board on the
    [flashing page](../getting-started/flashing.md).

=== "PlatformIO"

    ```bash
    # ESP32 + TAS5805M
    pio run -e louder-esp32-bt -t upload
    pio run -e louder-esp32-bt -t uploadfs

    # ESP32 + TAS5825M
    pio run -e louder-esp32-plus-bt -t upload
    pio run -e louder-esp32-plus-bt -t uploadfs

    # ESP32-S3 + TAS5805M
    pio run -e louder-esp32-s3 -t upload
    pio run -e louder-esp32-s3 -t uploadfs

    # ESP32-S3 + TAS5825M
    pio run -e louder-esp32-s3-plus -t upload
    pio run -e louder-esp32-s3-plus -t uploadfs
    ```

=== "ESP-IDF"

    ```bash
    idf.py set-target esp32
    idf.py -DSDKCONFIG_DEFAULTS="config/sdkconfig.defaults;config/sdkconfig.defaults.louder-esp32-plus;config/sdkconfig.defaults.bt" build
    idf.py -p /dev/ttyUSB0 flash
    ```

    Swap in `config/sdkconfig.defaults.louder-esp32-s3-plus` after
    `idf.py set-target esp32s3` for the S3 revision.

## Default GPIO assignments

The ESP32 and S3 revisions share no pinout. The Plus boards differ from the plain ones
only in the Ethernet chip select and the OLED chip select.

| Function | Louder-ESP32 | Louder-ESP32-Plus | ESP32-S3 (both) |
| --- | :-: | :-: | :-: |
| I2S BCK | 26 | 26 | 14 |
| I2S WS | 25 | 25 | 15 |
| I2S DO | 22 | 22 | 16 |
| I2C SDA | 21 | 21 | 8 |
| I2C SCL | 27 | 27 | 9 |
| Amplifier `PDN` | 33 | 33 | 17 |
| SPI SCLK | 18 | 18 | 12 |
| SPI MOSI | 23 | 23 | 11 |
| SPI MISO | 19 | 19 | 13 |
| Ethernet CS | 5 | 15 | 10 |
| Ethernet INT | 35 | 35 | 6 |
| Ethernet RST | 14 | 14 | 5 |
| Display CS | 15 | 5 | 47 |
| Display DC | 4 | 4 | 38 |
| Display RST | 32 | 32 | 48 |

`PDN` is driven high once at boot and then left alone — it is the amplifier's power-down
pin, not the per-track mute the [Loud](loud-esp32.md) and [Amped](amped-esp32.md) boards
toggle from playback events.

## Related

- [Esparagus Audio Brick](esparagus-audio-brick.md) — the same TAS58xx driver, EQ and PPC3 workflow
- [HybridFlow DSP](../features/hybridflow.md)
- [Bluetooth A2DP](../features/bluetooth.md)
- [Ethernet (W5500)](../features/ethernet.md)
- [Build environments](../reference/build-environments.md)

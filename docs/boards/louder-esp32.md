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
| `louder-esp32-s3-mini` | ESP32-S3 | TAS5805M, bridged | — | — |

Bluetooth Classic exists only on the original ESP32, so neither S3 board has a `-bt`
build. On an ESP32 the published binary is the Bluetooth one.

!!! note "Esparagus Louder is a separate board"

    The [Esparagus Louder](esparagus-audio-brick.md#esparagus-louder) is the same
    amplifier family on Sonocotta's Esparagus form factor and has its own environments
    (`esparagus-louder`, `-bt`, `-s3`). Its ESP32 build differs from `louder-esp32` in
    pinout: it has a FAULTZ line and an RGB LED, and no `PDN` pin.

## Louder-ESP32-Mini

The [Louder-ESP32-Mini](https://sonocotta.com/louder-esp32-mini/) sits on the back of a
single passive speaker. It carries an ESP32-S3 with 8 MB of flash and 8 MB of PSRAM and a
TAS5805M, and a USB-C port that both powers the amplifier and flashes the board. It uses
the Louder-ESP32-S3's pins, without the Ethernet or the display. Sonocotta's
configurations for the 42 mm and 55 mm boards share the pins and the output wiring.

Its amplifier is **bridged (PBTL)**: the board ties each channel's two half-bridges
together, so all four drive the one speaker. That is wiring, not a setting, so the board
has a build of its own. `louder-esp32-s3-mini` sets `CONFIG_TAS58XX_FORCE_PBTL`, which
brings the amplifier up bridged before its outputs ever switch, and locks the settings
page's Primary Amplifier choice to bridged.

!!! danger "Only flash the Mini's own build"

    Every other Louder build starts the amplifier as a stereo pair, which drives the tied
    half-bridges against each other, and lets the settings page choose stereo.

A bridged TAS5805M plays the left I2S channel, and the TAS5805M has no input mixer to sum
the pair into it here. So the board starts with the output channel set to **Mono (L+R)**.
For a stereo pair of speakers, set one board to Left and the other to Right on the
settings page.

### USB-C power on the 55 mm board

The 55 mm board adds a Hynetek HUSB238A USB-PD trigger, so a USB-C charger can feed the
amplifier more than the 5 V every port gives. The trigger asks for nothing until the
firmware tells it to, and it forgets on every power loss, so the board asks again on every
boot, before the amplifier comes up. The 42 mm board has no trigger; the same build runs
both.

Choose the voltage under **USB-C Power** on the settings page. It starts at 5 V, so no
speaker gets more than it was set up for, and the choice is kept across restarts. Choose
what your speaker can take. 20 V needs a 65 W charger; a 30 W one manages 15 V. A charger
that does not offer the voltage you chose gets the highest one below it, and a supply
without USB-PD, such as a computer's port, stays at 5 V.

The amplifier's gain does not change with its supply, only how far it can swing before it
clips. So after changing the voltage, set **Digital gain** to match. That is the level full
volume plays at, and the page marks the recommended level for each supply, the loudest
that stays clean on it:

| Supply | Digital gain | Most it delivers, 4 Ω / 8 Ω |
| --- | --- | --- |
| 5 V | −16.5 dB | about 3 / 1.5 W |
| 9 V | −11 dB | about 9 / 4.5 W |
| 12 V | −8.5 dB | about 15 / 8 W |
| 15 V | −7 dB | about 22 / 11 W |
| 20 V | −4.5 dB | about 39 / 19 W |

The digital gain starts at −16.5 dB, the 5 V level, which is right for the 42 mm board.
It is set by hand rather than following the supply, so it also suits a board that cannot
read its supply, such as a 55 mm one whose trigger has been strapped to a fixed voltage in
hardware. A louder setting clips the loudest passages; at low frequencies that is often
hard to hear.

An EQ boost needs room above that level too: the recommended gain leaves none, so a
+9 dB boost clips at full volume unless the digital gain comes down by 9 dB. The EQ page
says when the filters boost past what the supply carries, and what to set the digital
gain to.

!!! note "Never more than 20 V"

    The board's supply capacitors are rated for 25 V and the TAS5805M for 26.4 V. The
    trigger can negotiate up to 48 V from an EPR charger, but the firmware only ever asks
    for the fixed 5–20 V offers, and never above `CONFIG_HUSB238A_MAX_VOLTS`.

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

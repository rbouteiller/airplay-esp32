# ESP32-S3 + PCM5102A

The cheapest and most common build: a generic ESP32-S3 dev board with an external
PCM5102A I2S DAC plugged straight onto its pins. This is the default build environment
(`esp32s3`) and the configuration the project is developed against.

For the parts list and step-by-step assembly, see
[shopping list](../getting-started/shopping-list.md) and
[assembly](../getting-started/assembly.md).

## Default I2S pins

| Function | GPIO | PCM5102A pin |
| --- | --- | --- |
| Bit clock | 11 | BCK |
| Audio data | 12 | DIN |
| Word select (LRCLK) | 13 | LCK |
| Software ground | 14 | GND |
| Power | 5V | VIN |

MCLK is not needed by the PCM5102A, which generates it internally. It is nonetheless
routed to GPIO8 by default, which is useful if you want to drive a different converter
such as a WM8805 I2S-to-S/PDIF bridge.

Pins can be changed under **Board Configuration → Pin Configuration** in `menuconfig`.

!!! warning "Bridge VIN/VOUT"

    Most ESP32-S3 boards ship with the VIN/VOUT solder pads open. Bridge them, or the
    DAC gets no 5 V power and you hear nothing.

## Flashing

=== "Browser"

    Use the installer on the [flashing page](../getting-started/flashing.md).

=== "PlatformIO"

    ```bash
    pio run -e esp32s3 -t upload
    pio run -e esp32s3 -t uploadfs
    ```

    The second command is required — it writes the web UI to SPIFFS.

=== "ESP-IDF"

    ```bash
    idf.py set-target esp32s3
    idf.py -DSDKCONFIG_DEFAULTS="config/sdkconfig.defaults;config/sdkconfig.defaults.esp32s3" build
    idf.py -p /dev/ttyUSB0 flash
    ```

## No Bluetooth on the S3

The ESP32-S3 has Bluetooth LE only, not Bluetooth Classic, so A2DP audio is not available.
The `esp32s3` build contains no Bluetooth support at all. Use an ESP32-based board such as
the [SqueezeAMP](squeezeamp.md) or [Esparagus Audio Brick](esparagus-audio-brick.md) if you
want to stream over Bluetooth.

## Variants

### Waveshare ESP32-S3

Waveshare's ESP32-S3 boards use a different pin arrangement and have their own environment
and prebuilt binary:

```bash
pio run -e waveshare-esp32s3 -t upload
pio run -e waveshare-esp32s3 -t uploadfs
```

### JTAG debugging

`esp32s3-jtag` extends the `esp32s3` environment and uploads over the built-in USB JTAG
bridge instead of the serial bootloader:

```bash
pio run -e esp32s3-jtag -t upload
```

### ESP32-S2

An ESP32-S2 build is produced in CI and published as
`airplay2-receiver-esp32s2.bin`, flashable from the
[browser installer](../getting-started/flashing.md). There is no PlatformIO environment for
it — build it through ESP-IDF:

```bash
idf.py set-target esp32s2
idf.py -DSDKCONFIG_DEFAULTS="config/sdkconfig.defaults;config/sdkconfig.defaults.esp32s2" build
```

### ESP32-WROVER

For older WROVER modules with 4 MB flash, `esp32wrover-dev` targets the Freenove WROVER
board and includes Bluetooth:

```bash
pio run -e esp32wrover-dev -t upload
```

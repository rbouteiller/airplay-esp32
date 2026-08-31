# SqueezeAMP

The [SqueezeAMP](https://github.com/philippe44/SqueezeAMP) is an ESP32 board with a
TAS575xx (combined DAC and Class-D amplifier). Connect speakers
directly to the board.

## Flashing

=== "Browser"

    Use the SqueezeAMP installer on the [flashing page](../getting-started/flashing.md).
    Prebuilt binaries exist for the Bluetooth build and the 4 MB variant.

=== "PlatformIO"

    ```bash
    # AirPlay only
    pio run -e squeezeamp -t upload
    pio run -e squeezeamp -t uploadfs

    # AirPlay + Bluetooth A2DP
    pio run -e squeezeamp-bt -t upload
    pio run -e squeezeamp-bt -t uploadfs
    ```

=== "ESP-IDF"

    ```bash
    idf.py set-target esp32
    idf.py -DSDKCONFIG_DEFAULTS="config/sdkconfig.defaults;config/sdkconfig.defaults.squeezeamp" build
    idf.py -p /dev/ttyUSB0 flash
    ```

    `idf.py flash` also writes the SPIFFS `storage` partition from `data/`, so the
    captive-portal pages are present on first boot.

## Build variants

| Environment | Flash | Bluetooth | Notes |
| --- | --- | :-: | --- |
| `squeezeamp` | 8 MB | — | AirPlay only |
| `squeezeamp-bt` | 8 MB | yes | Prebuilt binary published |
| `squeezeamp-4m` | 4 MB | — | Smaller partition table, prebuilt binary published |

Bluetooth does not fit alongside AirPlay in 4 MB of flash, which is why there is no
`squeezeamp-4m-bt`.

## What the build configures

The SqueezeAMP build selects the TAS57xx DAC driver automatically through Kconfig
(`CONFIG_DAC_TAS57XX`) and sets the correct I2S and I2C pins. Audio buffers are reduced
from 5000 to 2500 frames to fit the original ESP32's more limited PSRAM bandwidth.

## Hybrid flow DSP

The SqueezeAMP's TAS5754M has a miniDSP core, so it can run a TI **HybridFlow** process
flow: a full-range stereo chain with EQ, bass enhancement and a compander, or a two-way
bi-amp crossover. The firmware ships the base flows and tunes them live from the
`/hf` page.

The TAS5754M is the part all of this has been tested on. See
[HybridFlow DSP](../features/hybridflow.md) for the flows, the tuning workflow and the
file layout.

!!! note

    HybridFlow needs a TAS57xx with a miniDSP. The driver detects the chip family at boot
    and skips flow loading on TAS578x devices, which have no DSP core.

See [SPIFFS filesystem](../reference/spiffs.md) for the file management API.

## Related

- [HybridFlow DSP](../features/hybridflow.md)
- [Bluetooth A2DP](../features/bluetooth.md)
- [Build environments](../reference/build-environments.md)

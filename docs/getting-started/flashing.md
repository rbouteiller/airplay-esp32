# Flash the firmware

There are three ways to get firmware onto the board. If you have no reason to prefer
another, use the browser installer.

| Method | Use it when | Needs |
| --- | --- | --- |
| **[A — Browser](#option-a-install-from-your-browser)** | You just want a working speaker | Chrome, Edge or Opera |
| **[B — PlatformIO](#option-b-platformio)** | You want to change build settings, or your board has no prebuilt binary | Python, a clone of the repo |
| **[C — ESP-IDF](#option-c-esp-idf)** | You already work with ESP-IDF | ESP-IDF v5.5+ |

## Option A — Install from your browser

Pick your board and click Install. Nothing to download, no toolchain, no command line.

!!! info "Requirements"

    Works in Chrome, Edge and Opera on desktop. It uses the Web Serial API, which
    Safari and Firefox do not implement, and which is unavailable on iOS and Android.
    Plug the board in over USB before clicking Install.

### Generic boards

<div class="grid cards" markdown>

-   __ESP32-S3 + external DAC__

    The standard build, for an ESP32-S3 with a PCM5102A or similar I2S DAC.

    <esp-web-install-button manifest="/airplay-esp32/firmware/esp32s3.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button>

-   __ESP32-S2 + external DAC__

    For ESP32-S2 boards with an external I2S DAC.

    <esp-web-install-button manifest="/airplay-esp32/firmware/esp32s2.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button>

-   __Waveshare ESP32-S3__

    For Waveshare ESP32-S3 boards.

    <esp-web-install-button manifest="/airplay-esp32/firmware/waveshare-esp32s3.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button>

</div>

### Amplifier boards

<div class="grid cards" markdown>

-   __SqueezeAMP__

    ESP32 + TAS5756. Includes Bluetooth A2DP. For 8 MB flash boards.

    <esp-web-install-button manifest="/airplay-esp32/firmware/squeezeamp-bt.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button>

-   __SqueezeAMP (4 MB flash)__

    For the 4 MB flash variant. No Bluetooth — it does not fit.

    <esp-web-install-button manifest="/airplay-esp32/firmware/squeezeamp-4m.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button>

-   __Esparagus Audio Brick__

    ESP32 + TAS5825M. Includes Bluetooth A2DP and W5500 Ethernet.

    <esp-web-install-button manifest="/airplay-esp32/firmware/esparagus-audio-brick-bt.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button>

-   __Esparagus Louder S3__

    ESP32-S3 + TAS5825M with extra gain.

    <esp-web-install-button manifest="/airplay-esp32/firmware/esparagus-louder-s3.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button>

-   __SmartAmp__

    ESP32 + Bluetooth A2DP.

    <esp-web-install-button manifest="/airplay-esp32/firmware/smartamp.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button>

</div>

Once the install finishes, unplug and re-plug the board. It boots into setup mode — carry
on to [First boot](first-boot.md).

!!! note "Prefer to flash manually?"

    Every build above is also published as a merged `.bin` on the
    [releases page](https://github.com/rbouteiller/airplay-esp32/releases/latest).
    Merged images are flashed at offset **`0x0`** with `esptool` or the
    [esptool-js web tool](https://espressif.github.io/esptool-js/).

    Note that only the build variants listed above are published. There is no separate
    non-Bluetooth SqueezeAMP or Esparagus Audio Brick binary — build those yourself with
    PlatformIO if you want them.

## Option B — PlatformIO

[PlatformIO](https://platformio.org/) handles the toolchain setup for you.

```bash
# 1. Install the PlatformIO CLI
pip install platformio

# 2. Clone the project, including submodules
git clone --recursive https://github.com/rbouteiller/airplay-esp32
cd airplay-esp32

# 3. Plug the board in over USB and flash the firmware
pio run -e esp32s3 -t upload

# 4. Flash the SPIFFS image containing the web UI and data files
pio run -e esp32s3 -t uploadfs

# 5. Optionally watch the serial output
pio run -e esp32s3 -t monitor
```

!!! warning "Step 4 is not optional"

    PlatformIO does **not** write the SPIFFS partition as part of `-t upload`. If you skip
    `-t uploadfs`, the device boots but the captive portal and web UI pages are missing,
    and you get "file not found" errors during setup. See
    [SPIFFS filesystem](../reference/spiffs.md).

Replace `esp32s3` with whichever environment matches your hardware — see
[build environments](../reference/build-environments.md) for the full list.

## Option C — ESP-IDF

```bash
# 1. Install ESP-IDF v5.5 or newer:
#    https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/

# 2. Clone the project, including submodules
git clone --recursive https://github.com/rbouteiller/airplay-esp32
cd airplay-esp32

# 3. Activate the ESP-IDF environment
source /path/to/esp-idf/export.sh

# 4. Build and flash, including the SPIFFS "storage" partition from data/
idf.py set-target esp32s3
idf.py build
idf.py -p /dev/ttyUSB0 flash

# 5. Optionally monitor the serial output
idf.py -p /dev/ttyUSB0 monitor
```

Unlike PlatformIO, `idf.py flash` writes the SPIFFS partition in the same step, so there
is no separate filesystem upload to remember.

## Next

Continue to [First boot](first-boot.md).

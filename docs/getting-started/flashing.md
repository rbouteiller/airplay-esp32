# Flash the firmware

There are three ways to get firmware onto the board. If you have no reason to prefer
another, use the browser installer.

| Method | Use it when | Needs |
| --- | --- | --- |
| **[A — Browser](#option-a-install-from-your-browser)** | You just want a working speaker | Chrome, Edge or Opera |
| **[B — PlatformIO](#option-b-platformio)** | You want to change build settings, or your board has no prebuilt binary | Python, a clone of the repo |
| **[C — ESP-IDF](#option-c-esp-idf)** | You already work with ESP-IDF | ESP-IDF v5.5.5+ |

## Option A — Install from your browser

Pick your board and click Install. Nothing to download, no toolchain, no command line.

!!! info "Requirements"

    Works in Chrome, Edge and Opera on desktop. It uses the Web Serial API, which
    Safari and Firefox do not implement, and which is unavailable on iOS and Android.
    Plug the board in over USB before clicking Install.

Each board has an **Install** button for the latest release and, beside it, a dashed
**Install beta** button for a build of the current `staging` branch. Read
[beta builds](#beta-builds) before using the second one.

### Generic boards

<div class="grid cards" markdown>

-   __ESP32-S3 + external DAC__

    The standard build, for an ESP32-S3 with a PCM5102A or similar I2S DAC.

    <esp-web-install-button manifest="/airplay-esp32/firmware/esp32s3.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/esp32s3.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __ESP32-S2 + external DAC__

    For ESP32-S2 boards with an external I2S DAC.

    <esp-web-install-button manifest="/airplay-esp32/firmware/esp32s2.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/esp32s2.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __Waveshare ESP32-S3__

    For Waveshare ESP32-S3 boards.

    <esp-web-install-button manifest="/airplay-esp32/firmware/waveshare-esp32s3.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/waveshare-esp32s3.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
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
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/squeezeamp-bt.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __SqueezeAMP (4 MB flash)__

    For the 4 MB flash variant. No Bluetooth — it does not fit.

    <esp-web-install-button manifest="/airplay-esp32/firmware/squeezeamp-4m.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/squeezeamp-4m.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __SmartAmp__

    ESP32 + Bluetooth A2DP.

    <esp-web-install-button manifest="/airplay-esp32/firmware/smartamp.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/smartamp.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

</div>

### Esparagus boards

Every Esparagus board is fitted with a **TAS58xx** amplifier — a TAS5825M or a TAS5805M,
detected at startup, so one binary covers both. The Audio Bricks also have W5500
Ethernet. Bluetooth A2DP only exists on the original ESP32.

<div class="grid cards" markdown>

-   __Esparagus Audio Brick__

    ESP32 + TAS58xx. Includes Bluetooth A2DP and W5500 Ethernet.

    <esp-web-install-button manifest="/airplay-esp32/firmware/esparagus-audio-brick-bt.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/esparagus-audio-brick-bt.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __Esparagus Audio Brick S3__

    ESP32-S3 + TAS58xx, with W5500 Ethernet.

    <esp-web-install-button manifest="/airplay-esp32/firmware/esparagus-audio-brick-s3.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/esparagus-audio-brick-s3.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __Esparagus Audio Brick Dual__

    ESP32-S3 + two amplifiers: stereo plus a bridged mono subwoofer.

    <esp-web-install-button manifest="/airplay-esp32/firmware/esparagus-audio-brick-dual-dac.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/esparagus-audio-brick-dual-dac.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __Esparagus Audio Brick Dual + USB audio__

    The Dual, also enumerating as a USB speaker. See [USB audio](../features/usb-audio.md).

    <esp-web-install-button manifest="/airplay-esp32/firmware/esparagus-audio-brick-dual-uac.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/esparagus-audio-brick-dual-uac.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __Esparagus Louder__

    ESP32 + TAS58xx. Includes Bluetooth A2DP.

    <esp-web-install-button manifest="/airplay-esp32/firmware/esparagus-louder-bt.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/esparagus-louder-bt.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __Esparagus Louder S3__

    ESP32-S3 + TAS58xx.

    <esp-web-install-button manifest="/airplay-esp32/firmware/esparagus-louder-s3.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/esparagus-louder-s3.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

</div>

### HiFi boards

[HiFi-ESP32 and HiFi-Esparagus](../boards/hifi-esp32.md) carry a **PCM5100** line-level
DAC and no amplifier — they feed an amp or active speakers. The `-ESP32` boards have
W5500 Ethernet and an OLED; the Esparagus ones do not.

<div class="grid cards" markdown>

-   __HiFi-ESP32__

    ESP32 + PCM5100, Ethernet and OLED. Includes Bluetooth A2DP.

    <esp-web-install-button manifest="/airplay-esp32/firmware/hifi-esp32-bt.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/hifi-esp32-bt.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __HiFi-Esparagus__

    ESP32 + PCM5100, WiFi only. Includes Bluetooth A2DP.

    <esp-web-install-button manifest="/airplay-esp32/firmware/hifi-esparagus-bt.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/hifi-esparagus-bt.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __HiFi-ESP32-S3__

    ESP32-S3 + PCM5100, Ethernet and OLED.

    <esp-web-install-button manifest="/airplay-esp32/firmware/hifi-esp32-s3.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/hifi-esp32-s3.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __HiFi-Esparagus-S3__

    ESP32-S3 + PCM5100, WiFi only.

    <esp-web-install-button manifest="/airplay-esp32/firmware/hifi-esparagus-s3.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/hifi-esparagus-s3.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

</div>

### Loud and Echo boards

[Loud-ESP32, Loud-Esparagus and Esparagus Echo](../boards/loud-esp32.md) drive
**MAX98357A** amplifiers directly — connect speakers to the board.

<div class="grid cards" markdown>

-   __Loud-ESP32__

    ESP32 + MAX98357A, Ethernet and OLED. Includes Bluetooth A2DP.

    <esp-web-install-button manifest="/airplay-esp32/firmware/loud-esp32-bt.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/loud-esp32-bt.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __Loud-Esparagus__

    ESP32 + dual MAX98357A, WiFi only. Includes Bluetooth A2DP.

    <esp-web-install-button manifest="/airplay-esp32/firmware/loud-esparagus-bt.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/loud-esparagus-bt.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __Loud-ESP32-S3__

    ESP32-S3 + dual MAX98357A, Ethernet and OLED.

    <esp-web-install-button manifest="/airplay-esp32/firmware/loud-esp32-s3.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/loud-esp32-s3.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __Esparagus Echo__

    ESP32-S3 + dual MAX98357A, Ethernet, no display.

    <esp-web-install-button manifest="/airplay-esp32/firmware/esparagus-echo.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/esparagus-echo.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

</div>

### Amped boards

[Amped-ESP32 and Amped-Esparagus](../boards/amped-esp32.md) put a **PCM5100** DAC in front
of a **TPA3110/TPA3128** amplifier. Connect speakers to the board.

<div class="grid cards" markdown>

-   __Amped-ESP32__

    ESP32 + PCM5100 + TPA31xx, Ethernet and OLED. Includes Bluetooth A2DP.

    <esp-web-install-button manifest="/airplay-esp32/firmware/amped-esp32-bt.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/amped-esp32-bt.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __Amped-Esparagus__

    ESP32 rev M, Ethernet and a rotary encoder. Includes Bluetooth A2DP.

    <esp-web-install-button manifest="/airplay-esp32/firmware/amped-esparagus-bt.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/amped-esparagus-bt.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __Amped-ESP32-S3__

    ESP32-S3 + PCM5100 + TPA31xx, Ethernet and OLED.

    <esp-web-install-button manifest="/airplay-esp32/firmware/amped-esp32-s3.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/amped-esp32-s3.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

</div>

### Louder boards

[Louder-ESP32](../boards/louder-esp32.md) carries a **TAS58xx** DAC and amplifier. The
**Plus** boards have a TAS5825M, the plain ones a TAS5805M — pick the card that matches
the board, the pinouts differ.

<div class="grid cards" markdown>

-   __Louder-ESP32__

    ESP32 + TAS5805M, Ethernet and OLED. Includes Bluetooth A2DP.

    <esp-web-install-button manifest="/airplay-esp32/firmware/louder-esp32-bt.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/louder-esp32-bt.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __Louder-ESP32-Plus__

    ESP32 + TAS5825M, Ethernet and OLED. Includes Bluetooth A2DP.

    <esp-web-install-button manifest="/airplay-esp32/firmware/louder-esp32-plus-bt.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/louder-esp32-plus-bt.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __Louder-ESP32-S3__

    ESP32-S3 + TAS5805M, Ethernet and OLED.

    <esp-web-install-button manifest="/airplay-esp32/firmware/louder-esp32-s3.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/louder-esp32-s3.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

-   __Louder-ESP32-S3-Plus__

    ESP32-S3 + TAS5825M, Ethernet and OLED.

    <esp-web-install-button manifest="/airplay-esp32/firmware/louder-esp32-s3-plus.json">
      <button slot="activate" class="md-button md-button--primary">Install</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button><esp-web-install-button class="install-beta" manifest="/airplay-esp32/firmware/beta/louder-esp32-s3-plus.json">
      <button slot="activate" class="md-button md-button--beta">Install beta</button>
      <span slot="unsupported"></span>
      <span slot="not-allowed"></span>
    </esp-web-install-button>

</div>

Once the install finishes, unplug and re-plug the board. It boots into setup mode — carry
on to [First boot](first-boot.md).

### Beta builds

The dashed **Install beta** buttons flash a build of the tip of the `staging` branch,
rebuilt on every push. That is where fixes land before a release, so a beta is the way to
try one — or to confirm a bug you reported is gone.

It is also unreleased code. Betas come off the same CI as a release, but nobody has run
them on hardware, so treat a failure to boot as expected rather than surprising and
[report it](https://github.com/rbouteiller/airplay-esp32/issues). Installing the release
build again always recovers the board.

A button only appears when the build behind it exists, so the beta buttons are absent
between `staging` pushes, and a board added since the last release shows its beta button
alone until a release carries a build for it.

!!! note "Prefer to flash manually?"

    Every build above is also published as a merged `.bin`, on the
    [releases page](https://github.com/rbouteiller/airplay-esp32/releases/latest) for
    releases and under the [`beta` tag](https://github.com/rbouteiller/airplay-esp32/releases/tag/beta)
    for the current staging build. Merged images are flashed at offset **`0x0`** with
    `esptool` or the [esptool-js web tool](https://espressif.github.io/esptool-js/).

    Only the variants listed above are published — anything else in
    [build environments](../reference/build-environments.md) you build yourself.

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
# 1. Install ESP-IDF v5.5.5 or newer:
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

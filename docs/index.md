---
title: ESP32 AirPlay 2 Receiver
hide:
  - navigation
---

# ESP32 AirPlay 2 Receiver

**Stream music from your Apple devices — or from any phone over Bluetooth — to any speaker, for about $10.**

This firmware turns a cheap ESP32 board into a wireless AirPlay 2 speaker. Plug it into
an amplifier or powered speakers and it shows up on your iPhone, iPad or Mac just like a
HomePod or an AirPlay TV.

No cloud. No app. Just tap and play.

!!! tip "Already have a board? Install it right now"

    Plug it in over USB and click Install. No toolchain, no downloads, no command line
    — your browser talks to the board directly.

    <esp-web-install-button manifest="/airplay-esp32/firmware/esp32s3.json">
      <button slot="activate" class="md-button md-button--primary">Install on ESP32-S3</button>
      <span slot="unsupported">Your browser cannot flash over USB. Use Chrome, Edge or Opera on desktop.</span>
      <span slot="not-allowed">Flashing needs a secure (HTTPS) connection.</span>
    </esp-web-install-button>

    That button is for a generic **ESP32-S3**. For SqueezeAMP, Esparagus, Waveshare and
    the rest, see [all boards on the flashing page](getting-started/flashing.md). Requires
    Chrome, Edge or Opera on desktop.

<div class="grid cards" markdown>

-   __New here?__

    Buy two boards, plug them together, flash from your browser.

    [Start here](getting-started/index.md)

-   __Already have a board?__

    SqueezeAMP, Esparagus Audio Brick, XIAO ESP32-C5 and more.

    [Pick your board](boards/index.md)

-   __Something not working?__

    No setup WiFi, no sound, missing web pages, build errors.

    [Troubleshooting](troubleshooting.md)

-   __Want to hack on it?__

    Build environments, audio pipeline, protocol stack.

    [Architecture](reference/architecture.md)

</div>

## What you are building

<figure markdown>
  ![An ESP32-S3 with a PCM5102A DAC plugged onto it, forming a small stacked board with a 3.5 mm jack](assets/ESP_PCM_front.png){ width="240" }
  <figcaption>Two boards, one pin header, no soldering — the 3.5 mm jack goes to your amplifier</figcaption>
</figure>

## How it works in 30 seconds

```mermaid
flowchart LR
    P["iPhone / Mac"]
    W(("WiFi"))
    E["ESP32<br/><small>this firmware</small>"]
    D["DAC"]
    S["Your speakers"]

    P -->|AirPlay| W --> E -->|I2S| D -->|analog| S

    classDef hi stroke:#26a69a,stroke-width:3px
    class E hi
```

Your phone sees an AirPlay speaker on the network. The ESP32 receives the encrypted
stream, decodes it, keeps it clock-synced to the sender, and pushes the audio out over I2S
to a DAC. The DAC drives your amplifier. Full detail in
[architecture](reference/architecture.md).

## Supported hardware

Works with **ESP32**, **ESP32-S2**, **ESP32-S3** and **ESP32-C5** chips. That includes
plain dev boards paired with an external I2S DAC, and several integrated
amplifier boards:

- [SqueezeAMP](boards/squeezeamp.md) — ESP32 + TAS5756 DAC and Class-D amplifier
- [Esparagus Audio Brick](boards/esparagus-audio-brick.md) — ESP32 or ESP32-S3 + TAS5825M DAC/amp, on-chip DSP, Ethernet
- [Esparagus Audio Brick rev D](boards/esparagus-audio-brick-dual-dac.md) — ESP32-S3 + two TAS5825M, active crossover, USB audio
- [ESP32-S3 + PCM5102A](boards/esp32s3-pcm5102a.md) — the cheapest route, no soldering required

ESP32-based boards additionally support **Bluetooth A2DP**, so anything that can pair with
a Bluetooth speaker can play to them when AirPlay is idle.

## Features

- **AirPlay 2** — appears natively in Control Center and every AirPlay-capable app
- **ALAC and AAC decoding** — handles both live streaming (Siri, calls) and music playback
- **Multi-room** — PTP-based timing for synchronised playback across devices
- **Bluetooth A2DP** — receive audio from phones and tablets (ESP32 boards only)
- **W5500 Ethernet** — wired networking with automatic WiFi failover
- **Web configuration** — set WiFi and device name from a browser
- **OTA updates** — update over WiFi; USB is only needed for the first flash
- **48 kHz output** — optional 44.1 → 48 kHz conversion for DACs and S/PDIF receivers that need it
- **Displays** — optional OLED or 320×170 colour TFT showing track metadata and progress
- **Hardware buttons** — optional physical play/pause, volume and track-skip buttons

### Limitations

- Audio only — no AirPlay video or photos
- One speaker per ESP32 board
- Needs a decent WiFi signal for stable streaming

## Acknowledgements

- [Shairport Sync](https://github.com/mikebrady/shairport-sync) — the reference AirPlay implementation
- [openairplay/airplay2-receiver](https://github.com/openairplay/airplay2-receiver) — Python AirPlay 2 implementation
- [Espressif](https://github.com/espressif) — ESP-IDF framework and codec libraries

## Legal

**Non-commercial use only.** Commercial use requires explicit permission — see
[LICENSE](https://github.com/rbouteiller/airplay-esp32/blob/main/LICENSE).

This is an independent project based on protocol analysis. It is not affiliated with
Apple Inc., is not guaranteed to work with future iOS or macOS versions, and is provided
as-is without warranty.

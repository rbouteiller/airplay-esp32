# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ESP32 AirPlay 2 Receiver — firmware that turns ESP32/ESP32-S2/ESP32-S3/ESP32-C5/ESP32-P4 boards into AirPlay 2 speakers. Supports ALAC and AAC decoding, Bluetooth A2DP (ESP32 only), USB Audio Class in both directions, S/PDIF, W5500 Ethernet (Esparagus Audio Brick), OLED/TFT displays, hardware buttons, and OTA updates. The documentation site also lives in this repo, under `docs/`.

## Build & Flash

**PlatformIO** (recommended):
```bash
pio run -e <env> -t build          # Build firmware
pio run -e <env> -t upload          # Build + flash via USB
pio run -e <env> -t monitor         # Serial monitor (115200 baud)
pio run -e <env> -t uploadfs        # Flash SPIFFS from data/
pio run -e <env> -t menuconfig      # Kconfig configuration
```

**ESP-IDF** (native):
```bash
source /path/to/esp-idf/export.sh
idf.py set-target esp32s3           # or esp32, esp32p4
idf.py build
idf.py -p /dev/ttyUSB0 flash
idf.py -p /dev/ttyUSB0 monitor
```

## Build Environments

| Environment | Board | Notes |
|---|---|---|
| `esp32s3` | ESP32-S3 + external DAC (e.g. PCM5102A) | Default, 16MB flash |
| `esp32s3-uac` | Same, as a USB speaker | Extends esp32s3 + `defaults.uac` |
| `esp32s3-jtag` | ESP32-S3 with JTAG | Extends esp32s3 |
| `esp32c5-xiao` | Seeed XIAO ESP32-C5 | Needs the pioarduino platform fork; the ESP-IDF native flow works too |
| `esp32wrover-dev` | Freenove ESP32-WROVER devkit | 4MB, Bluetooth |
| `waveshare-esp32s3` | Waveshare ESP32-S3 audio board | 16MB |
| `squeezeamp` | ESP32 + TAS5756 DAC/amp | 8MB flash |
| `squeezeamp-bt` | Same + Bluetooth A2DP | |
| `squeezeamp-4m` | SqueezeAMP with 4MB flash | |
| `smartamp` | ESP32 + Bluetooth | 4MB |
| `esparagus-audio-brick` | ESP32 + TAS5825M/TAS5805M DAC/amp | Ethernet is on in every brick build |
| `esparagus-audio-brick-bt` | Same + Bluetooth | |
| `esparagus-audio-brick-s3` | ESP32-S3 + TAS5825M | Different pinout from the ESP32 revision |
| `esparagus-audio-brick-dual-dac` | ESP32-S3 + 2x TAS5825M (rev D) | Stereo @0x4C + PBTL mono sub @0x4D |
| `esparagus-audio-brick-dual-uac` | Same + USB speaker | |
| `esparagus-louder` | ESP32 + TAS5825M + extra gain | |
| `esparagus-louder-bt` | Louder + Bluetooth | |
| `esparagus-louder-s3` | ESP32-S3 + Louder | |

Bluetooth Classic only exists on the original ESP32, so the S3 revision of a board never has a `-bt` environment.

Board configs live in `config/` (the generated `sdkconfig` stays at the project root). Sdkconfig defaults are layered via `cmake_extra_args` (left-to-right override). Custom board config: create `config/sdkconfig.user.<name>` + `user_platformio.ini` to extend any environment without modifying the main config; `dma80`, `s3-custom`, `soundlink` and `wrover` are worked examples.

## Architecture

```
main/
├── main.c                  # Entry point — initializes NVS, WiFi, starts AirPlay services
├── settings.c              # NVS persistence for device name, WiFi credentials, volume
├── audio/                  # Audio pipeline
│   ├── audio_receiver.c    # RTSP session manager — orchestrates streams (buffered/realtime)
│   ├── audio_stream.c      # Base stream abstraction
│   ├── audio_stream_buffered.c   # AirPlay 2 AAC (deep jitter buffer)
│   ├── audio_stream_realtime.c     # AirPlay 1 ALAC (low latency UDP)
│   ├── audio_decoder.c     # ALAC and AAC decoders
│   ├── audio_decode_worker.c # Decoder task fed from the receive path
│   ├── audio_buffer.c      # Decoder scratch space (the sorted PCM ring is gone)
│   ├── audio_timeline.c    # RTP-addressed PCM store — holds the decoded audio
│   ├── audio_engine_v2.c   # Owns the epoch, timeline, clock map and scheduler
│   ├── audio_scheduler.c   # Anchor/preroll/play/pause/recover state machine + drift servo
│   ├── audio_clock_map.c   # Sender time ↔ RTP mapping (PTP for AP2, NTP for AP1)
│   ├── audio_epoch.c       # Generation counter that invalidates stale work
│   ├── audio_timing.c      # Clock plumbing shared by the streams
│   ├── audio_resample.c    # Sample rate conversion (44.1→48kHz)
│   ├── audio_output.c      # I2S output
│   ├── audio_output_spdif.c # S/PDIF output
│   ├── audio_output_usb.c  # USB audio *source* — board enumerates as a mic
│   ├── usb_audio_sink.c    # USB audio *sink* — board enumerates as a speaker
│   ├── audio_crypto.c      # AirPlay encryption
│   └── a2dp_sink.c         # Bluetooth A2DP sink
├── rtsp/                   # RTSP protocol server
│   ├── rtsp_server.c       # RTSP connection handler
│   ├── rtsp_conn.c         # Connection management
│   ├── rtsp_handlers.c     # RTSP method handlers (OPTIONS, SETUP, PLAY, etc.)
│   ├── rtsp_events.c       # RTSP event handling (including BT passthrough)
│   ├── rtsp_crypto.c       # RTSP-level encryption
│   ├── rtsp_fairplay.c     # Apple FairPlay integration
│   └── rtsp_rsa.c          # RSA crypto
├── hap/                    # HomeKit Accessory Protocol
│   ├── hap.c               # Core HAP
│   ├── hap_pair_setup.c    # Pairing setup (SRP handshake)
│   ├── hap_pair_verify.c   # Pair verify (Ed25519)
│   ├── hap_crypto.c        # HAP encryption
│   └── srp.c               # SRP-6a key exchange
├── plist/                  # Apple Property List parsing
├── usb/                    # TinyUSB composite device (UAC + HID transport controls)
├── network/                # Network stack
│   ├── wifi.c              # WiFi AP+STA, captive portal, auto-reconnect
│   ├── ethernet.c          # W5500 SPI Ethernet driver
│   ├── mdns_airplay.c      # mDNS AirPlay service advertisement
│   ├── ptp_clock.c         # Precision Time Protocol clock
│   ├── ntp_clock.c         # NTP time sync fallback
│   ├── web_server.c        # HTTP config/control server
│   ├── ota.c               # OTA firmware updates
│   ├── dns_server.c        # Captive portal DNS
│   └── log_stream.c        # Remote log streaming
├── dacp_client.c           # DACP (Digital Audio Control Protocol) — button/remote commands
├── playback_control.c      # Unified playback control abstraction
├── bt_coex.c               # Frees the Bluetooth stack's DRAM when AirPlay takes over
├── spiram_task.h           # Task-creation wrappers (stacks must stay in internal RAM)
├── buttons.c               # Hardware button input with debounce + auto-repeat
└── led.c                   # LED status indicator

components/
├── dac/                    # Abstract DAC API (Kconfig-selected implementation)
│   └── dac.c               # Dispatch layer → TAS57xx or TAS58xx driver
├── dac_tas57xx/            # TI TAS57xx (TAS5756/5754/5751) DAC driver with hybrid flow DSP
├── dac_tas58xx/            # TI TAS58xx (TAS5825M/TAS5805M) driver with on-chip DSP + biquad chains
├── dac_es8311/             # Everest ES8311 codec driver
├── display/                # Display drivers
│   ├── display.c           # Common display API
│   ├── display_st7789.c    # ST7789 TFT with LVGL 9 rendering (ESP32-S3)
│   └── display_stub.c      # No-op stub when display disabled
├── boards/                 # Board support (HAL) + partition tables
│   ├── board_common.c      # Shared board utilities
│   ├── esp32-generic/      # ESP32 generic board init
│   ├── esp32s2-generic/    # ESP32-S2 generic board init
│   ├── esp32s3-generic/    # ESP32-S3 generic board init
│   ├── esp32c5-xiao/       # Seeed XIAO ESP32-C5 board init
│   ├── waveshare-esp32p4/  # Waveshare ESP32-P4 board init
│   ├── waveshare-esp32s3/  # Waveshare ESP32-S3 board init
│   ├── squeezeamp/         # SqueezeAMP (ESP32 + TAS5756)
│   └── esparagus-audio-brick/ # Esparagus Audio Brick (ESP32/S3 + TAS58xx + W5500)
├── spiffs_storage/         # SPIFFS filesystem mount (stores web pages + DSP configs)
├── audio-resampler/        # sinc-based audio resampler (44.1→48kHz)
└── board_utils/            # Board-level utilities
```

## Key Conventions

- **CMake/Kconfig**: Board selection is via `CONFIG_` Kconfig options. DAC driver is auto-selected (`CONFIG_DAC_TAS57XX` or `CONFIG_DAC_TAS58XX`). Display, buttons, BT, Ethernet are all Kconfig-gated.
- **Component structure**: Each component has its own `CMakeLists.txt` with `idf_component_register()`.
- **Git submodules**: `u8g2` (OLED graphics) and `u8g2-hal-esp-idf` (ESP-IDF HAL for u8g2) are submodules — always clone with `--recursive`.
- **SPIFFS**: `data/` directory contents are flashed to SPIFFS. `data/www/` = web UI, `data/hf/` = DSP binaries. Only the four `base-hf<n>-<rate>.bin` hybrid-flow bases are tracked; tuned PPC3 dumps are user-supplied and deliberately untracked.
- **Audio pipeline**: receiver → decode worker → **RTP-addressed timeline** → scheduler → AudioOutput (I2S/SPDIF/USB). Both the buffered (AAC) and realtime (ALAC) paths now run through engine v2; the old sorted PCM pool is gone. The scheduler anchors on the sender's clock (PTP for AirPlay 2, NTP for AirPlay 1), prerolls, then closes a drift servo against the DMA play position.
- **AirPlay/Bluetooth coexistence**: Mutually exclusive at runtime. BT connection suspends AirPlay; disconnect resumes it. `bt_coex.c` releases the BT stack's DRAM once AirPlay owns the output.
- **USB audio, two directions**: `defaults.usb` (`CONFIG_AUDIO_OUTPUT_USB`) makes the board a USB *source* — it appears as a microphone and AirPlay audio leaves over USB. `defaults.uac` (`CONFIG_USB_AUDIO_SINK`) makes it a USB *speaker* — the host plays into the same I2S DAC, which stops the AirPlay services while it streams. The UAC descriptor advertises a single rate, so `CONFIG_UAC_SAMPLE_RATE` must equal `CONFIG_OUTPUT_SAMPLE_RATE_HZ`.
- **Eth/WiFi failover**: Ethernet preferred at boot; WiFi fallback if no cable. Hot-swap at runtime.
- **Task stacks stay in internal RAM** (`main/spiram_task.h`): flash operations disable the cache, so a stack in SPIRAM trips `esp_task_stack_is_sane_cache_disabled()`. Large *local* buffers are the opposite problem — `CONFIG_ESP_MAIN_TASK_STACK_SIZE` is only 3584 bytes, so anything of that order belongs in a `heap_caps_calloc(..., MALLOC_CAP_SPIRAM)` allocation. Overflowing it corrupts whatever was allocated next, which shows up as unrelated driver failures.

## TAS58xx notes

- **Two parts, one driver.** The model is guessed from the I2C address (0x4C–0x4F → TAS5825M, 0x2C–0x2F → TAS5805M), then confirmed against the die ID in register 0x67; a disagreement is logged as a warning.
- **A TAS5805M has no process flow.** PPC3 dumps are skipped for it (`tas58xx_load_hf()` returns early unless the model is a TAS5825M) and the input mixer refuses anything but stereo. Volume, mute and the 15 biquads per channel work on both parts, so the `/bq` web UI is the tuning route for a 5805M.
- **PPC3 dump filenames**, searched most specific first: `tas5825m_fw<i>-<rate>.bin` → `tas5825m_fw-<rate>.bin` → `tas5825m_fw<i>.bin` → `tas5825m_fw.bin`. The unindexed names only stand in for device 0. `components/dac_tas58xx/ppc3_convert.py` produces them from a PPC3 export.
- **Fault handling.** A clock fault is expected when the I2S clock stops at the end of a track, so it is logged and cleared rather than muting the amplifier; channel and global2 faults still mute. Rev D has no fault line at all and is polled instead.

## Code Quality

**Requirements**: ESP-IDF >= 5.5 (tested against v5.5.2). Older versions may need workarounds.

**Formatting**: LLVM-style, 2-space indent, 80-char column limit. See `.clang-format`.

**Linting**: clang-tidy with bugprone, performance, portability, and readability checks. See `.clang-tidy`.

**Pre-commit hook**: auto-formats staged C/H files with clang-format, runs clang-tidy (requires `build/compile_commands.json`). Install via `git config core.hooksPath .githooks`.

**CI** (`.github/workflows/`), four workflows:
- `ci.yml` — on push to `main` and on every PR. A `changes` job skips the firmware jobs for a Markdown-only PR; `format-check` (clang-format), `lint-check` (clang-tidy against an esp32s3 build), `output-backends` (links the spdif and usb backends, which the release matrix never covers) and `build` follow. **`ci-gate` is the one required check** — it runs unconditionally and treats skipped as fine, so branch protection does not have to list every matrix job.
- `build.yml` — reusable, and the single source of truth for the release matrix: esp32s3, waveshare-esp32s3, esp32s2, squeezeamp-bt, squeezeamp-4m, esparagus-audio-brick-bt, smartamp, esparagus-louder-s3. Uploads a merged `airplay2-receiver-<name>.bin` per target.
- `release.yml` — on a `v*` tag. Refuses to release unless the tag matches `version.txt` and points at a commit on `main`, then publishes the merged binaries.
- `docs.yml` — `zensical build --strict --clean`, bundles the latest release binaries into `site/firmware/` for the browser installer, and deploys to Pages. **`docs-build` is a required check**, so its `pull_request` trigger is deliberately unfiltered.

The `pull_request` triggers in `ci.yml` and `docs.yml` are unfiltered on purpose: a required check whose workflow never fires sits "Expected" forever and blocks the merge.

**Local tooling** (in `scripts/`):
```bash
scripts/format.sh          # Format all C/H files (excludes u8g2 submodule)
scripts/lint.sh            # Run clang-tidy on all C/H files
scripts/lint.sh --fix      # Attempt to auto-fix clang-tidy issues
```

**No unit tests**: This is embedded firmware — no test framework is in place. Manual testing on hardware is required.

## Documentation site

The site is built with **Zensical**, not mkdocs — it reads `mkdocs.yml` natively, and mkdocs is not installed.

```bash
python3 -m venv ~/.venvs/airplay-docs
~/.venvs/airplay-docs/bin/pip install -r docs/requirements.txt
~/.venvs/airplay-docs/bin/zensical build --strict --clean   # ~0.5 s
~/.venvs/airplay-docs/bin/zensical serve                    # http://localhost:8000
```

`--strict` turns a broken internal link into a build failure, which is the main thing worth checking locally. A new page **must** be added to `nav:` in `mkdocs.yml` or it is unreachable. Output lands in `site/`, which is gitignored.

VS Code's built-in Markdown preview does not understand `!!!` admonitions or `===` tabs and renders them as code blocks. That is a preview limitation, not a broken page — check with a real build before "fixing" the source.

## Adding a board

1. `config/sdkconfig.defaults.<board>` with the pins and Kconfig selections.
2. A `[env:<board>]` in `platformio.ini`, layering that file after `config/sdkconfig.defaults`.
3. A board directory under `components/boards/` if it needs its own init.
4. A page under `docs/boards/` **and** an entry in `nav:`.
5. For a board that should ship prebuilt firmware: a matrix entry in `.github/workflows/build.yml` **and** a matching `docs/firmware/<name>.json` ESP Web Tools manifest, whose `parts[0].path` must equal `airplay2-receiver-<name>.bin`. The docs workflow drops any manifest whose binary is missing from the release.

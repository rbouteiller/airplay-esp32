# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ESP32 AirPlay 2 Receiver — firmware that turns ESP32/ESP32-S3/ESP32-P4 boards into AirPlay 2 speakers. Supports ALAC and AAC decoding, Bluetooth A2DP (ESP32 only), W5500 Ethernet (Esparagus Audio Brick), OLED/TFT displays, hardware buttons, and OTA updates.

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
| `esp32s3` | ESP32-S3 + external DAC (e.g. PCM5102A) | Default |
| `esp32s3-jtag` | ESP32-S3 with JTAG | Extends esp32s3 |
| `squeezeamp` | ESP32 + TAS5756 DAC/amp | 8MB flash |
| `squeezeamp-bt` | Same + Bluetooth A2DP | |
| `squeezeamp-4m` | SqueezeAMP with 4MB flash | |
| `esparagus-audio-brick` | ESP32 + TAS5825M DAC/amp | |
| `esparagus-audio-brick-bt` | Same + Bluetooth + Ethernet | |
| `esparagus-audio-brick-s3` | ESP32-S3 + TAS5825M | |
| `esparagus-louder` | ESP32 + TAS5825M + extra gain | |
| `esparagus-louder-bt` | Louder + Bluetooth | |
| `esparagus-louder-s3` | ESP32-S3 + Louder | |

Sdkconfig defaults are layered via `cmake_extra_args` (left-to-right override). Custom board config: create `sdkconfig.user.<name>` + `user_platformio.ini` to extend any environment without modifying the main config.

## Architecture

```
main/
├── main.c                  # Entry point — initializes NVS, WiFi, starts AirPlay services
├── settings.c              # NVS persistence for device name, WiFi credentials, volume
├── audio/                  # Audio pipeline
│   ├── audio_receiver.c    # RTSP session manager — orchestrates streams (buffered/unbuffered)
│   ├── audio_stream.c      # Base stream abstraction
│   ├── audio_stream_buffered.c   # AirPlay 2 AAC (deep jitter buffer)
│   ├── audio_stream_realtime.c     # AirPlay 1 ALAC (low latency UDP)
│   ├── audio_decoder.c     # ALAC and AAC decoders
│   ├── audio_buffer.c      # Frame buffering between receiver and output
│   ├── audio_timing.c      # PTP-based timing — early/late frame handling
│   ├── audio_resample.c    # Sample rate conversion (44.1→48kHz)
│   ├── audio_output.c      # I2S output
│   ├── audio_output_spdif.c # S/PDIF output
│   ├── audio_output_usb.c  # USB audio output
│   ├── audio_crypto.c      # AirPlay encryption
│   ├── a2dp_sink.c         # Bluetooth A2DP sink
│   └── eq_events.c         # EQ parameter changes (TAS58xx)
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
├── buttons.c               # Hardware button input with debounce + auto-repeat
└── led.c                   # LED status indicator

components/
├── dac/                    # Abstract DAC API (Kconfig-selected implementation)
│   └── dac.c               # Dispatch layer → TAS57xx or TAS58xx driver
├── dac_tas57xx/            # TI TAS57xx (TAS5756/5754/5751) DAC driver with hybrid flow DSP
├── dac_tas58xx/            # TI TAS58xx (TAS5825M) DAC driver with on-chip DSP + 15-band EQ
├── display/                # Display drivers
│   ├── display.c           # Common display API
│   ├── display_st7789.c    # ST7789 TFT with LVGL 9 rendering (ESP32-S3)
│   └── display_stub.c      # No-op stub when display disabled
├── boards/                 # Board support (HAL)
│   ├── board_common.c      # Shared board utilities
│   ├── esp32-generic/      # ESP32 generic board init
│   ├── esp32s3-generic/    # ESP32-S3 generic board init
│   ├── waveshare-esp32p4/  # Waveshare ESP32-P4 board init
│   ├── squeezeamp/         # SqueezeAMP (ESP32 + TAS5756)
│   └── esparagus-audio-brick/ # Esparagus Audio Brick (ESP32 + TAS5825M + W5500)
├── spiffs_storage/         # SPIFFS filesystem mount (stores web pages + DSP configs)
├── audio-resampler/        # sinc-based audio resampler (44.1→48kHz)
└── board_utils/            # Board-level utilities
```

## Key Conventions

- **CMake/Kconfig**: Board selection is via `CONFIG_` Kconfig options. DAC driver is auto-selected (`CONFIG_DAC_TAS57XX` or `CONFIG_DAC_TAS58XX`). Display, buttons, BT, Ethernet are all Kconfig-gated.
- **Component structure**: Each component has its own `CMakeLists.txt` with `idf_component_register()`.
- **Git submodules**: `u8g2` (OLED graphics) and `u8g2-hal-esp-idf` (ESP-IDF HAL for u8g2) are submodules — always clone with `--recursive`.
- **SPIFFS**: `data/` directory contents are flashed to SPIFFS. `data/www/` = web UI, `data/hf/` = hybrid flow DSP binaries for TAS57xx.
- **Audio pipeline**: AudioReceiver (rtsp) → decoder → AudioBuffer → AudioOutput (I2S/SPDIF/USB). Buffered streams (AAC) use deep jitter buffer; realtime streams (ALAC) use low-latency UDP with early/late timing thresholds.
- **AirPlay/Bluetooth coexistence**: Mutually exclusive at runtime. BT connection suspends AirPlay; disconnect resumes it.
- **Eth/WiFi failover**: Ethernet preferred at boot; WiFi fallback if no cable. Hot-swap at runtime.

## Code Quality

**Requirements**: ESP-IDF >= 5.5 (tested against v5.5.2). Older versions may need workarounds.

**Formatting**: LLVM-style, 2-space indent, 80-char column limit. See `.clang-format`.

**Linting**: clang-tidy with bugprone, performance, portability, and readability checks. See `.clang-tidy`.

**Pre-commit hook**: auto-formats staged C/H files with clang-format, runs clang-tidy (requires `build/compile_commands.json`). Install via `git config core.hooksPath .githooks`.

**CI** (`.github/workflows/ci-release.yml`): On push/PR to `main`:
- `format-check`: clang-format dry-run on all C/H files (excludes `components/u8g2`)
- `lint-check`: clang-tidy on build output (requires ESP-IDF v5.5 toolchain)
- `build`: compiles 4 target configs (esp32s3, squeezeamp-bt, squeezeamp-4m, esparagus-audio-brick-bt)
- `release`: auto-creates GitHub release with merged firmware bins (only on push)

**Local tooling** (in `scripts/`):
```bash
scripts/format.sh          # Format all C/H files (excludes u8g2 submodule)
scripts/lint.sh            # Run clang-tidy on all C/H files
scripts/lint.sh --fix      # Attempt to auto-fix clang-tidy issues
```

**No unit tests**: This is embedded firmware — no test framework is in place. Manual testing on hardware is required.

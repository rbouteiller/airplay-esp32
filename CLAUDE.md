# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ESP32 AirPlay 2 Receiver — firmware that turns ESP32/ESP32-S2/ESP32-S3/ESP32-C5/ESP32-P4 boards into AirPlay 2 speakers. Supports ALAC and AAC decoding, Bluetooth A2DP (ESP32 only), USB Audio Class in both directions, S/PDIF, W5500 Ethernet (Esparagus Audio Brick), OLED/TFT displays, hardware buttons, and OTA updates. The documentation site also lives in this repo, under `docs/`.

**Every supported board must have PSRAM.** A module without it will not run this firmware — the jitter buffer, the AAC decoder's scratch and the timeline all live in external RAM.

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
| `esp32c5-xiao` | Seeed XIAO ESP32-C5 | The ESP-IDF native flow works too |
| `esp32wrover-dev` | Freenove ESP32-WROVER devkit | 4MB, Bluetooth |
| `waveshare-esp32s3` | Waveshare ESP32-S3 audio board | 16MB |
| `squeezeamp` | ESP32 + TAS5756 DAC/amp | 8MB flash |
| `squeezeamp-bt` | Same + Bluetooth A2DP | |
| `squeezeamp-4m` | SqueezeAMP with 4MB flash | |
| `smartamp` | ESP32 + Bluetooth | 4MB |
| `hifi-esp32` | ESP32 + PCM5100 DAC | Plain I2S DAC, no I2C/mute pin; Ethernet + OLED |
| `hifi-esp32-bt` | Same + Bluetooth | |
| `hifi-esparagus` | ESP32 + PCM5100 DAC | Plain I2S DAC, no I2C/mute pin, no Ethernet/display |
| `hifi-esparagus-bt` | Same + Bluetooth | |
| `hifi-esp32-s3` | ESP32-S3 + PCM5100 DAC | Ethernet + OLED |
| `hifi-esparagus-s3` | ESP32-S3 + PCM5100 DAC | OLED only, no Ethernet |
| `loud-esp32` | ESP32 + MAX98357A I2S amp | No I2C; enable pin gated by playback play/pause, not just boot-released |
| `loud-esp32-bt` | Same + Bluetooth | |
| `loud-esp32-s3` | ESP32-S3 + dual MAX98357A | |
| `loud-esparagus` | ESP32 + dual MAX98357A | No Ethernet/display |
| `loud-esparagus-bt` | Same + Bluetooth | |
| `esparagus-echo` | ESP32-S3 + dual MAX98357A | Ethernet, no display |
| `amped-esp32` | ESP32 + PCM5100 DAC + TPA3110/TPA3128 amp | No I2C; UNMUTE pin gated by playback play/pause |
| `amped-esp32-bt` | Same + Bluetooth | |
| `amped-esp32-s3` | ESP32-S3 + PCM5100 + TPA3110/TPA3128 | |
| `amped-esparagus` | ESP32 + PCM5100 + TPA3110/TPA3128 | Rev M only; rotary encoder (volume + play/pause); no display — hardware TFT (ILI9342) isn't a supported driver |
| `amped-esparagus-bt` | Same + Bluetooth | |
| `esparagus-audio-brick` | ESP32 + TAS5825M/TAS5805M DAC/amp | Ethernet is on in every brick build |
| `esparagus-audio-brick-bt` | Same + Bluetooth | |
| `esparagus-audio-brick-s3` | ESP32-S3 + TAS5825M/TAS5805M | Different pinout from the ESP32 revision |
| `esparagus-audio-brick-dual-dac` | ESP32-S3 + 2x TAS58xx ("Audio Brick Dual", rev D hardware) | Stereo @0x4C + PBTL mono sub @0x4D |
| `esparagus-audio-brick-dual-uac` | Same + USB speaker | |
| `louder-esp32-plus` | ESP32 + TAS5825M DAC/amp | |
| `louder-esp32-plus-bt` | Same + Bluetooth | |
| `louder-esp32-s3-plus` | ESP32-S3 + TAS5825M | |
| `esparagus-louder` | ESP32 + TAS5825M/TAS5805M | |
| `esparagus-louder-bt` | Louder + Bluetooth | |
| `esparagus-louder-s3` | ESP32-S3 + Louder | |
| `louder-esp32` | ESP32 + TAS5805M DAC/amp | |
| `louder-esp32-bt` | Same + Bluetooth | |
| `louder-esp32-s3` | ESP32-S3 + TAS5805M | |

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
├── sendspin/               # Sendspin player role (Kconfig-gated, experimental)
│   ├── sendspin.c          # WebSocket endpoint, protocol state machine, mDNS
│   ├── sendspin_time.c     # Server clock estimator (offset + skew least-squares fit)
│   └── sendspin_player.c   # Re-blocks chunks into its own audio_engine_v2 timeline
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
├── playback_events.c       # Per-source playback state, fanned out as an aggregate
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
│   ├── hifi-esp32/         # HiFi-ESP32(-S3) / HiFi-Esparagus(-S3) (PCM5100)
│   ├── loud-esp32/         # Loud-ESP32(-S3), Loud-Esparagus, Esparagus-Echo, Amped-ESP32(-S3), Amped-Esparagus (RTSP-gated amp enable pin)
│   └── esparagus-audio-brick/ # Esparagus Audio Brick (ESP32/S3 + TAS58xx + W5500)
├── spiffs_storage/         # SPIFFS filesystem mount (stores web pages + DSP configs)
├── audio-resampler/        # sinc-based audio resampler (44.1→48kHz)
└── board_utils/            # Board-level utilities
```

## Key Conventions

- **PSRAM is not optional**: `CONFIG_SPIRAM=y` is set once, in the base `config/sdkconfig.defaults`, and no board layer turns it off — the board files only pick the mode and speed (`CONFIG_SPIRAM_MODE_OCT` on the S3/P4, the 80 MHz quad default elsewhere). The `# CONFIG_SPIRAM=y` line in `config/sdkconfig.defaults.esp32s2` is a *comment* and overrides nothing, so the S2 gets PSRAM like everything else. A Kconfig `depends on SPIRAM` is therefore always satisfied and is not a real gate.
- **CMake/Kconfig**: Board selection is via `CONFIG_` Kconfig options. DAC driver is auto-selected (`CONFIG_DAC_TAS57XX` or `CONFIG_DAC_TAS58XX`). Display, buttons, BT, Ethernet are all Kconfig-gated.
- **A board without an I2C DAC can still register one.** `dac_ops_t` (`components/dac/include/dac.h`) doesn't require I2C — `loud-esp32/board.c` registers a driver whose `set_power_mode` just drives `CONFIG_DAC_ENABLE_GPIO` (the amp's single active-high enable/unmute pin — SD_MODE on the MAX98357A boards, UNMUTE on the PCM5100+TPA3110/TPA3128 Amped boards) from aggregate `playback_events` play/pause/disconnect, the same events Esparagus Audio Brick uses to drive TAS58xx over I2C. This is a different pin from `CONFIG_DAC_PDN_GPIO`, which boards with an I2C DAC drive high once at boot and never touch again — `DAC_ENABLE_GPIO` is toggled on every playback state change because it's the *only* control surface the amp has.
- **Component structure**: Each component has its own `CMakeLists.txt` with `idf_component_register()`.
- **Git submodules**: `u8g2` (OLED graphics) and `u8g2-hal-esp-idf` (ESP-IDF HAL for u8g2) are submodules — always clone with `--recursive`.
- **SPIFFS**: `data/` directory contents are flashed to SPIFFS. `data/www/` = web UI, `data/hf/` = DSP binaries. Only the four `base-hf<n>-<rate>.bin` hybrid-flow bases are tracked; tuned PPC3 dumps are user-supplied and deliberately untracked.
- **Audio pipeline**: receiver → decode worker → **RTP-addressed timeline** → scheduler → AudioOutput (I2S/SPDIF/USB). Both the buffered (AAC) and realtime (ALAC) paths now run through engine v2; the old sorted PCM pool is gone. The scheduler anchors on the sender's clock (PTP for AirPlay 2, NTP for AirPlay 1), prerolls, then closes a drift servo against the DMA play position.
- **AirPlay/Bluetooth coexistence**: Mutually exclusive at runtime. BT connection suspends AirPlay; disconnect resumes it. `bt_coex.c` releases the BT stack's DRAM once AirPlay owns the output.
- **Output source indirection**: the playback task in every backend pulls through `audio_output_read_source()` (`audio_output_common.c`), which defaults to `audio_receiver_read` until something calls `audio_output_set_source()`. That is how Sendspin renders from its own engine without touching the AirPlay path. `audio_output_stop()` has a weak no-op default there too — only the I2S backend has a real stop, because only it has a DMA channel to hand over.
- **Sendspin**: `CONFIG_SENDSPIN_ENABLE` defaults **on** wherever there is PSRAM, but compiling it in is not the same as running it — `settings_sendspin_enabled()` gates `sendspin_init()`, defaults to off, and only takes effect on a restart, so a board pays none of the ~448 KB until someone turns it on from the web UI (`/api/sendspin/mode`). The symbol survives only as a flash escape hatch: `smartamp` and `esp32wrover-dev` set it `=n` because Bluetooth plus a 1.92 MB app slot leaves 4–5 % free before Sendspin and ~1 % after. It puts a `/sendspin` WebSocket on the existing web server and advertises `_sendspin._tcp` on port 80. **PCM and FLAC everywhere; Opus on the S3/P4 only** (`CONFIG_SENDSPIN_OPUS`) — on the original ESP32 the decoder's state lands in PSRAM and a 20 ms packet takes ~7.7 ms to decode, which starves the httpd task that decodes it. Opus also needs a far deeper timeline (1024 blocks, 2 MB) because the server meters its queue in *bytes*, so the same budget buys ~10x the duration and anything past the window is rejected and later concealed. Pairing (static PIN via CPace, and the pairing PSK) and in-band re-handshaking are in place, so a session can be authenticated rather than merely encrypted; until a server pairs, the Sentinel PSK keeps it unpaired. It owns a *separate* `audio_engine_v2_t` from `audio_receiver.c`, because the receiver's is deliberately never torn down. Chunks must be re-cut into fixed 512-frame blocks: `audio_engine_v2_push_pcm()` rejects more than `frame_samples`, and `audio_timeline_phase_blocked()` requires block-aligned RTP. **AirPlay outranks it.** `audio_receiver_set_format()`/`audio_receiver_end_session()` drive an edge-triggered activity callback into `main.c`, which calls `sendspin_set_output_available()`; those two are the claim/release pair because both are immediate, whereas `PLAYBACK_EVENT_DISCONNECTED` can sit behind the RTSP DACP grace period for minutes. The release is deliberately *not* on `audio_receiver_stop()`, which also runs for a stream-level TEARDOWN — and that is a pause, so releasing there would have Music Assistant playing out loud the moment the phone pauses. Two more things suppress the release: an RTSP connection being *replaced* (`slot->is_old`) never releases, because `is_old` is set before the replacement is accepted and its SETUP already owns the claim; and `on_airplay_audio_active(false)` bails out while Bluetooth or the USB sink is streaming, since it is their `stop_airplay_services()` that ended the AirPlay session in the first place. The AirPlay services now stay up while Sendspin streams, so only the playback task changes hands. Reporting `available:false` on its own leaves the server's queue *stopped*, and a stopped queue never restarts itself — so the takeover also sends a `client/command` `pause` through the controller role and the release sends a `play`, queued rather than sent inline so the tick reports the state first. A gap in delivery is **not** a reason to re-anchor: the anchor still maps server time onto RTP, so `sendspin_player_skip_to()` moves the write position and the timeline conceals the hole. Only a rewind rebuilds the map, because only then has RTP stopped being a continuous function of server time.
- **Sendspin has no cleartext mode.** Only `client/init`, `server/init` and `noise/handshake` travel in the open, as WebSocket *text* frames; everything after the split is a Noise transport message in a *binary* frame whose first decrypted byte is the Sendspin message type. `sendspin_noise.c` implements `Noise_KKpsk2_25519_ChaChaPoly_SHA256` on libsodium primitives — the server is the initiator, the board the responder. The prologue is the **raw wire bytes** of the two init messages, never a re-encoding. Without pairing the PSK is the spec's published **Sentinel** value, so a session is encrypted but not authenticated; `unpaired_access.enabled` is what tells the server we will accept that. Two easy-to-miss details: in a PSK-modified pattern every `e` token does `MixHash` **then** `MixKey`, and `MixKey`/`MixKeyAndHash` reset the nonce counter to 0. Nothing at all may leave the client between `client/init` and the first `server/activate`, not even a `client/time`.
- **USB audio, two directions**: `defaults.usb` (`CONFIG_AUDIO_OUTPUT_USB`) makes the board a USB *source* — it appears as a microphone and AirPlay audio leaves over USB. `defaults.uac` (`CONFIG_USB_AUDIO_SINK`) makes it a USB *speaker* — the host plays into the same I2S DAC, which stops the AirPlay services while it streams. The UAC descriptor advertises a single rate, so `CONFIG_UAC_SAMPLE_RATE` must equal `CONFIG_OUTPUT_SAMPLE_RATE_HZ`.
- **Eth/WiFi failover**: Ethernet preferred at boot; WiFi fallback if no cable. Hot-swap at runtime.
- **Task stacks stay in internal RAM** (`main/spiram_task.h`): flash operations disable the cache, so a stack in SPIRAM trips `esp_task_stack_is_sane_cache_disabled()`. Large *local* buffers are the opposite problem — `CONFIG_ESP_MAIN_TASK_STACK_SIZE` is only 3584 bytes, so anything of that order belongs in a `heap_caps_calloc(..., MALLOC_CAP_SPIRAM)` allocation. Overflowing it corrupts whatever was allocated next, which shows up as unrelated driver failures.

## TAS58xx notes

- **Two parts, one driver.** The model is guessed from the I2C address (0x4C–0x4F → TAS5825M, 0x2C–0x2F → TAS5805M), then confirmed against the die ID in register 0x67; a disagreement is logged as a warning.
- **A TAS5805M has no process flow.** PPC3 dumps are skipped for it (`tas58xx_load_hf()` returns early unless the model is a TAS5825M) and the input mixer refuses anything but stereo. Volume, mute and the 15 biquads per channel work on both parts, so the `/bq` web UI is the tuning route for a 5805M.
- **PPC3 dump filenames**, searched most specific first: `tas5825m_fw<i>-<rate>.bin` → `tas5825m_fw-<rate>.bin` → `tas5825m_fw<i>.bin` → `tas5825m_fw.bin`. The unindexed names only stand in for device 0. `components/dac_tas58xx/ppc3_convert.py` produces them from a PPC3 export.
- **Fault handling.** A clock fault is expected when the I2S clock stops at the end of a track, so it is logged and cleared rather than muting the amplifier; channel and global2 faults still mute. Rev D has no fault line at all and is polled instead.

## Code Quality

**Requirements**: ESP-IDF >= 5.5.5. Sendspin needs `ws_post_handshake_cb`, which only landed in v5.5.5 — on an older 5.5.x the build dies in `sendspin_register()` unless `CONFIG_SENDSPIN_ENABLE=n`. The CI workflows pin the same version. **PlatformIO gets 5.5.5 from the pioarduino platform pinned in `[env]`**, not from `platformio/espressif32`, which is stuck on 5.5.3 — and pinning only `framework-espidf` is not enough, because 5.5.5's `tool_version_check.cmake` rejects every toolchain but `esp-14.2.0_20260121`. The platform has to move as a unit.

**Formatting**: LLVM-style, 2-space indent, 80-char column limit. See `.clang-format`.

**Linting**: clang-tidy with bugprone, performance, portability, and readability checks. See `.clang-tidy`.

**Pre-commit hook**: auto-formats staged C/H files with clang-format, runs clang-tidy (requires `build/compile_commands.json`). Install via `git config core.hooksPath .githooks`.

**CI** (`.github/workflows/`), five workflows:
- `ci.yml` — on push to `main`, and on every PR to `main` or `staging`. A `changes` job skips the firmware jobs for a Markdown-only PR; `format-check` (clang-format), `lint-check` (clang-tidy against an esp32s3 build), `output-backends` (links the spdif and usb backends, which the release matrix never covers) and `build` follow. **`ci-gate` is the one required check** — it runs unconditionally and treats skipped as fine, so branch protection does not have to list every matrix job.
- `build.yml` — reusable, and the entry point for the release matrix. The matrix itself is `.github/workflows/targets.json`, because a matrix has to be JSON before `fromJSON` can filter it. Every entry there gets a published `airplay2-receiver-<name>.bin` and needs a matching `docs/firmware/<name>.json`. Entries flagged `"core": true` are the subset a **pull request** builds — one per chip and per `components/boards/` directory; a push to `main`, a push to `staging` and a tag build the lot. `fail-fast: false`, so a broken board no longer cancels the rest. Targets: esp32s3, waveshare-esp32s3, esp32s2, squeezeamp-bt, squeezeamp-4m, smartamp, the esparagus ones (audio-brick-bt, -s3, -dual-dac, -dual-uac, louder-bt, louder-s3, echo) and the Sonocotta dock boards (hifi-, loud-, amped-, louder- variants). **An ESP32 board's published binary is always the Bluetooth one** — the non-BT envs still exist, they just are not released.
- `release.yml` — on a `v*` tag. Refuses to release unless the tag matches `version.txt` and points at a commit on `main`, then publishes the merged binaries.
- `beta.yml` — on push to `staging`. Same matrix, published to a rolling `beta` pre-release that is deleted and recreated each time so the tag follows the staging tip. Because the matrix does not fail fast, `publish` runs on `always()` and ships whatever built, warning about each missing target; it only errors when nothing built at all. Fails if `version.txt` on staging is not strictly greater than the latest release, so **bump `version.txt` on staging right after a release**.
- `docs.yml` — `zensical build --strict --clean`, bundles the latest release binaries into `site/firmware/` and the beta ones into `site/firmware/beta/` for the browser installer, and deploys to Pages. **`docs-build` is a required check**, so its `pull_request` trigger is deliberately unfiltered.

A release created with `GITHUB_TOKEN` does not fire the `release` event, so `release.yml` and `beta.yml` both `gh workflow run docs.yml` explicitly. `workflow_dispatch` is one of only two events that escape the recursion guard.

The `pull_request` triggers in `ci.yml` and `docs.yml` are unfiltered on purpose: a required check whose workflow never fires sits "Expected" forever and blocks the merge. Both list `staging` as well as `main`, because **PRs are raised against `staging`** — a branch filter of just `main` means a PR to `staging` gets no checks at all.

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
5. For a board that should ship prebuilt firmware: an entry in `.github/workflows/targets.json` **and** a matching `docs/firmware/<name>.json` ESP Web Tools manifest, whose `parts[0].path` must equal `airplay2-receiver-<name>.bin`. Set `"core": true` only if the board brings new board-support code or a new chip — that flag is what a pull request builds. The docs workflow drops any manifest whose binary is missing from the release.
6. An install card (stable + beta buttons) in `docs/getting-started/flashing.md`.

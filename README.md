<div align="center">

# ESP32 AirPlay 2 Receiver

[![GitHub stars](https://img.shields.io/github/stars/rbouteiller/airplay-esp32?style=flat-square)](https://github.com/rbouteiller/airplay-esp32/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/rbouteiller/airplay-esp32?style=flat-square)](https://github.com/rbouteiller/airplay-esp32/network)
[![License](https://img.shields.io/badge/license-Non--Commercial-blue?style=flat-square)](LICENSE)
[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-v5.x-red?style=flat-square)](https://docs.espressif.com/projects/esp-idf/)
[![Platform](https://img.shields.io/badge/platform-ESP32--S3-green?style=flat-square)](https://www.espressif.com/en/products/socs/esp32-s3)

**Stream music from your Apple devices to any speaker for 10$**

[Quick Start](#quick-start) • [Hardware](#hardware) • [Configuration](#configuration) • [How It Works](#how-it-works)

</div>

---

## What is this?

This project transforms an ESP32-S3 into a standalone AirPlay 2 audio receiver. Connect it to any amplifier or powered speakers via a simple I2S DAC, and you've got a wireless audio endpoint that appears natively in iOS and macOS.

**No cloud. No app. Just tap and play.**

### Capabilities

- **AirPlay 2 protocol** — appears as a native speaker in Control Center
- **ALAC & AAC decoding** — handles both realtime and buffered audio streams
- **Multi-room support** — PTP-based timing for synchronized playback
- **Web configuration** — set up WiFi and device name from your browser
- **OTA updates** — update firmware without cables

### Limitations

- Audio only (no AirPlay video or photos)
- Single device per ESP32 (no multi-instance, new device will replace the old one)
- Requires decent WiFi signal for stable streaming

---

## Quick Start

### What You Need

| Component                         | Comment                                        |
| --------------------------------- | ---------------------------------------------- |
| **ESP32-S3** (N16R8 recommended)  | 8Mb PSRAM is mandatory                         |
| **PCM5102A DAC**                  | Can't drive passive speakers (like headphones) |
| **Amplifier or powered speakers** |                                                |

### Wiring

```
ESP32-S3          PCM5102A
────────          ────────
3V3  ──────────►  VCC
GND  ──────────►  GND
GPIO5 ─────────►  BCK  (bit clock)
GPIO6 ─────────►  LCK  (left/right clock)
GPIO7 ─────────►  DIN  (data)
```

### Flash & Configure

```bash
# Clone and build
git clone https://github.com/rbouteiller/airplay-esp32
cd airplay-esp32
idf.py set-target esp32s3
idf.py build
idf.py -p /dev/ttyUSB0 flash
```

**First boot:**
1. Connect to WiFi network `ESP32-AirPlay-Setup`
2. Open `http://192.168.4.1` in your browser
3. Select your WiFi network and set a device name
4. The device restarts and appears in AirPlay

---

## Hardware

### Tested Configuration

- **MCU:** ESP32-S3-WROOM-1 N16R8 (16MB flash, 8MB PSRAM)
- **DAC:** PCM5102A breakout board
- **Power:** USB-C or 5V regulated supply

### Signal Flow

```
┌─────────────────┐      WiFi       ┌─────────────┐
│  iPhone / Mac   │ ─────────────►  │   ESP32-S3  │
│    (AirPlay)    │                 │             │
└─────────────────┘                 └──────┬──────┘
                                           │ I2S
                                    ┌──────▼──────┐
                                    │  PCM5102A   │
                                    │    DAC      │
                                    └──────┬──────┘
                                           │ Analog
                                    ┌──────▼──────┐
                                    │  Amplifier  │
                                    │  + Speakers │
                                    └─────────────┘
```

### I2S Signals

| Signal | Function                              |
| ------ | ------------------------------------- |
| BCK    | Bit clock — 44100 × 16 × 2 = 1.41 MHz |
| LCK    | Word select — toggles at 44.1 kHz     |
| DIN    | Serial audio data (16-bit stereo)     |

MCLK is not used; the PCM5102A generates it internally.

---

## Configuration

On first boot (or when WiFi credentials are missing), the device creates an open access point:

| Setting | Value                 |
| ------- | --------------------- |
| Network | `ESP32-AirPlay-Setup` |
| IP      | `192.168.4.1`         |

### Web Interface

Navigate to `http://192.168.4.1` to:

- **Scan and connect** to your WiFi network
- **Set the device name** (appears in AirPlay menu)
- **Upload firmware** for OTA updates
- **Restart** the device

Settings persist in flash storage (NVS).

Once connected to WiFi, the access point is disabled. If connection fails after multiple retries, AP mode is re-enabled for reconfiguration.

---

## How It Works

### Protocol Stack

```
┌────────────────────────────────────────────────┐
│              AirPlay 2 Source                  │
│         (iPhone, iPad, Mac, Apple TV)          │
└───────────────────────┬────────────────────────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
    ┌──────────┐  ┌──────────┐  ┌──────────┐
    │   mDNS   │  │   RTSP   │  │   PTP    │
    │ Discovery│  │ Control  │  │  Timing  │
    └──────────┘  └──────────┘  └──────────┘
          │             │             │
          └─────────────┼─────────────┘
                        ▼
              ┌──────────────────┐
              │   HAP Pairing    │
              │  (Transient)     │
              └──────────────────┘
                        │
                  ┌───────────┐
                  ▼           ▼ 
            ┌──────────┐ ┌──────────┐
            │   ALAC   │ │   AAC    │
            └──────────┘ └──────────┘
                  │           │
                  └─────┬─────┘
                        ▼
              ┌──────────────────┐
              │   Audio Buffer   │
              │  + Timing Sync   │
              └──────────────────┘
                        │
                        ▼
              ┌──────────────────┐
              │    I2S Output    │
              │   (44.1kHz/16b)  │
              └──────────────────┘
```

### Key Components

| Module             | Location        | Purpose                          |
| ------------------ | --------------- | -------------------------------- |
| **RTSP Server**    | `main/rtsp/`    | Handles AirPlay control messages |
| **HAP Pairing**    | `main/hap/`     | Cryptographic device pairing     |
| **Audio Pipeline** | `main/audio/`   | Decoding, buffering, timing      |
| **PTP Clock**      | `main/network/` | Synchronization with source      |
| **Web Server**     | `main/network/` | Configuration interface          |

### Audio Formats

| Format          | Use Case             |
| --------------- | -------------------- |
| ALAC (realtime) | Live streaming, Siri |
| AAC (buffered)  | Music playback       |

---

## Building

### Prerequisites

- [ESP-IDF v5.x](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/)
- USB cable for initial flash

### Commands

```bash
# Setup
source /path/to/esp-idf/export.sh
git submodule update --init --recursive

# Build
idf.py set-target esp32s3
idf.py build

# Flash
idf.py -p /dev/ttyUSB0 flash monitor
```

### [PlatformIO](https://platformio.org/install/cli)

```bash
# Install PlatformIO CLI (if not already installed)
pip install platformio

# Build and flash
pio run -e esp32s3 -t upload

# Monitor serial output
pio run -e esp32s3 -t monitor

# Or both at once
pio run -e esp32s3 -t upload -t monitor
```

---

## Project Structure

```
main/
├── audio/          # Decoders, buffers, timing sync
├── rtsp/           # RTSP server and handlers
├── hap/            # HomeKit pairing (SRP, Ed25519)
├── plist/          # Binary plist parsing
├── network/        # WiFi, mDNS, PTP, web server
├── main.c          # Entry point
└── settings.c      # NVS persistence
```

---

## Acknowledgements

This project builds on the work of many others:

- **[Shairport Sync](https://github.com/mikebrady/shairport-sync)** — The reference AirPlay implementation. Much of the protocol understanding comes from studying this project.
- **[openairplay/airplay2-receiver](https://github.com/openairplay/airplay2-receiver)** — Python implementation that helped decode AirPlay 2 specifics.
- **[Espressif](https://github.com/espressif)** — ESP-IDF framework and audio codec libraries.

---

## Legal

### License

This project is licensed for **non-commercial use only**. Commercial use requires explicit permission. See [LICENSE](LICENSE).

### Disclaimer

This is an independent project based on protocol analysis. It is:

- **Not affiliated with Apple Inc.**
- **Not guaranteed to work** with future iOS/macOS versions
- **Provided as-is** without warranty

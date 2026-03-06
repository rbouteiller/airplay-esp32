<div align="center">
<img src="docs/logo_airplay_esp32.png" alt="AirPlay ESP32" width="200">

# ESP32 AirPlay 2 Receiver

[![GitHub stars](https://img.shields.io/github/stars/rbouteiller/airplay-esp32?style=flat-square)](https://github.com/rbouteiller/airplay-esp32/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/rbouteiller/airplay-esp32?style=flat-square)](https://github.com/rbouteiller/airplay-esp32/network)
[![License](https://img.shields.io/badge/license-Non--Commercial-blue?style=flat-square)](LICENSE)
[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-v5.x-red?style=flat-square)](https://docs.espressif.com/projects/esp-idf/)
[![Platform](https://img.shields.io/badge/platform-ESP32--S3-green?style=flat-square)](https://www.espressif.com/en/products/socs/esp32-s3)
[![Platform](https://img.shields.io/badge/platform-ESP32-green?style=flat-square)](https://www.espressif.com/en/products/socs/esp32)
[![Platform](https://img.shields.io/badge/platform-SqueezeAMP-green?style=flat-square)](https://github.com/philippe44/SqueezeAMP)

**Stream music from your Apple devices — or phone via Bluetooth — to any speaker for ~10$**

</div>

---

## What is this?

This turns a cheap ESP32-S3 board into a wireless AirPlay 2 speaker. Plug it into any amplifier or powered speakers, and it shows up on your iPhone/iPad/Mac just like a HomePod or AirPlay TV. Also supports the **[SqueezeAMP](https://github.com/philippe44/SqueezeAMP)** (ESP32 + TAS5756 DAC) and **[Esparagus Audio Brick](https://esparagus.com/)** (ESP32 + TAS5825M DAC/amp) boards with built-in amplifiers.

ESP32 boards (SqueezeAMP, Esparagus Audio Brick) also support **Bluetooth A2DP** — stream from any phone or tablet over Bluetooth when AirPlay isn't in use. The Esparagus Audio Brick additionally supports **wired Ethernet** via an optional W5500 SPI module.

**No cloud. No app. Just tap and play.**

---

## Shopping List

You only need 2 boards and a few wires. Everything is available on AliExpress / Amazon for under 10$.

| Component                | What to search for                                                      | Price |
| ------------------------ | ----------------------------------------------------------------------- | ----- |
| **ESP32-S3 dev board**   | "ESP32-S3 N16R8" (must have **8MB PSRAM**)                              | ~5$   |
| **PCM5102A DAC board**   | "PCM5102A I2S DAC" (the small purple board with 3.5mm jack)             | ~3$   |
| **Female 2.54mm header** | "Female pin header 2.54mm single row" (1x6 or longer, then cut to size) | ~0.5$ |

> **Important:** The ESP32-S3 must have **8MB PSRAM** (the N16R8 variant). Boards without enough PSRAM will not work — the audio decoding needs the extra memory.

> **Alternative:** If you have a **[SqueezeAMP](https://github.com/philippe44/SqueezeAMP)** or **[Esparagus Audio Brick](https://esparagus.com/)** board, you don't need a separate DAC — just flash the appropriate firmware target. See the [SqueezeAMP](#squeezeamp) and [Esparagus Audio Brick](#esparagus-audio-brick) sections below.

Here is what the PCM5102A board looks like:
Verify the solder bridges are in the same position as the picture.

<div align="center">
<img src="docs/PCM5102A.png" alt="PCM5102A DAC board" width="500">
</div>

---

## Assembly (No Soldering Skills Needed)

The PCM5102A plugs directly onto the ESP32 pins using a female header — no breadboard, no jumper wires.

### Step 1 — Prepare the ESP32

The pins on **one side** of the ESP32 need to be removed (or not soldered on) so the assembly fits inside the 3D-printed case. Only the side with GPIO11–GPIO14 needs pins.

If your board came with pins on both sides already soldered, you can carefully desolder or clip the pins on the opposite side.

### Step 2 — Plug the DAC onto the ESP32

Take a **female 2.54mm pin header** (6 pins) and plug it onto the ESP32 pins on the side with GPIO11–14. Then insert the PCM5102A board into the female header from the other side.

The connections through the header are:

```
ESP32-S3 pin     →  PCM5102A pin    What it does
─────────────────────────────────────────────────
5V               →  VIN             Power for the DAC
GPIO11           →  BCK             Bit clock (audio timing)
GPIO12           →  DIN             Audio data
GPIO13           →  LCK             Left/right channel select
GPIO14           →  GND             Software ground (pulled low by code)
Or GND           →  GND             Ground (GPIO14 software ground is sufficient)
```

### _⚠️ **Important:** On the ESP32S3 board, bridge the VIN/VOUT solder pads if they are not already connected. This lets the board use 5V power directly._

### Step 3 — Check the result

Your assembly should look like this:

<div align="center">

|                              Front                              |                             Back                              |                              Side                               |
| :-------------------------------------------------------------: | :-----------------------------------------------------------: | :-------------------------------------------------------------: |
| <img src="docs/ESP_PCM_front.png" alt="Front view" width="200"> | <img src="docs/ESP_PCM_back.png" alt="Back view" width="200"> | <img src="docs/ESP32_PCM_side.png" alt="Side view" width="150"> |

</div>

The PCM5102A sits on top of the ESP32 and the 3.5mm audio jack sticks out the end. Plug a USB-C cable into the ESP32 for power.

### Step 4 — (Optional) Print the case

A 3D-printable case is provided in [`docs/boite esp32.stl`](docs/boite%20esp32.stl). Print it with standard PLA settings. The case is designed for the assembly with pins on one side only.

---

## Flash the Firmware

Three options: **Web flasher** (no install needed), **PlatformIO**, or **ESP-IDF**.

### Option A — Web Flasher (Recommended for beginners)

Flash a pre-built firmware directly from your browser — no toolchain, no code, no command line.

1. Download the latest firmware from the [Releases page](https://github.com/rbouteiller/airplay-esp32/releases/latest):
   - **`airplay2-receiver-esp32s3.bin`** — for generic ESP32-S3 + PCM5102A
   - **`airplay2-receiver-squeezeamp.bin`** — for SqueezeAMP boards
   - **`airplay2-receiver-squeezeamp-bt.bin`** — for SqueezeAMP enabling Bluetooth
   - **`airplay2-receiver-squeezeamp-4m.bin`** — for SqueezeAMP with 4MB flash
   - **`airplay2-receiver-esparagus-audio-brick.bin`** — for Esparagus Audio Brick
   - **`airplay2-receiver-esparagus-audio-brick-bt.bin`** — for Esparagus Audio Brick enabling Bluetooth
2. Open the [ESP Web Flasher](https://espressif.github.io/esptool-js/) (requires Chrome or Edge)
3. Plug your ESP32 via USB-C, click **Connect** and select the serial port
4. Set the flash address to **`0x0`**, select the downloaded `.bin` file, and click **Program**
5. Once done, unplug and re-plug the board — it will boot into setup mode

> **Note:** The web flasher uses WebSerial, which is only supported in Chromium-based browsers (Chrome, Edge, Opera).

### Option B — PlatformIO

[PlatformIO](https://platformio.org/) handles all the toolchain setup for you.

```bash
# 1. Install PlatformIO CLI
pip install platformio

# 2. Clone this project (with submodules)
git clone --recursive https://github.com/rbouteiller/airplay-esp32
cd airplay-esp32

# 3. Plug in your ESP32 via USB-C and flash
pio run -e esp32s3 -t upload

# 4. (Optional) Watch serial output for debugging
pio run -e esp32s3 -t monitor
```

### Option C — ESP-IDF

```bash
# 1. Install ESP-IDF v5.x following:
#    https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/

# 2. Clone and enter the project (with submodules)
git clone --recursive https://github.com/rbouteiller/airplay-esp32
cd airplay-esp32

# 3. Activate ESP-IDF environment
source /path/to/esp-idf/export.sh

# 4. Build and flash
idf.py set-target esp32s3
idf.py build
idf.py -p /dev/ttyUSB0 flash

# 5. (Optional) Monitor serial output
idf.py -p /dev/ttyUSB0 monitor
```

---

## Setup (First Boot)

1. **Power up** the ESP32 via USB-C
2. On your phone or laptop, connect to the WiFi network **`ESP32-AirPlay-Setup`**
3. A captive portal will open. (IP: 192.168.4.1)
4. Set a name for your speaker (e.g. "Kitchen Speaker")
5. Select your home WiFi network and set a password
6. The device restarts and connects to your WiFi
7. Open any music app, tap the AirPlay icon, and select your speaker

That's it! Settings are saved and persist across reboots.

> **If WiFi connection fails** after several retries, the ESP32 automatically goes back into setup mode so you can reconfigure it.

---

## Updating the Firmware (OTA)

Once the device is connected to your WiFi, you can update the firmware wirelessly without unplugging anything:

1. Build the new firmware (`idf.py build` or `pio run`)
2. Open the device's web interface (find its IP in your router's connected devices list)
3. Use the firmware upload page to flash the new version

---

## SqueezeAMP

The **[SqueezeAMP](https://github.com/philippe44/SqueezeAMP)** is an ESP32-based board with a TAS5756 DAC and built-in Class-D amplifier. No external DAC needed — just connect speakers directly.

### Flashing

```bash
# PlatformIO
pio run -e squeezeamp -t upload

# ESP-IDF
idf.py set-target esp32
idf.py build
idf.py -p /dev/ttyUSB0 flash
```

The SqueezeAMP build selects the TAS57xx DAC driver automatically via Kconfig (`CONFIG_DAC_TAS57XX`) and configures the correct I2S/I2C pins. Buffer sizes are automatically reduced (2500 frames vs 5000) to fit the ESP32's more limited PSRAM access.

A 4MB flash variant is also supported (`squeezeamp-4m` PlatformIO environment).

### Bluetooth Build

To build with Bluetooth A2DP support:

```bash
# PlatformIO
pio run -e squeezeamp-bt -t upload
```

See the [Bluetooth A2DP](#bluetooth-a2dp) section for details.

---

## Esparagus Audio Brick

The **[Esparagus Audio Brick](https://github.com/sonocotta/esparagus-media-center/?tab=readme-ov-file#esparagus-audio-brick-prototype)** is an ESP32-based board with a **TI TAS5825M** Class-D DAC/amplifier. Like the SqueezeAMP, no external DAC is needed — connect speakers directly to the board.

### Features

- TAS5825M with on-chip DSP and 15-band parametric EQ (25 Hz – 16 kHz)
- Hardware volume control with configurable max level
- Speaker fault detection with automatic mute/recovery
- Automatic power state management (deep sleep / standby / play) based on AirPlay session state
- 8 MB flash
- Optional **Bluetooth A2DP** — receive audio from phones/tablets over Bluetooth
- **W5500 SPI Ethernet** — wired network connection with automatic WiFi failover

### Flashing

```bash
# PlatformIO (AirPlay only)
pio run -e esparagus-audio-brick -t upload

# PlatformIO (AirPlay + Bluetooth)
pio run -e esparagus-audio-brick-bt -t upload

# Monitor serial output
pio run -e esparagus-audio-brick -t monitor
```

### Default GPIO Assignments

| Function       | GPIO | Notes                              |
| -------------- | ---- | ---------------------------------- |
| I2S BCK        | 26   | Bit clock                          |
| I2S WS         | 25   | Word select (LRCLK)                |
| I2S DO         | 22   | Serial audio data                  |
| I2C SDA        | 21   | DAC control (TAS5825M)             |
| I2C SCL        | 27   | DAC control (TAS5825M)             |
| Jack detect    | 34   | Headphone jack insertion (input)   |
| DAC warning    | 36   | TAS5825M warning output (input)    |
| Speaker fault  | 39   | TAS5825M fault output (input)      |

> GPIOs 34–39 on ESP32 are input-only with no internal pull-up. The board provides external pull-ups on the fault and warning lines.

The build selects the TAS58xx DAC driver automatically (`CONFIG_DAC_TAS58XX`). The driver auto-detects the TAS5825M I2C address (0x4C–0x4F) at startup.

### Bluetooth Build

To build with Bluetooth A2DP support:

```bash
pio run -e esparagus-audio-brick-bt -t upload
```

See the [Bluetooth A2DP](#bluetooth-a2dp) section for details.

### Ethernet (W5500)

The Esparagus Audio Brick supports wired Ethernet via an external W5500 SPI module. This is enabled by default in the `esparagus-audio-brick-bt` build environment.

See the [Ethernet (W5500)](#ethernet-w5500) section for details.

---

## Bluetooth A2DP

ESP32-based boards (SqueezeAMP, Esparagus Audio Brick) can also receive audio over **Bluetooth Classic A2DP**. This lets any phone, tablet, or laptop stream music via Bluetooth — no Apple device required.

Bluedroid Bluetooth stack is used for A2DP support. The device appears as a standard Bluetooth speaker with AVRCP metadata and volume control. It is very tight on RAM and flash.

### How It Works

- AirPlay and Bluetooth coexist but are **mutually exclusive at runtime**
- When a BT device connects, AirPlay is automatically suspended
- When the BT device disconnects, AirPlay resumes
- BT discoverability is disabled during active AirPlay sessions to prevent interruptions
- AVRCP support for volume sync and track metadata (artist, title, album) on the OLED display
- BT volume is saved to NVS and restored on reconnect

### Pairing

The device appears as a Bluetooth speaker with the same name as your AirPlay device name (set via the web interface). Pairing uses a fixed PIN code (default: `05032026`, configurable via `idf.py menuconfig` → Bluetooth Configuration).

Secure Simple Pairing (SSP) can optionally be enabled for BT 2.1+ devices — this uses numeric confirmation instead of a PIN. SSP requires a display to show the confirmation number. This is not implemented on the display yet.

### Build Environments

| Environment | Board | Features |
|---|---|---|
| `squeezeamp-bt` | SqueezeAMP | AirPlay + Bluetooth |
| `esparagus-audio-brick-bt` | Esparagus Audio Brick | AirPlay + Bluetooth + Ethernet |

> **Note:** Bluetooth Classic is only available on the original ESP32 (not ESP32-S3). The ESP32-S3 generic build does not include Bluetooth support.

---

## Ethernet (W5500)

The Esparagus Audio Brick supports wired Ethernet via a **W5500 SPI Ethernet module**. This provides a reliable, low-latency network connection — useful in setups where WiFi is unreliable or unavailable.

### How It Works

- Ethernet is checked first at boot — if a cable is connected, WiFi is skipped entirely
- If the Ethernet cable is unplugged at runtime, WiFi automatically starts as a fallback (AP + STA mode)
- If the Ethernet cable is plugged back in, WiFi is stopped and Ethernet takes over
- The web interface shows "Ethernet" or "WiFi" depending on the active connection
- AirPlay and Bluetooth work identically on either interface

### Wiring

The W5500 module connects via SPI (shared bus with the OLED display):

| W5500 Pin | ESP32 GPIO | Function |
|---|---|---|
| CLK | GPIO 18 | SPI clock |
| MOSI | GPIO 23 | SPI data out |
| MISO | GPIO 19 | SPI data in |
| CS | GPIO 5 | Chip select |
| INT | GPIO 35 | Interrupt |
| RST | GPIO 14 | Hardware reset |
| 3V3 | 3.3V | Power |
| GND | GND | Ground |

### Configuration

Ethernet is enabled by default in the `esparagus-audio-brick-bt` build. The GPIOs can be changed via `idf.py menuconfig` → Board Configuration → SPI and Ethernet Configuration.

To disable Ethernet, set `CONFIG_ETH_W5500_ENABLED=n` in menuconfig. When disabled, all Ethernet code is compiled out — zero impact on flash size or RAM.

> **Note:** The W5500 has no factory MAC address. The firmware derives a unique MAC from the ESP32's base MAC using `ESP_MAC_ETH`, so each board gets a stable, unique Ethernet MAC.

---

## OLED Display (Optional)

You can connect a small OLED screen to show the currently playing track info — title, artist, album, a progress bar, and playback time. The display auto-scrolls long text and shows a pause indicator when playback is paused.

### Supported Displays

| Controller | Resolution | Bus     |
| ---------- | ---------- | ------- |
| SSD1306    | 128×64     | I2C/SPI |
| SH1106     | 128×64     | I2C/SPI |
| SSD1309    | 128×64     | I2C/SPI |

128×32 displays (SSD1306 / SH1106) are also supported — they use a compact two-line layout.

> These small OLED boards are widely available on AliExpress / Amazon for ~1–2$. Search for "0.96 inch OLED I2C SSD1306".

### Wiring (I2C — default)

| OLED Pin | ESP32 GPIO | Function  |
| -------- | ---------- | --------- |
| SDA      | GPIO 21    | I2C data  |
| SCL      | GPIO 22    | I2C clock |
| VCC      | 3.3V       | Power     |
| GND      | GND        | Ground    |

The default I2C address is `0x3C`. If your display uses `0x3D`, change it in `idf.py menuconfig` under **AirPlay Receiver → Display Configuration**.

### Enabling the Display

The display is **disabled by default**. To enable it:

#### ESP-IDF

```bash
idf.py menuconfig
# Navigate to: AirPlay Receiver → Display Configuration
# Enable "Enable OLED display"
# Select your driver (SSD1306, SH1106, or SSD1309)
# Select bus type (I2C or SPI) and set GPIO pins if needed
```

#### PlatformIO

Add `CONFIG_DISPLAY_ENABLED=y` and the relevant display options to your sdkconfig defaults, or run menuconfig:

```bash
pio run -e esp32s3 -t menuconfig
```

### Display Options

| Option           | Default   | Description                                 |
| ---------------- | --------- | ------------------------------------------- |
| Display driver   | SSD1306   | SSD1306 / SH1106 / SSD1309                  |
| Display height   | 64 pixels | 64 or 32 pixels                             |
| Bus type         | I2C       | I2C or SPI                                  |
| I2C SDA GPIO     | 21        | Data line (I2C mode)                        |
| I2C SCL GPIO     | 22        | Clock line (I2C mode)                       |
| I2C address      | 0x3C      | 7-bit address (0x3C or 0x3D)                |
| Flip display     | No        | Rotate output 180°                          |
| Refresh interval | 500 ms    | How often the display redraws (100–5000 ms) |

SPI mode exposes additional GPIO settings for CLK, MOSI, CS, DC, and RST.

---

## Features

- **AirPlay 2 protocol** — shows up natively in Control Center and all AirPlay apps
- **ALAC & AAC decoding** — handles both live streaming (Siri, calls) and music playback
- **Multi-room support** — PTP-based timing for synchronized playback across devices
- **Bluetooth A2DP** — receive audio from phones/tablets over Bluetooth (ESP32 boards only)
- **W5500 Ethernet** — wired network with automatic WiFi failover (Esparagus Audio Brick)
- **Web configuration** — set up WiFi and device name from your browser
- **OTA updates** — update firmware over WiFi, no USB needed after first flash
- **LED indicator** — visual feedback for playback status
- **OLED display** — optional screen showing track metadata, progress bar, and playback time
- **SqueezeAMP support** — ESP32 + TAS5756 DAC with built-in amplifier
- **Esparagus Audio Brick support** — ESP32 + TAS5825M DAC/amp with on-chip DSP and 15-band EQ

### Limitations

- Audio only (no AirPlay video or photos)
- One speaker per ESP32 board
- Needs decent WiFi signal for stable streaming

---

## Technical Details

### Signal Flow

```
┌─────────────────┐   WiFi / Eth   ┌─────────────┐
│  iPhone / Mac   │ ────────────►  │    ESP32    │
│    (AirPlay)    │                 │             │
└─────────────────┘                 └──────┬──────┘
┌─────────────────┐                        │
│  Phone / Tablet │   Bluetooth      │ I2S
│     (A2DP)      │ ────────────►  │
└─────────────────┘          ┌──────▼──────┐
                                    │  PCM5102A   │
                                    │  / TAS58xx  │
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

MCLK is not used for PCM5102A as generates it internally. It is, however, connected to pin 8 by default: this is useful in case you want to wire up some other kind of signal converter, like WM8805 I2S to SPDIF converter.

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

### Audio Formats

| Format          | Use Case             |
| --------------- | -------------------- |
| ALAC (realtime) | Live streaming, Siri |
| AAC (buffered)  | Music playback       |

### Key Components

| Module              | Location              | Purpose                                   |
| ------------------- | --------------------- | ----------------------------------------- |
| **RTSP Server**     | `main/rtsp/`          | Handles AirPlay control messages          |
| **HAP Pairing**     | `main/hap/`           | Cryptographic device pairing              |
| **Audio Pipeline**  | `main/audio/`         | Decoding, buffering, timing               |
| **A2DP Sink**       | `main/audio/`         | Bluetooth audio receiver (ESP32 only)     |
| **PTP Clock**       | `main/network/`       | Synchronization with source               |
| **WiFi**            | `main/network/`       | WiFi AP+STA management                    |
| **Ethernet**        | `main/network/`       | W5500 SPI Ethernet driver                 |
| **Web Server**      | `main/network/`       | Configuration interface                   |
| **DAC Abstraction** | `components/dac/`     | Abstract DAC API (Kconfig-selected)       |
| **Board Support**   | `components/boards/`  | Per-board HAL (GPIOs, SPI bus, init)      |
| **Display**         | `components/display/` | OLED display driver (u8g2-based)          |

### Project Structure

```
main/
├── audio/          # Decoders, buffers, timing sync, A2DP sink
├── rtsp/           # RTSP server and handlers
├── hap/            # HomeKit pairing (SRP, Ed25519)
├── plist/          # Binary plist parsing
├── network/        # WiFi, Ethernet, mDNS, PTP, web server
├── main.c          # Entry point
└── settings.c      # NVS persistence
components/
├── dac/            # Abstract DAC API (dispatch layer)
├── dac_tas57xx/    # TI TAS57xx DAC driver (SqueezeAMP)
├── dac_tas58xx/    # TI TAS58xx DAC driver (Esparagus Audio Brick)
├── display/        # OLED display driver (u8g2-based, optional)
├── u8g2/           # u8g2 graphics library (git submodule)
├── u8g2-hal-esp-idf/ # ESP-IDF HAL for u8g2 (git submodule)
└── boards/         # Board support (SqueezeAMP, Esparagus Audio Brick, ESP32-S3 generic)
```

---

## Acknowledgements

- **[Shairport Sync](https://github.com/mikebrady/shairport-sync)** — The reference AirPlay implementation
- **[openairplay/airplay2-receiver](https://github.com/openairplay/airplay2-receiver)** — Python AirPlay 2 implementation
- **[Espressif](https://github.com/espressif)** — ESP-IDF framework and codec libraries

---

## Legal

**Non-commercial use only.** Commercial use requires explicit permission. See [LICENSE](LICENSE).

This is an independent project based on protocol analysis. Not affiliated with Apple Inc. Not guaranteed to work with future iOS/macOS versions. Provided as-is without warranty.

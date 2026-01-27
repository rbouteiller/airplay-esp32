# AirPlay 2 Receiver for ESP32-S3

This project turns an ESP32-S3 into a small AirPlay receiver with I2S output.
It handles mDNS discovery, RTSP control, HAP pairing, ALAC/AAC decoding, and
PTP/NTP clocking for synchronized playback.

## Status
Work in progress. Core discovery, control, and audio pipeline pieces are in
place; additional features and hardening are still underway.
Todo:
- Demo video of the setup
- Better setup instructions
- 3D casing for ESP32 + PCM5102A

## Repository layout
- `main/audio/` - stream abstraction (realtime UDP vs buffered TCP), decoder,
  buffers, timing, crypto
- `main/rtsp/` - RTSP server, message parsing, handlers, FairPlay
- `main/hap/` - HAP pairing, SRP, crypto helpers
- `main/plist/` - plist XML + binary parse/build, base64
- `main/network/` - WiFi, mDNS, PTP/NTP clock, socket helpers
- `main/` - app entry point, settings, ALAC magic cookie

## Decoders
- ALAC via `esp_alac_dec` from `espressif/esp_audio_codec`
- AAC via `esp_aac_dec` from `espressif/esp_audio_codec`
- PCM (L16) path for uncompressed streams

## Espressif components
External dependencies (`main/idf_component.yml`):
- `espressif/esp_audio_codec`
- `espressif/mdns`
- `espressif/libsodium`

Core ESP-IDF components used (`main/CMakeLists.txt`):
- `nvs_flash`, `esp_wifi`, `esp_netif`, `esp_event`
- `esp_ringbuf`, `esp_driver_i2s`, `esp_timer`

## Hardware
- ESP32-S3 (tested on N16R8)
- PCM5102A I2S DAC board (or compatible)

## Wiring overview:

```
AirPlay source (iOS/macOS)
        |
        v
   WiFi + mDNS/RTSP/HAP
        |
        v
     ESP32-S3
        |
        v
 I2S (BCK/LRCK/DOUT)
        |
        v
    PCM5102A DAC
        |
        v
   Amplifier/Speakers
```

PCM5102A example wiring (default pins in `main/main.c`):

```
ESP32-S3        PCM5102A
-------         --------
3V3   --------> VCC
GND   --------> GND
GPIO5 --------> BCK (SCK)
GPIO6 --------> LRCK (WS/LCK)
GPIO7 --------> DIN
```

I2S signal meaning:
- BCK is the bit clock.
- LRCK/WS is the left/right word select.
- DOUT is serial audio data from ESP32 to the DAC.
MCLK is unused in this design.

## Get started

### ESP-IDF Option
1) Install ESP-IDF v5.x and set up the environment:
   - `source /path/to/esp-idf/export.sh`
2) Initialize submodules:
   - `git submodule update --init --recursive`
3) Configure the project:
   - `idf.py set-target esp32s3`
   - `idf.py menuconfig`
     - `AirPlay 2 Receiver Configuration`:
       - `WiFi SSID`
       - `WiFi Password`
       - `AirPlay Device Name`
4) Build, flash, and monitor:
   - `idf.py build`
   - `idf.py -p /dev/ttyUSB0 flash monitor`
     (swap the port if yours is different)

### PlatformIO Option
1) Install [PlatformIO](https://platformio.org/install/cli)
2) Configure WiFi in `sdkconfig`/`sdkconfig.esp32s3`:
   - `CONFIG_WIFI_SSID`
   - `CONFIG_WIFI_PASSWORD`
   - `CONFIG_AIRPLAY_DEVICE_NAME`
3) Build and flash:
   - `pio run -e esp32s3 -t upload`
4) Monitor:
   - `pio run -e esp32s3 -t monitor`

## Usage
After boot and WiFi connection, the device advertises `_airplay._tcp` and
`_raop._tcp`. It should appear in the AirPlay device list using the configured
AirPlay device name.

## Notes
- I2S output is 16-bit stereo at 44.1 kHz by default; adjust in `main/main.c`.
- Output attenuation is applied in `main/main.c` to reduce clipping.
- Credentials are stored via `sdkconfig`; avoid committing secrets.
- Based on shairport-sync [https://github.com/mikebrady/shairport-sync](https://github.com/mikebrady/shairport-sync)

## License
Non-commercial; commercial use requires permission. See `LICENSE`.

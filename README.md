# AirPlay 2 Receiver for ESP32-S3

An ESP-IDF project that turns an ESP32-S3 into an AirPlay 2 audio receiver with
I2S output. It includes mDNS discovery, RTSP control, HAP pairing, ALAC decode,
and PTP/NTP clocking for synchronized playback.

## Status
Work in progress. Core discovery, control, and audio pipeline pieces are in
place; additional features and hardening are still underway.

## Hardware
- ESP32-S3 (tested on N16R8)
- PCM5102A I2S DAC board (or compatible)
- Default I2S pins: BCK=GPIO5, LRCK=GPIO6, DOUT=GPIO7
  (adjust in `main/main.c` if needed)

## Build and Flash
1) Install ESP-IDF v5.x and export the environment.
2) Initialize submodules:
   `git submodule update --init --recursive`
3) Configure:
   - `idf.py set-target esp32s3`
   - `idf.py menuconfig`
     - `AirPlay 2 Receiver Configuration`:
       - `WiFi SSID`
       - `WiFi Password`
       - `AirPlay Device Name`
4) Build and flash:
   - `idf.py build`
   - `idf.py -p /dev/ttyUSB0 flash monitor`

## Usage
After boot and WiFi connection, the device advertises `_airplay._tcp` and
`_raop._tcp`. It should appear in the AirPlay device list using the configured
AirPlay device name.

## Notes
- I2S sample rate defaults to 44.1 kHz; adjust in `main/main.c` if needed.
- Credentials are stored via `sdkconfig`; avoid committing secrets.

## License
Non-commercial; commercial use requires permission. See `LICENSE`. Third-party
components carry their own licenses under `external/` and `shairport-sync/`.

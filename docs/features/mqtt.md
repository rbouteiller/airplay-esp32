# MQTT now-playing (Home Assistant)

An optional MQTT client publishes what the receiver is playing and accepts playback
commands, with Home Assistant MQTT discovery. It is **off by default** twice: it is not
compiled in unless `CONFIG_MQTT_NOWPLAYING` is set, and even then it stays off until you
enable it on the device.

## Build

In `idf.py menuconfig` → *Airplay ESP Configuration* → *MQTT now-playing*:

| Option | Default | What it does |
|---|---|---|
| `CONFIG_MQTT_NOWPLAYING` | n | Compile the feature in. Adds the esp-mqtt client (`espressif/mqtt` on ESP-IDF 6.x). |
| `CONFIG_MQTT_NOWPLAYING_ARTWORK` | y (needs `SPIRAM`) | Keep the latest cover art in PSRAM and serve it to MQTT clients. |
| `CONFIG_MQTT_NOWPLAYING_ARTWORK_MAX_KB` | 256 | Size of the PSRAM cover-art buffer. Larger images are dropped. |
| `CONFIG_MQTT_NOWPLAYING_SNTP` | y | Start SNTP when MQTT is enabled, for `position_updated_at`. |

Or add `CONFIG_MQTT_NOWPLAYING=y` to an extra `sdkconfig.defaults` file.

`config/sdkconfig.defaults` builds esp-mqtt for plain TCP only (no TLS or WebSocket
transports) and puts its buffers in SPIRAM when there is one. The feature talks to a
broker on the local network.

## Setup

Open `http://<device>/mqtt` (`data/www/mqtt.html` in SPIFFS, only included when the
option is on), or send JSON to `POST /api/mqtt`:

```json
{"enabled": true, "host": "broker.local", "port": 1883,
 "username": "user", "password": "secret",
 "base_topic": "airplay/a1b2c3", "discovery_prefix": "homeassistant",
 "artwork": true}
```

- Keys you leave out keep their value.
- The password is write-only: `GET /api/mqtt` only reports `has_password`.
- Settings live in NVS namespace `mqtt_np`.
- The default base topic is `airplay/` plus the last three bytes of the Wi-Fi MAC.
- Changing the artwork setting takes effect after a restart, because it changes what the
  receiver advertises over mDNS.

## Topics

| Topic | Direction | Payload |
|---|---|---|
| `<base>/state` | out, retained | JSON, see below |
| `<base>/status` | out, retained | `online` / `offline` (last will) |
| `<base>/artwork_url` | out, retained | URL of the current cover art |
| `<base>/cmd` | in | `play_pause`, `play`, `pause`, `next`, `prev`, `volume_up`, `volume_down` |
| `<base>/volume/set` | in | `0`–`100` |

State fields:
- `state`: `playing`, `paused` or `idle`
- `source`, `connected`
- `title`, `artist`, `album`, `genre`
- `duration`, `position` (seconds)
- `position_ts`, `position_updated_at`: the moment `position` was true; null until the
  clock is set
- `volume` (0–100), `volume_level` (0–1), `muted`
- `dacp`
- `artwork`: URL or null

`state` is published on every change, and every 5 s while playing so the position stays
current.

Commands use the same path as the [hardware buttons](buttons.md): DACP for AirPlay v1,
the event channel for AirPlay 2. Volume always sets the local level. `play` and `pause`
send the play/pause toggle unless the receiver is already in that state.

## Home Assistant

With the MQTT integration set up, the device appears by itself with these entities:
- sensors: playback state (the full JSON as attributes), title, artist, album, position,
  duration
- a volume `number`
- an `image` for the cover art
- play/pause, next and previous buttons

A `universal` media player can combine them into one player.

## Memory

Static, from `idf.py size` (ESP-IDF 6.1):

| Preset | App image, option on | Change vs option off | Static internal RAM |
|---|---|---|---|
| `esp32s3` (16 MB) | 1,737,296 B | +36,592 B | +900 B |
| `esp32wrover-dev` (plain ESP32, 4 MB) | 1,962,112 B (3,968 B free in the app slot) | +29,664 B | DRAM +848 B, IRAM +68 B |

- With the option off, nothing changes: the image is byte-for-byte the same size.
- At runtime, when enabled, there is one task: the esp-mqtt client (4 KB stack, internal
  RAM). The periodic publish runs as a 500 ms `esp_timer` callback instead of a task of
  its own, and the MQTT buffers are in SPIRAM.
- Cover art lives only in PSRAM. Its buffer is allocated when the first image arrives.
  Without PSRAM, artwork is not requested at all.

## Cover art and realtime streams

- With artwork on, the receiver asks senders for cover art: the `md` TXT record becomes
  `0,1,2` and feature bit 15 is set.
- As with `CONFIG_ENABLE_AIRPLAY_ARTWORK`, receiving images can cause drop-outs on
  realtime (AirPlay 1) streams. If you hear them, turn artwork off.

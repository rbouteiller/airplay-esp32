# Ethernet (W5500)

The [Esparagus Audio Brick](../boards/esparagus-audio-brick.md) supports wired Ethernet
through a **W5500 SPI module**, giving a reliable low-latency connection where WiFi is
unreliable or unavailable.

## How it works

Ethernet is checked first at boot. If a cable is connected, WiFi is skipped entirely.
Unplug the cable at runtime and WiFi starts automatically as a fallback; plug it back in
and Ethernet takes over again.

```mermaid
stateDiagram-v2
    [*] --> Boot
    Boot --> CableCheck: check link
    CableCheck: Cable connected?

    CableCheck --> Ethernet: yes
    CableCheck --> WiFi: no

    Ethernet: Ethernet active
    Ethernet: WiFi stack not started
    WiFi: WiFi active
    WiFi: AP + STA mode

    Ethernet --> WiFi: cable unplugged
    WiFi --> Ethernet: cable plugged in
```

The web interface shows "Ethernet" or "WiFi" depending on which is active, and AirPlay and
Bluetooth behave identically on either.

## Wiring

The W5500 connects over SPI, sharing the clock and MOSI lines with the OLED display. The
ESP32 and ESP32-S3 revisions of the Brick use different pins.

| W5500 pin | ESP32 | ESP32-S3 | Function |
| --- | :-: | :-: | --- |
| CLK | 18 | 12 | SPI clock |
| MOSI | 23 | 11 | SPI data out |
| MISO | 19 | 13 | SPI data in |
| CS | 5 | 10 | Chip select |
| INT | 35 | 6 | Interrupt |
| RST | 14 | 5 | Hardware reset |
| 3V3 | 3.3 V | 3.3 V | Power |
| GND | GND | GND | Ground |

## Configuration

Ethernet is enabled by default in every Esparagus Audio Brick build, on both revisions.
GPIOs can be changed under **Board Configuration → SPI and Ethernet Configuration** in
`menuconfig`.

To disable it, set:

```ini
CONFIG_ETH_W5500_ENABLED=n
```

When disabled, all Ethernet code is compiled out — no impact on flash size or RAM.

!!! note "MAC address"

    The W5500 has no factory MAC address. The firmware derives a unique one from the
    ESP32's base MAC using `ESP_MAC_ETH`, so every board gets a stable, unique Ethernet
    MAC.

# ST7789 TFT display

A 1.9" 320×170 colour IPS display can show track metadata over a full-colour bitmap
background, with a progress bar and elapsed/remaining time. Rendering uses
[LVGL 9](https://lvgl.io/) with `esp_lvgl_port`.

<figure markdown>
  ![ST7789 display showing track title, artist and a progress bar](../assets/display_st7789.png){ width="500" }
</figure>

!!! warning "ESP32-S3 with PSRAM required"

    This driver is not viable on the original ESP32. LVGL 9 plus the AirPlay audio
    pipeline plus WiFi exceeds the internal SRAM budget, and a Wrover's 4 MB flash is too
    small once the audio stack, SPIFFS partition and LVGL assets are accounted for.

    `idf_component.yml` enforces this: LVGL and `esp_lvgl_port` are only declared as
    dependencies when the target is `esp32s3`. Non-S3 builds are unaffected — the managed
    components are never downloaded and the OLED driver keeps working.

    Tested on an ESP32-S3 N16R8 (16 MB flash, 8 MB PSRAM) with ESP-IDF 5.5.3.

## Wiring

| Display pin | ESP32-S3 GPIO | Function |
| --- | --- | --- |
| SCL / CLK | 18 | SPI clock |
| SDA / MOSI | 17 | SPI data |
| CS | 15 | Chip select |
| DC / RS | 16 | Data / command select |
| RES / RST | 21 | Reset |
| BLK / BL | 38 | Backlight |
| VCC | 3.3 V | Power |
| GND | GND | Ground |

## Enabling

The display is **disabled by default**.

=== "menuconfig"

    ```bash
    idf.py menuconfig
    # AirPlay Receiver → Display Configuration → Enable display
    # Select driver: ST7789 TFT (320×170 landscape)
    ```

=== "sdkconfig defaults"

    ```ini
    CONFIG_DISPLAY_ENABLED=y
    CONFIG_DISPLAY_DRIVER_ST7789=y
    CONFIG_DISPLAY_SPI_CLK=18
    CONFIG_DISPLAY_SPI_MOSI=17
    CONFIG_DISPLAY_SPI_CS=15
    CONFIG_DISPLAY_SPI_DC=16
    CONFIG_DISPLAY_SPI_RST=21
    CONFIG_DISPLAY_BL_GPIO=38
    ```

## Background image

At startup the driver loads a full-screen background from `/spiffs/bg/background.bin` into
PSRAM and draws all widgets on top of it. With no file present the screen falls back to
solid black and everything still renders correctly.

To replace it:

1. Design your image and export a PNG. Any size works — it gets resized.
2. Convert it from the project root:
   ```bash
   python3 components/display/make_background.py <source.png> [brightness]
   ```
   Brightness ranges from `0.4` to `0.6`. Start at `0.5`; the ST7789 backlight is
   considerably brighter than a monitor.
3. The script writes `data/bg/background.bin`. Get it onto the device either by
   reflashing SPIFFS over serial with `idf.py flash`, or over WiFi:
   ```bash
   curl -X POST "http://<device-ip>/api/fs/upload?path=/spiffs/bg/background.bin" \
        --data-binary @data/bg/background.bin
   ```
   Then reboot — the new background loads on next boot.

There is no web UI for background uploads; the device's web interface covers WiFi setup
and configuration only.

### Colour banding

The panel is RGB565, so red and blue carry 32 levels and green 64, down from 256 each.
Subtle dark gradients show **visible banding**, which is a hardware limit with no complete
software fix. Bold contrast and distinct colour regions render well. The conversion script
applies Floyd–Steinberg dithering, which helps a little.

If colours come out washed out, swapped or psychedelic, the byte order is wrong rather than
the driver — see the colour bar test in the
[display component README](https://github.com/rbouteiller/airplay-esp32/blob/main/components/display/README.md).

## Cover art

Album artwork is disabled by default because it can stall the audio pipeline. If you have
a TFT display and want it, see [AirPlay tuning](airplay-tuning.md#cover-art).

## Implementation notes

Non-obvious integration requirements for ESP-IDF + LVGL 9 + `esp_lvgl_port` — rotation
ordering, LVGL task core affinity, and DMA buffer placement — are documented alongside the
code in the
[display component README](https://github.com/rbouteiller/airplay-esp32/blob/main/components/display/README.md).

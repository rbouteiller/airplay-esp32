# OLED display

A small OLED screen can show the currently playing track: title, artist, album, a progress
bar and playback time. Long text scrolls automatically and a pause indicator appears when
playback is paused.

These panels are widely available for $1–2. Search for "0.96 inch OLED I2C SSD1306".

## Supported displays

| Controller | Resolution | Bus |
| --- | --- | --- |
| SSD1306 | 128×64 | I2C or SPI |
| SH1106 | 128×64 | I2C or SPI |
| SSD1309 | 128×64 | I2C or SPI |

128×32 panels (SSD1306 and SH1106) also work and switch to a compact two-line layout.

## Wiring (I2C, the default)

| OLED pin | ESP32 GPIO | Function |
| --- | --- | --- |
| SDA | 21 | I2C data |
| SCL | 22 | I2C clock |
| VCC | 3.3 V | Power |
| GND | GND | Ground |

The default I2C address is `0x3C`. If your panel uses `0x3D`, change it under
**AirPlay Receiver → Display Configuration**.

## Enabling the display

The display is **disabled by default**.

=== "ESP-IDF"

    ```bash
    idf.py menuconfig
    # AirPlay Receiver → Display Configuration
    #   Enable "Enable OLED display"
    #   Select your driver (SSD1306, SH1106 or SSD1309)
    #   Select bus type (I2C or SPI) and set GPIO pins if needed
    ```

=== "PlatformIO"

    Run menuconfig through PlatformIO:

    ```bash
    pio run -e esp32s3 -t menuconfig
    ```

    Or add the options to your sdkconfig defaults directly:

    ```ini
    CONFIG_DISPLAY_ENABLED=y
    CONFIG_DISPLAY_I2C_SDA=21
    CONFIG_DISPLAY_I2C_SCL=22
    ```

## Options

| Option | Default | Description |
| --- | --- | --- |
| Display driver | SSD1306 | SSD1306, SH1106 or SSD1309 |
| Display height | 64 pixels | 64 or 32 |
| Bus type | I2C | I2C or SPI |
| I2C SDA GPIO | 21 | Data line, I2C mode |
| I2C SCL GPIO | 22 | Clock line, I2C mode |
| I2C address | 0x3C | 7-bit address, 0x3C or 0x3D |
| Flip display | No | Rotate output 180° |
| Refresh interval | 500 ms | How often the display redraws, 100–5000 ms |

SPI mode exposes additional GPIO settings for CLK, MOSI, CS, DC and RST.

!!! note "Submodules required"

    OLED rendering uses the `u8g2` and `u8g2-hal-esp-idf` git submodules. Clone with
    `--recursive`, or run `git submodule update --init --recursive` in an existing
    checkout, otherwise the build fails.

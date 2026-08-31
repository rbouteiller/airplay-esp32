# Custom board configuration

If you are porting to your own hardware, you can define a custom build environment without
touching `platformio.ini`. Create a **`user_platformio.ini`** file — the main config
already pulls it in via `extra_configs`, so PlatformIO picks it up automatically.

## How it works

1. Pick an existing environment to extend, for example `esp32s3` or `esp32wrover-dev`.
2. Create a `config/sdkconfig.user.<your_board>` file holding your board-specific Kconfig
   overrides: GPIO pins, DAC selection, display settings and so on.
3. Add an environment to `user_platformio.ini` that chains your sdkconfig file after the
   base defaults.

## Example

Say you have a custom ESP32 board called "myboard" with a SqueezeAMP-compatible DAC, but
different GPIO assignments and an OLED display. Create two files.

`config/sdkconfig.user.myboard` — your board-specific overrides:

```ini
# I2S pin assignments
CONFIG_I2S_BCK_PIN=5
CONFIG_I2S_WS_PIN=18
CONFIG_I2S_DO_PIN=19

# Enable OLED display
CONFIG_DISPLAY_ENABLED=y
CONFIG_DISPLAY_I2C_SDA=21
CONFIG_DISPLAY_I2C_SCL=22
```

`user_platformio.ini` — your build environment:

```ini
[env:myboard]
extends = env:esp32s3
board_build.cmake_extra_args =
    "-DSDKCONFIG_DEFAULTS=config/sdkconfig.defaults;config/sdkconfig.defaults.esp32s3;config/sdkconfig.user.myboard"
```

Then build and flash:

```bash
pio run -e myboard -t upload
pio run -e myboard -t uploadfs
```

## Notes

- Sdkconfig defaults are applied **left to right** — later files override earlier ones, so
  your `config/sdkconfig.user.*` must come last.
- `config/sdkconfig.user.*` files are gitignored, so they will not pollute the repository.
- If you change any sdkconfig defaults, delete the cached `sdkconfig.<env>` file before
  rebuilding, otherwise the old values are reused.
- You can extend any base environment: use `squeezeamp` or `squeezeamp-bt` for TAS57xx
  boards, `esparagus-audio-brick` or `esparagus-audio-brick-bt` for TAS58xx boards, and
  `esp32s3` for S3-based boards.

## Related

- [Build environments](../reference/build-environments.md)
- [Architecture](../reference/architecture.md)

# Seeed XIAO ESP32-C5

The Seeed XIAO ESP32-C5 is a RISC-V board with 8 MB flash, 8 MB PSRAM and **dual-band
WiFi 6**, which makes it attractive where 2.4 GHz is congested. Wire an external I2S DAC
such as a PCM5102A.

!!! warning "No Bluetooth A2DP"

    The ESP32-C5 has Bluetooth LE only, not Bluetooth Classic, so A2DP audio is not
    available on this board.

## Default I2S pins

| Function | GPIO | XIAO label |
| --- | --- | --- |
| Bit clock (BCK) | 8 | D8 |
| Word select (WS / LRCK) | 9 | D9 |
| Data in (DIN) | 10 | D10 |

Change them under **Board Configuration → Pin Configuration** in `menuconfig`.

## Building

Prebuilt stable and beta firmware are available from the
[browser installer](../getting-started/flashing.md#generic-boards).

=== "PlatformIO"

    The PlatformIO platform and toolchain are pinned in
    `platformio.ini` and downloaded automatically on the first build — no extra setup needed.


    ```bash
    pio run -e esp32c5-xiao -t upload
    pio run -e esp32c5-xiao -t uploadfs
    ```

=== "ESP-IDF"

    ```bash
    idf.py set-target esp32c5
    idf.py -DSDKCONFIG_DEFAULTS="config/sdkconfig.defaults;config/sdkconfig.defaults.esp32c5" build flash monitor
    ```

## Related

- [Build environments](../reference/build-environments.md)
- [Custom board configuration](custom.md)

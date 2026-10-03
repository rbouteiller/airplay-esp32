# Amplifier GPIO control

The optional amplifier GPIO controller drives one amplifier shutdown/enable
pin (`SD`) and one mute pin (`MUTE`) from the playback state. It works for
both AirPlay and Bluetooth playback.

- **Playback starts:** release `SD`, wait briefly, then release `MUTE`.
- **Playback stops:** assert `MUTE`, wait briefly, then assert `SD`.
- **Client connects but audio has not started:** outputs remain idle.
- **Pause, flush, or disconnect:** outputs return to idle.

The exact logic level is configurable because amplifier datasheets differ:
`*_PLAYING_LEVEL` is the value driven while audio is playing, and the opposite
value is driven while idle.

## Enable the outputs

Run `pio run -e <environment> -t menuconfig`, then open **Amplifier GPIO
Control**. Set `AMP_GPIO_CONTROL` to enabled and assign the two GPIO numbers.
Set unused GPIOs to `-1`.

For an amplifier whose `SD` pin is active-low shutdown and whose `MUTE` pin is
active-high mute, use:

```ini
CONFIG_AMP_GPIO_CONTROL=y
CONFIG_AMP_GPIO_SD_GPIO=4
# High releases shutdown while playing; low shuts down when idle.
CONFIG_AMP_GPIO_SD_PLAYING_LEVEL=1
CONFIG_AMP_GPIO_MUTE_GPIO=5
# Low releases mute while playing; high mutes when idle.
CONFIG_AMP_GPIO_MUTE_PLAYING_LEVEL=0
```

Adjust the two GPIO numbers to pins that are free on your board. The delays
control the brief power-up/power-down ordering interval; the defaults are
normally sufficient. Use external pull resistors if the amplifier must remain
safe while the ESP32 is booting or resetting.

Do not assign the same GPIO to both this feature and the board-level
`MUTE_GPIO`. Leave the board-level `MUTE_GPIO` set to `-1` when using this
playback-controlled amplifier controller.

Alternatively, put the same `CONFIG_*=...` values in a
`config/sdkconfig.user.<board>` file as described in
[Custom board configuration](../boards/custom.md).

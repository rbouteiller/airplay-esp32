# Software EQ

Plain I2S DACs and amplifiers — the PCM5102A, PCM5100 and MAX98357A among them — have no
DSP of their own. With `CONFIG_SOFTWARE_EQ` the ESP32 does the filtering itself and backs
the same `/bq` page the TAS58xx boards use: 15 biquad sections per output, designed by the
same code, plus a level and a mute per output.

!!! warning "Needs a chip with an FPU"

    The filters run in single-precision floating point, so the option exists only on the
    ESP32, ESP32-S3 and ESP32-P4. The ESP32-S2 and ESP32-C5 have no FPU and do not offer
    it. It is also hidden on boards with a TAS57xx or TAS58xx, whose own DSP does the job,
    and needs the I2S output rather than S/PDIF or USB.

## Enabling it

Layer `config/sdkconfig.defaults.software-eq` onto a board's defaults, or turn on
**Software parametric EQ** under **Airplay ESP Configuration** in `menuconfig`. For a
[custom board](../boards/custom.md), `CONFIG_SOFTWARE_EQ=y` in its `sdkconfig.user` file
does the same. The page itself ships in every filesystem image.

```bash
idf.py -DSDKCONFIG_DEFAULTS="config/sdkconfig.defaults;config/sdkconfig.defaults.esp32s3;config/sdkconfig.defaults.software-eq" build
```

## What it applies to

Every source goes through it: AirPlay, Sendspin, [USB audio](usb-audio.md) and
[Bluetooth](bluetooth.md). Each takes the same three steps on its way to I2S — the channel
mode, then the EQ, then software volume on a DAC that has no volume control of its own.
The page's input routing is that same channel mode, so setting one sets the other.

A flat chain with the levels at 0 dB leaves the audio bit for bit as it was.

## Using the page

The page works as described for the
[Esparagus Audio Brick](../boards/esparagus-audio-brick.md#equaliser): **Apply** to hear
an edit, **Commit to flash** to keep it, **Revert** to go back, and the same crossover
builder and measurement fit. What differs:

- **One amplifier, two outputs.** A is the left channel and B the right. Layouts that need
  a second amplifier are not offered.
- **Boosts cost level.** A TAS58xx has headroom inside its DSP; here a boost could only
  clip. So the signal is turned down ahead of the filters by as much as the curves boost
  at their highest point, both channels by the same amount so the balance holds. Cuts
  cost nothing, and an output trimmed down gives some of it back. The page shows how far
  the signal is currently turned down, and the volume is there to make it up.
- **Edits are heard at once, without a mute.** Sections that stay in the chain keep
  running through an edit, and level changes fade over a few milliseconds. A section
  newly added to a playing chain can still tick as it starts.
- **Both rates are ready.** Corners are designed for 44.1 and 48 kHz whenever the tuning
  changes, so a source switching the clock between them costs nothing. Any other rate,
  such as Bluetooth at 32 kHz, is designed when the clock gets there.

Committed chains are stored in `/spiffs/eq/sw_eq.cfg`. Levels and mutes are saved to NVS
as soon as they change, independently of the commit, as on the TAS58xx.

## 32-bit output

On the I2S line each sample is normally a 16-bit word, so the EQ's output is rounded back
to 16 bits and the software volume rounds it again. A DAC or amplifier that takes 32-bit
words, such as the MAX98357A (which picks the word length from the bit clock), can be
sent those instead: turn on **Send 32-bit words over I2S** (`CONFIG_I2S_32BIT_OUTPUT=y`).
The EQ then hands its output over in floating point, the volume is applied at full
precision, and the only rounding left is into the 32-bit word. A boost that runs past
full scale is no longer clipped ahead of the volume either, only where it is still past
full scale after it.

It costs about 16 KB more internal RAM: the DMA ring doubles, and the words need buffers
of their own.

## Cost

Measured on an ESP32-S3 at 240 MHz, with 48 kHz audio:

| | Time |
| --- | --- |
| Filtering, per section per channel | about 0.6 % of one core |
| Filtering, all 15 sections on both channels | 19 % of one core |
| An edit (both rates redesigned, on the web server task) | 1–19 ms |
| A clock change between 44.1 and 48 kHz | under 30 µs |

The original ESP32 has not been measured. The EQ takes about 1 KB of internal RAM, for
the running filters, and about 6 KB of PSRAM for everything else.

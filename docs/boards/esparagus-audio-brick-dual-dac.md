# Esparagus Audio Brick (dual DAC)

The [Esparagus Audio Brick](esparagus-audio-brick.md) carries **two TAS5825M**
amplifiers on one I2S bus. It is **ESP32-S3** based with a pair of
TAS5825M.

Two amplifiers give you a genuine active crossover: satellites on one chip, 
a bridged subwoofer or a second stereo pair on the other, split in the DSP 
rather than by a passive network.

## Features

- 2× TAS5825M, detected at I2C **0x4C** and **0x4D**
- 15 biquad sections per output, per amplifier — 60 in total across the four outputs
- Second amplifier wired as a bridged mono subwoofer or as a second stereo pair,
  switchable from the web interface
- [W5500 SPI Ethernet](../features/ethernet.md) with automatic WiFi failover
- Optional [USB audio](../features/usb-audio.md) — the S3's native USB makes the dual-DAC board 
  a USB speaker as well as an AirPlay one
- I2C and SPI exposed for external displays, sensors and GPIO expanders
- 8 MB flash, octal PSRAM
- No Bluetooth: A2DP needs Bluetooth Classic, which the ESP32-S3 does not have

## Flashing

```bash
# AirPlay + Ethernet
pio run -e esparagus-audio-brick-dual-dac -t upload
pio run -e esparagus-audio-brick-dual-dac -t uploadfs

# The same board, also enumerating as a USB speaker
pio run -e esparagus-audio-brick-dual-uac -t upload
pio run -e esparagus-audio-brick-dual-uac -t uploadfs
```

Under ESP-IDF:

```bash
idf.py set-target esp32s3
idf.py -DSDKCONFIG_DEFAULTS="config/sdkconfig.defaults;config/sdkconfig.defaults.esparagus-audio-brick-dual-dac" build
idf.py -p /dev/ttyUSB0 flash
```

No prebuilt binary is published; build it yourself.

## Default GPIO assignments

The dual-DAC board shares the S3 revision's I2S, I2C, SPI and display pins, and differs in what it
does with the two pins the single-DAC board spends on FAULTZ and PWDN.

| Function | GPIO | Notes |
| --- | :-: | --- |
| I2S BCK | 14 | Bit clock |
| I2S WS | 15 | Word select (LRCLK) |
| I2S DO | 16 | Serial audio data, both amplifiers |
| I2C SDA | 8 | Control port, both amplifiers |
| I2C SCL | 9 | Control port, both amplifiers |
| DAC 1 enable | 18 | PDN for the amplifier at 0x4C |
| DAC 2 enable | 17 | PDN for the amplifier at 0x4D |
| Status LED | 21 | Addressable RGB |
| SPI SCLK | 12 | Shared by Ethernet and display |
| SPI MOSI | 11 | Shared by Ethernet and display |
| SPI MISO | 13 | Ethernet only |
| Ethernet CS | 10 | W5500 |
| Ethernet INT | 6 | W5500 |
| Ethernet RST | 5 | W5500 |
| Display CS | 47 | SH1106 OLED |
| Display DC | 38 | SH1106 OLED |
| Display RST | 48 | SH1106 OLED |

!!! note "No fault line"

    GPIO 18 and 17 are the two DAC enables, so neither amplifier's FAULTZ pin
    reaches the MCU (`CONFIG_SPKFAULT_GPIO=-1`). The driver polls both parts' fault
    registers every two seconds instead, which catches over-current and thermal
    shutdown a little later than an interrupt would but reports the same detail.

## Amplifier roles

Roles follow detection order, which follows I2C address:

| Index | Address | Role |
| --- | --- | --- |
| 0 | 0x4C | Stereo satellites, always a BTL pair |
| 1 | 0x4D | Second amplifier — bridged mono, or a second stereo pair |

Both are fed the same I2S stream; what each one does with it is set by its own DSP input
mixer, so no external wiring decides the routing.

### Second amplifier wiring

**Second Amplifier** on the main web page chooses between the two:

- **Bridged mono (PBTL)** — OUT_A and OUT_B are paralleled into one driver, for a
  subwoofer. The amplifier is fed `(L+R)/2` by default, since a single voice coil has no
  stereo to reproduce.
- **Stereo (BTL)** — two separate speakers, as on the first amplifier.

!!! danger "Rewire before restarting"

    PBTL is a control-port setting written while the part is still in HiZ, so the change
    takes effect on the next boot, not immediately. **Match the speaker wiring to the
    setting before you restart.** Leaving OUT_A and OUT_B shorted together while the part
    comes up as a stereo BTL pair drives the two outputs against each other and can
    damage the amplifier and its output filters. The web interface asks you to confirm
    for this reason.

The setting is stored in NVS and read back before the DAC is initialised, because PBTL
has to be established before the output stage ever drives the load.

## Crossovers and EQ

The [Equaliser](esparagus-audio-brick.md#equaliser) page treats both amplifiers as one
system. **Build crossover** offers the layouts the dual-DAC board makes possible — tweeters on one
amplifier and woofers on the other, or satellites plus a subwoofer — and writes the
filters, ganging and input routing into every output the split touches. Apply always
pushes both amplifiers together, so a crossover spanning the pair can never go live by
halves.

Per-output channel selection disappears from the main page once two amplifiers are
found: with a crossover in the DSP the routing is already decided, so choosing it again
per output would mean nothing.

## PPC3 dumps

TAS5825M DACs are used, so [full PPC3 tunings](esparagus-audio-brick.md#full-ppc3-tuning)
apply — one file per amplifier, indexed by detection order:

| File | Applies to |
| --- | --- |
| `/spiffs/hf/tas5825m_fw0-44100.bin` | amplifier at 0x4C, at 44.1 kHz |
| `/spiffs/hf/tas5825m_fw1-44100.bin` | amplifier at 0x4D, at 44.1 kHz |
| `/spiffs/hf/tas5825m_fw0-48000.bin` | amplifier at 0x4C, at 48 kHz |
| `/spiffs/hf/tas5825m_fw1-48000.bin` | amplifier at 0x4D, at 48 kHz |

A PPC3 log that drives both amplifiers carries the writes for each, so convert it twice,
picking the device with `--dev 98` or `--dev 9a`:

```bash
python3 components/dac_tas58xx/ppc3_convert.py both_amps.cfg --dev 98 -o tas5825m_fw0-48000.bin
python3 components/dac_tas58xx/ppc3_convert.py both_amps.cfg --dev 9a -o tas5825m_fw1-48000.bin
```

The unindexed `tas5825m_fw-<rate>.bin` stands in for the first amplifier only, so on rev
D it is worth using the indexed names throughout to avoid confusion.

## USB audio

`esparagus-audio-brick-dual-uac` is the same board with
[USB audio](../features/usb-audio.md) layered on. The host sees a stereo USB speaker
feeding the same DSP, crossover and volume control AirPlay uses, and AirPlay is suspended
while the host is streaming.

USB audio runs at **48 kHz** — see [the sample rate warning](../features/usb-audio.md#sample-rate)
for why 44.1 kHz does not work on this path. AirPlay's 44.1 kHz stream is resampled on
the way out, so a 48 kHz PPC3 dump is the one that matters on a UAC build.

TinyUSB claims the USB PHY, so USB-Serial-JTAG cannot also be a console on this build.
Logs stay on UART0, and reflashing over USB needs BOOT held during reset;
[OTA updates](../reference/ota.md) sidestep it.

## Related

- [Esparagus Audio Brick](esparagus-audio-brick.md) — the single-DAC ESP32 and S3 boards
- [USB audio (UAC)](../features/usb-audio.md)
- [Ethernet (W5500)](../features/ethernet.md)
- [Build environments](../reference/build-environments.md)

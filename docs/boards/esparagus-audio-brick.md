# Esparagus Audio Brick

The [Esparagus Audio Brick](https://github.com/sonocotta/esparagus-media-center/?tab=readme-ov-file#esparagus-audio-brick-prototype)
is built around a TI **TAS5825M** Class-D DAC and amplifier. Like the SqueezeAMP, it
needs no external DAC — connect speakers directly.

The board exists as an **ESP32** revision and an **ESP32-S3** revision. The audio design
is the same; the pinout is not, and neither is what the two chips can do — see
[Default GPIO assignments](#default-gpio-assignments) and [Variants](#variants).

Some bricks are fitted with a TI **TAS5805M** rather than the TAS5825M. It is the same
family and the same driver, but it is not the same part: see
[TAS5805M boards](#tas5805m-boards) for what it does and does not do here.

## Features

- TAS5825M with on-chip DSP and a 15-band parametric EQ (25 Hz – 16 kHz)
- Hardware volume control with a configurable maximum level
- Speaker fault detection with automatic mute and recovery
- Automatic power state management (deep sleep / standby / play) driven by AirPlay session state
- 8 MB flash
- [Bluetooth A2DP](../features/bluetooth.md) on the **ESP32 revision only** — the S3 has no
  Bluetooth Classic radio, so there is no `-bt` build for it
- [W5500 SPI Ethernet](../features/ethernet.md) with automatic WiFi failover, on both
  revisions

## Flashing

=== "Browser"

    Use the Esparagus Audio Brick installer on the
    [flashing page](../getting-started/flashing.md). The published binary is the
    Bluetooth + Ethernet build.

=== "PlatformIO"

    ```bash
    # ESP32 — AirPlay + Ethernet
    pio run -e esparagus-audio-brick -t upload
    pio run -e esparagus-audio-brick -t uploadfs

    # ESP32 — AirPlay + Bluetooth + Ethernet
    pio run -e esparagus-audio-brick-bt -t upload
    pio run -e esparagus-audio-brick-bt -t uploadfs

    # ESP32-S3 — AirPlay + Ethernet (no Bluetooth on this chip)
    pio run -e esparagus-audio-brick-s3 -t upload
    pio run -e esparagus-audio-brick-s3 -t uploadfs

    # Serial monitor
    pio run -e esparagus-audio-brick -t monitor
    ```

=== "ESP-IDF"

    ```bash
    # ESP32 revision
    idf.py set-target esp32
    idf.py -DSDKCONFIG_DEFAULTS="config/sdkconfig.defaults;config/sdkconfig.defaults.esparagus-audio-brick" build

    # ESP32-S3 revision
    idf.py set-target esp32s3
    idf.py -DSDKCONFIG_DEFAULTS="config/sdkconfig.defaults;config/sdkconfig.defaults.esparagus-audio-brick-s3" build

    idf.py -p /dev/ttyUSB0 flash
    ```

## Default GPIO assignments

The two revisions share no pinout, so pick the column matching your board. The ESP32
column is `config/sdkconfig.defaults.esparagus-audio-brick`, the S3 column
`config/sdkconfig.defaults.esparagus-audio-brick-s3`.

| Function | ESP32 | ESP32-S3 | Notes |
| --- | :-: | :-: | --- |
| I2S BCK | 26 | 14 | Bit clock |
| I2S WS | 25 | 15 | Word select (LRCLK) |
| I2S DO | 22 | 16 | Serial audio data |
| I2C SDA | 21 | 8 | DAC control (TAS5825M) |
| I2C SCL | 27 | 9 | DAC control (TAS5825M) |
| DAC warning | 36 | 4 | TAS5825M warning output, input |
| Speaker fault | 39 | 18 | TAS5825M FAULTZ, input |
| Status LED | 12 | 21 | Addressable RGB |
| SPI SCLK | 18 | 12 | Shared by Ethernet and display |
| SPI MOSI | 23 | 11 | Shared by Ethernet and display |
| SPI MISO | 19 | 13 | Ethernet only |
| Ethernet CS | 5 | 10 | W5500 |
| Ethernet INT | 35 | 6 | W5500 |
| Ethernet RST | 14 | 5 | W5500 |
| Display CS | 15 | 47 | SH1106 OLED |
| Display DC | 4 | 38 | SH1106 OLED |
| Display RST | 32 | 48 | SH1106 OLED |

!!! note "GPIOs 34–39 are input-only on the ESP32"

    On the ESP32 revision the fault, warning and Ethernet interrupt lines land on
    GPIOs 35–39, which are input-only and have no internal pull-up. The board provides
    external pull-ups. The S3 revision has no such restriction on the pins it uses.

Rev D is an S3 board with a third pinout: it has two amplifiers and no FAULTZ line back
to the MCU, spending GPIO 18 and 17 on the two DAC enables instead. See
[Esparagus Audio Brick rev D](esparagus-audio-brick-dual-dac.md).

The build selects the TAS58xx driver automatically (`CONFIG_DAC_TAS58XX`). The driver
auto-detects the amplifier at startup: 0x4C–0x4F for a TAS5825M, 0x2C–0x2F for a
TAS5805M. It then confirms the guess against the die ID and warns if the two disagree.

## TAS5805M boards

Some bricks carry a **TAS5805M** instead. The driver detects it, drives it and gives it
its own init sequence, so the board plays and its volume, mute and 15-band biquad chain
all work through the [Equaliser](#equaliser) page exactly as on a TAS5825M.

Two things do not carry over:

!!! warning "No PPC3 dumps on a TAS5805M"

    A dump replays a *process flow*, which is a TAS5825M feature — the TAS5805M has no
    flow-select register and lays its coefficients out differently, so a dump exported
    for one part would write garbage into the other. The driver checks the model and
    skips the file rather than risk it. There is no equivalent to load, so
    [Full PPC3 tuning](#full-ppc3-tuning) simply does not apply: the
    [Equaliser](#equaliser) page is the whole of the tuning available, which for most
    builds is the whole signal path anyway.

The **input mixer** is TAS5825M-only too. Summing to mono or feeding one channel to both
outputs is done in the DSP mixer, and only the TAS5825M's mixer is implemented here, so
a TAS5805M passes the stereo pair straight through and logs a warning if asked for
anything else. That also means no crossover layout needing a summed or single-channel
feed — the ones that route the pair as-is still work.

## Equaliser

TAS5825M boards expose the DAC's 15 cascaded biquad sections through the device's web
interface at `/bq`, one filter per section, per output and per amplifier. Each
section can be a peaking filter, a shelf, a low or high pass in six alignments, a band
pass, a notch, a phase shift, or five raw coefficients. The filter models match
PurePath Console 3, and coefficients are recomputed whenever the I2S sample rate
changes. The chip's two outputs are named A and B — which of them carries left, right
or a sum is the routing setting, not a fixed assignment. A and B can be ganged or
tuned separately. Editing only redraws the response graph: **Apply** sends the filters
to the amplifiers so you can hear them, and **Commit to flash** makes them survive a
reboot. **Revert** goes back to what is in flash. For plain tone shaping, **Load
15-band EQ** fills the chain with a flat graphic equaliser — one peaking section per
band from 20 Hz to 16 kHz — leaving only the gains to set. It fills in the form and
nothing more, so the amplifier hears it only once applied.

Crossovers are built from these same sections, so a two-way or subwoofer split is just
a high pass on one amplifier and a low pass on the other. **Build crossover** does that
for you: pick how the drivers are wired — both bands on one amplifier, one amplifier per
speaker, tweeters on one amplifier and woofers on the other, or satellites plus a
subwoofer — then a crossover frequency and an alignment: Linkwitz-Riley at 12 or
24 dB per octave, Butterworth at 6, 12 or 24, or Bessel at 12. It writes the filters
into every output the split touches, sets ganging and input routing to match, and
leaves the filters staged so nothing is heard until applied. Apply always pushes all
amplifiers, so a crossover spanning both can never go live by halves. Layouts the
wiring rules out are not offered — a bridged amplifier has no separate A and B to
split across.

Steeper alignments cost more slots, because sections cascade. A Linkwitz-Riley is two
cascaded Butterworths of half its order, so LR2 is two 1st-order Butterworths — real
poles, which collapse into a single biquad at Q 0.5 — while LR4 is two Butterworth 2
sections at Q 0.707 and cannot be folded into one. That is why a 24 dB per octave
split shows two Butterworth 2 sections rather than one Linkwitz-Riley 2: both would
slope at 24 dB per octave, but only the Butterworth pair sits 6 dB down at the corner,
which is what lets the two branches sum flat. Two Linkwitz-Riley 2 sections would be
12 dB down there and sum 6 dB short.

Each section also has an **Inv** box that flips its polarity. The builder sets this
itself and does not offer it as a choice, because the alignment decides it: at the
corner the branches sit 180° apart at 12 dB per octave and need opposite polarity to
sum flat, but they are back in phase at 24, where inverting would instead dig a notch.
Only one section of a branch ever carries it — polarity belongs to the chain, and
since sections multiply, inverting an even number of them cancels back to none. The
box is still there by hand for drivers wired out of phase. A section left on Bypass
with Inv ticked is a plain polarity flip and costs nothing else.

### Fitting to a measurement

**Fit to a measurement…** turns a measured response into a correction. Load a frequency
response export — REW text, or any file with a frequency and a level in its first two
columns — and the fitter searches for the peaking filters and shelves that flatten it,
then writes them into the chain. Only the shape is fitted, never the absolute level. The
response graph gains two overlays, the measurement as it was and as it would be once
corrected, so the fit can be judged before anything is applied.

Three settings matter more than the rest. The fit range decides where the effort goes: a
driver rolls off at its ends by more than any filter can undo, and leaving the range
wide spends filters fighting that instead of correcting the band the driver covers — the
page says so when the measurement is already well down at the low limit. Smoothing sets
how much detail is chased, and a sixth of an octave keeps the room modes while ignoring
the fine structure that moves when the microphone does. The boost and cut limits apply
to the summed correction rather than to any one filter, and the result reports how much
boost was used, so the same amount can come off that output's level to keep the
headroom.

**Keep first N sections** protects the head of the chain. The fit replaces everything
past that count, so on a bi-amped speaker keep the crossover, measure each way through
it, and fit into what is left; the count is filled in from any low or high passes
already sitting at the top of the chain. Kept sections are slots the fitter cannot have,
so **Filters to use** caps itself at what remains — a 24 dB per octave crossover leaves
13 of the 15. Fitted filters are staged like any other edit — nothing is heard until
applied and nothing survives a reboot until committed.

Each amplifier carries its own input routing: the stereo pair as-is, summed to
`(L+R)/2`, or one channel fed to both outputs. A bridged amplifier drives a single voice
coil, so it is always fed a single channel and defaults to the sum; ganging is implicit
and the stereo option is not offered. A combined response graph at the top of the page
plots every active output together, so a crossover spread across both amplifiers can be
read as one picture.

**Show what the outputs sum to** adds one more trace to that graph. Outputs feeding
separate drivers add as vectors and not as curves, so two branches that each look right
alone can still cancel where they overlap — and the two curves look identical either
way round, which is what makes it easy to miss. The sum is taken on the complex
response instead: a crossover is right when it runs flat through the corner, and a dip
there means the branches are fighting, so one of them needs **Inv**. The trace knows
only the filters, never the drivers, their spacing or the room, so it shows what the
crossover is aiming at rather than what a microphone would hear.

Levels are set in the Volume section. Master is the AirPlay volume and moves
everything together. Below it each output has its own level and mute, applied in the
DSP input mixer ahead of the filters — so they only ever attenuate and cost no filter
headroom. Use them to match drivers of differing sensitivity. Levels and mutes take
effect immediately and are stored in NVS, independently of the filter commit.

## Full PPC3 tuning

!!! info "TAS5825M only"

    This whole section applies to boards fitted with a TAS5825M. A TAS5805M brick has no
    process flow to replay and ignores these files \u2014 see
    [TAS5805M boards](#tas5805m-boards).

The Equaliser page covers the fifteen biquads per channel, the crossover and the levels,
which is the whole signal path for most builds. A tuned dump from TI PurePath Console 3
goes further: it is the complete device configuration — clocking, I2S format, the process
flow select and every coefficient — so it reaches blocks the web interface does not
expose. That includes flows whose coefficient map TI never published, because a dump
replays TI's own register writes rather than addresses we would have to know.

At boot the driver looks for a dump on SPIFFS and, if one is present, replays it *instead
of* the built-in init sequence. PPC3 bakes every coefficient at the rate the flow was
exported for, so a 48 kHz tuning played at 44.1 kHz puts every corner about 8% low: name
the file for its rate and the driver picks the one matching what it is playing.

| File | Applies to |
| --- | --- |
| `/spiffs/hf/tas5825m_fw-44100.bin` | the only amplifier, or the first of two, at 44.1 kHz |
| `/spiffs/hf/tas5825m_fw-48000.bin` | the same, at 48 kHz |
| `/spiffs/hf/tas5825m_fw0-44100.bin` | first amplifier on a dual-DAC board, at 44.1 kHz |
| `/spiffs/hf/tas5825m_fw1-44100.bin` | second amplifier on a dual-DAC board, at 44.1 kHz |

Drop the `-<rate>` suffix — `tas5825m_fw.bin`, `tas5825m_fw0.bin` — for a dump that
should serve every rate. Those names are the fallback, searched only once no
rate-specific file matches, so a single-rate install keeps working untouched. A process
flow is a TAS5825M feature, so the driver only looks for any of these on that part —
see [TAS5805M boards](#tas5805m-boards).

To install one:

1. Tune the part in PPC3 and export either the I2C log (`.cfg`) or the C header, at each
   sample rate you want covered.
2. Convert it:
   ```bash
   python3 components/dac_tas58xx/ppc3_convert.py my_tuning_44k1.cfg -o tas5825m_fw-44100.bin
   ```
   A log that drives both amplifiers carries writes for each, so pick one with
   `--dev 98` or `--dev 9a` and convert it twice.
3. Copy the result to `data/hf/` for a serial flash, or upload it over WiFi:
   ```bash
   curl -X POST "http://<device-ip>/api/fs/upload?path=/spiffs/hf/tas5825m_fw-44100.bin" \
        --data-binary @tas5825m_fw-44100.bin
   ```
4. Reboot.

Delete the file to go back to the built-in flow.

!!! warning

    A dump owns the configuration, so the driver stops writing its own signal-path
    defaults and trusts the tuning instead. Get the clocking or the I2S format wrong
    and the part will not play — keep a serial console attached the first time.

The biquad addresses are identical in every documented flow on both the TAS5825M and the
TAS5805M, so the Equaliser page keeps working on top of a dump. A dump that selects an
undocumented flow is the exception: nothing guarantees its coefficients live where the
page expects them.

## Variants

| Environment | Chip | Bluetooth | Notes |
| --- | --- | :-: | --- |
| `esparagus-audio-brick` | ESP32 | — | AirPlay + Ethernet |
| `esparagus-audio-brick-bt` | ESP32 | yes | Prebuilt binary published |
| `esparagus-audio-brick-s3` | ESP32-S3 | — | S3 pinout, PSRAM, no Bluetooth Classic on this chip |
| `esparagus-audio-brick-dual-dac` | ESP32-S3 | — | [Rev D](esparagus-audio-brick-dual-dac.md), two TAS5825M: stereo at 0x4C, second at 0x4D |
| `esparagus-audio-brick-dual-uac` | ESP32-S3 | — | [Rev D](esparagus-audio-brick-dual-dac.md) as a USB audio device |

Bluetooth Classic exists only on the original ESP32, so the `-bt` build has no S3
equivalent; an S3 brick reaches the network over Ethernet or WiFi. Rev D has two
amplifiers and a pinout of its own, and gets [its own page](esparagus-audio-brick-dual-dac.md).

### Esparagus Louder

The Esparagus Louder is the same TAS5825M design with additional gain.

| Environment | Chip | Bluetooth | Prebuilt |
| --- | --- | :-: | :-: |
| `esparagus-louder` | ESP32 | — | — |
| `esparagus-louder-bt` | ESP32 | yes | — |
| `esparagus-louder-s3` | ESP32-S3 | — | yes |

```bash
pio run -e esparagus-louder-s3 -t upload
pio run -e esparagus-louder-s3 -t uploadfs
```

## Related

- [Bluetooth A2DP](../features/bluetooth.md)
- [Ethernet (W5500)](../features/ethernet.md)
- [Build environments](../reference/build-environments.md)

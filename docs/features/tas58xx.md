# TAS58xx DAC

The **TAS5825M** and **TAS5805M** are Class-D audio DACs with on-chip DSP. They
feature a 15-section biquad EQ per channel, hybrid flow DSP (TAS5825M only), and
hardware volume control with configurable maximum level.

!!! note "TAS5825M vs TAS5805M"

    Both parts share the same driver and web interface, but there are important
differences:

    | Feature | TAS5825M | TAS5805M |
    | --- | :-: | :-: |
    | Process flow (PPC3) | ✓ | ✗ |
    | 15-band biquad EQ | ✓ | ✓ |
    | Input mixer (mono routing) | ✓ | ✗ |

    The input mixer allows summing L+R to mono or feeding one channel to both outputs.
    This is only available on the TAS5825M. A TAS5805M passes stereo straight through.

## Hardware requirements

PBTL (mono) mode is available on both parts. The firmware detects which chip you have at
boot.

## Biquad Equaliser

Both parts expose the DAC's 15 cascaded biquad sections through the device's web
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
leaves the filters staged so nothing is heard until applied. **Apply** always pushes all
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

Levels are set in the Output card. The volume at the top of the page is the AirPlay
volume and moves everything together; each output has its own level and mute, applied in the
DSP input mixer ahead of the filters — so they only ever attenuate and cost no filter
headroom. Use them to match drivers of differing sensitivity. Levels and mutes take
effect immediately and are stored in NVS, independently of the filter commit.

On a board with one amplifier, **EQ runs on** in the same card can move the filters
off the amplifier's DSP and onto the ESP32's software EQ, with the DSP's sections set
flat. The software EQ turns the signal down ahead of the filters by as much as they
boost, and the amplifier's volume gives that back, so the two sound the same unless
one of them is wrong: a quick check of the DSP path by ear. The ESP32 runs the
filters at the stream's rate (44.1 or 48 kHz) rather than the DSP's, so filters near
the top of the audio band come out slightly different. The choice is stored in NVS
(`CONFIG_SOFTWARE_EQ_AB`).

## PBTL (Mono) Mode

TAS58xx amplifiers can be wired in **Parallel Bridge-Tied Load (PBTL)** mode to drive a
single speaker from both outputs, summing the left and right channels into one voice coil.
This is often used for subwoofers or in space-constrained installations where a single
driver suffices.

!!! warning "You must rewire the amplifier"

    PBTL mode changes what the outputs drive. An output that was wired to one speaker must
    instead be wired to a single driver, and *both* outputs must drive that same driver.
    Leaving them wired for stereo while the amplifier is in PBTL mode shorts the two
    outputs against each other and can damage the amp.

### How it works

The PBTL setting is a control-port register on the TAS58xx. It can only be changed while
the amplifier is idle — the output stage must not be driving a load. The firmware sets it
on every power-on, so to change it you must:

1. Change the PBTL setting in the web interface
2. Power off the board
3. Rewire the speakers
4. Power on the board

The firmware stores the PBTL setting in NVS so it survives reboots. When PBTL is active
on the primary amplifier, the input routing defaults to **mono (L+R)** and the stereo
option is not offered — a bridged amplifier drives one output, so feeding it stereo has no
meaning.

A TAS5805M has no input mixer to sum with, so a bridged one plays the left I2S channel.
The output **channel mode** decides what that carries instead, and it starts on mono
(L+R) on a board built with `CONFIG_TAS58XX_FORCE_PBTL`.

### Configuration options

#### From web UI (when not forced)

The web interface at `http://<device-ip>/` has a **Primary Amplifier** dropdown under
the Channel section. Select:

- **Stereo (BTL)** — Standard stereo: left drives one speaker, right drives the other
- **Bridged mono (PBTL)** — Both outputs drive one speaker, summing L+R

!!! note "Restart required"

    Changing the PBTL setting only takes effect after a reboot. The web UI indicates this
    with the message "Restart to apply the new wiring."

#### From menuconfig (forced mode)

To prevent accidental changes, PBTL can be forced in `menuconfig`:

```bash
pio run -e <env> -t menuconfig
```

Navigate to **DAC Configuration** → **TAS58xx DAC options** and set:

- **Force PBTL (mono) mode on primary amplifier** — Enable to lock the setting

When forced:

- The PBTL dropdown is present in the web UI
- Clicking **Apply** returns an error: "PBTL mode is forced by configuration and cannot be changed"
- The web UI shows: "PBTL mode is forced by configuration and cannot be changed"

### API

The `/api/audio/pbtl` endpoint returns:

```json
{
  "devices": 1,
  "pbtl": true,
  "restart_required": false,
  "forced": true,
  "success": true
}
```

- `pbtl` — Current PBTL setting
- `restart_required` — Whether a reboot is needed for the stored value to take effect
- `forced` — Whether PBTL mode cannot be changed from the web UI

POST to change (only when not forced):

```bash
curl -X POST "http://<device-ip>/api/audio/pbtl" \
     -H 'Content-Type: application/json' -d '{"pbtl": true}'
```

## Full PPC3 Tuning (TAS5825M only)

!!! info "TAS5825M only"

    This whole section applies to boards fitted with a TAS5825M. A TAS5805M has no
    process flow to replay and ignores these files — see the note at the top of this page.

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
see the note at the top of this page.

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

## Related

- [HybridFlow DSP (TAS57xx)](hybridflow.md) — Different hardware, different tuning options
- [Build environments](../reference/build-environments.md)

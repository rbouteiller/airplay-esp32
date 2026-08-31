# HybridFlow DSP (TAS57xx)

Some TAS57xx amplifiers carry a small DSP core — TI calls it the miniDSP — that can run a
signal chain in front of the output stage. TI ships those chains as **HybridFlow** process
flows, and the firmware can load one, tune it live from a web page, and keep the tuning
across reboots.

The tuning page is at `http://<device-ip>/hf`, or **HybridFlow Tuning** on the settings
page. It only appears on a build with `CONFIG_DAC_TAS57XX`.

## Hardware requirement

!!! warning "You need a TAS57xx that has a miniDSP"

    Not every part in the family has one. The DSP-capable devices are the "M" variants —
    TAS5754M, TAS5756M and their relatives — and only those can run a HybridFlow. A
    TAS578x has no miniDSP at all: the driver detects it at boot and skips flow loading
    entirely, leaving the part on its built-in stereo program.

!!! note "Only tested on the TAS5754M"

    All of this has been developed and tested against a **TAS5754M** (the SqueezeAMP's
    amplifier). Other DSP-capable parts in the family are register-compatible on paper and
    are expected to work, but nobody has run them. Treat them as unverified: check the boot
    log for the flow verification, and be ready for the tuning page to report that no flow
    is available.

Check what the part is doing from the boot log or from the API:

```bash
curl "http://<device-ip>/api/hf/flow"
# {"active":1,"sample_rate":44100,"available":[1,3],"success":true}
```

`active` is `0` when no flow is loaded, and `available` lists the flows this device has a
base image for.

## The two flows

Both are stereo in, two channels out, and only one can be resident at a time — they map
coefficient RAM differently.

=== "HybridFlow 1 — full range"

    A conventional stereo chain, the same processing on both channels:

    ```
    In → Biquad EQ (10 bands) → PBE → DBE → Compander → Volume → Smooth clip → Out
    ```

    PBE is psychoacoustic bass, DBE dynamic bass, and the compander is a three-band
    compressor/expander. Tune in that order: volume ceiling first, then EQ for the baseline
    response, then the compander and smooth clipper for power limiting, then DBE and PBE.

=== "HybridFlow 3 — bi-amp"

    The two amplifier outputs stop being left and right. The input feeds two ways in
    parallel, each with a crossover leg and four EQ bands, and they are recombined into a
    shared compander and clipper:

    ```
    In ─┬→ Low way  → PBE → DBE ─┬→ Compander → Smooth clip → Volume → Out
        └→ High way → Delay ─────┘
    ```

    Channel A drives the woofer, channel B the tweeter. The high way's delay aligns its
    acoustic centre with the low way's. Only the low way gets the bass enhancers.

=== "No processing"

    Flow `0` removes the working flow and hands playback back to the part's ROM stereo
    program: plain left and right with digital volume, no crossover, EQ or dynamics. This
    is the only setting available on a part without a usable HybridFlow, and it discards
    nothing but the flow file — saved tunings stay.

!!! danger "Switching to bi-amp changes what your speakers see"

    A tweeter wired to an output that suddenly carries full-range bass will not survive it.
    The firmware drops the volume to minimum on any flow change and leaves it there, so
    confirm the wiring before turning it back up.

## Base flows and sample rates

The flow images live in SPIFFS under `/spiffs/hf/`. The repository tracks four pristine
base images:

```
base-hf1-44100.bin   base-hf1-48000.bin
base-hf3-44100.bin   base-hf3-48000.bin
```

Coefficients are designed for one sample rate, so each flow has a 44.1 kHz and a 48 kHz
twin. The driver picks the one matching the running output rate and swaps to the other if
the rate changes, replaying the saved tuning onto it. The bases are copied to the working
flow rather than played from directly, so a commit can never scribble on them.

Selecting a flow rewrites the working flow and re-downloads it:

```bash
curl -X POST "http://<device-ip>/api/hf/flow" \
     -H 'Content-Type: application/json' -d '{"flow":3}'
```

## Apply, Commit and Revert

The tuning page distinguishes three things, and the difference matters:

| Action | What it does | Survives |
| --- | --- | --- |
| **Apply** | Writes the tuning into the DSP's coefficient RAM so you can hear it | Playback, standby, a Bluetooth handover |
| **Commit** | Bakes the tuning into the flow image and writes it to SPIFFS | Reboots and flow reloads |
| **Revert** | Reloads the committed flow from SPIFFS, dropping the audition | — |

Auditioning is free: nothing is written to flash until you commit, and a reboot always
brings back the last committed tuning.

Master volume and the per-channel trims sit *outside* this. They are the part's own
registers, the same ones AirPlay drives, so they apply immediately and are saved
separately — they work even with no flow loaded. The fine volume trim is the exception: it
is a gain inside the flow, so it belongs to the tuning and only Commit persists it.

## Where the files live

| Path | Contents |
| --- | --- |
| `/spiffs/hf/base-hf<n>-<rate>.bin` | Pristine base flow, never written to |
| `/spiffs/hf/tas57xx_fw.bin` | The working flow, rewritten by Commit |
| `/spiffs/hf/hf1.cfg` | Committed HF1 tuning |
| `/spiffs/hf/hf3.cfg` | Committed HF3 tuning |

A `.cfg` records the parameters the flow image cannot — filter shapes, band types — so the
page can show a peaking filter as a peaking filter rather than as six raw coefficients. It
is only trusted while it still reproduces the flow byte for byte; if the flow has been
replaced since, the flow wins and the page says so.

Uploading a flow by hand still works, if you have a PurePath Console export:

```bash
curl -X POST "http://<device-ip>/api/fs/upload?path=/spiffs/hf/tas57xx_fw.bin" \
     --data-binary @my_flow.bin
```

See [SPIFFS filesystem](../reference/spiffs.md) for the rest of the file API.

## Troubleshooting

**The page says "No processing" and the flow selector is empty.** No base image for the
current sample rate is present. Check `curl "http://<device-ip>/api/fs/list?dir=/spiffs/hf"`
and re-flash SPIFFS with `pio run -e <env> -t uploadfs` if it is empty.

**The page loads but every control is disabled.** The part has no usable miniDSP, or the
flow failed verification. The boot log reports both.

**A tuning stopped matching after a firmware update.** SPIFFS is not touched by an OTA app
update, so the old `.cfg` is still there. If the flow image changed, the driver falls back
to reading the tuning out of the flow itself and logs a warning.

## Related

- [SqueezeAMP](../boards/squeezeamp.md)
- [SPIFFS filesystem](../reference/spiffs.md)
- [AirPlay tuning](airplay-tuning.md)

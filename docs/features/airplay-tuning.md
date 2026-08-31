# AirPlay tuning

Advanced timing and metadata options live under **AirPlay Receiver → AirPlay Protocol** in
`menuconfig`. The defaults suit most setups — change these only if you hear drop-outs or
want to control what metadata is received.

## Cover art

Album cover art is **disabled by default**. Most receivers have no screen, or only a small
OLED, and pulling artwork over the RTSP connection can stall the audio pipeline and cause
drop-outs — especially on unbuffered AirPlay 1 / realtime streams.

When disabled, the receiver drops artwork type `1` from its advertised `md` txt record so
senders do not transmit cover art at all, and ignores any that arrives anyway. Track title,
artist, album and progress metadata are always received.

To enable it, for instance when you have a [TFT display](tft-display.md):

```bash
idf.py menuconfig
# AirPlay Receiver → AirPlay Protocol
# Enable "Enable cover-art / artwork reception"
```

Or in your sdkconfig defaults:

```ini
CONFIG_ENABLE_AIRPLAY_ARTWORK=y
```

## Early and late timing thresholds

The timing engine holds frames that arrive early, outputting silence until their scheduled
play time, and drops frames that arrive late. The threshold controls how much slack is
allowed before a frame is held or dropped.

Buffered AirPlay 2 streams (AAC) have a deep jitter buffer and can use a tight threshold
for precise sync. Unbuffered realtime streams (ALAC over UDP) have almost no buffer, so a
tight threshold causes audible drop-outs whenever the pipeline stalls — when metadata
arrives, for example.

| Option | Default | Applies to |
| --- | --- | --- |
| `CONFIG_AIRPLAY_TIMING_THRESHOLD_MS` | 10 ms | Buffered streams (AAC) |
| `CONFIG_AIRPLAY_RT_TIMING_THRESHOLD_MS` | 50 ms | Unbuffered realtime streams (ALAC) |

If you still hear drop-outs on AirPlay 1 / realtime playback, increase
`CONFIG_AIRPLAY_RT_TIMING_THRESHOLD_MS`, at the cost of slightly looser sync.

## Forcing AirPlay v1

Classic AirPlay v1 makes the receiver advertise itself as a plain RAOP receiver. There are
two reasons to do this:

- **Hardware buttons.** iOS only sends DACP headers in v1 mode, so this is what makes
  [hardware buttons](buttons.md#read-this-first-the-airplay-v1-requirement) work.
- **Apple Music for Windows.** It is a RAOP-only sender and refuses any device that
  advertises the `_airplay._tcp` service, reporting that the device "is not compatible
  with this version of AMPLibraryAgent". The device still appears in its picker and it
  still opens an RTSP connection — it sends `OPTIONS` with an `Apple-Challenge` and then
  walks away.

The mode lives in NVS, so no rebuild is needed. Open the web interface and pick
**Device Settings → AirPlay Mode**, then restart the device. The mDNS records and the RTSP
listening port are both built at startup, so the change only takes effect on the next boot.

In v1 mode the receiver mirrors a classic RAOP advertisement: no `_airplay._tcp`
service, a shairport-sync-style `_raop._tcp` TXT record, `Server: AirTunes/105.1` on RTSP
responses, and RTSP on port 5000 instead of 7000.

It costs you AirPlay 2 features: HomeKit pairing, encrypted transport and multi-room sync.

There is no setting that keeps both senders happy. The deciding factor for Apple Music is
the presence of `_airplay._tcp` alone — a receiver publishing a fully classic `_raop._tcp`
TXT record on port 5000 is still refused while that service is up, and starts working the
moment it is withdrawn. iOS needs the same service to negotiate AirPlay 2, and a device
publishes one advertisement, so the mode is a real either/or.

airplay-esp32 V22
=================

V22 keeps the V20 true PID PTP -> I2S clock servo and replaces V21's failed
"measure one enable, compensate a second enable" startup scheme.

Startup alignment:
- A new RTP generation disables/flushes I2S once, while priming.
- Two silent 256-frame DMA blocks are preloaded and I2S is enabled once.
- The first silent TX EOF is timestamped in the esp_timer domain and converted
  to PTP with the current filtered PTP offset.
- I2S stays running. While silent block #2 is in flight, V22 predicts the exact
  physical start boundary of DMA block #3 (one 256-frame interval later).
- The AirPlay RTP sample belonging at that physical PTP boundary is calculated
  directly from the current anchor. RTP is rounded to the nearest sample.
- The first real 256-frame PCM block is read from that exact RTP address and
  queued behind silent block #2. No second i2s_channel_enable() occurs.
- Silence probe tags use generation 0, so they never become the public SYNC
  measurement. The first real tagged EOF becomes SYNC START.

At 44.1 kHz, choosing an arbitrary RTP sample gives 1/44100 s = 22.68 us phase
resolution. There is no need for V21's measured startup compensation or a
second enable whose phase was shown to be non-repeatable.

Steady clock servo (unchanged in principle from V20):
- Feedback: tagged TX DMA EOF versus exact AirPlay RTP/PTP block-end target.
- PID calculation every 1 second.
- Physical i2s_channel_tune_rate() at most every 5 seconds.
- +/-1.0 ms is GOOD: hold the learned clock instead of chasing exact zero.
- 1..2 ms uses a softer P term; >2 ms uses full P.
- Kp=22 ppm/ms, Ki=0.55 ppm/(ms*s), Kd=55 ppm/(ms/s).
- D is low-pass filtered (alpha 0.20).
- Integral anti-windup and +/-110 ppm I-term clamp.
- Clock output clamp +/-160 ppm, max physical jump 80 ppm, ignore <5 ppm changes.

New startup log example:
  ALIGN gen=4 probe=-6.73ms shift=297 samples (+6.735ms) real_rtp=...
  SYNC START=+0.12 ms (ESP early) | DMA EOF vs AirPlay PTP

The ALIGN probe value is diagnostic only. It is not reused as a second-enable
compensation. The important result is SYNC START for the first real block.

Important: ESP-IDF 5.5 rate tuning still uses disable -> tune -> enable, so the
steady controller computes more often than it physically retunes.

airplay-esp32 V18

V18 adds an experimental closed-loop PTP -> I2S clock-rate servo on top of V17.

Feedback:
  SYNC = tagged DMA EOF vs AirPlay PTP target.
  positive SYNC = ESP/I2S early -> servo decreases MCLK
  negative SYNC = ESP/I2S late  -> servo increases MCLK

Controller:
  update period: 5 s
  deadband: +/-0.5 ms
  incremental step: 1..8 ppm depending on phase error
  clamp: +/-120 ppm

The servo calls i2s_channel_tune_rate() using the ESP-IDF-required
disable -> tune -> enable sequence, and only from the Core1 playout task between
application writes. This is experimental: Espressif warns that changing the
rate while audio is playing can produce plosive/glitch artifacts. Watch for
audible clicks and DMA/tag errors.

Compact log example:
  SYNC=-2.40ms S=+18ppm | VOL=11% CMD=0 PK=100% CLIP=0 | ...

Expected behavior:
  when SYNC is negative, S should walk positive every ~5 s until SYNC bends
  toward zero; if SYNC crosses positive beyond +0.5ms, S should walk downward.

No AAC/PCM ring, volume, RTP admission, or PTP anchor logic was intentionally
changed.

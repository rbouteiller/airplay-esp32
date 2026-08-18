airplay-esp32 V19

V19 replaces the slow V18 incremental servo with a phase PI-D/PLL controller.

Feedback:
  SYNC = tagged DMA EOF vs AirPlay PTP target
  SYNC < 0 = ESP late  -> increase I2S rate
  SYNC > 0 = ESP early -> decrease I2S rate

Controller:
  update period: 8 s
  deadband: +/-0.25 ms
  Kp: 18 ppm/ms
  Ki: 0.25 ppm/(ms*s)
  Kd: 30 ppm/(ms/s), derivative on measured phase
  integral clamp: +/-320 ms*s
  I2S rate clamp: +/-160 ppm
  minimum actual tune change: 4 ppm
  maximum one-shot tune jump: 80 ppm

The goal is to reach the useful rate quickly, then brake before crossing zero.
The integral learns the steady crystal/PTP rate bias. The derivative sees the
measured SYNC slope and reduces command when phase is already moving toward zero.

Because IDF 5.5 i2s_channel_tune_rate() requires READY, every actual tune still
uses disable -> tune -> enable. V19 therefore suppresses tiny changes and updates
only every 8 s, reducing the number of phase-disturbing tune operations.

Compact log example:
  SYNC=-2.40ms S=+82/+74ppm d=+0.080ms/s | VOL=11% ...

S=actual/target ppm. d is measured phase slope; positive means SYNC is moving
upward (for a negative SYNC this means it is moving toward zero).

No AAC/PCM ring, RTP admission, volume, PTP anchor, or tagged-DMA measurement
logic was intentionally changed.

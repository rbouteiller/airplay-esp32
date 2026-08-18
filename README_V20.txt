airplay-esp32 V21
=================

V21 replaces the V19 PI-D experiment with a true PID-style PTP -> I2S clock servo.

Control policy:
- Feedback: tagged TX DMA EOF versus exact AirPlay RTP/PTP block-end target.
- PID calculation every 1 second.
- Physical i2s_channel_tune_rate() at most every 5 seconds.
- +/-1.0 ms is GOOD: hold the learned clock instead of chasing exact zero.
- 1..2 ms uses a softer P term; >2 ms uses full P.
- Kp=22 ppm/ms, Ki=0.55 ppm/(ms*s), Kd=55 ppm/(ms/s).
- D is low-pass filtered (alpha 0.20).
- Integral anti-windup and +/-110 ppm I-term clamp.
- Clock output clamp +/-160 ppm, max physical jump 80 ppm, ignore <5 ppm changes.

Compact log:
  SYNC=-0.82ms S=+71/+71ppm d=+0.03ms/s | ...

S is actual/target clock correction. d is filtered SYNC slope.

Important: IDF 5.5 rate tuning still uses disable -> tune -> enable, so the
controller deliberately computes more often than it physically retunes.

airplay-esp32 V12
=================

Purpose
-------
V12 is a diagnostic-only follow-up to V11. It does not intentionally change
receive, decode, PCM buffering, priming, I2S format, or playout correction.

The goal is to locate the ~15-16 ms phase seen by V11 before applying any
compensation.

New STAT field
--------------
  phase_frames(loop=...,start=...,end=...)

loop:
  cursor_rtp - desired_rtp computed by the scheduler at the start of the
  playout iteration. Positive means the sequential I2S cursor is ahead of
  current PTP-derived wanted RTP.

start:
  block_start_rtp - wanted_rtp_at(write_begin_ptp)

end:
  block_end_rtp - wanted_rtp_at(write_end_ptp)

At 44.1 kHz:
  256 frames = 5.805 ms
  512 frames = 11.610 ms
  768 frames = 17.415 ms
  1024 frames = 23.220 ms

Interpretation
--------------
If phase_frames stays around +650..+750 while txerr_us stays around -15..-16ms,
the offset is already present in the sequential playout cursor. The current
resync threshold is +/- 4 blocks (=1024 frames), so such an error is allowed
and will not trigger a resync. That would identify the scheduler phase policy,
not DMA, as the source.

If loop is near zero but start/end are displaced, the offset is introduced
between scheduler selection and I2S submission/output timing.

Keep CONFIG_AP2_PLAYOUT_TEST_OFFSET_US=0 for this diagnostic.

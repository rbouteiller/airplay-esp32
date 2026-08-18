airplay-esp32 V13
=================

V13 fixes the playout phase error measured by V12. V12 showed a persistent
+450..700 frame cursor lead that matched the -10..-16 ms PTP timing error.
The lead was created when an empty I2S DMA ring accepted several 256-frame
writes quickly at startup; cursor_rtp advanced into the future and the old
+/-4-block resync deadband allowed that phase to persist.

V13 changes only playout scheduling:
- desired_rtp is wanted_rtp at current PTP time.
- PCM may be fetched early, but each 256-frame block is held until the exact
  PTP presentation time of its first RTP sample before i2s_channel_write().
- Long waits yield to FreeRTOS; only the final sub-ms window uses short delays.
- Gross cursor resync deadband is tightened from +/-4 to +/-2 blocks.
- AAC ring, PCM ring, decoder, admission window and 250 ms priming are unchanged.
- test_off_us remains diagnostic; positive values deliberately submit early.

Expected at test_off_us=0:
- phase_frames(start=...) near 0 instead of hundreds of frames.
- txerr_us(start=...) near 0 instead of -10..-16 ms.
- underrun remains 0 after priming.

ZIP integrity was checked; no ESP-IDF build was run in the assistant environment.

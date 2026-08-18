airplay-esp32 V17

Based on V15 tagged-DMA/PTP playout.

V17 changes:
- AirPlay SET_PARAMETER volume is now applied to PCM output.
- Correct dB amplitude mapping: 0 dB = unity, -144 dB = mute.
- 256-frame gain ramp prevents clicks/zipper noise when volume changes.
- No normalization/AGC is performed; decoded AAC stays signed 16-bit PCM.
- Compact log adds VOL, PEAK, RAIL and CLIP:
    SYNC=-0.20ms | VOL=50% PEAK=91% RAIL=0 CLIP=0 | ...
  PEAK = source PCM peak during the latest stats interval, before volume.
  RAIL = source samples exactly at int16 rails during the interval.
  CLIP = samples clipped by our software gain (should always stay 0 because V17 never boosts above 0 dB).
- RTSP control logs volume changes in dB and linear amplitude percent.

V15 tagged DMA synchronization architecture is otherwise unchanged.

V17 log cleanup:
- No per-command VOLUME ESP_LOGI on the RTSP/control path.
- CMD in the 2 s compact audio line is the number of volume target updates since the previous line.
- Compact RUN format: SYNC | VOL/CMD/PK/CLIP | PCM/AAC | U/R/DROP/COLL/DEC/DMA.

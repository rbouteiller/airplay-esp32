airplay-esp32 V10

Changes from V9:
- Keeps the V9 RTP admission filter, 47.5 s AAC ring, ~4 s PCM target and 250 ms PRIMING unchanged.
- Adds I2S/DMA timing diagnostics for ESP + MacBook multiroom latency investigation.
- STAT now reports qdma, dmasub, dmasent, I2S blocking write time (last/average/max), wanted RTP now, estimated RTP at the I2S TX boundary and sync_us.
- Adds CONFIG_AP2_PLAYOUT_TEST_OFFSET_US in menuconfig, default 0, range -200000..+200000 us.
  Positive values advance ESP audio; negative values delay it. Keep 0 for the first measurement.
- The test offset changes only the PTP->RTP playout target; it does not change AAC/PCM buffering.

Suggested first test:
1. Leave AirPlay playout test offset at 0 us.
2. Group the ESP with the MacBook and play continuously for at least 15-20 seconds.
3. Send several steady-state STAT lines. Focus on wr_us(...), qdma, dmasub/dmasent, sync_us and test_off_us.
4. If the ESP is consistently late by an audible fixed amount, set a positive test offset (for example +10000 us, then +20000 us) and compare again.

Interpretation:
- sync_us < 0: estimated ESP I2S output RTP is behind the AirPlay/PTP wanted RTP.
- sync_us > 0: estimated ESP I2S output RTP is ahead.
- The value is diagnostic; the final correction should be based on repeated stable measurements and listening against the MacBook.

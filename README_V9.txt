airplay-esp32 V9

Changes from V8:
- Adds RTP admission filtering when anchor+PTP produce a valid wanted RTP.
- Allowed input window: wanted RTP - 1 second through wanted RTP + 45 seconds.
- Packets outside the window are intentionally dropped before AAC-ring insertion and counted as timeline_drop.
- The check runs before decrypt and again before ring publication.
- Rejected transition leftovers do not update continuity/last_rtp diagnostics.
- V8 250 ms PRIMING, 4 s PCM target, 47.5 s AAC ring and I2S playout are unchanged.

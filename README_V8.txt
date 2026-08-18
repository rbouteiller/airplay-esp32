airplay-esp32 V8

Changes on top of V7:

1. Anchor-committed timeline generations.
   Immediate FLUSH / pause invalidates the active anchor and flushes I2S, but
   does not publish a new ring generation yet. TCP may continue receiving into
   a provisional epoch. The next valid SETRATEANCHORTIME commits a fresh
   generation in O(1), making all pre-anchor AAC/PCM tags unreachable.

2. Playout priming state.
   STOPPED -> PRIMING -> RUNNING. On a new committed timeline, I2S does not
   report startup PCM holes as underruns. The decoder is allowed to build a
   contiguous 250 ms PCM window beginning at the current PTP-derived wanted
   RTP. Only then does playout enter RUNNING. wanted RTP keeps advancing while
   priming, so old audio is never replayed late.

3. Discontinuity-safe diagnostics.
   rx_ahead_ms is emitted only when last_rtp belongs to the currently committed
   generation and the signed RTP delta is inside the AAC ring address span.
   This prevents meaningless multi-hour values while old/provisional RTP and a
   new anchor coexist briefly.

4. New stats:
   primewait= number of scheduler iterations spent waiting for priming PCM
   starts=    playout transitions into RUNNING
   pstate=    0 STOPPED, 1 PRIMING, 2 RUNNING

Steady-state AAC/PCM ring sizes and direct RTP addressing are unchanged.

This archive was not built with ESP-IDF inside the ChatGPT container.

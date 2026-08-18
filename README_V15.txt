airplay-esp32 V15
=================

Goal
----
Measure the real I2S/DMA output phase instead of estimating it from queue depth.

Changes vs V14
--------------
- I2S TX stays disabled after init/flush.
- At every new AirPlay epoch, two 256-frame RTP-tagged blocks are preloaded into
  the two DMA descriptors before I2S is enabled.
- First block is scheduled one block (~5.805 ms) into the future, both blocks
  are preloaded, then I2S is enabled at the exact PTP target of the first block.
- Every subsequent 256-frame write carries {RTP, generation, frames} metadata.
- TX on_sent ISR pops the matching oldest tag and timestamps the exact DMA EOF
  edge with esp_timer_get_time().
- Playout task converts that local EOF timestamp to PTP and compares it with
  the exact AirPlay target PTP for the end of that RTP block.
- SYNC sign:
    + = ESP DMA output edge is early
    - = ESP DMA output edge is late
- First completion of every generation prints:
    SYNC START=-0.23 ms (ESP late) | DMA EOF vs AirPlay PTP
- Periodic log is intentionally compact:
    SYNC=-0.18 ms | PCM=4000ms AAC=24000ms | U=0 R=0 DROP=0 COLL=0 DEC=0 DMAERR=0
- DMAERR counts untagged EOF callbacks or completion-queue overflow. It should
  stay 0. A non-zero value means the tag<->DMA FIFO relationship was lost.
- Fixed the V14 boot I2S pin log argument order.

Unchanged
---------
AAC direct RTP ring, admission window, decoder, ~4 s PCM target, 250 ms
priming, generation handling and RTSP/PTP control logic are otherwise kept.

Build note
----------
This package was not built with ESP-IDF in the artifact container. ZIP
integrity and source/patch consistency were checked only.

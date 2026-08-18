airplay-esp32 V14
==================

V14 replaces V13 per-block PTP gating with a deterministic two-descriptor I2S
pipeline: the first block of every timeline starts on its exact AirPlay PTP
edge, the next block is queued immediately, and subsequent writes are paced by
DMA turnover. This means one future 256-frame block (~5.80 ms) is intentionally
queued while the current block is being transmitted.

The scheduler compares PTP against an estimated physical output RTP (submit
cursor minus current+queued blocks), not against the software submit cursor.
A large phase error flushes DMA and re-primes instead of jumping over queued
audio.

The periodic audio log is intentionally compact:
  SYNC=+0.12 ms | I2S=current+1blk(5.80ms) | PCM=4000ms AAC=25000ms | U=0 R=0 DROP=0 COLL=0 DECERR=0 | state=RUN

SYNC is printed first. Positive means the ESP output estimate is ahead of the
AirPlay PTP/RTP target; negative means late. Target is near 0 ms.

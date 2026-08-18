airplay-esp32_V6

V6 keeps the V5 two-ring architecture and the Core1 watchdog fix.

AAC RTP ring semantics:
- TCP RX never intentionally waits for the decoder.
- Each decrypted AAC AU is placed by its RTP key.
- A slot from an older generation is overwritten immediately.
- Within the same generation, a newer RTP that wraps onto the same physical slot supersedes the older RTP.
- An older/out-of-order RTP never evicts newer data.
- READY/READING/WRITING/FREE are concurrency states only, not timeline validity.
- When Core1 takes an AAC AU it copies it to private scratch and marks the slot FREE before decode.
- FLUSH/seek/pause increments generation in O(1); no 2048-slot purge/scan is performed.

PCM ring remains 256 x 1024 stereo frames (~5.94 s) with a ~4 s decoded target.

New diagnostic field: aac_replace counts same-generation older slots superseded by newer RTP after circular wrap. aac_collision should represent only a genuine non-overwritable/busy or older-incoming conflict.

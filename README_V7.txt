airplay-esp32 V7

Adds the first real PTP/RTP -> PCM ring -> I2S playout path on top of the stable V6 AAC/PCM buffering architecture.

Core 0: Wi-Fi/lwIP/PTP/RTSP/AP2 TCP RX + decrypt.
Core 1: high-priority 256-frame I2S playout (prio 8) + lower-priority AAC decode (prio 6).

I2S defaults (same ESP32-S3 generic mapping used by the earlier project):
  MCLK GPIO8
  BCLK GPIO11
  LRCK/WS GPIO13
  DOUT GPIO12
These are configurable in menuconfig under I2S Playout (V7).

Playout is RTP-addressed and time driven from PTP + anchor. Missing PCM produces silence without shifting the RTP timeline. Immediate flush invalidates generation and flushes DMA. Deferred flush no longer destroys PCM immediately; it is armed to the supplied RTP boundary.

This archive was not built with ESP-IDF inside the ChatGPT container.

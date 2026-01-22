# AirPlay 2 Receiver for ESP32-S3 N16R8 - Implementation Plan

## Project Overview

Build a full AirPlay 2 receiver running on ESP32-S3 N16R8 with PCM5102A I2S DAC, supporting HomeKit authentication, FairPlay v3 DRM, and buffered audio streaming.

**Key Integration**: Leverage [HomeKey-ESP32](https://github.com/rednblkx/HomeKey-ESP32) project structure and its [HomeSpan](https://github.com/HomeSpan/HomeSpan) component for HAP cryptography (libsodium for Ed25519/X25519/ChaCha20-Poly1305, SRP, HKDF).

## Hardware Configuration

- **MCU**: ESP32-S3 N16R8 (Dual-core LX7 @ 240MHz, 16MB Flash, 8MB PSRAM)
- **DAC**: PCM5102A (32-bit, 384kHz, I2S input, no MCLK required)
- **Connectivity**: WiFi 802.11 b/g/n

### I2S Pin Assignment (Configurable)
| Signal | GPIO | Description |
|--------|------|-------------|
| BCLK   | 5    | Bit clock   |
| LRCK   | 6    | Word select (L/R clock) |
| DIN    | 7    | Data out to DAC |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        iOS/macOS Device                         │
└─────────────────────────────────────────────────────────────────┘
                                │
                                │ WiFi
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                         ESP32-S3                                │
│                                                                 │
│  ┌────────────────────────────────────────────────────────┐    │
│  │                    HomeSpan Library                     │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐   │    │
│  │  │libsodium│  │  SRP.h  │  │ HKDF.h  │  │ TLV8.h  │   │    │
│  │  │Ed25519  │  │ 3072-bit│  │SHA-512  │  │ Parser  │   │    │
│  │  │X25519   │  │         │  │         │  │         │   │    │
│  │  │ChaCha20 │  │         │  │         │  │         │   │    │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘   │    │
│  └────────────────────────────────────────────────────────┘    │
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │    mDNS      │    │   AirPlay    │    │  FairPlay    │      │
│  │  Discovery   │    │   HAP Auth   │    │     v3       │      │
│  │ _airplay._tcp│    │  (transient) │    │  (AES-CTR)   │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│         │                   │                   │               │
│         ▼                   ▼                   ▼               │
│  ┌─────────────────────────────────────────────────────┐       │
│  │              RTSP/RTP/RTCP Server                   │       │
│  │         (Control + Audio Data Channels)             │       │
│  └─────────────────────────────────────────────────────┘       │
│                            │                                    │
│         ┌──────────────────┼──────────────────┐                │
│         ▼                  ▼                  ▼                 │
│  ┌──────────┐       ┌──────────┐       ┌──────────┐            │
│  │   ALAC   │       │   AAC    │       │   OPUS   │            │
│  │ Decoder  │       │ Decoder  │       │ Decoder  │            │
│  └──────────┘       └──────────┘       └──────────┘            │
│         │                  │                  │                 │
│         └──────────────────┼──────────────────┘                │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────┐       │
│  │              Audio Buffer (PSRAM)                   │       │
│  │           ~2 seconds buffered audio                 │       │
│  └─────────────────────────────────────────────────────┘       │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────┐       │
│  │           PTP Clock Sync + Playback Timing          │       │
│  └─────────────────────────────────────────────────────┘       │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────┐       │
│  │                 I2S DMA Output                      │       │
│  └─────────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                        ┌──────────────┐
                        │  PCM5102A    │
                        │    DAC       │
                        └──────────────┘
```

---

## Implementation Phases

### Phase 1: Project Foundation (Fork HomeKey-ESP32 Structure)
**Goal**: ESP-IDF project with WiFi, mDNS, HomeSpan crypto, and I2S audio output

1. **Clone HomeKey-ESP32 Project Structure**
   - Fork/clone to get ESP-IDF + HomeSpan integration
   - Strip HomeKey-specific code (NFC, lock manager)
   - Keep: WiFi, NVS, HomeSpan component with crypto
   - Target ESP-IDF v5.x

2. **Configure for ESP32-S3 N16R8**
   - Enable Octal PSRAM mode in sdkconfig
   - Partition table: 16MB flash (app 4MB, NVS 64KB, OTA slots)
   - Verify HomeSpan builds for S3

3. **mDNS Service Advertisement**
   - Publish `_airplay._tcp` service on port 7000
   - Publish `_raop._tcp` service
   - TXT records for AirPlay 2 features (see Appendix A)

4. **I2S Audio Output**
   - Configure ESP-IDF I2S driver for PCM5102A
   - DMA double-buffering (minimize latency)
   - Support 44.1kHz/48kHz, 16/24-bit stereo
   - Test with sine wave generation

### Phase 2: AirPlay HAP Authentication (Reuse HomeSpan Crypto)
**Goal**: Implement AirPlay 2 transient pairing using HomeSpan primitives

1. **Extract Crypto from HomeSpan**
   - Use HomeSpan's libsodium integration:
     - `crypto_sign_*` (Ed25519)
     - `crypto_box_*` / `crypto_scalarmult_*` (X25519)
     - `crypto_aead_chacha20poly1305_*` (AEAD)
   - Use HomeSpan's SRP.h for SRP-6a
   - Use HomeSpan's HKDF.h for key derivation

2. **Implement Transient Pairing**
   - AirPlay 2 uses "transient" HAP pairing (no persistent storage needed)
   - Pair-Verify only (skip Pair-Setup for transient)
   - X25519 ephemeral key exchange
   - Derive session keys with HKDF

3. **Encrypted Session Layer**
   - ChaCha20-Poly1305 encryption wrapper
   - 8-byte little-endian nonce counter
   - 16-byte auth tag per message
   - Integrate with RTSP message handling

4. **Key Management**
   - Generate device Ed25519 keypair (store in NVS)
   - Generate unique device ID (48-bit MAC-based)

### Phase 3: FairPlay v3 Authentication
**Goal**: DRM handshake for encrypted audio keys

1. **FairPlay Handshake Implementation**
   - Port from [airplay2-receiver](https://github.com/openairplay/airplay2-receiver) Python
   - Message type 1: Receive challenge
   - Message type 2: Send response with FairPlay signature
   - Message type 3: Receive encrypted AES key

2. **Audio Decryption Setup**
   - AES-128-CTR mode (use mbedTLS from ESP-IDF)
   - Key/IV derived from FairPlay handshake
   - Per-packet decryption in RTP receiver

3. **FairPlay Keys**
   - Extract from airplay2-receiver or similar
   - Store securely (consider obfuscation)

### Phase 4: RTSP/RTP Protocol Stack
**Goal**: Control and media transport

1. **RTSP Server (TCP port 7000)**
   - Methods: OPTIONS, ANNOUNCE, SETUP, RECORD, PAUSE, TEARDOWN, SET_PARAMETER, GET_PARAMETER, FLUSH, POST (for /pair-*, /fp-*)
   - Parse SDP for codec information
   - Binary plist parsing (for AirPlay 2 messages)
   - Integrate HAP encryption layer

2. **RTP Receiver**
   - Audio data channel (UDP, dynamic port)
   - Control channel (UDP)
   - Timing channel (UDP)
   - RFC 2198 redundancy handling
   - Sequence number tracking, reordering buffer

3. **RTCP Handling**
   - Sender/receiver reports
   - Retransmission requests (NACK)

### Phase 5: Audio Decoders
**Goal**: Decode all supported audio formats

1. **ALAC Decoder**
   - Port Apple's libalac (Apache 2.0)
   - Primary codec for lossless streaming
   - ~200KB code size

2. **AAC Decoder**
   - Use libhelix-aac (optimized for embedded)
   - Or ESP-ADF's AAC decoder
   - LC-AAC profile

3. **Opus Decoder**
   - Port libopus
   - Used for real-time/low-latency streams

4. **Audio Pipeline**
   - Codec detection from RTP payload type / SDP
   - Decoder task with FreeRTOS queue
   - Output: 16-bit PCM to audio buffer

### Phase 6: Audio Buffering & Playback
**Goal**: Buffered playback with timing synchronization

1. **Audio Buffer (PSRAM)**
   - Ring buffer: ~2 seconds @ 44.1kHz stereo 16-bit = ~350KB
   - Timestamped audio frames
   - Handle underrun: silence insertion

2. **PTP Clock Synchronization**
   - Implement PTP client (IEEE 1588 subset)
   - Sync ESP32 clock to sender's master clock
   - Goal: <1ms offset

3. **Playback Timing**
   - Map RTP timestamps to local PTP time
   - Schedule I2S DMA buffer fills
   - Adaptive buffer level management

4. **Sample Rate Handling**
   - Support 44.1kHz and 48kHz native
   - Simple resampling if needed (or reject unsupported)

### Phase 7: Integration & Polish
**Goal**: Complete working system

1. **State Machine**
   ```
   IDLE → CONNECTING → PAIRED → BUFFERING → PLAYING → PAUSED
                  ↑                                      │
                  └──────────── DISCONNECTED ←──────────┘
   ```

2. **Volume Control**
   - Handle SET_PARAMETER volume messages
   - Software volume scaling (or hardware if DAC supports)

3. **Metadata Display (Optional)**
   - Parse DMAP/DAAP metadata
   - Could display on attached screen

4. **Error Recovery**
   - Network timeout handling
   - Decoder error recovery
   - Graceful reconnection

---

## Appendix A: mDNS TXT Records for AirPlay 2

```c
// _airplay._tcp TXT records
"deviceid=AA:BB:CC:DD:EE:FF"  // Device MAC
"features=0x5A7FFFF7,0x1E"    // AirPlay 2 features bitmap
"flags=0x4"                    // Receiver flags
"model=AppleTV3,2"            // Device model (spoof)
"pi=<uuid>"                   // Pairing identity
"pk=<ed25519_pubkey_hex>"     // Device public key (32 bytes hex)
"srcvers=220.68"              // Source version
"vv=2"                        // Protocol version
```

---

## File Structure

```
airplay2-esp32/
├── CMakeLists.txt
├── sdkconfig.defaults
├── sdkconfig.defaults.esp32s3
├── partitions.csv
├── main/
│   ├── CMakeLists.txt
│   ├── main.cpp                # Entry point
│   ├── wifi_manager.cpp/h      # WiFi provisioning & management
│   ├── mdns_service.cpp/h      # AirPlay mDNS advertisement
│   ├── i2s_output.cpp/h        # PCM5102A I2S driver
│   ├── audio_buffer.cpp/h      # PSRAM ring buffer
│   ├── airplay_server.cpp/h    # Main AirPlay state machine
│   └── Kconfig.projbuild       # Project config options
├── components/
│   ├── HomeSpan/               # Git submodule (crypto source)
│   │   └── src/
│   │       ├── SRP.cpp/h       # SRP-6a (reuse)
│   │       ├── HKDF.cpp/h      # HKDF (reuse)
│   │       ├── TLV8.cpp/h      # TLV parser (reuse)
│   │       └── ...             # libsodium integration
│   ├── airplay/
│   │   ├── CMakeLists.txt
│   │   ├── rtsp_server.cpp/h   # RTSP protocol handler
│   │   ├── rtp_receiver.cpp/h  # RTP/RTCP handling
│   │   ├── hap_transient.cpp/h # Transient pairing (uses HomeSpan crypto)
│   │   ├── ptp_client.cpp/h    # PTP time sync
│   │   ├── plist_parser.cpp/h  # Binary plist parser
│   │   └── airplay_defs.h      # Constants, feature flags
│   ├── fairplay/
│   │   ├── CMakeLists.txt
│   │   ├── fairplay.cpp/h      # FairPlay v3 handshake
│   │   └── fp_keys.h           # FairPlay keys
│   └── codecs/
│       ├── CMakeLists.txt
│       ├── alac_decoder.cpp/h  # ALAC (from libalac)
│       ├── aac_decoder.cpp/h   # AAC (libhelix or ESP-ADF)
│       └── opus_decoder.cpp/h  # Opus (from libopus)
└── docs/
    └── PROTOCOL_NOTES.md
```

---

## Dependencies & Libraries

| Component | Library | License | Source |
|-----------|---------|---------|--------|
| Framework | ESP-IDF v5.x | Apache 2.0 | Espressif |
| HAP Crypto | HomeSpan | MIT | Submodule from HomeKey-ESP32 |
| Ed25519/X25519/ChaCha20 | libsodium (via HomeSpan) | ISC | Bundled with HomeSpan |
| SRP-6a | HomeSpan SRP.cpp | MIT | HomeSpan |
| HKDF | HomeSpan HKDF.cpp | MIT | HomeSpan |
| TLV Parser | HomeSpan TLV8.cpp | MIT | HomeSpan |
| AES-CTR | mbedTLS | Apache 2.0 | ESP-IDF built-in |
| ALAC | libalac | Apache 2.0 | Apple |
| AAC | libhelix-aac | RPSL | RealNetworks |
| Opus | libopus | BSD-3 | Xiph.org |
| mDNS | ESP-IDF mdns | Apache 2.0 | Built-in |
| JSON | cJSON | MIT | ESP-IDF built-in |

---

## Technical Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| HomeSpan crypto not directly reusable | Rework crypto layer | Extract libsodium calls directly; HomeSpan's structure is modular |
| FairPlay implementation complex | Blocks audio playback | Start with airplay2-receiver port; test each message type |
| PTP timing insufficient | Multi-room desync | Accept <5ms accuracy initially; optimize later |
| PSRAM bandwidth | Audio glitches | Use DMA, prioritize audio task, minimize contention |
| Memory pressure | Instability | Profile early; use static allocation for buffers |

---

## References

- [HomeKey-ESP32](https://github.com/rednblkx/HomeKey-ESP32) - Project structure & HomeSpan integration
- [HomeSpan](https://github.com/HomeSpan/HomeSpan) - HAP crypto (Ed25519, X25519, SRP, HKDF)
- [Unofficial AirPlay 2 Specification](https://openairplay.github.io/airplay-spec/)
- [AirPlay 2 Internals - Emanuele Cozzi](https://emanuelecozzi.net/docs/airplay2)
- [airplay2-receiver](https://github.com/openairplay/airplay2-receiver) - Python reference implementation
- [shairport-sync](https://github.com/mikebrady/shairport-sync) - C reference (Linux)
- [pyatv](https://pyatv.dev/documentation/protocols/) - Protocol documentation
- [ESP-IDF I2S](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-reference/peripherals/i2s.html)

---

## Success Criteria

- [ ] ESP32-S3 appears in iOS/macOS AirPlay device list
- [ ] Successful HAP transient pairing
- [ ] FairPlay v3 handshake completes
- [ ] Audio streams and plays through PCM5102A DAC
- [ ] ALAC, AAC, Opus codecs working
- [ ] ~2 second buffer maintained
- [ ] No audible glitches during normal playback
- [ ] Volume control functional

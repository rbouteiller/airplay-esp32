# AirPlay 1 + 2 Quality Roadmap

> **For agentic workers:** Use `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement each phase task-by-task. Steps use `- [ ]` for
> tracking. **Phases are sequential by priority** — finish P0 before starting P1.

**Goal:** Bring `airplay-esp32` to production-grade reliability for **both AirPlay 1 (RAOP)
and AirPlay 2 (HAP)** by closing the gaps surfaced by a side-by-side audit against
`mikebrady/shairport-sync` (and `mikebrady/nqptp` for PTP).

**Architecture:** Seven sequential remediation phases plus one decision-gate phase. Each
phase is a stand-alone, releasable increment that can be tested end-to-end with real Apple
clients before the next phase begins.

**Tech stack:** ESP-IDF v5.x, mbedTLS, libsodium, ALAC (Espressif), FreeRTOS, mDNS-IDF.

---

## Audit Verdict

### Current uncommitted diff (`audio_stream_realtime.c` + `audio_receiver.c`) — **7/10**

**What is good (keep):**

- NACK packet layout (`0x80 0xD5 <htons(1)> <first> <count>`) now matches shairport's
  `rtp_request_resend()` exactly. The previous `count - 1` encoding was wrong.
- 64-bit missing-mask + slide window + 250 ms retry cadence + sendto-error backoff is a
  clean, allocation-free design that fits ESP32 RAM.
- Centralized `audio_receiver_reset_resend_state()` covers start / stop / flush / control
  re-bind — matches the spirit of shairport's `reset_input_flow_metrics()`.
- Masking control packet types with `& 0x7F` correctly normalizes `0xD4↔0x54`,
  `0xD6↔0x56`, `0xD7↔0x57` (RTP marker bit).

**What is risky (revisit in this roadmap):**

- 64-slot window vs shairport's ~1024 — burst loss recovery is weaker. Acceptable trade
  for embedded RAM, but should be **documented** and the failure mode (`packets_dropped`
  bumped, audible glitch) understood.
- `resend_retry_if_due()` is only invoked on the regular-RTP receive path. If a sender
  stalls and only 0x56 retransmits arrive, the retry timer never advances → in-flight
  resend requests can starve. **Phase 3 task.**
- `state->stats.packets_dropped += gap` over-reports loss — every successfully retransmitted
  packet was already counted as a drop. **Phase 3 task.**
- No mutex around the retransmit fields shared by the data RX task, control RX task, and
  the RTSP thread that calls `audio_receiver_set_client_control()`. **Phase 5 task.**

The diff is shippable as a foundation. The roadmap below builds on it.

### Severity heat-map across the codebase

| Subsystem                                      | Critical | High | Medium | Low |
| ---------------------------------------------- | -------: | ---: | -----: | --: |
| HAP pair-setup / pair-verify (`main/hap/`)     |        2 |    1 |      4 |   2 |
| Lip-sync timing (`audio_timing`, `*_clock.c`)  |        2 |    4 |      4 |   3 |
| mDNS / identity / network lifecycle            |        2 |    3 |      2 |   2 |
| RTSP handlers + dual v1/v2 selection           |        0 |    1 |      3 |   4 |
| RTP receive / NACK / retransmit (current diff) |        0 |    0 |      4 |   4 |
| **Totals**                                     |    **6** |  **9** | **17** | **15** |

The **six critical** issues are the gating items: until they are fixed, AirPlay 2
HomeKit-paired playback cannot be considered reliable, and large lip-sync offsets vs other
HomePods will be visible in any multi-room comparison.

---

## Phase Index

| Phase | Title                                                | Priority | Est. Effort |
| ----- | ---------------------------------------------------- | -------- | ----------- |
| **1** | Pairing & Identity (the AP2 blockers)                | **P0**   | 1 week      |
| **2** | Lip-Sync Correctness (anchor RTP + locking)          | **P0**   | 1 week      |
| **3** | Stream Reliability (retransmit + drift modeling)     | P1       | 1 week      |
| **4** | Network Lifecycle & RTSP Polish                      | P1       | 4 days      |
| **5** | Concurrency Hardening                                | P1       | 3 days      |
| **6** | Crypto Hardening                                     | P2       | 4 days      |
| **7** | Edge Cases (BMCA, multi-bearer, codec, TXT polish)   | P2       | 1 week      |
| **8** | Decision Gate: FairPlay v2 + Test Harness            | Decision | 0–4 weeks   |

**Total core effort:** ~5 weeks of focused work for P0 + P1 + P2. Phase 8 is a separate
discussion because FairPlay v2 implementation cost dwarfs everything else combined.

---

## Phase 1 — Pairing & Identity (the AP2 blockers)

**Why first:** Without these fixes, every iPhone pairing attempt resets state on reboot,
and HomeKit-paired playback is broken. These are also the cheapest wins.

**Success criteria:**

1. Pair iPhone (Home app or AirPlay sheet → "Allow Speaker") on first boot. Reboot ESP32.
   Reconnect — playback resumes **without re-pairing**.
2. `dns-sd -B _airplay._tcp` shows non-zero `pi=` UUID stable across reboots.
3. Esparagus board with Ethernet only (Wi-Fi disabled in menuconfig) successfully
   completes RAOP from TuneBlade on Windows.
4. `dns-sd -L` shows `deviceid=` matching the Ethernet MAC, not the Wi-Fi STA MAC.

### Files

- `main/hap/srp.c` — fix password mismatch in verify (Critical #1)
- `main/hap/srp.h` — add password storage to `srp_session_t`
- `main/hap/hap_pair_setup.c` — implement M6 TLV emission (Critical #2)
- `main/hap/hap_pair_verify.c` — verify Ed25519 signature in raw verify (Critical #3)
- `main/hap/hap.c` — generate + persist `pi` UUID alongside `pk` keypair
- `main/hap/hap.h` — expose `hap_get_pairing_id()`
- `main/network/mdns_airplay.c` — feed real `pi`, branch MAC source by active bearer
- `main/network/wifi.c` / `main/network/ethernet.c` — expose "active bearer MAC"
- `main/rtsp/rtsp_handlers.c`
  - line ~438–446: Apple-Challenge response IP/MAC from active netif
  - line ~496: `/info` plist `pi` from persisted UUID
  - line ~616: M5 success branch returns body when `*output_len > 0`
- `main/main.c` — generate `pi` at first boot if NVS empty

### Tasks

- [ ] **1.1 Add password storage to SRP session.** In `srp.h`, extend `srp_session_t`
  with `char password[16]; size_t password_len;`. In `srp.c:srp_start()`, copy the
  caller's password into the session. In `srp_verify_client()` (~line 311), recompute
  `x` with `session->password` instead of the hard-coded `"3939"`.

- [ ] **1.2 Test SRP fix.** Add a unit test
  `main/hap/test_srp.c` (link as `main` test or simple ESP-IDF unit-test) that runs
  full M1→M2→M3→M4 with password `"0000"` (non-transient). Should compute matching
  M1/M2 proofs. Commit.

- [ ] **1.3 Implement M5 → M6 TLV emission** in `hap_pair_setup_m5()`
  (`main/hap/hap_pair_setup.c` ~line 155–211). After successful ChaCha20-Poly1305
  decrypt of `encrypted_data` and signature check on the inner sub-TLV, build the M6
  response: derive accessory long-term Ed25519 keypair, sign
  `(AccessoryX || AccessoryPairingID || AccessoryLTPK)`, encrypt the inner TLV
  `(0x01=AccessoryPairingID, 0x03=AccessoryLTPK, 0x0A=AccessorySignature)` with the
  same session key + nonce `"PS-Msg06"`, emit `(0x06=state=6, 0x05=encrypted_data)`
  into `output`/`output_len`. See shairport-sync's
  `airplay2_pairings/airplay2_pairings.c` for reference structure.

- [ ] **1.4 Fix RTSP handler success branch** in `rtsp_handlers.c` `handle_post()` for
  `/pair-setup`. Today the success branch is gated on `err == ESP_OK && response_len > 0`
  — verify M5 path now emits `response_len > 0` after task 1.3 and that the response
  is sent with `Content-Type: application/octet-stream` and the encrypted M6 body.

- [ ] **1.5 Implement raw pair-verify signature check** in `hap_pair_verify_m3_raw`
  (`hap_pair_verify.c` ~line 296). Use `crypto_sign_verify_detached()` (libsodium) on
  the ChaCha20-decrypted client signature with the controller LTPK retrieved from the
  pairings store. If the controller is unknown, return error TLV (state=6,
  error=0x02 = authentication). **Do not** silently log-and-pass.

- [ ] **1.6 Generate + persist `pi` UUID at first boot.** In `hap_init()`
  (`main/hap/hap.c`), after the existing `pk` load/generate logic, do the same for `pi`:
  load 16 bytes from NVS key `"hap.pi"`; if absent, fill with `esp_fill_random(buf, 16)`,
  set RFC-4122 v4 bits (`buf[6] = (buf[6] & 0x0f) | 0x40; buf[8] = (buf[8] & 0x3f) | 0x80`),
  write to NVS, log it. Add `hap_get_pairing_id(uint8_t out[16])`.

- [ ] **1.7 Replace zero `pi=`** in `mdns_airplay.c` (~line 80) with hex of the 16-byte
  UUID from `hap_get_pairing_id()` formatted as `8-4-4-4-12` (e.g.
  `e2c8c0d2-4a3f-4f1e-9c3b-1a2b3c4d5e6f`). Same in `rtsp_handlers.c` `/info` plist
  (~line 496).

- [ ] **1.8 Expose active-bearer MAC.** Add `network_active_mac(uint8_t out[6])` and
  `network_active_ipv4(esp_ip4_addr_t *out)` in a new tiny module
  `main/network/active_bearer.c` (or extend an existing helper). Logic: if Ethernet
  netif has an IP, use `ESP_MAC_ETH`; else use `ESP_MAC_WIFI_STA`. Update
  `wifi_get_mac_str()` to delegate to this helper.

- [ ] **1.9 Wire active-bearer MAC into mDNS** (`mdns_airplay.c:44-45,80`),
  RAOP service-name prefix, and `deviceid` TXT.

- [ ] **1.10 Wire active-bearer IP+MAC into Apple-Challenge response**
  (`rtsp_handlers.c:438-446`). The PKCS#1 v1.5 signed payload must contain the IPv4 and
  MAC the iOS device used to reach us, otherwise the challenge fails.

- [ ] **1.11 Field test:** pair from iPhone (iOS 17+), reboot ESP32, restream. Expected:
  no re-pair prompt, audio plays in <2 s. Pair from second iPhone — both should appear
  in the pairings store. Reboot — both should still work.

- [ ] **1.12 Field test (Ethernet):** Esparagus Audio Brick with Wi-Fi disabled in
  `menuconfig`, Ethernet only. TuneBlade on Windows discovers, pairs (no PIN), streams
  successfully. Repeat with iOS in AirPlay 2 mode.

- [ ] **1.13 Commit phase 1** with message
  `feat(hap): complete pair-setup M6 + persistent pi + active-bearer identity (fixes #XXX)`.

### Risks

- Pair-setup M6 can subtly break existing already-paired iPhones if the encryption nonce
  or the inner TLV ordering differs from spec. Plan to test with a freshly factory-reset
  pairings store.
- Changing the MAC source by active bearer means existing users on Wi-Fi will see the
  same `deviceid` (no change), but Esparagus users currently on Ethernet who previously
  paired with the Wi-Fi MAC will appear as a new device. Document in `CHANGELOG.md`.

---

## Phase 2 — Lip-Sync Correctness (anchor RTP + locking)

**Why second:** Even with pairing fixed, multi-room sync vs HomePods will be visibly off
(hundreds of ms class for AP1, less for AP2 but still audible). This is the second-most-
visible quality regression.

**Success criteria:**

1. Two devices in a HomeKit group: ESP32 + a real HomePod mini. Play in stereo. No
   audible echo / phase difference (target: <10 ms between speakers, measured with a
   phone microphone or a logic-analyzer-fed comparator).
2. Sustained 1-hour playback session has zero **drift** complaints (sync at start ≈ sync
   at end), with only periodic SYNC packets keeping us anchored — no resync glitches.
3. RAOP `Audio-Latency:` header in RECORD response matches measured pipeline latency
   within ±5 ms.

### Files

- `main/audio/audio_stream_realtime.c` (~line 439–471): control_receiver_task — the
  sync packet parsers
- `main/audio/audio_timing.c` (~line 195–215, 87–125): `audio_timing_set_anchor`,
  `compute_early_us`
- `main/audio/audio_timing.h`: add `clock_id` field to `audio_timing_t`
- `main/network/ntp_clock.c`: add gradient (least-squares slope) to offset model
- `main/network/ptp_clock.c`: add frequency-offset estimation
- `main/audio/audio_receiver.c`: pass `clock_id` through `audio_receiver_set_anchor_time`
- `main/rtsp/rtsp_handlers.c` (~line 1265–1272): RECORD `Audio-Latency:` honest value
- `main/audio/audio_output.{c,h}`: expose actual DAC pipeline depth
- new `main/audio/sync_lock.c/h` (or use FreeRTOS portMUX directly inline): mutex on
  anchor

### Tasks

- [ ] **2.1 Fix AP1 sync anchor RTP.** In `control_receiver_task` 0x54 case
  (`audio_stream_realtime.c` ~line 447), change the anchor RTP source from
  `nctoh32(packet+4)` (rtp_timestamp_less_latency) to:

```c
uint32_t latency_delayed = nctoh32(packet + 4);   // playing-now RTP (incl. latency)
uint32_t sync_rtp        = nctoh32(packet + 16);  // emitted-now RTP (latency frames ahead)
uint32_t conn_latency    = sync_rtp - latency_delayed;   // u32 modular subtraction
state->stream_latency_frames = conn_latency;
uint32_t anchor_rtp = sync_rtp - conn_latency;    // == latency_delayed, but stored as adjusted
```

  Note: this restores the shairport `latency_delayed_timestamp` semantic. The existing
  code happens to use that value already — verify by reading shairport `rtp.c`
  `rtp_control_receiver` 0xd4 case carefully and ensure ours is mathematically
  equivalent. If it is, the fix may be only "store the derived `stream_latency_frames`
  and use it in advertised `Audio-Latency:`" (Task 2.6).

- [ ] **2.2 Fix AP2 PTP anchor RTP** (`audio_stream_realtime.c` ~line 463). Parse
  `frame_2 = nctoh32(packet + 16)` and a fixed offset `11035`:

```c
uint32_t frame_1 = nctoh32(packet + 4);
uint64_t ptp_ns  = nctoh64(packet + 8);
uint32_t frame_2 = nctoh32(packet + 16);
uint64_t clock_id = nctoh64(packet + 20);
uint32_t added_latency = (uint32_t)(frame_2 - frame_1);  // modular
uint32_t anchor_rtp = frame_1 - 11035u - added_latency;  // shairport set_ptp_anchor_info
audio_receiver_set_anchor_time(clock_id, ptp_ns, anchor_rtp);
```

  Reference: shairport-sync `rtp.c` `rtp_control_receiver` case 215 (or 0x57).

- [ ] **2.3 Plumb `clock_id` through the timing layer.**
  - Add `uint64_t anchor_clock_id` to `audio_timing_t` in `audio_timing.h`.
  - In `audio_timing_set_anchor()`, store `clock_id` instead of `(void)clock_id`.
  - Compare incoming `clock_id` against `ptp_clock_get_master_id()` (new accessor in
    `ptp_clock.c`). If mismatch and we are in PTP sync mode: log warning, **do not
    update anchor**, and set a "pending master switch" flag.
  - On master switch + 5 s grace, accept the new anchor and rebase. Mirrors
    shairport's `get_ptp_anchor_local_time_info` master-change handling.

- [ ] **2.4 Add NTP gradient.** In `ntp_clock.c`, retain the last N=8 timing exchanges
  with `(local_time, remote_time)` pairs. Compute the slope `gradient = Σ(xy) / Σ(x²)`
  (least-squares through origin after centering). Expose
  `ntp_clock_get_offset_at_local_time(int64_t local_ns)` that returns
  `base_offset + gradient * (local_ns - reference_local_ns)`. Use this in
  `compute_early_us()` instead of the static offset.

- [ ] **2.5 Add PTP frequency model.** In `ptp_clock.c`, after the median filter on
  instantaneous offsets, fit a gradient over the same window. Expose
  `ptp_clock_get_offset_at_local_time(int64_t local_ns)`. This corrects the
  `local_time + offset → ptp_time` mapping for clocks with measurable drift.

- [ ] **2.6 Honest `Audio-Latency:` in RAOP RECORD response**
  (`rtsp_handlers.c` ~line 1268). Replace `0` with the **measured** end-to-end latency
  in RTP frames at 44.1 kHz:
  `latency_frames = (DAC_PIPELINE_US + I2S_DMA_BUFFER_US + JITTER_BUFFER_US) * 44100 / 1000000`.
  Expose constants from `audio_output.h` and `audio_buffer.h`.
  Typical value: ~88200 frames (2 s) for a 200 ms jitter target + DAC/DMA depth.
  Make this match `state->stream_latency_frames` from task 2.1 if AP1 has set one.

- [ ] **2.7 Add anchor-update mutex.** Wrap `audio_timing_set_anchor()` and the
  read-side `compute_early_us()` (both in `audio_timing.c`) with a `SemaphoreHandle_t`
  mutex (or `portMUX_TYPE` spinlock since this is a fixed-size critical section).
  Initialize in `audio_timing_init()`. On the read side, copy anchor + clock_id +
  gradient into a local snapshot under the lock, then release before doing the maths.

- [ ] **2.8 Add anchor staleness detection.** Track `state->last_sync_packet_us` in
  `audio_stream_realtime.c` (updated in both 0x54 and 0x57 paths). In the audio output
  pull path or a 1 Hz watchdog, if `(now - last_sync_packet_us) > 7_000_000` (7 s,
  matches shairport AP2 realtime), call a new
  `audio_timing_invalidate_anchor()` and stop emitting samples until next anchor. Log
  `WARN: anchor stale, pausing playback`.

- [ ] **2.9 Add monotonic ratchet.** In `audio_timing_set_anchor()`, reject anchors
  where `network_time_ns < last_anchor_network_time_ns - threshold` (threshold ~1 s
  to allow legitimate FLUSH-driven seeks). On reject, log + bump
  `audio_stats.anchor_rejected`.

- [ ] **2.10 Field test:** ESP32 + iPhone playing stereo across two HomePod minis.
  Walk between speakers — no audible echo. Use a microphone-equipped phone app
  (e.g., `Audio Tools` "Speaker Test") to verify <10 ms inter-speaker offset.

- [ ] **2.11 Bench test for drift:** 60-minute sine-wave playback, scope the I2S clock
  vs the streaming source's clock (or compare frame number at start vs end against
  expected `start + 44100 × 3600`). Should be drift-corrected, no slow phase walk.

- [ ] **2.12 Commit phase 2** with message
  `fix(timing): correct anchor RTP for AP1+AP2, add clock-id check + drift model`.

### Risks

- Changing anchor RTP semantics could break **single-speaker** lip-sync that users have
  gotten used to. Test single-device first to verify no regression, then multi-device.
- Adding mutex to the audio output read path adds a few µs of latency. Acceptable
  unless we are already running tight on ESP32 (not ESP32-S3).

---

## Phase 3 — Stream Reliability (retransmit + drift tail)

**Why third:** With Phases 1–2 done, a stream works and stays in sync. Phase 3 is about
making it tolerant of WiFi packet loss and long sessions.

**Success criteria:**

1. Inject 5% random UDP packet loss (using a Wi-Fi AP that supports it, or a Linux
   `tc qdisc netem` upstream). No audible glitches with the receiver tracking
   shairport-style behavior. Stat counters report accurate `loss_recovered` vs
   `loss_unrecovered`.
2. NACK retry continues even when no fresh non-retransmit packets arrive (sender stall).
3. Burst loss of 32 packets → recovered. Burst loss of >64 packets → graceful
   acknowledgement (single short skip), not cascading drift.

### Files

- `main/audio/audio_stream_realtime.c` (current diff is here): refine retry/timer
- `main/audio/audio_receiver_internal.h`: add separate counters
- `main/audio/audio_buffer.c`: add "before-played-frame" gate

### Tasks

- [ ] **3.1 Split loss counters.** In `audio_stats_t`
  (`audio_receiver_internal.h`): rename current `packets_dropped` to
  `gap_detected_packets`. Add `loss_recovered_packets` (incremented in
  `resend_mark_received` for 0x56 retransmits) and `loss_unrecovered_packets`
  (incremented when a missing slot ages out of the window without recovery — see 3.2).

- [ ] **3.2 Track unrecovered loss as the window slides.** In
  `resend_track_missing()` reset branch (`audio_stream_realtime.c` ~line 134), the
  current code abandons holes when a new gap arrives outside the window. Before
  abandoning, count any still-set bits in the old mask as `loss_unrecovered_packets`.

- [ ] **3.3 Run resend retry from a periodic timer.** Add an `esp_timer` (1 ms or
  10 ms tick) or piggyback on the audio output pull task. On each tick, call
  `resend_retry_if_due(state)`. This decouples retry cadence from incoming-packet
  arrival, fixing the "sender-stall starves retries" issue.

- [ ] **3.4 Optionally widen the resend window.** If profiling shows free PSRAM,
  extend `RESEND_WINDOW_BITS` from 64 to 256 (still a pair of 64-bit words, but two of
  them = `uint64_t mask[4]`). If PSRAM is tight, leave at 64 and document the trade
  in `audio_stream_realtime.c` header comment. Decision item — flag in plan review.

- [ ] **3.5 Drop late retransmits cheaply.** In `realtime_receive_packet()`, before
  the AES decrypt + ALAC decode (which costs ~50 µs/packet), check if `seq` is older
  than the next-to-be-played frame (using `audio_buffer_next_play_seq()` — add this
  accessor). Skip with `ESP_LOGD("late retransmit, skipping decode")`.

- [ ] **3.6 Field test with packet loss.** Use a Wi-Fi AP that supports loss
  injection (or a Linux router with `tc netem loss 5%`) between iPhone and ESP32.
  Play 10 min — count audible glitches (manual). Target: ≤1 glitch per 10 min at 5%
  loss with retransmit recovery.

- [ ] **3.7 Commit phase 3** with message
  `feat(audio): timer-driven NACK retry + loss accounting + late-retransmit gate`.

---

## Phase 4 — Network Lifecycle & RTSP Polish

**Success criteria:**

1. Wi-Fi disconnect/reconnect mid-session: mDNS re-announces, RTSP sessions are torn
   down cleanly, no zombie sockets, next stream attempt works in <5 s.
2. NTP timing exchange uses the port advertised in SETUP — verifiable with
   `tcpdump port <timing_port>`.
3. `CONFIG_AIRPLAY_FORCE_V1` actually does what its help text says (and the help text
   matches reality).

### Files

- `main/main.c`: react to `IP_EVENT_*` to refresh mDNS
- `main/network/mdns_airplay.{c,h}`: add `mdns_airplay_refresh()`
- `main/network/ntp_clock.c`: bind to advertised port instead of ephemeral
- `main/rtsp/rtsp_handlers.c`:
  - line ~120–142: keep ports for the timing socket consistent
  - line ~1085: parse `Transport:` from header block only
  - line ~1622–1664: distinguish stream-only vs full TEARDOWN
  - line ~1265–1272: see Phase 2 task 2.6 (already covered)
- `main/rtsp/rtsp_message.c`: case-insensitive header lookup
- `main/Kconfig.projbuild` ~line 332: align help text with implementation; add
  `AIRPLAY_DISABLE_V2_HANDLERS` if we want to truly disable v2 (vs just hide it from
  mDNS)

### Tasks

- [ ] **4.1 Bind NTP timing socket to advertised port.** Today
  `ensure_stream_ports()` (`rtsp_handlers.c` ~line 120) opens a UDP socket, reads its
  ephemeral port, and **closes the socket**. Then `ntp_clock_start_client()`
  (`ntp_clock.c` ~line 227) opens a fresh ephemeral socket. Refactor:
  `ensure_stream_ports()` keeps the bound socket and hands its FD to
  `ntp_clock_start_client(int fd)`. The advertised port now matches the listening
  port end-to-end.

- [ ] **4.2 mDNS refresh on network event.** In `main.c`'s `IP_EVENT_*` handler
  (`event_handler` ~line 87–144), on `IP_EVENT_STA_GOT_IP` or `IP_EVENT_ETH_GOT_IP`,
  if `s_airplay_started`, call new `mdns_airplay_refresh()` (which does
  `mdns_service_remove_all()` then re-runs the registration logic from
  `mdns_airplay_init()`). Ensures `_airplay._tcp` and `_raop._tcp` are re-published
  with the current IP/hostname.

- [ ] **4.3 RTSP TCP close ⇒ cleanup.** In `rtsp_server.c` client_task error/exit
  branch, ensure: (a) `audio_receiver_stop()`, (b) `audio_receiver_set_client_control(0,0)`,
  (c) `ntp_clock_stop()`, (d) per-connection state freed. Audit existing code — most
  is there but verify error paths.

- [ ] **4.4 Distinguish stream-only TEARDOWN vs full session TEARDOWN.** In
  `handle_teardown()` (`rtsp_handlers.c` ~line 1622), parse the request body. If
  `streams[]` is present (v2 stream-only teardown), call a new
  `audio_receiver_stop_streams()` which keeps the receiver state alive but clears
  the active stream. If no body or no streams[], call `audio_receiver_stop()` (full
  stop). Mirror shairport's session-vs-stream distinction.

- [ ] **4.5 Restrict `Transport:` parsing to header block.** In SETUP path
  (`rtsp_handlers.c` ~line 1085), today `strcasestr(raw, "Transport:")` searches the
  entire message including body. Refactor to walk header lines only via existing
  `rtsp_message_get_header()` parsing.

- [ ] **4.6 Case-insensitive `Content-Length` lookup.** In `rtsp_message.c` ~line
  32–40, use a case-insensitive header walk for all required headers (RFC 2326 §12).

- [ ] **4.7 Fix Kconfig help text.** Update `AIRPLAY_FORCE_V1` help (Kconfig
  ~line 332) to accurately describe what it does after commit `104d456`: hides
  `_airplay._tcp` from mDNS but does **not** disable v2 RTSP handlers (a v2-aware
  client could still try `/pair-setup`). If we want a hard-disable mode, add a
  separate `AIRPLAY_DISABLE_V2_HANDLERS` and gate the post handlers on it.

- [ ] **4.8 Field test:** Wi-Fi off → on mid-stream. Stream resumes. iOS device shows
  "Speaker Disconnected" → speaker still in picker → reconnect works.

- [ ] **4.9 Commit phase 4** with `feat(network): mDNS refresh + bind timing port + cleanup paths`.

---

## Phase 5 — Concurrency Hardening

**Why now:** Phases 1–4 added mutexes ad-hoc. Phase 5 makes the concurrency model
explicit and consistent.

**Success criteria:**

1. Document the threading model in `docs/THREADING.md`: which task owns which struct,
   which fields cross task boundaries, what protects them.
2. ThreadSanitizer-equivalent inspection (manual with `// THREAD: <task>` comments at
   each cross-task field) catches no unprotected reads/writes.
3. 24-hour soak test with continuous play + pause/resume + reconnect → no crashes,
   no torn-state-induced glitches.

### Files

- All of `main/audio/`: add ownership comments
- `main/audio/audio_receiver_internal.h`: split `audio_stats_t` into "RX-task-local" +
  "shared-snapshot"
- `main/audio/audio_receiver.c`: add `xQueue` or atomic snapshot for stats getter
- `main/network/ptp_clock.c`: review ISR vs task contexts (LWIP socket is task-context
  but the timer callback may not be)
- new `docs/THREADING.md`

### Tasks

- [ ] **5.1 Document threading model.** Create `docs/THREADING.md` with a table:

```
Task                     | Core | Owns                          | Reads (shared)
-------------------------|------|-------------------------------|----------------
RTSP server (per-conn)   | 0    | rtsp_conn_t                   | hap.pairings
audio receiver_task      | 1    | state->stats, ->resend_*      | state->client_control_addr
audio control_recv_task  | 1    | (writes anchor)               | -
audio output             | 1    | I2S DMA                       | audio_buffer, audio_timing
ptp_clock_task           | 0    | ptp.clock_state               | -
ntp_clock_task           | 0    | ntp.history                   | -
mDNS                     | 0    | (LWIP-internal)               | -
```

- [ ] **5.2 Atomic stats snapshot.** In `audio_receiver_get_stats()`, wrap the
  `memcpy` in a critical section (portMUX). Producer side (RX task) updates each
  field individually — single 32-bit writes are atomic on Xtensa, but multi-field
  reads need protection.

- [ ] **5.3 Protect `client_control_addr`.** In
  `audio_receiver_set_client_control()`, today we directly mutate
  `state->client_control_addr` while RX task may be reading it for `sendto`. Either
  (a) use a portMUX, or (b) require the receiver be stopped before calling this
  setter. Pick (b) for simplicity — call sites are RTSP-thread only at SETUP/TEARDOWN
  boundaries.

- [ ] **5.4 Validate ESP-IDF mDNS thread safety** for `mdns_service_*` calls from the
  IP event handler context. Read ESP-IDF mdns docs — most calls are thread-safe but
  `mdns_init`/`deinit` may not be.

- [ ] **5.5 24-hour soak test.** Run a script that reconnects every 5 min, pauses
  every 90 s, restreams. Check for crashes (`coredump`), heap fragmentation (log
  free heap every minute, expect stable), task watermarks (no stack near-overflow).

- [ ] **5.6 Commit** `chore(audio): document + harden cross-task synchronization`.

---

## Phase 6 — Crypto Hardening

**Success criteria:**

1. SRP M1/M2 proof comparison is constant-time (no observable timing diff for
   right-vs-wrong PINs in `pair-setup`).
2. AES-256 keys are accepted (not silently truncated). 128 stays the default.
3. ChaCha20-Poly1305 nonce reuse is impossible across reconnects (tested by running
   pair-verify twice in quick succession against same controller).
4. HAP HKDF salt/info strings audited against the AirPlay 2 spec / shairport
   reference.

### Files

- `main/hap/srp.c`: constant-time `memcmp`
- `main/audio/audio_crypto.c` ~line 41–48: branch on key length
- `main/hap/hap_crypto.c`: nonce-counter persistence
- `main/rtsp/rtsp_handlers.c` ~line 1007–1058 + `main/hap/hap_crypto.c` ~line 57–72:
  HKDF labels for SETUP audio key

### Tasks

- [ ] **6.1 Constant-time proof compare** in `srp.c:srp_verify_client()` ~line 389.
  Replace `memcmp` with libsodium `sodium_memcmp()` (already a dependency).

- [ ] **6.2 AES-256 audio decrypt support.** In `audio_crypto.c:41`, branch on
  `key_len`:
  ```c
  int key_bits = (key_len == 32) ? 256 : 128;
  if (key_len != 16 && key_len != 32) return -1;  // explicit reject
  mbedtls_aes_setkey_dec(&ctx, key, key_bits);
  ```
  In `rtsp_handlers.c` after `rsa_decrypt_aes_key`, allow both 16- and 32-byte keys.

- [ ] **6.3 Verify HAP audio-key HKDF labels.** Trace shairport's
  `airplay2_pairings/airplay2_pairings.c` `derive_chacha_key_v2_session()` (or current
  equivalent) to see what salt/info pair it uses for the audio stream key. Compare
  to our `hap_derive_audio_key()` (`hap_crypto.c:57-72`). Expected values per
  spec: salt=`"Control-Salt"` info=`"Control-Read-Encryption-Key"` for control RX,
  but for **audio stream encryption** the labels differ (often
  `"AudioStreamReadEncryptionKey"` or session-specific). Fix if needed.

- [ ] **6.4 Audit ChaCha nonce strategy.** In `hap_crypto.c:82-114`, the nonce is
  an 8-byte counter in the last 8 bytes of a 12-byte field. Verify counters are reset
  on **session establishment** (not just on first packet) and never decremented. Add
  an assertion.

- [ ] **6.5 mbedTLS HKDF migration (optional).** Replace custom HKDF in
  `hap_crypto.c:11-54` with `mbedtls_hkdf()`. Reduces audit surface. Run unit test
  comparing old vs new outputs to ensure bit-identical.

- [ ] **6.6 Field test:** pair iPhone, unpair, repair within 30 seconds. Should
  succeed both times (no nonce-reuse panic). Test with 5 different iOS versions.

- [ ] **6.7 Commit** `fix(crypto): constant-time SRP, AES-256 support, HAP key audit`.

---

## Phase 7 — Edge Cases & TXT Polish

**Success criteria:**

1. PTP master selection survives a HomePod restart on the network (master changes,
   we follow correctly).
2. Esparagus dual-bearer (Wi-Fi + Ethernet on same L2) works on either or both.
3. mDNS TXT records pass `dns-sd` parsing for both `_raop._tcp` and `_airplay._tcp`
   with all keys typically present on commercial AirPlay devices.
4. 24-bit ALAC streams either play correctly or are explicitly refused, never
   silently truncated.

### Files

- `main/network/ptp_clock.c`: minimal BMCA
- `main/network/mdns_airplay.c`: TXT polish
- `main/audio/audio_decoder.c` ~line 210–245: 24-bit handling
- `main/audio/alac_magic_cookie.c`: validation in `build_alac_magic_cookie()`

### Tasks

- [ ] **7.1 Minimal PTP BMCA.** In `ptp_clock.c` `PTP_MSG_ANNOUNCE` handler (today a
  no-op), parse `priority1`, `clockClass`, `clockAccuracy`, `clockIdentity`. Track
  current best master in `ptp.best_master_id`. On SYNC arrival, ignore if source
  ID != `best_master_id`. On master timeout (no ANNOUNCE for 3× announceInterval),
  clear and re-elect from next ANNOUNCE.

- [ ] **7.2 Per-interface PTP multicast subscription.** In `ptp_clock.c:283-293`,
  replace `imr_interface = INADDR_ANY` with the active netif's IPv4. If both Wi-Fi
  and Ethernet are up, subscribe on **both** with separate sockets, or pick the one
  with default route. Test on Esparagus board.

- [ ] **7.3 Add `txtvers=1`, `pw=false`, `protovers=1.1`** to `_raop._tcp` (RAOP)
  and `_airplay._tcp` (AP2) TXT records (`mdns_airplay.c`). Some legacy clients
  reject services missing `txtvers`.

- [ ] **7.4 Audit `AIRPLAY_FEATURES_LO/HI`** in `rtsp_handlers.h`. List each bit,
  identify which features we actually support (PCM yes, ALAC yes, AAC partial?,
  metadata yes, screen mirroring no, MFi no, FairPlay v2 stub-only). Trim the
  bitmask to what we actually deliver. Misadvertised features cause iOS to attempt
  flows that we then fail.

- [ ] **7.5 ALAC 24-bit handling.** In `audio_decoder.c:210-245`, when `bits_per_sample`
  in fmtp != 16, either: (a) reject the SETUP with 415 Unsupported Media Type, or
  (b) decode-and-truncate explicitly with an `ESP_LOGW`. Pick (b) for compatibility.
  In `build_alac_magic_cookie()`, validate fmtp fields (frame_length, bit_depth,
  channels, sample_rate) before encoding into the cookie; reject obviously bad
  values.

- [ ] **7.6 mDNS hostname collision.** Wire ESP-IDF mDNS conflict callback (if
  exposed in your IDF version) to append `-2` / `-3` suffix on collision.

- [ ] **7.7 Field test (multi-bearer):** Esparagus board with both Ethernet and
  Wi-Fi connected to same router. iOS on Wi-Fi-only finds the speaker. Stream from
  Ethernet path. Disconnect Ethernet — stream survives on Wi-Fi (or fails over
  cleanly).

- [ ] **7.8 Field test (PTP master switch):** With ESP32 + HomePod mini in a
  HomeKit group both playing, restart the HomePod. ESP32 should re-elect master
  (verify in PTP debug log) and resume sync within 5 seconds without audible
  glitch.

- [ ] **7.9 Commit** `feat(network): minimal BMCA + dual-bearer mDNS + TXT polish`.

---

## Phase 8 — Decision Gate: FairPlay v2 + Test Harness

**Why a separate phase:** This is a **scope decision**, not just an implementation. The
right answer depends on user-base and risk tolerance.

### 8a. FairPlay v2 — Scope Decision

**Context:** iOS uses FairPlay v2 for content protection signalling (`/fp-setup`
endpoint). Our current `rtsp_fairplay.c` returns canned blobs that are enough for
**most** non-DRM Apple-Music / Spotify / podcast / system audio cases, but **iOS may
silently downgrade** features or refuse some streams (notably from Apple Music
"Lossless" tier).

**Options:**

| Option                       | Cost          | Outcome                                       |
| ---------------------------- | ------------- | --------------------------------------------- |
| **A. Keep stub as is**       | 0             | Works for ~85% of iOS streaming. Documented gaps. |
| **B. Improve stub fidelity** | 1 week        | Maybe 90–95%, no real DRM compliance.        |
| **C. Implement FairPlay v2** | 3–4 weeks + access to spec / reference materials | Production-grade, parity with HomePod for non-MFi audio. Cannot pass MFi without Apple license. |

**Decision needed before any implementation work.** Discuss with the project owner.

If **A**: Add a `docs/COMPATIBILITY.md` listing iOS streams known to refuse / degrade.

If **B**: Compare to `openairplay/airplay-spec`'s FP discussion + try newer canned
responses captured from a working third-party AirPlay 2 receiver via Wireshark.

If **C**: Start with shairport-sync 4.x's FairPlay handling (a spec-style
implementation lives outside the open-source tree; see
[`mikebrady/shairport-sync` issue tracker](https://github.com/mikebrady/shairport-sync/issues)
for what's known publicly).

### 8b. Test Harness & CI

Regardless of the FairPlay decision, we need a repeatable test fleet so future
regressions are caught.

- [ ] **8.1 Define the test matrix.**

```
            | iOS 17 | iOS 18 | macOS Sonoma | TuneBlade Win | AirMusic Android
ESP32-WROOM | ✓      | ✓      | ✓            | ✓             | ✓
ESP32-S3    | ✓      | ✓      | ✓            | ✓             | ✓
SqueezeAMP  | ✓      | ✓      | -            | ✓             | -
Esparagus   | ✓      | ✓      | ✓            | ✓             | -
Esparagus+ETH | ✓    | ✓      | ✓            | ✓             | -
```

  For each cell, exercise: pair → play 30 s → pause → seek → reconnect → unpair.

- [ ] **8.2 Add structured tracing.** Compile-time-gated `TRACE(...)` macro that
  emits `subsystem | event | rtp_seq | rtp_ts | local_ns | network_ns` lines via
  `ESP_LOGI`. Disabled by default; enable per-subsystem via menuconfig. Helps
  field-debug user-reported sync issues.

- [ ] **8.3 Bench fixtures.** Build a Linux script (`scripts/bench/inject_loss.sh`)
  that uses `tc qdisc netem` to inject loss/jitter on the AP-side. Document in
  `docs/BENCH.md`.

- [ ] **8.4 GitHub Actions on PR.** Add a CI job that builds all four sdkconfig
  variants (esp32, esp32s3, squeezeamp, esparagus) and runs `clang-tidy`. Manual
  field test required for merge — document in `CONTRIBUTING.md`.

- [ ] **8.5 Commit** `chore: test matrix + structured tracing + CI build variants`.

---

## Cross-Phase Reference: Findings Catalog

Severity legend: **C**ritical / **H**igh / **M**edium / **L**ow.

| #  | Sev | Where                                          | Phase |
| -- | --- | ---------------------------------------------- | ----- |
| 1  | C   | `srp.c:311-328` — verify uses hardcoded `"3939"` | 1.1   |
| 2  | C   | `hap_pair_setup.c:155-211` — M5 never emits M6 | 1.3   |
| 3  | C   | `hap_pair_verify.c:296` — raw verify skips Ed25519 | 1.5   |
| 4  | C   | `mdns_airplay.c:80` — `pi=` is all-zero        | 1.6–1.7 |
| 5  | C   | `wifi_get_mac_str()` — always `WIFI_STA_DEF`   | 1.8–1.10 |
| 6  | C   | `audio_stream_realtime.c:447` — AP1 anchor RTP wrong | 2.1 |
| 7  | C   | `audio_stream_realtime.c:463` — AP2 anchor RTP wrong | 2.2 |
| 8  | H   | `audio_timing.c:195` — `clock_id` discarded    | 2.3   |
| 9  | H   | `rtsp_handlers.c:1265` — `Audio-Latency: 0`     | 2.6   |
| 10 | H   | no mutex on `audio_timing_t` anchor            | 2.7   |
| 11 | H   | `ntp_clock.c` — no gradient/drift model        | 2.4   |
| 12 | H   | `ptp_clock.c` — no frequency model             | 2.5   |
| 13 | H   | `audio_crypto.c:41` — AES-128 only             | 6.2   |
| 14 | H   | `hap_crypto.c:57-72` — control labels for audio key | 6.3 |
| 15 | H   | `rtsp_handlers.c:120` + `ntp_clock.c:227` — timing port mismatch | 4.1 |
| 16 | H   | `main.c:39` — no mDNS refresh on flap          | 4.2   |
| 17 | H   | RAOP TXT — `AIRPLAY_FORCE_V1` semantics       | 4.7   |
| 18 | M   | `audio_stream_realtime.c` retry only on RX path | 3.3   |
| 19 | M   | `packets_dropped += gap` over-counts loss      | 3.1   |
| 20 | M   | 64-slot resend window                          | 3.4   |
| 21 | M   | `srp.c:389` — non-constant-time memcmp         | 6.1   |
| 22 | M   | `tlv8.c:76-112` — only contiguous concat       | (deferred) |
| 23 | M   | `rtsp_handlers.c:1622` — TEARDOWN granularity  | 4.4   |
| 24 | M   | `audio_decoder.c:210` — 24-bit ALAC truncated  | 7.5   |
| 25 | M   | `ptp_clock.c:250` — no BMCA                    | 7.1   |
| 26 | L   | `rtsp_handlers.c:1085` — Transport: in body    | 4.5   |
| 27 | L   | `rtsp_message.c:32` — case-sensitive headers   | 4.6   |
| 28 | L   | `mdns_airplay.c` — missing `txtvers`, `pw`     | 7.3   |
| 29 | L   | `mdns_airplay.c` — no hostname collision      | 7.6   |
| 30 | L   | `rtsp_handlers.c:689` — `/fp-setup` doesn't set v2 | (cosmetic) |

---

## Definition of Done (per phase)

A phase is "done" when:

1. All tasks committed to a feature branch named `phase-N-<short-name>`.
2. CI passes on all four sdkconfig variants.
3. Pre-commit hook passes (`scripts/lint.sh` clean).
4. The acceptance criteria in the phase header are demonstrated with **video or screenshot
   evidence** in the PR description (audio recordings count for sync).
5. PR reviewed by at least one other contributor; user-facing changes mentioned in
   `CHANGELOG.md` and `README.md`.
6. Squash-merged into `feat/dual-airplay-v1-v2` (or `main` if that branch is closed).

---

## Open Questions for the Project Owner

1. **Phase 8a (FairPlay v2):** A, B, or C? Affects scope by ~3 weeks.
2. **Phase 3.4 (resend window size):** widen from 64 to 256 slots (more PSRAM) or stay
   at 64 with documented limit?
3. **Phase 4.7 (Kconfig):** add `AIRPLAY_DISABLE_V2_HANDLERS` as a separate build option,
   or just fix the help text and keep `_FORCE_V1` as mDNS-hide-only?
4. **Phase 7.4 (FEATURES bitmask):** authoritative list of what we promise to deliver?
   Need the project owner to confirm AAC support, screen mirroring, etc.
5. **Test devices available:** which iOS versions / macOS versions / non-Apple clients
   should be in the regression matrix?

---

## References

- `mikebrady/shairport-sync` master:
  [`rtp.c`](https://github.com/mikebrady/shairport-sync/blob/master/rtp.c),
  [`player.c`](https://github.com/mikebrady/shairport-sync/blob/master/player.c),
  [`rtsp.c`](https://github.com/mikebrady/shairport-sync/blob/master/rtsp.c),
  [`mdns_avahi.c`](https://github.com/mikebrady/shairport-sync/blob/master/mdns_avahi.c)
- `mikebrady/nqptp` main:
  [`nqptp.c`](https://github.com/mikebrady/nqptp/blob/main/nqptp.c),
  [`nqptp-shm-structures.h`](https://github.com/mikebrady/nqptp/blob/main/nqptp-shm-structures.h)
- `openairplay/airplay-spec` for protocol notes
- HomeKit Accessory Protocol Specification (Apple, NDA — public derivative summaries
  exist in `homebridge` / `homebridge-config-ui` source trees)

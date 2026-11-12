// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/* Host tests for main/audio/rtp_resend.c, the realtime stream's record of
 * missing packets: which holes are asked for and when, which late packets are
 * taken, when a hole is given up on, and how much of a bursty loss comes back
 * compared with the 64-packet window it replaced. */

#include "rtp_resend.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STEP     352U        /* frames in an ALAC packet */
#define BASE_RTP 0xfff00000U /* so the RTP wraps during the longer runs */
#define MAX_REQ  16

static int failures;

#define CHECK(cond, ...)                            \
  do {                                              \
    if (!(cond)) {                                  \
      failures++;                                   \
      printf("  FAIL %s:%d: ", __FILE__, __LINE__); \
      printf(__VA_ARGS__);                          \
      printf("\n");                                 \
    }                                               \
  } while (0)

static rtp_resend_t r;
static rtp_resend_range_t ranges[MAX_REQ];

static uint32_t rtp_at(uint32_t i) {
  return BASE_RTP + i * STEP;
}

static rtp_resend_verdict_t feed(uint32_t i) {
  return rtp_resend_on_packet(&r, (uint16_t)i, rtp_at(i), false);
}

static rtp_resend_verdict_t resend(uint32_t i) {
  return rtp_resend_on_packet(&r, (uint16_t)i, rtp_at(i), true);
}

// Packets first..last in order, without those in [hole, hole + holes).
static void feed_around(uint32_t first, uint32_t last, uint32_t hole,
                        uint32_t holes) {
  for (uint32_t i = first; i <= last; i++) {
    if (i < hole || i >= hole + holes) {
      (void)feed(i);
    }
  }
}

static size_t ask(uint32_t now_ms) {
  return rtp_resend_collect(&r, now_ms, false, 0, ranges, MAX_REQ);
}

// As ask(), with playback at packet `playing`.
static size_t ask_playing(uint32_t now_ms, uint32_t playing) {
  return rtp_resend_collect(&r, now_ms, true, rtp_at(playing), ranges, MAX_REQ);
}

// Every hole is filled, given up on, or still open.
static bool balanced(void) {
  const rtp_resend_counts_t *c = &r.counts;
  return c->skipped ==
         c->resent + c->late + c->expired + rtp_resend_outstanding(&r);
}

static void test_in_order(void) {
  printf("in order: nothing asked for\n");
  rtp_resend_reset(&r, STEP);
  for (uint32_t i = 0; i < 1000; i++) {
    CHECK(feed(i) == RTP_RESEND_NEWEST, "packet %u not the newest", i);
    CHECK(ask(i * 8U) == 0, "asked for something at packet %u", i);
  }
  CHECK(r.counts.received == 1000 && r.counts.skipped == 0,
        "received %u, skipped %u", r.counts.received, r.counts.skipped);
}

static void test_one_hole(void) {
  printf("one hole: asked for, again after 250 ms, filled once\n");
  rtp_resend_reset(&r, STEP);
  feed_around(0, 99, 50, 1);
  size_t n = ask(1000);
  CHECK(n == 1 && ranges[0].first == 50 && ranges[0].count == 1,
        "first request: %zu ranges, from %u", n, n ? ranges[0].first : 0);
  CHECK(ask(1100) == 0, "asked again 100 ms later");
  n = ask(1300);
  CHECK(n == 1 && ranges[0].first == 50, "not asked again 300 ms later");
  CHECK(resend(50) == RTP_RESEND_FILLED, "retransmission not taken");
  CHECK(resend(50) == RTP_RESEND_UNWANTED, "second copy taken");
  CHECK(feed(60) == RTP_RESEND_UNWANTED, "duplicate taken");
  CHECK(ask(2000) == 0, "asked for a filled hole");
  CHECK(r.counts.resent == 1 && r.counts.unwanted == 2 && r.counts.asked == 2 &&
            r.counts.requests == 2 && balanced(),
        "resent %u unwanted %u asked %u requests %u", r.counts.resent,
        r.counts.unwanted, r.counts.asked, r.counts.requests);
}

/* The old window was 64 packets long, and a newer gap outside it made it
 * forget the holes it held, and then throw their retransmissions away. */
static void test_holes_far_apart(void) {
  printf("holes 200 packets apart: all asked for and taken\n");
  rtp_resend_reset(&r, STEP);
  for (uint32_t i = 0; i < 500; i++) {
    if (i != 100 && i != 300 && i != 450) {
      (void)feed(i);
    }
  }
  const size_t n = ask(0);
  CHECK(n == 3 && ranges[0].first == 100 && ranges[1].first == 300 &&
            ranges[2].first == 450,
        "%zu ranges", n);
  CHECK(resend(100) == RTP_RESEND_FILLED, "oldest hole forgotten");
  CHECK(resend(300) == RTP_RESEND_FILLED, "middle hole forgotten");
  CHECK(resend(450) == RTP_RESEND_FILLED, "newest hole forgotten");
  CHECK(rtp_resend_outstanding(&r) == 0 && balanced(), "%u still open",
        rtp_resend_outstanding(&r));
}

// The old code never asked for a gap of more than 64 packets, half a second.
static void test_long_gap(void) {
  printf("a 150-packet gap: asked for in one request\n");
  rtp_resend_reset(&r, STEP);
  feed_around(0, 399, 200, 150);
  const size_t n = ask(0);
  CHECK(n == 1 && ranges[0].first == 200 && ranges[0].count == 150,
        "%zu ranges, the first %u+%u", n, n ? ranges[0].first : 0,
        n ? ranges[0].count : 0);
  for (uint32_t i = 200; i < 350; i++) {
    CHECK(resend(i) == RTP_RESEND_FILLED, "packet %u not taken", i);
  }
  CHECK(r.counts.resent == 150 && balanced(), "resent %u", r.counts.resent);
}

static void test_late_original(void) {
  printf("an original that arrives late fills its hole\n");
  rtp_resend_reset(&r, STEP);
  feed_around(0, 20, 5, 1);
  CHECK(feed(5) == RTP_RESEND_FILLED, "late packet not taken");
  CHECK(feed(5) == RTP_RESEND_UNWANTED, "its duplicate taken");
  CHECK(r.counts.late == 1 && r.counts.resent == 0 && balanced(),
        "late %u resent %u", r.counts.late, r.counts.resent);
}

static void test_due_holes_dropped(void) {
  printf("holes already due to play are given up on\n");
  rtp_resend_reset(&r, STEP);
  feed_around(0, 199, 100, 10);
  // Playback has reached packet 105, so 100-104 can no longer be heard.
  const size_t n = ask_playing(0, 105);
  CHECK(n == 1 && ranges[0].first == 105 && ranges[0].count == 5,
        "%zu ranges, the first %u+%u", n, n ? ranges[0].first : 0,
        n ? ranges[0].count : 0);
  CHECK(r.counts.expired == 5, "expired %u", r.counts.expired);
  CHECK(resend(102) == RTP_RESEND_UNWANTED, "a hole given up on was filled");
  CHECK(resend(107) == RTP_RESEND_FILLED, "an open hole was not filled");
  CHECK(balanced(), "counts do not add up");
}

static void test_window_end(void) {
  printf("a hole lasts one window\n");
  rtp_resend_reset(&r, STEP);
  feed_around(0, 10 + RTP_RESEND_WINDOW - 1U, 10, 1);
  CHECK(rtp_resend_outstanding(&r) == 1, "hole gone before the window passed");
  CHECK(ask(0) == 1 && ranges[0].first == 10, "last chance not taken");
  (void)feed(10 + RTP_RESEND_WINDOW);
  CHECK(rtp_resend_outstanding(&r) == 0 && r.counts.expired == 1,
        "open %u, expired %u", rtp_resend_outstanding(&r), r.counts.expired);
  CHECK(resend(10) == RTP_RESEND_UNWANTED, "taken after its window");
  CHECK(balanced(), "counts do not add up");
}

static void test_gap_longer_than_window(void) {
  printf("a gap longer than the window is not asked for\n");
  rtp_resend_reset(&r, STEP);
  feed_around(0, 9, 5, 1);
  CHECK(feed(1000) == RTP_RESEND_NEWEST, "packet after the gap not taken");
  CHECK(r.counts.skipped == 991 && r.counts.expired == 991 &&
            rtp_resend_outstanding(&r) == 0,
        "skipped %u expired %u open %u", r.counts.skipped, r.counts.expired,
        rtp_resend_outstanding(&r));
  CHECK(ask(0) == 0, "asked for part of it");
  CHECK(feed(1001) == RTP_RESEND_NEWEST && balanced(), "stream did not go on");
}

static void test_request_cap(void) {
  printf("50 separate holes: 12 requests a quarter second, oldest first\n");
  rtp_resend_reset(&r, STEP);
  for (uint32_t i = 0; i <= 100; i += 2) {
    (void)feed(i);
  }
  size_t n = ask(0);
  CHECK(n == 12 && ranges[0].first == 1 && ranges[11].first == 23,
        "first pass: %zu, from %u", n, n ? ranges[0].first : 0);
  CHECK(ask(0) == 0 && ask(200) == 0, "asked past the quarter's share");
  n = ask(250);
  CHECK(n == 12 && ranges[0].first == 25, "second quarter: %zu, from %u", n,
        n ? ranges[0].first : 0);
  // The oldest are due again by now, and come first.  Nothing has been
  // resent, so this is the last of the 32 requests a silent sender gets.
  n = ask(500);
  CHECK(n == 8 && ranges[0].first == 1, "third quarter: %zu, from %u", n,
        n ? ranges[0].first : 0);
  CHECK(ask(750) == 0 && ask(2000) == 0, "asked a silent sender again");
  n = ask(2500);
  CHECK(n == RTP_RESEND_PROBE_REQUESTS, "probe: %zu", n);
  CHECK(ask(2750) == 0, "asked again straight after the probe");
  // One answer, and asking is back to the quarter's share.
  CHECK(resend(1) == RTP_RESEND_FILLED, "answer refused");
  n = ask(3000);
  CHECK(n == 12, "after an answer: %zu", n);
}

static void test_wraparound(void) {
  printf("holes across the sequence number wrap\n");
  rtp_resend_reset(&r, STEP);
  feed_around(65500, 65600, 65530, 11);
  const size_t n = ask(0);
  CHECK(n == 1 && ranges[0].first == 65530 && ranges[0].count == 11,
        "%zu ranges, the first %u+%u", n, n ? ranges[0].first : 0,
        n ? ranges[0].count : 0);
  for (uint32_t i = 65530; i <= 65540; i++) {
    CHECK(resend(i) == RTP_RESEND_FILLED, "packet %u not taken", i);
  }
  CHECK(balanced(), "counts do not add up");
}

static void test_packet_length_learnt(void) {
  printf("1024-frame packets: due holes found from the real length\n");
  rtp_resend_reset(&r, STEP);
  for (uint32_t i = 0; i < 200; i++) {
    if (i < 50 || i > 59) {
      (void)rtp_resend_on_packet(&r, (uint16_t)i, 5000U + i * 1024U, false);
    }
  }
  const size_t n =
      rtp_resend_collect(&r, 0, true, 5000U + 55U * 1024U, ranges, MAX_REQ);
  CHECK(n == 1 && ranges[0].first == 55 && ranges[0].count == 5 &&
            r.counts.expired == 5,
        "%zu ranges, the first %u+%u, expired %u", n, n ? ranges[0].first : 0,
        n ? ranges[0].count : 0, r.counts.expired);
}

static void test_reset(void) {
  printf("before the first packet and after a reset\n");
  rtp_resend_reset(&r, STEP);
  CHECK(resend(7) == RTP_RESEND_UNWANTED, "retransmission before any packet");
  feed_around(0, 9, 3, 1);
  rtp_resend_reset(&r, STEP);
  CHECK(rtp_resend_outstanding(&r) == 0, "hole kept through a reset");
  CHECK(feed(500) == RTP_RESEND_NEWEST && ask(0) == 0,
        "stream after a reset not taken as new");
}

/* ---------- a lossy stream, against the tracker this replaced ---------- */

/* The receive task's bookkeeping before this file existed, as it was: holes
 * were kept in a 64-packet window from the oldest one, a gap that did not fit
 * replaced everything in it, a gap longer than the window was never asked
 * for, and only the oldest run of holes was asked for again. */
#define OLD_WINDOW 64U

typedef struct {
  bool valid;
  uint16_t last_seq;
  uint16_t first;
  uint64_t mask;
  int64_t last_request_ms;
} old_tracker_t;

static uint64_t old_mask_for(uint32_t count) {
  return count >= OLD_WINDOW ? UINT64_MAX : ((1ULL << count) - 1ULL);
}

static bool old_mark_received(old_tracker_t *o, uint16_t seq) {
  const uint16_t offset = (uint16_t)(seq - o->first);
  if (o->mask == 0 || offset >= OLD_WINDOW ||
      (o->mask & (1ULL << offset)) == 0) {
    return false;
  }
  o->mask &= ~(1ULL << offset);
  while (o->mask != 0 && (o->mask & 1ULL) == 0) {
    o->mask >>= 1;
    o->first++;
  }
  if (o->mask == 0) {
    o->last_request_ms = -1;
  }
  return true;
}

static void old_track_missing(old_tracker_t *o, uint16_t first,
                              uint16_t count) {
  const uint16_t offset = (uint16_t)(first - o->first);
  if (o->mask == 0 || offset >= OLD_WINDOW || offset + count > OLD_WINDOW) {
    o->first = first;
    o->mask = old_mask_for(count);
    return;
  }
  o->mask |= old_mask_for(count) << offset;
}

// The sender, answering a request: defined with the simulation below.
static void sender_request(int64_t now_ms, uint16_t first, uint16_t count);

static void old_request(old_tracker_t *o, int64_t now_ms, uint16_t first,
                        uint16_t count) {
  sender_request(now_ms, first, count);
  o->last_request_ms = now_ms;
}

static void old_retry_if_due(old_tracker_t *o, int64_t now_ms) {
  if (o->mask == 0 ||
      (o->last_request_ms >= 0 && now_ms - o->last_request_ms < 250)) {
    return;
  }
  uint64_t mask = o->mask;
  uint16_t first = o->first;
  while ((mask & 1ULL) == 0) {
    mask >>= 1;
    first++;
  }
  uint16_t count = 0;
  while ((mask & 1ULL) != 0 && count < OLD_WINDOW) {
    count++;
    mask >>= 1;
  }
  old_request(o, now_ms, first, count);
}

static bool old_on_packet(old_tracker_t *o, int64_t now_ms, uint16_t seq,
                          bool retransmit) {
  if (retransmit) {
    if (!old_mark_received(o, seq)) {
      return false;
    }
  } else if (!o->valid) {
    o->valid = true;
    o->last_seq = seq;
  } else {
    const uint16_t expected = (uint16_t)(o->last_seq + 1U);
    const int16_t delta = (int16_t)(uint16_t)(seq - expected);
    if (delta > 0) {
      if ((uint16_t)delta <= OLD_WINDOW) {
        old_track_missing(o, expected, (uint16_t)delta);
        old_request(o, now_ms, expected, (uint16_t)delta);
      }
      o->last_seq = seq;
    } else if (delta == 0) {
      o->last_seq = seq;
    } else if (!old_mark_received(o, seq)) {
      return false;
    }
  }
  old_retry_if_due(o, now_ms);
  return true;
}

/* The network: bursts of heavy loss in a mostly clean stream, as a two-state
 * (Gilbert-Elliott) chain stepped every packet interval.  Whether a given
 * transmission is lost depends only on when it is sent and what it is, so
 * both trackers face the same network. */
#define SIM_MS         120000
#define PACKET_MS      8 /* 352 frames at 44.1 kHz, rounded */
#define LATENCY_MS     2000
#define ONE_WAY_MS     10
#define RESEND_TURN_MS 20 /* sender's reaction to a request */
#define SIM_PACKETS    (SIM_MS / PACKET_MS)
#define GOOD_TO_BAD    0.002 /* per packet: a burst every ~4 s */
#define BAD_TO_GOOD    0.01  /* a burst lasts ~0.8 s */
#define LOSS_GOOD      0.005
#define LOSS_BAD       0.7

static bool bad_state[SIM_PACKETS + 1024];

static uint32_t mix(uint32_t x) {
  x ^= x >> 16;
  x *= 0x7feb352dU;
  x ^= x >> 15;
  x *= 0x846ca68bU;
  x ^= x >> 16;
  return x;
}

static void make_network(void) {
  uint32_t state = 12345;
  bool bad = false;
  for (size_t i = 0; i < sizeof(bad_state) / sizeof(bad_state[0]); i++) {
    state = mix(state + 0x9e3779b9U);
    const double u = (double)state / 4294967296.0;
    bad = bad ? u >= BAD_TO_GOOD : u < GOOD_TO_BAD;
    bad_state[i] = bad;
  }
}

static bool lost(int64_t sent_ms, uint32_t what) {
  const size_t tick = (size_t)(sent_ms / PACKET_MS);
  const double p = bad_state[tick] ? LOSS_BAD : LOSS_GOOD;
  const uint32_t h = mix(mix((uint32_t)sent_ms) ^ (what * 0x85ebca6bU));
  return (double)h / 4294967296.0 < p;
}

/* Retransmissions in flight, by arrival time.  A small binary heap. */
typedef struct {
  int64_t at_ms;
  uint32_t index; // packet number, unwrapped
} arrival_t;

static arrival_t heap[1 << 16];
static size_t heap_len;

static void heap_push(arrival_t a) {
  size_t i = heap_len++;
  while (i > 0 && heap[(i - 1) / 2].at_ms > a.at_ms) {
    heap[i] = heap[(i - 1) / 2];
    i = (i - 1) / 2;
  }
  heap[i] = a;
}

static arrival_t heap_pop(void) {
  const arrival_t top = heap[0];
  const arrival_t last = heap[--heap_len];
  size_t i = 0;
  for (;;) {
    size_t child = 2 * i + 1;
    if (child >= heap_len) {
      break;
    }
    if (child + 1 < heap_len && heap[child + 1].at_ms < heap[child].at_ms) {
      child++;
    }
    if (heap[child].at_ms >= last.at_ms) {
      break;
    }
    heap[i] = heap[child];
    i = child;
  }
  heap[i] = last;
  return top;
}

static uint32_t sim_newest; // highest packet number sent so far
static uint32_t sim_requests;

static uint32_t unwrap(uint16_t seq) {
  return sim_newest - (uint16_t)((uint16_t)sim_newest - seq);
}

static void sender_request(int64_t now_ms, uint16_t first, uint16_t count) {
  sim_requests++;
  if (lost(now_ms, 0x10000000U + first)) {
    return; // the request itself
  }
  for (uint16_t k = 0; k < count; k++) {
    const uint32_t index = unwrap((uint16_t)(first + k));
    const int64_t sent = now_ms + ONE_WAY_MS + RESEND_TURN_MS + k;
    if (index <= sim_newest && !lost(sent, 0x20000000U + index)) {
      heap_push((arrival_t){sent + ONE_WAY_MS, index});
    }
  }
}

static bool heard[SIM_PACKETS];
static int64_t asked_ms[SIM_PACKETS];

static void new_service(int64_t now_ms) {
  const int64_t playing = (now_ms - LATENCY_MS) / PACKET_MS;
  rtp_resend_range_t req[MAX_REQ];
  const size_t n = rtp_resend_collect(
      &r, (uint32_t)now_ms, playing >= 0,
      rtp_at((uint32_t)(playing > 0 ? playing : 0)), req, MAX_REQ);
  for (size_t i = 0; i < n; i++) {
    for (uint16_t k = 0; k < req[i].count; k++) {
      const uint32_t index = unwrap((uint16_t)(req[i].first + k));
      if (index < SIM_PACKETS && asked_ms[index] >= 0) {
        CHECK(now_ms - asked_ms[index] >= 224,
              "packet %u asked again after %lld ms", index,
              (long long)(now_ms - asked_ms[index]));
      }
      if (index < SIM_PACKETS) {
        asked_ms[index] = now_ms;
      }
    }
    sender_request(now_ms, req[i].first, req[i].count);
  }
}

static void deliver(bool use_new, old_tracker_t *old, int64_t now_ms,
                    uint32_t index, bool retransmit) {
  bool taken;
  if (use_new) {
    taken = rtp_resend_on_packet(&r, (uint16_t)index, rtp_at(index),
                                 retransmit) != RTP_RESEND_UNWANTED;
    new_service(now_ms);
  } else {
    taken = old_on_packet(old, now_ms, (uint16_t)index, retransmit);
  }
  // Heard if it arrives before its audio is due.
  if (taken && index < SIM_PACKETS &&
      now_ms < (int64_t)index * PACKET_MS + LATENCY_MS) {
    heard[index] = true;
  }
}

// Plays the whole stream through one tracker; returns the packets heard.
static uint32_t simulate(bool use_new, uint32_t *lost_on_the_way) {
  old_tracker_t old = {.last_request_ms = -1};
  rtp_resend_reset(&r, STEP);
  memset(heard, 0, sizeof(heard));
  for (size_t i = 0; i < SIM_PACKETS; i++) {
    asked_ms[i] = -1;
  }
  heap_len = 0;
  sim_requests = 0;
  *lost_on_the_way = 0;

  for (int64_t now = 0; now < SIM_MS + LATENCY_MS; now++) {
    // The original, sent ONE_WAY_MS ago.
    const int64_t sent = now - ONE_WAY_MS;
    if (sent >= 0 && sent % PACKET_MS == 0 && sent / PACKET_MS < SIM_PACKETS) {
      const uint32_t index = (uint32_t)(sent / PACKET_MS);
      sim_newest = index;
      if (lost(sent, index)) {
        (*lost_on_the_way)++;
      } else {
        deliver(use_new, &old, now, index, false);
      }
    }
    while (heap_len > 0 && heap[0].at_ms <= now) {
      const arrival_t a = heap_pop();
      deliver(use_new, &old, now, a.index, true);
    }
    // The receive loop's 100 ms socket timeout.
    if (now % 100 == 0) {
      if (use_new) {
        new_service(now);
      } else {
        old_retry_if_due(&old, now);
      }
    }
  }

  uint32_t heard_count = 0;
  for (size_t i = 0; i < SIM_PACKETS; i++) {
    heard_count += heard[i] ? 1U : 0U;
  }
  return heard_count;
}

static void test_bursty_loss(void) {
  printf("bursty loss, 120 s: recovered against the 64-packet window\n");
  make_network();
  uint32_t lost_old = 0;
  uint32_t lost_new = 0;
  const uint32_t heard_old = simulate(false, &lost_old);
  const uint32_t requests_old = sim_requests;
  const uint32_t heard_new = simulate(true, &lost_new);
  const uint32_t requests_new = sim_requests;
  CHECK(lost_old == lost_new, "the two runs saw different networks");
  const uint32_t back_old = heard_old - (SIM_PACKETS - lost_old);
  const uint32_t back_new = heard_new - (SIM_PACKETS - lost_new);
  printf("  %u of %u packets lost on the way\n", lost_new, SIM_PACKETS);
  printf("  64-packet window: %u back in time (%.0f%%), %u requests\n",
         back_old, 100.0 * back_old / lost_old, requests_old);
  printf("  whole buffer:     %u back in time (%.0f%%), %u requests\n",
         back_new, 100.0 * back_new / lost_new, requests_new);
  CHECK(back_new > back_old, "no more packets recovered than before");
  CHECK(balanced(), "counts do not add up after the run");
}

/* ---------- a sender that does not answer ---------- */

/* What the receive task did to an ESP32 Audio Brick in the field: most
 * packets lost, none ever resent, and every open hole asked for again four
 * times a second.  The task spent its time sending requests, fell behind its
 * socket, and so lost more.  The work has to stay bounded whatever is lost. */
static void test_silent_sender(void) {
  printf("silent sender, 2 in 3 packets lost for 20 s: bounded asking\n");
  rtp_resend_reset(&r, STEP);
  uint32_t state = 12345;
  uint32_t requests = 0;
  uint32_t worst_second = 0;
  uint32_t this_second = 0;
  for (uint32_t i = 0; i < 2500; i++) { // 125 packets a second
    const uint32_t now_ms = i * 8U;
    if (i % 125U == 0U) {
      this_second = 0;
    }
    state = state * 1664525U + 1013904223U;
    if (i != 0U && (state >> 16) % 3U != 0U) {
      continue; // lost
    }
    (void)feed(i);
    const size_t n = ask(now_ms);
    requests += (uint32_t)n;
    this_second += (uint32_t)n;
    if (this_second > worst_second) {
      worst_second = this_second;
    }
  }
  printf("  %u requests for %u packets asked, worst second %u requests\n",
         requests, r.counts.asked, worst_second);
  CHECK(worst_second <= RTP_RESEND_REQUESTS_PER_SECOND,
        "%u requests in one second", worst_second);
  // Once the sender has shown it will not answer, asking all but stops.
  CHECK(requests <= 20U * RTP_RESEND_REQUESTS_PER_SECOND / 4U,
        "%u requests to a sender that never answered", requests);
  CHECK(balanced(), "counts do not add up");
}

/* A hole is asked for a few times and then left alone, though it stays open
 * for a late answer. */
static void test_ask_limit(void) {
  printf("one hole, never answered: asked %u times, then left open\n",
         RTP_RESEND_MAX_ASKS);
  rtp_resend_reset(&r, STEP);
  feed_around(0, 10, 5, 1);
  uint32_t asks = 0;
  for (uint32_t now = 0; now < 4000U; now += 50U) {
    asks += (uint32_t)ask(now);
  }
  CHECK(asks == RTP_RESEND_MAX_ASKS, "asked %u times", asks);
  CHECK(rtp_resend_outstanding(&r) == 1, "hole closed");
  CHECK(resend(5) == RTP_RESEND_FILLED, "late answer refused");
}

/* An answering sender is asked as before, apart from the cap per second. */
static void test_answering_sender_not_paused(void) {
  printf("answering sender: asking goes on past the silence limit\n");
  rtp_resend_reset(&r, STEP);
  uint32_t filled = 0;
  for (uint32_t i = 0; i < 4000U; i++) {
    if (i % 4U == 1U) {
      continue; // one packet in four lost: 31 holes a second
    }
    const uint32_t now_ms = i * 8U;
    (void)feed(i);
    const size_t n = ask(now_ms);
    for (size_t k = 0; k < n; k++) {
      for (uint16_t c = 0; c < ranges[k].count; c++) {
        if (resend((uint16_t)(ranges[k].first + c)) == RTP_RESEND_FILLED) {
          filled++;
        }
      }
    }
  }
  CHECK(filled >= 990U, "only %u of 1000 holes filled", filled);
  CHECK(balanced(), "counts do not add up");
}

int main(void) {
  test_in_order();
  test_one_hole();
  test_holes_far_apart();
  test_long_gap();
  test_late_original();
  test_due_holes_dropped();
  test_window_end();
  test_gap_longer_than_window();
  test_request_cap();
  test_wraparound();
  test_packet_length_learnt();
  test_reset();
  test_bursty_loss();
  test_silent_sender();
  test_ask_limit();
  test_answering_sender_not_paused();
  if (failures) {
    printf("%d check(s) failed\n", failures);
    return 1;
  }
  printf("all passed\n");
  return 0;
}

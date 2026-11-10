// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "rtp_resend.h"

#include <string.h>

#define WINDOW_MASK (RTP_RESEND_WINDOW - 1U)
#define TICK_SHIFT  5U // 32 ms ticks: a uint8_t covers 8 s
#define RETRY_TICKS \
  ((RTP_RESEND_RETRY_MS + (1U << TICK_SHIFT) - 1U) >> TICK_SHIFT)
// The longest packet believed when learning rtp_step.
#define MAX_RTP_STEP    8192U
#define BUDGET_MS       250U
#define BUDGET_REQUESTS (RTP_RESEND_REQUESTS_PER_SECOND / (1000U / BUDGET_MS))

_Static_assert((RTP_RESEND_WINDOW & WINDOW_MASK) == 0U,
               "RTP_RESEND_WINDOW must be a power of two");
_Static_assert(RTP_RESEND_WINDOW <= 32768U,
               "the window must be shorter than half the sequence space");

static inline uint32_t slot(uint16_t seq) {
  return seq & WINDOW_MASK;
}

static inline bool bit_get(const uint32_t *bits, uint16_t seq) {
  const uint32_t i = slot(seq);
  return ((bits[i >> 5] >> (i & 31U)) & 1U) != 0U;
}

static inline void bit_set(uint32_t *bits, uint16_t seq) {
  const uint32_t i = slot(seq);
  bits[i >> 5] |= 1U << (i & 31U);
}

static inline void bit_clear(uint32_t *bits, uint16_t seq) {
  const uint32_t i = slot(seq);
  bits[i >> 5] &= ~(1U << (i & 31U));
}

void rtp_resend_reset(rtp_resend_t *r, uint32_t rtp_step) {
  memset(r, 0, sizeof(*r));
  r->rtp_step = rtp_step;
}

uint32_t rtp_resend_outstanding(const rtp_resend_t *r) {
  uint32_t open = 0;
  for (size_t i = 0; i < RTP_RESEND_WINDOW / 32U; i++) {
    open += (uint32_t)__builtin_popcount(r->missing[i]);
  }
  return open;
}

rtp_resend_verdict_t rtp_resend_on_packet(rtp_resend_t *r, uint16_t seq,
                                          uint32_t rtp, bool retransmit) {
  if (!r->valid) {
    // Nothing has been asked for yet, so no retransmission can be wanted.
    if (retransmit) {
      r->counts.unwanted++;
      return RTP_RESEND_UNWANTED;
    }
    r->valid = true;
    r->newest_seq = seq;
    r->newest_rtp = rtp;
    r->counts.received++;
    return RTP_RESEND_NEWEST;
  }

  const int32_t delta = (int16_t)(uint16_t)(seq - r->newest_seq);
  if (delta <= 0 || retransmit) {
    // Anything but the newest packet is wanted only while its hole is open.
    if (delta < 0 && (uint32_t)-delta < RTP_RESEND_WINDOW &&
        bit_get(r->missing, seq)) {
      bit_clear(r->missing, seq);
      if (retransmit) {
        r->counts.resent++;
        // The sender does answer.
        r->unanswered = 0;
        r->silent = false;
      } else {
        r->counts.late++;
      }
      return RTP_RESEND_FILLED;
    }
    r->counts.unwanted++;
    return RTP_RESEND_UNWANTED;
  }

  const uint32_t step = rtp - r->newest_rtp;
  if (delta == 1 && step > 0U && step <= MAX_RTP_STEP) {
    r->rtp_step = step;
  }

  const uint32_t skipped = (uint32_t)delta - 1U;
  r->counts.skipped += skipped;
  if ((uint32_t)delta >= RTP_RESEND_WINDOW) {
    // Longer than any realtime buffer, so none of it could still play.
    r->counts.expired += skipped + rtp_resend_outstanding(r);
    memset(r->missing, 0, sizeof(r->missing));
  } else {
    // Each slot the window moves onto last held the packet one window
    // earlier, and a hole still open there has had its chance.
    for (uint32_t i = 1; i <= (uint32_t)delta; i++) {
      const uint16_t s = (uint16_t)(r->newest_seq + i);
      if (bit_get(r->missing, s)) {
        r->counts.expired++;
      }
      if (i < (uint32_t)delta) {
        bit_set(r->missing, s);
        bit_clear(r->asked, s);
        r->asks[slot(s)] = 0;
      } else {
        bit_clear(r->missing, s);
      }
    }
  }

  r->newest_seq = seq;
  r->newest_rtp = rtp;
  r->counts.received++;
  return RTP_RESEND_NEWEST;
}

size_t rtp_resend_collect(rtp_resend_t *r, uint32_t now_ms, bool cursor_valid,
                          uint32_t cursor_rtp, rtp_resend_range_t *ranges,
                          size_t max_ranges) {
  if (!r->valid) {
    return 0;
  }

  const uint8_t tick = (uint8_t)(now_ms >> TICK_SHIFT);

  const uint32_t window = now_ms / BUDGET_MS;
  if (window != r->budget_window) {
    r->budget_window = window;
    r->budget_used = 0;
  }
  if (r->silent && (int32_t)(now_ms - r->silent_until_ms) >= 0) {
    r->silent = false;
    r->unanswered = RTP_RESEND_SILENT_REQUESTS - RTP_RESEND_PROBE_REQUESTS;
  }
  size_t allowed = 0;
  if (!r->silent && r->budget_used < BUDGET_REQUESTS) {
    allowed = BUDGET_REQUESTS - r->budget_used;
    const size_t probe = RTP_RESEND_SILENT_REQUESTS - r->unanswered;
    if (allowed > probe) {
      allowed = probe;
    }
    if (allowed > max_ranges) {
      allowed = max_ranges;
    }
  }

  size_t n = 0;
  bool extending = false;

  // Oldest first, from a window behind the newest packet up to it.
  for (uint32_t back = RTP_RESEND_WINDOW - 1U; back > 0U; back--) {
    const uint16_t seq = (uint16_t)(r->newest_seq - back);
    if (!bit_get(r->missing, seq)) {
      extending = false;
      continue;
    }

    // A packet that would arrive after its audio has played is no use.
    if (cursor_valid) {
      const uint32_t rtp = r->newest_rtp - back * r->rtp_step;
      if ((int32_t)(rtp - cursor_rtp) < 0) {
        bit_clear(r->missing, seq);
        r->counts.expired++;
        extending = false;
        continue;
      }
    }

    const uint32_t i = slot(seq);
    if (r->asks[i] >= RTP_RESEND_MAX_ASKS ||
        (bit_get(r->asked, seq) &&
         (uint8_t)(tick - r->asked_tick[i]) < RETRY_TICKS)) {
      extending = false;
      continue;
    }

    if (extending) {
      ranges[n - 1].count++;
    } else if (n < allowed) {
      ranges[n].first = seq;
      ranges[n].count = 1;
      n++;
      extending = true;
    } else {
      continue;
    }
    bit_set(r->asked, seq);
    r->asked_tick[i] = tick;
    r->counts.asked++;
    if (++r->asks[i] == RTP_RESEND_MAX_ASKS) {
      r->counts.gave_up++;
    }
  }

  r->counts.requests += (uint32_t)n;
  r->budget_used += (uint32_t)n;
  r->unanswered += (uint32_t)n;
  if (n > 0 && r->unanswered >= RTP_RESEND_SILENT_REQUESTS) {
    r->silent = true;
    r->silent_until_ms = now_ms + RTP_RESEND_SILENT_MS;
  }
  return n;
}

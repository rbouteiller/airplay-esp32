// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Missing-packet bookkeeping for the realtime (UDP) stream.
 *
 * Every sequence number skipped among the last RTP_RESEND_WINDOW packets is
 * remembered until it turns up, retransmitted or late, or until its audio is
 * due to play, so it can be asked for again for as long as it could still be
 * heard.  The window is longer than any realtime buffer: 512 packets of 352
 * frames is 4.1 s at 44.1 kHz, where a sender runs about 2 s ahead.
 *
 * Bookkeeping only, with no clock or socket of its own.  The receive task
 * owns the tracker and sends the requests.
 *
 * Asking is bounded, because the task that asks is the one that reads the
 * stream: on an ESP32 whose sender had stopped answering, re-asking for
 * hundreds of open holes four times a second kept it from its socket, which
 * overflowed and lost still more.  So a hole is asked for a few times and
 * then only waited for, the requests in any second are capped, and a sender
 * that answers none of them is left alone but for an occasional probe. */

#define RTP_RESEND_WINDOW 512U
// How long to wait for a requested packet before asking for it again.
#define RTP_RESEND_RETRY_MS 250U
// How many times one packet is asked for.  It stays wanted after that.
#ifndef RTP_RESEND_MAX_ASKS
#define RTP_RESEND_MAX_ASKS 6U
#endif
// Requests allowed in a second, shared out over its quarters.
#ifndef RTP_RESEND_REQUESTS_PER_SECOND
#define RTP_RESEND_REQUESTS_PER_SECOND 48U
#endif
// After this many requests with nothing resent, the sender is taken to be
// ignoring them: asking stops for RTP_RESEND_SILENT_MS, then
// RTP_RESEND_PROBE_REQUESTS more are tried, and so on until one is answered.
#define RTP_RESEND_SILENT_REQUESTS 32U
#define RTP_RESEND_SILENT_MS       2000U
#define RTP_RESEND_PROBE_REQUESTS  4U

typedef struct {
  uint16_t first;
  uint16_t count;
} rtp_resend_range_t;

typedef enum {
  RTP_RESEND_NEWEST,   // Newer than any packet before it; may open holes
  RTP_RESEND_FILLED,   // Filled a hole, retransmitted or out of order
  RTP_RESEND_UNWANTED, // A duplicate, or older than any hole still open
} rtp_resend_verdict_t;

// Running totals for the receive task's status line, which may clear them.
typedef struct {
  uint32_t received; // packets newer than any before them
  uint32_t skipped;  // sequence numbers that went missing
  uint32_t resent;   // holes filled by a retransmission
  uint32_t late;     // holes filled by the original packet, out of order
  uint32_t expired;  // holes given up on: due to play, or out of the window
  uint32_t unwanted; // duplicates, and packets nobody was waiting for
  uint32_t asked;    // packets asked for, each repeat counted again
  uint32_t requests; // requests made, one per run of packets
  uint32_t gave_up;  // holes asked for RTP_RESEND_MAX_ASKS times, unanswered
} rtp_resend_counts_t;

typedef struct {
  // Indexed by sequence number modulo the window.
  uint32_t missing[RTP_RESEND_WINDOW / 32U];
  uint32_t asked[RTP_RESEND_WINDOW / 32U];
  // When each hole was last asked for, in 32 ms ticks.
  uint8_t asked_tick[RTP_RESEND_WINDOW];
  // How many times each hole has been asked for.
  uint8_t asks[RTP_RESEND_WINDOW];
  // Requests made in the current quarter second.
  uint32_t budget_window;
  uint32_t budget_used;
  // Requests since a retransmission last arrived, and the pause they earn.
  uint32_t unanswered;
  bool silent;
  uint32_t silent_until_ms;
  bool valid;
  uint16_t newest_seq;
  uint32_t newest_rtp;
  // RTP frames per packet, taken from consecutive packets.
  uint32_t rtp_step;
  rtp_resend_counts_t counts;
} rtp_resend_t;

// Forgets everything.  rtp_step is the packet length to assume until two
// consecutive packets show the real one.
void rtp_resend_reset(rtp_resend_t *r, uint32_t rtp_step);

// Records a data packet or a retransmission and says whether to use it.
rtp_resend_verdict_t rtp_resend_on_packet(rtp_resend_t *r, uint16_t seq,
                                          uint32_t rtp, bool retransmit);

/* Gives up on the holes whose audio starts before cursor_rtp, when
 * cursor_valid, then writes up to max_ranges runs of holes to ask for now,
 * oldest first: those never asked for, and those last asked for at least
 * RTP_RESEND_RETRY_MS before now_ms.  Holes written count as asked at now_ms;
 * holes that do not fit wait for the next call.  Fewer than max_ranges, or
 * none, are written once the second's requests are used up, or while the
 * sender is answering nothing; a hole asked for RTP_RESEND_MAX_ASKS times is
 * not written again. */
size_t rtp_resend_collect(rtp_resend_t *r, uint32_t now_ms, bool cursor_valid,
                          uint32_t cursor_rtp, rtp_resend_range_t *ranges,
                          size_t max_ranges);

// Holes still open.
uint32_t rtp_resend_outstanding(const rtp_resend_t *r);

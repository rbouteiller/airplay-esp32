// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stdint.h>

/**
 * @file sendspin_time.h
 * @brief Sendspin client/server clock estimator.
 *
 * Sendspin timestamps every audio chunk with the instant, on the *server's*
 * monotonic microsecond clock, at which the first sample must leave the
 * speaker.  Nothing in the protocol relates that clock to ours, so the client
 * has to estimate the mapping itself from client/time exchanges:
 *
 *     client -> server  { client_transmitted }
 *     server -> client  { client_transmitted, server_received,
 *                         server_transmitted }
 *
 * plus the local arrival time, giving the four timestamps of an NTP-style
 * round trip.  Each exchange yields one offset estimate; a least-squares fit
 * over a sliding window of the low-latency ones recovers both the offset and
 * the *rate* difference between the two crystals, which is what stops the
 * playout position walking away over a long track.
 *
 * This is the AirPlay ntp_clock.c problem with different field names, and the
 * output is consumed the same way: audio_engine_v2 works in the sender's
 * clock domain, so the renderer converts its local playout instant with
 * sendspin_time_offset_ns() before asking the scheduler what to emit.
 */

/** Samples kept for the regression. ~30 s of history at the steady-state
 *  interval, which is long enough to separate drift from round-trip noise. */
#define SENDSPIN_TIME_WINDOW 16

/** Exchanges required before the estimate is trusted. The spec forbids
 *  reporting the player as available until the filter has converged. */
#define SENDSPIN_TIME_MIN_SAMPLES 6

/** Shortest history the regression will draw a rate from (us). */
#define SENDSPIN_TIME_MIN_SPAN_US 1500000LL

/** Consecutive outlier rejections tolerated before one is let through
 *  anyway. The baseline is the best round trip still in the window, so the
 *  window has to keep moving for it to track the link; without this a spell
 *  of congestion after a lucky-fast sample would reject everything for ever
 *  and freeze the fit. */
#define SENDSPIN_TIME_MAX_REJECT_RUN 4

typedef struct {
  int64_t local_us;  /* round-trip midpoint on our clock */
  int64_t offset_us; /* server - local at that instant */
  int64_t rtt_us;
} sendspin_time_sample_t;

typedef struct {
  sendspin_time_sample_t samples[SENDSPIN_TIME_WINDOW];
  uint8_t count;
  uint8_t next; /* ring insert position once full */
  uint32_t accepted;
  uint32_t rejected;
  uint8_t reject_run; /* consecutive outlier rejections */

  /* Fit: offset_us(local_us) = base_offset_us + skew * (local_us - base_us) */
  int64_t base_us;
  int64_t base_offset_us;
  double skew;
  int64_t best_rtt_us;
  bool valid;
} sendspin_time_t;

/** Drop all history; the next exchange starts a fresh estimate. */
void sendspin_time_reset(sendspin_time_t *t);

/**
 * Fold in one completed exchange. All arguments are microseconds:
 * transmitted/received on our monotonic clock for the client fields and on
 * the server's for the server fields.
 *
 * @return true if the sample was accepted (it can be rejected as an outlier).
 */
bool sendspin_time_update(sendspin_time_t *t, int64_t client_transmitted,
                          int64_t server_received, int64_t server_transmitted,
                          int64_t client_received);

/** True once the estimate is good enough to start playing to. */
bool sendspin_time_converged(const sendspin_time_t *t);

/**
 * Server-clock offset, in nanoseconds, to add to a local monotonic instant.
 *
 * Returned in nanoseconds rather than microseconds because the caller adds it
 * to audio_output_get_next_playout_time_ns(), and rounding the offset to a
 * microsecond there would inject 1 us of jitter into an error signal the
 * scheduler resolves to a fraction of a sample.
 *
 * @return false while the filter has not converged.
 */
bool sendspin_time_offset_ns(const sendspin_time_t *t, int64_t local_us,
                             int64_t *offset_ns);

/** Estimated server-vs-local rate error, parts per million. */
int32_t sendspin_time_skew_ppm(const sendspin_time_t *t);

/** Best round-trip seen in the current window (us), or 0 if none. */
int64_t sendspin_time_best_rtt_us(const sendspin_time_t *t);

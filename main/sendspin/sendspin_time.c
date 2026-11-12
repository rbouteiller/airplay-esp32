// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "sendspin_time.h"

#include <string.h>

/* An exchange is only useful if it was not delayed. Anything slower than this
 * multiple of the best round trip still in the window carries an unknown
 * amount of one-sided queueing delay, which biases the offset by half of
 * it. */
#define SENDSPIN_TIME_RTT_TOLERANCE 2

/* ...but on a quiet LAN the best RTT can be a few hundred microseconds, and
 * then the multiple above rejects almost everything. Always allow this much
 * absolute slack on top.  It has to be generous: the exchange shares one TCP
 * connection with the audio, so a chunk in flight delays it by milliseconds
 * as a matter of course.  Rejecting those wholesale leaves only the samples
 * forced through by the reject-run escape below, which are the delayed ones
 * by construction -- the worst possible selection.  The fit anchors on the
 * least-delayed sample it holds, so a wide gate costs little. */
#define SENDSPIN_TIME_RTT_SLACK_US 10000LL

/* No LAN round trip takes this long; one side stalled. Such a sample in the
 * window sets a baseline that makes the gate above meaningless until it ages
 * out, so it never gets in. */
#define SENDSPIN_TIME_RTT_CEILING_US 500000LL

/* Largest rate error the fit will report. Two crystals within spec differ by
 * well under 200 ppm; anything larger means the regression is fitting noise
 * or a step in the server's clock, and extrapolating it would be worse than
 * assuming the clocks run at the same rate. */
#define SENDSPIN_TIME_MAX_SKEW_PPM 300.0

void sendspin_time_reset(sendspin_time_t *t) {
  if (!t) {
    return;
  }
  memset(t, 0, sizeof(*t));
}

/* Least squares over the window. Both axes are taken relative to the oldest
 * retained sample so the doubles stay small: a monotonic clock that has been
 * up for a week is ~6e11 us, and squaring that loses the resolution the fit
 * is trying to find. */
static void sendspin_time_refit(sendspin_time_t *t) {
  int64_t origin_us = t->samples[0].local_us;
  int64_t oldest_us = origin_us;
  int64_t newest_us = origin_us;
  for (uint8_t i = 1; i < t->count; i++) {
    if (t->samples[i].local_us < oldest_us) {
      oldest_us = t->samples[i].local_us;
    }
    if (t->samples[i].local_us > newest_us) {
      newest_us = t->samples[i].local_us;
    }
  }
  origin_us = oldest_us;

  double sum_x = 0.0;
  double sum_y = 0.0;
  double sum_xx = 0.0;
  double sum_xy = 0.0;
  const double n = (double)t->count;
  const int64_t origin_offset = t->samples[0].offset_us;

  for (uint8_t i = 0; i < t->count; i++) {
    const double x = (double)(t->samples[i].local_us - origin_us);
    const double y = (double)(t->samples[i].offset_us - origin_offset);
    sum_x += x;
    sum_y += y;
    sum_xx += x * x;
    sum_xy += x * y;
  }

  double skew = 0.0;
  const double denom = (n * sum_xx) - (sum_x * sum_x);
  const int64_t span_us = newest_us - oldest_us;
  if (denom > 0.0 && span_us >= SENDSPIN_TIME_MIN_SPAN_US &&
      t->count >= SENDSPIN_TIME_MIN_SAMPLES) {
    skew = ((n * sum_xy) - (sum_x * sum_y)) / denom;
    const double limit = SENDSPIN_TIME_MAX_SKEW_PPM / 1e6;
    if (skew > limit) {
      skew = limit;
    } else if (skew < -limit) {
      skew = -limit;
    }
  }

  /* Take the offset from the least-delayed exchange in the window, not from
   * the regression's mean. A delayed exchange biases its own offset by half
   * the excess delay and always in the same direction, so the mean of a
   * jittery window sits well off the truth -- and audio sharing this TCP
   * connection makes the window jittery by construction. The minimum-RTT
   * sample is the one whose two one-way delays are most nearly equal, which
   * is the assumption the offset formula rests on. */
  uint8_t best = 0;
  for (uint8_t i = 1; i < t->count; i++) {
    if (t->samples[i].rtt_us < t->samples[best].rtt_us) {
      best = i;
    }
  }

  /* Carry it to the newest sample rather than leaving it where it was
   * measured: the renderer only ever evaluates the fit at or slightly after
   * "now", so keeping the lever arm short bounds what the skew term can
   * contribute. */
  t->base_us = newest_us;
  t->base_offset_us =
      t->samples[best].offset_us +
      (int64_t)(skew * (double)(newest_us - t->samples[best].local_us));
  t->skew = skew;
  t->valid = t->count >= SENDSPIN_TIME_MIN_SAMPLES;
}

bool sendspin_time_update(sendspin_time_t *t, int64_t client_transmitted,
                          int64_t server_received, int64_t server_transmitted,
                          int64_t client_received) {
  if (!t) {
    return false;
  }

  const int64_t rtt_us = (client_received - client_transmitted) -
                         (server_transmitted - server_received);
  if (rtt_us < 0 || client_received < client_transmitted) {
    /* Either clock stepped mid-exchange, or the server echoed a stale
     * client_transmitted. Neither is a usable measurement. */
    t->rejected++;
    return false;
  }
  if (rtt_us > SENDSPIN_TIME_RTT_CEILING_US) {
    t->rejected++;
    return false;
  }

  /* Standard four-timestamp offset, which assumes the two one-way delays are
   * equal. That assumption is exactly why the outlier gate below matters. */
  const int64_t offset_us = ((server_received - client_transmitted) +
                             (server_transmitted - client_received)) /
                            2;
  const int64_t midpoint_us = client_transmitted + ((rtt_us) / 2);

  /* Drop an exchange that was clearly delayed, but only once there is a
   * window to judge it against: applying this while the filter is still
   * filling lets a single lucky-fast early sample set a baseline nothing
   * else can meet, and then it never converges at all. */
  if (t->count >= SENDSPIN_TIME_MIN_SAMPLES && t->best_rtt_us > 0 &&
      rtt_us > (t->best_rtt_us * SENDSPIN_TIME_RTT_TOLERANCE) +
                   SENDSPIN_TIME_RTT_SLACK_US) {
    t->rejected++;
    if (t->reject_run < SENDSPIN_TIME_MAX_REJECT_RUN) {
      t->reject_run++;
      return false;
    }
    /* Fall through: the link has evidently changed, so take this one and
     * re-derive the baseline from it. */
  }
  t->reject_run = 0;

  const sendspin_time_sample_t sample = {
      .local_us = midpoint_us,
      .offset_us = offset_us,
      .rtt_us = rtt_us,
  };

  if (t->count < SENDSPIN_TIME_WINDOW) {
    t->samples[t->count++] = sample;
  } else {
    t->samples[t->next] = sample;
    t->next = (uint8_t)((t->next + 1U) % SENDSPIN_TIME_WINDOW);
  }
  t->accepted++;

  /* Re-derive the baseline from the retained window rather than latching an
   * all-time minimum, so it ages out with the samples: a record set minutes
   * ago on a link that has since slowed would otherwise reject every sample
   * that is perfectly good now. */
  t->best_rtt_us = t->samples[0].rtt_us;
  for (uint8_t i = 1; i < t->count; i++) {
    if (t->samples[i].rtt_us < t->best_rtt_us) {
      t->best_rtt_us = t->samples[i].rtt_us;
    }
  }

  sendspin_time_refit(t);
  return true;
}

bool sendspin_time_converged(const sendspin_time_t *t) {
  return t && t->valid;
}

bool sendspin_time_offset_ns(const sendspin_time_t *t, int64_t local_us,
                             int64_t *offset_ns) {
  if (!t || !t->valid || !offset_ns) {
    return false;
  }
  const double elapsed_us = (double)(local_us - t->base_us);
  const double offset_us = (double)t->base_offset_us + (t->skew * elapsed_us);
  *offset_ns = (int64_t)(offset_us * 1000.0);
  return true;
}

int32_t sendspin_time_skew_ppm(const sendspin_time_t *t) {
  if (!t || !t->valid) {
    return 0;
  }
  return (int32_t)(t->skew * 1e6);
}

int64_t sendspin_time_best_rtt_us(const sendspin_time_t *t) {
  return t ? t->best_rtt_us : 0;
}

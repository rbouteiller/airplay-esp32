// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Every shape the /bq page can ask for, across the band and at each rate a
 * chain is designed for, printed one JSON object per line with the five
 * coefficients the firmware designs for it. page.js designs the same
 * settings with the page's own code and compares.
 */

#include "tas58xx_biquad.h"

#include <stdio.h>

static const double rates[] = {44100.0, 48000.0, 88200.0, 96000.0};
static const double freqs[] = {20.0,    50.0,    100.0,   200.0,   500.0,
                               1000.0,  2000.0,  3150.0,  5000.0,  8000.0,
                               10000.0, 12500.0, 16000.0, 18000.0, 20000.0};
static const double qs[] = {0.5, 0.707, 2.0, 5.0, 20.0};
static const double gains[] = {-20.0, -12.0, -3.0, 3.0, 12.0, 20.0};
static const double widths[] = {0.05, 0.3, 1.0}; /* bandwidth / frequency */
static const double ripples[] = {0.1, 1.0, 3.0};

static void emit(const tas58xx_bq_t *bq, double fs) {
  double c[5];
  tas58xx_bq_design(bq, fs, c);
  printf("{\"fs\":%.1f,\"type\":%d,\"sub\":%d,\"freq\":%.9g,\"q\":%.9g,"
         "\"bw\":%.9g,\"gain\":%.9g,\"ripple\":%.9g,\"invert\":%s,"
         "\"c\":[%.17g,%.17g,%.17g,%.17g,%.17g]}\n",
         fs, bq->type, bq->sub, bq->freq_hz, bq->q, bq->bandwidth_hz,
         bq->gain_db, bq->ripple_db, bq->invert ? "true" : "false", c[0], c[1],
         c[2], c[3], c[4]);
}

int main(void) {
  const int nf = (int)(sizeof(freqs) / sizeof(freqs[0]));
  for (int r = 0; r < 4; r++) {
    const double fs = rates[r];
    for (int fi = 0; fi < nf; fi++) {
      tas58xx_bq_t bq;
      tas58xx_bq_init_bypass(&bq);
      bq.freq_hz = (float)freqs[fi];
      for (int qi = 0; qi < 5; qi++) {
        for (int gi = 0; gi < 6; gi++) {
          bq.type = TAS58XX_BQ_PEAKING_Q;
          bq.q = (float)qs[qi];
          bq.gain_db = (float)gains[gi];
          bq.invert = (qi + gi) % 2;
          emit(&bq, fs);
        }
      }
      for (int gi = 0; gi < 6; gi++) {
        bq.gain_db = (float)gains[gi];
        bq.invert = 0;
        bq.type = TAS58XX_BQ_BASS_SHELF;
        emit(&bq, fs);
        bq.type = TAS58XX_BQ_TREBLE_SHELF;
        emit(&bq, fs);
      }
      for (int t = TAS58XX_BQ_LOWPASS; t <= TAS58XX_BQ_HIGHPASS; t++) {
        bq.type = (uint8_t)t;
        for (int sub = 0; sub < TAS58XX_BQ_SUB_COUNT; sub++) {
          bq.sub = (uint8_t)sub;
          for (int qi = 0; qi < 5; qi++) {
            bq.q = (float)qs[qi];
            bq.ripple_db = (float)ripples[qi % 3];
            emit(&bq, fs);
          }
        }
        bq.sub = 0;
      }
      bq.gain_db = 6.0f;
      for (int wi = 0; wi < 3; wi++) {
        bq.bandwidth_hz = (float)(freqs[fi] * widths[wi]);
        for (int t = TAS58XX_BQ_PEAKING_BW; t <= TAS58XX_BQ_PHASE_SHIFT; t++) {
          if (t == TAS58XX_BQ_PEAKING_BW || t >= TAS58XX_BQ_BANDPASS) {
            bq.type = (uint8_t)t;
            emit(&bq, fs);
          }
        }
      }
    }
  }
  return 0;
}

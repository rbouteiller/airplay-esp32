// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Drives main/audio/audio_output_cursor.c from a model of ESP-IDF's I2S TX
 * driver (esp_driver_i2s/i2s_common.c, v6.1) and checks that the depth the
 * scheduler is given puts every frame where the DMA really plays it.
 *
 * The driver model, frame by frame:
 *  - a ring of N descriptors of F frames; i2s_channel_enable() starts the
 *    DMA at desc[0] with an empty queue and no current buffer;
 *  - at each descriptor's EOF: auto_clear, on_sent, then if the queue of
 *    N - 1 is full drop its oldest entry and call on_send_q_ovf, then push
 *    the descriptor;
 *  - i2s_channel_write(): per chunk, take the oldest queue entry (waiting
 *    for one) if the current buffer is full or unset or the queue has at
 *    most one space left, then copy as much as fits;
 *  - i2s_channel_preload_data() (S/PDIF): fills every descriptor before the
 *    enable, leaving the queue empty and the writer on a full desc[N-1].
 *
 * The writer is the backends' playback task: query the depth (the scheduler
 * does, inside audio_output_read_source()), spend some time rendering, then
 * hand the block over through output_stage (for S/PDIF it stands in for the
 * BMC encode buffer, which also writes whole descriptors).  Each frame carries
 * a tag; the prediction is query time + depth + offset in the block, and the
 * check is against the time the DMA reads it.  Frames rendered before an
 * injected event (stall, stop, hand-over) but written after it are not checked:
 * the event, not the cursor, made them late.
 *
 * Usage: test <i2s|spdif>   prints one line per scenario, exits 1 if any
 * frame is off by more than TOLERANCE frames.
 */

#include "audio_output_cursor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXN      32
#define MAXF      256
#define FB        ((size_t)sizeof(int32_t)) /* "bytes" per frame: a tag */
#define MAXTAGS   (1 << 20)
#define TOLERANCE 2
#define RENDER    40 /* frames between the depth query and the write */

typedef struct {
  const char *name;
  int n, f;
  bool preload;
  bool stops; /* the backend stops and restarts its playback task */
} config_t;

static const config_t CONFIGS[] = {
    {"i2s", 8, 256, false, true},
    {"spdif", 22, 96, true, false},
};

/* ── driver model ──────────────────────────────────────────────────────── */

static struct {
  int n, f;
  int32_t buf[MAXN][MAXF];
  int q[MAXN];
  int qh, qn;
  int cur, rw; /* cur < 0: no current buffer */
  bool running;
  int64_t pos; /* frames read by the DMA since enable */
} drv;

static const config_t *cfg;
static int64_t t; /* frames since the start of the scenario */
static uint32_t rate;

static output_cursor_t cursor;
static output_stage_t stage;
static int32_t stage_buf[MAXF];

static int64_t *played; /* tag -> t when the DMA read it, -1 never */
static int64_t *pred;   /* tag -> predicted t, -1 none */
static uint8_t *skip;   /* tag -> excluded */
static int32_t next_tag, written_tag;

/* Races injected at the points where the cursor's word could be caught
 * mid-update. */
static bool race_write; /* an EOF between the driver's pop and wrote() */
static bool race_clock; /* an EOF between the cursor load and the clock */
static bool probe;      /* a reader between on_sent and the drop */
static int probe_bad, stuck;
static long races_write, races_clock, probes_drop;

static int64_t now_us(void) {
  return t * 1000000 / (int64_t)rate;
}

static void eof(int desc);

static void dma_step(void) {
  if (drv.running) {
    const int desc = (int)((drv.pos / drv.f) % drv.n);
    const int off = (int)(drv.pos % drv.f);
    const int32_t tag = drv.buf[desc][off];
    if (tag > 0 && played[tag] < 0) {
      played[tag] = t;
    }
    drv.pos++;
    t++;
    if (drv.pos % drv.f == 0) {
      eof(desc);
    }
  } else {
    t++;
  }
}

static void advance(int64_t frames) {
  while (frames-- > 0) {
    dma_step();
  }
}

static void to_next_eof(void) {
  do {
    dma_step();
  } while (drv.pos % drv.f != 0);
}

static int64_t plain_clock(void) {
  return now_us();
}

static int64_t racy_clock(void) {
  /* An EOF due within a few frames lands between the load and this read. */
  if (race_clock && drv.running && drv.f - drv.pos % drv.f <= 8) {
    to_next_eof();
    dma_step();
    races_clock++;
  }
  return now_us();
}

static void eof(int desc) {
  for (int i = 0; i < drv.f; i++) {
    drv.buf[desc][i] = 0; /* auto_clear */
  }
  output_cursor_on_sent(&cursor, now_us());
  int64_t probe_now = 0;
  uint32_t mid = 0;
  const bool probed = probe && output_cursor_depth(&cursor, rate, plain_clock,
                                                   &probe_now, &mid);
  if (drv.qn == drv.n - 1) {
    probes_drop += probed;
    drv.qh = (drv.qh + 1) % drv.n;
    drv.qn--;
    output_cursor_on_overflow(&cursor);
  }
  drv.q[(drv.qh + drv.qn) % drv.n] = desc;
  drv.qn++;
  if (probed) {
    uint32_t after = 0;
    if (output_cursor_depth(&cursor, rate, plain_clock, &probe_now, &after) &&
        (mid > after + 1 || after > mid + 1)) {
      probe_bad++;
    }
  }
}

static void drv_reset(const config_t *cfg) {
  memset(&drv, 0, sizeof(drv));
  drv.n = cfg->n;
  drv.f = cfg->f;
  drv.cur = -1;
  for (int d = 0; d < MAXN; d++) {
    for (int i = 0; i < MAXF; i++) {
      drv.buf[d][i] = 0;
    }
  }
}

static void drv_preload(void) {
  /* Every descriptor filled (with silence here), queue empty, the writer
   * holding the last one full. */
  drv.cur = drv.n - 1;
  drv.rw = drv.f;
  drv.qn = 0;
}

static void drv_enable(void) {
  output_cursor_reset(&cursor, now_us());
  drv.running = true;
  drv.pos = 0;
}

static size_t drv_write(const int32_t *tags, size_t frames) {
  size_t i = 0;
  while (i < frames) {
    if (drv.rw == drv.f || drv.cur < 0 || drv.n - 1 - drv.qn <= 1) {
      while (drv.qn == 0) {
        dma_step();
      }
      drv.cur = drv.q[drv.qh];
      drv.qh = (drv.qh + 1) % drv.n;
      drv.qn--;
      drv.rw = 0;
      if (race_write && drv.f - drv.pos % drv.f <= 8) {
        to_next_eof(); /* ...before the writer counts what it took */
        dma_step();
        races_write++;
      }
    }
    size_t take = (size_t)(drv.f - drv.rw);
    if (take > frames - i) {
      take = frames - i;
    }
    memcpy(&drv.buf[drv.cur][drv.rw], tags + i, take * FB);
    drv.rw += (int)take;
    i += take;
  }
  return i;
}

/* ── the backends' write path ──────────────────────────────────────────── */

static void note_written(const int32_t *tags, size_t frames) {
  for (size_t i = 0; i < frames; i++) {
    if (tags[i] >= written_tag) {
      written_tag = tags[i] + 1;
    }
  }
}

/* audio_output.c: write_descs() */
static bool write_cb(void *ctx, const void *data, size_t bytes) {
  (void)ctx;
  const size_t frames = drv_write(data, bytes / FB);
  note_written(data, frames);
  if (frames * FB == bytes) {
    output_cursor_wrote(&cursor, (uint32_t)frames);
    return true;
  }
  output_cursor_lost_track(&cursor);
  return false;
}

static uint32_t lcg = 1;
static int block_frames(void) {
  lcg = lcg * 1103515245U + 12345U;
  const int jitter = (int)((lcg >> 16) % 14U); /* the servo's +-1 and more */
  return (rate == 48000 ? 370 : 340) + jitter;
}

/* One pass of the playback task loop. */
static void play_block(void) {
  for (int waited = 0; !output_cursor_known(&cursor); waited++) {
    if (waited == 1000) {
      stuck++; /* a second without regaining track */
      return;
    }
    advance(rate / 1000); /* vTaskDelay(1) */
  }
  if (output_cursor_ring_drained(&cursor)) {
    output_stage_pad(&stage, write_cb, NULL);
  }
  int64_t q_us = 0;
  uint32_t depth = 0;
  const bool ok = output_cursor_depth(&cursor, rate, racy_clock, &q_us, &depth);
  const int64_t q_t = t;
  depth += (uint32_t)(output_stage_bytes(&stage) / FB);

  const int frames = block_frames();
  static int32_t tags[1024];
  for (int i = 0; i < frames; i++) {
    tags[i] = next_tag + i;
    if (ok && next_tag + i < MAXTAGS) {
      pred[next_tag + i] = q_t + depth + i;
    }
  }
  next_tag += frames;
  /* Spread the phases when hunting for races, staying well inside the
   * descriptor of margin a writer has after a dry ring. */
  advance(race_write ? 10 + (int)((lcg >> 8) % (uint32_t)(drv.f / 2)) : RENDER);
  output_stage_push(&stage, tags, (size_t)frames * FB, write_cb, NULL);
}

static void run_blocks(int blocks) {
  for (int i = 0; i < blocks && next_tag < MAXTAGS - 2048 && !stuck; i++) {
    play_block();
  }
}

/* An event delays whatever has been rendered but not yet written. */
static void event(void) {
  for (int32_t tag = written_tag; tag < next_tag; tag++) {
    skip[tag] = 1;
  }
}

static void stop_task(void) {
  if (output_stage_bytes(&stage) > 0) {
    output_stage_pad(&stage, write_cb, NULL);
  }
}

static void start_task(void) {
  output_cursor_writer_started(&cursor);
}

/* A Bluetooth or USB sink writing through audio_output_write_pcm(). */
static void raw_writer(int chunks) {
  static int32_t silence[128];
  for (int i = 0; i < 128; i++) {
    silence[i] = 0;
  }
  for (int i = 0; i < chunks; i++) {
    drv_write(silence, 100 + (size_t)(i % 3) * 14);
    output_cursor_lost_track(&cursor);
    advance(10);
  }
}

/* ── scenarios ─────────────────────────────────────────────────────────── */

static void setup(void) {
  drv_reset(cfg);
  t = 0;
  next_tag = written_tag = 1; /* 0 is silence, as on the wire */
  race_write = race_clock = probe = false;
  probe_bad = stuck = 0;
  races_write = races_clock = probes_drop = 0;
  lcg = 1;
  for (int32_t i = 0; i < MAXTAGS; i++) {
    played[i] = -1;
    pred[i] = -1;
    skip[i] = 0;
  }
  output_cursor_init(&cursor, (uint16_t)cfg->n, (uint16_t)cfg->f);
  output_stage_init(&stage, stage_buf, (size_t)cfg->f * FB);
  advance(1000);
  if (cfg->preload) {
    drv_preload();
  }
  drv_enable();
}

/* Results gathered over one or more runs, printed as one line. */
static struct {
  int64_t worst;
  long checked, lost;
  int probe_bad, stuck;
} tally;

static void collect(void) {
  stop_task(); /* what is still staged goes out too */
  advance((int64_t)drv.n * drv.f * 3);
  for (int32_t tag = 1; tag < next_tag && tag < MAXTAGS; tag++) {
    if (pred[tag] < 0 || skip[tag]) {
      continue;
    }
    tally.checked++;
    if (played[tag] < 0) {
      tally.lost++;
      continue;
    }
    int64_t err = played[tag] - pred[tag];
    if (err < 0) {
      err = -err;
    }
    if (err > tally.worst) {
      tally.worst = err;
    }
  }
  tally.probe_bad += probe_bad;
  tally.stuck += stuck;
}

static bool report(const char *what) {
  const bool pass = tally.worst <= TOLERANCE && tally.lost == 0 &&
                    tally.probe_bad == 0 && tally.stuck == 0;
  printf("%-5s %-28s %5u Hz: worst |played - predicted| = %4lld frames "
         "(%5.2f ms) over %7ld frames%s%s%s %s\n",
         cfg->name, what, (unsigned)rate, (long long)tally.worst,
         (double)tally.worst * 1000.0 / rate, tally.checked,
         tally.lost ? ", some never played" : "",
         tally.probe_bad ? ", mid-interrupt read off" : "",
         tally.stuck ? ", writer never resumed" : "", pass ? "ok" : "FAIL");
  memset(&tally, 0, sizeof(tally));
  return pass;
}

int main(int argc, char **argv) {
  cfg = &CONFIGS[0];
  if (argc > 1 && strcmp(argv[1], "spdif") == 0) {
    cfg = &CONFIGS[1];
  }
  played = malloc(sizeof(*played) * MAXTAGS);
  pred = malloc(sizeof(*pred) * MAXTAGS);
  skip = malloc(MAXTAGS);
  if (!played || !pred || !skip) {
    return 2;
  }

  static const uint32_t RATES[] = {32000, 44100, 48000};
  static const int STALLS[] = {500, 1000, 1500, 1800, 2000, 3000};
  static const int GAPS_MS[] = {5, 20, 50, 100};
  bool ok = true;
  char what[64];

  for (size_t r = 0; r < sizeof(RATES) / sizeof(RATES[0]); r++) {
    rate = RATES[r];

    /* Writer starts 0..N+1 EOFs after the enable, at several phases. */
    for (int eofs = 0; eofs <= cfg->n + 1; eofs++) {
      for (int phase = 0; phase < cfg->f; phase += cfg->f / 4 + 1) {
        setup();
        advance((int64_t)eofs * cfg->f + phase);
        start_task();
        run_blocks(40);
        collect();
      }
    }
    snprintf(what, sizeof(what), "start 0..%d EOFs after enable", cfg->n + 1);
    ok &= report(what);

    setup();
    start_task();
    run_blocks(3000);
    collect();
    ok &= report("continuous writing");

    for (size_t s = 0; s < sizeof(STALLS) / sizeof(STALLS[0]); s++) {
      setup();
      start_task();
      run_blocks(50);
      for (int i = 0; i < 16; i++) {
        event();
        advance(STALLS[s]);
        run_blocks(17 + i * 3);
      }
      collect();
      snprintf(what, sizeof(what), "stall of %d frames", STALLS[s]);
      ok &= report(what);
    }

    if (cfg->stops) {
      for (size_t g = 0; g < sizeof(GAPS_MS) / sizeof(GAPS_MS[0]); g++) {
        setup();
        start_task();
        run_blocks(50);
        for (int i = 0; i < 12; i++) {
          stop_task();
          event();
          advance((int64_t)GAPS_MS[g] * rate / 1000 + i * 7);
          start_task();
          run_blocks(15 + i * 2);
        }
        collect();
        snprintf(what, sizeof(what), "stop, restart after %d ms", GAPS_MS[g]);
        ok &= report(what);
      }
      for (size_t g = 0; g < sizeof(GAPS_MS) / sizeof(GAPS_MS[0]); g++) {
        setup();
        start_task();
        run_blocks(30);
        for (int i = 0; i < 6; i++) {
          stop_task();
          event();
          raw_writer(150 + i * 5);
          advance((int64_t)GAPS_MS[g] * rate / 1000);
          start_task();
          run_blocks(30);
        }
        collect();
        snprintf(what, sizeof(what), "sink hand-over, %d ms gap", GAPS_MS[g]);
        ok &= report(what);
      }
    }

    setup();
    race_write = race_clock = probe = true;
    start_task();
    run_blocks(50);
    for (int i = 0; i < 300; i++) {
      event();
      advance(STALLS[i % 6] + i * 11 % 257);
      run_blocks(6);
    }
    collect();
    printf("      (EOFs landed: %ld inside a write, %ld inside a depth read, "
           "%ld drops read mid-interrupt)\n",
           races_write, races_clock, probes_drop);
    ok &= report("EOF during cursor updates");
  }

  printf(ok ? "all passed\n" : "FAILED\n");
  free(played);
  free(pred);
  free(skip);
  return ok ? 0 : 1;
}

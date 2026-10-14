// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/* Host tests for the offset filter in main/network/ptp_clock.c: SYNCs held
 * up by the network, a master whose clock steps, and when a lock may carry
 * over from one session to the next.  The file is included whole so the
 * tests can feed update_offset() without sockets. */

#include "ptp_clock.c"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#define MASTER_A      0x5c3e1b15cc4d0008ULL
#define MASTER_B      0x0011223344556677ULL
#define TRUE_OFFSET   146894076359526LL /* ns, as seen from an iPhone */
#define MS            1000000LL
#define SYNC_INTERVAL 125 /* ms, 8 Hz */

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

/* ---------- mocks ---------- */

uint32_t mock_now_ms = 1000;

void mock_log(const char *tag, const char *format, ...) {
  if (getenv("PTP_TEST_VERBOSE") == NULL) {
    return;
  }
  va_list args;
  va_start(args, format);
  printf("    [%s] ", tag);
  vprintf(format, args);
  printf("\n");
  va_end(args);
}

BaseType_t task_create_spiram(TaskFunction_t fn, const char *name,
                              uint32_t depth, void *param, int prio,
                              TaskHandle_t *handle, spiram_task_mem_t *mem) {
  (void)fn, (void)name, (void)depth, (void)param, (void)prio, (void)handle;
  (void)mem;
  return 0;
}

void task_free_spiram(spiram_task_mem_t *mem) {
  (void)mem;
}

/* ---------- helpers ---------- */

static void reset(void) {
  ptp_clock_clear();
  ptp.outlier_count = 0;
  mock_now_ms += 60000;
}

/* One SYNC whose trip took delay_ms longer than the fastest possible. */
static void sync_from(uint64_t master, int64_t offset_ns, int delay_ms) {
  mock_now_ms += SYNC_INTERVAL;
  update_offset(offset_ns - delay_ms * MS, master);
}

/* Typical WiFi: a few ms of queuing on every SYNC, never less than zero. */
static int jitter_ms(int i) {
  static const int pattern[] = {3, 11, 1, 7, 18, 0, 5, 26, 2, 9};
  return pattern[i % 10];
}

static void settle(uint64_t master, int64_t offset_ns, int count) {
  for (int i = 0; i < count; i++) {
    sync_from(master, offset_ns, jitter_ms(i));
  }
}

/* A congested network: every SYNC 70-400 ms late.  On the board, runs of 2 s
 * or more whose least delayed SYNC was 52-206 ms late came several times an
 * hour of playback, and single SYNCs up to ~700 ms late. */
static int congested_ms(int i) {
  static const int pattern[] = {70, 180, 95, 260, 120, 310, 85, 220, 150, 400};
  return pattern[i % 10];
}

static int64_t error_ms(int64_t offset_ns) {
  return (ptp_clock_get_offset_ns() - offset_ns) / MS;
}

/* ---------- tests ---------- */

/* The first sample after a reset is taken as it is.  One held up 178 ms (seen
 * on the board while the phone was streaming its opening buffer) used to make
 * every accurate sample after it an outlier. */
static void test_delayed_first_sample(void) {
  printf("delayed first sample\n");
  reset();
  sync_from(MASTER_A, TRUE_OFFSET, 178);
  settle(MASTER_A, TRUE_OFFSET, 8);
  CHECK(llabs(error_ms(TRUE_OFFSET)) <= 30, "offset %lld ms off",
        (long long)error_ms(TRUE_OFFSET));
  CHECK(ptp_clock_is_locked(), "not locked after 1 s of good samples");
}

/* A burst of delayed SYNCs is ignored, and the lock holds. */
static void test_delay_burst_ignored(void) {
  printf("delay burst\n");
  reset();
  settle(MASTER_A, TRUE_OFFSET, 40);
  int64_t before = ptp_clock_get_offset_ns();
  for (int i = 0; i < OUTLIER_RUN_RESET - 1; i++) {
    sync_from(MASTER_A, TRUE_OFFSET, 80 + jitter_ms(i));
    CHECK(ptp_clock_is_locked(), "lock lost on delayed sample %d", i);
  }
  CHECK(llabs(ptp_clock_get_offset_ns() - before) < MS,
        "offset moved %lld ns on delayed samples",
        (long long)(ptp_clock_get_offset_ns() - before));
  settle(MASTER_A, TRUE_OFFSET, 8);
  CHECK(llabs(error_ms(TRUE_OFFSET)) <= 30, "offset %lld ms off after burst",
        (long long)error_ms(TRUE_OFFSET));
}

/* An iPhone's clock stops while it sleeps, so its offset falls by the time it
 * slept.  The filter follows within a run of samples, without ever reporting
 * itself unlocked -- a playing stream reads an unlocked clock as offset 0. */
static void test_backward_step_followed(void) {
  printf("backward step\n");
  reset();
  settle(MASTER_A, TRUE_OFFSET, 40);
  int64_t stepped = TRUE_OFFSET - 4445 * MS;
  for (int i = 0; i < OUTLIER_RUN_RESET + 8; i++) {
    sync_from(MASTER_A, stepped, jitter_ms(i));
    CHECK(ptp_clock_is_locked(), "unlocked on sample %d after the step", i);
  }
  CHECK(llabs(error_ms(stepped)) <= 30, "offset %lld ms off after the step",
        (long long)error_ms(stepped));
}

/* The same step measured through congestion.  The SYNC that ends the run can
 * sit hundreds of ms below the least delayed one the filter steps to, and
 * that used to cost the lock at the very moment it was followed. */
static void test_step_through_congestion(void) {
  printf("step through congestion\n");
  reset();
  settle(MASTER_A, TRUE_OFFSET, 40);
  int64_t stepped = TRUE_OFFSET - 4445 * MS;
  for (int i = 0; i < OUTLIER_RUN_RESET + 8; i++) {
    sync_from(MASTER_A, stepped, congested_ms(i));
    CHECK(ptp_clock_is_locked(), "unlocked on sample %d after the step", i);
  }
  settle(MASTER_A, stepped, 8);
  CHECK(llabs(error_ms(stepped)) <= 30, "offset %lld ms off after the step",
        (long long)error_ms(stepped));
}

/* Congestion is not the master's clock moving.  Following it dropped the
 * estimate by the least delay of the run, and on the board threw the playout
 * error out by up to tens of ms for 10-20 s. */
static void test_congestion_not_followed(void) {
  printf("congestion\n");
  reset();
  settle(MASTER_A, TRUE_OFFSET, 40);
  int64_t before = ptp_clock_get_offset_ns();
  for (int i = 0; i < 80; i++) {
    sync_from(MASTER_A, TRUE_OFFSET, congested_ms(i));
    CHECK(ptp_clock_is_locked(), "unlocked on congested sample %d", i);
  }
  CHECK(llabs(ptp_clock_get_offset_ns() - before) < MS,
        "offset moved %lld ms in 10 s of congestion",
        (long long)((ptp_clock_get_offset_ns() - before) / MS));
  settle(MASTER_A, TRUE_OFFSET, 8);
  CHECK(llabs(error_ms(TRUE_OFFSET)) <= 30, "offset %lld ms off after it",
        (long long)error_ms(TRUE_OFFSET));
}

/* A fall no larger than congestion can cause is followed once it has lasted
 * long enough that congestion would have cleared. */
static void test_small_step_followed_later(void) {
  printf("small step\n");
  reset();
  settle(MASTER_A, TRUE_OFFSET, 40);
  int64_t stepped = TRUE_OFFSET - 300 * MS;
  for (int i = 0; i < OUTLIER_RUN_RESET_SMALL + 8; i++) {
    sync_from(MASTER_A, stepped, jitter_ms(i));
    CHECK(ptp_clock_is_locked(), "unlocked on sample %d after the step", i);
  }
  CHECK(llabs(error_ms(stepped)) <= 30, "offset %lld ms off after the step",
        (long long)error_ms(stepped));
}

/* A forward step is taken at once. */
static void test_forward_step_followed(void) {
  printf("forward step\n");
  reset();
  settle(MASTER_A, TRUE_OFFSET, 40);
  int64_t stepped = TRUE_OFFSET + 2000 * MS;
  sync_from(MASTER_A, stepped, 0);
  CHECK(llabs(error_ms(stepped)) <= 1, "offset %lld ms off after one sample",
        (long long)error_ms(stepped));
  CHECK(ptp_clock_is_locked(), "unlocked by a forward step");
}

/* The next track from the same phone keeps the lock; anything else starts
 * over. */
static void test_session_handover(void) {
  printf("session handover\n");

  reset();
  ptp_clock_set_master_clock_id(MASTER_A);
  settle(MASTER_A, TRUE_OFFSET, 40);
  ptp_clock_end_session();
  mock_now_ms += 400;
  ptp_clock_set_master_clock_id(MASTER_A);
  CHECK(ptp_clock_is_locked(), "same master, current samples: lock dropped");

  reset();
  settle(MASTER_A, TRUE_OFFSET, 40);
  ptp_clock_end_session();
  ptp_clock_set_master_clock_id(MASTER_B);
  CHECK(!ptp_clock_is_locked(), "different master: lock kept");

  reset();
  settle(MASTER_A, TRUE_OFFSET, 40);
  ptp_clock_end_session();
  mock_now_ms += SESSION_KEEP_MS + 100;
  ptp_clock_set_master_clock_id(MASTER_A);
  CHECK(!ptp_clock_is_locked(), "no samples for 2 s: lock kept");

  reset();
  settle(MASTER_A, TRUE_OFFSET, 40);
  ptp_clock_end_session();
  sync_from(MASTER_A, TRUE_OFFSET - 4445 * MS, 0);
  ptp_clock_set_master_clock_id(MASTER_A);
  CHECK(!ptp_clock_is_locked(), "master's clock just moved: lock kept");

  reset();
  settle(MASTER_A, TRUE_OFFSET, 20);
  settle(MASTER_B, TRUE_OFFSET, 20);
  ptp_clock_end_session();
  ptp_clock_set_master_clock_id(MASTER_A);
  CHECK(!ptp_clock_is_locked(), "samples from two masters: lock kept");

  /* Another master on the network keeps sending between the two sessions;
   * the ended session's filter still turns it away. */
  reset();
  ptp_clock_set_master_clock_id(MASTER_A);
  settle(MASTER_A, TRUE_OFFSET, 40);
  ptp_clock_end_session();
  const uint32_t rejected = ptp.rejected_master_count;
  uint8_t followup[PTP_HEADER_SIZE + 10] = {PTP_MSG_FOLLOW_UP};
  for (int i = 0; i < 8; i++) {
    followup[20 + i] = (uint8_t)(MASTER_B >> (56 - 8 * i));
  }
  process_ptp_message(followup, sizeof(followup), false);
  CHECK(ptp.rejected_master_count == rejected + 1,
        "other master's FOLLOW_UP let in between sessions");
  CHECK(ptp.sample_clock_id == MASTER_A,
        "samples marked mixed between sessions");
  mock_now_ms += 400;
  ptp_clock_set_master_clock_id(MASTER_A);
  CHECK(ptp_clock_is_locked(), "other master between sessions: lock dropped");
}

int main(void) {
  test_delayed_first_sample();
  test_delay_burst_ignored();
  test_backward_step_followed();
  test_step_through_congestion();
  test_congestion_not_followed();
  test_small_step_followed_later();
  test_forward_step_followed();
  test_session_handover();
  if (failures) {
    printf("%d check(s) failed\n", failures);
    return 1;
  }
  printf("all passed\n");
  return 0;
}

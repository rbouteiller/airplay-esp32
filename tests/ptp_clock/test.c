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
static _Thread_local unsigned critical_depth;
static void (*log_hook)(void);

void mock_enter_critical(portMUX_TYPE *mux) {
  if (pthread_mutex_lock(mux) != 0) {
    abort();
  }
  critical_depth++;
}

void mock_exit_critical(portMUX_TYPE *mux) {
  critical_depth--;
  if (pthread_mutex_unlock(mux) != 0) {
    abort();
  }
}

void mock_log(const char *tag, const char *format, ...) {
  if (critical_depth != 0) {
    fputs("FAIL: logging while the clock-state mux is held\n", stderr);
    abort();
  }
  if (log_hook) {
    void (*hook)(void) = log_hook;
    log_hook = NULL;
    hook();
  }
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
  ptp_update_log_t log = {0};
  portENTER_CRITICAL(&ptp_state_mux);
  update_offset(offset_ns - delay_ms * MS, master, mock_now_ms, &log);
  portEXIT_CRITICAL(&ptp_state_mux);
  log_offset_update(&log);
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

/* Build complete PTPv2 packets so source/sequence matching is exercised. */
static void make_packet(uint8_t *packet, uint8_t type, uint64_t master,
                        uint16_t port, uint16_t seq, uint64_t timestamp_ns) {
  memset(packet, 0, PTP_HEADER_SIZE + PTP_TIMESTAMP_SIZE);
  packet[0] = type;
  packet[1] = 2;
  packet[3] = PTP_HEADER_SIZE + PTP_TIMESTAMP_SIZE;
  if (type == PTP_MSG_SYNC) {
    packet[6] = 2; // twoStepFlag
  }
  for (int i = 0; i < 8; i++) {
    packet[20 + i] = (uint8_t)(master >> (56 - 8 * i));
  }
  packet[28] = (uint8_t)(port >> 8);
  packet[29] = (uint8_t)port;
  packet[30] = (uint8_t)(seq >> 8);
  packet[31] = (uint8_t)seq;
  uint64_t seconds = timestamp_ns / 1000000000ULL;
  uint32_t nanos = (uint32_t)(timestamp_ns % 1000000000ULL);
  for (int i = 0; i < 6; i++) {
    packet[34 + i] = (uint8_t)(seconds >> (40 - 8 * i));
  }
  for (int i = 0; i < 4; i++) {
    packet[40 + i] = (uint8_t)(nanos >> (24 - 8 * i));
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

/* A long pause re-seeds smoothing without dropping the lock. The accepted
 * sample ends any pre-pause outlier run, so one later delayed SYNC cannot
 * masquerade as the end of that run and move the resumed stream by 600 ms. */
static void test_resume_breaks_outlier_run(void) {
  printf("resume breaks outlier run\n");
  reset();
  settle(MASTER_A, TRUE_OFFSET, 40);
  for (int i = 0; i < OUTLIER_RUN_RESET - 1; i++) {
    sync_from(MASTER_A, TRUE_OFFSET, 600);
  }
  ptp_clock_notify_resume(30000);
  sync_from(MASTER_A, TRUE_OFFSET, 0);
  int64_t before = ptp_clock_get_offset_ns();
  sync_from(MASTER_A, TRUE_OFFSET, 700);
  CHECK(llabs(ptp_clock_get_offset_ns() - before) < MS,
        "one delayed sample after resume moved offset by %lld ms",
        (long long)((ptp_clock_get_offset_ns() - before) / MS));
  CHECK(ptp_clock_is_locked(), "resume or delayed sample dropped the lock");
}

/* The unfiltered listener can hear multiple masters before the first anchor.
 * A same-sequence FOLLOW_UP from another source must not fabricate a forward
 * clock step or let that step carry over when its master is selected. */
static void test_followup_source_identity(void) {
  printf("FOLLOW_UP source identity\n");
  reset();
  settle(MASTER_B, TRUE_OFFSET, 40);
  int64_t before = ptp_clock_get_offset_ns();
  uint32_t samples = ptp.sample_count;
  uint8_t sync[PTP_HEADER_SIZE + PTP_TIMESTAMP_SIZE];
  uint8_t followup[sizeof(sync)];
  make_packet(sync, PTP_MSG_SYNC, MASTER_A, 1, 123, 0);
  process_ptp_message(sync, sizeof(sync), true);
  mock_now_ms += 100;
  make_packet(followup, PTP_MSG_FOLLOW_UP, MASTER_B, 1, 123,
              (uint64_t)get_local_time_ns() + TRUE_OFFSET);
  process_ptp_message(followup, sizeof(followup), false);
  CHECK(ptp.sample_count == samples && ptp.sample_clock_id == MASTER_B,
        "mismatched clock changed the accepted sample history");
  CHECK(ptp_clock_get_offset_ns() == before,
        "mismatched clock fabricated an offset step");
  ptp_clock_set_master_clock_id(MASTER_B);
  CHECK(ptp_clock_is_locked() && ptp_clock_get_offset_ns() == before,
        "master selection retained a fabricated offset or lost its good lock");

  /* A second port on the same clock is also a different source. Reject it,
   * and a wrong sequence, without consuming the pending valid SYNC. */
  make_packet(sync, PTP_MSG_SYNC, MASTER_B, 1, UINT16_MAX, 0);
  process_ptp_message(sync, sizeof(sync), true);
  uint64_t origin = (uint64_t)get_local_time_ns() + TRUE_OFFSET;
  mock_now_ms += 100;
  make_packet(followup, PTP_MSG_FOLLOW_UP, MASTER_B, 2, UINT16_MAX,
              (uint64_t)get_local_time_ns() + TRUE_OFFSET);
  process_ptp_message(followup, sizeof(followup), false);
  CHECK(ptp.sample_count == samples && ptp_clock_get_offset_ns() == before,
        "mismatched source port changed the offset");
  make_packet(followup, PTP_MSG_FOLLOW_UP, MASTER_B, 1, 0, origin);
  process_ptp_message(followup, sizeof(followup), false);
  CHECK(ptp.sample_count == samples, "wrong sequence accepted");
  make_packet(followup, PTP_MSG_FOLLOW_UP, MASTER_B, 1, UINT16_MAX, origin);
  process_ptp_message(followup, sizeof(followup), false);
  CHECK(ptp.sample_count == samples + 1, "matching FOLLOW_UP rejected");

  /* Sequence wrap is valid; a duplicate FOLLOW_UP is not another sample. */
  make_packet(sync, PTP_MSG_SYNC, MASTER_B, 1, 0, 0);
  process_ptp_message(sync, sizeof(sync), true);
  make_packet(followup, PTP_MSG_FOLLOW_UP, MASTER_B, 1, 0,
              (uint64_t)get_local_time_ns() + TRUE_OFFSET);
  process_ptp_message(followup, sizeof(followup), false);
  process_ptp_message(followup, sizeof(followup), false);
  CHECK(ptp.sample_count == samples + 2,
        "sequence wrap rejected or duplicate FOLLOW_UP counted");
}

/* A reset or a switch to another master invalidates any pending pair. */
static void test_followup_invalidation(void) {
  printf("FOLLOW_UP invalidation\n");
  reset();
  ptp_clock_set_master_clock_id(MASTER_A);
  settle(MASTER_A, TRUE_OFFSET, 40);
  uint8_t sync[PTP_HEADER_SIZE + PTP_TIMESTAMP_SIZE];
  uint8_t followup[sizeof(sync)];
  make_packet(sync, PTP_MSG_SYNC, MASTER_A, 1, 10, 0);
  process_ptp_message(sync, sizeof(sync), true);
  ptp_clock_clear();
  make_packet(followup, PTP_MSG_FOLLOW_UP, MASTER_A, 1, 10,
              (uint64_t)get_local_time_ns() + TRUE_OFFSET);
  process_ptp_message(followup, sizeof(followup), false);
  CHECK(ptp.sample_count == 0, "clear retained a pending SYNC");

  ptp_clock_set_master_clock_id(MASTER_A);
  settle(MASTER_A, TRUE_OFFSET, 40);
  process_ptp_message(sync, sizeof(sync), true);
  ptp_clock_set_master_clock_id(MASTER_B);
  make_packet(followup, PTP_MSG_FOLLOW_UP, MASTER_B, 1, 10,
              (uint64_t)get_local_time_ns() + TRUE_OFFSET);
  process_ptp_message(followup, sizeof(followup), false);
  CHECK(ptp.sample_count == 0, "master change retained a pending SYNC");
}

/* Freshness belongs to the SYNC receive time, not a delayed FOLLOW_UP. Test
 * both retention and lock timeout boundaries while the millisecond tick
 * counter wraps between the two packets. */
static void test_followup_does_not_refresh_old_sample(void) {
  printf("FOLLOW_UP sample freshness\n");
  static const uint32_t delays[] = {SESSION_KEEP_MS - 1, SESSION_KEEP_MS,
                                    LOCK_TIMEOUT_MS + 1};
  for (size_t i = 0; i < sizeof(delays) / sizeof(delays[0]); i++) {
    reset();
    mock_now_ms = UINT32_MAX - 1000 - 40 * SYNC_INTERVAL;
    ptp_clock_set_master_clock_id(MASTER_A);
    settle(MASTER_A, TRUE_OFFSET, 40);
    CHECK(ptp_clock_is_locked(), "failed to lock before freshness test");
    ptp_clock_end_session();
    uint8_t sync[PTP_HEADER_SIZE + PTP_TIMESTAMP_SIZE];
    uint8_t followup[sizeof(sync)];
    make_packet(sync, PTP_MSG_SYNC, MASTER_A, 1, 10, 0);
    process_ptp_message(sync, sizeof(sync), true);
    uint64_t origin = (uint64_t)get_local_time_ns() + TRUE_OFFSET;
    mock_now_ms += delays[i];
    make_packet(followup, PTP_MSG_FOLLOW_UP, MASTER_A, 1, 10, origin);
    process_ptp_message(followup, sizeof(followup), false);
    if (delays[i] > LOCK_TIMEOUT_MS) {
      CHECK(!ptp_clock_is_locked(), "late FOLLOW_UP revived an expired lock");
    }
    ptp_clock_set_master_clock_id(MASTER_A);
    CHECK(ptp_clock_is_locked() == (delays[i] < SESSION_KEEP_MS),
          "same-master session with a %u ms old SYNC retained the wrong state",
          (unsigned)delays[i]);
  }
}

/* ESP_LOGI can yield to the PTP task. Once master selection reaches its log,
 * a foreign packet must already be excluded from the lock it decided to keep.
 */
static void foreign_packet_during_master_log(void) {
  uint8_t packet[PTP_HEADER_SIZE + PTP_TIMESTAMP_SIZE];
  make_packet(packet, PTP_MSG_SYNC, MASTER_A, 1, 50,
              (uint64_t)get_local_time_ns() + TRUE_OFFSET + 100 * MS);
  packet[6] = 0; // one-step sample
  process_ptp_message(packet, sizeof(packet), true);
}

static void test_master_selection_log_yield(void) {
  printf("master selection log yield\n");
  reset();
  settle(MASTER_B, TRUE_OFFSET, 40);
  int64_t before = ptp_clock_get_offset_ns();
  uint32_t rejected = ptp.rejected_master_count;
  log_hook = foreign_packet_during_master_log;
  ptp_clock_set_master_clock_id(MASTER_B);
  CHECK(log_hook == NULL, "master selection did not reach its log");
  CHECK(ptp.rejected_master_count == rejected + 1,
        "foreign packet was accepted during the master-selection log");
  CHECK(ptp.sample_clock_id == MASTER_B && ptp_clock_is_locked() &&
            ptp_clock_get_offset_ns() == before,
        "master selection retained a mixed clock or fabricated offset");
}

static void *packet_worker(void *unused) {
  (void)unused;
  uint8_t sync[PTP_HEADER_SIZE + PTP_TIMESTAMP_SIZE];
  uint8_t followup[sizeof(sync)];
  for (uint16_t i = 0; i < 6000; i++) {
    uint64_t master = i % 2 ? MASTER_A : MASTER_B;
    uint64_t origin = (uint64_t)get_local_time_ns() + TRUE_OFFSET +
                      (master == MASTER_A ? 100 * MS : 0);
    make_packet(sync, PTP_MSG_SYNC, master, 1, i, origin);
    if (i % 3 == 0) {
      sync[6] = 0;
    }
    process_ptp_message(sync, sizeof(sync), true);
    make_packet(followup, PTP_MSG_FOLLOW_UP, master, 1, i, origin);
    process_ptp_message(followup, sizeof(followup), false);
  }
  return NULL;
}

/* Exercise real host mutual exclusion while packets, session transitions and
 * diagnostic/audio getters run concurrently. Mock time stays fixed so this
 * isolates shared clock state from the test clock itself. */
static void test_concurrent_packets_and_sessions(void) {
  printf("concurrent packets and sessions\n");
  reset();
  pthread_t sender;
  int err = pthread_create(&sender, NULL, packet_worker, NULL);
  CHECK(err == 0, "failed to start packet worker: %d", err);
  if (err != 0) {
    return;
  }
  for (unsigned i = 0; i < 6000; i++) {
    if (i % 37 == 0) {
      ptp_clock_clear();
    }
    ptp_clock_set_master_clock_id(i % 2 ? MASTER_A : MASTER_B);
    if (i % 3 == 0) {
      ptp_clock_end_session();
    }
    if (i % 7 == 0) {
      ptp_clock_notify_resume(30000);
    }
    ptp_stats_t stats;
    ptp_clock_get_stats(&stats);
    (void)ptp_clock_get_offset_ns();
    (void)ptp_clock_get_time_ns();
    (void)ptp_clock_is_locked();
    (void)ptp_clock_get_master_clock_id();
    portENTER_CRITICAL(&ptp_state_mux);
    CHECK(ptp.expected_clock_id == 0 || ptp.sample_count == 0 ||
              ptp.sample_clock_id == ptp.expected_clock_id,
          "selected master retained samples from another clock");
    portEXIT_CRITICAL(&ptp_state_mux);
  }
  CHECK(pthread_join(sender, NULL) == 0, "failed to join packet worker");
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
  test_resume_breaks_outlier_run();
  test_followup_source_identity();
  test_followup_invalidation();
  test_followup_does_not_refresh_old_sample();
  test_master_selection_log_yield();
  test_concurrent_packets_and_sessions();
  test_session_handover();
  if (failures) {
    printf("%d check(s) failed\n", failures);
    return 1;
  }
  printf("all passed\n");
  return 0;
}

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

/*
 * V5 compressed AAC RTP store.
 *
 * 2048 directly-addressed slots. Each slot represents one 1024-sample AAC AU
 * and can hold up to 2048 decrypted AAC bytes. At 44.1 kHz the address space
 * spans 47.55 seconds before the same physical slot is reused.
 *
 * RTP is the key. Successive AAC AUs advance by 1024 samples, therefore
 *   slot = (rtp >> 10) & (2048 - 1)
 * maps successive frames to successive physical slots even when the first RTP
 * is not aligned to 1024. The exact RTP tag is always verified.
 */

#define AAC_RTP_SLOT_COUNT       2048U
#define AAC_RTP_FRAME_SAMPLES    1024U
#define AAC_RTP_SLOT_BYTES       2048U
#define AAC_RTP_RING_DURATION_MS ((AAC_RTP_SLOT_COUNT * AAC_RTP_FRAME_SAMPLES * 1000ULL) / 44100ULL)

typedef struct aac_rtp_ring aac_rtp_ring_t;

typedef struct {
  uint32_t seq;
  uint32_t rtp;
  uint32_t generation;
  uint32_t format_generation;
  uint16_t len;
} aac_rtp_item_t;

typedef struct {
  uint32_t generation;
  uint32_t ready_slots;
  uint64_t stored;
  uint64_t taken;
  uint64_t collisions;
  uint64_t oversized;
  uint64_t duplicates;
  uint64_t stale_replaced;
} aac_rtp_ring_stats_t;

esp_err_t aac_rtp_ring_create(aac_rtp_ring_t **out);
void aac_rtp_ring_destroy(aac_rtp_ring_t *ring);

/* O(1) logical clear. Old slots are invalid because their generation differs. */
void aac_rtp_ring_set_generation(aac_rtp_ring_t *ring, uint32_t generation);

/*
 * Store one decrypted AAC AU by exact RTP key. This function never waits.
 * If the direct destination still contains useful future data from the current
 * generation, the incoming AU is rejected and collisions increments.
 */
bool aac_rtp_ring_store(aac_rtp_ring_t *ring, uint32_t seq, uint32_t rtp,
                        uint32_t generation, uint32_t format_generation,
                        const uint8_t *payload, size_t len,
                        uint32_t wanted_rtp, bool wanted_valid);

/*
 * Take an exact RTP AU. The payload is copied out and the slot becomes FREE
 * immediately, before AAC decode, so TCP can reuse storage while Core1 decodes.
 */
bool aac_rtp_ring_take_exact(aac_rtp_ring_t *ring, uint32_t rtp,
                             uint32_t generation, uint8_t *out,
                             size_t out_capacity, aac_rtp_item_t *meta);

/*
 * Bootstrap decoder position without scanning: probe at most three direct RTP
 * pages and return either the AU containing wanted_rtp or the first AU after it.
 * The chosen slot is consumed/freed like take_exact().
 */
bool aac_rtp_ring_take_at_or_after(aac_rtp_ring_t *ring, uint32_t wanted_rtp,
                                   uint32_t generation, uint8_t *out,
                                   size_t out_capacity,
                                   aac_rtp_item_t *meta);

void aac_rtp_ring_get_stats(const aac_rtp_ring_t *ring,
                            aac_rtp_ring_stats_t *out);

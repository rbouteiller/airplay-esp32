#include "aac_rtp_ring.h"

#include <stdlib.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"

#define AAC_RING_MASK (AAC_RTP_SLOT_COUNT - 1U)

typedef enum {
  AAC_SLOT_FREE = 0,
  AAC_SLOT_READY = 1,
  AAC_SLOT_WRITING = 2,
  AAC_SLOT_READING = 3,
} aac_slot_state_t;

typedef struct {
  volatile uint32_t state;
  uint32_t seq;
  uint32_t rtp;
  uint32_t generation;
  uint32_t format_generation;
  uint16_t len;
  uint16_t reserved;
} aac_slot_tag_t;

struct aac_rtp_ring {
  uint8_t *payload;
  aac_slot_tag_t *tags;
  volatile uint32_t generation;
  volatile uint32_t ready_slots;
  uint64_t stored;
  uint64_t taken;
  uint64_t collisions;
  uint64_t oversized;
  uint64_t duplicates;
  uint64_t stale_replaced;
};

static const char *TAG = "aac_rtp_ring";

_Static_assert((AAC_RTP_SLOT_COUNT & (AAC_RTP_SLOT_COUNT - 1U)) == 0,
               "AAC_RTP_SLOT_COUNT must be power of two");
_Static_assert(AAC_RTP_FRAME_SAMPLES == 1024U,
               "V5 direct AAC addressing assumes 1024 samples/AU");

static inline uint32_t slot_for_rtp(uint32_t rtp) {
  return (rtp >> 10) & AAC_RING_MASK;
}

static inline int32_t rtp_delta(uint32_t a, uint32_t b) {
  return (int32_t)(a - b);
}

static inline bool frame_is_old(uint32_t rtp, uint32_t wanted_rtp) {
  return rtp_delta(rtp + AAC_RTP_FRAME_SAMPLES, wanted_rtp) <= 0;
}

esp_err_t aac_rtp_ring_create(aac_rtp_ring_t **out) {
  if (!out) {
    return ESP_ERR_INVALID_ARG;
  }
  *out = NULL;

  aac_rtp_ring_t *r = calloc(1, sizeof(*r));
  if (!r) {
    return ESP_ERR_NO_MEM;
  }

  const size_t payload_bytes =
      (size_t)AAC_RTP_SLOT_COUNT * AAC_RTP_SLOT_BYTES;
  r->payload = heap_caps_malloc(payload_bytes,
                                MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  r->tags = heap_caps_calloc(AAC_RTP_SLOT_COUNT, sizeof(aac_slot_tag_t),
                             MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  if (!r->tags) {
    r->tags = heap_caps_calloc(AAC_RTP_SLOT_COUNT, sizeof(aac_slot_tag_t),
                               MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  }
  if (!r->payload || !r->tags) {
    aac_rtp_ring_destroy(r);
    return ESP_ERR_NO_MEM;
  }

  ESP_LOGI(TAG,
           "direct RTP AAC ring V22: %u slots x %u bytes, %u ms timeline @44.1k, payload=%u bytes",
           (unsigned)AAC_RTP_SLOT_COUNT, (unsigned)AAC_RTP_SLOT_BYTES,
           (unsigned)AAC_RTP_RING_DURATION_MS, (unsigned)payload_bytes);
  *out = r;
  return ESP_OK;
}

void aac_rtp_ring_destroy(aac_rtp_ring_t *r) {
  if (!r) {
    return;
  }
  free(r->payload);
  free(r->tags);
  free(r);
}

void aac_rtp_ring_set_generation(aac_rtp_ring_t *r, uint32_t generation) {
  if (!r) {
    return;
  }
  __atomic_store_n(&r->generation, generation, __ATOMIC_RELEASE);
  __atomic_store_n(&r->ready_slots, 0U, __ATOMIC_RELEASE);
}

static bool claim_for_write(aac_rtp_ring_t *r, aac_slot_tag_t *tag,
                            uint32_t rtp, uint32_t generation,
                            uint32_t wanted_rtp, bool wanted_valid,
                            bool *replacing_current) {
  (void)wanted_rtp;
  (void)wanted_valid;
  *replacing_current = false;

  /*
   * V6 ring rule:
   *   - FREE: use it.
   *   - Different generation: old timeline, overwrite unconditionally.
   *   - Same RTP in current generation: duplicate, ignore.
   *   - Different RTP in current generation: the newer RTP wins.
   *
   * READY is only a concurrency state. It must not keep old timeline data
   * alive. Core0 never waits for the decoder; it only refuses a slot during
   * the very short READING/WRITING window.
   */
  for (int retry = 0; retry < 4; ++retry) {
    uint32_t state = __atomic_load_n(&tag->state, __ATOMIC_ACQUIRE);

    if (state == AAC_SLOT_FREE) {
      uint32_t expected = AAC_SLOT_FREE;
      if (__atomic_compare_exchange_n(&tag->state, &expected,
                                      AAC_SLOT_WRITING, false,
                                      __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        return true;
      }
      continue;
    }

    if (state != AAC_SLOT_READY) {
      return false;
    }

    const uint32_t old_gen = tag->generation;
    const uint32_t old_rtp = tag->rtp;

    if (old_gen == generation && old_rtp == rtp) {
      r->duplicates++;
      return false;
    }

    bool replace = false;
    if (old_gen != generation) {
      replace = true;
    } else if (rtp_delta(rtp, old_rtp) > 0) {
      replace = true;
      *replacing_current = true;
    } else {
      return false;
    }

    uint32_t expected = AAC_SLOT_READY;
    if (__atomic_compare_exchange_n(&tag->state, &expected,
                                    AAC_SLOT_WRITING, false,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
      if (old_gen == generation) {
        r->stale_replaced++;
      }
      return true;
    }
  }
  return false;
}

bool aac_rtp_ring_store(aac_rtp_ring_t *r, uint32_t seq, uint32_t rtp,
                        uint32_t generation, uint32_t format_generation,
                        const uint8_t *payload, size_t len,
                        uint32_t wanted_rtp, bool wanted_valid) {
  if (!r || !payload || len == 0 ||
      generation != __atomic_load_n(&r->generation, __ATOMIC_ACQUIRE)) {
    return false;
  }
  if (len > AAC_RTP_SLOT_BYTES) {
    r->oversized++;
    return false;
  }

  uint32_t slot = slot_for_rtp(rtp);
  aac_slot_tag_t *tag = &r->tags[slot];
  bool replacing_current = false;
  if (!claim_for_write(r, tag, rtp, generation, wanted_rtp, wanted_valid,
                       &replacing_current)) {
    /* A duplicate is not a capacity collision. */
    if (!(tag->generation == generation && tag->rtp == rtp &&
          __atomic_load_n(&tag->state, __ATOMIC_ACQUIRE) == AAC_SLOT_READY)) {
      r->collisions++;
    }
    return false;
  }

  memcpy(r->payload + ((size_t)slot * AAC_RTP_SLOT_BYTES), payload, len);
  tag->seq = seq;
  tag->rtp = rtp;
  tag->generation = generation;
  tag->format_generation = format_generation;
  tag->len = (uint16_t)len;
  __atomic_store_n(&tag->state, AAC_SLOT_READY, __ATOMIC_RELEASE);

  if (!replacing_current) {
    __atomic_add_fetch(&r->ready_slots, 1U, __ATOMIC_RELAXED);
  }
  r->stored++;
  return true;
}

static bool take_slot(aac_rtp_ring_t *r, uint32_t slot, uint32_t expected_rtp,
                      uint32_t generation, uint8_t *out, size_t out_capacity,
                      aac_rtp_item_t *meta) {
  aac_slot_tag_t *tag = &r->tags[slot];
  uint32_t expected = AAC_SLOT_READY;
  if (!__atomic_compare_exchange_n(&tag->state, &expected, AAC_SLOT_READING,
                                   false, __ATOMIC_ACQ_REL,
                                   __ATOMIC_ACQUIRE)) {
    return false;
  }

  if (tag->generation != generation || tag->rtp != expected_rtp ||
      tag->len == 0 || tag->len > out_capacity) {
    __atomic_store_n(&tag->state, AAC_SLOT_READY, __ATOMIC_RELEASE);
    return false;
  }

  const uint16_t len = tag->len;
  if (meta) {
    meta->seq = tag->seq;
    meta->rtp = tag->rtp;
    meta->generation = tag->generation;
    meta->format_generation = tag->format_generation;
    meta->len = len;
  }
  memcpy(out, r->payload + ((size_t)slot * AAC_RTP_SLOT_BYTES), len);

  __atomic_store_n(&tag->state, AAC_SLOT_FREE, __ATOMIC_RELEASE);
  uint32_t ready = __atomic_load_n(&r->ready_slots, __ATOMIC_RELAXED);
  if (ready > 0) {
    __atomic_sub_fetch(&r->ready_slots, 1U, __ATOMIC_RELAXED);
  }
  r->taken++;
  return true;
}

bool aac_rtp_ring_take_exact(aac_rtp_ring_t *r, uint32_t rtp,
                             uint32_t generation, uint8_t *out,
                             size_t out_capacity, aac_rtp_item_t *meta) {
  if (!r || !out || generation !=
                         __atomic_load_n(&r->generation, __ATOMIC_ACQUIRE)) {
    return false;
  }
  return take_slot(r, slot_for_rtp(rtp), rtp, generation, out, out_capacity,
                   meta);
}

static bool inspect_ready(const aac_rtp_ring_t *r, uint32_t slot,
                          uint32_t generation, uint32_t *rtp_out) {
  const aac_slot_tag_t *tag = &r->tags[slot];
  if (__atomic_load_n(&tag->state, __ATOMIC_ACQUIRE) != AAC_SLOT_READY ||
      tag->generation != generation) {
    return false;
  }
  *rtp_out = tag->rtp;
  return true;
}

bool aac_rtp_ring_take_at_or_after(aac_rtp_ring_t *r, uint32_t wanted_rtp,
                                   uint32_t generation, uint8_t *out,
                                   size_t out_capacity,
                                   aac_rtp_item_t *meta) {
  if (!r || !out || generation !=
                         __atomic_load_n(&r->generation, __ATOMIC_ACQUIRE)) {
    return false;
  }

  /* A 1024-sample AU containing wanted can only have (rtp>>10) equal to q or
   * q-1. The first AU after wanted can only be in q or q+1. Three probes are
   * therefore enough; no ring scan is needed. */
  uint32_t q = wanted_rtp >> 10;
  uint32_t slots[3] = {(q - 1U) & AAC_RING_MASK, q & AAC_RING_MASK,
                       (q + 1U) & AAC_RING_MASK};

  bool have_containing = false;
  uint32_t containing_rtp = 0;
  bool have_future = false;
  uint32_t future_rtp = 0;

  for (unsigned i = 0; i < 3; ++i) {
    uint32_t rtp;
    if (!inspect_ready(r, slots[i], generation, &rtp)) {
      continue;
    }
    int32_t from_start = rtp_delta(wanted_rtp, rtp);
    if (from_start >= 0 && from_start < (int32_t)AAC_RTP_FRAME_SAMPLES) {
      containing_rtp = rtp;
      have_containing = true;
      break;
    }
    int32_t future = rtp_delta(rtp, wanted_rtp);
    if (future > 0 && future < (int32_t)AAC_RTP_FRAME_SAMPLES &&
        (!have_future || rtp_delta(rtp, future_rtp) < 0)) {
      future_rtp = rtp;
      have_future = true;
    }
  }

  if (have_containing) {
    return aac_rtp_ring_take_exact(r, containing_rtp, generation, out,
                                   out_capacity, meta);
  }
  if (have_future) {
    return aac_rtp_ring_take_exact(r, future_rtp, generation, out,
                                   out_capacity, meta);
  }
  return false;
}

void aac_rtp_ring_get_stats(const aac_rtp_ring_t *r,
                            aac_rtp_ring_stats_t *out) {
  if (!r || !out) {
    return;
  }
  out->generation = __atomic_load_n(&r->generation, __ATOMIC_ACQUIRE);
  out->ready_slots = __atomic_load_n(&r->ready_slots, __ATOMIC_ACQUIRE);
  out->stored = r->stored;
  out->taken = r->taken;
  out->collisions = r->collisions;
  out->oversized = r->oversized;
  out->duplicates = r->duplicates;
  out->stale_replaced = r->stale_replaced;
}

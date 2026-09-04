#include "audio_clock_map.h"

#include <limits.h>

void audio_clock_map_reset(audio_clock_map_t *map) {
  if (!map) {
    return;
  }
  *map = (audio_clock_map_t){0};
}

bool audio_clock_map_set(audio_clock_map_t *map, uint32_t sample_rate,
                         uint32_t anchor_rtp, uint64_t anchor_network_ns,
                         int64_t playout_offset_ns) {
  if (!map || sample_rate == 0U || anchor_network_ns > (uint64_t)INT64_MAX) {
    return false;
  }

  map->sample_rate = sample_rate;
  map->anchor_rtp = anchor_rtp;
  map->anchor_network_ns = anchor_network_ns;
  map->playout_offset_ns = playout_offset_ns;
  map->valid = true;
  return true;
}

bool audio_clock_map_rtp_to_network(const audio_clock_map_t *map, uint32_t rtp,
                                    int64_t *network_ns) {
  if (!map || !map->valid || !network_ns || map->sample_rate == 0U) {
    return false;
  }

  int64_t delta_samples = (int64_t)(int32_t)(rtp - map->anchor_rtp);
  int64_t delta_ns = (delta_samples * 1000000000LL) / map->sample_rate;
  *network_ns =
      (int64_t)map->anchor_network_ns + map->playout_offset_ns + delta_ns;
  return true;
}

bool audio_clock_map_network_to_rtp(const audio_clock_map_t *map,
                                    int64_t network_ns, uint32_t *rtp) {
  if (!map || !map->valid || !rtp || map->sample_rate == 0U) {
    return false;
  }

  int64_t base_ns = (int64_t)map->anchor_network_ns + map->playout_offset_ns;
  int64_t delta_ns = network_ns - base_ns;
  int64_t delta_samples = (delta_ns * map->sample_rate) / 1000000000LL;
  *rtp = map->anchor_rtp + (uint32_t)(int32_t)delta_samples;
  return true;
}

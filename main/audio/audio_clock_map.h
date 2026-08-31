#pragma once

#include <stdbool.h>
#include <stdint.h>

/* The anchor lives in the SENDER's clock domain, which is PTP for AirPlay 2
 * and NTP for AirPlay 1.  The mapping is identical either way, so nothing
 * here names a protocol; the caller converts local time into the domain the
 * anchor arrived in before calling audio_clock_map_network_to_rtp(). */
typedef struct {
  bool valid;
  uint32_t sample_rate;
  uint32_t anchor_rtp;
  uint64_t anchor_network_ns;
  int64_t playout_offset_ns;
} audio_clock_map_t;

void audio_clock_map_reset(audio_clock_map_t *map);
bool audio_clock_map_set(audio_clock_map_t *map, uint32_t sample_rate,
                         uint32_t anchor_rtp, uint64_t anchor_network_ns,
                         int64_t playout_offset_ns);
bool audio_clock_map_rtp_to_network(const audio_clock_map_t *map, uint32_t rtp,
                                    int64_t *network_ns);
bool audio_clock_map_network_to_rtp(const audio_clock_map_t *map,
                                    int64_t network_ns, uint32_t *rtp);

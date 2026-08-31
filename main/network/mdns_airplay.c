#include "esp_app_desc.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "mdns.h"
#include <stdio.h>
#include <string.h>

#include "hap.h"
#include "mdns_airplay.h"
#include "rtsp_handlers.h"
#include "rtsp_server.h"
#include "wifi.h"
#include "settings.h"

static const char *TAG = "mdns_airplay";

// Longest single DNS label (RFC 1035). The mDNS component caps names at
// MDNS_NAME_MAX_LEN, which is never smaller than this.
#define MDNS_HOSTNAME_MAX_LEN 63

// Feature flags are defined in rtsp_handlers.h (shared with /info handler)

// Only ever emitted on the AirPlay 2 records; the classic _raop._tcp TXT has
// no vv field and _airplay._tcp is not registered at all in v1 mode.
#define AIRPLAY_PROTOCOL_VERSION "2"
#define AIRPLAY_SOURCE_VERSION   "377.40.00"

// Flags: 0x4 = audio receiver
#define AIRPLAY_FLAGS "0x4"

// Metadata types advertised in the "md" txt record:
//   0 = text (track title/artist/album), 1 = artwork (cover art images),
//   2 = progress.
// When artwork is disabled, drop "1" so senders do not transmit cover art
// (which can stall the audio pipeline and cause drop-outs on realtime
// streams) while still sending text and progress metadata.
#ifdef CONFIG_ENABLE_AIRPLAY_ARTWORK
#define AIRPLAY_METADATA_TYPES "0,1,2"
#else
#define AIRPLAY_METADATA_TYPES "0,2"
#endif

// Model identifier - AudioAccessory for speaker appearance
// AppleTV3,2 = Apple TV, AudioAccessory5,1 = HomePod mini (speaker)
#define AIRPLAY_MODEL "AudioAccessory5,1"

// In classic mode the device must not look like an AirPlay 2 speaker at all:
// AirPort4,107 is the first-generation AirPort Express and 105.1 is the source
// version it reported.
#define AIRPLAY_V1_MODEL          "AirPort4,107"
#define AIRPLAY_V1_SOURCE_VERSION "105.1"

void mdns_airplay_init(void) {
  char mac_str[18];
  char device_id[18];
  char features_str[32];
  char service_name[80];
  char pk_str[65]; // 32 bytes = 64 hex chars + null
  char device_name[65];
  char hostname[MDNS_HOSTNAME_MAX_LEN + 1];

  // Get device name from settings. This is the user-facing name and stays
  // UTF-8 for the service instance names below; only the hostname is
  // restricted to ASCII.
  settings_get_device_name(device_name, sizeof(device_name));
  settings_device_name_to_hostname(device_name, hostname, sizeof(hostname));

  // Get MAC address
  wifi_get_mac_str(mac_str, sizeof(mac_str));
  strncpy(device_id, mac_str, sizeof(device_id));

  // Get real Ed25519 public key from HAP module
  const uint8_t *pk = hap_get_public_key();
  for (int i = 0; i < 32; i++) {
    snprintf(pk_str + (size_t)i * 2, 3, "%02x", pk[i]);
  }

  // Format features as "hi,lo" hex string
  uint64_t features = airplay_features();
  snprintf(features_str, sizeof(features_str), "0x%X,0x%X",
           (unsigned)(features & 0xFFFFFFFF), (unsigned)(features >> 32));

  // Create service name for RAOP: <mac>@<name>
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  snprintf(service_name, sizeof(service_name), "%02X%02X%02X%02X%02X%02X@%s",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], device_name);

  // Initialize mDNS
  ESP_ERROR_CHECK(mdns_init());

  // Set hostname. A bad name must not panic the device, so this is logged
  // like the service registrations below rather than ESP_ERROR_CHECK'd.
  esp_err_t err_host = mdns_hostname_set(hostname);
  if (err_host != ESP_OK) {
    ESP_LOGE(TAG, "Failed to set mDNS hostname '%s': %s", hostname,
             esp_err_to_name(err_host));
  } else {
    ESP_LOGI(TAG, "mDNS hostname: %s.local (device name: %s)", hostname,
             device_name);
  }

  const bool airplay_v1 = settings_airplay_v1();

  if (!airplay_v1) {
    // ========================================
    // _airplay._tcp service
    // Only registered for AirPlay 2 mode
    // ========================================
    mdns_txt_item_t airplay_txt[] = {
        {"deviceid", device_id},
        {"features", features_str},
        {"flags", AIRPLAY_FLAGS},
        {"model", AIRPLAY_MODEL},
        {"pk", pk_str},
        {"pi", "00000000-0000-0000-0000-000000000000"}, // Pairing identity UUID
        {"srcvers", AIRPLAY_SOURCE_VERSION},
        {"vv", AIRPLAY_PROTOCOL_VERSION},
        {"acl", "0"},
    };

    esp_err_t err = mdns_service_add(
        device_name, "_airplay", "_tcp", airplay_rtsp_port(), airplay_txt,
        sizeof(airplay_txt) / sizeof(airplay_txt[0]));
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Failed to add _airplay._tcp service: %s",
               esp_err_to_name(err));
    }
  }

  // ========================================
  // _raop._tcp service
  // RAOP = Remote Audio Output Protocol
  // Service name format: <MAC>@<DeviceName>
  // ========================================
  esp_err_t err_raop;
  if (airplay_v1) {
    // AirPlay v1 (classic RAOP). This mirrors shairport-sync's classic record
    // (bonjour_strings.c), which is the advertisement Apple Music on Windows
    // accepts — it rejects anything carrying AirPlay 2 markers. No features, no
    // pk, no HAP pairing.
    mdns_txt_item_t raop_txt[] = {
        {"am", AIRPLAY_V1_MODEL},
        {"ch", "2"},    // Channels
        {"cn", "0,1"},  // Audio codecs: PCM, ALAC
        {"da", "true"}, // Digest auth
        {"ek", "1"},    // Encryption key available
        {"et", "0,1"},  // Encryption types: none, RSA
        {"fv", esp_app_get_description()->version}, // Firmware version
        {"md", AIRPLAY_METADATA_TYPES},             // Metadata types
        {"pw", "false"},                            // No password required
        {"sf", AIRPLAY_FLAGS},                      // Status flags
        {"sr", "44100"},                            // Sample rate
        {"ss", "16"},                               // Sample size (bits)
        {"sv", "false"},                            // Server version (unused)
        {"tp", "UDP"},                              // Transport protocol
        {"vn", "65537"},                            // Version number
        {"vs", AIRPLAY_V1_SOURCE_VERSION},          // Source version
        {"txtvers", "1"},                           // TXT record version
    };
    err_raop =
        mdns_service_add(service_name, "_raop", "_tcp", airplay_rtsp_port(),
                         raop_txt, sizeof(raop_txt) / sizeof(raop_txt[0]));
  } else {
    // Dual-mode: include et=1 (RSA) so RAOP-only clients (TuneBlade, AirMusic,
    // shairtunes2, etc.) accept the advertisement, while keeping et=3,5 for
    // AirPlay 2 FairPlay/MFi-SAP. ek=1 advertises that an RSA-encrypted key
    // can be supplied via SDP rsaaeskey: at ANNOUNCE time.
    mdns_txt_item_t raop_txt[] = {
        {"am", AIRPLAY_MODEL},
        {"cn", "0,1,2,3"},              // Audio codecs: PCM, ALAC, AAC, AAC-ELD
        {"da", "true"},                 // Digest auth
        {"ek", "1"},                    // Encryption key available (RSA)
        {"et", "0,1,3,5"},              // Encryption types
        {"ft", features_str},           // Features (same as airplay)
        {"md", AIRPLAY_METADATA_TYPES}, // Metadata types
        {"pk", pk_str},                 // Public key
        {"sf", AIRPLAY_FLAGS},          // Status flags
        {"tp", "UDP"},                  // Transport protocol
        {"vn", "65537"},                // Version number
        {"vs", AIRPLAY_SOURCE_VERSION},
        {"vv", AIRPLAY_PROTOCOL_VERSION},
    };
    err_raop =
        mdns_service_add(service_name, "_raop", "_tcp", airplay_rtsp_port(),
                         raop_txt, sizeof(raop_txt) / sizeof(raop_txt[0]));
  }
  if (err_raop != ESP_OK) {
    ESP_LOGE(TAG, "Failed to add _raop._tcp service: %s",
             esp_err_to_name(err_raop));
  }
  ESP_LOGI(TAG, "_raop._tcp advertised on port %d (AirPlay %s)",
           airplay_rtsp_port(), airplay_v1 ? "1" : "2");
}

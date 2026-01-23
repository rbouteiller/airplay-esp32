#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_mac.h"
#include "mdns.h"

#include "mdns_airplay.h"
#include "wifi.h"
#include "hap.h"

static const char *TAG = "mdns_airplay";

// Device name that appears in AirPlay menu
#define AIRPLAY_DEVICE_NAME CONFIG_AIRPLAY_DEVICE_NAME

// AirPlay 2 feature flags (matching shairport-sync)
// Bit definitions from: https://openairplay.github.io/airplay-spec/features.html
// Key bits for encryption:
//   Bit 38: SupportsCoreUtilsPairingAndEncryption
//   Bit 46: SupportsHKPairingAndAccessControl
//   Bit 48: SupportsTransientPairing
#define AIRPLAY_FEATURES_HI  0x1C340
#define AIRPLAY_FEATURES_LO  0x405C4A00

// Protocol version
#define AIRPLAY_PROTOCOL_VERSION "2"
#define AIRPLAY_SOURCE_VERSION   "377.40.00"

// Flags: 0x4 = audio receiver
#define AIRPLAY_FLAGS "0x4"

// Model identifier - AudioAccessory for speaker appearance
// AppleTV3,2 = Apple TV, AudioAccessory5,1 = HomePod mini (speaker)
#define AIRPLAY_MODEL "AudioAccessory5,1"

void mdns_airplay_init(void)
{
    char mac_str[18];
    char device_id[18];
    char features_str[32];
    char service_name[64];
    char pk_str[65]; // 32 bytes = 64 hex chars + null

    // Get MAC address
    wifi_get_mac_str(mac_str, sizeof(mac_str));
    strncpy(device_id, mac_str, sizeof(device_id));

    // Get real Ed25519 public key from HAP module
    const uint8_t *pk = hap_get_public_key();
    for (int i = 0; i < 32; i++) {
        snprintf(pk_str + i * 2, 3, "%02x", pk[i]);
    }

    // Format features as "hi,lo" hex string
    snprintf(features_str, sizeof(features_str), "0x%X,0x%X",
             AIRPLAY_FEATURES_LO, AIRPLAY_FEATURES_HI);

    // Create service name for RAOP: <mac>@<name>
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(service_name, sizeof(service_name), "%02X%02X%02X%02X%02X%02X@%s",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
             AIRPLAY_DEVICE_NAME);

    ESP_LOGI(TAG, "Initializing mDNS...");
    ESP_LOGI(TAG, "Device ID: %s", device_id);
    ESP_LOGI(TAG, "Device Name: %s", AIRPLAY_DEVICE_NAME);
    ESP_LOGI(TAG, "Features: %s", features_str);

    // Initialize mDNS
    ESP_ERROR_CHECK(mdns_init());

    // Set hostname
    ESP_ERROR_CHECK(mdns_hostname_set(AIRPLAY_DEVICE_NAME));

    // ========================================
    // _airplay._tcp service (port 7000)
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

    esp_err_t err = mdns_service_add(AIRPLAY_DEVICE_NAME, "_airplay", "_tcp",
                                     7000, airplay_txt,
                                     sizeof(airplay_txt) / sizeof(airplay_txt[0]));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to add _airplay._tcp service: %s", esp_err_to_name(err));
    } else {
        ESP_LOGI(TAG, "Added _airplay._tcp service on port 7000");
    }

    // ========================================
    // _raop._tcp service (port 7000)
    // RAOP = Remote Audio Output Protocol
    // Service name format: <MAC>@<DeviceName>
    // ========================================
    mdns_txt_item_t raop_txt[] = {
        {"am", AIRPLAY_MODEL},
        {"cn", "0,1,2,3"},           // Audio codecs: PCM, ALAC, AAC, AAC-ELD
        {"da", "true"},              // Digest auth
        {"et", "0,3,5"},             // Encryption types
        {"ft", features_str},        // Features (same as airplay)
        {"md", "0,1,2"},             // Metadata types
        {"pk", pk_str},              // Public key
        {"sf", AIRPLAY_FLAGS},       // Status flags
        {"tp", "UDP"},               // Transport protocol
        {"vn", "65537"},             // Version number
        {"vs", AIRPLAY_SOURCE_VERSION},
        {"vv", AIRPLAY_PROTOCOL_VERSION},
    };

    err = mdns_service_add(service_name, "_raop", "_tcp",
                           7000, raop_txt,
                           sizeof(raop_txt) / sizeof(raop_txt[0]));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to add _raop._tcp service: %s", esp_err_to_name(err));
    } else {
        ESP_LOGI(TAG, "Added _raop._tcp service: %s", service_name);
    }

    ESP_LOGI(TAG, "mDNS AirPlay services started");
    ESP_LOGI(TAG, "Device '%s' should now appear in AirPlay menu", AIRPLAY_DEVICE_NAME);
}

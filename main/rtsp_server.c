#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_heap_caps.h"

#include "sodium.h"

#include "rtsp_server.h"
#include "plist.h"
#include "hap.h"
#include "tlv8.h"
#include "audio_receiver.h"

static const char *TAG = "rtsp_server";

#define RTSP_PORT 7000
// Small buffer for normal RTSP messages
#define RTSP_BUFFER_INITIAL 4096
// Large buffer for buffered audio data (up to 256KB)
#define RTSP_BUFFER_LARGE (256 * 1024)
#define RTSP_MAX_RESPONSE_SIZE 8192
#define ENCRYPTED_BLOCK_MAX 0x400

static int server_socket = -1;
static TaskHandle_t server_task_handle = NULL;
static bool server_running = false;

// Current HAP session (one client at a time for now)
static hap_session_t *current_session = NULL;

// Encrypted communication state
static bool encrypted_mode = false;

// Volume control: stored as Q15 fixed-point (0-32768)
// 32768 = 0 dB (unity), 0 = mute
static volatile int32_t g_volume_q15 = 32768;  // Default to full volume
static float g_volume_db = 0.0f;  // Current volume in dB

void airplay_set_volume(float volume_db)
{
    g_volume_db = volume_db;

    // AirPlay volume: 0 dB = max, -30 dB = mute
    // Use linear mapping with squared curve for better perceptual control
    if (volume_db <= -30.0f) {
        g_volume_q15 = 0;
    } else if (volume_db >= 0.0f) {
        g_volume_q15 = 32768;
    } else {
        // Map -30..0 to 0..1, then square for perceptual curve
        float normalized = (volume_db + 30.0f) / 30.0f;
        float curved = normalized * normalized;
        g_volume_q15 = (int32_t)(curved * 32768.0f);
    }
}

int32_t airplay_get_volume_q15(void)
{
    return g_volume_q15;
}

// AirPlay 2 features flags (matching shairport-sync)
// Key bits:
//   Bit 38: SupportsCoreUtilsPairingAndEncryption
//   Bit 46: SupportsHKPairingAndAccessControl
//   Bit 48: SupportsTransientPairing
#define FEATURES_HI 0x1C340
#define FEATURES_LO 0x405C4A00

// FairPlay pre-computed responses (from shairport-sync)
// These static tables handle the FairPlay handshake
static const uint8_t fp_reply1[] = {
    0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x82,
    0x02, 0x00, 0x0f, 0x9f, 0x3f, 0x9e, 0x0a, 0x25, 0x21, 0xdb, 0xdf, 0x31,
    0x2a, 0xb2, 0xbf, 0xb2, 0x9e, 0x8d, 0x23, 0x2b, 0x63, 0x76, 0xa8, 0xc8,
    0x18, 0x70, 0x1d, 0x22, 0xae, 0x93, 0xd8, 0x27, 0x37, 0xfe, 0xaf, 0x9d,
    0xb4, 0xfd, 0xf4, 0x1c, 0x2d, 0xba, 0x9d, 0x1f, 0x49, 0xca, 0xaa, 0xbf,
    0x65, 0x91, 0xac, 0x1f, 0x7b, 0xc6, 0xf7, 0xe0, 0x66, 0x3d, 0x21, 0xaf,
    0xe0, 0x15, 0x65, 0x95, 0x3e, 0xab, 0x81, 0xf4, 0x18, 0xce, 0xed, 0x09,
    0x5a, 0xdb, 0x7c, 0x3d, 0x0e, 0x25, 0x49, 0x09, 0xa7, 0x98, 0x31, 0xd4,
    0x9c, 0x39, 0x82, 0x97, 0x34, 0x34, 0xfa, 0xcb, 0x42, 0xc6, 0x3a, 0x1c,
    0xd9, 0x11, 0xa6, 0xfe, 0x94, 0x1a, 0x8a, 0x6d, 0x4a, 0x74, 0x3b, 0x46,
    0xc3, 0xa7, 0x64, 0x9e, 0x44, 0xc7, 0x89, 0x55, 0xe4, 0x9d, 0x81, 0x55,
    0x00, 0x95, 0x49, 0xc4, 0xe2, 0xf7, 0xa3, 0xf6, 0xd5, 0xba
};
static const uint8_t fp_reply2[] = {
    0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x82,
    0x02, 0x01, 0xcf, 0x32, 0xa2, 0x57, 0x14, 0xb2, 0x52, 0x4f, 0x8a, 0xa0,
    0xad, 0x7a, 0xf1, 0x64, 0xe3, 0x7b, 0xcf, 0x44, 0x24, 0xe2, 0x00, 0x04,
    0x7e, 0xfc, 0x0a, 0xd6, 0x7a, 0xfc, 0xd9, 0x5d, 0xed, 0x1c, 0x27, 0x30,
    0xbb, 0x59, 0x1b, 0x96, 0x2e, 0xd6, 0x3a, 0x9c, 0x4d, 0xed, 0x88, 0xba,
    0x8f, 0xc7, 0x8d, 0xe6, 0x4d, 0x91, 0xcc, 0xfd, 0x5c, 0x7b, 0x56, 0xda,
    0x88, 0xe3, 0x1f, 0x5c, 0xce, 0xaf, 0xc7, 0x43, 0x19, 0x95, 0xa0, 0x16,
    0x65, 0xa5, 0x4e, 0x19, 0x39, 0xd2, 0x5b, 0x94, 0xdb, 0x64, 0xb9, 0xe4,
    0x5d, 0x8d, 0x06, 0x3e, 0x1e, 0x6a, 0xf0, 0x7e, 0x96, 0x56, 0x16, 0x2b,
    0x0e, 0xfa, 0x40, 0x42, 0x75, 0xea, 0x5a, 0x44, 0xd9, 0x59, 0x1c, 0x72,
    0x56, 0xb9, 0xfb, 0xe6, 0x51, 0x38, 0x98, 0xb8, 0x02, 0x27, 0x72, 0x19,
    0x88, 0x57, 0x16, 0x50, 0x94, 0x2a, 0xd9, 0x46, 0x68, 0x8a
};
static const uint8_t fp_reply3[] = {
    0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x82,
    0x02, 0x02, 0xc1, 0x69, 0xa3, 0x52, 0xee, 0xed, 0x35, 0xb1, 0x8c, 0xdd,
    0x9c, 0x58, 0xd6, 0x4f, 0x16, 0xc1, 0x51, 0x9a, 0x89, 0xeb, 0x53, 0x17,
    0xbd, 0x0d, 0x43, 0x36, 0xcd, 0x68, 0xf6, 0x38, 0xff, 0x9d, 0x01, 0x6a,
    0x5b, 0x52, 0xb7, 0xfa, 0x92, 0x16, 0xb2, 0xb6, 0x54, 0x82, 0xc7, 0x84,
    0x44, 0x11, 0x81, 0x21, 0xa2, 0xc7, 0xfe, 0xd8, 0x3d, 0xb7, 0x11, 0x9e,
    0x91, 0x82, 0xaa, 0xd7, 0xd1, 0x8c, 0x70, 0x63, 0xe2, 0xa4, 0x57, 0x55,
    0x59, 0x10, 0xaf, 0x9e, 0x0e, 0xfc, 0x76, 0x34, 0x7d, 0x16, 0x40, 0x43,
    0x80, 0x7f, 0x58, 0x1e, 0xe4, 0xfb, 0xe4, 0x2c, 0xa9, 0xde, 0xdc, 0x1b,
    0x5e, 0xb2, 0xa3, 0xaa, 0x3d, 0x2e, 0xcd, 0x59, 0xe7, 0xee, 0xe7, 0x0b,
    0x36, 0x29, 0xf2, 0x2a, 0xfd, 0x16, 0x1d, 0x87, 0x73, 0x53, 0xdd, 0xb9,
    0x9a, 0xdc, 0x8e, 0x07, 0x00, 0x6e, 0x56, 0xf8, 0x50, 0xce
};
static const uint8_t fp_reply4[] = {
    0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x82,
    0x02, 0x03, 0x90, 0x01, 0xe1, 0x72, 0x7e, 0x0f, 0x57, 0xf9, 0xf5, 0x88,
    0x0d, 0xb1, 0x04, 0xa6, 0x25, 0x7a, 0x23, 0xf5, 0xcf, 0xff, 0x1a, 0xbb,
    0xe1, 0xe9, 0x30, 0x45, 0x25, 0x1a, 0xfb, 0x97, 0xeb, 0x9f, 0xc0, 0x01,
    0x1e, 0xbe, 0x0f, 0x3a, 0x81, 0xdf, 0x5b, 0x69, 0x1d, 0x76, 0xac, 0xb2,
    0xf7, 0xa5, 0xc7, 0x08, 0xe3, 0xd3, 0x28, 0xf5, 0x6b, 0xb3, 0x9d, 0xbd,
    0xe5, 0xf2, 0x9c, 0x8a, 0x17, 0xf4, 0x81, 0x48, 0x7e, 0x3a, 0xe8, 0x63,
    0xc6, 0x78, 0x32, 0x54, 0x22, 0xe6, 0xf7, 0x8e, 0x16, 0x6d, 0x18, 0xaa,
    0x7f, 0xd6, 0x36, 0x25, 0x8b, 0xce, 0x28, 0x72, 0x6f, 0x66, 0x1f, 0x73,
    0x88, 0x93, 0xce, 0x44, 0x31, 0x1e, 0x4b, 0xe6, 0xc0, 0x53, 0x51, 0x93,
    0xe5, 0xef, 0x72, 0xe8, 0x68, 0x62, 0x33, 0x72, 0x9c, 0x22, 0x7d, 0x82,
    0x0c, 0x99, 0x94, 0x45, 0xd8, 0x92, 0x46, 0xc8, 0xc3, 0x59
};
static const uint8_t fp_header[] = {
    0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x14
};
#define FP_REPLY_SIZE 142
#define FP_HEADER_SIZE 12
#define FP_SETUP2_SUFFIX_LEN 20

// Audio streaming state
typedef struct {
    bool active;
    bool paused;             // True when paused but session should persist
    int64_t stream_type;     // 96 = realtime/UDP, 103 = buffered/TCP
    uint16_t data_port;      // UDP port for audio data (type 96)
    uint16_t control_port;   // UDP port for control (retransmit requests)
    uint16_t timing_port;    // UDP port for timing
    uint16_t event_port;     // TCP port for server->client events (AirPlay 2)
    uint16_t buffered_port;  // TCP port for buffered audio (type 103)
    int data_socket;
    int control_socket;
    int event_socket;        // TCP listener for event port
    char codec[32];          // Audio codec from ANNOUNCE
    int sample_rate;
    int channels;
    int bits_per_sample;
} audio_stream_t;

static audio_stream_t audio_stream = {
    .active = false,
    .paused = false,
    .data_socket = -1,
    .control_socket = -1,
    .event_socket = -1,
};

static void get_device_id(char *device_id, size_t len)
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(device_id, len, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int send_all(int socket, const uint8_t *data, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        int r = send(socket, data + sent, len - sent, 0);
        if (r <= 0) {
            return -1;
        }
        sent += (size_t)r;
    }
    return 0;
}

static size_t build_setup_bplist(uint8_t *out, size_t capacity,
                                 int64_t stream_type,
                                 uint16_t data_port,
                                 uint16_t control_port,
                                 uint16_t timing_port,
                                 uint16_t event_port)
{
    if (capacity < 160) {
        return 0;
    }

    size_t pos = 0;
    memcpy(out + pos, "bplist00", 8);
    pos += 8;

    size_t offsets[16];
    size_t obj = 0;

    // 0: "streams"
    offsets[obj++] = pos;
    out[pos++] = 0x57;  // ASCII string, len=7
    memcpy(out + pos, "streams", 7);
    pos += 7;

    // 1: "eventPort" (top-level key for AirPlay 2)
    offsets[obj++] = pos;
    out[pos++] = 0x59;  // len=9
    memcpy(out + pos, "eventPort", 9);
    pos += 9;

    // 2: "type"
    offsets[obj++] = pos;
    out[pos++] = 0x54;  // len=4
    memcpy(out + pos, "type", 4);
    pos += 4;

    // 3: "dataPort"
    offsets[obj++] = pos;
    out[pos++] = 0x58;  // len=8
    memcpy(out + pos, "dataPort", 8);
    pos += 8;

    // 4: "controlPort"
    offsets[obj++] = pos;
    out[pos++] = 0x5B;  // len=11
    memcpy(out + pos, "controlPort", 11);
    pos += 11;

    // 5: "timingPort"
    offsets[obj++] = pos;
    out[pos++] = 0x5A;  // len=10
    memcpy(out + pos, "timingPort", 10);
    pos += 10;

    // 6: int stream_type (96 or 103)
    offsets[obj++] = pos;
    out[pos++] = 0x10;  // int, 1 byte
    out[pos++] = (uint8_t)stream_type;

    // 7: int data_port
    offsets[obj++] = pos;
    out[pos++] = 0x11;  // int, 2 bytes
    out[pos++] = (data_port >> 8) & 0xFF;
    out[pos++] = data_port & 0xFF;

    // 8: int control_port
    offsets[obj++] = pos;
    out[pos++] = 0x11;
    out[pos++] = (control_port >> 8) & 0xFF;
    out[pos++] = control_port & 0xFF;

    // 9: int timing_port
    offsets[obj++] = pos;
    out[pos++] = 0x11;
    out[pos++] = (timing_port >> 8) & 0xFF;
    out[pos++] = timing_port & 0xFF;

    // 10: int event_port
    offsets[obj++] = pos;
    out[pos++] = 0x11;
    out[pos++] = (event_port >> 8) & 0xFF;
    out[pos++] = event_port & 0xFF;

    // 11: stream dict (4 entries: type, dataPort, controlPort, timingPort)
    offsets[obj++] = pos;
    out[pos++] = 0xD4;
    out[pos++] = 2;  // key "type"
    out[pos++] = 3;  // key "dataPort"
    out[pos++] = 4;  // key "controlPort"
    out[pos++] = 5;  // key "timingPort"
    out[pos++] = 6;  // val stream_type
    out[pos++] = 7;  // val data_port
    out[pos++] = 8;  // val control_port
    out[pos++] = 9;  // val timing_port

    // 12: streams array (1 element)
    offsets[obj++] = pos;
    out[pos++] = 0xA1;
    out[pos++] = 11;  // ref stream dict

    // 13: top dict (2 entries: streams, eventPort)
    offsets[obj++] = pos;
    out[pos++] = 0xD2;  // dict with 2 entries
    out[pos++] = 0;   // key "streams"
    out[pos++] = 1;   // key "eventPort"
    out[pos++] = 12;  // value streams array
    out[pos++] = 10;  // value event_port

    size_t offset_table_offset = pos;
    for (size_t i = 0; i < obj; i++) {
        if (offsets[i] > 0xFF) {
            return 0;
        }
        out[pos++] = (uint8_t)offsets[i];
    }

    // Trailer
    memset(out + pos, 0, 6);
    pos += 6;
    out[pos++] = 1;  // offset size
    out[pos++] = 1;  // ref size

    // num objects (8 bytes)
    out[pos++] = 0; out[pos++] = 0; out[pos++] = 0; out[pos++] = 0;
    out[pos++] = 0; out[pos++] = 0; out[pos++] = 0; out[pos++] = (uint8_t)obj;

    // top object index (8 bytes) - now index 13
    out[pos++] = 0; out[pos++] = 0; out[pos++] = 0; out[pos++] = 0;
    out[pos++] = 0; out[pos++] = 0; out[pos++] = 0; out[pos++] = 13;

    // offset table offset (8 bytes)
    out[pos++] = 0; out[pos++] = 0; out[pos++] = 0; out[pos++] = 0;
    out[pos++] = 0; out[pos++] = 0; out[pos++] = 0; out[pos++] = (uint8_t)offset_table_offset;

    return pos;
}

// Read encrypted block from socket
// Format: [2-byte length (little-endian)][encrypted data + 16-byte tag]
// Returns decrypted length on success, -1 on error
static int read_encrypted_block(int socket, uint8_t *buffer, size_t buffer_size)
{
    if (!current_session || !encrypted_mode) {
        // Expected during session teardown - not an error
        return -1;
    }

    // Read 2-byte length header (little-endian)
    uint8_t len_buf[2];
    int received = 0;
    while (received < 2) {
        int r = recv(socket, len_buf + received, 2 - received, 0);
        if (r <= 0) {
            return -1;
        }
        received += r;
    }

    uint16_t block_len = (uint16_t)len_buf[0] | ((uint16_t)len_buf[1] << 8);

    if (block_len == 0 || block_len > ENCRYPTED_BLOCK_MAX || block_len > buffer_size) {
        ESP_LOGE(TAG, "Invalid encrypted block length: %d", block_len);
        return -1;
    }

    // Allocate temporary buffer for encrypted data
    size_t encrypted_len = block_len + 16;
    uint8_t *encrypted = malloc(encrypted_len);
    if (!encrypted) {
        ESP_LOGE(TAG, "Failed to allocate encrypted buffer");
        return -1;
    }

    received = 0;
    while ((size_t)received < encrypted_len) {
        int r = recv(socket, encrypted + received, encrypted_len - received, 0);
        if (r <= 0) {
            free(encrypted);
            return -1;
        }
        received += r;
    }

    // Decrypt
    uint8_t nonce[12] = {0};
    memcpy(nonce + 4, &current_session->decrypt_nonce, 8);

    unsigned long long plaintext_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            buffer, &plaintext_len,
            NULL,
            encrypted, encrypted_len,
            len_buf, sizeof(len_buf),
            nonce,
            current_session->decrypt_key) != 0) {
        free(encrypted);
        ESP_LOGE(TAG, "Failed to decrypt frame");
        return -1;
    }
    free(encrypted);

    current_session->decrypt_nonce++;

    return (int)plaintext_len;
}

// Write encrypted frame to socket
// Format: [2-byte length (little-endian)][encrypted data + 16-byte tag]
static int write_encrypted_frame(int socket, const uint8_t *data, size_t data_len)
{
    if (!current_session || !encrypted_mode) {
        // Expected during session teardown - not an error
        return -1;
    }

    size_t offset = 0;
    while (offset < data_len) {
        uint16_t block_len = (data_len - offset) > ENCRYPTED_BLOCK_MAX
            ? ENCRYPTED_BLOCK_MAX
            : (uint16_t)(data_len - offset);

        uint8_t len_buf[2];
        len_buf[0] = block_len & 0xFF;
        len_buf[1] = (block_len >> 8) & 0xFF;

        uint8_t nonce[12] = {0};
        memcpy(nonce + 4, &current_session->encrypt_nonce, 8);

        size_t encrypted_len = block_len + 16;
        uint8_t *encrypted = malloc(encrypted_len);
        if (!encrypted) {
            ESP_LOGE(TAG, "Failed to allocate encrypted buffer");
            return -1;
        }

        unsigned long long ct_len;
        crypto_aead_chacha20poly1305_ietf_encrypt(
            encrypted, &ct_len,
            data + offset, block_len,
            len_buf, sizeof(len_buf),
            NULL,
            nonce,
            current_session->encrypt_key);

        if (ct_len != encrypted_len) {
            ESP_LOGE(TAG, "Unexpected encrypted length: %llu", ct_len);
            free(encrypted);
            return -1;
        }

        if (send_all(socket, len_buf, sizeof(len_buf)) != 0 ||
            send_all(socket, encrypted, encrypted_len) != 0) {
            ESP_LOGE(TAG, "Failed to send encrypted block");
            free(encrypted);
            return -1;
        }

        free(encrypted);
        current_session->encrypt_nonce++;
        offset += block_len;
    }

    return 0;
}

static int send_response(int client_socket, int status_code, const char *status_text,
                         const char *content_type, const char *body, size_t body_len)
{
    char header[512];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Server: AirTunes/377.40.00\r\n"
        "CSeq: 1\r\n"
        "\r\n",
        status_code, status_text, content_type, body_len);

    // Build complete response
    size_t total_len = header_len + body_len;
    uint8_t *response = malloc(total_len);
    if (!response) {
        ESP_LOGE(TAG, "Failed to allocate response buffer");
        return -1;
    }

    memcpy(response, header, header_len);
    if (body && body_len > 0) {
        memcpy(response + header_len, body, body_len);
    }

    // Send encrypted or plain depending on mode
    int result;
    if (encrypted_mode) {
        result = write_encrypted_frame(client_socket, response, total_len);
    } else {
        result = (send(client_socket, response, total_len, 0) < 0) ? -1 : 0;
        if (result < 0) {
            ESP_LOGE(TAG, "Failed to send response");
        }
    }

    free(response);
    return result;
}

static int send_rtsp_response(int client_socket, int status_code, const char *status_text,
                              int cseq, const char *extra_headers, const char *body, size_t body_len)
{
    char header[1024];
    int header_len;

    if (extra_headers && body && body_len > 0) {
        header_len = snprintf(header, sizeof(header),
            "RTSP/1.0 %d %s\r\n"
            "CSeq: %d\r\n"
            "Server: AirTunes/377.40.00\r\n"
            "%s"
            "Content-Length: %zu\r\n"
            "\r\n",
            status_code, status_text, cseq, extra_headers, body_len);
    } else if (extra_headers) {
        header_len = snprintf(header, sizeof(header),
            "RTSP/1.0 %d %s\r\n"
            "CSeq: %d\r\n"
            "Server: AirTunes/377.40.00\r\n"
            "%s"
            "\r\n",
            status_code, status_text, cseq, extra_headers);
    } else {
        header_len = snprintf(header, sizeof(header),
            "RTSP/1.0 %d %s\r\n"
            "CSeq: %d\r\n"
            "Server: AirTunes/377.40.00\r\n"
            "\r\n",
            status_code, status_text, cseq);
    }

    // Build complete response
    size_t total_len = header_len + body_len;
    uint8_t *response = malloc(total_len);
    if (!response) {
        ESP_LOGE(TAG, "Failed to allocate response buffer");
        return -1;
    }

    memcpy(response, header, header_len);
    if (body && body_len > 0) {
        memcpy(response + header_len, body, body_len);
    }

    // Send encrypted or plain depending on mode
    int result;
    if (encrypted_mode) {
        result = write_encrypted_frame(client_socket, response, total_len);
    } else {
        result = (send(client_socket, response, total_len, 0) < 0) ? -1 : 0;
        if (result < 0) {
            ESP_LOGE(TAG, "Failed to send RTSP response");
        }
    }

    free(response);
    return result;
}

static int parse_cseq(const char *request)
{
    const char *cseq = strstr(request, "CSeq:");
    if (cseq) {
        return atoi(cseq + 5);
    }
    return 1;
}

static const uint8_t *find_header_end(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i + 3 < len; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n' &&
            data[i + 2] == '\r' && data[i + 3] == '\n') {
            return data + i;
        }
    }
    return NULL;
}

static void handle_info_request(int client_socket, const char *request)
{

    char device_id[18];
    static char body[4096];
    plist_t p;

    get_device_id(device_id, sizeof(device_id));

    // Get real Ed25519 public key from HAP module
    const uint8_t *pk = hap_get_public_key();

    // Combine features into single 64-bit value
    uint64_t features = ((uint64_t)FEATURES_HI << 32) | FEATURES_LO;

    // Build plist response
    plist_init(&p, body, sizeof(body));
    plist_begin(&p);
    plist_dict_begin(&p);

    plist_dict_string(&p, "deviceid", device_id);
    plist_dict_uint(&p, "features", features);
    plist_dict_string(&p, "model", "AudioAccessory5,1");  // HomePod mini model = speaker
    plist_dict_string(&p, "protovers", "1.1");
    plist_dict_string(&p, "srcvers", "377.40.00");
    plist_dict_int(&p, "vv", 2);
    plist_dict_int(&p, "statusFlags", 4);
    plist_dict_data(&p, "pk", pk, 32);
    plist_dict_string(&p, "pi", "00000000-0000-0000-0000-000000000000");
    plist_dict_string(&p, "name", CONFIG_AIRPLAY_DEVICE_NAME);

    // Audio formats array - describes supported audio configurations
    // type 96 = dynamic RTP payload, audioInputFormats/audioOutputFormats are bitmasks
    plist_dict_array_begin(&p, "audioFormats");
    plist_dict_begin(&p);
    plist_dict_int(&p, "type", 96);
    plist_dict_int(&p, "audioInputFormats", 0x01000000);  // ALAC 44100/16
    plist_dict_int(&p, "audioOutputFormats", 0x01000000);
    plist_dict_end(&p);
    plist_array_end(&p);

    // Audio latencies array
    plist_dict_array_begin(&p, "audioLatencies");
    plist_dict_begin(&p);
    plist_dict_int(&p, "type", 96);
    plist_dict_int(&p, "audioType", 0x64);  // Default audio
    plist_dict_int(&p, "inputLatencyMicros", 0);
    plist_dict_int(&p, "outputLatencyMicros", 400000);  // 400ms
    plist_dict_end(&p);
    plist_array_end(&p);

    plist_dict_end(&p);
    size_t body_len = plist_end(&p);

    send_response(client_socket, 200, "OK", "text/x-apple-plist+xml", body, body_len);
}

static void handle_options_request(int client_socket, const char *request)
{

    int cseq = parse_cseq(request);

    const char *public_methods = "Public: ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, FLUSHBUFFERED, TEARDOWN, OPTIONS, POST, GET, SET_PARAMETER, GET_PARAMETER, SETPEERS, SETRATEANCHORTIME\r\n";

    send_rtsp_response(client_socket, 200, "OK", cseq, public_methods, NULL, 0);
}

static int parse_content_length(const char *request)
{
    const char *cl = strstr(request, "Content-Length:");
    if (!cl) {
        cl = strstr(request, "content-length:");
    }
    if (cl) {
        return atoi(cl + 15);
    }
    return 0;
}

static const uint8_t *get_body(const char *request, size_t request_len, size_t *body_len)
{
    const char *body = strstr(request, "\r\n\r\n");
    if (body) {
        body += 4;
        *body_len = request_len - (body - request);
        return (const uint8_t *)body;
    }
    *body_len = 0;
    return NULL;
}

static void handle_post_request(int client_socket, const char *request, size_t request_len, const char *path)
{

    int cseq = parse_cseq(request);
    size_t body_len;
    const uint8_t *body = get_body(request, request_len, &body_len);

    if (strstr(path, "/pair-setup")) {

        // Create session if needed
        if (!current_session) {
            current_session = hap_session_create();
            if (!current_session) {
                ESP_LOGE(TAG, "Failed to create HAP session");
                send_rtsp_response(client_socket, 500, "Internal Error", cseq, NULL, NULL, 0);
                return;
            }
        }

        uint8_t *response = malloc(2048);
        if (!response) {
            ESP_LOGE(TAG, "Failed to allocate response buffer");
            send_rtsp_response(client_socket, 500, "Internal Error", cseq, NULL, NULL, 0);
            return;
        }

        size_t response_len = 0;
        esp_err_t err = ESP_FAIL;

        if (body && body_len > 0) {
            // Parse TLV to get state
            size_t state_len;
            const uint8_t *state = tlv8_find(body, body_len, TLV_TYPE_STATE, &state_len);

            if (state && state_len == 1) {
                switch (state[0]) {
                    case 1:
                        err = hap_pair_setup_m1(current_session, body, body_len,
                                                response, 2048, &response_len);
                        break;
                    case 3:
                        err = hap_pair_setup_m3(current_session, body, body_len,
                                                response, 2048, &response_len);
                        break;
                    case 5:
                        err = hap_pair_setup_m5(current_session, body, body_len,
                                                response, 2048, &response_len);
                        break;
                    default:
                        break;
                }
            }
        }

        if (err == ESP_OK && response_len > 0) {
            send_rtsp_response(client_socket, 200, "OK", cseq,
                              "Content-Type: application/octet-stream\r\n",
                              (const char *)response, response_len);

            if (current_session && current_session->pair_setup_state == 4 &&
                current_session->session_established) {
                encrypted_mode = true;
            }
        } else {
            ESP_LOGE(TAG, "Pair-setup failed: err=%d, response_len=%zu", err, response_len);
            // Return error TLV
            static const uint8_t error_response[] = {0x06, 0x01, 0x02, 0x07, 0x01, 0x02};
            send_rtsp_response(client_socket, 200, "OK", cseq,
                              "Content-Type: application/octet-stream\r\n",
                              (const char *)error_response, sizeof(error_response));
        }

        free(response);
    } else if (strstr(path, "/pair-verify")) {

        // Create session if needed
        if (!current_session) {
            current_session = hap_session_create();
            if (!current_session) {
                ESP_LOGE(TAG, "Failed to create HAP session");
                send_rtsp_response(client_socket, 500, "Internal Error", cseq, NULL, NULL, 0);
                return;
            }
        }

        uint8_t *response = malloc(1024);
        if (!response) {
            ESP_LOGE(TAG, "Failed to allocate response buffer");
            send_rtsp_response(client_socket, 500, "Internal Error", cseq, NULL, NULL, 0);
            return;
        }

        size_t response_len = 0;
        esp_err_t err = ESP_FAIL;

        if (body && body_len > 0) {
            // Check if this is TLV format (has state byte) or raw format
            size_t state_len;
            const uint8_t *state = tlv8_find(body, body_len, TLV_TYPE_STATE, &state_len);

            if (state && state_len == 1) {
                if (state[0] == 0x01) {
                    err = hap_pair_verify_m1(current_session, body, body_len,
                                             response, 1024, &response_len);
                } else if (state[0] == 0x03) {
                    err = hap_pair_verify_m3(current_session, body, body_len,
                                             response, 1024, &response_len);
                } else {
                    ESP_LOGE(TAG, "Unexpected TLV state: %d", state[0]);
                    err = ESP_ERR_INVALID_ARG;
                }
            } else {
                if (current_session->pair_verify_state == 0) {
                    err = hap_pair_verify_m1_raw(current_session, body, body_len,
                                                 response, 1024, &response_len);
                } else if (current_session->pair_verify_state == PAIR_VERIFY_STATE_M2) {
                    err = hap_pair_verify_m3_raw(current_session, body, body_len,
                                                 response, 1024, &response_len);
                } else {
                    ESP_LOGE(TAG, "Unexpected state for raw format: %d", current_session->pair_verify_state);
                    err = ESP_ERR_INVALID_STATE;
                }
            }
        } else {
            ESP_LOGE(TAG, "No body in pair-verify request");
            err = ESP_ERR_INVALID_ARG;
        }

        if (err == ESP_OK && response_len > 0) {
            send_rtsp_response(client_socket, 200, "OK", cseq,
                              "Content-Type: application/octet-stream\r\n",
                              (const char *)response, response_len);
        } else {
            ESP_LOGE(TAG, "Pair-verify failed, err=%d, response_len=%zu", err, response_len);
            // Return error
            send_rtsp_response(client_socket, 200, "OK", cseq,
                              "Content-Type: application/octet-stream\r\n",
                              "\x06\x01\x04\x07\x01\x02", 6);  // State=4, Error=2 (auth)
        }

        free(response);
    } else if (strstr(path, "/fp-setup")) {
        if (body && body_len >= 16) {
            uint8_t version = body[4];
            uint8_t type = body[5];
            uint8_t seq = body[6];
            uint8_t mode = body[14];

            const uint8_t *response = NULL;
            size_t response_len = 0;
            uint8_t *dynamic_response = NULL;

            if (version == 3 && type == 1) {
                if (seq == 1) {
                    response_len = FP_REPLY_SIZE;
                    switch (mode) {
                        case 0: response = fp_reply1; break;
                        case 1: response = fp_reply2; break;
                        case 2: response = fp_reply3; break;
                        case 3: response = fp_reply4; break;
                        default: response = fp_reply1; break;
                    }
                } else if (seq == 3) {
                    response_len = FP_HEADER_SIZE + FP_SETUP2_SUFFIX_LEN;
                    dynamic_response = malloc(response_len);
                    if (dynamic_response) {
                        memcpy(dynamic_response, fp_header, FP_HEADER_SIZE);
                        if (body_len >= FP_SETUP2_SUFFIX_LEN) {
                            memcpy(dynamic_response + FP_HEADER_SIZE,
                                   body + body_len - FP_SETUP2_SUFFIX_LEN,
                                   FP_SETUP2_SUFFIX_LEN);
                        }
                        response = dynamic_response;
                    }
                }
            }

            if (response && response_len > 0) {
                send_rtsp_response(client_socket, 200, "OK", cseq,
                                  "Content-Type: application/octet-stream\r\n",
                                  (const char *)response, response_len);
            } else {
                send_rtsp_response(client_socket, 200, "OK", cseq,
                                  "Content-Type: application/octet-stream\r\n",
                                  "\x00", 1);
            }
            if (dynamic_response) free(dynamic_response);
        } else {
            send_rtsp_response(client_socket, 200, "OK", cseq,
                              "Content-Type: application/octet-stream\r\n",
                              "\x00", 1);
        }
    } else if (strstr(path, "/command")) {
        if (body && body_len > 0) {
            if (body_len >= 8 && memcmp(body, "bplist00", 8) == 0) {
                int64_t cmd_type = 0;
                if (bplist_find_int(body, body_len, "type", &cmd_type)) {
                }
            }
        }
        send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
    } else if (strstr(path, "/feedback")) {
        send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
    } else if (strstr(path, "/audio") || strstr(path, "/stream")) {
        if (body && body_len > 0) {
        }
        send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
    } else {
        if (body_len > 1024) {
        }
        send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
    }
}

// Parse SDP from ANNOUNCE body to extract codec and encryption info
static void parse_sdp(const char *sdp, size_t len)
{
    audio_format_t format = {0};
    audio_encrypt_t encrypt = {0};
    encrypt.type = AUDIO_ENCRYPT_NONE;

    // Default values
    format.sample_rate = 44100;
    format.channels = 2;
    format.bits_per_sample = 16;
    format.frame_size = 352;
    strcpy(format.codec, "AppleLossless");

    // Look for audio format info in SDP
    // m=audio 0 RTP/AVP 96
    // a=rtpmap:96 AppleLossless
    // a=fmtp:96 352 0 16 40 10 14 2 255 0 0 44100

    const char *media = strstr(sdp, "m=audio");
    if (media) {
    }

    const char *rtpmap = strstr(sdp, "a=rtpmap:");
    if (rtpmap) {
        if (sscanf(rtpmap, "a=rtpmap:%*d %31s", format.codec) == 1) {
        }
    }

    // Parse ALAC fmtp line for detailed config
    // Format: a=fmtp:96 <frame_length> <compatible_version> <bit_depth> <pb> <mb> <kb>
    //                   <num_channels> <max_run> <max_frame_bytes> <avg_bit_rate> <sample_rate>
    const char *fmtp = strstr(sdp, "a=fmtp:");
    if (fmtp) {
        unsigned int frame_len, bit_depth, pb, mb, kb, num_ch, max_run, max_frame, avg_rate, rate;
        unsigned int compat;
        int matched = sscanf(fmtp, "a=fmtp:%*d %u %u %u %u %u %u %u %u %u %u %u",
                             &frame_len, &compat, &bit_depth, &pb, &mb, &kb,
                             &num_ch, &max_run, &max_frame, &avg_rate, &rate);
        if (matched >= 7) {
            format.max_samples_per_frame = frame_len;
            format.sample_size = bit_depth;
            format.rice_history_mult = pb;
            format.rice_initial_history = mb;
            format.rice_limit = kb;
            format.num_channels = num_ch;
            format.channels = num_ch;
            format.bits_per_sample = bit_depth;
            if (matched >= 8) format.max_run = max_run;
            if (matched >= 9) format.max_coded_frame_size = max_frame;
            if (matched >= 10) format.avg_bit_rate = avg_rate;
            if (matched >= 11) {
                format.sample_rate_config = rate;
                format.sample_rate = rate;
            }
        }
    }

    // Parse encryption parameters for RAOP (AirPlay 1)
    // a=rsaaeskey: - RSA-encrypted AES key (base64)
    // a=aesiv: - AES IV (base64)
    const char *rsaaeskey = strstr(sdp, "a=rsaaeskey:");
    const char *aesiv = strstr(sdp, "a=aesiv:");

    if (rsaaeskey && aesiv) {
        encrypt.type = AUDIO_ENCRYPT_AES_CBC;

        // Parse IV (base64 encoded, typically 16 bytes -> ~24 base64 chars)
        aesiv += 8;  // Skip "a=aesiv:"
        while (*aesiv == ' ') aesiv++;

        // Find end of IV (newline or end)
        const char *aesiv_end = aesiv;
        while (*aesiv_end && *aesiv_end != '\r' && *aesiv_end != '\n') {
            aesiv_end++;
        }
        size_t aesiv_len = aesiv_end - aesiv;

        if (aesiv_len > 0 && aesiv_len < 64) {
            int decoded = base64_decode(aesiv, aesiv_len, encrypt.iv, 16);
            if (decoded == 16) {
            } else {
            }
        }

        ESP_LOGW(TAG, "RAOP RSA key decryption not implemented - audio may be encrypted");
    }

    // Update local state
    strncpy(audio_stream.codec, format.codec, sizeof(audio_stream.codec) - 1);
    audio_stream.sample_rate = format.sample_rate;
    audio_stream.channels = format.channels;
    audio_stream.bits_per_sample = format.bits_per_sample;

    // Set format in audio receiver
    audio_receiver_set_format(&format);

    // Set encryption if present
    if (encrypt.type != AUDIO_ENCRYPT_NONE) {
        audio_receiver_set_encryption(&encrypt);
    }
}

static void handle_announce_request(int client_socket, const char *request, size_t request_len)
{
    int cseq = parse_cseq(request);

    size_t body_len;
    const uint8_t *body = get_body(request, request_len, &body_len);

    if (body && body_len > 0) {
        parse_sdp((const char *)body, body_len);
    }

    send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
}

// Create UDP socket and bind to a port
static int create_udp_socket(uint16_t *port)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create UDP socket");
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0;  // Let system assign port

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind UDP socket");
        close(sock);
        return -1;
    }

    // Get assigned port
    socklen_t addr_len = sizeof(addr);
    getsockname(sock, (struct sockaddr *)&addr, &addr_len);
    *port = ntohs(addr.sin_port);

    return sock;
}

// Create TCP listening socket for event port (AirPlay 2 session persistence)
static int create_event_socket(uint16_t *port)
{
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create event TCP socket");
        return -1;
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0;  // Let system assign port

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind event socket");
        close(sock);
        return -1;
    }

    if (listen(sock, 1) < 0) {
        ESP_LOGE(TAG, "Failed to listen on event socket");
        close(sock);
        return -1;
    }

    // Get assigned port
    socklen_t addr_len = sizeof(addr);
    getsockname(sock, (struct sockaddr *)&addr, &addr_len);
    *port = ntohs(addr.sin_port);

    return sock;
}

// Event port client connection (for AirPlay 2 session persistence)
static int event_client_socket = -1;
static TaskHandle_t event_task_handle = NULL;

static void event_port_task(void *pvParameters)
{
    int listen_socket = (int)(intptr_t)pvParameters;

    while (audio_stream.event_socket >= 0) {
        // Set up select with timeout to allow task to exit
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_socket, &read_fds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int ret = select(listen_socket + 1, &read_fds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno != EINTR) {
                ESP_LOGE(TAG, "Event port select error: %d", errno);
            }
            break;
        }

        if (ret == 0) {
            continue;  // Timeout, check if we should exit
        }

        if (FD_ISSET(listen_socket, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client = accept(listen_socket, (struct sockaddr *)&client_addr, &addr_len);
            if (client < 0) {
                ESP_LOGE(TAG, "Event port accept error: %d", errno);
                continue;
            }

            if (event_client_socket >= 0) {
                close(event_client_socket);
            }
            event_client_socket = client;

            // Keep connection alive - just monitor for disconnection
            while (event_client_socket >= 0 && audio_stream.event_socket >= 0) {
                fd_set cfds;
                FD_ZERO(&cfds);
                FD_SET(event_client_socket, &cfds);
                struct timeval ctv = { .tv_sec = 1, .tv_usec = 0 };

                ret = select(event_client_socket + 1, &cfds, NULL, NULL, &ctv);
                if (ret < 0) {
                    break;
                }
                if (ret > 0 && FD_ISSET(event_client_socket, &cfds)) {
                    // Check if connection closed
                    char buf[16];
                    int n = recv(event_client_socket, buf, sizeof(buf), MSG_PEEK);
                    if (n <= 0) {
                        close(event_client_socket);
                        event_client_socket = -1;
                        break;
                    }
                }
            }
        }
    }

    // Cleanup
    if (event_client_socket >= 0) {
        close(event_client_socket);
        event_client_socket = -1;
    }
    event_task_handle = NULL;
    vTaskDelete(NULL);
}

static void start_event_port_task(int listen_socket)
{
    if (event_task_handle != NULL) {
        return;  // Already running
    }
    xTaskCreate(event_port_task, "event_port", 3072, (void *)(intptr_t)listen_socket, 5, &event_task_handle);
}

static void stop_event_port_task(void)
{
    if (event_client_socket >= 0) {
        close(event_client_socket);
        event_client_socket = -1;
    }
    // Task will exit on its own when event_socket becomes -1
}

static void handle_setup_request(int client_socket, const char *request, size_t request_len)
{
    int cseq = parse_cseq(request);

    const char *content_type = strstr(request, "Content-Type:");
    bool is_bplist = false;
    if (content_type) {
        char ct[64] = {0};
        sscanf(content_type, "Content-Type: %63s", ct);
        if (strcmp(ct, "application/x-apple-binary-plist") == 0) {
            is_bplist = true;
        }
    }

    size_t body_len;
    const uint8_t *body = get_body(request, request_len, &body_len);
    if (body && body_len > 0) {

        if (is_bplist) {
            size_t stream_count = 0;
            if (bplist_get_streams_count(body, body_len, &stream_count)) {
                for (size_t i = 0; i < stream_count; i++) {
                    int64_t stream_type = -1;
                    size_t ekey_len_dbg = 0;
                    size_t eiv_len_dbg = 0;
                    size_t shk_len_dbg = 0;
                    if (bplist_get_stream_info(body, body_len, i, &stream_type,
                                               &ekey_len_dbg, &eiv_len_dbg, &shk_len_dbg)) {
                        if (i == 0) {
                            audio_stream.stream_type = stream_type;
                        }
                        bplist_kv_info_t kv[16];
                        size_t kv_count = 0;

                        // Variables to collect audio format info
                        int64_t codec_type = -1;  // ct: 2 = ALAC
                        int64_t sample_rate = 44100;  // sr: default 44100
                        int64_t samples_per_frame = 352;  // spf: default 352

                        if (bplist_get_stream_kv_info(body, body_len, i, kv, 16, &kv_count)) {
                            for (size_t k = 0; k < kv_count; k++) {
                                if (kv[k].value_type == BPLIST_VALUE_INT) {
                                    if (strcmp(kv[k].key, "ct") == 0) {
                                        codec_type = kv[k].int_value;
                                    } else if (strcmp(kv[k].key, "sr") == 0) {
                                        sample_rate = kv[k].int_value;
                                    } else if (strcmp(kv[k].key, "spf") == 0) {
                                        samples_per_frame = kv[k].int_value;
                                    }
                                }
                            }

                            // Set audio format based on extracted parameters
                            audio_format_t format = {0};
                            if (codec_type == 2) {
                                strcpy(format.codec, "ALAC");
                            } else if (codec_type == 8) {
                                strcpy(format.codec, "AAC-ELD");
                            } else {
                                strcpy(format.codec, "ALAC");  // Default to ALAC
                            }
                            format.sample_rate = (int)sample_rate;
                            format.channels = 2;  // Stereo
                            format.bits_per_sample = 16;
                            format.frame_size = (int)samples_per_frame;
                            format.max_samples_per_frame = (uint32_t)samples_per_frame;
                            format.sample_size = 16;
                            format.num_channels = 2;
                            format.sample_rate_config = (uint32_t)sample_rate;

                            audio_receiver_set_format(&format);
                        }
                    }
                }
            }
        }

        // Try to extract encryption key from binary plist
        uint8_t ekey_encrypted[64];  // Encrypted key (typically 16 or 32 bytes + 16 tag)
        size_t ekey_len = 0;
        uint8_t eiv[16];
        size_t eiv_len = 0;
        uint8_t shk[32];  // Shared key (if present, unencrypted)
        size_t shk_len = 0;

        // Parse binary plist to extract encryption parameters
        bool has_stream_crypto = bplist_find_stream_crypto(
            body, body_len, 96,
            ekey_encrypted, sizeof(ekey_encrypted), &ekey_len,
            eiv, sizeof(eiv), &eiv_len,
            shk, sizeof(shk), &shk_len);

        bool has_ekey = ekey_len > 0;
        bool has_eiv = eiv_len > 0;
        bool has_shk = shk_len > 0;

        if (!has_stream_crypto || (!has_ekey && !has_shk)) {
            has_ekey = bplist_find_data_deep(body, body_len, "ekey", ekey_encrypted, sizeof(ekey_encrypted), &ekey_len);
            has_eiv = bplist_find_data_deep(body, body_len, "eiv", eiv, sizeof(eiv), &eiv_len);
            has_shk = bplist_find_data_deep(body, body_len, "shk", shk, sizeof(shk), &shk_len);
        }

        if (has_ekey) {
        }
        if (has_eiv) {
        }
        if (has_shk) {
        }

        bool encryption_set = false;
        audio_encrypt_t audio_encrypt = {0};

        if (has_shk && shk_len >= 16) {
            audio_encrypt.type = AUDIO_ENCRYPT_CHACHA20_POLY1305;
            memcpy(audio_encrypt.key, shk, shk_len > 32 ? 32 : shk_len);
            audio_encrypt.key_len = shk_len > 32 ? 32 : shk_len;
            if (has_eiv && eiv_len >= 16) {
                memcpy(audio_encrypt.iv, eiv, 16);
            }
            audio_receiver_set_encryption(&audio_encrypt);
            encryption_set = true;
        } else if (has_ekey && ekey_len > 16 && current_session && current_session->session_established) {
            uint8_t nonce[12] = {0};

            uint8_t decrypted_key[32];
            unsigned long long decrypted_len;

            int ret = crypto_aead_chacha20poly1305_ietf_decrypt(
                decrypted_key, &decrypted_len,
                NULL,
                ekey_encrypted, ekey_len,
                NULL, 0,
                nonce,
                current_session->shared_secret);

            if (ret == 0 && decrypted_len >= 16) {
                audio_encrypt.type = AUDIO_ENCRYPT_CHACHA20_POLY1305;
                memcpy(audio_encrypt.key, decrypted_key, decrypted_len > 32 ? 32 : decrypted_len);
                audio_encrypt.key_len = decrypted_len > 32 ? 32 : decrypted_len;
                if (has_eiv && eiv_len >= 16) {
                    memcpy(audio_encrypt.iv, eiv, 16);
                }
                audio_receiver_set_encryption(&audio_encrypt);
                encryption_set = true;
            } else {
                // Try with encrypt_key instead of shared_secret
                ret = crypto_aead_chacha20poly1305_ietf_decrypt(
                    decrypted_key, &decrypted_len,
                    NULL,
                    ekey_encrypted, ekey_len,
                    NULL, 0,
                    nonce,
                    current_session->encrypt_key);

                if (ret == 0 && decrypted_len >= 16) {
                    audio_encrypt.type = AUDIO_ENCRYPT_CHACHA20_POLY1305;
                    memcpy(audio_encrypt.key, decrypted_key, decrypted_len > 32 ? 32 : decrypted_len);
                    audio_encrypt.key_len = decrypted_len > 32 ? 32 : decrypted_len;
                    if (has_eiv && eiv_len >= 16) {
                        memcpy(audio_encrypt.iv, eiv, 16);
                    }
                    audio_receiver_set_encryption(&audio_encrypt);
                    encryption_set = true;
                } else {
                }
            }
        } else if (has_ekey) {
        }

        if (!encryption_set && current_session && current_session->session_established) {
            audio_encrypt_t audio_encrypt = {0};
            audio_encrypt.type = AUDIO_ENCRYPT_CHACHA20_POLY1305;

            esp_err_t err = hap_derive_audio_key(current_session,
                                                  audio_encrypt.key,
                                                  sizeof(audio_encrypt.key));
            if (err == ESP_OK) {
                audio_encrypt.key_len = 32;

                if (has_eiv && eiv_len >= 16) {
                    memcpy(audio_encrypt.iv, eiv, 16);
                }

                audio_receiver_set_encryption(&audio_encrypt);
            }
        }
    } else {
        if (current_session && current_session->session_established) {
            audio_encrypt_t audio_encrypt = {0};
            audio_encrypt.type = AUDIO_ENCRYPT_CHACHA20_POLY1305;

            esp_err_t err = hap_derive_audio_key(current_session,
                                                  audio_encrypt.key,
                                                  sizeof(audio_encrypt.key));
            if (err == ESP_OK) {
                audio_encrypt.key_len = 32;
                audio_receiver_set_encryption(&audio_encrypt);
            }
        }
    }

    int64_t stream_type = audio_stream.stream_type;
    if (stream_type == 0) {
        stream_type = 96;
    }

    if (stream_type == 103) {
        // Type 103 = buffered audio over TCP
        // Start buffered audio receiver which creates TCP listener
        esp_err_t err = audio_receiver_start_buffered(0);  // Let system choose port
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to start buffered audio receiver");
            send_rtsp_response(client_socket, 500, "Internal Error", cseq, NULL, NULL, 0);
            return;
        }
        audio_stream.buffered_port = audio_receiver_get_buffered_port();

        int temp_socket;
        if (audio_stream.control_port == 0) {
            temp_socket = create_udp_socket(&audio_stream.control_port);
            if (temp_socket > 0) close(temp_socket);
        }
        if (audio_stream.timing_port == 0) {
            temp_socket = create_udp_socket(&audio_stream.timing_port);
            if (temp_socket > 0) close(temp_socket);
        }
    } else {
        // Type 96 = realtime audio over UDP
        // Allocate UDP ports for audio streaming
        // We just need the port numbers to tell the client - audio_receiver will bind later
        int temp_socket;

        if (audio_stream.data_port == 0) {
            temp_socket = create_udp_socket(&audio_stream.data_port);
            if (temp_socket > 0) close(temp_socket);  // Close after getting port
        }
        if (audio_stream.control_port == 0) {
            temp_socket = create_udp_socket(&audio_stream.control_port);
            if (temp_socket > 0) close(temp_socket);
        }
        if (audio_stream.timing_port == 0) {
            temp_socket = create_udp_socket(&audio_stream.timing_port);
            if (temp_socket > 0) close(temp_socket);
        }
    }

    // Create event port for AirPlay 2 session persistence
    if (audio_stream.event_port == 0) {
        audio_stream.event_socket = create_event_socket(&audio_stream.event_port);
        if (audio_stream.event_socket >= 0) {
            start_event_port_task(audio_stream.event_socket);
        }
    }

    // For type 103, dataPort is the TCP buffered port
    uint16_t response_data_port = (stream_type == 103) ? audio_stream.buffered_port : audio_stream.data_port;

    if (is_bplist) {
        uint8_t plist_body[256];
        size_t plist_len = build_setup_bplist(plist_body, sizeof(plist_body),
                                              stream_type,
                                              response_data_port,
                                              audio_stream.control_port,
                                              audio_stream.timing_port,
                                              audio_stream.event_port);
        if (plist_len == 0) {
            ESP_LOGE(TAG, "Failed to build SETUP response plist");
            send_rtsp_response(client_socket, 500, "Internal Error", cseq, NULL, NULL, 0);
            return;
        }
        send_rtsp_response(client_socket, 200, "OK", cseq,
                          "Content-Type: application/x-apple-binary-plist\r\n",
                          (const char *)plist_body, plist_len);
    } else {
        // Build Transport response header
        char transport_response[256];
        snprintf(transport_response, sizeof(transport_response),
                 "Transport: RTP/AVP/UDP;unicast;mode=record;"
                 "server_port=%d;control_port=%d;timing_port=%d\r\n"
                 "Session: 1\r\n",
                 audio_stream.data_port, audio_stream.control_port, audio_stream.timing_port);

        send_rtsp_response(client_socket, 200, "OK", cseq, transport_response, NULL, 0);
    }
    audio_stream.active = true;
}

static void handle_record_request(int client_socket, const char *request)
{
    int cseq = parse_cseq(request);

    const char *rtp_info = strstr(request, "RTP-Info:");
    if (rtp_info) {
    }

    if (audio_stream.stream_type == 103) {
    } else if (audio_stream.data_port > 0) {
        esp_err_t err = audio_receiver_start(audio_stream.data_port, audio_stream.control_port);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to start audio receiver");
        }
    }

    // Audio headers for response
    char headers[128];
    snprintf(headers, sizeof(headers),
             "Audio-Latency: 11025\r\n"
             "Audio-Jack-Status: connected\r\n");

    send_rtsp_response(client_socket, 200, "OK", cseq, headers, NULL, 0);
}

static void handle_set_parameter_request(int client_socket, const char *request, size_t request_len)
{
    int cseq = parse_cseq(request);

    // Check Content-Type to determine parameter type
    const char *content_type = strstr(request, "Content-Type:");

    if (content_type && strstr(content_type, "text/parameters")) {
        // Volume, progress, etc.
        size_t body_len;
        const uint8_t *body = get_body(request, request_len, &body_len);
        if (body) {
            // Check for volume parameter
            if (strstr((const char *)body, "volume:")) {
                const char *vol = strstr((const char *)body, "volume:");
                if (vol) {
                    float volume = atof(vol + 7);
                    airplay_set_volume(volume);
                }
            }
            if (strstr((const char *)body, "progress:")) {
            }
        }
    } else if (content_type && strstr(content_type, "image/")) {
    } else if (content_type && strstr(content_type, "application/x-dmap-tagged")) {
    }

    send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
}

static void handle_teardown_request(int client_socket, const char *request)
{
    int cseq = parse_cseq(request);

    audio_receiver_stop();

    audio_stats_t stats;
    audio_receiver_get_stats(&stats);

    audio_stream.data_port = 0;
    audio_stream.control_port = 0;
    audio_stream.timing_port = 0;
    audio_stream.active = false;
    audio_stream.paused = false;

    // Stop event port task and close socket
    stop_event_port_task();
    if (audio_stream.event_socket >= 0) {
        close(audio_stream.event_socket);
        audio_stream.event_socket = -1;
        audio_stream.event_port = 0;
    }

    // For AirPlay 2: Don't destroy HAP session on TEARDOWN
    // The session should persist until the TCP connection is closed
    // This allows quick reconnection without re-pairing

    send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
}

static void process_rtsp_buffer(int client_socket, uint8_t *buffer, size_t *buf_len)
{
    while (*buf_len > 0) {
        const uint8_t *header_end = find_header_end(buffer, *buf_len);
        if (!header_end) {
            break;
        }

        size_t header_len = (size_t)(header_end - buffer) + 4;
        char *header_str = malloc(header_len + 1);
        if (!header_str) {
            ESP_LOGE(TAG, "Failed to allocate header buffer");
            *buf_len = 0;
            break;
        }
        memcpy(header_str, buffer, header_len);
        header_str[header_len] = '\0';

        int content_len = parse_content_length(header_str);
        if (content_len < 0) {
            content_len = 0;
        }
        size_t total_len = header_len + (size_t)content_len;
        if (total_len > RTSP_BUFFER_LARGE) {
            ESP_LOGE(TAG, "RTSP message too large: %zu bytes (max %d)", total_len, RTSP_BUFFER_LARGE);
            free(header_str);
            *buf_len = 0;
            break;
        }
        if (*buf_len < total_len) {
            free(header_str);
            break;
        }

        char *request = malloc(total_len + 1);
        if (!request) {
            ESP_LOGE(TAG, "Failed to allocate request buffer");
            free(header_str);
            *buf_len = 0;
            break;
        }
        memcpy(request, buffer, total_len);
        request[total_len] = '\0';

        // Log first line of request
        char *first_line_end = strstr(header_str, "\r\n");
        if (first_line_end) {
            *first_line_end = '\0';
            *first_line_end = '\r';
        }

        char method[16] = {0};
        char path[256] = {0};
        int parsed = sscanf(header_str, "%15s %255s", method, path);

        if (parsed < 1 || method[0] == '\0') {
            ESP_LOGW(TAG, "Failed to parse method (parsed=%d, recv_len=%zu)", parsed, total_len);
        } else if (strcmp(method, "GET") == 0) {
            if (strcmp(path, "/info") == 0) {
                handle_info_request(client_socket, request);
            } else {
                ESP_LOGW(TAG, "Unknown GET path: %s", path);
                send_response(client_socket, 404, "Not Found", "text/plain", "Not Found", 9);
            }
        } else if (strcmp(method, "OPTIONS") == 0) {
            handle_options_request(client_socket, request);
        } else if (strcmp(method, "POST") == 0) {
            handle_post_request(client_socket, request, total_len, path);
        } else if (strcmp(method, "ANNOUNCE") == 0) {
            handle_announce_request(client_socket, request, total_len);
        } else if (strcmp(method, "SETUP") == 0) {
            handle_setup_request(client_socket, request, total_len);
        } else if (strcmp(method, "RECORD") == 0) {
            handle_record_request(client_socket, request);
        } else if (strcmp(method, "SET_PARAMETER") == 0) {
            handle_set_parameter_request(client_socket, request, total_len);
        } else if (strcmp(method, "GET_PARAMETER") == 0) {
            int cseq = parse_cseq(request);

            size_t body_len;
            const uint8_t *body = get_body(request, total_len, &body_len);
            if (body && body_len > 0) {
                if (strstr((const char*)body, "volume")) {
                    char vol_response[32];
                    int vol_len = snprintf(vol_response, sizeof(vol_response), "volume: %.2f\r\n", g_volume_db);
                    send_rtsp_response(client_socket, 200, "OK", cseq,
                                      "Content-Type: text/parameters\r\n",
                                      vol_response, vol_len);
                } else {
                    send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
                }
            } else {
                send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
            }
        } else if (strcmp(method, "PAUSE") == 0) {
            int cseq = parse_cseq(request);
            audio_receiver_flush();
            send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
        } else if (strcmp(method, "FLUSH") == 0 || strcmp(method, "FLUSHBUFFERED") == 0) {
            int cseq = parse_cseq(request);
            audio_receiver_flush();
            send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
        } else if (strcmp(method, "TEARDOWN") == 0) {
            handle_teardown_request(client_socket, request);
        } else if (strcmp(method, "SETRATEANCHORTIME") == 0) {
            int cseq = parse_cseq(request);

            // Parse the body to get rate (binary plist)
            size_t body_len;
            const uint8_t *body = get_body(request, total_len, &body_len);
            double rate = 1.0;  // Default to playing
            if (body && body_len > 0) {
                if (!bplist_find_real(body, body_len, "rate", &rate)) {
                    // Try as integer
                    int64_t rate_int;
                    if (bplist_find_int(body, body_len, "rate", &rate_int)) {
                        rate = (double)rate_int;
                    }
                }
            }

            if (rate == 0.0) {
                audio_stream.paused = true;
                audio_receiver_flush();
            } else {
                audio_stream.paused = false;
            }
            send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
        } else if (strcmp(method, "SETPEERS") == 0 || strcmp(method, "SETPEERSX") == 0) {
            int cseq = parse_cseq(request);
            send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
        } else {
            ESP_LOGW(TAG, "Unknown method: %s", method);
            send_response(client_socket, 501, "Not Implemented", "text/plain", "Not Implemented", 15);
        }

        free(request);
        free(header_str);

        if (*buf_len > total_len) {
            memmove(buffer, buffer + total_len, *buf_len - total_len);
        }
        *buf_len -= total_len;
    }
}

// Helper to grow buffer using PSRAM if possible
static uint8_t *grow_buffer(uint8_t *old_buf, size_t old_size, size_t new_size, size_t data_len)
{
    uint8_t *new_buf = heap_caps_malloc(new_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!new_buf) {
        // Fallback to regular RAM
        new_buf = malloc(new_size);
    }
    if (!new_buf) {
        return NULL;
    }
    if (old_buf && data_len > 0) {
        memcpy(new_buf, old_buf, data_len);
    }
    if (old_buf) {
        free(old_buf);
    }
    return new_buf;
}

static void handle_client(int client_socket)
{
    // Start with small buffer, grow if needed for large messages (buffered audio)
    size_t buf_capacity = RTSP_BUFFER_INITIAL;
    uint8_t *buffer = malloc(buf_capacity);
    if (!buffer) {
        ESP_LOGE(TAG, "Failed to allocate request buffer");
        close(client_socket);
        return;
    }

    size_t buf_len = 0;

    while (server_running) {
        // Check if we should switch to encrypted mode
        if (encrypted_mode) {
            while (server_running && encrypted_mode) {
                if (buf_len >= buf_capacity - 1024) {
                    size_t new_capacity = (buf_capacity < RTSP_BUFFER_LARGE) ? RTSP_BUFFER_LARGE : buf_capacity * 2;
                    if (new_capacity > RTSP_BUFFER_LARGE) {
                        ESP_LOGE(TAG, "RTSP buffer overflow (%zu bytes)", buf_len);
                        goto cleanup;
                    }
                    uint8_t *new_buf = grow_buffer(buffer, buf_capacity, new_capacity, buf_len);
                    if (!new_buf) {
                        ESP_LOGE(TAG, "Failed to grow RTSP buffer to %zu bytes", new_capacity);
                        goto cleanup;
                    }
                    buffer = new_buf;
                    buf_capacity = new_capacity;
                }

                int block_len = read_encrypted_block(client_socket,
                                                     buffer + buf_len,
                                                     buf_capacity - buf_len);
                if (block_len <= 0) {
                    goto cleanup;
                }

                buf_len += (size_t)block_len;
                process_rtsp_buffer(client_socket, buffer, &buf_len);
            }

            goto cleanup;
        }

        // Plain-text mode (before encryption is enabled)
        if (buf_len >= buf_capacity - 1024) {
            // Grow buffer if needed
            size_t new_capacity = (buf_capacity < RTSP_BUFFER_LARGE) ? RTSP_BUFFER_LARGE : buf_capacity * 2;
            if (new_capacity > RTSP_BUFFER_LARGE) {
                ESP_LOGE(TAG, "RTSP buffer overflow (%zu bytes)", buf_len);
                break;
            }
            uint8_t *new_buf = grow_buffer(buffer, buf_capacity, new_capacity, buf_len);
            if (!new_buf) {
                ESP_LOGE(TAG, "Failed to grow RTSP buffer to %zu bytes", new_capacity);
                break;
            }
            buffer = new_buf;
            buf_capacity = new_capacity;
        }

        int recv_len = recv(client_socket, buffer + buf_len,
                            buf_capacity - buf_len, 0);
        if (recv_len <= 0) {
            if (recv_len < 0) {
                ESP_LOGE(TAG, "recv error: %d", errno);
            }
            break;
        }
        buf_len += (size_t)recv_len;
        process_rtsp_buffer(client_socket, buffer, &buf_len);
    }

cleanup:
    free(buffer);
    close(client_socket);

    stop_event_port_task();
    if (audio_stream.event_socket >= 0) {
        close(audio_stream.event_socket);
        audio_stream.event_socket = -1;
        audio_stream.event_port = 0;
    }

    // Reset audio stream state
    audio_stream.active = false;
    audio_stream.paused = false;
    audio_stream.data_socket = -1;
    audio_stream.control_socket = -1;

    // Reset encryption state and session for next client
    encrypted_mode = false;
    if (current_session) {
        hap_session_free(current_session);
        current_session = NULL;
    }
}

static void server_task(void *pvParameters)
{
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket < 0) {
        ESP_LOGE(TAG, "Failed to create socket: %d", errno);
        vTaskDelete(NULL);
        return;
    }

    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(RTSP_PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind socket: %d", errno);
        close(server_socket);
        server_socket = -1;
        vTaskDelete(NULL);
        return;
    }

    if (listen(server_socket, 5) < 0) {
        ESP_LOGE(TAG, "Failed to listen: %d", errno);
        close(server_socket);
        server_socket = -1;
        vTaskDelete(NULL);
        return;
    }

    server_running = true;

    while (server_running) {
        int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket < 0) {
            if (server_running) {
                ESP_LOGE(TAG, "Failed to accept: %d", errno);
            }
            continue;
        }

        handle_client(client_socket);
    }

    if (server_socket >= 0) {
        close(server_socket);
        server_socket = -1;
    }

    vTaskDelete(NULL);
}

esp_err_t rtsp_server_start(void)
{
    if (server_task_handle != NULL) {
        ESP_LOGW(TAG, "Server already running");
        return ESP_ERR_INVALID_STATE;
    }

    BaseType_t ret = xTaskCreate(server_task, "rtsp_server", 8192, NULL, 5, &server_task_handle);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create server task");
        return ESP_FAIL;
    }

    return ESP_OK;
}

void rtsp_server_stop(void)
{
    server_running = false;

    if (server_socket >= 0) {
        shutdown(server_socket, SHUT_RDWR);
        close(server_socket);
        server_socket = -1;
    }

    if (server_task_handle != NULL) {
        vTaskDelay(pdMS_TO_TICKS(100));
        server_task_handle = NULL;
    }
}

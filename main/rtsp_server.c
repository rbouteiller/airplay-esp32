#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_mac.h"

#include "rtsp_server.h"
#include "plist.h"
#include "hap.h"
#include "tlv8.h"
#include "audio_receiver.h"

static const char *TAG = "rtsp_server";

#define RTSP_PORT 7000
#define RTSP_MAX_REQUEST_SIZE 4096
#define RTSP_MAX_RESPONSE_SIZE 8192

static int server_socket = -1;
static TaskHandle_t server_task_handle = NULL;
static bool server_running = false;

// Current HAP session (one client at a time for now)
static hap_session_t *current_session = NULL;

// AirPlay 2 features flags
#define FEATURES_HI 0x1E
#define FEATURES_LO 0x5A7FFFF7

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
    uint16_t data_port;      // UDP port for audio data
    uint16_t control_port;   // UDP port for control (retransmit requests)
    uint16_t timing_port;    // UDP port for timing
    int data_socket;
    int control_socket;
    char codec[32];          // Audio codec from ANNOUNCE
    int sample_rate;
    int channels;
    int bits_per_sample;
} audio_stream_t;

static audio_stream_t audio_stream = {0};

static void get_device_id(char *device_id, size_t len)
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(device_id, len, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
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

    if (send(client_socket, header, header_len, 0) < 0) {
        ESP_LOGE(TAG, "Failed to send header");
        return -1;
    }

    if (body && body_len > 0) {
        if (send(client_socket, body, body_len, 0) < 0) {
            ESP_LOGE(TAG, "Failed to send body");
            return -1;
        }
    }

    return 0;
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

    if (send(client_socket, header, header_len, 0) < 0) {
        ESP_LOGE(TAG, "Failed to send RTSP header");
        return -1;
    }

    if (body && body_len > 0) {
        if (send(client_socket, body, body_len, 0) < 0) {
            ESP_LOGE(TAG, "Failed to send RTSP body");
            return -1;
        }
    }

    return 0;
}

static int parse_cseq(const char *request)
{
    const char *cseq = strstr(request, "CSeq:");
    if (cseq) {
        return atoi(cseq + 5);
    }
    return 1;
}

static void handle_info_request(int client_socket, const char *request)
{
    ESP_LOGI(TAG, "Handling /info request");

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
    ESP_LOGI(TAG, "Handling OPTIONS request");

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
    ESP_LOGI(TAG, "Handling POST %s", path);

    int cseq = parse_cseq(request);
    size_t body_len;
    const uint8_t *body = get_body(request, request_len, &body_len);

    if (strstr(path, "/pair-setup")) {
        ESP_LOGI(TAG, "Pair-setup requested, body_len=%zu", body_len);

        // Log body to debug
        if (body && body_len > 0) {
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, body, body_len > 64 ? 64 : body_len, ESP_LOG_INFO);
        }

        // AirPlay 2 simplified pair-setup:
        // - Client sends 32-byte Ed25519 public key (or encrypted blob)
        // - Server responds with its 32-byte Ed25519 public key
        // This establishes identity for transient pairing
        if (body_len == 32) {
            // Client sent their public key, respond with ours
            const uint8_t *our_pk = hap_get_public_key();
            ESP_LOGI(TAG, "Pair-setup: responding with our Ed25519 public key");
            send_rtsp_response(client_socket, 200, "OK", cseq,
                              "Content-Type: application/octet-stream\r\n",
                              (const char *)our_pk, 32);
        } else {
            // Unknown format - try TLV response
            ESP_LOGW(TAG, "Pair-setup: unexpected body size %zu, trying TLV response", body_len);
            static const uint8_t pair_setup_m2[] = {
                0x06, 0x01, 0x02  // State = 2 (M2)
            };
            send_rtsp_response(client_socket, 200, "OK", cseq,
                              "Content-Type: application/octet-stream\r\n",
                              (const char *)pair_setup_m2, sizeof(pair_setup_m2));
        }
    } else if (strstr(path, "/pair-verify")) {
        ESP_LOGI(TAG, "Pair-verify requested, body_len=%zu", body_len);

        // Log first bytes for debugging
        if (body && body_len > 0) {
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, body, body_len > 32 ? 32 : body_len, ESP_LOG_INFO);
        }

        // Create session if needed
        if (!current_session) {
            current_session = hap_session_create();
            if (!current_session) {
                ESP_LOGE(TAG, "Failed to create HAP session");
                send_rtsp_response(client_socket, 500, "Internal Error", cseq, NULL, NULL, 0);
                return;
            }
        }

        uint8_t response[1024];
        size_t response_len = 0;
        esp_err_t err = ESP_FAIL;

        if (body && body_len > 0) {
            // Check if this is TLV format (has state byte) or raw format
            size_t state_len;
            const uint8_t *state = tlv8_find(body, body_len, TLV_TYPE_STATE, &state_len);

            if (state && state_len == 1) {
                // TLV format
                if (state[0] == 0x01) {
                    ESP_LOGI(TAG, "Pair-verify M1 (TLV format)");
                    err = hap_pair_verify_m1(current_session, body, body_len,
                                            response, sizeof(response), &response_len);
                } else if (state[0] == 0x03) {
                    ESP_LOGI(TAG, "Pair-verify M3 (TLV format)");
                    err = hap_pair_verify_m3(current_session, body, body_len,
                                            response, sizeof(response), &response_len);
                } else {
                    ESP_LOGE(TAG, "Unexpected TLV state: %d", state[0]);
                    err = ESP_ERR_INVALID_ARG;
                }
            } else {
                // Raw format (AirPlay 2 simplified)
                if (current_session->pair_verify_state == 0) {
                    // First message - M1 raw (68 bytes: 32 pubkey + 36 encrypted)
                    ESP_LOGI(TAG, "Pair-verify M1 (raw format)");
                    err = hap_pair_verify_m1_raw(current_session, body, body_len,
                                                 response, sizeof(response), &response_len);
                } else if (current_session->pair_verify_state == PAIR_VERIFY_STATE_M2) {
                    // Second message - M3 raw (encrypted data)
                    ESP_LOGI(TAG, "Pair-verify M3 (raw format)");
                    err = hap_pair_verify_m3_raw(current_session, body, body_len,
                                                 response, sizeof(response), &response_len);
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
            // Return error
            send_rtsp_response(client_socket, 200, "OK", cseq,
                              "Content-Type: application/octet-stream\r\n",
                              "\x06\x01\x04\x07\x01\x02", 6);  // State=4, Error=2 (auth)
        }
    } else if (strstr(path, "/fp-setup")) {
        ESP_LOGI(TAG, "FairPlay setup requested, body_len=%zu", body_len);

        if (body && body_len >= 16) {
            uint8_t version = body[4];
            uint8_t type = body[5];
            uint8_t seq = body[6];
            uint8_t mode = body[14];

            ESP_LOGI(TAG, "FairPlay: version=%d, type=%d, seq=%d, mode=%d",
                     version, type, seq, mode);

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
                    ESP_LOGI(TAG, "FairPlay setup1 response, mode=%d", mode);
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
                        ESP_LOGI(TAG, "FairPlay setup2 response");
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
        ESP_LOGI(TAG, "Command received");
        send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
    } else if (strstr(path, "/feedback")) {
        ESP_LOGI(TAG, "Feedback received");
        send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
    } else {
        ESP_LOGW(TAG, "Unknown POST path: %s", path);
        send_rtsp_response(client_socket, 404, "Not Found", cseq, NULL, NULL, 0);
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
        ESP_LOGI(TAG, "Found audio media in SDP");
    }

    const char *rtpmap = strstr(sdp, "a=rtpmap:");
    if (rtpmap) {
        // Extract codec name
        if (sscanf(rtpmap, "a=rtpmap:%*d %31s", format.codec) == 1) {
            ESP_LOGI(TAG, "Audio codec: %s", format.codec);
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
            ESP_LOGI(TAG, "ALAC config: %u samples, %u bit, %u ch, %d Hz",
                     frame_len, bit_depth, num_ch, format.sample_rate);
        }
    }

    // Parse encryption parameters for RAOP (AirPlay 1)
    // a=rsaaeskey: - RSA-encrypted AES key (base64)
    // a=aesiv: - AES IV (base64)
    const char *rsaaeskey = strstr(sdp, "a=rsaaeskey:");
    const char *aesiv = strstr(sdp, "a=aesiv:");

    if (rsaaeskey && aesiv) {
        ESP_LOGI(TAG, "Found encryption params in SDP (RAOP mode)");

        // Note: rsaaeskey is RSA-encrypted with device's private key
        // For AirPlay 1, we would need to RSA-decrypt the key
        // For now, just parse and store the IV
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
                ESP_LOGI(TAG, "AES IV parsed successfully");
            } else {
                ESP_LOGW(TAG, "Failed to decode AES IV (got %d bytes)", decoded);
            }
        }

        // Note: For real RAOP support, we need RSA private key to decrypt rsaaeskey
        // For AirPlay 2, encryption key is derived from pair-verify shared secret
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
    ESP_LOGI(TAG, "Handling ANNOUNCE request");
    int cseq = parse_cseq(request);

    size_t body_len;
    const uint8_t *body = get_body(request, request_len, &body_len);

    if (body && body_len > 0) {
        // Parse SDP content
        parse_sdp((const char *)body, body_len);
        ESP_LOGI(TAG, "ANNOUNCE SDP parsed, codec=%s", audio_stream.codec);
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

static void handle_setup_request(int client_socket, const char *request, size_t request_len)
{
    ESP_LOGI(TAG, "Handling SETUP request");
    int cseq = parse_cseq(request);

    // Log Content-Type if present (might be application/x-apple-binary-plist for AirPlay 2)
    const char *content_type = strstr(request, "Content-Type:");
    if (content_type) {
        char ct[64] = {0};
        sscanf(content_type, "Content-Type: %63s", ct);
        ESP_LOGI(TAG, "SETUP Content-Type: %s", ct);
    }

    // Check for body (AirPlay 2 sends binary plist with stream config)
    size_t body_len;
    const uint8_t *body = get_body(request, request_len, &body_len);
    if (body && body_len > 0) {
        ESP_LOGI(TAG, "SETUP body: %zu bytes", body_len);
        // Log first 128 bytes to look for encryption keys
        ESP_LOG_BUFFER_HEX_LEVEL(TAG, body, body_len > 128 ? 128 : body_len, ESP_LOG_INFO);

        // Look for "ekey" or "eiv" in binary plist (encryption key/iv)
        for (size_t i = 0; i < body_len - 4; i++) {
            if (memcmp(body + i, "ekey", 4) == 0) {
                ESP_LOGI(TAG, "Found 'ekey' at offset %zu", i);
            }
            if (memcmp(body + i, "eiv", 3) == 0) {
                ESP_LOGI(TAG, "Found 'eiv' at offset %zu", i);
            }
            if (memcmp(body + i, "shk", 3) == 0) {
                ESP_LOGI(TAG, "Found 'shk' (shared key) at offset %zu", i);
            }
        }
    }

    // Parse Transport header to get client ports
    // Transport: RTP/AVP/UDP;unicast;mode=record;timing_port=50466;control_port=50465
    const char *transport = strstr(request, "Transport:");
    uint16_t client_control_port = 0;
    uint16_t client_timing_port = 0;

    if (transport) {
        const char *cp = strstr(transport, "control_port=");
        if (cp) {
            client_control_port = atoi(cp + 13);
        }
        const char *tp = strstr(transport, "timing_port=");
        if (tp) {
            client_timing_port = atoi(tp + 12);
        }
        ESP_LOGI(TAG, "Client ports - control: %d, timing: %d",
                 client_control_port, client_timing_port);
    }

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

    ESP_LOGI(TAG, "Server ports - data: %d, control: %d, timing: %d",
             audio_stream.data_port, audio_stream.control_port, audio_stream.timing_port);

    // Build Transport response header
    char transport_response[256];
    snprintf(transport_response, sizeof(transport_response),
             "Transport: RTP/AVP/UDP;unicast;mode=record;"
             "server_port=%d;control_port=%d;timing_port=%d\r\n"
             "Session: 1\r\n",
             audio_stream.data_port, audio_stream.control_port, audio_stream.timing_port);

    send_rtsp_response(client_socket, 200, "OK", cseq, transport_response, NULL, 0);
    audio_stream.active = true;
}

static void handle_record_request(int client_socket, const char *request)
{
    ESP_LOGI(TAG, "Handling RECORD request - starting audio stream");
    int cseq = parse_cseq(request);

    // Parse RTP-Info header if present
    const char *rtp_info = strstr(request, "RTP-Info:");
    if (rtp_info) {
        ESP_LOGI(TAG, "RTP-Info received");
    }

    // Start audio receiver on the data port
    if (audio_stream.data_port > 0) {
        esp_err_t err = audio_receiver_start(audio_stream.data_port, audio_stream.control_port);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to start audio receiver");
        } else {
            ESP_LOGI(TAG, "Audio receiver started on port %d", audio_stream.data_port);
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
                    ESP_LOGI(TAG, "Volume set to: %.2f dB", volume);
                    // Convert from dB to linear: 0dB = max, -144dB = min
                    // volume_linear = 10^(volume/20)
                }
            }
            if (strstr((const char *)body, "progress:")) {
                ESP_LOGI(TAG, "Progress update received");
            }
        }
    } else if (content_type && strstr(content_type, "image/")) {
        ESP_LOGI(TAG, "Album art received");
    } else if (content_type && strstr(content_type, "application/x-dmap-tagged")) {
        ESP_LOGI(TAG, "DMAP metadata received");
    }

    send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
}

static void handle_teardown_request(int client_socket, const char *request)
{
    ESP_LOGI(TAG, "Handling TEARDOWN request - stopping audio stream");
    int cseq = parse_cseq(request);

    // Stop audio receiver
    audio_receiver_stop();

    // Log audio stats
    audio_stats_t stats;
    audio_receiver_get_stats(&stats);
    ESP_LOGI(TAG, "Audio stats: recv=%lu, decoded=%lu, dropped=%lu",
             stats.packets_received, stats.packets_decoded, stats.packets_dropped);

    // Reset audio stream state (sockets are managed by audio_receiver)
    audio_stream.data_port = 0;
    audio_stream.control_port = 0;
    audio_stream.timing_port = 0;
    audio_stream.active = false;

    // Clean up HAP session
    if (current_session) {
        hap_session_free(current_session);
        current_session = NULL;
    }

    send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
}

static void handle_client(int client_socket)
{
    char *request = malloc(RTSP_MAX_REQUEST_SIZE);
    if (!request) {
        ESP_LOGE(TAG, "Failed to allocate request buffer");
        close(client_socket);
        return;
    }

    while (server_running) {
        memset(request, 0, RTSP_MAX_REQUEST_SIZE);

        int recv_len = recv(client_socket, request, RTSP_MAX_REQUEST_SIZE - 1, 0);
        if (recv_len <= 0) {
            if (recv_len < 0) {
                ESP_LOGE(TAG, "recv error: %d", errno);
            }
            break;
        }

        request[recv_len] = '\0';

        // Log first line of request
        char *first_line_end = strstr(request, "\r\n");
        if (first_line_end) {
            *first_line_end = '\0';
            ESP_LOGI(TAG, "Request: %s", request);
            *first_line_end = '\r';
        }

        // Parse request method and path
        char method[16] = {0};
        char path[256] = {0};
        sscanf(request, "%15s %255s", method, path);

        if (strcmp(method, "GET") == 0) {
            if (strcmp(path, "/info") == 0) {
                handle_info_request(client_socket, request);
            } else {
                ESP_LOGW(TAG, "Unknown GET path: %s", path);
                send_response(client_socket, 404, "Not Found", "text/plain", "Not Found", 9);
            }
        } else if (strcmp(method, "OPTIONS") == 0) {
            handle_options_request(client_socket, request);
        } else if (strcmp(method, "POST") == 0) {
            handle_post_request(client_socket, request, recv_len, path);
        } else if (strcmp(method, "ANNOUNCE") == 0) {
            handle_announce_request(client_socket, request, recv_len);
        } else if (strcmp(method, "SETUP") == 0) {
            handle_setup_request(client_socket, request, recv_len);
        } else if (strcmp(method, "RECORD") == 0) {
            handle_record_request(client_socket, request);
        } else if (strcmp(method, "SET_PARAMETER") == 0) {
            handle_set_parameter_request(client_socket, request, recv_len);
        } else if (strcmp(method, "GET_PARAMETER") == 0) {
            int cseq = parse_cseq(request);
            ESP_LOGI(TAG, "GET_PARAMETER received");

            // Check what parameter is being requested (in body)
            size_t body_len;
            const uint8_t *body = get_body(request, recv_len, &body_len);
            if (body && body_len > 0) {
                ESP_LOGI(TAG, "GET_PARAMETER query: %.*s", (int)body_len, (char*)body);

                // Check for volume query
                if (strstr((const char*)body, "volume")) {
                    // Return current volume (0 dB = max)
                    send_rtsp_response(client_socket, 200, "OK", cseq,
                                      "Content-Type: text/parameters\r\n",
                                      "volume: 0.0\r\n", 13);
                } else {
                    send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
                }
            } else {
                send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
            }
        } else if (strcmp(method, "PAUSE") == 0) {
            int cseq = parse_cseq(request);
            ESP_LOGI(TAG, "Pause request received - flushing audio");
            audio_receiver_flush();
            send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
        } else if (strcmp(method, "FLUSH") == 0 || strcmp(method, "FLUSHBUFFERED") == 0) {
            int cseq = parse_cseq(request);
            ESP_LOGI(TAG, "Flush request received");
            audio_receiver_flush();
            send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
        } else if (strcmp(method, "TEARDOWN") == 0) {
            handle_teardown_request(client_socket, request);
        } else if (strcmp(method, "SETRATEANCHORTIME") == 0) {
            int cseq = parse_cseq(request);
            ESP_LOGI(TAG, "SetRateAnchorTime received (play/pause)");
            send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
        } else if (strcmp(method, "SETPEERS") == 0 || strcmp(method, "SETPEERSX") == 0) {
            int cseq = parse_cseq(request);
            ESP_LOGI(TAG, "SetPeers received (PTP timing)");
            send_rtsp_response(client_socket, 200, "OK", cseq, NULL, NULL, 0);
        } else if (method[0] == '\0') {
            // Empty method - might be partial data or keep-alive
            ESP_LOGD(TAG, "Empty method received, skipping");
            continue;
        } else {
            ESP_LOGW(TAG, "Unknown method: %s", method);
            send_response(client_socket, 501, "Not Implemented", "text/plain", "Not Implemented", 15);
        }
    }

    free(request);
    close(client_socket);
    ESP_LOGI(TAG, "Client disconnected");
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

    ESP_LOGI(TAG, "RTSP server listening on port %d", RTSP_PORT);
    server_running = true;

    while (server_running) {
        int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket < 0) {
            if (server_running) {
                ESP_LOGE(TAG, "Failed to accept: %d", errno);
            }
            continue;
        }

        ESP_LOGI(TAG, "Client connected from %d.%d.%d.%d",
                 (client_addr.sin_addr.s_addr >> 0) & 0xFF,
                 (client_addr.sin_addr.s_addr >> 8) & 0xFF,
                 (client_addr.sin_addr.s_addr >> 16) & 0xFF,
                 (client_addr.sin_addr.s_addr >> 24) & 0xFF);

        // Handle client in same task (single client for now)
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

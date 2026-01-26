#include "rtsp_handlers.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "esp_log.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sodium.h"

#include "audio_receiver.h"
#include "hap.h"
#include "plist.h"
#include "rtsp_fairplay.h"
#include "tlv8.h"

static const char *TAG = "rtsp_handlers";

// ============================================================================
// Codec Registry
// ============================================================================
// To add a new codec, add an entry to codec_registry[] below.

static void configure_alac(audio_format_t *fmt, int64_t sr, int64_t spf) {
    strcpy(fmt->codec, "ALAC");
    fmt->sample_rate = (int)sr;
    fmt->channels = 2;
    fmt->bits_per_sample = 16;
    fmt->frame_size = (int)spf;
    fmt->max_samples_per_frame = (uint32_t)spf;
    fmt->sample_size = 16;
    fmt->num_channels = 2;
    fmt->sample_rate_config = (uint32_t)sr;
}

static void configure_aac(audio_format_t *fmt, int64_t sr, int64_t spf) {
    strcpy(fmt->codec, "AAC");
    fmt->sample_rate = (int)sr;
    fmt->channels = 2;
    fmt->bits_per_sample = 16;
    fmt->frame_size = (int)spf;
    fmt->max_samples_per_frame = (uint32_t)spf;
    fmt->sample_size = 16;
    fmt->num_channels = 2;
    fmt->sample_rate_config = (uint32_t)sr;
}

static void configure_aac_eld(audio_format_t *fmt, int64_t sr, int64_t spf) {
    strcpy(fmt->codec, "AAC-ELD");
    fmt->sample_rate = (int)sr;
    fmt->channels = 2;
    fmt->bits_per_sample = 16;
    fmt->frame_size = (int)spf;
    fmt->max_samples_per_frame = (uint32_t)spf;
    fmt->sample_size = 16;
    fmt->num_channels = 2;
    fmt->sample_rate_config = (uint32_t)sr;
}

static void configure_opus(audio_format_t *fmt, int64_t sr, int64_t spf) {
    strcpy(fmt->codec, "OPUS");
    fmt->sample_rate = (int)sr;
    fmt->channels = 2;
    fmt->bits_per_sample = 16;
    fmt->frame_size = (int)spf;
    fmt->max_samples_per_frame = (uint32_t)spf;
    fmt->sample_size = 16;
    fmt->num_channels = 2;
    fmt->sample_rate_config = (uint32_t)sr;
}

// Codec registry - add new codecs here
// ct values: 2=ALAC, 4=AAC, 8=AAC-ELD, 64=OPUS (based on AirPlay 2 protocol)
static const rtsp_codec_t codec_registry[] = {
    {"ALAC",    2,  configure_alac},
    {"AAC",     4,  configure_aac},
    {"AAC-ELD", 8,  configure_aac_eld},
    {"OPUS",    64, configure_opus},
    {NULL, 0, NULL}
};

bool rtsp_codec_configure(int64_t type_id, audio_format_t *fmt,
                          int64_t sample_rate, int64_t samples_per_frame) {
    for (const rtsp_codec_t *codec = codec_registry; codec->name; codec++) {
        if (codec->type_id == type_id) {
            codec->configure(fmt, sample_rate, samples_per_frame);
            ESP_LOGI(TAG, "Configured codec: %s (ct=%lld, sr=%lld, spf=%lld)",
                     codec->name, (long long)type_id,
                     (long long)sample_rate, (long long)samples_per_frame);
            return true;
        }
    }
    // Default to ALAC if unknown codec type
    ESP_LOGW(TAG, "Unknown codec type %lld, defaulting to ALAC",
             (long long)type_id);
    configure_alac(fmt, sample_rate, samples_per_frame);
    return false;
}

// Event port task state
static int event_client_socket = -1;
static TaskHandle_t event_task_handle = NULL;

void rtsp_get_device_id(char *device_id, size_t len) {
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(device_id, len, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1],
             mac[2], mac[3], mac[4], mac[5]);
}

int rtsp_create_udp_socket(uint16_t *port) {
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

int rtsp_create_event_socket(uint16_t *port) {
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
    addr.sin_port = 0;

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

    socklen_t addr_len = sizeof(addr);
    getsockname(sock, (struct sockaddr *)&addr, &addr_len);
    *port = ntohs(addr.sin_port);

    return sock;
}

// Event port task - handles AirPlay 2 session persistence
static void event_port_task(void *pvParameters) {
    int listen_socket = (int)(intptr_t)pvParameters;

    while (listen_socket >= 0) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_socket, &read_fds);

        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        int ret = select(listen_socket + 1, &read_fds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno != EINTR) {
                ESP_LOGE(TAG, "Event port select error: %d", errno);
            }
            break;
        }

        if (ret == 0) {
            continue;
        }

        if (FD_ISSET(listen_socket, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client =
                accept(listen_socket, (struct sockaddr *)&client_addr, &addr_len);
            if (client < 0) {
                ESP_LOGE(TAG, "Event port accept error: %d", errno);
                continue;
            }

            if (event_client_socket >= 0) {
                close(event_client_socket);
            }
            event_client_socket = client;

            // Monitor connection for disconnection
            while (event_client_socket >= 0 && listen_socket >= 0) {
                fd_set cfds;
                FD_ZERO(&cfds);
                FD_SET(event_client_socket, &cfds);
                struct timeval ctv = {.tv_sec = 1, .tv_usec = 0};

                ret = select(event_client_socket + 1, &cfds, NULL, NULL, &ctv);
                if (ret < 0) {
                    break;
                }
                if (ret > 0 && FD_ISSET(event_client_socket, &cfds)) {
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

    if (event_client_socket >= 0) {
        close(event_client_socket);
        event_client_socket = -1;
    }
    event_task_handle = NULL;
    vTaskDelete(NULL);
}

void rtsp_start_event_port_task(int listen_socket) {
    if (event_task_handle != NULL) {
        return;
    }
    xTaskCreate(event_port_task, "event_port", 3072,
                (void *)(intptr_t)listen_socket, 5, &event_task_handle);
}

void rtsp_stop_event_port_task(void) {
    if (event_client_socket >= 0) {
        close(event_client_socket);
        event_client_socket = -1;
    }
}

// Forward declarations of handlers
static void handle_options(int socket, rtsp_conn_t *conn,
                           const rtsp_request_t *req,
                           const uint8_t *raw, size_t raw_len);
static void handle_get(int socket, rtsp_conn_t *conn,
                       const rtsp_request_t *req,
                       const uint8_t *raw, size_t raw_len);
static void handle_post(int socket, rtsp_conn_t *conn,
                        const rtsp_request_t *req,
                        const uint8_t *raw, size_t raw_len);
static void handle_announce(int socket, rtsp_conn_t *conn,
                            const rtsp_request_t *req,
                            const uint8_t *raw, size_t raw_len);
static void handle_setup(int socket, rtsp_conn_t *conn,
                         const rtsp_request_t *req,
                         const uint8_t *raw, size_t raw_len);
static void handle_record(int socket, rtsp_conn_t *conn,
                          const rtsp_request_t *req,
                          const uint8_t *raw, size_t raw_len);
static void handle_set_parameter(int socket, rtsp_conn_t *conn,
                                 const rtsp_request_t *req,
                                 const uint8_t *raw, size_t raw_len);
static void handle_get_parameter(int socket, rtsp_conn_t *conn,
                                 const rtsp_request_t *req,
                                 const uint8_t *raw, size_t raw_len);
static void handle_pause(int socket, rtsp_conn_t *conn,
                         const rtsp_request_t *req,
                         const uint8_t *raw, size_t raw_len);
static void handle_flush(int socket, rtsp_conn_t *conn,
                         const rtsp_request_t *req,
                         const uint8_t *raw, size_t raw_len);
static void handle_teardown(int socket, rtsp_conn_t *conn,
                            const rtsp_request_t *req,
                            const uint8_t *raw, size_t raw_len);
static void handle_setrateanchortime(int socket, rtsp_conn_t *conn,
                                      const rtsp_request_t *req,
                                      const uint8_t *raw, size_t raw_len);
static void handle_setpeers(int socket, rtsp_conn_t *conn,
                            const rtsp_request_t *req,
                            const uint8_t *raw, size_t raw_len);

// Dispatch table - like shairport-sync method_handlers
static const rtsp_method_handler_t method_handlers[] = {
    {"OPTIONS",           handle_options},
    {"GET",               handle_get},
    {"POST",              handle_post},
    {"ANNOUNCE",          handle_announce},
    {"SETUP",             handle_setup},
    {"RECORD",            handle_record},
    {"SET_PARAMETER",     handle_set_parameter},
    {"GET_PARAMETER",     handle_get_parameter},
    {"PAUSE",             handle_pause},
    {"FLUSH",             handle_flush},
    {"FLUSHBUFFERED",     handle_flush},
    {"TEARDOWN",          handle_teardown},
    {"SETRATEANCHORTIME", handle_setrateanchortime},
    {"SETPEERS",          handle_setpeers},
    {"SETPEERSX",         handle_setpeers},
    {NULL, NULL}
};

int rtsp_dispatch(int socket, rtsp_conn_t *conn,
                  const uint8_t *raw_request, size_t raw_len) {
    rtsp_request_t req;
    if (rtsp_request_parse(raw_request, raw_len, &req) < 0) {
        ESP_LOGW(TAG, "Failed to parse RTSP request");
        return -1;
    }

    // Find handler in dispatch table
    for (const rtsp_method_handler_t *h = method_handlers; h->method; h++) {
        if (strcasecmp(req.method, h->method) == 0) {
            h->handler(socket, conn, &req, raw_request, raw_len);
            return 0;
        }
    }

    ESP_LOGW(TAG, "Unknown method: %s", req.method);
    rtsp_send_http_response(socket, conn, 501, "Not Implemented",
                            "text/plain", "Not Implemented", 15);
    return 0;
}

// ============================================================================
// Handler implementations
// ============================================================================

static void handle_options(int socket, rtsp_conn_t *conn,
                           const rtsp_request_t *req,
                           const uint8_t *raw, size_t raw_len) {
    (void)raw;
    (void)raw_len;

    const char *public_methods =
        "Public: ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, FLUSHBUFFERED, TEARDOWN, "
        "OPTIONS, POST, GET, SET_PARAMETER, GET_PARAMETER, SETPEERS, "
        "SETRATEANCHORTIME\r\n";

    rtsp_send_response(socket, conn, 200, "OK", req->cseq, public_methods,
                       NULL, 0);
}

static void handle_get(int socket, rtsp_conn_t *conn,
                       const rtsp_request_t *req,
                       const uint8_t *raw, size_t raw_len) {
    (void)raw;
    (void)raw_len;

    if (strcmp(req->path, "/info") == 0) {
        // Build info response
        char device_id[18];
        static char body[4096];
        plist_t p;

        rtsp_get_device_id(device_id, sizeof(device_id));
        const uint8_t *pk = hap_get_public_key();
        uint64_t features = ((uint64_t)AIRPLAY_FEATURES_HI << 32) | AIRPLAY_FEATURES_LO;

        plist_init(&p, body, sizeof(body));
        plist_begin(&p);
        plist_dict_begin(&p);

        plist_dict_string(&p, "deviceid", device_id);
        plist_dict_uint(&p, "features", features);
        plist_dict_string(&p, "model", "AudioAccessory5,1");
        plist_dict_string(&p, "protovers", "1.1");
        plist_dict_string(&p, "srcvers", "377.40.00");
        plist_dict_int(&p, "vv", 2);
        plist_dict_int(&p, "statusFlags", 4);
        plist_dict_data(&p, "pk", pk, 32);
        plist_dict_string(&p, "pi", "00000000-0000-0000-0000-000000000000");
        plist_dict_string(&p, "name", CONFIG_AIRPLAY_DEVICE_NAME);

        // Audio formats array
        plist_dict_array_begin(&p, "audioFormats");
        plist_dict_begin(&p);
        plist_dict_int(&p, "type", 96);
        plist_dict_int(&p, "audioInputFormats", 0x01000000);
        plist_dict_int(&p, "audioOutputFormats", 0x01000000);
        plist_dict_end(&p);
        plist_array_end(&p);

        // Audio latencies array
        plist_dict_array_begin(&p, "audioLatencies");
        plist_dict_begin(&p);
        plist_dict_int(&p, "type", 96);
        plist_dict_int(&p, "audioType", 0x64);
        plist_dict_int(&p, "inputLatencyMicros", 0);
        plist_dict_int(&p, "outputLatencyMicros",
                       audio_receiver_get_output_latency_us());
        plist_dict_end(&p);
        plist_array_end(&p);

        plist_dict_end(&p);
        size_t body_len = plist_end(&p);

        rtsp_send_http_response(socket, conn, 200, "OK",
                                "text/x-apple-plist+xml", body, body_len);
    } else {
        ESP_LOGW(TAG, "Unknown GET path: %s", req->path);
        rtsp_send_http_response(socket, conn, 404, "Not Found",
                                "text/plain", "Not Found", 9);
    }
}

static void handle_post(int socket, rtsp_conn_t *conn,
                        const rtsp_request_t *req,
                        const uint8_t *raw, size_t raw_len) {
    (void)raw;
    (void)raw_len;

    const uint8_t *body = req->body;
    size_t body_len = req->body_len;

    if (strstr(req->path, "/pair-setup")) {
        // Create session if needed
        if (!conn->hap_session) {
            conn->hap_session = hap_session_create();
            if (!conn->hap_session) {
                ESP_LOGE(TAG, "Failed to create HAP session");
                rtsp_send_response(socket, conn, 500, "Internal Error",
                                   req->cseq, NULL, NULL, 0);
                return;
            }
        }

        uint8_t *response = malloc(2048);
        if (!response) {
            rtsp_send_response(socket, conn, 500, "Internal Error",
                               req->cseq, NULL, NULL, 0);
            return;
        }

        size_t response_len = 0;
        esp_err_t err = ESP_FAIL;

        if (body && body_len > 0) {
            size_t state_len;
            const uint8_t *state =
                tlv8_find(body, body_len, TLV_TYPE_STATE, &state_len);

            if (state && state_len == 1) {
                switch (state[0]) {
                case 1:
                    err = hap_pair_setup_m1(conn->hap_session, body, body_len,
                                            response, 2048, &response_len);
                    break;
                case 3:
                    err = hap_pair_setup_m3(conn->hap_session, body, body_len,
                                            response, 2048, &response_len);
                    break;
                case 5:
                    err = hap_pair_setup_m5(conn->hap_session, body, body_len,
                                            response, 2048, &response_len);
                    break;
                }
            }
        }

        if (err == ESP_OK && response_len > 0) {
            rtsp_send_response(socket, conn, 200, "OK", req->cseq,
                               "Content-Type: application/octet-stream\r\n",
                               (const char *)response, response_len);

            if (conn->hap_session && conn->hap_session->pair_setup_state == 4 &&
                conn->hap_session->session_established) {
                conn->encrypted_mode = true;
            }
        } else {
            ESP_LOGE(TAG, "Pair-setup failed: err=%d", err);
            static const uint8_t error_response[] = {0x06, 0x01, 0x02,
                                                     0x07, 0x01, 0x02};
            rtsp_send_response(socket, conn, 200, "OK", req->cseq,
                               "Content-Type: application/octet-stream\r\n",
                               (const char *)error_response, sizeof(error_response));
        }

        free(response);

    } else if (strstr(req->path, "/pair-verify")) {
        if (!conn->hap_session) {
            conn->hap_session = hap_session_create();
            if (!conn->hap_session) {
                rtsp_send_response(socket, conn, 500, "Internal Error",
                                   req->cseq, NULL, NULL, 0);
                return;
            }
        }

        uint8_t *response = malloc(1024);
        if (!response) {
            rtsp_send_response(socket, conn, 500, "Internal Error",
                               req->cseq, NULL, NULL, 0);
            return;
        }

        size_t response_len = 0;
        esp_err_t err = ESP_FAIL;

        if (body && body_len > 0) {
            size_t state_len;
            const uint8_t *state =
                tlv8_find(body, body_len, TLV_TYPE_STATE, &state_len);

            if (state && state_len == 1) {
                if (state[0] == 0x01) {
                    err = hap_pair_verify_m1(conn->hap_session, body, body_len,
                                             response, 1024, &response_len);
                } else if (state[0] == 0x03) {
                    err = hap_pair_verify_m3(conn->hap_session, body, body_len,
                                             response, 1024, &response_len);
                }
            } else {
                // Raw format
                if (conn->hap_session->pair_verify_state == 0) {
                    err = hap_pair_verify_m1_raw(conn->hap_session, body, body_len,
                                                 response, 1024, &response_len);
                } else if (conn->hap_session->pair_verify_state == PAIR_VERIFY_STATE_M2) {
                    err = hap_pair_verify_m3_raw(conn->hap_session, body, body_len,
                                                 response, 1024, &response_len);
                }
            }
        }

        if (err == ESP_OK && response_len > 0) {
            rtsp_send_response(socket, conn, 200, "OK", req->cseq,
                               "Content-Type: application/octet-stream\r\n",
                               (const char *)response, response_len);
        } else {
            ESP_LOGE(TAG, "Pair-verify failed, err=%d", err);
            rtsp_send_response(socket, conn, 200, "OK", req->cseq,
                               "Content-Type: application/octet-stream\r\n",
                               "\x06\x01\x04\x07\x01\x02", 6);
        }

        free(response);

    } else if (strstr(req->path, "/fp-setup")) {
        uint8_t *fp_response = NULL;
        size_t fp_response_len = 0;

        if (body && body_len >= 16) {
            if (rtsp_fairplay_handle(body, body_len, &fp_response,
                                     &fp_response_len) == 0) {
                rtsp_send_response(socket, conn, 200, "OK", req->cseq,
                                   "Content-Type: application/octet-stream\r\n",
                                   (const char *)fp_response, fp_response_len);
                free(fp_response);
                return;
            }
        }

        rtsp_send_response(socket, conn, 200, "OK", req->cseq,
                           "Content-Type: application/octet-stream\r\n",
                           "\x00", 1);

    } else if (strstr(req->path, "/command")) {
        if (body && body_len >= 8 && memcmp(body, "bplist00", 8) == 0) {
            int64_t cmd_type = 0;
            if (bplist_find_int(body, body_len, "type", &cmd_type)) {
                ESP_LOGI(TAG, "/command type=%lld", (long long)cmd_type);
            }
        }
        rtsp_send_ok(socket, conn, req->cseq);

    } else if (strstr(req->path, "/feedback")) {
        if (body && body_len >= 8 && memcmp(body, "bplist00", 8) == 0) {
            int64_t value;
            if (bplist_find_int(body, body_len, "networkTimeSecs", &value)) {
                ESP_LOGI(TAG, "/feedback has networkTimeSecs=%lld",
                         (long long)value);
            }
        }
        rtsp_send_ok(socket, conn, req->cseq);

    } else {
        rtsp_send_ok(socket, conn, req->cseq);
    }
}

static void parse_sdp(rtsp_conn_t *conn, const char *sdp, size_t len) {
    (void)len;

    audio_format_t format = {0};
    audio_encrypt_t encrypt = {0};
    encrypt.type = AUDIO_ENCRYPT_NONE;

    format.sample_rate = 44100;
    format.channels = 2;
    format.bits_per_sample = 16;
    format.frame_size = 352;
    strcpy(format.codec, "AppleLossless");

    const char *rtpmap = strstr(sdp, "a=rtpmap:");
    if (rtpmap) {
        sscanf(rtpmap, "a=rtpmap:%*d %31s", format.codec);
        char *slash = strchr(format.codec, '/');
        if (slash) {
            *slash = '\0';
            int sr = 0;
            int ch = 0;
            if (sscanf(slash + 1, "%d/%d", &sr, &ch) >= 1) {
                if (sr > 0) {
                    format.sample_rate = sr;
                }
                if (ch > 0) {
                    format.channels = ch;
                }
            }
        }
    }

    const char *fmtp = strstr(sdp, "a=fmtp:");
    if (fmtp) {
        unsigned int frame_len, bit_depth, pb, mb, kb, num_ch, max_run,
            max_frame, avg_rate, rate;
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
            if (matched >= 8)
                format.max_run = max_run;
            if (matched >= 9)
                format.max_coded_frame_size = max_frame;
            if (matched >= 10)
                format.avg_bit_rate = avg_rate;
            if (matched >= 11) {
                format.sample_rate_config = rate;
                format.sample_rate = rate;
            }
        }
    }

    if ((strstr(format.codec, "AAC") || strstr(format.codec, "aac") ||
         strstr(format.codec, "mpeg4-generic") ||
         strstr(format.codec, "MPEG4-GENERIC")) &&
        format.max_samples_per_frame == 0) {
        format.frame_size = 1024;
        format.max_samples_per_frame = 1024;
    }

    // Update connection state
    strncpy(conn->codec, format.codec, sizeof(conn->codec) - 1);
    conn->sample_rate = format.sample_rate;
    conn->channels = format.channels;
    conn->bits_per_sample = format.bits_per_sample;

    audio_receiver_set_format(&format);

    if (encrypt.type != AUDIO_ENCRYPT_NONE) {
        audio_receiver_set_encryption(&encrypt);
    }
}

static void handle_announce(int socket, rtsp_conn_t *conn,
                            const rtsp_request_t *req,
                            const uint8_t *raw, size_t raw_len) {
    (void)raw;
    (void)raw_len;

    if (req->body && req->body_len > 0) {
        parse_sdp(conn, (const char *)req->body, req->body_len);
    }

    rtsp_send_ok(socket, conn, req->cseq);
}


static void handle_setup(int socket, rtsp_conn_t *conn,
                         const rtsp_request_t *req,
                         const uint8_t *raw, size_t raw_len) {
    (void)raw;
    (void)raw_len;

    const uint8_t *body = req->body;
    size_t body_len = req->body_len;

    bool is_bplist = strstr(req->content_type, "application/x-apple-binary-plist") != NULL;

    // Check for streams array
    bool request_has_streams = false;
    size_t stream_count = 0;
    if (body && body_len >= 8 && memcmp(body, "bplist00", 8) == 0) {
        if (bplist_get_streams_count(body, body_len, &stream_count)) {
            request_has_streams = true;
        }
    }

    ESP_LOGI(TAG, "SETUP: has_streams=%d, stream_count=%zu", request_has_streams, stream_count);

    if (body && body_len > 0 && is_bplist && request_has_streams) {
        for (size_t i = 0; i < stream_count; i++) {
            int64_t stream_type = -1;
            size_t ekey_len = 0, eiv_len = 0, shk_len = 0;
            if (bplist_get_stream_info(body, body_len, i, &stream_type,
                                       &ekey_len, &eiv_len, &shk_len)) {
                if (i == 0) {
                    conn->stream_type = stream_type;
                    audio_receiver_set_stream_type((audio_stream_type_t)stream_type);
                }

                bplist_kv_info_t kv[16];
                size_t kv_count = 0;
                int64_t codec_type = -1;
                int64_t sample_rate = 44100;
                int64_t samples_per_frame = 352;

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

                    // Use codec registry to configure audio format
                    audio_format_t format = {0};
                    rtsp_codec_configure(codec_type, &format, sample_rate, samples_per_frame);
                    audio_receiver_set_format(&format);
                }
            }
        }
    }

    // Process encryption keys
    if (body && body_len > 0) {
        uint8_t ekey_encrypted[64];
        size_t ekey_len = 0;
        uint8_t eiv[16];
        size_t eiv_len = 0;
        uint8_t shk[32];
        size_t shk_len = 0;

        int64_t crypto_stream_type = conn->stream_type > 0 ? conn->stream_type : 96;
        bool has_stream_crypto = bplist_find_stream_crypto(
            body, body_len, crypto_stream_type, ekey_encrypted,
            sizeof(ekey_encrypted), &ekey_len, eiv, sizeof(eiv), &eiv_len, shk,
            sizeof(shk), &shk_len);

        if (!has_stream_crypto || (ekey_len == 0 && shk_len == 0)) {
            bplist_find_data_deep(body, body_len, "ekey", ekey_encrypted,
                                  sizeof(ekey_encrypted), &ekey_len);
            bplist_find_data_deep(body, body_len, "eiv", eiv, sizeof(eiv), &eiv_len);
            bplist_find_data_deep(body, body_len, "shk", shk, sizeof(shk), &shk_len);
        }

        audio_encrypt_t audio_encrypt = {0};
        bool encryption_set = false;

        if (shk_len >= 16) {
            audio_encrypt.type = AUDIO_ENCRYPT_CHACHA20_POLY1305;
            memcpy(audio_encrypt.key, shk, shk_len > 32 ? 32 : shk_len);
            audio_encrypt.key_len = shk_len > 32 ? 32 : shk_len;
            if (eiv_len >= 16) {
                memcpy(audio_encrypt.iv, eiv, 16);
            }
            audio_receiver_set_encryption(&audio_encrypt);
            encryption_set = true;
        } else if (ekey_len > 16 && conn->hap_session &&
                   conn->hap_session->session_established) {
            uint8_t nonce[12] = {0};
            uint8_t decrypted_key[32];
            unsigned long long decrypted_len;

            if (crypto_aead_chacha20poly1305_ietf_decrypt(
                    decrypted_key, &decrypted_len, NULL, ekey_encrypted, ekey_len,
                    NULL, 0, nonce, conn->hap_session->shared_secret) == 0 &&
                decrypted_len >= 16) {
                audio_encrypt.type = AUDIO_ENCRYPT_CHACHA20_POLY1305;
                memcpy(audio_encrypt.key, decrypted_key,
                       decrypted_len > 32 ? 32 : decrypted_len);
                audio_encrypt.key_len = decrypted_len > 32 ? 32 : decrypted_len;
                if (eiv_len >= 16) {
                    memcpy(audio_encrypt.iv, eiv, 16);
                }
                audio_receiver_set_encryption(&audio_encrypt);
                encryption_set = true;
            }
        }

        if (!encryption_set && conn->hap_session &&
            conn->hap_session->session_established) {
            audio_encrypt.type = AUDIO_ENCRYPT_CHACHA20_POLY1305;
            if (hap_derive_audio_key(conn->hap_session, audio_encrypt.key,
                                     sizeof(audio_encrypt.key)) == ESP_OK) {
                audio_encrypt.key_len = 32;
                if (eiv_len >= 16) {
                    memcpy(audio_encrypt.iv, eiv, 16);
                }
                audio_receiver_set_encryption(&audio_encrypt);
            }
        }
    }

    // Create event port if needed
    if (conn->event_port == 0) {
        conn->event_socket = rtsp_create_event_socket(&conn->event_port);
        if (conn->event_socket >= 0) {
            rtsp_start_event_port_task(conn->event_socket);
            ESP_LOGI(TAG, "SETUP: Created event port %u", conn->event_port);
        }
    }

    // Handle initial SETUP vs stream SETUP
    if (!request_has_streams) {
        ESP_LOGI(TAG, "SETUP: Initial connection setup (no streams)");

        if (is_bplist) {
            uint8_t plist_body[128];
            size_t plist_len = bplist_build_initial_setup(plist_body,
                                                          sizeof(plist_body),
                                                          conn->event_port);
            if (plist_len == 0) {
                rtsp_send_response(socket, conn, 500, "Internal Error",
                                   req->cseq, NULL, NULL, 0);
                return;
            }
            rtsp_send_response(socket, conn, 200, "OK", req->cseq,
                               "Content-Type: application/x-apple-binary-plist\r\n",
                               (const char *)plist_body, plist_len);
        } else {
            rtsp_send_ok(socket, conn, req->cseq);
        }
        return;
    }

    // Stream SETUP
    int64_t stream_type = conn->stream_type;
    if (stream_type == 0) {
        stream_type = 96;
    }

    ESP_LOGI(TAG, "SETUP: Stream setup, stream_type=%lld", (long long)stream_type);

    if (stream_type == 103) {
        esp_err_t err = audio_receiver_start_buffered(0);
        if (err != ESP_OK) {
            rtsp_send_response(socket, conn, 500, "Internal Error",
                               req->cseq, NULL, NULL, 0);
            return;
        }
        conn->buffered_port = audio_receiver_get_buffered_port();

        int temp_socket;
        if (conn->control_port == 0) {
            temp_socket = rtsp_create_udp_socket(&conn->control_port);
            if (temp_socket > 0)
                close(temp_socket);
        }
        if (conn->timing_port == 0) {
            temp_socket = rtsp_create_udp_socket(&conn->timing_port);
            if (temp_socket > 0)
                close(temp_socket);
        }
    } else {
        int temp_socket;
        if (conn->data_port == 0) {
            temp_socket = rtsp_create_udp_socket(&conn->data_port);
            if (temp_socket > 0)
                close(temp_socket);
        }
        if (conn->control_port == 0) {
            temp_socket = rtsp_create_udp_socket(&conn->control_port);
            if (temp_socket > 0)
                close(temp_socket);
        }
        if (conn->timing_port == 0) {
            temp_socket = rtsp_create_udp_socket(&conn->timing_port);
            if (temp_socket > 0)
                close(temp_socket);
        }
    }

    uint16_t response_data_port = (stream_type == 103)
                                      ? conn->buffered_port
                                      : conn->data_port;

    if (is_bplist) {
        uint8_t plist_body[256];
        size_t plist_len = bplist_build_stream_setup(plist_body, sizeof(plist_body),
                                                     stream_type, response_data_port,
                                                     conn->control_port,
                                                     AP2_AUDIO_BUFFER_SIZE);
        if (plist_len == 0) {
            rtsp_send_response(socket, conn, 500, "Internal Error",
                               req->cseq, NULL, NULL, 0);
            return;
        }
        ESP_LOGI(TAG, "SETUP response: type=%lld dataPort=%u controlPort=%u",
                 (long long)stream_type, response_data_port, conn->control_port);
        rtsp_send_response(socket, conn, 200, "OK", req->cseq,
                           "Content-Type: application/x-apple-binary-plist\r\n",
                           (const char *)plist_body, plist_len);
    } else {
        char transport_response[256];
        snprintf(transport_response, sizeof(transport_response),
                 "Transport: RTP/AVP/UDP;unicast;mode=record;"
                 "server_port=%d;control_port=%d;timing_port=%d\r\n"
                 "Session: 1\r\n",
                 conn->data_port, conn->control_port, conn->timing_port);
        rtsp_send_response(socket, conn, 200, "OK", req->cseq,
                           transport_response, NULL, 0);
    }

    // Start audio receiver
    audio_receiver_set_stream_type((audio_stream_type_t)stream_type);

    if (stream_type == 103) {
        audio_receiver_start_buffered(conn->buffered_port);
    } else if (conn->data_port > 0) {
        audio_receiver_start(conn->data_port, conn->control_port);
    }

    audio_receiver_set_playing(true);
    conn->stream_paused = false;
    conn->stream_active = true;
}

static void handle_record(int socket, rtsp_conn_t *conn,
                          const rtsp_request_t *req,
                          const uint8_t *raw, size_t raw_len) {
    (void)raw;
    (void)raw_len;

    if (conn->stream_type == 103) {
        // Buffered audio already started
    } else if (conn->data_port > 0) {
        audio_receiver_start(conn->data_port, conn->control_port);
    }
    audio_receiver_set_playing(true);

    char headers[128];
    uint32_t output_latency_us = audio_receiver_get_output_latency_us();
    int sample_rate = conn->sample_rate > 0 ? conn->sample_rate : 44100;
    uint32_t latency_samples =
        (uint32_t)(((uint64_t)output_latency_us * (uint64_t)sample_rate) / 1000000ULL);
    snprintf(headers, sizeof(headers),
             "Audio-Latency: %" PRIu32 "\r\n"
             "Audio-Jack-Status: connected\r\n",
             latency_samples);

    rtsp_send_response(socket, conn, 200, "OK", req->cseq, headers, NULL, 0);
}

static void handle_set_parameter(int socket, rtsp_conn_t *conn,
                                 const rtsp_request_t *req,
                                 const uint8_t *raw, size_t raw_len) {
    (void)raw;
    (void)raw_len;

    const uint8_t *body = req->body;
    size_t body_len = req->body_len;

    if (strstr(req->content_type, "text/parameters")) {
        if (body) {
            if (strstr((const char *)body, "volume:")) {
                const char *vol = strstr((const char *)body, "volume:");
                if (vol) {
                    float volume = atof(vol + 7);
                    rtsp_conn_set_volume(conn, volume);
                }
            }
        }
    } else if (strstr(req->content_type, "application/x-apple-binary-plist")) {
        if (body && body_len >= 8 && memcmp(body, "bplist00", 8) == 0) {
            int64_t value;
            if (bplist_find_int(body, body_len, "networkTimeSecs", &value)) {
                ESP_LOGI(TAG, "SET_PARAMETER has networkTimeSecs=%lld",
                         (long long)value);
            }
            double rate;
            if (bplist_find_real(body, body_len, "rate", &rate)) {
                ESP_LOGI(TAG, "SET_PARAMETER has rate=%.2f", rate);
            }
        }
    }

    rtsp_send_ok(socket, conn, req->cseq);
}

static void handle_get_parameter(int socket, rtsp_conn_t *conn,
                                 const rtsp_request_t *req,
                                 const uint8_t *raw, size_t raw_len) {
    (void)raw;
    (void)raw_len;

    if (req->body && req->body_len > 0) {
        if (strstr((const char *)req->body, "volume")) {
            char vol_response[32];
            int vol_len = snprintf(vol_response, sizeof(vol_response),
                                   "volume: %.2f\r\n", conn->volume_db);
            rtsp_send_response(socket, conn, 200, "OK", req->cseq,
                               "Content-Type: text/parameters\r\n",
                               vol_response, vol_len);
            return;
        }
    }

    rtsp_send_ok(socket, conn, req->cseq);
}

static void handle_pause(int socket, rtsp_conn_t *conn,
                         const rtsp_request_t *req,
                         const uint8_t *raw, size_t raw_len) {
    (void)raw;
    (void)raw_len;

    audio_receiver_flush();
    rtsp_send_ok(socket, conn, req->cseq);
}

static void handle_flush(int socket, rtsp_conn_t *conn,
                         const rtsp_request_t *req,
                         const uint8_t *raw, size_t raw_len) {
    (void)raw;
    (void)raw_len;

    audio_receiver_flush();
    rtsp_send_ok(socket, conn, req->cseq);
}

static void handle_teardown(int socket, rtsp_conn_t *conn,
                            const rtsp_request_t *req,
                            const uint8_t *raw, size_t raw_len) {
    (void)raw;
    (void)raw_len;

    const uint8_t *body = req->body;
    size_t body_len = req->body_len;
    bool has_streams = false;

    if (body && body_len >= 8 && memcmp(body, "bplist00", 8) == 0) {
        size_t stream_count = 0;
        if (bplist_get_streams_count(body, body_len, &stream_count)) {
            has_streams = true;
            ESP_LOGI(TAG, "TEARDOWN with streams array (count=%zu)", stream_count);
        }
    }

    if (has_streams) {
        ESP_LOGI(TAG, "TEARDOWN: closing stream only (pause)");
        audio_receiver_stop();
        conn->stream_active = false;
        conn->stream_paused = true;
    } else {
        ESP_LOGI(TAG, "TEARDOWN: stopping audio");
        audio_receiver_stop();
        conn->stream_active = false;
        conn->stream_paused = false;
    }

    rtsp_send_ok(socket, conn, req->cseq);
}

static void handle_setrateanchortime(int socket, rtsp_conn_t *conn,
                                      const rtsp_request_t *req,
                                      const uint8_t *raw, size_t raw_len) {
    (void)raw;
    (void)raw_len;

    const uint8_t *body = req->body;
    size_t body_len = req->body_len;

    double rate = 1.0;
    uint64_t clock_id = 0;
    uint64_t network_time_secs = 0;
    uint64_t network_time_frac = 0;
    uint64_t rtp_time = 0;

    if (body && body_len > 0 && body_len >= 8 && memcmp(body, "bplist00", 8) == 0) {
        if (!bplist_find_real(body, body_len, "rate", &rate)) {
            int64_t rate_int;
            if (bplist_find_int(body, body_len, "rate", &rate_int)) {
                rate = (double)rate_int;
            }
        }

        int64_t value;
        if (bplist_find_int(body, body_len, "networkTimeTimelineID", &value)) {
            clock_id = (uint64_t)value;
        }
        if (bplist_find_int(body, body_len, "networkTimeSecs", &value)) {
            network_time_secs = (uint64_t)value;
        }
        if (bplist_find_int(body, body_len, "networkTimeFrac", &value)) {
            network_time_frac = (uint64_t)value;
        }
        if (bplist_find_int(body, body_len, "rtpTime", &value)) {
            rtp_time = (uint64_t)value;
        }

        ESP_LOGI(TAG, "SETRATEANCHORTIME: secs=%llu, rtp=%llu, rate=%.1f",
                 (unsigned long long)network_time_secs,
                 (unsigned long long)rtp_time, rate);

        if (network_time_secs != 0 && rtp_time != 0) {
            uint64_t frac = network_time_frac >> 32;
            frac = (frac * 1000000000ULL) >> 32;
            uint64_t network_time_ns = network_time_secs * 1000000000ULL + frac;
            audio_receiver_set_anchor_time(clock_id, network_time_ns, (uint32_t)rtp_time);
        }
    }

    if (rate == 0.0) {
        conn->stream_paused = true;
        audio_receiver_set_playing(false);
        audio_receiver_flush();
    } else {
        conn->stream_paused = false;
        audio_receiver_set_playing(true);
    }

    rtsp_send_ok(socket, conn, req->cseq);
}

static void handle_setpeers(int socket, rtsp_conn_t *conn,
                            const rtsp_request_t *req,
                            const uint8_t *raw, size_t raw_len) {
    (void)raw;
    (void)raw_len;

    const uint8_t *body = req->body;
    size_t body_len = req->body_len;

    ESP_LOGI(TAG, "%s: body_len=%zu", req->method, body_len);
    if (body && body_len >= 8 && memcmp(body, "bplist00", 8) == 0) {
        ESP_LOGI(TAG, "SETPEERS: got bplist");
    }

    rtsp_send_ok(socket, conn, req->cseq);
}

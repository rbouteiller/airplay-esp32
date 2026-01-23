#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/ringbuf.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "sodium.h"
#include "mbedtls/aes.h"

#include "audio_receiver.h"
#include "apple_alac.h"

static const char *TAG = "audio_recv";

// Buffered audio constants
#define BUFFERED_AUDIO_BUFFER_SIZE (128 * 1024)  // 128KB for buffered audio (in PSRAM)
#define BUFFERED_AUDIO_PACKET_SIZE 8192          // Max buffered audio packet size

// RTP header structure
typedef struct __attribute__((packed)) {
    uint8_t flags;          // Version, padding, extension, CSRC count
    uint8_t type;           // Marker, payload type
    uint16_t seq;           // Sequence number
    uint32_t timestamp;     // RTP timestamp
    uint32_t ssrc;          // Synchronization source
} rtp_header_t;

#define RTP_HEADER_SIZE 12
#define MAX_RTP_PACKET_SIZE 2048
#define AUDIO_BUFFER_SIZE (64 * 1024)  // 64KB ring buffer for PCM
#define MAX_SAMPLES_PER_FRAME 4096
#if CONFIG_FREERTOS_UNICORE
#define AUDIO_TASK_CORE 0
#else
#define AUDIO_TASK_CORE 1
#endif

// Receiver state
static struct {
    bool running;
    int data_socket;
    int control_socket;
    TaskHandle_t task_handle;
    RingbufHandle_t pcm_buffer;
    audio_format_t format;
    audio_encrypt_t encrypt;
    audio_stats_t stats;
    bool alac_ready;
    int16_t *decode_buffer;
    uint8_t *decrypt_buffer;

    // Buffered audio (type=103) state
    audio_stream_type_t stream_type;
    int buffered_listen_socket;     // TCP listening socket
    int buffered_client_socket;     // Connected client socket
    uint16_t buffered_port;         // TCP port for buffered audio
    TaskHandle_t buffered_task_handle;
    uint8_t *buffered_recv_buffer;  // Large buffer in PSRAM
    bool buffered_running;
} receiver = {0};

// Decrypt RTP payload if encryption is enabled
// Returns decrypted length, or -1 on error
// full_packet is the entire RTP packet (for extracting nonce from last 8 bytes)
static int decrypt_payload(const uint8_t *input, size_t input_len,
                           uint8_t *output, size_t output_capacity,
                           uint16_t seq, uint32_t timestamp,
                           const uint8_t *full_packet, size_t full_packet_len)
{
    if (receiver.encrypt.type == AUDIO_ENCRYPT_NONE) {
        // No encryption - just copy
        if (input_len > output_capacity) {
            return -1;
        }
        memcpy(output, input, input_len);
        return input_len;
    }

    if (receiver.encrypt.type == AUDIO_ENCRYPT_AES_CBC) {
        // AES-128-CBC decryption using ESP32 hardware acceleration via mbedtls
        // For AirPlay RAOP, encrypted data is in multiples of 16 bytes,
        // with any remainder left unencrypted

        if (input_len > output_capacity) {
            return -1;
        }

        // Use the stored IV (AirPlay uses same IV for all packets in a session)
        uint8_t iv[16];
        memcpy(iv, receiver.encrypt.iv, 16);

        size_t num_blocks = input_len / 16;
        size_t remainder = input_len % 16;
        size_t encrypted_len = num_blocks * 16;

        if (encrypted_len > 0) {
            // Initialize AES context
            mbedtls_aes_context aes;
            mbedtls_aes_init(&aes);

            // Set decryption key (128-bit = 16 bytes)
            int ret = mbedtls_aes_setkey_dec(&aes, receiver.encrypt.key, 128);
            if (ret != 0) {
                mbedtls_aes_free(&aes);
                return -1;
            }

            // Decrypt in CBC mode
            ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, encrypted_len,
                                        iv, input, output);
            mbedtls_aes_free(&aes);

            if (ret != 0) {
                return -1;
            }
        }

        // Copy remainder (unencrypted trailing bytes < 16 per RAOP spec)
        if (remainder > 0) {
            memcpy(output + encrypted_len, input + encrypted_len, remainder);
        }

        return input_len;
    }

    if (receiver.encrypt.type == AUDIO_ENCRYPT_CHACHA20_POLY1305) {
        // ChaCha20-Poly1305 AEAD decryption for AirPlay 2
        // Per shairport-sync decipher_player_put_packet():
        // - Nonce: 4 zero bytes + last 8 bytes of packet
        // - AAD: bytes 4-11 of full packet (timestamp + SSRC)
        // - Ciphertext: payload (excluding last 8 bytes which are nonce)

        if (input_len < crypto_aead_chacha20poly1305_ietf_ABYTES + 8) {
            return -1;
        }

        // Build 12-byte nonce: 4 zeros + last 8 bytes of full packet
        uint8_t nonce[12] = {0};
        if (full_packet && full_packet_len >= 8) {
            memcpy(nonce + 4, full_packet + full_packet_len - 8, 8);
        }

        // AAD is RTP timestamp + SSRC (bytes 4-11 of the full packet)
        const uint8_t *aad = NULL;
        size_t aad_len = 0;
        if (full_packet && full_packet_len >= 12) {
            aad = full_packet + 4;
            aad_len = 8;
        }

        // Ciphertext excludes the last 8 bytes (which are nonce)
        size_t ciphertext_len = input_len - 8;

        unsigned long long decrypted_len;
        int ret = crypto_aead_chacha20poly1305_ietf_decrypt(
            output, &decrypted_len,
            NULL,  // No secret nonce
            input, ciphertext_len,
            aad, aad_len,
            nonce,
            receiver.encrypt.key
        );

        if (ret == 0) {
            return (int)decrypted_len;
        }

        // Fallback: try without AAD
        ret = crypto_aead_chacha20poly1305_ietf_decrypt(
            output, &decrypted_len,
            NULL,
            input, ciphertext_len,
            NULL, 0,
            nonce,
            receiver.encrypt.key
        );

        if (ret == 0) {
            return (int)decrypted_len;
        }

        // Fallback: try with full input (nonce not at end)
        memset(nonce, 0, sizeof(nonce));
        if (full_packet && full_packet_len >= 8) {
            memcpy(nonce + 4, full_packet + full_packet_len - 8, 8);
        }

        ret = crypto_aead_chacha20poly1305_ietf_decrypt(
            output, &decrypted_len,
            NULL,
            input, input_len,
            aad, aad_len,
            nonce,
            receiver.encrypt.key
        );

        if (ret == 0) {
            return (int)decrypted_len;
        }

        // Last fallback: sequence-based nonce
        memset(nonce, 0, sizeof(nonce));
        nonce[10] = (seq >> 8) & 0xFF;
        nonce[11] = seq & 0xFF;

        ret = crypto_aead_chacha20poly1305_ietf_decrypt(
            output, &decrypted_len,
            NULL,
            input, input_len,
            NULL, 0,
            nonce,
            receiver.encrypt.key
        );

        if (ret != 0) {
            return -1;
        }

        return (int)decrypted_len;
    }

    return -1;
}

// Decrypt buffered audio packet (type=103)
// Buffered audio format (per shairport-sync):
// - Bytes 0: flags
// - Bytes 1-3: 24-bit sequence number
// - Bytes 4-7: timestamp
// - Bytes 8-11: SSRC
// - Bytes 12 to (len-8): ciphertext + Poly1305 tag
// - Last 8 bytes: nonce
static int decrypt_buffered_payload(const uint8_t *packet, size_t packet_len,
                                     uint8_t *output, size_t output_capacity)
{
    if (receiver.encrypt.type != AUDIO_ENCRYPT_CHACHA20_POLY1305) {
        // No encryption - copy payload directly (skip 12-byte header)
        if (packet_len <= 12) return -1;
        size_t payload_len = packet_len - 12;
        if (payload_len > output_capacity) return -1;
        memcpy(output, packet + 12, payload_len);
        return payload_len;
    }

    // ChaCha20-Poly1305 decryption for buffered audio
    // Need at least: 12-byte header + 16-byte tag + 8-byte nonce = 36 bytes minimum
    if (packet_len < 36) {
        return -1;
    }

    // Build 12-byte nonce: 4 zeros + last 8 bytes of packet
    uint8_t nonce[12] = {0};
    memcpy(nonce + 4, packet + packet_len - 8, 8);

    // AAD is bytes 4-11 (timestamp + SSRC)
    const uint8_t *aad = packet + 4;
    size_t aad_len = 8;

    // Ciphertext is bytes 12 to (len - 8)
    const uint8_t *ciphertext = packet + 12;
    size_t ciphertext_len = packet_len - 12 - 8;  // Minus header and nonce

    if (ciphertext_len > output_capacity + crypto_aead_chacha20poly1305_ietf_ABYTES) {
        return -1;
    }

    unsigned long long decrypted_len;
    int ret = crypto_aead_chacha20poly1305_ietf_decrypt(
        output, &decrypted_len,
        NULL,
        ciphertext, ciphertext_len,
        aad, aad_len,
        nonce,
        receiver.encrypt.key
    );

    if (ret != 0) {
        return -1;
    }

    return (int)decrypted_len;
}

// Read exactly 'len' bytes from socket with timeout
static ssize_t read_exact(int sock, uint8_t *buf, size_t len)
{
    size_t total = 0;
    while (total < len && receiver.buffered_running) {
        ssize_t n = recv(sock, buf + total, len - total, 0);
        if (n <= 0) {
            if (n == 0) {
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ESP_LOGE(TAG, "Buffered audio recv error: %d", errno);
            }
            return -1;
        }
        total += n;
    }
    return total;
}

// Buffered audio receiver task (type=103 over TCP)
static void buffered_audio_task(void *pvParameters)
{
    while (receiver.buffered_running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        // Accept connection
        int client_sock = accept(receiver.buffered_listen_socket,
                                  (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && receiver.buffered_running) {
                ESP_LOGE(TAG, "Buffered audio accept error: %d", errno);
            }
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        receiver.buffered_client_socket = client_sock;

        // Set receive timeout
        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
        setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // Allocate packet buffer in PSRAM if available
        uint8_t *packet = receiver.buffered_recv_buffer;
        if (!packet) {
            packet = heap_caps_malloc(BUFFERED_AUDIO_PACKET_SIZE, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
            if (!packet) {
                packet = malloc(BUFFERED_AUDIO_PACKET_SIZE);
            }
            if (!packet) {
                ESP_LOGE(TAG, "Failed to allocate buffered audio packet buffer");
                close(client_sock);
                receiver.buffered_client_socket = -1;
                continue;
            }
            receiver.buffered_recv_buffer = packet;
        }

        // Receive loop - each packet has 2-byte length prefix
        while (receiver.buffered_running) {
            // Read 2-byte length
            uint8_t len_buf[2];
            if (read_exact(client_sock, len_buf, 2) != 2) {
                break;
            }

            uint16_t data_len = (len_buf[0] << 8) | len_buf[1];
            if (data_len < 2 || data_len > BUFFERED_AUDIO_PACKET_SIZE) {
                ESP_LOGW(TAG, "Invalid buffered audio packet length: %d", data_len);
                break;
            }

            // Read packet data (length includes the 2 length bytes, so subtract 2)
            size_t packet_len = data_len - 2;
            if (read_exact(client_sock, packet, packet_len) != (ssize_t)packet_len) {
                break;
            }

            receiver.stats.packets_received++;

            // Parse sequence number (bytes 1-3, 24-bit)
            uint32_t seq_no = (packet[1] << 16) | (packet[2] << 8) | packet[3];

            // Parse timestamp (bytes 4-7)
            uint32_t timestamp = (packet[4] << 24) | (packet[5] << 16) |
                                 (packet[6] << 8) | packet[7];

            // Decrypt
            uint8_t *decrypted = receiver.decrypt_buffer;
            if (!decrypted) {
                decrypted = packet + 12;  // Fallback: use payload area
            }

            int decrypted_len = decrypt_buffered_payload(packet, packet_len,
                                                          decrypted, MAX_RTP_PACKET_SIZE);
            if (decrypted_len < 0) {
                receiver.stats.decrypt_errors++;
                receiver.stats.packets_dropped++;
                continue;
            }

            receiver.stats.packets_decoded++;
            receiver.stats.last_seq = seq_no & 0xFFFF;
            receiver.stats.last_timestamp = timestamp;
        }
        close(client_sock);
        receiver.buffered_client_socket = -1;
    }
    vTaskDelete(NULL);
}

// Parse RTP packet and return pointer to payload
static const uint8_t *parse_rtp(const uint8_t *packet, size_t len,
                                 uint16_t *seq, uint32_t *timestamp, size_t *payload_len)
{
    if (len < RTP_HEADER_SIZE) {
        return NULL;
    }

    const rtp_header_t *hdr = (const rtp_header_t *)packet;

    // Check RTP version (should be 2)
    uint8_t version = (hdr->flags >> 6) & 0x03;
    if (version != 2) {
        ESP_LOGW(TAG, "Invalid RTP version: %d", version);
        return NULL;
    }

    *seq = ntohs(hdr->seq);
    *timestamp = ntohl(hdr->timestamp);

    // Check for extension header
    size_t header_len = RTP_HEADER_SIZE;
    if (hdr->flags & 0x10) {
        // Extension present
        if (len < RTP_HEADER_SIZE + 4) {
            return NULL;
        }
        uint16_t ext_len = ntohs(*(uint16_t *)(packet + RTP_HEADER_SIZE + 2));
        header_len += 4 + ext_len * 4;
    }

    // CSRC count
    uint8_t csrc_count = hdr->flags & 0x0F;
    header_len += csrc_count * 4;

    if (len <= header_len) {
        return NULL;
    }

    *payload_len = len - header_len;
    return packet + header_len;
}

// Receiver task
static void receiver_task(void *pvParameters)
{
    uint8_t *packet = malloc(MAX_RTP_PACKET_SIZE);
    if (!packet) {
        ESP_LOGE(TAG, "Failed to allocate packet buffer");
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    while (receiver.running) {
        int len = recvfrom(receiver.data_socket, packet, MAX_RTP_PACKET_SIZE, 0,
                           (struct sockaddr *)&src_addr, &addr_len);

        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            // Don't log error during normal shutdown (socket closed)
            if (receiver.running) {
                ESP_LOGE(TAG, "recvfrom error: %d", errno);
            }
            break;
        }

        if (len == 0) {
            continue;
        }

        receiver.stats.packets_received++;

        uint16_t seq;
        uint32_t timestamp;
        size_t payload_len;
        const uint8_t *payload = parse_rtp(packet, len, &seq, &timestamp, &payload_len);

        if (!payload || payload_len == 0) {
            receiver.stats.packets_dropped++;
            continue;
        }

        // Check for sequence discontinuity
        if (receiver.stats.packets_decoded > 0) {
            uint16_t expected_seq = (receiver.stats.last_seq + 1) & 0xFFFF;
            if (seq != expected_seq) {
                int gap = (int)seq - (int)expected_seq;
                if (gap < 0) gap += 65536;
                if (gap > 0 && gap < 100) {
                    receiver.stats.packets_dropped += gap;
                }
            }
        }

        receiver.stats.last_seq = seq;
        receiver.stats.last_timestamp = timestamp;

        // Decrypt payload if encryption is enabled
        const uint8_t *audio_data = payload;
        size_t audio_len = payload_len;

        if (receiver.encrypt.type != AUDIO_ENCRYPT_NONE && receiver.decrypt_buffer) {
            int decrypted_len = decrypt_payload(payload, payload_len,
                                                receiver.decrypt_buffer, MAX_RTP_PACKET_SIZE,
                                                seq, timestamp,
                                                packet, len);  // Pass full packet for nonce extraction
            if (decrypted_len < 0) {
                receiver.stats.decrypt_errors++;
                receiver.stats.packets_dropped++;
                continue;
            }
            audio_data = receiver.decrypt_buffer;
            audio_len = decrypted_len;
        }

        // Decode audio based on codec
        size_t decoded_samples = 0;

        if (strcmp(receiver.format.codec, "AppleLossless") == 0 ||
            strcmp(receiver.format.codec, "ALAC") == 0) {
            // ALAC decode
            if (receiver.alac_ready && receiver.decode_buffer) {
                int out_samples = 0;
                int ret = apple_alac_decode_frame((unsigned char *)audio_data, audio_len,
                                                  (unsigned char *)receiver.decode_buffer,
                                                  &out_samples);
                if (ret == 0 && out_samples > 0) {
                    if (out_samples > (int)MAX_SAMPLES_PER_FRAME) {
                        out_samples = MAX_SAMPLES_PER_FRAME;
                    }
                    decoded_samples = (size_t)out_samples;
                } else {
                    receiver.stats.packets_dropped++;
                    continue;
                }
            } else {
                // Log if decoder not initialized
                static bool logged_missing = false;
                if (!logged_missing) {
                    ESP_LOGE(TAG, "ALAC decoder not initialized: ready=%d decode_buf=%p",
                             receiver.alac_ready, receiver.decode_buffer);
                    logged_missing = true;
                }
            }
        } else if (strcmp(receiver.format.codec, "L16") == 0 ||
                   strcmp(receiver.format.codec, "PCM") == 0) {
            // Raw PCM - just copy (may need byte swap for big-endian)
            decoded_samples = audio_len / (receiver.format.channels * 2);
            if (decoded_samples > MAX_SAMPLES_PER_FRAME) {
                decoded_samples = MAX_SAMPLES_PER_FRAME;
            }

            // Convert from network byte order (big-endian) to native
            const int16_t *src = (const int16_t *)audio_data;
            for (size_t i = 0; i < decoded_samples * receiver.format.channels; i++) {
                receiver.decode_buffer[i] = ntohs(src[i]);
            }
        } else {
            // Unknown codec - log first occurrence
            static bool logged = false;
            if (!logged) {
                ESP_LOGW(TAG, "Unsupported codec: %s", receiver.format.codec);
                logged = true;
            }
            receiver.stats.packets_dropped++;
            continue;
        }

        // Write decoded samples to ring buffer
        if (decoded_samples > 0) {
            size_t bytes = decoded_samples * receiver.format.channels * sizeof(int16_t);
            BaseType_t ret = xRingbufferSend(receiver.pcm_buffer, receiver.decode_buffer,
                                             bytes, pdMS_TO_TICKS(10));
            if (ret != pdTRUE) {
                // Buffer full - drop oldest data
                receiver.stats.buffer_underruns++;
                static int overrun_log = 0;
                if (overrun_log < 5) {
                    ESP_LOGW(TAG, "Ring buffer full, dropping audio");
                    overrun_log++;
                }
            } else {
                receiver.stats.packets_decoded++;
            }
        }
    }

    free(packet);
    vTaskDelete(NULL);
}

esp_err_t audio_receiver_init(void)
{
    if (receiver.pcm_buffer) {
        return ESP_OK;  // Already initialized
    }

    // Create ring buffer for PCM samples
    receiver.pcm_buffer = xRingbufferCreate(AUDIO_BUFFER_SIZE, RINGBUF_TYPE_BYTEBUF);
    if (!receiver.pcm_buffer) {
        ESP_LOGE(TAG, "Failed to create ring buffer");
        return ESP_ERR_NO_MEM;
    }

    // Allocate decrypt buffer
    receiver.decrypt_buffer = malloc(MAX_RTP_PACKET_SIZE);
    if (!receiver.decrypt_buffer) {
        ESP_LOGE(TAG, "Failed to allocate decrypt buffer");
        vRingbufferDelete(receiver.pcm_buffer);
        receiver.pcm_buffer = NULL;
        return ESP_ERR_NO_MEM;
    }

    // Allocate decode buffer
    receiver.decode_buffer = malloc(MAX_SAMPLES_PER_FRAME * 2 * sizeof(int16_t));
    if (!receiver.decode_buffer) {
        ESP_LOGE(TAG, "Failed to allocate decode buffer");
        vRingbufferDelete(receiver.pcm_buffer);
        receiver.pcm_buffer = NULL;
        return ESP_ERR_NO_MEM;
    }

    // Set default format
    receiver.format.sample_rate = 44100;
    receiver.format.channels = 2;
    receiver.format.bits_per_sample = 16;
    receiver.format.frame_size = 352;
    strcpy(receiver.format.codec, "AppleLossless");

    return ESP_OK;
}

void audio_receiver_set_format(const audio_format_t *format)
{
    memcpy(&receiver.format, format, sizeof(audio_format_t));

    if (strcmp(format->codec, "AppleLossless") == 0 ||
        strcmp(format->codec, "ALAC") == 0) {
        int32_t fmtp[12] = {0};
        fmtp[0] = 96;
        fmtp[1] = format->max_samples_per_frame ? (int32_t)format->max_samples_per_frame :
                  (format->frame_size > 0 ? format->frame_size : 352);
        fmtp[2] = 0;
        fmtp[3] = format->sample_size ? format->sample_size :
                  (format->bits_per_sample ? format->bits_per_sample : 16);
        fmtp[4] = format->rice_history_mult ? format->rice_history_mult : 40;
        fmtp[5] = format->rice_initial_history ? format->rice_initial_history : 10;
        fmtp[6] = format->rice_limit ? format->rice_limit : 14;
        fmtp[7] = format->num_channels ? format->num_channels :
                  (format->channels ? format->channels : 2);
        fmtp[8] = format->max_run ? format->max_run : 255;
        fmtp[9] = format->max_coded_frame_size ? (int32_t)format->max_coded_frame_size : 0;
        fmtp[10] = format->avg_bit_rate ? (int32_t)format->avg_bit_rate : 0;
        fmtp[11] = format->sample_rate_config ? (int32_t)format->sample_rate_config :
                   (format->sample_rate ? format->sample_rate : 44100);

        if (receiver.alac_ready) {
            apple_alac_terminate();
            receiver.alac_ready = false;
        }

        int ret = apple_alac_init(fmtp);
        if (ret != 0) {
            ESP_LOGE(TAG, "Failed to init Apple ALAC decoder: %d", ret);
        } else {
            receiver.alac_ready = true;
        }
    } else if (receiver.alac_ready) {
        apple_alac_terminate();
        receiver.alac_ready = false;
    }
}

void audio_receiver_set_encryption(const audio_encrypt_t *encrypt)
{
    if (encrypt) {
        memcpy(&receiver.encrypt, encrypt, sizeof(audio_encrypt_t));
    } else {
        memset(&receiver.encrypt, 0, sizeof(audio_encrypt_t));
    }
}

esp_err_t audio_receiver_start(uint16_t data_port, uint16_t control_port)
{
    if (receiver.running) {
        ESP_LOGW(TAG, "Already running");
        return ESP_ERR_INVALID_STATE;
    }

    // Create data socket
    receiver.data_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (receiver.data_socket < 0) {
        ESP_LOGE(TAG, "Failed to create data socket");
        return ESP_FAIL;
    }

    // Set socket timeout
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(receiver.data_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Increase receive buffer to reduce packet loss
    int rcvbuf = 131072;  // 128KB receive buffer
    setsockopt(receiver.data_socket, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    // Bind to port
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(data_port);

    if (bind(receiver.data_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind data socket to port %d: %d", data_port, errno);
        close(receiver.data_socket);
        receiver.data_socket = 0;
        return ESP_FAIL;
    }

    // Reset stats
    memset(&receiver.stats, 0, sizeof(receiver.stats));

    // Start receiver task
    receiver.running = true;
    BaseType_t ret = xTaskCreatePinnedToCore(receiver_task, "audio_recv", 8192, NULL, 8,
                                             &receiver.task_handle, AUDIO_TASK_CORE);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create receiver task");
        close(receiver.data_socket);
        receiver.data_socket = 0;
        receiver.running = false;
        return ESP_FAIL;
    }

    return ESP_OK;
}

void audio_receiver_stop(void)
{
    // Stop realtime (UDP) receiver
    if (receiver.running) {
        receiver.running = false;

        // Close sockets to unblock recv
        if (receiver.data_socket > 0) {
            close(receiver.data_socket);
            receiver.data_socket = 0;
        }
        if (receiver.control_socket > 0) {
            close(receiver.control_socket);
            receiver.control_socket = 0;
        }

        // Wait for task to exit
        if (receiver.task_handle) {
            vTaskDelay(pdMS_TO_TICKS(200));
            receiver.task_handle = NULL;
        }
    }

    // Stop buffered (TCP) receiver
    if (receiver.buffered_running) {
        receiver.buffered_running = false;

        // Close client socket first
        if (receiver.buffered_client_socket > 0) {
            close(receiver.buffered_client_socket);
            receiver.buffered_client_socket = -1;
        }

        // Close listening socket
        if (receiver.buffered_listen_socket > 0) {
            close(receiver.buffered_listen_socket);
            receiver.buffered_listen_socket = -1;
        }

        // Wait for task to exit
        if (receiver.buffered_task_handle) {
            vTaskDelay(pdMS_TO_TICKS(300));
            receiver.buffered_task_handle = NULL;
        }

        // Free buffered receive buffer
        if (receiver.buffered_recv_buffer) {
            heap_caps_free(receiver.buffered_recv_buffer);
            receiver.buffered_recv_buffer = NULL;
        }

        receiver.buffered_port = 0;
    }

    // Free ALAC decoder
    if (receiver.alac_ready) {
        apple_alac_terminate();
        receiver.alac_ready = false;
    }

    // Clear encryption state
    memset(&receiver.encrypt, 0, sizeof(audio_encrypt_t));

    // Flush buffer
    audio_receiver_flush();
}

void audio_receiver_get_stats(audio_stats_t *stats)
{
    memcpy(stats, &receiver.stats, sizeof(audio_stats_t));
}

size_t audio_receiver_read(int16_t *buffer, size_t samples)
{
    if (!receiver.pcm_buffer || !buffer || samples == 0) {
        return 0;
    }

    size_t bytes_wanted = samples * receiver.format.channels * sizeof(int16_t);
    size_t bytes_read = 0;

    void *data = xRingbufferReceiveUpTo(receiver.pcm_buffer, &bytes_read,
                                         pdMS_TO_TICKS(10), bytes_wanted);
    if (data && bytes_read > 0) {
        memcpy(buffer, data, bytes_read);
        vRingbufferReturnItem(receiver.pcm_buffer, data);
        return bytes_read / (receiver.format.channels * sizeof(int16_t));
    }

    return 0;
}

bool audio_receiver_has_data(void)
{
    if (!receiver.pcm_buffer) {
        return false;
    }

    UBaseType_t free_size = xRingbufferGetCurFreeSize(receiver.pcm_buffer);
    return free_size < AUDIO_BUFFER_SIZE;
}

void audio_receiver_flush(void)
{
    if (!receiver.pcm_buffer) {
        return;
    }

    // Read and discard all data
    size_t bytes_read;
    void *data;
    while ((data = xRingbufferReceiveUpTo(receiver.pcm_buffer, &bytes_read, 0, AUDIO_BUFFER_SIZE)) != NULL) {
        vRingbufferReturnItem(receiver.pcm_buffer, data);
    }
}

void audio_receiver_set_stream_type(audio_stream_type_t type)
{
    receiver.stream_type = type;
}

esp_err_t audio_receiver_start_buffered(uint16_t tcp_port)
{
    if (receiver.buffered_running) {
        ESP_LOGW(TAG, "Buffered audio already running");
        return ESP_ERR_INVALID_STATE;
    }

    // Create TCP listening socket
    receiver.buffered_listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (receiver.buffered_listen_socket < 0) {
        ESP_LOGE(TAG, "Failed to create TCP socket for buffered audio");
        return ESP_FAIL;
    }

    // Allow address reuse
    int opt = 1;
    setsockopt(receiver.buffered_listen_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Set non-blocking for accept
    int flags = fcntl(receiver.buffered_listen_socket, F_GETFL, 0);
    fcntl(receiver.buffered_listen_socket, F_SETFL, flags | O_NONBLOCK);

    // Bind to port
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(tcp_port);

    if (bind(receiver.buffered_listen_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind TCP socket to port %d: %d", tcp_port, errno);
        close(receiver.buffered_listen_socket);
        receiver.buffered_listen_socket = -1;
        return ESP_FAIL;
    }

    // Get actual port if 0 was specified
    if (tcp_port == 0) {
        socklen_t addr_len = sizeof(addr);
        getsockname(receiver.buffered_listen_socket, (struct sockaddr *)&addr, &addr_len);
        tcp_port = ntohs(addr.sin_port);
    }
    receiver.buffered_port = tcp_port;

    // Start listening
    if (listen(receiver.buffered_listen_socket, 1) < 0) {
        ESP_LOGE(TAG, "Failed to listen on TCP socket: %d", errno);
        close(receiver.buffered_listen_socket);
        receiver.buffered_listen_socket = -1;
        return ESP_FAIL;
    }

    // Allocate large receive buffer in PSRAM if available
    if (!receiver.buffered_recv_buffer) {
        receiver.buffered_recv_buffer = heap_caps_malloc(BUFFERED_AUDIO_PACKET_SIZE,
                                                          MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!receiver.buffered_recv_buffer) {
            // Fallback to regular RAM
            receiver.buffered_recv_buffer = malloc(BUFFERED_AUDIO_PACKET_SIZE);
        }
        if (receiver.buffered_recv_buffer) {
        }
    }

    // Reset stats
    memset(&receiver.stats, 0, sizeof(receiver.stats));

    // Start buffered audio task with larger stack (in PSRAM if possible)
    receiver.buffered_running = true;
    BaseType_t ret = xTaskCreate(buffered_audio_task, "buff_audio", 8192, NULL, 5,
                                  &receiver.buffered_task_handle);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create buffered audio task");
        close(receiver.buffered_listen_socket);
        receiver.buffered_listen_socket = -1;
        receiver.buffered_running = false;
        return ESP_FAIL;
    }

    return ESP_OK;
}

uint16_t audio_receiver_get_buffered_port(void)
{
    return receiver.buffered_port;
}

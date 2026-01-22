#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/ringbuf.h"
#include "esp_log.h"
#include "sodium.h"
#include "mbedtls/aes.h"

#include "audio_receiver.h"
#include "alac_decoder.h"

static const char *TAG = "audio_recv";

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
#define AUDIO_BUFFER_SIZE (32 * 1024)  // 32KB ring buffer for PCM
#define MAX_SAMPLES_PER_FRAME 4096

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
    alac_decoder_t *alac;
    int16_t *decode_buffer;
    uint8_t *decrypt_buffer;
} receiver = {0};

// Decrypt RTP payload if encryption is enabled
// Returns decrypted length, or -1 on error
static int decrypt_payload(const uint8_t *input, size_t input_len,
                           uint8_t *output, size_t output_capacity,
                           uint16_t seq, uint32_t timestamp)
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
        // ChaCha20-Poly1305 AEAD decryption
        // The nonce is typically derived from RTP sequence/timestamp

        if (input_len < crypto_aead_chacha20poly1305_ietf_ABYTES) {
            return -1;
        }

        // Build nonce from RTP header info (12 bytes for IETF ChaCha20-Poly1305)
        uint8_t nonce[12] = {0};
        // Common pattern: use sequence number and timestamp
        nonce[0] = (seq >> 8) & 0xFF;
        nonce[1] = seq & 0xFF;
        nonce[4] = (timestamp >> 24) & 0xFF;
        nonce[5] = (timestamp >> 16) & 0xFF;
        nonce[6] = (timestamp >> 8) & 0xFF;
        nonce[7] = timestamp & 0xFF;

        unsigned long long decrypted_len;
        int ret = crypto_aead_chacha20poly1305_ietf_decrypt(
            output, &decrypted_len,
            NULL,  // No secret nonce
            input, input_len,
            NULL, 0,  // No additional data
            nonce,
            receiver.encrypt.key
        );

        if (ret != 0) {
            return -1;  // Decryption failed (auth tag mismatch)
        }

        return (int)decrypted_len;
    }

    return -1;
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

    ESP_LOGI(TAG, "Audio receiver task started");

    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    while (receiver.running) {
        int len = recvfrom(receiver.data_socket, packet, MAX_RTP_PACKET_SIZE, 0,
                           (struct sockaddr *)&src_addr, &addr_len);

        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            ESP_LOGE(TAG, "recvfrom error: %d", errno);
            break;
        }

        if (len == 0) {
            continue;
        }

        receiver.stats.packets_received++;

        // Parse RTP header
        uint16_t seq;
        uint32_t timestamp;
        size_t payload_len;
        const uint8_t *payload = parse_rtp(packet, len, &seq, &timestamp, &payload_len);

        if (!payload || payload_len == 0) {
            ESP_LOGW(TAG, "Invalid RTP packet");
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
                    ESP_LOGW(TAG, "Sequence gap: expected %d, got %d (gap=%d)",
                             expected_seq, seq, gap);
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
                                                seq, timestamp);
            if (decrypted_len < 0) {
                ESP_LOGW(TAG, "Decryption failed for seq %d", seq);
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
            if (receiver.alac && receiver.decode_buffer) {
                int ret = alac_decode_frame(receiver.alac, audio_data, audio_len,
                                            receiver.decode_buffer, MAX_SAMPLES_PER_FRAME);
                if (ret > 0) {
                    decoded_samples = ret;
                } else {
                    ESP_LOGW(TAG, "ALAC decode failed: %d", ret);
                    receiver.stats.packets_dropped++;
                    continue;
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
            } else {
                receiver.stats.packets_decoded++;
            }
        }
    }

    free(packet);
    ESP_LOGI(TAG, "Audio receiver task stopped");
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

    ESP_LOGI(TAG, "Audio receiver initialized");
    return ESP_OK;
}

void audio_receiver_set_format(const audio_format_t *format)
{
    memcpy(&receiver.format, format, sizeof(audio_format_t));
    ESP_LOGI(TAG, "Audio format set: %s, %d Hz, %d ch, %d bits",
             format->codec, format->sample_rate, format->channels, format->bits_per_sample);

    // Initialize ALAC decoder if needed
    if (strcmp(format->codec, "AppleLossless") == 0 ||
        strcmp(format->codec, "ALAC") == 0) {
        if (receiver.alac) {
            alac_decoder_free(receiver.alac);
        }
        receiver.alac = alac_decoder_create(format);
        if (!receiver.alac) {
            ESP_LOGE(TAG, "Failed to create ALAC decoder");
        }
    }
}

void audio_receiver_set_encryption(const audio_encrypt_t *encrypt)
{
    if (encrypt) {
        memcpy(&receiver.encrypt, encrypt, sizeof(audio_encrypt_t));
        const char *type_str = "none";
        switch (encrypt->type) {
            case AUDIO_ENCRYPT_AES_CBC: type_str = "AES-CBC"; break;
            case AUDIO_ENCRYPT_CHACHA20_POLY1305: type_str = "ChaCha20-Poly1305"; break;
            default: break;
        }
        ESP_LOGI(TAG, "Audio encryption set: %s, key_len=%d", type_str, encrypt->key_len);
    } else {
        memset(&receiver.encrypt, 0, sizeof(audio_encrypt_t));
        ESP_LOGI(TAG, "Audio encryption disabled");
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
    BaseType_t ret = xTaskCreate(receiver_task, "audio_recv", 8192, NULL, 6, &receiver.task_handle);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create receiver task");
        close(receiver.data_socket);
        receiver.data_socket = 0;
        receiver.running = false;
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Audio receiver started on port %d", data_port);
    return ESP_OK;
}

void audio_receiver_stop(void)
{
    if (!receiver.running) {
        return;
    }

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

    // Free ALAC decoder
    if (receiver.alac) {
        alac_decoder_free(receiver.alac);
        receiver.alac = NULL;
    }

    // Clear encryption state
    memset(&receiver.encrypt, 0, sizeof(audio_encrypt_t));

    // Flush buffer
    audio_receiver_flush();

    ESP_LOGI(TAG, "Audio receiver stopped. Stats: recv=%lu, decoded=%lu, dropped=%lu, decrypt_err=%lu",
             receiver.stats.packets_received,
             receiver.stats.packets_decoded,
             receiver.stats.packets_dropped,
             receiver.stats.decrypt_errors);
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

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_random.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "sodium.h"
#include "mbedtls/aes.h"

#include "hap.h"
#include "tlv8.h"
#include "srp.h"
#include "esp_mac.h"

static const char *TAG = "hap";

// NVS storage keys
#define NVS_NAMESPACE "airplay"
#define NVS_KEY_PUBLIC "ed25519_pub"
#define NVS_KEY_SECRET "ed25519_sec"

// Device long-term keypair (loaded from NVS)
static uint8_t g_device_public_key[HAP_ED25519_PUBLIC_KEY_SIZE];
static uint8_t g_device_secret_key[HAP_ED25519_SECRET_KEY_SIZE];
static bool g_initialized = false;

// HKDF-SHA512 implementation using libsodium
static int hkdf_sha512(const uint8_t *salt, size_t salt_len,
                       const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len)
{
    // HKDF-Extract: PRK = HMAC-SHA512(salt, IKM)
    uint8_t prk[crypto_auth_hmacsha512_BYTES];
    crypto_auth_hmacsha512_state state;

    if (salt && salt_len > 0) {
        crypto_auth_hmacsha512_init(&state, salt, salt_len);
    } else {
        uint8_t zero_salt[crypto_auth_hmacsha512_BYTES] = {0};
        crypto_auth_hmacsha512_init(&state, zero_salt, sizeof(zero_salt));
    }
    crypto_auth_hmacsha512_update(&state, ikm, ikm_len);
    crypto_auth_hmacsha512_final(&state, prk);

    // HKDF-Expand
    uint8_t t[crypto_auth_hmacsha512_BYTES];
    uint8_t counter = 1;
    size_t t_len = 0;
    size_t pos = 0;

    while (pos < okm_len) {
        crypto_auth_hmacsha512_init(&state, prk, sizeof(prk));
        if (t_len > 0) {
            crypto_auth_hmacsha512_update(&state, t, t_len);
        }
        if (info && info_len > 0) {
            crypto_auth_hmacsha512_update(&state, info, info_len);
        }
        crypto_auth_hmacsha512_update(&state, &counter, 1);
        crypto_auth_hmacsha512_final(&state, t);
        t_len = crypto_auth_hmacsha512_BYTES;

        size_t copy_len = okm_len - pos;
        if (copy_len > crypto_auth_hmacsha512_BYTES) {
            copy_len = crypto_auth_hmacsha512_BYTES;
        }
        memcpy(okm + pos, t, copy_len);
        pos += copy_len;
        counter++;
    }

    sodium_memzero(prk, sizeof(prk));
    sodium_memzero(t, sizeof(t));
    return 0;
}

esp_err_t hap_init(void)
{
    if (g_initialized) {
        return ESP_OK;
    }

    // Initialize libsodium
    if (sodium_init() < 0) {
        ESP_LOGE(TAG, "Failed to initialize libsodium");
        return ESP_FAIL;
    }

    // Try to load existing keypair from NVS
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return err;
    }

    size_t pub_len = HAP_ED25519_PUBLIC_KEY_SIZE;
    size_t sec_len = HAP_ED25519_SECRET_KEY_SIZE;

    err = nvs_get_blob(nvs, NVS_KEY_PUBLIC, g_device_public_key, &pub_len);
    if (err == ESP_OK) {
        err = nvs_get_blob(nvs, NVS_KEY_SECRET, g_device_secret_key, &sec_len);
    }

    if (err != ESP_OK || pub_len != HAP_ED25519_PUBLIC_KEY_SIZE || sec_len != HAP_ED25519_SECRET_KEY_SIZE) {
        // Generate new keypair
        ESP_LOGI(TAG, "Generating new Ed25519 keypair...");
        crypto_sign_keypair(g_device_public_key, g_device_secret_key);

        // Store in NVS
        err = nvs_set_blob(nvs, NVS_KEY_PUBLIC, g_device_public_key, HAP_ED25519_PUBLIC_KEY_SIZE);
        if (err == ESP_OK) {
            err = nvs_set_blob(nvs, NVS_KEY_SECRET, g_device_secret_key, HAP_ED25519_SECRET_KEY_SIZE);
        }
        if (err == ESP_OK) {
            err = nvs_commit(nvs);
        }
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to store keypair in NVS: %s", esp_err_to_name(err));
            nvs_close(nvs);
            return err;
        }
        ESP_LOGI(TAG, "Ed25519 keypair generated and stored");
    } else {
        ESP_LOGI(TAG, "Ed25519 keypair loaded from NVS");
    }

    nvs_close(nvs);

    // Log public key (for debugging)
    ESP_LOGI(TAG, "Device public key: %02x%02x%02x%02x...",
             g_device_public_key[0], g_device_public_key[1],
             g_device_public_key[2], g_device_public_key[3]);

    g_initialized = true;
    return ESP_OK;
}

const uint8_t *hap_get_public_key(void)
{
    return g_device_public_key;
}

hap_session_t *hap_session_create(void)
{
    hap_session_t *session = calloc(1, sizeof(hap_session_t));
    if (!session) {
        return NULL;
    }

    // Copy device keypair
    memcpy(session->device_public_key, g_device_public_key, HAP_ED25519_PUBLIC_KEY_SIZE);
    memcpy(session->device_secret_key, g_device_secret_key, HAP_ED25519_SECRET_KEY_SIZE);

    // Generate ephemeral X25519 keypair for this session
    crypto_box_keypair(session->session_public_key, session->session_secret_key);

    session->pair_verify_state = 0;
    session->session_established = false;
    session->pair_setup_transient = false;
    session->encrypt_nonce = 0;
    session->decrypt_nonce = 0;

    return session;
}

void hap_session_free(hap_session_t *session)
{
    if (session) {
        // Free SRP session if exists
        if (session->srp) {
            srp_session_free(session->srp);
            session->srp = NULL;
        }
        // Zero sensitive data
        sodium_memzero(session->device_secret_key, sizeof(session->device_secret_key));
        sodium_memzero(session->session_secret_key, sizeof(session->session_secret_key));
        sodium_memzero(session->shared_secret, sizeof(session->shared_secret));
        sodium_memzero(session->encrypt_key, sizeof(session->encrypt_key));
        sodium_memzero(session->decrypt_key, sizeof(session->decrypt_key));
        free(session);
    }
}

esp_err_t hap_pair_verify_m1(hap_session_t *session,
                             const uint8_t *input, size_t input_len,
                             uint8_t *output, size_t output_capacity, size_t *output_len)
{
    ESP_LOGI(TAG, "Processing pair-verify M1");

    // Parse M1: state (0x06) = 1, public key (0x03) = client's X25519 public key
    size_t state_len;
    const uint8_t *state = tlv8_find(input, input_len, TLV_TYPE_STATE, &state_len);
    if (!state || state_len != 1 || state[0] != PAIR_VERIFY_STATE_M1) {
        ESP_LOGE(TAG, "Invalid M1 state");
        return ESP_ERR_INVALID_ARG;
    }

    // Get client's X25519 public key
    size_t client_pk_len;
    const uint8_t *client_pk = tlv8_find(input, input_len, TLV_TYPE_PUBLIC_KEY, &client_pk_len);
    if (!client_pk || client_pk_len != HAP_X25519_KEY_SIZE) {
        ESP_LOGE(TAG, "Invalid M1 public key");
        return ESP_ERR_INVALID_ARG;
    }

    // Store client's public key
    memcpy(session->client_public_key, client_pk, HAP_X25519_KEY_SIZE);

    // Compute shared secret: X25519(my_secret, client_public)
    if (crypto_scalarmult(session->shared_secret, session->session_secret_key, session->client_public_key) != 0) {
        ESP_LOGE(TAG, "X25519 key exchange failed");
        return ESP_FAIL;
    }

    // Create AccessoryInfo: session_public_key + device_id + client_public_key
    // Device ID is the MAC address in XX:XX:XX:XX:XX:XX format
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char device_id[18];
    snprintf(device_id, sizeof(device_id), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    size_t device_id_len = 17; // XX:XX:XX:XX:XX:XX

    uint8_t accessory_info[128];
    size_t accessory_info_len = 0;
    memcpy(accessory_info + accessory_info_len, session->session_public_key, HAP_X25519_KEY_SIZE);
    accessory_info_len += HAP_X25519_KEY_SIZE;
    memcpy(accessory_info + accessory_info_len, device_id, device_id_len);
    accessory_info_len += device_id_len;
    memcpy(accessory_info + accessory_info_len, session->client_public_key, HAP_X25519_KEY_SIZE);
    accessory_info_len += HAP_X25519_KEY_SIZE;

    // Sign AccessoryInfo with device's Ed25519 key
    uint8_t signature[crypto_sign_BYTES];
    crypto_sign_detached(signature, NULL, accessory_info, accessory_info_len, session->device_secret_key);

    // Create sub-TLV: identifier + signature
    uint8_t sub_tlv[256];
    tlv8_encoder_t sub_enc;
    tlv8_encoder_init(&sub_enc, sub_tlv, sizeof(sub_tlv));
    tlv8_encode(&sub_enc, TLV_TYPE_IDENTIFIER, (const uint8_t *)device_id, device_id_len);
    tlv8_encode(&sub_enc, TLV_TYPE_SIGNATURE, signature, crypto_sign_BYTES);

    // Derive encryption key for M2
    uint8_t session_key[32];
    hkdf_sha512((uint8_t*)"Pair-Verify-Encrypt-Salt", 24,
                session->shared_secret, HAP_X25519_KEY_SIZE,
                (uint8_t*)"Pair-Verify-Encrypt-Info", 24,
                session_key, 32);

    // Encrypt sub-TLV with ChaCha20-Poly1305
    uint8_t nonce[12] = {0, 0, 0, 0, 'P', 'V', '-', 'M', 's', 'g', '0', '2'};
    uint8_t encrypted[256 + crypto_aead_chacha20poly1305_ietf_ABYTES];
    unsigned long long encrypted_len;

    crypto_aead_chacha20poly1305_ietf_encrypt(
        encrypted, &encrypted_len,
        sub_tlv, tlv8_encoder_size(&sub_enc),
        NULL, 0,  // No additional data
        NULL,     // No secret nonce
        nonce,
        session_key);

    // Build M2 response
    tlv8_encoder_t enc;
    tlv8_encoder_init(&enc, output, output_capacity);
    tlv8_encode_byte(&enc, TLV_TYPE_STATE, PAIR_VERIFY_STATE_M2);
    tlv8_encode(&enc, TLV_TYPE_PUBLIC_KEY, session->session_public_key, HAP_X25519_KEY_SIZE);
    tlv8_encode(&enc, TLV_TYPE_ENCRYPTED_DATA, encrypted, (size_t)encrypted_len);

    *output_len = tlv8_encoder_size(&enc);
    session->pair_verify_state = PAIR_VERIFY_STATE_M2;

    // Store session key for M3
    memcpy(session->encrypt_key, session_key, 32);

    ESP_LOGI(TAG, "M2 response created, len=%zu", *output_len);
    ESP_LOGI(TAG, "M2 public key: %02x%02x%02x%02x...",
             session->session_public_key[0], session->session_public_key[1],
             session->session_public_key[2], session->session_public_key[3]);
    ESP_LOGI(TAG, "M2 encrypted data len: %llu", encrypted_len);
    ESP_LOGI(TAG, "Device ID used in signature: %s", device_id);
    return ESP_OK;
}

esp_err_t hap_pair_verify_m3(hap_session_t *session,
                             const uint8_t *input, size_t input_len,
                             uint8_t *output, size_t output_capacity, size_t *output_len)
{
    ESP_LOGI(TAG, "Processing pair-verify M3");

    // Parse M3: state (0x06) = 3, encrypted data (0x05)
    size_t state_len;
    const uint8_t *state = tlv8_find(input, input_len, TLV_TYPE_STATE, &state_len);
    if (!state || state_len != 1 || state[0] != PAIR_VERIFY_STATE_M3) {
        ESP_LOGE(TAG, "Invalid M3 state");
        return ESP_ERR_INVALID_ARG;
    }

    // Get encrypted data
    uint8_t encrypted[512];
    size_t encrypted_len;
    if (!tlv8_decode_concat(input, input_len, TLV_TYPE_ENCRYPTED_DATA,
                            encrypted, sizeof(encrypted), &encrypted_len)) {
        ESP_LOGE(TAG, "Missing M3 encrypted data");
        return ESP_ERR_INVALID_ARG;
    }

    // Decrypt with session key
    uint8_t nonce[12] = {0, 0, 0, 0, 'P', 'V', '-', 'M', 's', 'g', '0', '3'};
    uint8_t decrypted[512];
    unsigned long long decrypted_len;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted, &decrypted_len,
            NULL,
            encrypted, encrypted_len,
            NULL, 0,
            nonce,
            session->encrypt_key) != 0) {
        ESP_LOGE(TAG, "M3 decryption failed");
        // Return error TLV
        tlv8_encoder_t enc;
        tlv8_encoder_init(&enc, output, output_capacity);
        tlv8_encode_byte(&enc, TLV_TYPE_STATE, PAIR_VERIFY_STATE_M4);
        tlv8_encode_byte(&enc, TLV_TYPE_ERROR, TLV_ERROR_AUTHENTICATION);
        *output_len = tlv8_encoder_size(&enc);
        return ESP_ERR_INVALID_STATE;
    }

    // Parse decrypted sub-TLV to verify (in production, verify signature)
    // For now, we trust the client and proceed

    // Derive session encryption keys (server uses swapped directions)
    hkdf_sha512((uint8_t*)"Control-Salt", 12,
                session->shared_secret, HAP_X25519_KEY_SIZE,
                (uint8_t*)"Control-Read-Encryption-Key", 27,
                session->encrypt_key, 32);

    hkdf_sha512((uint8_t*)"Control-Salt", 12,
                session->shared_secret, HAP_X25519_KEY_SIZE,
                (uint8_t*)"Control-Write-Encryption-Key", 28,
                session->decrypt_key, 32);

    // Build M4 response (just state = 4, no error)
    tlv8_encoder_t enc;
    tlv8_encoder_init(&enc, output, output_capacity);
    tlv8_encode_byte(&enc, TLV_TYPE_STATE, PAIR_VERIFY_STATE_M4);

    *output_len = tlv8_encoder_size(&enc);
    session->pair_verify_state = PAIR_VERIFY_STATE_M4;
    session->session_established = true;

    ESP_LOGI(TAG, "Pair-verify complete, session established");
    return ESP_OK;
}

// AirPlay 2 "fruit" protocol pair-verify
// Based on shairport-sync pair_fruit.c:
// - Key derivation: SHA512("Pair-Verify-AES-Key" || shared_secret)[0:16]
// - IV derivation: SHA512("Pair-Verify-AES-IV" || shared_secret)[0:16]
// - Encryption: AES-128-CTR (NOT ChaCha20-Poly1305!)
// - M1: client sends 4-byte header + 32-byte X25519 epk + 32-byte Ed25519 pk = 68 bytes
// - M2: server sends 32-byte epk + 64-byte encrypted signature = 96 bytes
esp_err_t hap_pair_verify_m1_raw(hap_session_t *session,
                                  const uint8_t *input, size_t input_len,
                                  uint8_t *output, size_t output_capacity, size_t *output_len)
{
    ESP_LOGI(TAG, "Processing pair-verify M1 (fruit protocol), len=%zu", input_len);
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, input, input_len > 32 ? 32 : input_len, ESP_LOG_DEBUG);

    // AirPlay fruit format for verify M1:
    // - 4 bytes: header [0x01, 0x00, 0x00, 0x00] = method (verify start)
    // - 32 bytes: client ephemeral X25519 public key (epk)
    // - 32 bytes: client long-term Ed25519 public key (pk)
    // Total: 68 bytes

    const uint8_t *client_epk;
    const uint8_t *client_pk = NULL;

    if (input_len >= 68) {
        // Standard format: 4-byte header + 32 epk + 32 pk
        client_epk = input + 4;
        client_pk = input + 4 + 32;
        ESP_LOGI(TAG, "Fruit M1: 4-byte header + 32-byte epk + 32-byte pk");
    } else if (input_len >= 64) {
        // No header: 32 epk + 32 pk
        client_epk = input;
        client_pk = input + 32;
        ESP_LOGI(TAG, "Fruit M1: 32-byte epk + 32-byte pk (no header)");
    } else if (input_len >= 32) {
        // Just ephemeral public key
        client_epk = input;
        ESP_LOGI(TAG, "Fruit M1: 32-byte epk only");
    } else {
        ESP_LOGE(TAG, "Input too short for pair-verify: %zu", input_len);
        return ESP_ERR_INVALID_ARG;
    }

    // Store client's ephemeral X25519 public key
    memcpy(session->client_public_key, client_epk, HAP_X25519_KEY_SIZE);

    // Log client's public keys for debugging
    ESP_LOGI(TAG, "Client epk (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             client_epk[0], client_epk[1], client_epk[2], client_epk[3],
             client_epk[4], client_epk[5], client_epk[6], client_epk[7]);
    if (client_pk) {
        ESP_LOGI(TAG, "Client pk (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
                 client_pk[0], client_pk[1], client_pk[2], client_pk[3],
                 client_pk[4], client_pk[5], client_pk[6], client_pk[7]);
    }

    // Compute shared secret: X25519(my_secret, client_epk)
    if (crypto_scalarmult(session->shared_secret, session->session_secret_key, session->client_public_key) != 0) {
        ESP_LOGE(TAG, "X25519 key exchange failed");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Shared secret (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             session->shared_secret[0], session->shared_secret[1],
             session->shared_secret[2], session->shared_secret[3],
             session->shared_secret[4], session->shared_secret[5],
             session->shared_secret[6], session->shared_secret[7]);

    // FRUIT PROTOCOL: Derive AES key and IV using SHA512 concatenation
    // key = SHA512("Pair-Verify-AES-Key" || shared_secret)[0:16]
    // iv = SHA512("Pair-Verify-AES-IV" || shared_secret)[0:16]
    uint8_t aes_key[16];
    uint8_t aes_iv[16];

    // Derive AES key
    {
        crypto_hash_sha512_state state;
        uint8_t hash[64];
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, (const uint8_t *)"Pair-Verify-AES-Key", 19);
        crypto_hash_sha512_update(&state, session->shared_secret, 32);
        crypto_hash_sha512_final(&state, hash);
        memcpy(aes_key, hash, 16);
    }

    // Derive AES IV
    {
        crypto_hash_sha512_state state;
        uint8_t hash[64];
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, (const uint8_t *)"Pair-Verify-AES-IV", 18);
        crypto_hash_sha512_update(&state, session->shared_secret, 32);
        crypto_hash_sha512_final(&state, hash);
        memcpy(aes_iv, hash, 16);
    }

    ESP_LOGI(TAG, "AES key (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             aes_key[0], aes_key[1], aes_key[2], aes_key[3],
             aes_key[4], aes_key[5], aes_key[6], aes_key[7]);
    ESP_LOGI(TAG, "AES IV (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             aes_iv[0], aes_iv[1], aes_iv[2], aes_iv[3],
             aes_iv[4], aes_iv[5], aes_iv[6], aes_iv[7]);

    // FRUIT PROTOCOL: Sign (server_epk || client_epk)
    // NOT (epk + device_id + client_epk) like HomeKit!
    uint8_t signed_data[64];
    memcpy(signed_data, session->session_public_key, 32);  // Server's ephemeral X25519 pubkey
    memcpy(signed_data + 32, session->client_public_key, 32);  // Client's ephemeral X25519 pubkey

    uint8_t signature[64];  // Ed25519 signature is 64 bytes
    crypto_sign_detached(signature, NULL, signed_data, 64, session->device_secret_key);

    ESP_LOGI(TAG, "Signature (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             signature[0], signature[1], signature[2], signature[3],
             signature[4], signature[5], signature[6], signature[7]);

    // FRUIT PROTOCOL: Encrypt signature with AES-128-CTR
    // Output: 32-byte server epk + 64-byte encrypted signature = 96 bytes
    if (output_capacity < 96) {
        ESP_LOGE(TAG, "Output buffer too small for M2 (need 96, have %zu)", output_capacity);
        return ESP_ERR_NO_MEM;
    }

    // Copy server's ephemeral public key to output
    memcpy(output, session->session_public_key, 32);

    // Encrypt signature using AES-128-CTR
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_enc(&aes_ctx, aes_key, 128);

    uint8_t stream_block[16] = {0};
    size_t nc_off = 0;
    uint8_t nonce_counter[16];
    memcpy(nonce_counter, aes_iv, 16);

    mbedtls_aes_crypt_ctr(&aes_ctx, 64, &nc_off, nonce_counter, stream_block,
                          signature, output + 32);
    mbedtls_aes_free(&aes_ctx);

    *output_len = 96;  // 32 epk + 64 encrypted signature
    session->pair_verify_state = PAIR_VERIFY_STATE_M2;

    // Store derived keys for M3 processing and session encryption
    memcpy(session->encrypt_key, aes_key, 16);
    memcpy(session->decrypt_key, aes_iv, 16);  // Store IV for M3

    ESP_LOGI(TAG, "M2 fruit response: 96 bytes (32-byte epk + 64-byte encrypted sig)");
    return ESP_OK;
}

// Handle AirPlay 2 fruit pair-verify M3 format
// M3: 4-byte header + 64-byte encrypted signature
esp_err_t hap_pair_verify_m3_raw(hap_session_t *session,
                                  const uint8_t *input, size_t input_len,
                                  uint8_t *output, size_t output_capacity, size_t *output_len)
{
    ESP_LOGI(TAG, "Processing pair-verify M3 (fruit protocol), len=%zu", input_len);
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, input, input_len > 32 ? 32 : input_len, ESP_LOG_DEBUG);

    // Fruit M3 format: 4-byte header + 64-byte encrypted signature = 68 bytes
    // Or just 64 bytes encrypted signature if no header
    const uint8_t *encrypted_sig;

    if (input_len >= 68) {
        // Has 4-byte header
        encrypted_sig = input + 4;
        ESP_LOGI(TAG, "Fruit M3: 4-byte header + 64-byte encrypted sig");
    } else if (input_len >= 64) {
        // No header
        encrypted_sig = input;
        ESP_LOGI(TAG, "Fruit M3: 64-byte encrypted sig (no header)");
    } else {
        ESP_LOGE(TAG, "Input too short for M3: %zu", input_len);
        return ESP_ERR_INVALID_ARG;
    }

    // Reconstruct AES key and IV from shared secret (same as M1)
    uint8_t aes_key[16];
    uint8_t aes_iv[16];

    // Derive AES key
    {
        crypto_hash_sha512_state state;
        uint8_t hash[64];
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, (const uint8_t *)"Pair-Verify-AES-Key", 19);
        crypto_hash_sha512_update(&state, session->shared_secret, 32);
        crypto_hash_sha512_final(&state, hash);
        memcpy(aes_key, hash, 16);
    }

    // Derive AES IV
    {
        crypto_hash_sha512_state state;
        uint8_t hash[64];
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, (const uint8_t *)"Pair-Verify-AES-IV", 18);
        crypto_hash_sha512_update(&state, session->shared_secret, 32);
        crypto_hash_sha512_final(&state, hash);
        memcpy(aes_iv, hash, 16);
    }

    // Decrypt client's signature using AES-128-CTR
    uint8_t client_signature[64];
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_enc(&aes_ctx, aes_key, 128);

    uint8_t stream_block[16] = {0};
    size_t nc_off = 0;
    uint8_t nonce_counter[16];
    memcpy(nonce_counter, aes_iv, 16);

    mbedtls_aes_crypt_ctr(&aes_ctx, 64, &nc_off, nonce_counter, stream_block,
                          encrypted_sig, client_signature);
    mbedtls_aes_free(&aes_ctx);

    ESP_LOGI(TAG, "Client signature (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             client_signature[0], client_signature[1], client_signature[2], client_signature[3],
             client_signature[4], client_signature[5], client_signature[6], client_signature[7]);

    // Verify client signature: signed data is (client_epk || server_epk)
    // Note: opposite order from M2 which signs (server_epk || client_epk)
    uint8_t signed_data[64];
    memcpy(signed_data, session->client_public_key, 32);      // Client's ephemeral X25519 pubkey
    memcpy(signed_data + 32, session->session_public_key, 32); // Server's ephemeral X25519 pubkey

    // For transient pairing, we don't have the client's Ed25519 public key
    // to verify the signature. We just accept it and establish the session.
    // A real implementation would verify the signature using the client's pk
    // received in M1 (if available).
    ESP_LOGW(TAG, "Skipping signature verification (transient pairing)");

    // Derive session keys for encrypted communication using HKDF
    // These are different from the pair-verify AES keys!
    hkdf_sha512((uint8_t*)"Control-Salt", 12,
                session->shared_secret, HAP_X25519_KEY_SIZE,
                (uint8_t*)"Control-Read-Encryption-Key", 27,
                session->decrypt_key, 32);

    hkdf_sha512((uint8_t*)"Control-Salt", 12,
                session->shared_secret, HAP_X25519_KEY_SIZE,
                (uint8_t*)"Control-Write-Encryption-Key", 28,
                session->encrypt_key, 32);

    // Reset nonce counters
    session->encrypt_nonce = 0;
    session->decrypt_nonce = 0;

    // Return empty M4 response for fruit protocol
    *output_len = 0;
    session->pair_verify_state = PAIR_VERIFY_STATE_M4;
    session->session_established = true;

    ESP_LOGI(TAG, "Pair-verify complete (fruit protocol), session established");
    ESP_LOGI(TAG, "Encrypt key (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             session->encrypt_key[0], session->encrypt_key[1],
             session->encrypt_key[2], session->encrypt_key[3],
             session->encrypt_key[4], session->encrypt_key[5],
             session->encrypt_key[6], session->encrypt_key[7]);
    return ESP_OK;
}

esp_err_t hap_derive_audio_key(hap_session_t *session, uint8_t *audio_key, size_t key_len)
{
    if (!session || !audio_key || key_len < 16) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!session->session_established) {
        ESP_LOGW(TAG, "Cannot derive audio key before session established");
        return ESP_ERR_INVALID_STATE;
    }

    // Derive audio encryption key using HKDF-SHA512
    // Use same derivation strings as control channel (per shairport-sync)
    // "Control-Read" = key to decrypt data FROM client (audio stream)
    hkdf_sha512(
        (uint8_t*)"Control-Salt", 12,              // Salt (same as control channel)
        session->shared_secret, 32,                // IKM (Input Key Material)
        (uint8_t*)"Control-Read-Encryption-Key", 27,  // Info (server reads from client)
        audio_key, key_len                         // Output
    );

    ESP_LOGI(TAG, "Audio encryption key derived from pair-verify session");
    return ESP_OK;
}

esp_err_t hap_encrypt(hap_session_t *session,
                      const uint8_t *plaintext, size_t plaintext_len,
                      uint8_t *ciphertext, size_t *ciphertext_len)
{
    if (!session->session_established) {
        return ESP_ERR_INVALID_STATE;
    }

    // Build nonce from counter (little-endian)
    uint8_t nonce[12] = {0};
    memcpy(nonce + 4, &session->encrypt_nonce, 8);

    unsigned long long ct_len;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext, &ct_len,
        plaintext, plaintext_len,
        NULL, 0,
        NULL,
        nonce,
        session->encrypt_key);

    *ciphertext_len = (size_t)ct_len;
    session->encrypt_nonce++;

    return ESP_OK;
}

esp_err_t hap_decrypt(hap_session_t *session,
                      const uint8_t *ciphertext, size_t ciphertext_len,
                      uint8_t *plaintext, size_t *plaintext_len)
{
    if (!session->session_established) {
        return ESP_ERR_INVALID_STATE;
    }

    // Build nonce from counter (little-endian)
    uint8_t nonce[12] = {0};
    memcpy(nonce + 4, &session->decrypt_nonce, 8);

    unsigned long long pt_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext, &pt_len,
            NULL,
            ciphertext, ciphertext_len,
            NULL, 0,
            nonce,
            session->decrypt_key) != 0) {
        return ESP_ERR_INVALID_STATE;  // Auth failed
    }

    *plaintext_len = (size_t)pt_len;
    session->decrypt_nonce++;

    return ESP_OK;
}

// ============================================================================
// Pair-setup handlers (SRP-based)
// ============================================================================

// TLV type for pair-setup
#define TLV_TYPE_METHOD     0x00
#define TLV_TYPE_SALT       0x02
#define TLV_TYPE_PROOF      0x04
#define TLV_TYPE_FLAGS      0x13

// Pair-setup states
#define PAIR_SETUP_M1 1
#define PAIR_SETUP_M2 2
#define PAIR_SETUP_M3 3
#define PAIR_SETUP_M4 4
#define PAIR_SETUP_M5 5
#define PAIR_SETUP_M6 6

esp_err_t hap_pair_setup_m1(hap_session_t *session,
                            const uint8_t *input, size_t input_len,
                            uint8_t *output, size_t output_capacity, size_t *output_len)
{
    ESP_LOGI(TAG, "Processing pair-setup M1, len=%zu", input_len);
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, input, input_len, ESP_LOG_DEBUG);

    // Parse M1: method (0x00), state (0x06), flags (0x13)
    size_t method_len, state_len, flags_len;
    const uint8_t *method = tlv8_find(input, input_len, TLV_TYPE_METHOD, &method_len);
    const uint8_t *state = tlv8_find(input, input_len, TLV_TYPE_STATE, &state_len);
    const uint8_t *flags = tlv8_find(input, input_len, TLV_TYPE_FLAGS, &flags_len);

    if (!state || state_len != 1 || state[0] != PAIR_SETUP_M1) {
        ESP_LOGE(TAG, "Invalid pair-setup M1 state");
        return ESP_ERR_INVALID_ARG;
    }

    if (method && method_len == 1) {
        ESP_LOGI(TAG, "Pair-setup method: %d (0=SRP, 1=MFi)", method[0]);
    }

    bool transient = false;
    if (flags && flags_len == 1) {
        transient = (flags[0] & 0x10) != 0;
        ESP_LOGI(TAG, "Pair-setup flags: 0x%02x (transient=%d)", flags[0], transient);
    }
    session->pair_setup_transient = transient;

    // Create SRP session if not exists
    if (session->srp) {
        srp_session_free(session->srp);
    }
    session->srp = srp_session_create();
    if (!session->srp) {
        ESP_LOGE(TAG, "Failed to create SRP session");
        return ESP_ERR_NO_MEM;
    }

    // Start SRP with username "Pair-Setup" and PIN "3939" for transient
    const char *password = transient ? "3939" : "0000";  // Default PIN if not transient
    esp_err_t err = srp_start(session->srp, "Pair-Setup", password);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start SRP: %d", err);
        return err;
    }

    // Build M2 response: state=2, salt, public_key
    size_t pk_len;
    const uint8_t *salt = srp_get_salt(session->srp);
    const uint8_t *pk = srp_get_public_key(session->srp, &pk_len);

    tlv8_encoder_t enc;
    tlv8_encoder_init(&enc, output, output_capacity);
    tlv8_encode_byte(&enc, TLV_TYPE_STATE, PAIR_SETUP_M2);
    tlv8_encode(&enc, TLV_TYPE_SALT, salt, SRP_SALT_BYTES);
    tlv8_encode(&enc, TLV_TYPE_PUBLIC_KEY, pk, pk_len);

    *output_len = tlv8_encoder_size(&enc);
    session->pair_setup_state = PAIR_SETUP_M2;

    ESP_LOGI(TAG, "Pair-setup M2 response: %zu bytes (salt=%d, pk=%zu)",
             *output_len, SRP_SALT_BYTES, pk_len);
    return ESP_OK;
}

esp_err_t hap_pair_setup_m3(hap_session_t *session,
                            const uint8_t *input, size_t input_len,
                            uint8_t *output, size_t output_capacity, size_t *output_len)
{
    ESP_LOGI(TAG, "Processing pair-setup M3, len=%zu", input_len);

    if (!session->srp) {
        ESP_LOGE(TAG, "No SRP session for M3");
        return ESP_ERR_INVALID_STATE;
    }

    // Parse M3: state=3, public_key (A), proof (M1)
    size_t state_len, pk_len, proof_len;
    const uint8_t *state = tlv8_find(input, input_len, TLV_TYPE_STATE, &state_len);

    if (!state || state_len != 1 || state[0] != PAIR_SETUP_M3) {
        ESP_LOGE(TAG, "Invalid pair-setup M3 state");
        return ESP_ERR_INVALID_ARG;
    }

    // Get client's public key A (may be fragmented in TLV)
    uint8_t client_pk[512];
    if (!tlv8_decode_concat(input, input_len, TLV_TYPE_PUBLIC_KEY,
                            client_pk, sizeof(client_pk), &pk_len)) {
        ESP_LOGE(TAG, "Missing client public key in M3");
        return ESP_ERR_INVALID_ARG;
    }
    ESP_LOGI(TAG, "Client public key A: %zu bytes", pk_len);

    // Get client's proof M1
    uint8_t client_proof[64];
    if (!tlv8_decode_concat(input, input_len, TLV_TYPE_PROOF,
                            client_proof, sizeof(client_proof), &proof_len)) {
        ESP_LOGE(TAG, "Missing client proof in M3");
        return ESP_ERR_INVALID_ARG;
    }
    ESP_LOGI(TAG, "Client proof M1: %zu bytes", proof_len);

    // Verify client
    esp_err_t err = srp_verify_client(session->srp, client_pk, pk_len,
                                       client_proof, proof_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Client verification failed");
        // Send error response
        tlv8_encoder_t enc;
        tlv8_encoder_init(&enc, output, output_capacity);
        tlv8_encode_byte(&enc, TLV_TYPE_STATE, PAIR_SETUP_M4);
        tlv8_encode_byte(&enc, TLV_TYPE_ERROR, 0x02);  // Authentication error
        *output_len = tlv8_encoder_size(&enc);
        return ESP_OK;  // Return OK but with error TLV
    }

    if (session->pair_setup_transient) {
        size_t srp_key_len = 0;
        const uint8_t *srp_key = srp_get_session_key(session->srp, &srp_key_len);
        if (!srp_key || srp_key_len == 0) {
            ESP_LOGE(TAG, "Missing SRP session key for transient pairing");
            return ESP_ERR_INVALID_STATE;
        }

        memcpy(session->shared_secret, srp_key, 32);
        hkdf_sha512((uint8_t*)"Control-Salt", 12,
                    srp_key, srp_key_len,
                    (uint8_t*)"Control-Read-Encryption-Key", 27,
                    session->encrypt_key, 32);
        hkdf_sha512((uint8_t*)"Control-Salt", 12,
                    srp_key, srp_key_len,
                    (uint8_t*)"Control-Write-Encryption-Key", 28,
                    session->decrypt_key, 32);
        session->encrypt_nonce = 0;
        session->decrypt_nonce = 0;
        session->session_established = true;
        ESP_LOGI(TAG, "Transient pair-setup complete, session established");
    }

    // Build M4 response: state=4, proof (M2)
    const uint8_t *server_proof = srp_get_proof(session->srp);

    tlv8_encoder_t enc;
    tlv8_encoder_init(&enc, output, output_capacity);
    tlv8_encode_byte(&enc, TLV_TYPE_STATE, PAIR_SETUP_M4);
    tlv8_encode(&enc, TLV_TYPE_PROOF, server_proof, SRP_PROOF_BYTES);

    *output_len = tlv8_encoder_size(&enc);
    session->pair_setup_state = PAIR_SETUP_M4;

    ESP_LOGI(TAG, "Pair-setup M4 response: %zu bytes", *output_len);
    return ESP_OK;
}

esp_err_t hap_pair_setup_m5(hap_session_t *session,
                            const uint8_t *input, size_t input_len,
                            uint8_t *output, size_t output_capacity, size_t *output_len)
{
    ESP_LOGI(TAG, "Processing pair-setup M5, len=%zu", input_len);

    if (!session->srp) {
        ESP_LOGE(TAG, "No SRP session for M5");
        return ESP_ERR_INVALID_STATE;
    }

    // Parse M5: state=5, encrypted_data
    size_t state_len;
    const uint8_t *state = tlv8_find(input, input_len, TLV_TYPE_STATE, &state_len);

    if (!state || state_len != 1 || state[0] != PAIR_SETUP_M5) {
        ESP_LOGE(TAG, "Invalid pair-setup M5 state");
        return ESP_ERR_INVALID_ARG;
    }

    // Get encrypted data
    uint8_t encrypted[512];
    size_t encrypted_len;
    if (!tlv8_decode_concat(input, input_len, TLV_TYPE_ENCRYPTED_DATA,
                            encrypted, sizeof(encrypted), &encrypted_len)) {
        ESP_LOGE(TAG, "Missing encrypted data in M5");
        return ESP_ERR_INVALID_ARG;
    }
    ESP_LOGI(TAG, "Encrypted data: %zu bytes", encrypted_len);

    // Derive encryption key from SRP session key
    // Key = HKDF-SHA512(Salt="Pair-Setup-Encrypt-Salt", IKM=SRP_K, Info="Pair-Setup-Encrypt-Info")
    size_t srp_key_len = 0;
    const uint8_t *srp_key = srp_get_session_key(session->srp, &srp_key_len);
    if (!srp_key || srp_key_len == 0) {
        ESP_LOGE(TAG, "Missing SRP session key");
        return ESP_ERR_INVALID_STATE;
    }
    uint8_t setup_key[32];
    hkdf_sha512((uint8_t*)"Pair-Setup-Encrypt-Salt", 23,
                srp_key, srp_key_len,
                (uint8_t*)"Pair-Setup-Encrypt-Info", 23,
                setup_key, 32);

    // Decrypt M5 data
    uint8_t nonce[12] = {0, 0, 0, 0, 'P', 'S', '-', 'M', 's', 'g', '0', '5'};
    uint8_t decrypted[512];
    unsigned long long decrypted_len;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted, &decrypted_len,
            NULL,
            encrypted, encrypted_len,
            NULL, 0,
            nonce,
            setup_key) != 0) {
        ESP_LOGE(TAG, "M5 decryption failed");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Decrypted M5: %llu bytes", decrypted_len);

    // Parse decrypted sub-TLV: identifier, public_key, signature
    size_t id_len, ltpk_len;
    const uint8_t *identifier = tlv8_find(decrypted, decrypted_len, TLV_TYPE_IDENTIFIER, &id_len);
    const uint8_t *ltpk = tlv8_find(decrypted, decrypted_len, TLV_TYPE_PUBLIC_KEY, &ltpk_len);
    // Note: signature is present but not verified for transient pairing

    if (identifier) {
        char id_str[64] = {0};
        memcpy(id_str, identifier, id_len < 63 ? id_len : 63);
        ESP_LOGI(TAG, "Client identifier: %s", id_str);
    }
    if (ltpk) {
        ESP_LOGI(TAG, "Client LTPK: %zu bytes", ltpk_len);
    }

    // For transient pairing, we don't need to store client's LTPK
    // Just acknowledge and establish the session

    // Copy SRP session key to shared_secret for key derivation
    memcpy(session->shared_secret, srp_key, 32);

    // Build M6 response: state=6, encrypted_data (containing our identifier + LTPK + signature)
    // Create sub-TLV for encryption
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char device_id[18];
    snprintf(device_id, sizeof(device_id), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // Sign: LTPK || identifier || client_LTPK
    uint8_t sign_data[128];
    size_t sign_data_len = 0;
    memcpy(sign_data, session->device_public_key, HAP_ED25519_PUBLIC_KEY_SIZE);
    sign_data_len += HAP_ED25519_PUBLIC_KEY_SIZE;
    memcpy(sign_data + sign_data_len, device_id, 17);
    sign_data_len += 17;
    if (ltpk && ltpk_len == 32) {
        memcpy(sign_data + sign_data_len, ltpk, 32);
        sign_data_len += 32;
    }

    uint8_t signature[64];
    crypto_sign_detached(signature, NULL, sign_data, sign_data_len, session->device_secret_key);

    // Create sub-TLV
    uint8_t sub_tlv[256];
    tlv8_encoder_t sub_enc;
    tlv8_encoder_init(&sub_enc, sub_tlv, sizeof(sub_tlv));
    tlv8_encode(&sub_enc, TLV_TYPE_IDENTIFIER, (const uint8_t *)device_id, 17);
    tlv8_encode(&sub_enc, TLV_TYPE_PUBLIC_KEY, session->device_public_key, HAP_ED25519_PUBLIC_KEY_SIZE);
    tlv8_encode(&sub_enc, TLV_TYPE_SIGNATURE, signature, 64);

    // Encrypt sub-TLV
    uint8_t nonce6[12] = {0, 0, 0, 0, 'P', 'S', '-', 'M', 's', 'g', '0', '6'};
    uint8_t encrypted_response[256 + 16];
    unsigned long long encrypted_response_len;

    crypto_aead_chacha20poly1305_ietf_encrypt(
        encrypted_response, &encrypted_response_len,
        sub_tlv, tlv8_encoder_size(&sub_enc),
        NULL, 0, NULL, nonce6, setup_key);

    // Build M6 TLV response
    tlv8_encoder_t enc;
    tlv8_encoder_init(&enc, output, output_capacity);
    tlv8_encode_byte(&enc, TLV_TYPE_STATE, PAIR_SETUP_M6);
    tlv8_encode(&enc, TLV_TYPE_ENCRYPTED_DATA, encrypted_response, encrypted_response_len);

    *output_len = tlv8_encoder_size(&enc);
    session->pair_setup_state = PAIR_SETUP_M6;
    session->session_established = true;

    // Derive session keys for future communication
    hkdf_sha512((uint8_t*)"Control-Salt", 12,
                srp_key, srp_key_len,
                (uint8_t*)"Control-Read-Encryption-Key", 27,
                session->encrypt_key, 32);

    hkdf_sha512((uint8_t*)"Control-Salt", 12,
                srp_key, srp_key_len,
                (uint8_t*)"Control-Write-Encryption-Key", 28,
                session->decrypt_key, 32);

    session->encrypt_nonce = 0;
    session->decrypt_nonce = 0;

    ESP_LOGI(TAG, "Pair-setup M6 response: %zu bytes", *output_len);
    ESP_LOGI(TAG, "Pair-setup complete, session established!");
    return ESP_OK;
}

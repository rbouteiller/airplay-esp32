#include <string.h>
#include <stdarg.h>
#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/bignum.h"
#include "sodium.h"

#include "srp.h"

static const char *TAG = "srp";

// SRP-6a 3072-bit prime N (from RFC 5054)
static const uint8_t srp_N[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
    0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
    0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
    0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
    0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
    0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D,
    0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
    0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57,
    0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
    0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0,
    0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
    0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73,
    0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
    0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0,
    0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
    0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20,
    0xA9, 0x3A, 0xD2, 0xCA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// Generator g = 5
#define SRP_GENERATOR 5

// Helper: compute SHA-512 hash
static void sha512_hash(const uint8_t *data, size_t len, uint8_t *out)
{
    crypto_hash_sha512(out, data, len);
}

// Helper: compute SHA-512 hash of multiple inputs
static void sha512_hash_multi(uint8_t *out, int count, ...)
{
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);

    va_list args;
    va_start(args, count);
    for (int i = 0; i < count; i++) {
        const uint8_t *data = va_arg(args, const uint8_t *);
        size_t len = va_arg(args, size_t);
        crypto_hash_sha512_update(&state, data, len);
    }
    va_end(args);

    crypto_hash_sha512_final(&state, out);
}

static void srp_compute_m1(uint8_t *out,
                           const uint8_t *h_Ng_xor,
                           const uint8_t *h_I,
                           const uint8_t *salt,
                           size_t salt_len,
                           const uint8_t *A,
                           size_t A_len,
                           const uint8_t *B,
                           size_t B_len,
                           const uint8_t *K,
                           size_t K_len)
{
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);
    crypto_hash_sha512_update(&state, h_Ng_xor, 64);
    crypto_hash_sha512_update(&state, h_I, 64);
    crypto_hash_sha512_update(&state, salt, salt_len);
    crypto_hash_sha512_update(&state, A, A_len);
    crypto_hash_sha512_update(&state, B, B_len);
    crypto_hash_sha512_update(&state, K, K_len);
    crypto_hash_sha512_final(&state, out);
}

static size_t mpi_to_bytes_min(const mbedtls_mpi *mpi, uint8_t *buf, size_t len)
{
    size_t mpi_size = mbedtls_mpi_size(mpi);
    if (mpi_size == 0) {
        if (len < 1) {
            return 0;
        }
        buf[0] = 0;
        return 1;
    }
    if (mpi_size > len) {
        return 0;
    }
    if (mbedtls_mpi_write_binary(mpi, buf, mpi_size) != 0) {
        return 0;
    }
    return mpi_size;
}

static void trim_leading_zeros(const uint8_t *in, size_t in_len,
                               const uint8_t **out, size_t *out_len)
{
    size_t offset = 0;
    while (offset < in_len && in[offset] == 0) {
        offset++;
    }
    if (offset == in_len) {
        *out = in + (in_len ? in_len - 1 : 0);
        *out_len = in_len ? 1 : 0;
        return;
    }
    *out = in + offset;
    *out_len = in_len - offset;
}

// Helper: pad MPI to fixed size (big-endian)
static int mpi_to_bytes_padded(const mbedtls_mpi *mpi, uint8_t *buf, size_t len)
{
    size_t mpi_size = mbedtls_mpi_size(mpi);
    if (mpi_size > len) {
        return -1;
    }
    memset(buf, 0, len);
    return mbedtls_mpi_write_binary(mpi, buf + (len - mpi_size), mpi_size);
}

srp_session_t *srp_session_create(void)
{
    srp_session_t *session = calloc(1, sizeof(srp_session_t));
    if (session) {
        session->state = 0;
        session->verified = false;
    }
    return session;
}

void srp_session_free(srp_session_t *session)
{
    if (session) {
        // Clear sensitive data
        memset(session, 0, sizeof(srp_session_t));
        free(session);
    }
}

esp_err_t srp_start(srp_session_t *session, const char *username, const char *password)
{
    if (!session || !username || !password) {
        return ESP_ERR_INVALID_ARG;
    }

    int ret;
    mbedtls_mpi N, g, k, v, b, B, tmp, tmp2;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&g);
    mbedtls_mpi_init(&k);
    mbedtls_mpi_init(&v);
    mbedtls_mpi_init(&b);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_init(&tmp2);

    // Generate random salt
    esp_fill_random(session->salt, SRP_SALT_BYTES);
    ESP_LOGI(TAG, "Generated salt");

    // Load N (prime)
    ret = mbedtls_mpi_read_binary(&N, srp_N, sizeof(srp_N));
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to load N: %d", ret);
        goto cleanup;
    }

    // g = 5
    mbedtls_mpi_lset(&g, SRP_GENERATOR);

    // Compute k = H(N || pad(g))
    {
        uint8_t hash_input[SRP_PRIME_BYTES * 2];
        memcpy(hash_input, srp_N, SRP_PRIME_BYTES);
        memset(hash_input + SRP_PRIME_BYTES, 0, SRP_PRIME_BYTES);
        hash_input[SRP_PRIME_BYTES * 2 - 1] = SRP_GENERATOR;

        uint8_t k_hash[64];
        sha512_hash(hash_input, sizeof(hash_input), k_hash);
        mbedtls_mpi_read_binary(&k, k_hash, 64);
        mbedtls_mpi_mod_mpi(&k, &k, &N);
    }

    // Compute x = H(s || H(I || ":" || P))
    mbedtls_mpi x;
    mbedtls_mpi_init(&x);
    {
        // Inner hash: H(I || ":" || P)
        uint8_t inner_hash[64];
        crypto_hash_sha512_state state;
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, (const uint8_t *)username, strlen(username));
        crypto_hash_sha512_update(&state, (const uint8_t *)":", 1);
        crypto_hash_sha512_update(&state, (const uint8_t *)password, strlen(password));
        crypto_hash_sha512_final(&state, inner_hash);

        // Outer hash: H(s || inner_hash)
        uint8_t x_hash[64];
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, session->salt, SRP_SALT_BYTES);
        crypto_hash_sha512_update(&state, inner_hash, 64);
        crypto_hash_sha512_final(&state, x_hash);

        mbedtls_mpi_read_binary(&x, x_hash, 64);
    }

    // Compute v = g^x mod N (verifier)
    ret = mbedtls_mpi_exp_mod(&v, &g, &x, &N, NULL);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to compute v: %d", ret);
        mbedtls_mpi_free(&x);
        goto cleanup;
    }
    mbedtls_mpi_free(&x);

    // Generate random b (server secret)
    {
        uint8_t b_bytes[SRP_PRIME_BYTES];
        esp_fill_random(b_bytes, sizeof(b_bytes));
        mbedtls_mpi_read_binary(&b, b_bytes, sizeof(b_bytes));
        mbedtls_mpi_mod_mpi(&b, &b, &N);

        // Store b for later
        mpi_to_bytes_padded(&b, session->server_secret, SRP_PRIME_BYTES);
    }

    // Compute B = (k*v + g^b) mod N
    ret = mbedtls_mpi_exp_mod(&tmp, &g, &b, &N, NULL);  // tmp = g^b mod N
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to compute g^b: %d", ret);
        goto cleanup;
    }

    ret = mbedtls_mpi_mul_mpi(&tmp2, &k, &v);  // tmp2 = k*v
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to compute k*v: %d", ret);
        goto cleanup;
    }

    ret = mbedtls_mpi_add_mpi(&B, &tmp2, &tmp);  // B = k*v + g^b
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to compute B: %d", ret);
        goto cleanup;
    }

    mbedtls_mpi_mod_mpi(&B, &B, &N);  // B = B mod N

    // Store B (server public key)
    mpi_to_bytes_padded(&B, session->server_public_key, SRP_PRIME_BYTES);

    session->state = 1;
    ESP_LOGI(TAG, "SRP session started");
    ESP_LOGI(TAG, "Server public key B (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             session->server_public_key[0], session->server_public_key[1],
             session->server_public_key[2], session->server_public_key[3],
             session->server_public_key[4], session->server_public_key[5],
             session->server_public_key[6], session->server_public_key[7]);

    ret = 0;

cleanup:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&g);
    mbedtls_mpi_free(&k);
    mbedtls_mpi_free(&v);
    mbedtls_mpi_free(&b);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&tmp);
    mbedtls_mpi_free(&tmp2);

    return ret == 0 ? ESP_OK : ESP_FAIL;
}

const uint8_t *srp_get_salt(srp_session_t *session)
{
    return session ? session->salt : NULL;
}

const uint8_t *srp_get_public_key(srp_session_t *session, size_t *len)
{
    if (!session) return NULL;
    if (len) *len = SRP_PRIME_BYTES;
    return session->server_public_key;
}

esp_err_t srp_verify_client(srp_session_t *session,
                            const uint8_t *client_public_key, size_t client_pk_len,
                            const uint8_t *client_proof, size_t proof_len)
{
    if (!session || !client_public_key || !client_proof) {
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(TAG, "Verifying client, A_len=%zu, proof_len=%zu", client_pk_len, proof_len);

    // Store client's public key A
    if (client_pk_len > SRP_PRIME_BYTES) {
        client_pk_len = SRP_PRIME_BYTES;
    }
    memset(session->client_public_key, 0, SRP_PRIME_BYTES);
    memcpy(session->client_public_key + (SRP_PRIME_BYTES - client_pk_len),
           client_public_key, client_pk_len);

    int ret;
    mbedtls_mpi N, g, A, B, b, u, S, k, v, x, tmp, tmp2;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&g);
    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&b);
    mbedtls_mpi_init(&u);
    mbedtls_mpi_init(&S);
    mbedtls_mpi_init(&k);
    mbedtls_mpi_init(&v);
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_init(&tmp2);

    // Load parameters
    mbedtls_mpi_read_binary(&N, srp_N, sizeof(srp_N));
    mbedtls_mpi_lset(&g, SRP_GENERATOR);
    mbedtls_mpi_read_binary(&A, session->client_public_key, SRP_PRIME_BYTES);
    mbedtls_mpi_read_binary(&B, session->server_public_key, SRP_PRIME_BYTES);
    mbedtls_mpi_read_binary(&b, session->server_secret, SRP_PRIME_BYTES);

    // Check A != 0 and A % N != 0
    if (mbedtls_mpi_cmp_int(&A, 0) == 0) {
        ESP_LOGE(TAG, "Invalid client public key A (zero)");
        ret = -1;
        goto cleanup;
    }
    mbedtls_mpi_mod_mpi(&tmp, &A, &N);
    if (mbedtls_mpi_cmp_int(&tmp, 0) == 0) {
        ESP_LOGE(TAG, "Invalid client public key A (multiple of N)");
        ret = -1;
        goto cleanup;
    }

    // Compute u = H(PAD(A) || PAD(B)) using RFC 5054 padding
    // Both A and B are padded to SRP_PRIME_BYTES before hashing
    uint8_t u_hash[64];
    {
        uint8_t ab_concat[SRP_PRIME_BYTES * 2];
        // A and B are already padded to SRP_PRIME_BYTES in session->client/server_public_key
        memcpy(ab_concat, session->client_public_key, SRP_PRIME_BYTES);
        memcpy(ab_concat + SRP_PRIME_BYTES, session->server_public_key, SRP_PRIME_BYTES);
        sha512_hash(ab_concat, sizeof(ab_concat), u_hash);
        mbedtls_mpi_read_binary(&u, u_hash, 64);
        ESP_LOGI(TAG, "u (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
                 u_hash[0], u_hash[1], u_hash[2], u_hash[3],
                 u_hash[4], u_hash[5], u_hash[6], u_hash[7]);
    }

    // Recompute k, v, x (same as in srp_start)
    // k = H(N || pad(g))
    uint8_t k_hash[64];
    {
        uint8_t hash_input[SRP_PRIME_BYTES * 2];
        memcpy(hash_input, srp_N, SRP_PRIME_BYTES);
        memset(hash_input + SRP_PRIME_BYTES, 0, SRP_PRIME_BYTES);
        hash_input[SRP_PRIME_BYTES * 2 - 1] = SRP_GENERATOR;
        sha512_hash(hash_input, sizeof(hash_input), k_hash);
        mbedtls_mpi_read_binary(&k, k_hash, 64);
        mbedtls_mpi_mod_mpi(&k, &k, &N);
        ESP_LOGI(TAG, "k (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
                 k_hash[0], k_hash[1], k_hash[2], k_hash[3],
                 k_hash[4], k_hash[5], k_hash[6], k_hash[7]);
    }

    // x = H(s || H(I || ":" || P)) for "Pair-Setup" and "3939"
    uint8_t x_hash[64];
    {
        uint8_t inner_hash[64];
        crypto_hash_sha512_state state;
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, (const uint8_t *)"Pair-Setup", 10);
        crypto_hash_sha512_update(&state, (const uint8_t *)":", 1);
        crypto_hash_sha512_update(&state, (const uint8_t *)"3939", 4);
        crypto_hash_sha512_final(&state, inner_hash);

        ESP_LOGI(TAG, "H(I:P) (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
                 inner_hash[0], inner_hash[1], inner_hash[2], inner_hash[3],
                 inner_hash[4], inner_hash[5], inner_hash[6], inner_hash[7]);

        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, session->salt, SRP_SALT_BYTES);
        crypto_hash_sha512_update(&state, inner_hash, 64);
        crypto_hash_sha512_final(&state, x_hash);

        mbedtls_mpi_read_binary(&x, x_hash, 64);
        ESP_LOGI(TAG, "x (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
                 x_hash[0], x_hash[1], x_hash[2], x_hash[3],
                 x_hash[4], x_hash[5], x_hash[6], x_hash[7]);
    }

    // v = g^x mod N
    mbedtls_mpi_exp_mod(&v, &g, &x, &N, NULL);

    // Compute S = (A * v^u)^b mod N
    ret = mbedtls_mpi_exp_mod(&tmp, &v, &u, &N, NULL);  // tmp = v^u mod N
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to compute v^u: %d", ret);
        goto cleanup;
    }

    ret = mbedtls_mpi_mul_mpi(&tmp2, &A, &tmp);  // tmp2 = A * v^u
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to compute A*v^u: %d", ret);
        goto cleanup;
    }
    mbedtls_mpi_mod_mpi(&tmp2, &tmp2, &N);

    ret = mbedtls_mpi_exp_mod(&S, &tmp2, &b, &N, NULL);  // S = (A*v^u)^b mod N
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to compute S: %d", ret);
        goto cleanup;
    }

    // Get S as minimal bytes
    uint8_t S_bytes[SRP_PRIME_BYTES];
    size_t S_len = mpi_to_bytes_min(&S, S_bytes, sizeof(S_bytes));
    {
        uint8_t s_prefix[8] = {0};
        size_t copy_len = S_len < sizeof(s_prefix) ? S_len : sizeof(s_prefix);
        memcpy(s_prefix, S_bytes, copy_len);
        ESP_LOGI(TAG, "S (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
                 s_prefix[0], s_prefix[1], s_prefix[2], s_prefix[3],
                 s_prefix[4], s_prefix[5], s_prefix[6], s_prefix[7]);
    }

    // Standard SRP key: K = H(S)
    uint8_t k_srp[64];
    sha512_hash(S_bytes, S_len, k_srp);

    // Apple "fruit" protocol: K = H(S || 0x00000000) || H(S || 0x00000001)
    // This creates a 128-byte session key (2 × 64 bytes for SHA-512)
    {
        crypto_hash_sha512_state state;
        uint8_t suffix[4];

        // First half: H(S || 0x00000000)
        memset(suffix, 0, 4);
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, S_bytes, S_len);
        crypto_hash_sha512_update(&state, suffix, 4);
        crypto_hash_sha512_final(&state, session->session_key);

        // Second half: H(S || 0x00000001)
        suffix[3] = 1;
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, S_bytes, S_len);
        crypto_hash_sha512_update(&state, suffix, 4);
        crypto_hash_sha512_final(&state, session->session_key + 64);
    }

    ESP_LOGI(TAG, "Session key K (SRP) (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             k_srp[0], k_srp[1], k_srp[2], k_srp[3],
             k_srp[4], k_srp[5], k_srp[6], k_srp[7]);
    ESP_LOGI(TAG, "Session key K (fruit) (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             session->session_key[0], session->session_key[1],
             session->session_key[2], session->session_key[3],
             session->session_key[4], session->session_key[5],
             session->session_key[6], session->session_key[7]);

    // Compute expected M1 using standard SRP-6a formula:
    // M1 = H(H(N) ⊕ H(g) || H(I) || s || A || B || K)
    uint8_t expected_m1_srp[64];
    uint8_t expected_m1_fruit_64[64];
    uint8_t expected_m1_fruit_128[64];
    {
        // H(N)
        uint8_t h_N[64];
        sha512_hash(srp_N, sizeof(srp_N), h_N);
        ESP_LOGI(TAG, "H(N) (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
                 h_N[0], h_N[1], h_N[2], h_N[3], h_N[4], h_N[5], h_N[6], h_N[7]);

        // H(g) - g as a single byte
        uint8_t g_bytes[1] = {SRP_GENERATOR};
        uint8_t h_g[64];
        sha512_hash(g_bytes, sizeof(g_bytes), h_g);
        ESP_LOGI(TAG, "H(g) (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
                 h_g[0], h_g[1], h_g[2], h_g[3], h_g[4], h_g[5], h_g[6], h_g[7]);

        // H(N) ⊕ H(g)
        uint8_t h_Ng_xor[64];
        for (int i = 0; i < 64; i++) {
            h_Ng_xor[i] = h_N[i] ^ h_g[i];
        }
        ESP_LOGI(TAG, "H(N)⊕H(g) (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
                 h_Ng_xor[0], h_Ng_xor[1], h_Ng_xor[2], h_Ng_xor[3],
                 h_Ng_xor[4], h_Ng_xor[5], h_Ng_xor[6], h_Ng_xor[7]);

        // H(I) where I = "Pair-Setup"
        uint8_t h_I[64];
        sha512_hash((const uint8_t *)"Pair-Setup", 10, h_I);
        ESP_LOGI(TAG, "H(I) (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
                 h_I[0], h_I[1], h_I[2], h_I[3], h_I[4], h_I[5], h_I[6], h_I[7]);
        const uint8_t *salt_ptr = NULL;
        size_t salt_len = 0;
        trim_leading_zeros(session->salt, SRP_SALT_BYTES, &salt_ptr, &salt_len);

        uint8_t A_bytes[SRP_PRIME_BYTES];
        uint8_t B_bytes[SRP_PRIME_BYTES];
        size_t A_len = mpi_to_bytes_min(&A, A_bytes, sizeof(A_bytes));
        size_t B_len = mpi_to_bytes_min(&B, B_bytes, sizeof(B_bytes));

        uint8_t salt_prefix[8] = {0};
        uint8_t a_prefix[8] = {0};
        uint8_t b_prefix[8] = {0};
        size_t salt_copy_len = salt_len < sizeof(salt_prefix) ? salt_len : sizeof(salt_prefix);
        size_t a_copy_len = A_len < sizeof(a_prefix) ? A_len : sizeof(a_prefix);
        size_t b_copy_len = B_len < sizeof(b_prefix) ? B_len : sizeof(b_prefix);
        memcpy(salt_prefix, salt_ptr, salt_copy_len);
        memcpy(a_prefix, A_bytes, a_copy_len);
        memcpy(b_prefix, B_bytes, b_copy_len);

        ESP_LOGI(TAG, "salt (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
                 salt_prefix[0], salt_prefix[1], salt_prefix[2], salt_prefix[3],
                 salt_prefix[4], salt_prefix[5], salt_prefix[6], salt_prefix[7]);
        ESP_LOGI(TAG, "A (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
                 a_prefix[0], a_prefix[1], a_prefix[2], a_prefix[3],
                 a_prefix[4], a_prefix[5], a_prefix[6], a_prefix[7]);
        ESP_LOGI(TAG, "B (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
                 b_prefix[0], b_prefix[1], b_prefix[2], b_prefix[3],
                 b_prefix[4], b_prefix[5], b_prefix[6], b_prefix[7]);

        ESP_LOGI(TAG, "Trying M1 with K = H(S) (64 bytes)");
        srp_compute_m1(expected_m1_srp, h_Ng_xor, h_I,
                       salt_ptr, salt_len,
                       A_bytes, A_len,
                       B_bytes, B_len,
                       k_srp, 64);
        ESP_LOGI(TAG, "M1 with K=H(S) (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
                 expected_m1_srp[0], expected_m1_srp[1], expected_m1_srp[2], expected_m1_srp[3],
                 expected_m1_srp[4], expected_m1_srp[5], expected_m1_srp[6], expected_m1_srp[7]);

        ESP_LOGI(TAG, "Trying M1 with K_fruit_len=64");
        srp_compute_m1(expected_m1_fruit_64, h_Ng_xor, h_I,
                       salt_ptr, salt_len,
                       A_bytes, A_len,
                       B_bytes, B_len,
                       session->session_key, 64);
        ESP_LOGI(TAG, "M1 with K_fruit[0:64] (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
                 expected_m1_fruit_64[0], expected_m1_fruit_64[1],
                 expected_m1_fruit_64[2], expected_m1_fruit_64[3],
                 expected_m1_fruit_64[4], expected_m1_fruit_64[5],
                 expected_m1_fruit_64[6], expected_m1_fruit_64[7]);

        ESP_LOGI(TAG, "Trying M1 with K_fruit_len=128");
        srp_compute_m1(expected_m1_fruit_128, h_Ng_xor, h_I,
                       salt_ptr, salt_len,
                       A_bytes, A_len,
                       B_bytes, B_len,
                       session->session_key, 128);
        ESP_LOGI(TAG, "M1 with K_fruit[0:128] (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
                 expected_m1_fruit_128[0], expected_m1_fruit_128[1],
                 expected_m1_fruit_128[2], expected_m1_fruit_128[3],
                 expected_m1_fruit_128[4], expected_m1_fruit_128[5],
                 expected_m1_fruit_128[6], expected_m1_fruit_128[7]);
    }

    ESP_LOGI(TAG, "Received M1 (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             client_proof[0], client_proof[1], client_proof[2], client_proof[3],
             client_proof[4], client_proof[5], client_proof[6], client_proof[7]);

    // Verify client proof - check SRP vs fruit variants
    bool matched_srp = (proof_len >= SRP_PROOF_BYTES &&
                        memcmp(client_proof, expected_m1_srp, SRP_PROOF_BYTES) == 0);
    bool matched_fruit_64 = (proof_len >= SRP_PROOF_BYTES &&
                             memcmp(client_proof, expected_m1_fruit_64, SRP_PROOF_BYTES) == 0);
    bool matched_fruit_128 = (proof_len >= SRP_PROOF_BYTES &&
                              memcmp(client_proof, expected_m1_fruit_128, SRP_PROOF_BYTES) == 0);

    if (matched_srp) {
        ESP_LOGI(TAG, "✓ Client proof MATCHED with K=H(S)!");
        memcpy(session->session_key, k_srp, 64);
        memset(session->session_key + 64, 0, 64);
        session->session_key_len = 64;
    } else if (matched_fruit_64) {
        ESP_LOGI(TAG, "✓ Client proof MATCHED with K_fruit_len=64!");
        session->session_key_len = 64;
    } else if (matched_fruit_128) {
        ESP_LOGI(TAG, "✓ Client proof MATCHED with K_fruit_len=128!");
        session->session_key_len = 128;
    } else {
        ESP_LOGW(TAG, "Client proof verification failed with all K variants");
        ret = -1;
        goto cleanup;
    }

    ESP_LOGI(TAG, "Client proof verified!");

    // Store client's M1
    memcpy(session->proof_m1, client_proof, SRP_PROOF_BYTES);

    // Compute server proof M2 = H(A || M1 || K)
    {
        uint8_t A_bytes[SRP_PRIME_BYTES];
        size_t A_len = mpi_to_bytes_min(&A, A_bytes, sizeof(A_bytes));

        ESP_LOGI(TAG, "Computing M2 with K_len=%zu", session->session_key_len);

        crypto_hash_sha512_state state;
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, A_bytes, A_len);
        crypto_hash_sha512_update(&state, session->proof_m1, SRP_PROOF_BYTES);
        crypto_hash_sha512_update(&state, session->session_key, session->session_key_len);
        crypto_hash_sha512_final(&state, session->proof_m2);
    }

    ESP_LOGI(TAG, "Server proof M2 (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             session->proof_m2[0], session->proof_m2[1],
             session->proof_m2[2], session->proof_m2[3],
             session->proof_m2[4], session->proof_m2[5],
             session->proof_m2[6], session->proof_m2[7]);

    session->verified = true;
    session->state = 2;
    ret = 0;

cleanup:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&g);
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&b);
    mbedtls_mpi_free(&u);
    mbedtls_mpi_free(&S);
    mbedtls_mpi_free(&k);
    mbedtls_mpi_free(&v);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&tmp);
    mbedtls_mpi_free(&tmp2);

    return ret == 0 ? ESP_OK : ESP_FAIL;
}

const uint8_t *srp_get_proof(srp_session_t *session)
{
    if (!session || !session->verified) return NULL;
    return session->proof_m2;
}

const uint8_t *srp_get_session_key(srp_session_t *session, size_t *len)
{
    if (!session || !session->verified) return NULL;
    if (len) *len = session->session_key_len;
    return session->session_key;
}

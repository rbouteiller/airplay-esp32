#include <string.h>
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

#define SRP_GENERATOR 5

// Helper: write MPI to buffer with minimum bytes (no leading zeros except for value 0)
static size_t mpi_to_bytes_min(const mbedtls_mpi *mpi, uint8_t *buf, size_t len)
{
    size_t mpi_size = mbedtls_mpi_size(mpi);
    if (mpi_size == 0) {
        if (len < 1) return 0;
        buf[0] = 0;
        return 1;
    }
    if (mpi_size > len) return 0;
    if (mbedtls_mpi_write_binary(mpi, buf, mpi_size) != 0) return 0;
    return mpi_size;
}

// Helper: write MPI to buffer, zero-padded to fixed length
static int mpi_to_bytes_padded(const mbedtls_mpi *mpi, uint8_t *buf, size_t len)
{
    size_t mpi_size = mbedtls_mpi_size(mpi);
    if (mpi_size > len) return -1;
    memset(buf, 0, len);
    return mbedtls_mpi_write_binary(mpi, buf + (len - mpi_size), mpi_size);
}

// Helper: trim leading zeros from buffer
static void trim_leading_zeros(const uint8_t *in, size_t in_len,
                               const uint8_t **out, size_t *out_len)
{
    while (in_len > 1 && *in == 0) {
        in++;
        in_len--;
    }
    *out = in;
    *out_len = in_len;
}

// Compute M1 = H(H(N)^H(g) || H(I) || s || A || B || K)
static void compute_m1(uint8_t *out,
                       const uint8_t *h_Ng_xor,
                       const uint8_t *h_I,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *A, size_t A_len,
                       const uint8_t *B, size_t B_len,
                       const uint8_t *K, size_t K_len)
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

srp_session_t *srp_session_create(void)
{
    srp_session_t *session = calloc(1, sizeof(srp_session_t));
    return session;
}

void srp_session_free(srp_session_t *session)
{
    if (session) {
        memset(session, 0, sizeof(srp_session_t));
        free(session);
    }
}

esp_err_t srp_start(srp_session_t *session, const char *username, const char *password)
{
    if (!session || !username || !password) {
        return ESP_ERR_INVALID_ARG;
    }

    mbedtls_mpi N, g, k, v, b, B, x, tmp, tmp2;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&g);
    mbedtls_mpi_init(&k);
    mbedtls_mpi_init(&v);
    mbedtls_mpi_init(&b);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_init(&tmp2);

    int ret = -1;

    // Generate random salt
    esp_fill_random(session->salt, SRP_SALT_BYTES);

    // Load N and g
    mbedtls_mpi_read_binary(&N, srp_N, sizeof(srp_N));
    mbedtls_mpi_lset(&g, SRP_GENERATOR);

    // k = H(N || pad(g))
    {
        uint8_t hash_input[SRP_PRIME_BYTES * 2];
        memcpy(hash_input, srp_N, SRP_PRIME_BYTES);
        memset(hash_input + SRP_PRIME_BYTES, 0, SRP_PRIME_BYTES);
        hash_input[SRP_PRIME_BYTES * 2 - 1] = SRP_GENERATOR;

        uint8_t k_hash[64];
        crypto_hash_sha512(k_hash, hash_input, sizeof(hash_input));
        mbedtls_mpi_read_binary(&k, k_hash, 64);
        mbedtls_mpi_mod_mpi(&k, &k, &N);
    }

    // x = H(s || H(I || ":" || P))
    {
        uint8_t inner_hash[64];
        crypto_hash_sha512_state state;
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, (const uint8_t *)username, strlen(username));
        crypto_hash_sha512_update(&state, (const uint8_t *)":", 1);
        crypto_hash_sha512_update(&state, (const uint8_t *)password, strlen(password));
        crypto_hash_sha512_final(&state, inner_hash);

        uint8_t x_hash[64];
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, session->salt, SRP_SALT_BYTES);
        crypto_hash_sha512_update(&state, inner_hash, 64);
        crypto_hash_sha512_final(&state, x_hash);

        mbedtls_mpi_read_binary(&x, x_hash, 64);
    }

    // v = g^x mod N
    if (mbedtls_mpi_exp_mod(&v, &g, &x, &N, NULL) != 0) goto cleanup;

    // Generate random b (server secret)
    {
        uint8_t b_bytes[SRP_PRIME_BYTES];
        esp_fill_random(b_bytes, sizeof(b_bytes));
        mbedtls_mpi_read_binary(&b, b_bytes, sizeof(b_bytes));
        mbedtls_mpi_mod_mpi(&b, &b, &N);
        mpi_to_bytes_padded(&b, session->server_secret, SRP_PRIME_BYTES);
    }

    // B = (k*v + g^b) mod N
    if (mbedtls_mpi_exp_mod(&tmp, &g, &b, &N, NULL) != 0) goto cleanup;
    if (mbedtls_mpi_mul_mpi(&tmp2, &k, &v) != 0) goto cleanup;
    if (mbedtls_mpi_add_mpi(&B, &tmp2, &tmp) != 0) goto cleanup;
    mbedtls_mpi_mod_mpi(&B, &B, &N);

    mpi_to_bytes_padded(&B, session->server_public_key, SRP_PRIME_BYTES);
    session->state = 1;
    ret = 0;

cleanup:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&g);
    mbedtls_mpi_free(&k);
    mbedtls_mpi_free(&v);
    mbedtls_mpi_free(&b);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&x);
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
    if (!session || !client_public_key || !client_proof || proof_len < SRP_PROOF_BYTES) {
        return ESP_ERR_INVALID_ARG;
    }

    // Store client's public key A (zero-padded)
    if (client_pk_len > SRP_PRIME_BYTES) client_pk_len = SRP_PRIME_BYTES;
    memset(session->client_public_key, 0, SRP_PRIME_BYTES);
    memcpy(session->client_public_key + (SRP_PRIME_BYTES - client_pk_len),
           client_public_key, client_pk_len);

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

    int ret = -1;

    // Load parameters
    mbedtls_mpi_read_binary(&N, srp_N, sizeof(srp_N));
    mbedtls_mpi_lset(&g, SRP_GENERATOR);
    mbedtls_mpi_read_binary(&A, session->client_public_key, SRP_PRIME_BYTES);
    mbedtls_mpi_read_binary(&B, session->server_public_key, SRP_PRIME_BYTES);
    mbedtls_mpi_read_binary(&b, session->server_secret, SRP_PRIME_BYTES);

    // Check A != 0 and A % N != 0
    if (mbedtls_mpi_cmp_int(&A, 0) == 0) {
        ESP_LOGE(TAG, "Invalid client public key (zero)");
        goto cleanup;
    }
    mbedtls_mpi_mod_mpi(&tmp, &A, &N);
    if (mbedtls_mpi_cmp_int(&tmp, 0) == 0) {
        ESP_LOGE(TAG, "Invalid client public key (multiple of N)");
        goto cleanup;
    }

    // u = H(PAD(A) || PAD(B))
    {
        uint8_t ab_concat[SRP_PRIME_BYTES * 2];
        memcpy(ab_concat, session->client_public_key, SRP_PRIME_BYTES);
        memcpy(ab_concat + SRP_PRIME_BYTES, session->server_public_key, SRP_PRIME_BYTES);
        uint8_t u_hash[64];
        crypto_hash_sha512(u_hash, ab_concat, sizeof(ab_concat));
        mbedtls_mpi_read_binary(&u, u_hash, 64);
    }

    // Recompute k = H(N || pad(g))
    {
        uint8_t hash_input[SRP_PRIME_BYTES * 2];
        memcpy(hash_input, srp_N, SRP_PRIME_BYTES);
        memset(hash_input + SRP_PRIME_BYTES, 0, SRP_PRIME_BYTES);
        hash_input[SRP_PRIME_BYTES * 2 - 1] = SRP_GENERATOR;
        uint8_t k_hash[64];
        crypto_hash_sha512(k_hash, hash_input, sizeof(hash_input));
        mbedtls_mpi_read_binary(&k, k_hash, 64);
        mbedtls_mpi_mod_mpi(&k, &k, &N);
    }

    // Recompute x = H(s || H(I || ":" || P)) for "Pair-Setup:3939"
    {
        uint8_t inner_hash[64];
        crypto_hash_sha512_state state;
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, (const uint8_t *)"Pair-Setup", 10);
        crypto_hash_sha512_update(&state, (const uint8_t *)":", 1);
        crypto_hash_sha512_update(&state, (const uint8_t *)"3939", 4);
        crypto_hash_sha512_final(&state, inner_hash);

        uint8_t x_hash[64];
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, session->salt, SRP_SALT_BYTES);
        crypto_hash_sha512_update(&state, inner_hash, 64);
        crypto_hash_sha512_final(&state, x_hash);

        mbedtls_mpi_read_binary(&x, x_hash, 64);
    }

    // v = g^x mod N
    if (mbedtls_mpi_exp_mod(&v, &g, &x, &N, NULL) != 0) goto cleanup;

    // S = (A * v^u)^b mod N
    if (mbedtls_mpi_exp_mod(&tmp, &v, &u, &N, NULL) != 0) goto cleanup;
    if (mbedtls_mpi_mul_mpi(&tmp2, &A, &tmp) != 0) goto cleanup;
    mbedtls_mpi_mod_mpi(&tmp2, &tmp2, &N);
    if (mbedtls_mpi_exp_mod(&S, &tmp2, &b, &N, NULL) != 0) goto cleanup;

    // K = H(S)
    uint8_t S_bytes[SRP_PRIME_BYTES];
    size_t S_len = mpi_to_bytes_min(&S, S_bytes, sizeof(S_bytes));
    crypto_hash_sha512(session->session_key, S_bytes, S_len);
    session->session_key_len = 64;

    // Compute expected M1 = H(H(N)^H(g) || H(I) || s || A || B || K)
    uint8_t expected_m1[64];
    {
        // H(N)
        uint8_t h_N[64];
        crypto_hash_sha512(h_N, srp_N, sizeof(srp_N));

        // H(g)
        uint8_t g_byte = SRP_GENERATOR;
        uint8_t h_g[64];
        crypto_hash_sha512(h_g, &g_byte, 1);

        // H(N) ^ H(g)
        uint8_t h_Ng_xor[64];
        for (int i = 0; i < 64; i++) {
            h_Ng_xor[i] = h_N[i] ^ h_g[i];
        }

        // H(I) where I = "Pair-Setup"
        uint8_t h_I[64];
        crypto_hash_sha512(h_I, (const uint8_t *)"Pair-Setup", 10);

        // Get minimal representations
        const uint8_t *salt_ptr;
        size_t salt_len;
        trim_leading_zeros(session->salt, SRP_SALT_BYTES, &salt_ptr, &salt_len);

        uint8_t A_bytes[SRP_PRIME_BYTES];
        uint8_t B_bytes[SRP_PRIME_BYTES];
        size_t A_len = mpi_to_bytes_min(&A, A_bytes, sizeof(A_bytes));
        size_t B_len = mpi_to_bytes_min(&B, B_bytes, sizeof(B_bytes));

        compute_m1(expected_m1, h_Ng_xor, h_I,
                   salt_ptr, salt_len,
                   A_bytes, A_len,
                   B_bytes, B_len,
                   session->session_key, 64);
    }

    // Verify client proof
    if (memcmp(client_proof, expected_m1, SRP_PROOF_BYTES) != 0) {
        ESP_LOGE(TAG, "Client proof verification failed");
        goto cleanup;
    }

    memcpy(session->proof_m1, client_proof, SRP_PROOF_BYTES);
    {
        uint8_t A_bytes[SRP_PRIME_BYTES];
        size_t A_len = mpi_to_bytes_min(&A, A_bytes, sizeof(A_bytes));

        crypto_hash_sha512_state state;
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, A_bytes, A_len);
        crypto_hash_sha512_update(&state, session->proof_m1, SRP_PROOF_BYTES);
        crypto_hash_sha512_update(&state, session->session_key, session->session_key_len);
        crypto_hash_sha512_final(&state, session->proof_m2);
    }

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

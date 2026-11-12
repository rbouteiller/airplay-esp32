// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "sendspin_cpace.h"

#include <string.h>

#include "esp_log.h"
#include "sodium.h"

static const char *TAG = "sendspin-cpace";

/* Domain separators, byte-exact with the reference implementation. */
static const uint8_t DSI[] = {'C', 'P', 'a', 'c', 'e', '2', '5', '5'};
static const uint8_t DSI_ISK[] = {'C', 'P', 'a', 'c', 'e', '2',
                                  '5', '5', '_', 'I', 'S', 'K'};
static const uint8_t MAC_LABEL[] = {'C', 'P', 'a', 'c', 'e', 'M', 'a', 'c'};

#define SHA512_BLOCK_BYTES 128

/* ------------------------------------------------------------------------- */
/* GF(2^255 - 19) arithmetic                                                  */
/*                                                                            */
/* Elligator2 needs field inversion and a Legendre symbol, neither of which */
/* libsodium exposes -- its only elligator entry point clears the cofactor, */
/* which CPace must not do.  Eight 32-bit limbs, little-endian, always kept */
/* fully reduced.  Deliberately plain rather than fast: this runs a handful of
 */
/* times during an interactive pairing, and it is fuzzed against Python's */
/* arbitrary-precision integers on the host. */
/* ------------------------------------------------------------------------- */

typedef uint32_t fe[8];

static const fe FE_Q = {0xFFFFFFEDu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                        0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x7FFFFFFFu};
/* q - 2, the Fermat inversion exponent. */
static const fe FE_Q_MINUS_2 = {0xFFFFFFEBu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                                0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                                0xFFFFFFFFu, 0x7FFFFFFFu};
/* (q - 1) / 2, the Legendre symbol exponent. */
static const fe FE_LEGENDRE = {0xFFFFFFF6u, 0xFFFFFFFFu, 0xFFFFFFFFu,
                               0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                               0xFFFFFFFFu, 0x3FFFFFFFu};

static void fe_zero(fe r) {
  memset(r, 0, sizeof(fe));
}

static void fe_set_u32(fe r, uint32_t v) {
  fe_zero(r);
  r[0] = v;
}

/* Conditionally subtract q until the value is canonical.  The caller only ever
   hands in something below 2^256, which needs at most two subtractions. */
static void fe_canonical(fe a) {
  for (int k = 0; k < 3; k++) {
    fe tmp;
    int64_t borrow = 0;
    for (int i = 0; i < 8; i++) {
      int64_t cur = (int64_t)a[i] - (int64_t)FE_Q[i] - borrow;
      tmp[i] = (uint32_t)cur;
      borrow = (cur < 0) ? 1 : 0;
    }
    if (borrow == 0) {
      memcpy(a, tmp, sizeof(fe));
    }
  }
}

/* a += v, returning the carry out of the top limb. */
static uint32_t fe_add_u64(fe a, uint64_t v) {
  uint64_t carry = v;
  for (int i = 0; i < 8; i++) {
    uint64_t cur = (uint64_t)a[i] + (carry & 0xFFFFFFFFu);
    carry >>= 32;
    carry += (cur >> 32);
    a[i] = (uint32_t)cur;
  }
  return (uint32_t)carry;
}

static void fe_add(fe r, const fe a, const fe b) {
  uint64_t carry = 0;
  for (int i = 0; i < 8; i++) {
    uint64_t cur = (uint64_t)a[i] + (uint64_t)b[i] + carry;
    r[i] = (uint32_t)cur;
    carry = cur >> 32;
  }
  /* 2^256 = 38 (mod 2^255 - 19), so anything above the top limb folds back. */
  uint32_t c = (uint32_t)carry;
  while (c != 0) {
    c = fe_add_u64(r, 38ULL * (uint64_t)c);
  }
  fe_canonical(r);
}

static void fe_sub(fe r, const fe a, const fe b) {
  int64_t borrow = 0;
  for (int i = 0; i < 8; i++) {
    int64_t cur = (int64_t)a[i] - (int64_t)b[i] - borrow;
    r[i] = (uint32_t)cur;
    borrow = (cur < 0) ? 1 : 0;
  }
  if (borrow != 0) {
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
      uint64_t cur = (uint64_t)r[i] + (uint64_t)FE_Q[i] + carry;
      r[i] = (uint32_t)cur;
      carry = cur >> 32;
    }
  }
}

static void fe_mul(fe r, const fe a, const fe b) {
  uint32_t t[16];
  memset(t, 0, sizeof(t));
  for (int i = 0; i < 8; i++) {
    uint64_t carry = 0;
    for (int j = 0; j < 8; j++) {
      /* Each term is bounded so the sum is exactly representable in 64 bits. */
      uint64_t cur =
          (uint64_t)t[i + j] + (uint64_t)a[i] * (uint64_t)b[j] + carry;
      t[i + j] = (uint32_t)cur;
      carry = cur >> 32;
    }
    for (int k = i + 8; carry != 0 && k < 16; k++) {
      uint64_t cur = (uint64_t)t[k] + carry;
      t[k] = (uint32_t)cur;
      carry = cur >> 32;
    }
  }
  /* Fold the high half back in: 2^256 = 38 (mod q). */
  uint64_t carry = 0;
  for (int i = 0; i < 8; i++) {
    uint64_t cur = (uint64_t)t[i] + 38ULL * (uint64_t)t[i + 8] + carry;
    r[i] = (uint32_t)cur;
    carry = cur >> 32;
  }
  uint32_t c = (uint32_t)carry;
  while (c != 0) {
    c = fe_add_u64(r, 38ULL * (uint64_t)c);
  }
  fe_canonical(r);
}

static void fe_sq(fe r, const fe a) {
  fe_mul(r, a, a);
}

/* Square-and-multiply over a public, fixed exponent, so no constant-time
   ladder is needed -- the exponents here are protocol constants. */
static void fe_pow(fe r, const fe a, const fe e) {
  fe acc;
  fe_set_u32(acc, 1);
  for (int bit = 255; bit >= 0; bit--) {
    fe_sq(acc, acc);
    if ((e[bit >> 5] >> (bit & 31)) & 1u) {
      fe_mul(acc, acc, a);
    }
  }
  memcpy(r, acc, sizeof(fe));
}

/* RFC 9380's inv0: the inverse, mapping zero to zero. */
static void fe_inv0(fe r, const fe a) {
  fe_pow(r, a, FE_Q_MINUS_2);
}

static void fe_from_bytes_le(fe r, const uint8_t in[32]) {
  for (int i = 0; i < 8; i++) {
    r[i] = (uint32_t)in[4 * i] | ((uint32_t)in[4 * i + 1] << 8) |
           ((uint32_t)in[4 * i + 2] << 16) | ((uint32_t)in[4 * i + 3] << 24);
  }
}

static void fe_to_bytes_le(uint8_t out[32], const fe a) {
  for (int i = 0; i < 8; i++) {
    out[4 * i] = (uint8_t)(a[i] & 0xFF);
    out[4 * i + 1] = (uint8_t)((a[i] >> 8) & 0xFF);
    out[4 * i + 2] = (uint8_t)((a[i] >> 16) & 0xFF);
    out[4 * i + 3] = (uint8_t)((a[i] >> 24) & 0xFF);
  }
}

/* ------------------------------------------------------------------------- */
/* Elligator2 on Curve25519                                                   */
/* ------------------------------------------------------------------------- */

#define CURVE_A 486662u
/* A is even, so A/2 mod q is just A/2 -- no inversion of 2 required. */
#define CURVE_A_HALF 243331u

/**
 * Map a uniform 32-byte string to a Curve25519 x-coordinate.
 *
 * Note there is no cofactor clearing: CPace feeds this straight to X25519 as
 * the group generator, and clearing would change the point.  That is why
 * libsodium's crypto_core_ed25519_from_uniform() cannot stand in here.
 */
static void elligator2(uint8_t out[32], const uint8_t hash[32]) {
  uint8_t buf[32];
  memcpy(buf, hash, 32);
  buf[31] &= 0x7F; /* 255-bit field: the top bit is not part of the value. */

  fe r;
  fe_from_bytes_le(r, buf);
  fe_canonical(r);

  fe one, a_fe;
  fe_set_u32(one, 1);
  fe_set_u32(a_fe, CURVE_A);

  /* t = 1 + Z * r^2, with Z = 2. */
  fe t;
  fe_sq(t, r);
  fe_add(t, t, t);
  fe_add(t, t, one);

  /* v = -A / t */
  fe v;
  fe_inv0(v, t);
  fe_mul(v, v, a_fe);
  fe zero;
  fe_zero(zero);
  fe_sub(v, zero, v);

  /* w = v^3 + A*v^2 + v  (curve is y^2 = x^3 + A x^2 + x, so B = 1) */
  fe v2, w, tmp;
  fe_sq(v2, v);
  fe_mul(w, v2, v);
  fe_mul(tmp, v2, a_fe);
  fe_add(w, w, tmp);
  fe_add(w, w, v);

  /* eps is the Legendre symbol: 1, q-1 or 0. */
  fe eps;
  fe_pow(eps, w, FE_LEGENDRE);

  /* x = eps*v - (1 - eps) * A/2 */
  fe x, one_minus_eps, a_half;
  fe_set_u32(a_half, CURVE_A_HALF);
  fe_mul(x, eps, v);
  fe_sub(one_minus_eps, one, eps);
  fe_mul(tmp, one_minus_eps, a_half);
  fe_sub(x, x, tmp);

  fe_to_bytes_le(out, x);
  sodium_memzero(buf, sizeof(buf));
}

/* ------------------------------------------------------------------------- */
/* LEB128 length-prefixed concatenation                                       */
/* ------------------------------------------------------------------------- */

/* Every field CPace hashes is length-prefixed so that the transcript cannot be
   re-split; the prefix is a VLQ with the continuation bit in the high bit. */
static bool lv_append(uint8_t *buf, size_t cap, size_t *len,
                      const uint8_t *data, size_t data_len) {
  size_t length = data_len;
  do {
    uint8_t byte = (uint8_t)(length & 0x7F);
    length >>= 7;
    if (length != 0) {
      byte |= 0x80;
    }
    if (*len >= cap) {
      return false;
    }
    buf[(*len)++] = byte;
  } while (length != 0);

  if (data_len > cap - *len) {
    return false;
  }
  if (data_len != 0) {
    memcpy(buf + *len, data, data_len);
    *len += data_len;
  }
  return true;
}

static size_t lv_size(size_t data_len) {
  size_t n = 1;
  size_t length = data_len >> 7;
  while (length != 0) {
    n++;
    length >>= 7;
  }
  return n + data_len;
}

/* ------------------------------------------------------------------------- */
/* Generator                                                                  */
/* ------------------------------------------------------------------------- */

/* The zero padding pushes the password past the first SHA-512 block, so that a
   guess cannot be tested with a partial-block shortcut. */
static bool calculate_generator(uint8_t out[32], const uint8_t *prs,
                                size_t prs_len, const uint8_t *sid,
                                size_t sid_len) {
  uint8_t buf[320];
  size_t len = 0;

  size_t zpad = 0;
  size_t used = lv_size(prs_len) + lv_size(sizeof(DSI));
  if (used + 1 < SHA512_BLOCK_BYTES) {
    zpad = SHA512_BLOCK_BYTES - 1 - used;
  }

  static const uint8_t zeros[SHA512_BLOCK_BYTES] = {0};
  if (zpad > sizeof(zeros)) {
    return false;
  }

  bool ok = lv_append(buf, sizeof(buf), &len, DSI, sizeof(DSI)) &&
            lv_append(buf, sizeof(buf), &len, prs, prs_len) &&
            lv_append(buf, sizeof(buf), &len, zeros, zpad) &&
            /* The channel identifier is unused by Sendspin, so it is empty. */
            lv_append(buf, sizeof(buf), &len, NULL, 0) &&
            lv_append(buf, sizeof(buf), &len, sid, sid_len);
  if (!ok) {
    return false;
  }

  uint8_t hash[crypto_hash_sha512_BYTES];
  crypto_hash_sha512(hash, buf, len);
  elligator2(out, hash);

  sodium_memzero(buf, sizeof(buf));
  sodium_memzero(hash, sizeof(hash));
  return true;
}

/**
 * X25519 that also rejects the identity.
 *
 * libsodium already returns -1 when the result is all zeroes, which covers
 * both a low-order peer share and a low-order generator.
 */
static bool scalar_mult_vfy(uint8_t out[32], const uint8_t scalar[32],
                            const uint8_t point[32]) {
  /* The scalar is used unclamped: X25519 clamps internally, and CPace
     specifies a plain uniform 32-byte scalar. */
  return crypto_scalarmult_curve25519(out, scalar, point) == 0;
}

/* ------------------------------------------------------------------------- */
/* Public API                                                                 */
/* ------------------------------------------------------------------------- */

esp_err_t sendspin_cpace_start(sendspin_cpace_t *cp, sendspin_cpace_role_t role,
                               const uint8_t *prs, size_t prs_len,
                               const uint8_t *sid, size_t sid_len,
                               const uint8_t *ad, size_t ad_len) {
  if (cp == NULL || sid_len > SENDSPIN_CPACE_SID_MAX ||
      ad_len > SENDSPIN_CPACE_AD_MAX) {
    return ESP_ERR_INVALID_ARG;
  }

  memset(cp, 0, sizeof(*cp));
  cp->role = role;
  cp->sid_len = sid_len;
  memcpy(cp->sid, sid, sid_len);
  cp->ad_len = ad_len;
  if (ad_len != 0) {
    memcpy(cp->ad, ad, ad_len);
  }

  uint8_t generator[32];
  if (!calculate_generator(generator, prs, prs_len, sid, sid_len)) {
    return ESP_ERR_INVALID_SIZE;
  }

  randombytes_buf(cp->scalar, sizeof(cp->scalar));
  if (!scalar_mult_vfy(cp->public_share, cp->scalar, generator)) {
    /* A low-order generator would make every share the identity. */
    ESP_LOGE(TAG, "password hashed to a low-order generator");
    sendspin_cpace_reset(cp);
    return ESP_FAIL;
  }

  sodium_memzero(generator, sizeof(generator));
  cp->started = true;
  return ESP_OK;
}

/* The transcript is ordered by role -- the initiator's side always first --
   not by share value. */
static void transcript_sides(const sendspin_cpace_t *cp, const uint8_t **share0,
                             const uint8_t **ad0, size_t *ad0_len,
                             const uint8_t **share1, const uint8_t **ad1,
                             size_t *ad1_len) {
  if (cp->role == SENDSPIN_CPACE_INITIATOR) {
    *share0 = cp->public_share;
    *ad0 = cp->ad;
    *ad0_len = cp->ad_len;
    *share1 = cp->peer_share;
    *ad1 = cp->peer_ad;
    *ad1_len = cp->peer_ad_len;
  } else {
    *share0 = cp->peer_share;
    *ad0 = cp->peer_ad;
    *ad0_len = cp->peer_ad_len;
    *share1 = cp->public_share;
    *ad1 = cp->ad;
    *ad1_len = cp->ad_len;
  }
}

esp_err_t sendspin_cpace_derive(sendspin_cpace_t *cp,
                                const uint8_t peer_share[32],
                                const uint8_t *peer_ad, size_t peer_ad_len) {
  if (cp == NULL || !cp->started || cp->derived ||
      peer_ad_len > SENDSPIN_CPACE_AD_MAX) {
    return ESP_ERR_INVALID_STATE;
  }

  memcpy(cp->peer_share, peer_share, SENDSPIN_CPACE_SHARE_LEN);
  cp->peer_ad_len = peer_ad_len;
  if (peer_ad_len != 0) {
    memcpy(cp->peer_ad, peer_ad, peer_ad_len);
  }

  uint8_t shared[32];
  bool ok = scalar_mult_vfy(shared, cp->scalar, peer_share);
  /* Single-use: burn the scalar before anything can fail. */
  sodium_memzero(cp->scalar, sizeof(cp->scalar));
  if (!ok) {
    ESP_LOGW(TAG, "peer share encodes a low-order point");
    return ESP_ERR_INVALID_RESPONSE;
  }

  const uint8_t *s0, *a0, *s1, *a1;
  size_t a0_len, a1_len;
  transcript_sides(cp, &s0, &a0, &a0_len, &s1, &a1, &a1_len);

  uint8_t buf[256];
  size_t len = 0;
  ok = lv_append(buf, sizeof(buf), &len, DSI_ISK, sizeof(DSI_ISK)) &&
       lv_append(buf, sizeof(buf), &len, cp->sid, cp->sid_len) &&
       lv_append(buf, sizeof(buf), &len, shared, sizeof(shared)) &&
       lv_append(buf, sizeof(buf), &len, s0, SENDSPIN_CPACE_SHARE_LEN) &&
       lv_append(buf, sizeof(buf), &len, a0, a0_len) &&
       lv_append(buf, sizeof(buf), &len, s1, SENDSPIN_CPACE_SHARE_LEN) &&
       lv_append(buf, sizeof(buf), &len, a1, a1_len);
  sodium_memzero(shared, sizeof(shared));
  if (!ok) {
    return ESP_ERR_INVALID_SIZE;
  }
  crypto_hash_sha512(cp->isk, buf, len);
  sodium_memzero(buf, sizeof(buf));

  /* The MAC key is a plain concatenation, without the length prefixes. */
  uint8_t mac_input[sizeof(MAC_LABEL) + SENDSPIN_CPACE_SID_MAX +
                    SENDSPIN_CPACE_ISK_LEN];
  size_t mac_len = 0;
  memcpy(mac_input, MAC_LABEL, sizeof(MAC_LABEL));
  mac_len += sizeof(MAC_LABEL);
  memcpy(mac_input + mac_len, cp->sid, cp->sid_len);
  mac_len += cp->sid_len;
  memcpy(mac_input + mac_len, cp->isk, sizeof(cp->isk));
  mac_len += sizeof(cp->isk);
  crypto_hash_sha512(cp->mac_key, mac_input, mac_len);
  sodium_memzero(mac_input, sizeof(mac_input));

  cp->derived = true;
  return ESP_OK;
}

/* Ta authenticates the initiator's (share, ad); Tb the responder's. */
static esp_err_t cpace_mac(const sendspin_cpace_t *cp, bool own,
                           uint8_t out[SENDSPIN_CPACE_TAG_LEN]) {
  const uint8_t *s0, *a0, *s1, *a1;
  size_t a0_len, a1_len;
  transcript_sides(cp, &s0, &a0, &a0_len, &s1, &a1, &a1_len);

  bool want_first = (own == (cp->role == SENDSPIN_CPACE_INITIATOR));
  const uint8_t *share = want_first ? s0 : s1;
  const uint8_t *ad = want_first ? a0 : a1;
  size_t ad_len = want_first ? a0_len : a1_len;

  uint8_t buf[64];
  size_t len = 0;
  if (!lv_append(buf, sizeof(buf), &len, share, SENDSPIN_CPACE_SHARE_LEN) ||
      !lv_append(buf, sizeof(buf), &len, ad, ad_len)) {
    return ESP_ERR_INVALID_SIZE;
  }

  crypto_auth_hmacsha512_state st;
  crypto_auth_hmacsha512_init(&st, cp->mac_key, sizeof(cp->mac_key));
  crypto_auth_hmacsha512_update(&st, buf, len);
  crypto_auth_hmacsha512_final(&st, out);
  return ESP_OK;
}

esp_err_t sendspin_cpace_tag(const sendspin_cpace_t *cp,
                             uint8_t out[SENDSPIN_CPACE_TAG_LEN]) {
  if (cp == NULL || !cp->derived) {
    return ESP_ERR_INVALID_STATE;
  }
  return cpace_mac(cp, true, out);
}

bool sendspin_cpace_verify(const sendspin_cpace_t *cp,
                           const uint8_t peer_tag[SENDSPIN_CPACE_TAG_LEN]) {
  if (cp == NULL || !cp->derived) {
    return false;
  }
  /* A reflected share would make the expected peer tag our own. */
  if (cp->ad_len == cp->peer_ad_len &&
      sodium_memcmp(cp->public_share, cp->peer_share,
                    SENDSPIN_CPACE_SHARE_LEN) == 0 &&
      (cp->ad_len == 0 ||
       sodium_memcmp(cp->ad, cp->peer_ad, cp->ad_len) == 0)) {
    return false;
  }

  uint8_t expected[SENDSPIN_CPACE_TAG_LEN];
  if (cpace_mac(cp, false, expected) != ESP_OK) {
    return false;
  }
  bool ok = sodium_memcmp(expected, peer_tag, sizeof(expected)) == 0;
  sodium_memzero(expected, sizeof(expected));
  return ok;
}

const uint8_t *sendspin_cpace_isk(const sendspin_cpace_t *cp) {
  return (cp != NULL && cp->derived) ? cp->isk : NULL;
}

void sendspin_cpace_reset(sendspin_cpace_t *cp) {
  if (cp != NULL) {
    sodium_memzero(cp, sizeof(*cp));
  }
}

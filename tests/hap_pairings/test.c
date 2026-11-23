// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/* The real HomeKit pairing store and /pair-add, /pair-remove, /pair-list
 * handlers against an in-memory NVS that survives a simulated reboot. */

#include "mocks.h"

#include <assert.h>

/* The store keeps its state in statics; compiling it in here lets a test
 * "reboot" by dropping them and loading again from the mock NVS. */
#define TAG TAG_manage // each file has its own static TAG
#include "hap_pair_manage.c"
#undef TAG
#define TAG TAG_store
#include "hap_pairings.c"
#undef TAG
#include "tlv8.c"

int mock_mutex_token, mock_locked;
int64_t mock_now_us;

#define MINUTES(m) ((int64_t)(m) * 60 * 1000000)

int xSemaphoreTake(SemaphoreHandle_t s, int ticks) {
  (void)s;
  (void)ticks;
  assert(!mock_locked && "the store must never lock twice");
  mock_locked = 1;
  return 1;
}

int xSemaphoreGive(SemaphoreHandle_t s) {
  (void)s;
  assert(mock_locked);
  mock_locked = 0;
  return 1;
}

static struct {
  bool present;
  uint8_t blob[4096];
  size_t len;
  bool fail_writes;
  int writes;
} nvs;

esp_err_t nvs_open(const char *ns, nvs_open_mode_t mode, nvs_handle_t *h) {
  assert(strcmp(ns, "homekit") == 0);
  *h = 1;
  if (mode == NVS_READONLY && !nvs.present) {
    return ESP_ERR_NVS_NOT_FOUND;
  }
  return ESP_OK;
}

esp_err_t nvs_get_blob(nvs_handle_t h, const char *key, void *out,
                       size_t *len) {
  (void)h;
  assert(strcmp(key, "store") == 0);
  if (!nvs.present) {
    return ESP_ERR_NVS_NOT_FOUND;
  }
  if (*len < nvs.len) {
    return ESP_FAIL;
  }
  memcpy(out, nvs.blob, nvs.len);
  *len = nvs.len;
  return ESP_OK;
}

esp_err_t nvs_set_blob(nvs_handle_t h, const char *key, const void *v,
                       size_t len) {
  (void)h;
  assert(strcmp(key, "store") == 0 && len <= sizeof(nvs.blob));
  if (nvs.fail_writes) {
    return ESP_FAIL;
  }
  memcpy(nvs.blob, v, len);
  nvs.len = len;
  nvs.present = true;
  nvs.writes++;
  return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t h, const char *key) {
  (void)h;
  assert(strcmp(key, "store") == 0);
  if (nvs.fail_writes) {
    return ESP_FAIL;
  }
  if (!nvs.present) {
    return ESP_ERR_NVS_NOT_FOUND;
  }
  nvs.present = false;
  nvs.len = 0;
  nvs.writes++;
  return ESP_OK;
}

static int changes;
static void on_change(void) {
  assert(!mock_locked && "change callback must run outside the lock");
  changes++;
}

static void reboot(void) {
  free(s_store);
  s_store = NULL;
  s_lock = NULL;
  s_setup_seen = false; // RAM only: a restart ends any setup
  mock_now_us += MINUTES(1);
  assert(hap_pairings_init() == ESP_OK);
  hap_pairings_set_change_cb(on_change);
}

static void wipe(void) {
  memset(&nvs, 0, sizeof(nvs));
  changes = 0;
  reboot();
}

#define ID(s) (const uint8_t *)(s), strlen(s)

static void key(uint8_t out[32], uint8_t seed) {
  for (int i = 0; i < 32; i++) {
    out[i] = (uint8_t)(seed + i);
  }
}

static void test_store(void) {
  uint8_t ka[32], kb[32], got[32];
  key(ka, 1);
  key(kb, 2);
  uint8_t perms = 0xFF;

  wipe();
  assert(hap_pairings_count() == 0);
  assert(!hap_pairings_find(ID("A"), got, &perms));
  assert(!hap_homekit_access_control() && hap_homekit_acl() == 0);

  // Bad identifiers are refused outright.
  assert(hap_pairings_add(NULL, 0, ka, 1) == ESP_ERR_INVALID_ARG);
  char long_id[HAP_PAIRING_ID_MAX + 1];
  memset(long_id, 'x', sizeof(long_id) - 1);
  long_id[sizeof(long_id) - 1] = '\0';
  assert(hap_pairings_add(ID(long_id), ka, 1) == ESP_ERR_INVALID_ARG);

  // Added, found, and still there after a reboot.
  assert(hap_pairings_add(ID("A"), ka, HAP_PERM_ADMIN) == ESP_OK);
  assert(hap_pairings_find(ID("A"), got, &perms));
  assert(memcmp(got, ka, 32) == 0 && perms == HAP_PERM_ADMIN);
  assert(!hap_pairings_find(ID("AB"), NULL, NULL)); // no prefix matches
  reboot();
  assert(hap_pairings_count() == 1 && hap_pairings_admin_count() == 1);
  assert(hap_pairings_find(ID("A"), got, &perms) && perms == HAP_PERM_ADMIN);

  // Same identifier, another key: refused. Same key: permissions updated,
  // and an unchanged add does not write flash.
  assert(hap_pairings_add(ID("A"), kb, HAP_PERM_ADMIN) ==
         ESP_ERR_INVALID_STATE);
  int writes = nvs.writes;
  assert(hap_pairings_add(ID("A"), ka, HAP_PERM_ADMIN) == ESP_OK);
  assert(nvs.writes == writes);
  assert(hap_pairings_add(ID("B"), kb, HAP_PERM_USER) == ESP_OK);
  assert(hap_pairings_add(ID("B"), kb, HAP_PERM_ADMIN) == ESP_OK);
  assert(hap_pairings_admin_count() == 2);
  assert(hap_pairings_add(ID("B"), kb, HAP_PERM_USER) == ESP_OK);
  assert(hap_pairings_admin_count() == 1);

  // put (pair-setup) replaces a re-keyed controller in place: the only
  // admin never goes missing, so access control survives.
  assert(hap_homekit_set_config(true, 1) == ESP_OK);
  assert(hap_pairings_put(ID("A"), kb, HAP_PERM_ADMIN) == ESP_OK);
  assert(hap_pairings_find(ID("A"), got, NULL) && memcmp(got, kb, 32) == 0);
  assert(hap_homekit_access_control() && hap_pairings_count() == 2);
  assert(hap_pairings_put(ID("A"), ka, HAP_PERM_ADMIN) == ESP_OK);
  assert(hap_homekit_set_config(false, 0) == ESP_OK);

  // A failed write leaves RAM as it was.
  nvs.fail_writes = true;
  assert(hap_pairings_add(ID("C"), kb, HAP_PERM_USER) != ESP_OK);
  assert(hap_pairings_count() == 2 && !hap_pairings_find(ID("C"), NULL, NULL));
  assert(hap_pairings_remove(ID("B")) != ESP_OK);
  assert(hap_pairings_find(ID("B"), NULL, NULL));
  // ... and is not announced: mDNS must not advertise what a reboot loses.
  changes = 0;
  assert(hap_homekit_set_config(true, 2) != ESP_OK);
  assert(!hap_homekit_access_control() && hap_homekit_acl() == 0);
  assert(hap_pairings_clear() != ESP_OK);
  assert(hap_pairings_count() == 2);
  assert(hap_pairings_claim(ID("new-home"), kb, HAP_PERM_ADMIN, false) !=
         ESP_OK);
  assert(hap_pairings_count() == 2 && hap_pairings_find(ID("A"), NULL, NULL));
  assert(changes == 0);
  nvs.fail_writes = false;

  // Full at 16.
  for (int i = hap_pairings_count(); i < HAP_PAIRINGS_MAX; i++) {
    char id[16];
    snprintf(id, sizeof(id), "c%d", i);
    assert(hap_pairings_add(ID(id), kb, HAP_PERM_USER) == ESP_OK);
  }
  assert(hap_pairings_add(ID("one-too-many"), kb, HAP_PERM_USER) ==
         ESP_ERR_NO_MEM);

  // Removing a user leaves the rest, in order.
  assert(hap_pairings_remove(ID("B")) == ESP_OK);
  assert(hap_pairings_remove(ID("B")) == ESP_ERR_NOT_FOUND);
  hap_pairing_t snap[HAP_PAIRINGS_MAX];
  size_t n = hap_pairings_snapshot(snap, HAP_PAIRINGS_MAX);
  assert(n == HAP_PAIRINGS_MAX - 1);
  assert(snap[0].id_len == 1 && snap[0].id[0] == 'A');
  assert(memcmp(snap[1].id, "c2", 2) == 0);

  // HomeKit configuration: persisted, and every change is announced.
  changes = 0;
  assert(hap_homekit_set_config(true, 2) == ESP_OK);
  assert(changes == 1);
  assert(hap_homekit_set_config(true, 2) == ESP_OK);
  assert(changes == 1); // nothing changed, nothing announced
  reboot();
  assert(hap_homekit_access_control() && hap_homekit_acl() == 2);

  // Removing the last admin unpairs the accessory entirely.
  changes = 0;
  assert(hap_pairings_remove(ID("A")) == ESP_OK);
  assert(hap_pairings_count() == 0);
  assert(!hap_homekit_access_control() && hap_homekit_acl() == 0);
  assert(changes == 1);
  reboot();
  assert(hap_pairings_count() == 0 && !hap_homekit_access_control());

  // Clear forgets everything.
  assert(hap_pairings_add(ID("A"), ka, HAP_PERM_ADMIN) == ESP_OK);
  assert(hap_homekit_set_config(true, 1) == ESP_OK);
  changes = 0;
  assert(hap_pairings_clear() == ESP_OK);
  assert(changes == 1 && hap_pairings_count() == 0);
  reboot();
  assert(hap_pairings_count() == 0 && !hap_homekit_access_control());
  assert(hap_pairings_clear() == ESP_OK); // nothing stored: still fine

  // Claim, with no setup in progress: starts over, even for a controller
  // already stored with this key (the same iPhone adding the speaker to its
  // next home). The configuration stays: /configure may have come first.
  uint8_t kc[32];
  key(kc, 3);
  assert(hap_pairings_add(ID("A"), ka, HAP_PERM_ADMIN) == ESP_OK);
  assert(hap_pairings_add(ID("B"), kb, HAP_PERM_USER) == ESP_OK);
  assert(hap_homekit_set_config(true, 1) == ESP_OK);
  assert(hap_pairings_claim(ID("A"), ka, HAP_PERM_ADMIN, false) == ESP_OK);
  assert(hap_pairings_count() == 1 && hap_homekit_access_control());
  assert(!hap_pairings_find(ID("B"), NULL, NULL));
  // Within five minutes of it, a claim joins: the same setup again.
  mock_now_us += MINUTES(4);
  assert(hap_pairings_claim(ID("B"), kb, HAP_PERM_USER, false) == ESP_OK);
  assert(hap_pairings_claim(ID("A"), kb, HAP_PERM_ADMIN, false) == ESP_OK);
  assert(hap_pairings_count() == 2); // A re-keyed in place, not dropped
  assert(hap_pairings_find(ID("A"), got, NULL) && memcmp(got, kb, 32) == 0);
  // A joining session never starts over, however long it has been...
  mock_now_us += MINUTES(30);
  assert(hap_pairings_claim(ID("C"), kc, HAP_PERM_USER, true) == ESP_OK);
  assert(hap_pairings_count() == 3);
  // ... and it keeps the window open; once that closes, a claim starts over.
  mock_now_us += MINUTES(5);
  assert(hap_pairings_claim(ID("C"), kc, HAP_PERM_ADMIN, false) == ESP_OK);
  assert(hap_pairings_count() == 1);
  // Already the whole set: nothing to write.
  mock_now_us += MINUTES(10);
  int before = nvs.writes;
  assert(hap_pairings_claim(ID("C"), kc, HAP_PERM_ADMIN, false) == ESP_OK);
  assert(nvs.writes == before);
  assert(hap_homekit_set_config(false, 0) == ESP_OK);
  // A restart ends a setup in progress.
  assert(hap_pairings_add(ID("B"), kb, HAP_PERM_USER) == ESP_OK);
  reboot();
  assert(hap_pairings_claim(ID("A"), ka, HAP_PERM_ADMIN, false) == ESP_OK);
  assert(hap_pairings_count() == 1);
  // Claiming an unpaired accessory is announced: it is now paired.
  assert(hap_pairings_clear() == ESP_OK);
  changes = 0;
  assert(hap_pairings_claim(ID("C"), ka, HAP_PERM_ADMIN, false) == ESP_OK);
  assert(changes == 1);
  reboot();
  assert(hap_pairings_count() == 1 && !hap_pairings_find(ID("A"), NULL, NULL));
  assert(hap_pairings_find(ID("C"), NULL, &perms) && perms == HAP_PERM_ADMIN);

  // A blob of the wrong size or version is ignored rather than trusted.
  assert(hap_pairings_add(ID("A"), ka, HAP_PERM_ADMIN) == ESP_OK);
  nvs.blob[0] = 99;
  reboot();
  assert(hap_pairings_count() == 0);
  nvs.blob[0] = STORE_VERSION;
  nvs.blob[3] = HAP_PAIRINGS_MAX + 1; // count past the table
  reboot();
  assert(hap_pairings_count() == 0);
  nvs.blob[3] = 1;
  nvs.len -= 1;
  reboot();
  assert(hap_pairings_count() == 0);

  printf("PASS: pairing store\n");
}

/* ---- /pair-add, /pair-remove, /pair-list ---- */

static size_t request(uint8_t *buf, uint8_t method, const char *id,
                      const uint8_t *pk, int perms) {
  tlv8_encoder_t enc;
  tlv8_encoder_init(&enc, buf, 256);
  tlv8_encode_byte(&enc, TLV_TYPE_STATE, 1);
  tlv8_encode_byte(&enc, TLV_TYPE_METHOD, method);
  if (id) {
    tlv8_encode(&enc, TLV_TYPE_IDENTIFIER, (const uint8_t *)id, strlen(id));
  }
  if (pk) {
    tlv8_encode(&enc, TLV_TYPE_PUBLIC_KEY, pk, 32);
  }
  if (perms >= 0) {
    tlv8_encode_byte(&enc, TLV_TYPE_PERMISSIONS, (uint8_t)perms);
  }
  return tlv8_encoder_size(&enc);
}

// Error code in a response, 0 for success; asserts State M2.
static int response_error(const uint8_t *out, size_t len) {
  size_t l = 0;
  const uint8_t *state = tlv8_find(out, len, TLV_TYPE_STATE, &l);
  assert(state && l == 1 && state[0] == 2);
  const uint8_t *err = tlv8_find(out, len, TLV_TYPE_ERROR, &l);
  return err ? err[0] : 0;
}

static void as_controller(hap_session_t *s, const char *id, bool verified) {
  memset(s, 0, sizeof(*s));
  if (id) {
    memcpy(s->controller_id, id, strlen(id));
    s->controller_id_len = strlen(id);
  }
  s->controller_verified = verified;
}

static int add(hap_session_t *s, const char *id, const uint8_t *pk, int perms) {
  uint8_t req[256], out[256];
  size_t out_len = 0;
  size_t len = request(req, TLV_METHOD_ADD_PAIRING, id, pk, perms);
  assert(hap_pair_add(s, req, len, out, sizeof(out), &out_len) == ESP_OK);
  return response_error(out, out_len);
}

static int remove_pairing(hap_session_t *s, const char *id) {
  uint8_t req[256], out[256];
  size_t out_len = 0;
  size_t len = request(req, TLV_METHOD_REMOVE_PAIRING, id, NULL, -1);
  assert(hap_pair_remove(s, req, len, out, sizeof(out), &out_len) == ESP_OK);
  return response_error(out, out_len);
}

static void test_manage(void) {
  uint8_t ka[32], kb[32], kc[32];
  key(ka, 10);
  key(kb, 20);
  key(kc, 30);
  hap_session_t s;
  uint8_t req[256], out[2048];
  size_t out_len = 0;

  wipe();

  // An accessory with no admin lets the first controller in.
  as_controller(&s, NULL, false);
  assert(add(&s, "admin-A", ka, HAP_PERM_ADMIN) == 0);

  // Now it has an admin: an unverified or unknown session is refused.
  assert(add(&s, "B", kb, HAP_PERM_USER) == TLV_ERROR_AUTHENTICATION);
  as_controller(&s, "stranger", false);
  assert(add(&s, "B", kb, HAP_PERM_USER) == TLV_ERROR_AUTHENTICATION);
  // ... as is a session claiming an admin's name without having verified.
  as_controller(&s, "admin-A", false);
  assert(add(&s, "B", kb, HAP_PERM_USER) == TLV_ERROR_AUTHENTICATION);

  // The verified admin adds a user (permissions 0, as a home hub does).
  as_controller(&s, "admin-A", true);
  assert(add(&s, "B", kb, HAP_PERM_USER) == 0);
  // Same identifier, different key: Unknown. Malformed: Unknown.
  assert(add(&s, "B", kc, HAP_PERM_USER) == TLV_ERROR_UNKNOWN);
  assert(add(&s, "C", NULL, HAP_PERM_USER) == TLV_ERROR_UNKNOWN);
  assert(add(&s, "C", kc, -1) == TLV_ERROR_UNKNOWN);
  size_t len = request(req, TLV_METHOD_REMOVE_PAIRING, "C", kc, 0);
  assert(hap_pair_add(&s, req, len, out, sizeof(out), &out_len) == ESP_OK);
  assert(response_error(out, out_len) == TLV_ERROR_UNKNOWN); // wrong method

  // A verified user may not manage pairings.
  hap_session_t user;
  as_controller(&user, "B", true);
  assert(add(&user, "C", kc, HAP_PERM_USER) == TLV_ERROR_AUTHENTICATION);
  len = request(req, TLV_METHOD_LIST_PAIRINGS, NULL, NULL, -1);
  assert(hap_pair_list(&user, req, len, out, sizeof(out), &out_len) == ESP_OK);
  assert(response_error(out, out_len) == TLV_ERROR_AUTHENTICATION);

  // The admin lists both, separated, with their keys and permissions.
  assert(hap_pair_list(&s, req, len, out, sizeof(out), &out_len) == ESP_OK);
  assert(response_error(out, out_len) == 0);
  const uint8_t expected_ids[2][8] = {"admin-A", "B"};
  const uint8_t *expected_keys[2] = {ka, kb};
  const uint8_t expected_perms[2] = {HAP_PERM_ADMIN, HAP_PERM_USER};
  size_t pos = 3; // past State
  for (int i = 0; i < 2; i++) {
    if (i > 0) {
      assert(out[pos] == TLV_TYPE_SEPARATOR && out[pos + 1] == 0);
      pos += 2;
    }
    size_t id_len = strlen((const char *)expected_ids[i]);
    assert(out[pos] == TLV_TYPE_IDENTIFIER && out[pos + 1] == id_len);
    assert(memcmp(out + pos + 2, expected_ids[i], id_len) == 0);
    pos += 2 + id_len;
    assert(out[pos] == TLV_TYPE_PUBLIC_KEY && out[pos + 1] == 32);
    assert(memcmp(out + pos + 2, expected_keys[i], 32) == 0);
    pos += 34;
    assert(out[pos] == TLV_TYPE_PERMISSIONS && out[pos + 1] == 1 &&
           out[pos + 2] == expected_perms[i]);
    pos += 3;
  }
  assert(pos == out_len);

  // A full store answers MaxPeers; a full list still fits the RTSP buffer.
  for (int i = hap_pairings_count(); i < HAP_PAIRINGS_MAX; i++) {
    char id[48];
    snprintf(id, sizeof(id), "%08d-0000-4000-8000-000000000000", i);
    assert(add(&s, id, kc, HAP_PERM_USER) == 0);
  }
  assert(add(&s, "overflow", kc, HAP_PERM_USER) == TLV_ERROR_MAX_PEERS);
  assert(hap_pair_list(&s, req, len, out, sizeof(out), &out_len) == ESP_OK);
  assert(response_error(out, out_len) == 0 && out_len < 2048);
  // A buffer too small for the answer is an error, not a truncated list.
  assert(hap_pair_list(&s, req, len, out, 100, &out_len) == ESP_ERR_NO_MEM);

  // Removing: a user, then one that is not there (still success).
  assert(remove_pairing(&s, "B") == 0);
  assert(!hap_pairings_find(ID("B"), NULL, NULL));
  assert(remove_pairing(&s, "B") == 0);
  assert(remove_pairing(&user, "admin-A") == TLV_ERROR_AUTHENTICATION);

  // The admin removing itself unpairs the accessory and loses its rights.
  changes = 0;
  assert(hap_homekit_set_config(true, 1) == ESP_OK);
  assert(remove_pairing(&s, "admin-A") == 0);
  assert(hap_pairings_count() == 0 && !hap_homekit_access_control());
  assert(!s.controller_verified);
  assert(changes >= 2);

  printf("PASS: pair-add, pair-remove, pair-list\n");
}

/* The Home app adds the speaker over a transient pair-setup session: it
 * proved the setup code, then sends /pair-add for the home's controllers.
 * (Seen on hardware: refusing it left the speaker impossible to add.) */
static void test_home_app_add(void) {
  uint8_t ka[32], kb[32], kc[32], kd[32];
  key(ka, 40);
  key(kb, 50);
  key(kc, 60);
  key(kd, 70);
  uint8_t req[256], out[2048];
  size_t out_len = 0;

  // An old home filled every slot, then removed the speaker while it was
  // offline: its admins are still stored.
  wipe();
  for (int i = 0; i < HAP_PAIRINGS_MAX; i++) {
    char id[16];
    snprintf(id, sizeof(id), "old-%d", i);
    assert(hap_pairings_add(ID(id), ka,
                            i < 2 ? HAP_PERM_ADMIN : HAP_PERM_USER) == ESP_OK);
  }
  assert(hap_homekit_set_config(true, 2) == ESP_OK);

  // A new home adds it. The first /pair-add starts a new set, the rest of
  // that session's adds join it, and the old home is gone.
  hap_session_t setup;
  as_controller(&setup, NULL, false);
  setup.setup_code_proven = true;
  assert(add(&setup, "owner", kb, HAP_PERM_ADMIN) == 0);
  assert(setup.pairings_claimed);
  assert(add(&setup, "hub", kc, HAP_PERM_ADMIN) == 0);
  assert(add(&setup, "member", kd, HAP_PERM_USER) == 0);
  assert(hap_pairings_count() == 3 && hap_homekit_acl() == 2);
  assert(!hap_pairings_find(ID("old-0"), NULL, NULL));
  // ... and so the old home's admin has lost its rights.
  hap_session_t old_admin;
  as_controller(&old_admin, "old-0", true);
  assert(add(&old_admin, "x", ka, HAP_PERM_USER) == TLV_ERROR_AUTHENTICATION);

  // That session may list, and may re-key a controller: it proved the code.
  size_t list_len = request(req, TLV_METHOD_LIST_PAIRINGS, NULL, NULL, -1);
  assert(hap_pair_list(&setup, req, list_len, out, sizeof(out), &out_len) ==
         ESP_OK);
  assert(response_error(out, out_len) == 0);
  assert(add(&setup, "member", ka, HAP_PERM_USER) == 0);
  assert(hap_pairings_count() == 3);

  // A second connection of the same setup, a minute later, joins the set,
  // whatever it adds first.
  mock_now_us += MINUTES(1);
  hap_session_t again;
  as_controller(&again, NULL, false);
  again.setup_code_proven = true;
  assert(add(&again, "member-2", ka, HAP_PERM_USER) == 0);
  assert(add(&again, "hub", kc, HAP_PERM_ADMIN) == 0);
  assert(hap_pairings_count() == 4);

  // Later, the same iPhone adds the speaker to another home (it was removed
  // from this one while offline). Same identifier, same key, but the old
  // home's hub and members must go.
  mock_now_us += MINUTES(60);
  hap_session_t next_home;
  as_controller(&next_home, NULL, false);
  next_home.setup_code_proven = true;
  assert(add(&next_home, "owner", kb, HAP_PERM_ADMIN) == 0);
  assert(hap_pairings_count() == 1 &&
         !hap_pairings_find(ID("hub"), NULL, NULL));
  hap_session_t old_hub;
  as_controller(&old_hub, "hub", true);
  assert(add(&old_hub, "x", ka, HAP_PERM_USER) == TLV_ERROR_AUTHENTICATION);

  // A failed claim leaves the old set in place, and the next try claims.
  mock_now_us += MINUTES(60);
  hap_session_t failing;
  as_controller(&failing, NULL, false);
  failing.setup_code_proven = true;
  nvs.fail_writes = true;
  assert(add(&failing, "other-owner", kd, HAP_PERM_ADMIN) == TLV_ERROR_UNKNOWN);
  assert(!failing.pairings_claimed && hap_pairings_count() == 1);
  nvs.fail_writes = false;
  assert(add(&failing, "other-owner", kd, HAP_PERM_ADMIN) == 0);
  assert(hap_pairings_count() == 1);

  // An admin that pair-verified adds without claiming, and may not re-key.
  hap_session_t admin;
  as_controller(&admin, "other-owner", true);
  assert(add(&admin, "guest", ka, HAP_PERM_USER) == 0);
  assert(add(&admin, "guest", kb, HAP_PERM_USER) == TLV_ERROR_UNKNOWN);
  assert(hap_pairings_count() == 2);

  printf("PASS: Home app add over a setup-code session\n");
}

int main(void) {
  test_store();
  test_manage();
  test_home_app_add();
  return 0;
}

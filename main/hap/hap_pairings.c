// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdlib.h>
#include <string.h>

#include "hap_pairings.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"

static const char *TAG = "hap_pairings";

#define NVS_NAMESPACE "homekit"
#define NVS_KEY       "store"
#define STORE_VERSION 1

// Persisted as one blob; the layout is versioned so a later change can tell
// an old blob from a corrupt one.
typedef struct {
  uint8_t version;
  uint8_t access_control;
  uint8_t acl;
  uint8_t count;
  hap_pairing_t entries[HAP_PAIRINGS_MAX];
} hap_store_t;

static hap_store_t *s_store;
static SemaphoreHandle_t s_lock;
static void (*s_change_cb)(void);

// A setup in progress: the last time a setup-code session stored a pairing.
// RAM only, so a restart always ends it.
#define SETUP_WINDOW_US (5LL * 60 * 1000000)
static bool s_setup_seen;
static int64_t s_setup_at_us;

static void lock(void) {
  xSemaphoreTake(s_lock, portMAX_DELAY);
}

static void unlock(void) {
  xSemaphoreGive(s_lock);
}

static void notify(void) {
  if (s_change_cb) {
    s_change_cb();
  }
}

// Caller holds the lock.
static esp_err_t persist(void) {
  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }
  err = nvs_set_blob(nvs, NVS_KEY, s_store, sizeof(*s_store));
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }
  nvs_close(nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to save pairings: %s", esp_err_to_name(err));
  }
  return err;
}

// Caller holds the lock.
static int find_index(const uint8_t *id, size_t id_len) {
  for (int i = 0; i < s_store->count; i++) {
    const hap_pairing_t *p = &s_store->entries[i];
    if (p->id_len == id_len && memcmp(p->id, id, id_len) == 0) {
      return i;
    }
  }
  return -1;
}

// Caller holds the lock.
static size_t admin_count_locked(void) {
  size_t admins = 0;
  for (int i = 0; i < s_store->count; i++) {
    if (s_store->entries[i].perms & HAP_PERM_ADMIN) {
      admins++;
    }
  }
  return admins;
}

static bool valid_id(const uint8_t *id, size_t id_len) {
  return id && id_len > 0 && id_len < HAP_PAIRING_ID_MAX;
}

esp_err_t hap_pairings_init(void) {
  if (s_store) {
    return ESP_OK;
  }

  s_lock = xSemaphoreCreateMutex();
  if (!s_lock) {
    return ESP_ERR_NO_MEM;
  }
  // Every supported board has PSRAM; the store is ~1.6 KB of DRAM otherwise.
  s_store = heap_caps_calloc(1, sizeof(*s_store), MALLOC_CAP_SPIRAM);
  if (!s_store) {
    s_store = calloc(1, sizeof(*s_store));
  }
  if (!s_store) {
    vSemaphoreDelete(s_lock);
    s_lock = NULL;
    return ESP_ERR_NO_MEM;
  }
  s_store->version = STORE_VERSION;

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
  if (err == ESP_ERR_NVS_NOT_FOUND) {
    return ESP_OK; // Never paired.
  }
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return ESP_OK; // Run unpaired rather than not at all.
  }

  hap_store_t *loaded = calloc(1, sizeof(*loaded));
  size_t len = sizeof(*loaded);
  err = loaded ? nvs_get_blob(nvs, NVS_KEY, loaded, &len) : ESP_ERR_NO_MEM;
  nvs_close(nvs);

  if (err == ESP_OK && len == sizeof(*loaded) &&
      loaded->version == STORE_VERSION && loaded->count <= HAP_PAIRINGS_MAX) {
    memcpy(s_store, loaded, sizeof(*s_store));
    ESP_LOGI(TAG, "%u HomeKit controller(s), access control %s, level %u",
             s_store->count, s_store->access_control ? "on" : "off",
             s_store->acl);
  } else if (err != ESP_ERR_NVS_NOT_FOUND) {
    ESP_LOGW(TAG, "Ignoring unreadable pairing store (%s, %u bytes)",
             esp_err_to_name(err), (unsigned)len);
  }
  free(loaded);
  return ESP_OK;
}

typedef enum {
  STORE_ADD,        // Refuse a known identifier with a different key.
  STORE_PUT,        // A known identifier takes the new key.
  STORE_SETUP_JOIN, // As PUT, and extends the setup window.
  STORE_CLAIM,      // Start a new pairing set unless a setup is in progress.
} store_mode_t;

// Caller holds the lock. Replaces every pairing by this one controller. The
// HomeKit configuration stays: the Home app may send /configure before its
// first /pair-add, and the new home sends its own either way.
static esp_err_t claim_locked(const uint8_t *id, size_t id_len,
                              const uint8_t ltpk[32], uint8_t perms,
                              size_t *dropped) {
  hap_store_t *backup = malloc(sizeof(*backup));
  if (!backup) {
    return ESP_ERR_NO_MEM;
  }
  memcpy(backup, s_store, sizeof(*backup));
  *dropped = s_store->count;

  memset(s_store->entries, 0, sizeof(s_store->entries));
  hap_pairing_t *p = &s_store->entries[0];
  memcpy(p->id, id, id_len);
  p->id_len = (uint8_t)id_len;
  p->perms = perms;
  memcpy(p->ltpk, ltpk, sizeof(p->ltpk));
  s_store->count = 1;

  esp_err_t err = persist();
  if (err != ESP_OK) {
    memcpy(s_store, backup, sizeof(*s_store));
  }
  free(backup);
  return err;
}

static esp_err_t store_pairing(const uint8_t *id, size_t id_len,
                               const uint8_t ltpk[32], uint8_t perms,
                               store_mode_t mode) {
  if (!s_store || !valid_id(id, id_len) || !ltpk) {
    return ESP_ERR_INVALID_ARG;
  }

  lock();
  const int64_t now_us = esp_timer_get_time();
  if (mode == STORE_CLAIM && s_setup_seen &&
      now_us - s_setup_at_us < SETUP_WINDOW_US) {
    // Another connection of the setup that claimed moments ago, or the
    // Home app retrying it: join that set rather than drop it.
    mode = STORE_SETUP_JOIN;
  }
  const bool was_paired = s_store->count > 0;
  const uint8_t was_access_control = s_store->access_control;
  const uint8_t was_acl = s_store->acl;
  size_t dropped = 0;
  bool claimed = false;
  esp_err_t err;
  int idx = find_index(id, id_len);
  const bool same_key =
      idx >= 0 && memcmp(s_store->entries[idx].ltpk, ltpk, 32) == 0;
  // Already the whole set: nothing to drop, and maybe nothing to write.
  const bool only_this = s_store->count == 1 && same_key;
  if (mode == STORE_CLAIM && !only_this) {
    // Not "unless already stored": the same iPhone is usually the first
    // controller added to the next home as well.
    err = claim_locked(id, id_len, ltpk, perms, &dropped);
    claimed = err == ESP_OK;
  } else if (idx >= 0) {
    hap_pairing_t *p = &s_store->entries[idx];
    if (!same_key && mode == STORE_ADD) {
      err = ESP_ERR_INVALID_STATE;
    } else if (same_key && p->perms == perms) {
      err = ESP_OK; // Nothing to write.
    } else {
      const hap_pairing_t before = *p;
      p->perms = perms;
      memcpy(p->ltpk, ltpk, sizeof(p->ltpk));
      err = persist();
      if (err != ESP_OK) {
        *p = before;
      }
    }
  } else if (s_store->count >= HAP_PAIRINGS_MAX) {
    err = ESP_ERR_NO_MEM;
  } else {
    hap_pairing_t *p = &s_store->entries[s_store->count];
    memset(p, 0, sizeof(*p));
    memcpy(p->id, id, id_len);
    p->id_len = (uint8_t)id_len;
    p->perms = perms;
    memcpy(p->ltpk, ltpk, sizeof(p->ltpk));
    s_store->count++;
    err = persist();
    if (err != ESP_OK) {
      s_store->count--;
    }
  }
  const bool advertised_changed =
      (was_paired != (s_store->count > 0)) ||
      was_access_control != s_store->access_control || was_acl != s_store->acl;
  if (err == ESP_OK && (mode == STORE_CLAIM || mode == STORE_SETUP_JOIN)) {
    s_setup_seen = true;
    s_setup_at_us = now_us;
  }
  unlock();

  if (err == ESP_OK) {
    ESP_LOGI(TAG, "Controller %.*s paired (%s)", (int)id_len, (const char *)id,
             (perms & HAP_PERM_ADMIN) ? "admin" : "user");
  }
  if (claimed && dropped > 0) {
    ESP_LOGI(TAG, "New pairing set: %u earlier controller(s) forgotten",
             (unsigned)dropped);
  }
  if (advertised_changed) {
    notify();
  }
  return err;
}

esp_err_t hap_pairings_add(const uint8_t *id, size_t id_len,
                           const uint8_t ltpk[32], uint8_t perms) {
  return store_pairing(id, id_len, ltpk, perms, STORE_ADD);
}

esp_err_t hap_pairings_put(const uint8_t *id, size_t id_len,
                           const uint8_t ltpk[32], uint8_t perms) {
  return store_pairing(id, id_len, ltpk, perms, STORE_PUT);
}

esp_err_t hap_pairings_claim(const uint8_t *id, size_t id_len,
                             const uint8_t ltpk[32], uint8_t perms,
                             bool joining) {
  return store_pairing(id, id_len, ltpk, perms,
                       joining ? STORE_SETUP_JOIN : STORE_CLAIM);
}

bool hap_pairings_find(const uint8_t *id, size_t id_len, uint8_t ltpk[32],
                       uint8_t *perms) {
  if (!s_store || !valid_id(id, id_len)) {
    return false;
  }
  lock();
  int idx = find_index(id, id_len);
  if (idx >= 0) {
    if (ltpk) {
      memcpy(ltpk, s_store->entries[idx].ltpk, 32);
    }
    if (perms) {
      *perms = s_store->entries[idx].perms;
    }
  }
  unlock();
  return idx >= 0;
}

esp_err_t hap_pairings_remove(const uint8_t *id, size_t id_len) {
  if (!s_store || !valid_id(id, id_len)) {
    return ESP_ERR_INVALID_ARG;
  }

  lock();
  int idx = find_index(id, id_len);
  if (idx < 0) {
    unlock();
    return ESP_ERR_NOT_FOUND;
  }

  hap_store_t *backup = malloc(sizeof(*backup));
  if (backup) {
    memcpy(backup, s_store, sizeof(*backup));
  }

  memmove(&s_store->entries[idx], &s_store->entries[idx + 1],
          (size_t)(s_store->count - idx - 1) * sizeof(hap_pairing_t));
  s_store->count--;
  memset(&s_store->entries[s_store->count], 0, sizeof(hap_pairing_t));

  // With no admin left nobody could manage the rest: the accessory is
  // unpaired. This is also how "Remove Accessory" in the Home app lands.
  const bool unpaired = admin_count_locked() == 0;
  if (unpaired) {
    memset(s_store->entries, 0, sizeof(s_store->entries));
    s_store->count = 0;
    s_store->access_control = 0;
    s_store->acl = 0;
  }

  esp_err_t err = persist();
  if (err != ESP_OK && backup) {
    memcpy(s_store, backup, sizeof(*s_store));
  }
  unlock();
  free(backup);

  if (err == ESP_OK) {
    ESP_LOGI(TAG, "Controller %.*s removed%s", (int)id_len, (const char *)id,
             unpaired ? "; no admin left, accessory unpaired" : "");
    if (unpaired) {
      notify();
    }
  }
  return err;
}

size_t hap_pairings_count(void) {
  if (!s_store) {
    return 0;
  }
  lock();
  size_t n = s_store->count;
  unlock();
  return n;
}

size_t hap_pairings_admin_count(void) {
  if (!s_store) {
    return 0;
  }
  lock();
  size_t n = admin_count_locked();
  unlock();
  return n;
}

size_t hap_pairings_snapshot(hap_pairing_t *out, size_t max) {
  if (!s_store || !out) {
    return 0;
  }
  lock();
  size_t n = s_store->count < max ? s_store->count : max;
  memcpy(out, s_store->entries, n * sizeof(hap_pairing_t));
  unlock();
  return n;
}

esp_err_t hap_pairings_clear(void) {
  if (!s_store) {
    return ESP_ERR_INVALID_STATE;
  }
  lock();
  // Flash first: if the erase fails, RAM keeps matching what a reboot loads.
  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err == ESP_OK) {
    err = nvs_erase_key(nvs, NVS_KEY);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
      err = ESP_OK; // Never saved: nothing to erase.
    }
    if (err == ESP_OK) {
      err = nvs_commit(nvs);
    }
    nvs_close(nvs);
  }
  if (err == ESP_OK) {
    memset(s_store, 0, sizeof(*s_store));
    s_store->version = STORE_VERSION;
  }
  unlock();

  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to forget pairings: %s", esp_err_to_name(err));
    return err;
  }
  ESP_LOGI(TAG, "All HomeKit pairings forgotten");
  notify();
  return ESP_OK;
}

bool hap_homekit_access_control(void) {
  if (!s_store) {
    return false;
  }
  lock();
  bool on = s_store->access_control != 0;
  unlock();
  return on;
}

uint8_t hap_homekit_acl(void) {
  if (!s_store) {
    return 0;
  }
  lock();
  uint8_t acl = s_store->acl;
  unlock();
  return acl;
}

esp_err_t hap_homekit_set_config(bool access_control, uint8_t acl) {
  if (!s_store) {
    return ESP_ERR_INVALID_STATE;
  }
  lock();
  const uint8_t old_access_control = s_store->access_control;
  const uint8_t old_acl = s_store->acl;
  const bool changed =
      (old_access_control != 0) != access_control || old_acl != acl;
  esp_err_t err = ESP_OK;
  if (changed) {
    s_store->access_control = access_control ? 1 : 0;
    s_store->acl = acl;
    err = persist();
    if (err != ESP_OK) {
      // Keep RAM, and so mDNS, on what a reboot would load.
      s_store->access_control = old_access_control;
      s_store->acl = old_acl;
    }
  }
  unlock();
  if (changed && err == ESP_OK) {
    ESP_LOGI(TAG, "HomeKit access control %s, level %u",
             access_control ? "on" : "off", acl);
    notify();
  }
  return err;
}

void hap_pairings_set_change_cb(void (*cb)(void)) {
  s_change_cb = cb;
}

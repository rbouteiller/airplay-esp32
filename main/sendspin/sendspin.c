#include "sendspin.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "freertos/queue.h"
#include "mdns.h"
#include "nvs.h"
#include "sodium.h"

#include "ethernet.h"
#include "playback_control.h"
#include "playback_events.h"
#include "sendspin_cpace.h"
#include "sendspin_noise.h"
#include "sendspin_player.h"
#include "sendspin_psk.h"
#include "sendspin_time.h"
#include "settings.h"
#include "spiram_task.h"
#include "wifi.h"

/* The post-handshake callback is the only way to see a real client arrive; it
 * landed in ESP-IDF v5.5.5. */
#ifndef CONFIG_HTTPD_WS_POST_HANDSHAKE_CB_SUPPORT
#error \
    "Sendspin needs ESP-IDF v5.5.5 or newer -- set CONFIG_SENDSPIN_ENABLE=n to build on an older release"
#endif

static const char *TAG = "sendspin";

#define SENDSPIN_WS_PATH       "/sendspin"
#define SENDSPIN_NVS_NAMESPACE "sendspin"
#define SENDSPIN_NVS_KEY_SK    "sk"

/* Housekeeping tick. Also the resolution of the clock-sync schedule, so it
 * has to divide the burst interval below. */
#define SENDSPIN_TICK_MS 50U

/* Clock exchange rate before the filter has converged. The player cannot
 * report itself available until it has, so this is the dominant term in how
 * long the server waits for us after connecting. */
#define SENDSPIN_TIME_BURST_MS 250U

#define SENDSPIN_TASK_STACK 5120

/* Roughly one esp_timer tick of slop on either side of the identity check
 * below; a Curve25519 public key is 32 bytes, which is 43 base64url
 * characters with the padding stripped. */
#define SENDSPIN_CLIENT_ID_LEN 43

/* The Noise prologue is the exact wire bytes of client/init followed by
 * server/init. Both are short and fixed in shape; anything approaching this
 * is a server we do not understand. */
#define SENDSPIN_PROLOGUE_MAX 1024

/* Largest JSON control message we will send. client/hello is the big one at
 * a few hundred bytes. */
#define SENDSPIN_TX_PLAIN_MAX 2048

/* First byte of a decrypted binary message. Audio chunk layout is
 * [4][timestamp:8 BE][send_ahead:4 BE][encoded audio]. */
#define SENDSPIN_BIN_JSON        0
#define SENDSPIN_BIN_FRAGMENT    1
#define SENDSPIN_BIN_AUDIO_CHUNK 4
#define SENDSPIN_AUDIO_HEADER    9

typedef enum {
  SENDSPIN_IDLE = 0,  /* no socket */
  SENDSPIN_NEED_INIT, /* socket up, client/init not sent yet */
  SENDSPIN_INIT_SENT, /* waiting for server/init */
  SENDSPIN_HANDSHAKE, /* waiting for Noise message 1 */
  SENDSPIN_ENCRYPTED, /* transport mode; waiting for server/hello */
  SENDSPIN_READY,     /* client/hello sent; waiting for server/activate */
  SENDSPIN_ACTIVATED, /* activated; clock sync and state reporting run */
} sendspin_state_t;

static httpd_handle_t s_server = NULL;
/* Guards every static below that outlives a single call.  Two tasks reach
 * them: the httpd task, which dispatches received frames and serves the
 * /api/sendspin endpoints, and the housekeeping task, which holds this for a
 * whole tick.  Without it a state change lands between the tick's test and
 * the action it decided on. */
static SemaphoreHandle_t s_lock = NULL;
/* Serialises socket writes.  Replies are sent from the httpd task while the
 * housekeeping task sends time requests and state reports, and a WebSocket
 * frame is several write() calls, so without this two frames interleave on
 * the wire and the server sees a corrupt stream.  Always taken *inside*
 * s_lock, never the other way round. */
static SemaphoreHandle_t s_tx_lock = NULL;
static TaskHandle_t s_task = NULL;

static volatile int s_fd = -1;
static volatile sendspin_state_t s_state = SENDSPIN_IDLE;

static sendspin_time_t s_clock;
static sendspin_activity_cb_t s_activity_cb = NULL;

/* Roles the server has activated. Carried across activations that omit
 * active_roles, so they cannot be re-derived per message. */
static bool s_role_player = false;
static bool s_role_metadata = false;
static bool s_role_controller = false;

/* Commands the server says the group accepts, as a bitmask over
 * sendspin_command_t. Sending one it has not offered is defined as ignored,
 * so this is what lets a button fall back to a local action instead. */
static uint32_t s_ctrl_commands = 0;
static QueueHandle_t s_cmd_queue = NULL;

/* Availability has two independent inputs: whether another source owns the
 * output, and whether the clock estimate is good enough to place audio. The
 * protocol only has one flag, so it is the AND of the two. */
static bool s_output_available = true;
/* Set when the takeover paused the server, so the release can undo it. */
static bool s_resume_on_release = false;
static bool s_reported_available = false;
static bool s_state_dirty = false;

/* Last volume and mute state sent to the server. The device's own buttons and
 * web UI move these too, so the tick compares them rather than relying on
 * every local path knowing to notify us. */
static int s_reported_volume = -1;
static bool s_reported_muted = false;

static uint8_t *s_rx = NULL;  /* one WebSocket frame */
static uint8_t *s_asm = NULL; /* fragment reassembly */
static size_t s_asm_len = 0;
static uint8_t s_asm_type = 0;
static bool s_asm_active = false;

/* Noise transport scratch. s_pt holds the plaintext of a received frame;
 * s_tx_plain and s_tx_cipher build one outgoing frame and are only touched
 * under s_tx_lock. */
static uint8_t *s_pt = NULL;
static uint8_t *s_tx_plain = NULL;
static uint8_t *s_tx_cipher = NULL;

static sendspin_noise_t s_noise;
static uint8_t s_client_priv[crypto_scalarmult_curve25519_BYTES];
static uint8_t s_client_pub[crypto_scalarmult_curve25519_BYTES];
static uint8_t s_prologue[SENDSPIN_PROLOGUE_MAX];
static size_t s_prologue_len = 0;

static char s_client_id[SENDSPIN_CLIENT_ID_LEN + 1];
static bool s_mdns_advertised = false;
static int64_t s_last_time_tx_us = 0;

/* Which credential keyed this connection, and the pairing exchange running
 * over it. A long-term PSK is only ever accepted from a server we have
 * finalized a pairing with, so the two are kept together. */
static sendspin_psk_kind_t s_psk_kind = SENDSPIN_PSK_SENTINEL;
static char s_server_id[SENDSPIN_CLIENT_ID_LEN + 1];
static uint8_t s_pending_long_term[SENDSPIN_PSK_LEN];
static bool s_pair_pending = false;

/* The PAKE behind static-PIN pairing. The session id binds a run to this
 * Noise session and this attempt, so it is rebuilt for every attempt. */
#define SENDSPIN_PAKE_SID_LABEL "sendspin-pair-pake-v1"
#define SENDSPIN_PAKE_SID_LEN \
  (sizeof(SENDSPIN_PAKE_SID_LABEL) - 1 + SENDSPIN_NOISE_HASH_LEN + 4)

static sendspin_cpace_t s_cpace;
static uint8_t s_pake_sid[SENDSPIN_PAKE_SID_LEN];
static size_t s_pake_sid_len = 0;
static bool s_pake_active = false;
/* A pairing activation gets the connection to itself: the server reads the
 * exchange, and the re-handshake that follows a successful one, with parsers
 * that accept only the frame they are waiting for. A clock request or a state
 * report slipping in between them aborts the attempt. It stays set until the
 * server/activate that ends pairing. */
static bool s_pairing_busy = false;
/* Counted per connection, and compared against the server's own count. */
static uint32_t s_pairing_index = 0;

/* Defined with the rest of the pairing code, but a session teardown has to
 * clear the PAKE too. */
static void sendspin_pake_reset(void);

/* ------------------------------------------------------------------ */
/*  Locking                                                            */
/* ------------------------------------------------------------------ */

/* Long enough to outlast a housekeeping tick stuck on a slow socket, short
 * enough that a wedged session cannot hold the whole HTTP surface hostage --
 * the httpd task serves the web UI and OTA as well. */
#define SENDSPIN_LOCK_WAIT_MS 2000

static bool sendspin_lock(void) {
  return s_lock &&
         xSemaphoreTake(s_lock, pdMS_TO_TICKS(SENDSPIN_LOCK_WAIT_MS)) == pdTRUE;
}

static void sendspin_unlock(void) {
  if (s_lock) {
    xSemaphoreGive(s_lock);
  }
}

/* ------------------------------------------------------------------ */
/*  Identity                                                           */
/* ------------------------------------------------------------------ */

static esp_err_t sendspin_store_identity(void) {
  nvs_handle_t nvs;
  esp_err_t err = nvs_open(SENDSPIN_NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    return err;
  }
  err = nvs_set_blob(nvs, SENDSPIN_NVS_KEY_SK, s_client_priv,
                     sizeof(s_client_priv));
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }
  nvs_close(nvs);
  return err;
}

/* Derive everything that hangs off the private key: the public half, the
 * client_id, and the pairing token, which carries the public key too. */
static esp_err_t sendspin_derive_identity(void) {
  if (crypto_scalarmult_curve25519_base(s_client_pub, s_client_priv) != 0) {
    sodium_memzero(s_client_priv, sizeof(s_client_priv));
    return ESP_FAIL;
  }

  sodium_bin2base64(s_client_id, sizeof(s_client_id), s_client_pub,
                    sizeof(s_client_pub),
                    sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  return sendspin_psk_init(s_client_pub);
}

/* client_id is the base64url of a Curve25519 public key, and the same keypair
 * is the client's static key in the Noise handshake -- which is why the
 * private half is kept for the life of the process rather than wiped here. */
static esp_err_t sendspin_load_identity(void) {
  nvs_handle_t nvs;
  esp_err_t err = nvs_open(SENDSPIN_NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    return err;
  }
  size_t len = sizeof(s_client_priv);
  err = nvs_get_blob(nvs, SENDSPIN_NVS_KEY_SK, s_client_priv, &len);
  nvs_close(nvs);

  if (err != ESP_OK || len != sizeof(s_client_priv)) {
    randombytes_buf(s_client_priv, sizeof(s_client_priv));
    err = sendspin_store_identity();
    if (err != ESP_OK) {
      ESP_LOGW(TAG, "identity not persisted: %s", esp_err_to_name(err));
    }
    ESP_LOGI(TAG, "generated a new client identity");
  }

  return sendspin_derive_identity();
}

/* ------------------------------------------------------------------ */
/*  Sending                                                            */
/* ------------------------------------------------------------------ */

/* Is `fd` still a live WebSocket on our server?  A session that dies without
 * sending CLOSE -- a reset, a WiFi drop, a port scanner hanging up -- leaves
 * no event behind, so a remembered fd cannot be trusted on its own: the
 * number is recycled and would eventually address an unrelated request.
 * log_stream.c avoids this by never remembering one at all; Sendspin's
 * session is stateful, so it re-checks instead. */
static bool sendspin_fd_is_live(int fd) {
  if (!s_server || fd < 0) {
    return false;
  }
  return httpd_ws_get_fd_info(s_server, fd) == HTTPD_WS_CLIENT_WEBSOCKET;
}

static bool sendspin_send_text(const char *json) {
  const int fd = s_fd;
  if (!s_server || fd < 0 || !json) {
    return false;
  }
  httpd_ws_frame_t frame = {
      .type = HTTPD_WS_TYPE_TEXT,
      .payload = (uint8_t *)json,
      .len = strlen(json),
  };
  if (xSemaphoreTake(s_tx_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
    ESP_LOGW(TAG, "send timed out waiting for the socket");
    return false;
  }
  esp_err_t err = httpd_ws_send_frame_async(s_server, fd, &frame);
  xSemaphoreGive(s_tx_lock);
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "send failed on fd=%d: %s", fd, esp_err_to_name(err));
    return false;
  }
  return true;
}

/* Seals `body` as a Noise transport message and sends it as a binary frame.
 * The nonce counter advances with the encryption, so encrypting and writing
 * have to stay inside one critical section or two concurrent senders would
 * put the frames on the wire out of counter order and the server's very next
 * decryption would fail. */
static bool sendspin_send_encrypted(uint8_t type, const uint8_t *body,
                                    size_t len) {
  const int fd = s_fd;
  if (!s_server || fd < 0) {
    return false;
  }
  if (len + 1 > SENDSPIN_TX_PLAIN_MAX) {
    ESP_LOGE(TAG, "message of %u bytes exceeds the send buffer", (unsigned)len);
    return false;
  }
  if (xSemaphoreTake(s_tx_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
    ESP_LOGW(TAG, "send timed out waiting for the socket");
    return false;
  }

  s_tx_plain[0] = type;
  memcpy(&s_tx_plain[1], body, len);

  size_t cipher_len = 0;
  esp_err_t err = sendspin_noise_encrypt(
      &s_noise, s_tx_plain, len + 1, s_tx_cipher,
      SENDSPIN_TX_PLAIN_MAX + SENDSPIN_NOISE_TAG_LEN, &cipher_len);
  if (err == ESP_OK) {
    httpd_ws_frame_t frame = {
        .type = HTTPD_WS_TYPE_BINARY,
        .payload = s_tx_cipher,
        .len = cipher_len,
    };
    err = httpd_ws_send_frame_async(s_server, fd, &frame);
  }
  xSemaphoreGive(s_tx_lock);

  if (err != ESP_OK) {
    ESP_LOGW(TAG, "encrypted send failed on fd=%d: %s", fd,
             esp_err_to_name(err));
    return false;
  }
  return true;
}

/* Serialises and sends `root` as a cleartext text frame, then frees it. Only
 * the three handshake messages may take this route. */
static bool sendspin_send_cleartext_json(cJSON *root) {
  if (!root) {
    return false;
  }
  char *text = cJSON_PrintUnformatted(root);
  cJSON_Delete(root);
  if (!text) {
    return false;
  }
  ESP_LOGD(TAG, "tx %s", text);
  const bool ok = sendspin_send_text(text);
  cJSON_free(text);
  return ok;
}

/* Serialises and sends `root`, then frees it. Returns false if the socket has
 * gone; the caller treats that as a disconnect rather than an error.
 *
 * The transport switches under this function: before the Noise split a
 * message goes out as cleartext text, after it as an encrypted binary frame
 * with a leading type byte. */
static bool sendspin_send_json(cJSON *root) {
  if (!sendspin_noise_ready(&s_noise)) {
    return sendspin_send_cleartext_json(root);
  }
  if (!root) {
    return false;
  }
  char *text = cJSON_PrintUnformatted(root);
  cJSON_Delete(root);
  if (!text) {
    return false;
  }
  ESP_LOGD(TAG, "tx %s", text);
  const bool ok = sendspin_send_encrypted(SENDSPIN_BIN_JSON,
                                          (const uint8_t *)text, strlen(text));
  cJSON_free(text);
  return ok;
}

static cJSON *sendspin_new_message(const char *type, cJSON **payload_out) {
  cJSON *root = cJSON_CreateObject();
  if (!root) {
    return NULL;
  }
  cJSON *payload = cJSON_CreateObject();
  if (!payload || !cJSON_AddStringToObject(root, "type", type) ||
      !cJSON_AddItemToObject(root, "payload", payload)) {
    cJSON_Delete(payload);
    cJSON_Delete(root);
    return NULL;
  }
  *payload_out = payload;
  return root;
}

/* The Noise prologue is the raw bytes of client/init and server/init exactly
 * as they crossed the wire, so neither may be re-serialised: two JSON writers
 * that order keys differently would produce the same message and a different
 * prologue, and the handshake would fail with nothing to point at. */
static bool sendspin_prologue_append(const void *data, size_t len) {
  if (s_prologue_len + len > sizeof(s_prologue)) {
    ESP_LOGE(TAG, "prologue overflow (%u bytes)",
             (unsigned)(s_prologue_len + len));
    return false;
  }
  memcpy(&s_prologue[s_prologue_len], data, len);
  s_prologue_len += len;
  return true;
}

static void sendspin_send_init(void) {
  cJSON *payload = NULL;
  cJSON *root = sendspin_new_message("client/init", &payload);
  if (!root) {
    return;
  }
  cJSON_AddStringToObject(payload, "client_id", s_client_id);
  cJSON_AddNumberToObject(payload, "version", 1);
  cJSON_AddStringToObject(payload, "suite", "25519_ChaChaPoly_SHA256");

  char *text = cJSON_PrintUnformatted(root);
  cJSON_Delete(root);
  if (!text) {
    return;
  }
  s_prologue_len = 0;
  if (sendspin_prologue_append(text, strlen(text))) {
    ESP_LOGD(TAG, "tx %s", text);
    (void)sendspin_send_text(text);
  }
  cJSON_free(text);
}

static void sendspin_send_hello(void) {
  char name[65];
  settings_get_device_name(name, sizeof(name));

  cJSON *payload = NULL;
  cJSON *root = sendspin_new_message("client/hello", &payload);
  if (!root) {
    return;
  }
  cJSON_AddStringToObject(payload, "name", name);

  uint8_t mac[6];
  char mac_str[18];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0],
           mac[1], mac[2], mac[3], mac[4], mac[5]);

  cJSON *info = cJSON_AddObjectToObject(payload, "device_info");
  if (info) {
    /* A server renders these as "<manufacturer>/<product_name>", and the same
     * board also advertises an AirPlay receiver, so name the transport here to
     * tell the two entries apart. */
    cJSON_AddStringToObject(info, "product_name", "Sendspin");
    cJSON_AddStringToObject(info, "manufacturer", "AirPlay-ESP32");
    cJSON_AddStringToObject(info, "software_version",
                            esp_app_get_description()->version);
    cJSON_AddStringToObject(info, "mac_address", mac_str);
  }

  cJSON *roles = cJSON_AddArrayToObject(payload, "supported_roles");
  if (roles) {
    cJSON_AddItemToArray(roles, cJSON_CreateString("player@v1"));
    /* metadata@v1 has no support object; listing it is the whole opt-in. */
    cJSON_AddItemToArray(roles, cJSON_CreateString("metadata@v1"));
    cJSON_AddItemToArray(roles, cJSON_CreateString("controller@v1"));
  }

  cJSON *support = cJSON_AddObjectToObject(payload, "player@v1_support");
  if (support) {
    cJSON *formats = cJSON_AddArrayToObject(support, "supported_formats");
    if (formats) {
      /* Priority order, so FLAC first: it roughly halves what has to cross
       * the link, and the clock exchange shares that link with the audio.
       * Opus halves it again but is lossy, so it sits behind PCM and is
       * something an operator opts into. It is defined at 48 kHz only --
       * the reference encoder rejects 44.1. */
      static const struct {
        const char *codec;
        int rate;
      } offered[] = {
          {"flac", 44100}, {"flac", 48000}, {"pcm", 44100}, {"pcm", 48000},
#ifdef CONFIG_SENDSPIN_OPUS
          {"opus", 48000},
#endif
      };
      for (size_t i = 0; i < sizeof(offered) / sizeof(offered[0]); i++) {
        cJSON *fmt = cJSON_CreateObject();
        if (!fmt) {
          continue;
        }
        cJSON_AddStringToObject(fmt, "codec", offered[i].codec);
        cJSON_AddNumberToObject(fmt, "channels", 2);
        cJSON_AddNumberToObject(fmt, "sample_rate", offered[i].rate);
        cJSON_AddNumberToObject(fmt, "bit_depth", 16);
        cJSON_AddItemToArray(formats, fmt);
      }
    }
    cJSON_AddNumberToObject(support, "buffer_capacity",
                            sendspin_player_buffer_capacity());
    cJSON *commands = cJSON_AddArrayToObject(support, "supported_commands");
    if (commands) {
      cJSON_AddItemToArray(commands, cJSON_CreateString("volume"));
      cJSON_AddItemToArray(commands, cJSON_CreateString("mute"));
    }
  }

  /* An *array* of descriptors, each naming its own method. The specification's
   * prose calls this an object keyed by method identifier, but the reference
   * implementation parses a list and hangs up on anything else, so follow the
   * code. */
  cJSON *methods = cJSON_AddArrayToObject(payload, "supported_pair_methods");
  if (methods) {
    /* Static PIN first: it is the only method a server will offer its
     * operator a prompt for. A server shown nothing but Pairing PSK reports
     * the device as unpairable, because that method is how a server enrols
     * itself from a token rather than something anyone can type in. */
    cJSON *pin_method = cJSON_CreateObject();
    if (pin_method) {
      cJSON_AddStringToObject(pin_method, "method", "static_pin");
      cJSON *locations = cJSON_AddArrayToObject(pin_method, "locations");
      if (locations) {
        cJSON_AddItemToArray(locations, cJSON_CreateString("operator"));
      }
      cJSON_AddItemToArray(methods, pin_method);
    }

    /* Pairing PSK is the one method required of a client, and the only one
     * with no PAKE round -- the operator carries the secret across in the
     * pairing token instead. */
    cJSON *psk_method = cJSON_CreateObject();
    if (psk_method) {
      cJSON_AddStringToObject(psk_method, "method", "pairing_psk");
      cJSON *locations = cJSON_AddArrayToObject(psk_method, "locations");
      if (locations) {
        /* Both secrets are on the device's own web page, so an operator with
         * access to it can read them; neither is printed on a label. */
        cJSON_AddItemToArray(locations, cJSON_CreateString("operator"));
      }
      cJSON_AddItemToArray(methods, psk_method);
    }
  }

  /* Unpaired access stays enabled so a server may still use the device for
   * playback before anyone pairs it. A client offering neither is "locked
   * down" and must hang up on server/hello. */
  cJSON *unpaired = cJSON_AddObjectToObject(payload, "unpaired_access");
  if (unpaired) {
    cJSON_AddBoolToObject(unpaired, "enabled", true);
  }

  (void)sendspin_send_json(root);
}

static void sendspin_send_state(void) {
  const bool available =
      s_output_available && sendspin_time_converged(&s_clock);
  const int volume = playback_control_get_level_percent();
  const bool muted = playback_control_is_muted();

  cJSON *payload = NULL;
  cJSON *root = sendspin_new_message("client/state", &payload);
  if (!root) {
    return;
  }
  cJSON_AddBoolToObject(payload, "available", available);

  /* A role object may only appear while its role is active. */
  cJSON *player =
      s_role_player ? cJSON_AddObjectToObject(payload, "player") : NULL;
  if (player) {
    /* The DAC and DMA ring are already compensated for by
     * audio_output_get_next_playout_time_ns(), so there is no delay left
     * beyond the audio port for the server to add. */
    cJSON_AddNumberToObject(player, "static_delay_ms", 0);
    cJSON_AddNumberToObject(player, "required_lead_time_ms",
                            (double)sendspin_player_min_buffer_ms());
    cJSON_AddNumberToObject(player, "min_buffer_ms",
                            (double)sendspin_player_min_buffer_ms());
    cJSON_AddNumberToObject(player, "volume", volume);
    cJSON_AddBoolToObject(player, "muted", muted);
    /* This list is only ever set_static_delay; volume and mute are advertised
     * in player@v1_support instead. */
    cJSON_AddArrayToObject(player, "supported_commands");
  }

  if (sendspin_send_json(root)) {
    s_reported_available = available;
    s_reported_volume = volume;
    s_reported_muted = muted;
    s_state_dirty = false;
  }
}

static void sendspin_send_time_request(void) {
  cJSON *payload = NULL;
  cJSON *root = sendspin_new_message("client/time", &payload);
  if (!root) {
    return;
  }
  /* Taken as late as the message layer allows: everything between here and
   * the socket write is measured as round-trip delay, and half of any
   * asymmetry there lands directly in the offset estimate. */
  const int64_t now_us = esp_timer_get_time();
  cJSON_AddNumberToObject(payload, "client_transmitted", (double)now_us);
  s_last_time_tx_us = now_us;
  (void)sendspin_send_json(root);
}

/* ------------------------------------------------------------------ */
/*  Playback events                                                    */
/* ------------------------------------------------------------------ */

/* The display, the LEDs and the boards that gate their amplifier on playback
 * all listen on the RTSP event bus, so a Sendspin session has to raise the
 * same events an AirPlay or a Bluetooth one would.  Without them a SqueezeAMP
 * or Esparagus board never leaves DAC_POWER_OFF and the stream is rendered
 * into a powered-down amplifier. */

typedef struct {
  playback_metadata_t meta; /* position_secs is filled in at emit time */
  int64_t timestamp_us;     /* server clock the progress was measured at */
  int64_t progress_ms;      /* track position at timestamp_us */
  int32_t speed;            /* playback_speed; 1000 is normal, 0 is paused */
  bool has_progress;
} sendspin_meta_t;

static sendspin_meta_t s_meta;
static sendspin_meta_t s_meta_pending;
static bool s_meta_pending_valid = false;
static bool s_events_connected = false;
static bool s_events_playing = false;

static void sendspin_events_playing(bool playing) {
  if (playing == s_events_playing) {
    return;
  }
  s_events_playing = playing;
  if (!playing) {
    settings_persist_volume();
  }
  playback_events_emit(PLAYBACK_SOURCE_SENDSPIN,
                       playing ? PLAYBACK_EVENT_PLAYING : PLAYBACK_EVENT_PAUSED,
                       NULL);
}

static void sendspin_events_connected(bool connected) {
  if (connected == s_events_connected) {
    return;
  }
  s_events_connected = connected;
  if (connected) {
    /* Listeners read this as "a new source has the output": the display drops
     * whatever it was showing and the amplifier comes up into standby. */
    playback_events_emit(PLAYBACK_SOURCE_SENDSPIN, PLAYBACK_EVENT_CONNECTED,
                         NULL);
    return;
  }
  s_events_playing = false;
  memset(&s_meta, 0, sizeof(s_meta));
  s_meta_pending_valid = false;
  settings_persist_volume();
  playback_events_emit(PLAYBACK_SOURCE_SENDSPIN, PLAYBACK_EVENT_DISCONNECTED,
                       NULL);
}

/* ------------------------------------------------------------------ */
/*  Session lifecycle                                                  */ /* ------------------------------------------------------------------
                                                                           */

static void sendspin_session_close(const char *reason) {
  if (s_fd < 0) {
    return;
  }
  ESP_LOGI(TAG, "session closed (%s)", reason);
  s_fd = -1;
  s_state = SENDSPIN_IDLE;
  s_asm_active = false;
  s_asm_len = 0;
  s_reported_available = false;
  s_state_dirty = false;
  /* A server MUST NOT assume volume and mute are unchanged after a
   * reconnect, so make sure the next state report is treated as news. */
  s_reported_volume = -1;
  s_prologue_len = 0;
  s_role_player = false;
  s_role_metadata = false;
  s_role_controller = false;
  s_ctrl_commands = 0;
  s_resume_on_release = false;
  s_psk_kind = SENDSPIN_PSK_SENTINEL;
  s_pair_pending = false;
  s_server_id[0] = '\0';
  sodium_memzero(s_pending_long_term, sizeof(s_pending_long_term));
  /* The pairing index is counted per connection, so it restarts with one. */
  s_pairing_index = 0;
  s_pairing_busy = false;
  sendspin_pake_reset();
  if (s_cmd_queue) {
    xQueueReset(s_cmd_queue);
  }
  sendspin_noise_reset(&s_noise);
  sendspin_time_reset(&s_clock);
  sendspin_events_connected(false);

  if (sendspin_player_is_streaming()) {
    sendspin_player_stream_end();
    if (s_activity_cb) {
      s_activity_cb(false);
    }
  }
}

/* sendspin_session_close() for a caller that does not hold s_lock. */
static void sendspin_locked_close(const char *reason) {
  if (!sendspin_lock()) {
    /* The housekeeping task reaps a dead fd on its next tick, so a close that
     * cannot get the lock costs a tick rather than the session. */
    ESP_LOGW(TAG, "session lock timed out; leaving the close to the tick (%s)",
             reason);
    return;
  }
  sendspin_session_close(reason);
  sendspin_unlock();
}

/* ------------------------------------------------------------------ */
/*  Message handling                                                   */
/* ------------------------------------------------------------------ */

static double sendspin_number(const cJSON *object, const char *key,
                              double fallback) {
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, key);
  return cJSON_IsNumber(item) ? cJSON_GetNumberValue(item) : fallback;
}

/* ------------------------------------------------------------------ */
/*  metadata@v1                                                        */
/* ------------------------------------------------------------------ */

/* Metadata timestamps are on the server's clock, the same domain the audio
 * chunks are addressed in. */
static bool sendspin_server_now_us(int64_t *server_us) {
  const int64_t local_us = esp_timer_get_time();
  int64_t offset_ns = 0;
  if (!sendspin_time_offset_ns(&s_clock, local_us, &offset_ns)) {
    return false;
  }
  *server_us = local_us + offset_ns / 1000;
  return true;
}

/* The state reports the position at its own timestamp, so a state that has
 * been sitting here -- a scheduled update that has just come due, or a late
 * join partway through a track -- has to be run forward to now. */
static uint32_t sendspin_meta_position_secs(void) {
  if (!s_meta.has_progress) {
    return 0;
  }
  int64_t ms = s_meta.progress_ms;
  int64_t now_us = 0;
  if (s_meta.speed != 0 && sendspin_server_now_us(&now_us)) {
    ms += (now_us - s_meta.timestamp_us) * s_meta.speed / 1000000;
  }
  const int64_t duration_ms = (int64_t)s_meta.meta.duration_secs * 1000;
  if (duration_ms > 0 && ms > duration_ms) {
    ms = duration_ms;
  }
  return ms > 0 ? (uint32_t)(ms / 1000) : 0;
}

/* Listeners interpolate the position themselves from the last one they were
 * given, so this only runs on a real change. */
static void sendspin_meta_apply(const sendspin_meta_t *next) {
  s_meta = *next;

  /* A server with an idle queue activates the role and immediately sends an
   * empty state. Taking that as a source would wake the amplifier and light
   * the display for as long as the server stayed connected, which for Music
   * Assistant is for ever. The same goes for metadata that keeps arriving
   * after something else took the output: the owner gets the display. */
  const bool has_content = next->meta.title[0] != '\0' ||
                           next->meta.artist[0] != '\0' ||
                           next->meta.album[0] != '\0' || next->has_progress;
  if (!s_output_available ||
      (!has_content && !sendspin_player_is_streaming())) {
    sendspin_events_connected(false);
    return;
  }

  sendspin_events_connected(true);

  playback_event_data_t data = {.metadata = s_meta.meta};
  data.metadata.position_secs = sendspin_meta_position_secs();
  playback_events_emit(PLAYBACK_SOURCE_SENDSPIN, PLAYBACK_EVENT_METADATA,
                       &data);

  if (next->has_progress) {
    sendspin_events_playing(next->speed != 0);
  }
}

static void sendspin_meta_string(const cJSON *object, const char *key,
                                 char *dst, size_t size) {
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, key);
  if (cJSON_IsString(item) && item->valuestring) {
    snprintf(dst, size, "%s", item->valuestring);
  }
}

/* server/state carries the full state of every role object it includes: an
 * omitted object means unchanged, and an explicit null clears the role. */
static void sendspin_handle_state_metadata(const cJSON *payload) {
  const cJSON *meta = cJSON_GetObjectItemCaseSensitive(payload, "metadata");
  if (!meta) {
    return;
  }
  if (cJSON_IsNull(meta)) {
    memset(&s_meta, 0, sizeof(s_meta));
    s_meta_pending_valid = false;
    if (!sendspin_player_is_streaming()) {
      sendspin_events_connected(false);
    }
    return;
  }
  if (!cJSON_IsObject(meta)) {
    return;
  }

  sendspin_meta_t next = {0};
  next.timestamp_us = (int64_t)sendspin_number(meta, "timestamp", 0);
  sendspin_meta_string(meta, "title", next.meta.title, sizeof(next.meta.title));
  sendspin_meta_string(meta, "artist", next.meta.artist,
                       sizeof(next.meta.artist));
  sendspin_meta_string(meta, "album", next.meta.album, sizeof(next.meta.album));

  const cJSON *progress = cJSON_GetObjectItemCaseSensitive(meta, "progress");
  if (cJSON_IsObject(progress)) {
    next.has_progress = true;
    next.progress_ms = (int64_t)sendspin_number(progress, "track_progress", 0);
    next.speed = (int32_t)sendspin_number(progress, "playback_speed", 1000);
    next.meta.duration_secs =
        (uint32_t)(sendspin_number(progress, "track_duration", 0) / 1000.0);
  }

  /* A future timestamp schedules the update -- usually the next track, timed
   * to the audible change -- and replaces any update still pending. */
  int64_t now_us = 0;
  if (next.timestamp_us > 0 && sendspin_server_now_us(&now_us) &&
      next.timestamp_us > now_us) {
    s_meta_pending = next;
    s_meta_pending_valid = true;
    return;
  }

  s_meta_pending_valid = false;
  sendspin_meta_apply(&next);
}

static void sendspin_meta_tick(void) {
  int64_t now_us = 0;
  if (!s_meta_pending_valid || !sendspin_server_now_us(&now_us) ||
      now_us < s_meta_pending.timestamp_us) {
    return;
  }
  const sendspin_meta_t due = s_meta_pending;
  s_meta_pending_valid = false;
  sendspin_meta_apply(&due);
}

/* ------------------------------------------------------------------ */
/*  controller@v1                                                      */
/* ------------------------------------------------------------------ */

/* Indexed by sendspin_command_t; s_ctrl_commands is a bitmask over the same
 * order. The protocol has many more commands, but these are the four a set of
 * hardware buttons can raise. */
static const char *const SENDSPIN_CMD_NAMES[] = {
    [SENDSPIN_CMD_PLAY] = "play",
    [SENDSPIN_CMD_PAUSE] = "pause",
    [SENDSPIN_CMD_NEXT] = "next",
    [SENDSPIN_CMD_PREVIOUS] = "previous",
};
#define SENDSPIN_CMD_COUNT \
  (sizeof(SENDSPIN_CMD_NAMES) / sizeof(SENDSPIN_CMD_NAMES[0]))

static void sendspin_handle_state_controller(const cJSON *payload) {
  const cJSON *controller =
      cJSON_GetObjectItemCaseSensitive(payload, "controller");
  if (!controller) {
    return;
  }
  if (!cJSON_IsObject(controller)) {
    s_ctrl_commands = 0;
    return;
  }

  const cJSON *commands =
      cJSON_GetObjectItemCaseSensitive(controller, "supported_commands");
  uint32_t mask = 0;
  const cJSON *item = NULL;
  cJSON_ArrayForEach(item, commands) {
    if (!cJSON_IsString(item)) {
      continue;
    }
    for (size_t i = 0; i < SENDSPIN_CMD_COUNT; i++) {
      if (strcmp(cJSON_GetStringValue(item), SENDSPIN_CMD_NAMES[i]) == 0) {
        mask |= 1U << i;
      }
    }
  }

  if (mask != s_ctrl_commands) {
    ESP_LOGI(TAG, "controller commands: play=%s pause=%s next=%s previous=%s",
             (mask & (1U << SENDSPIN_CMD_PLAY)) ? "yes" : "no",
             (mask & (1U << SENDSPIN_CMD_PAUSE)) ? "yes" : "no",
             (mask & (1U << SENDSPIN_CMD_NEXT)) ? "yes" : "no",
             (mask & (1U << SENDSPIN_CMD_PREVIOUS)) ? "yes" : "no");
  }
  s_ctrl_commands = mask;
}

static void sendspin_handle_server_state(const cJSON *payload) {
  sendspin_handle_state_metadata(payload);
  sendspin_handle_state_controller(payload);
}

static void sendspin_send_controller_command(sendspin_command_t cmd) {
  cJSON *payload = NULL;
  cJSON *root = sendspin_new_message("client/command", &payload);
  if (!root) {
    return;
  }
  cJSON *controller = cJSON_AddObjectToObject(payload, "controller");
  if (controller) {
    cJSON_AddStringToObject(controller, "command", SENDSPIN_CMD_NAMES[cmd]);
  }
  ESP_LOGI(TAG, "controller command: %s", SENDSPIN_CMD_NAMES[cmd]);
  (void)sendspin_send_json(root);
}

/* Drains the queue the buttons post to. Sending has to happen here because
 * the socket belongs to this task. */
static void sendspin_command_tick(void) {
  uint8_t cmd = 0;
  while (s_cmd_queue && xQueueReceive(s_cmd_queue, &cmd, 0) == pdTRUE) {
    if (cmd < SENDSPIN_CMD_COUNT) {
      sendspin_send_controller_command((sendspin_command_t)cmd);
    }
  }
}

/* ------------------------------------------------------------------ */
/*  Noise handshake                                                    */
/* ------------------------------------------------------------------ */

/* Noise message 1 is an ephemeral key, an encrypted static key and an
 * encrypted payload; message 2 is an ephemeral key and an encrypted "{}". */
#define SENDSPIN_NOISE_MSG_MAX 256
#define SENDSPIN_NOISE_MSG2_LEN \
  (SENDSPIN_NOISE_KEY_LEN + 2 + SENDSPIN_NOISE_TAG_LEN)

static void sendspin_handle_server_init(const cJSON *payload) {
  if (s_state != SENDSPIN_INIT_SENT) {
    sendspin_session_close("unexpected server/init");
    return;
  }
  /* An exact match, not a floor: a future core format bumps this and defines
   * its own negotiation. */
  if ((int)sendspin_number(payload, "version", 0) != 1) {
    sendspin_session_close("unsupported core message version");
    return;
  }

  const cJSON *id = cJSON_GetObjectItemCaseSensitive(payload, "server_id");
  const char *id_str = cJSON_IsString(id) ? cJSON_GetStringValue(id) : NULL;
  uint8_t server_pub[crypto_scalarmult_curve25519_BYTES];
  size_t decoded = 0;
  if (!id_str || strlen(id_str) != SENDSPIN_CLIENT_ID_LEN ||
      sodium_base642bin(server_pub, sizeof(server_pub), id_str, strlen(id_str),
                        NULL, &decoded, NULL,
                        sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0 ||
      decoded != sizeof(server_pub)) {
    sendspin_session_close("malformed server_id");
    return;
  }

  if (sendspin_noise_start(&s_noise, s_client_priv, s_client_pub, server_pub,
                           s_prologue, s_prologue_len) != ESP_OK) {
    sendspin_session_close("handshake setup failed");
    return;
  }
  ESP_LOGI(TAG, "server_id %s", id_str);
  snprintf(s_server_id, sizeof(s_server_id), "%s", id_str);
  s_state = SENDSPIN_HANDSHAKE;
}

/* The message 1 payload names the PSK the server picked, by psk_id. Which of
 * ours it resolves to is what decides whether the session is authenticated,
 * so the answer is remembered as well as returned: a pairing may only be
 * finalized over a connection keyed with the pairing PSK. */
static const uint8_t *sendspin_select_psk(const char *json, size_t len) {
  cJSON *root = cJSON_ParseWithLength(json, len);
  if (!root) {
    return sendspin_noise_sentinel_psk();
  }
  const cJSON *id = cJSON_GetObjectItemCaseSensitive(root, "psk_id");
  const cJSON *category =
      cJSON_GetObjectItemCaseSensitive(root, "psk_category");
  const char *id_str = cJSON_IsString(id) ? cJSON_GetStringValue(id) : "";

  sendspin_psk_kind_t kind = SENDSPIN_PSK_SENTINEL;
  const uint8_t *psk = sendspin_psk_lookup(id_str, &kind);
  if (!psk) {
    /* A lookup miss. The spec's Sentinel Fallback says to answer with the
     * Sentinel anyway, but the server cannot verify a message 2 keyed with it
     * and will just drop the connection and retry forever. Deleting the
     * server's own record breaks that loop, and so does taking a new identity
     * it has no record for. */
    ESP_LOGW(TAG,
             "server referenced an unknown PSK (%s, category %s) -- "
             "answering with the Sentinel, which it cannot verify; delete "
             "this device's record on the server, or POST "
             "/api/sendspin/reset-identity and restart",
             id_str,
             cJSON_IsString(category) ? cJSON_GetStringValue(category)
                                      : "unspecified");
    psk = sendspin_noise_sentinel_psk();
    kind = SENDSPIN_PSK_SENTINEL;
  }
  s_psk_kind = kind;
  cJSON_Delete(root);
  return psk;
}

static bool sendspin_handshake_data(const cJSON *payload, uint8_t *out,
                                    size_t cap, size_t *out_len) {
  const cJSON *data = cJSON_GetObjectItemCaseSensitive(payload, "data");
  const char *b64 = cJSON_IsString(data) ? cJSON_GetStringValue(data) : NULL;
  return b64 &&
         sodium_base642bin(out, cap, b64, strlen(b64), NULL, out_len, NULL,
                           sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 0;
}

/* Encodes Noise message 2 and hands it to @p send, which decides whether it
 * goes out in the clear or through an already-running transport. */
static bool sendspin_send_message2(const uint8_t *msg, size_t msg_len,
                                   bool (*send)(cJSON *)) {
  char b64[sodium_base64_ENCODED_LEN(SENDSPIN_NOISE_MSG2_LEN,
                                     sodium_base64_VARIANT_URLSAFE_NO_PADDING)];
  sodium_bin2base64(b64, sizeof(b64), msg, msg_len,
                    sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  cJSON *out = NULL;
  cJSON *root = sendspin_new_message("noise/handshake", &out);
  if (!root) {
    return false;
  }
  cJSON_AddStringToObject(out, "data", b64);
  return send(root);
}

/* A re-handshake runs *inside* the live session: both Noise messages are
 * ordinary encrypted frames, and the keys are swapped only once message 2 is
 * on the wire, so the server can still read it. Its prologue is the previous
 * handshake's hash, which chains each session to the one it replaced.
 *
 * The server does this after pairing, to promote the connection from the
 * Sentinel to the long-term PSK without dropping it. */
static void sendspin_handle_rehandshake(const cJSON *payload) {
  uint8_t msg[SENDSPIN_NOISE_MSG_MAX];
  size_t msg_len = 0;
  if (!sendspin_handshake_data(payload, msg, sizeof(msg), &msg_len)) {
    sendspin_session_close("malformed noise/handshake");
    return;
  }

  static sendspin_noise_t next;
  if (sendspin_noise_start(&next, s_client_priv, s_client_pub, s_noise.rs,
                           sendspin_noise_handshake_hash(&s_noise),
                           SENDSPIN_NOISE_HASH_LEN) != ESP_OK) {
    sendspin_session_close("re-handshake setup failed");
    return;
  }

  char psk_json[192];
  size_t psk_len = 0;
  uint8_t reply[SENDSPIN_NOISE_MSG2_LEN];
  size_t reply_len = 0;
  static const uint8_t empty_object[2] = {'{', '}'};
  if (sendspin_noise_read_message1(&next, msg, msg_len, (uint8_t *)psk_json,
                                   sizeof(psk_json) - 1, &psk_len) != ESP_OK) {
    sendspin_session_close("re-handshake message 1 rejected");
    return;
  }
  psk_json[psk_len] = '\0';
  const uint8_t *psk = sendspin_select_psk(psk_json, psk_len);
  if (sendspin_noise_write_message2(&next, psk, empty_object,
                                    sizeof(empty_object), reply, sizeof(reply),
                                    &reply_len) != ESP_OK) {
    sendspin_session_close("re-handshake message 2 failed");
    return;
  }

  if (!sendspin_send_message2(reply, reply_len, sendspin_send_json)) {
    sendspin_session_close("re-handshake reply not sent");
    return;
  }

  s_noise = next;
  sodium_memzero(&next, sizeof(next));
  /* The server counts pairing activations per Noise session, so its counter
   * restarts here too. */
  s_pairing_index = 0;
  s_state = SENDSPIN_ENCRYPTED;
  ESP_LOGI(TAG, "re-handshake complete, session rekeyed");
}

static void sendspin_handle_noise_handshake(const cJSON *payload) {
  if (s_state != SENDSPIN_HANDSHAKE) {
    if (sendspin_noise_ready(&s_noise)) {
      sendspin_handle_rehandshake(payload);
      return;
    }
    /* The specified response to any handshake failure is a silent close. */
    ESP_LOGW(TAG, "unexpected noise/handshake in state %d", (int)s_state);
    sendspin_session_close("out-of-order noise/handshake");
    return;
  }

  uint8_t msg[SENDSPIN_NOISE_MSG_MAX];
  size_t msg_len = 0;
  if (!sendspin_handshake_data(payload, msg, sizeof(msg), &msg_len)) {
    sendspin_session_close("malformed noise/handshake");
    return;
  }

  char psk_json[192];
  size_t psk_len = 0;
  if (sendspin_noise_read_message1(&s_noise, msg, msg_len, (uint8_t *)psk_json,
                                   sizeof(psk_json) - 1, &psk_len) != ESP_OK) {
    /* Almost always a prologue mismatch or the wrong static key rather than
     * anything to do with the PSK, which is not mixed in yet. */
    sendspin_session_close("handshake message 1 rejected");
    return;
  }
  psk_json[psk_len] = '\0';
  const uint8_t *psk = sendspin_select_psk(psk_json, psk_len);

  static const uint8_t empty_object[2] = {'{', '}'};
  uint8_t reply[SENDSPIN_NOISE_MSG2_LEN];
  size_t reply_len = 0;
  if (sendspin_noise_write_message2(&s_noise, psk, empty_object,
                                    sizeof(empty_object), reply, sizeof(reply),
                                    &reply_len) != ESP_OK) {
    sendspin_session_close("handshake message 2 failed");
    return;
  }

  /* Still cleartext: the split has happened but message 2 itself is the last
   * thing on the wire that is not a transport ciphertext. */
  s_state = SENDSPIN_ENCRYPTED;
  if (!sendspin_send_message2(reply, reply_len, sendspin_send_cleartext_json)) {
    sendspin_session_close("handshake reply not sent");
  }
}

static void sendspin_handle_server_time(const cJSON *payload,
                                        int64_t arrival_us) {
  const int64_t client_tx =
      (int64_t)sendspin_number(payload, "client_transmitted", 0);
  const int64_t server_rx =
      (int64_t)sendspin_number(payload, "server_received", 0);
  const int64_t server_tx =
      (int64_t)sendspin_number(payload, "server_transmitted", 0);
  if (client_tx == 0 || server_rx == 0 || server_tx == 0) {
    return;
  }

  const bool was_converged = sendspin_time_converged(&s_clock);
  (void)sendspin_time_update(&s_clock, client_tx, server_rx, server_tx,
                             arrival_us);
  if (!was_converged && sendspin_time_converged(&s_clock)) {
    ESP_LOGI(TAG, "clock converged: rtt=%" PRId64 " us skew=%" PRId32 " ppm",
             sendspin_time_best_rtt_us(&s_clock),
             sendspin_time_skew_ppm(&s_clock));
    s_state_dirty = true;
  }
}

static void sendspin_handle_stream_start(const cJSON *payload) {
  const cJSON *player = cJSON_GetObjectItemCaseSensitive(payload, "player");
  if (!cJSON_IsObject(player)) {
    return; /* a stream for a role we do not implement */
  }

  const cJSON *codec = cJSON_GetObjectItemCaseSensitive(player, "codec");
  const char *codec_name =
      cJSON_IsString(codec) ? cJSON_GetStringValue(codec) : "";

  /* "fLaC" plus a STREAMINFO block is 42 bytes; the field is standard base64
   * with padding. */
  uint8_t header[64];
  size_t header_len = 0;
  const cJSON *hdr = cJSON_GetObjectItemCaseSensitive(player, "codec_header");
  if (cJSON_IsString(hdr)) {
    const char *b64 = cJSON_GetStringValue(hdr);
    if (sodium_base642bin(header, sizeof(header), b64, strlen(b64), NULL,
                          &header_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
      ESP_LOGW(TAG, "codec_header did not decode");
      header_len = 0;
    }
  }

  sendspin_codec_t which = SENDSPIN_CODEC_UNSUPPORTED;
  if (strcmp(codec_name, "pcm") == 0) {
    which = SENDSPIN_CODEC_PCM;
  } else if (strcmp(codec_name, "flac") == 0) {
    which = SENDSPIN_CODEC_FLAC;
#ifdef CONFIG_SENDSPIN_OPUS
  } else if (strcmp(codec_name, "opus") == 0) {
    which = SENDSPIN_CODEC_OPUS;
#endif
  }

  const sendspin_player_format_t format = {
      .sample_rate = (uint32_t)sendspin_number(player, "sample_rate", 44100),
      .channels = (uint8_t)sendspin_number(player, "channels", 2),
      .bit_depth = (uint8_t)sendspin_number(player, "bit_depth", 16),
      .codec = which,
      .codec_header = header_len > 0 ? header : NULL,
      .codec_header_len = header_len,
  };

  if (!s_output_available) {
    ESP_LOGW(TAG, "stream/start while the output is owned elsewhere");
    return;
  }

  /* Hand the output over before the player claims it: the AirPlay playback
   * task and the Sendspin renderer both drive the same DMA ring. */
  if (!sendspin_player_is_streaming() && s_activity_cb) {
    s_activity_cb(true);
  }

  if (sendspin_player_stream_start(&format) != ESP_OK) {
    /* The decoder is closed before the reopen is attempted, so a format
     * change that fails mid-stream leaves nothing to render. End the stream
     * before handing the output back, or the renderer stays installed and
     * fights the AirPlay playback task for it. */
    if (sendspin_player_is_streaming()) {
      sendspin_player_stream_end();
      sendspin_events_connected(false);
    }
    if (s_activity_cb) {
      s_activity_cb(false);
    }
    return;
  }

  sendspin_events_connected(true);
  sendspin_events_playing(true);
}

static bool sendspin_role_selected(const cJSON *payload) {
  /* `roles` is optional and means "all active roles" when absent. */
  const cJSON *roles = cJSON_GetObjectItemCaseSensitive(payload, "roles");
  if (!cJSON_IsArray(roles)) {
    return true;
  }
  const cJSON *role = NULL;
  cJSON_ArrayForEach(role, roles) {
    if (cJSON_IsString(role) &&
        strcmp(cJSON_GetStringValue(role), "player@v1") == 0) {
      return true;
    }
  }
  return false;
}

/* ------------------------------------------------------------------ */
/*  Pairing                                                            */
/* ------------------------------------------------------------------ */

static void sendspin_pake_reset(void) {
  sendspin_cpace_reset(&s_cpace);
  sodium_memzero(s_pake_sid, sizeof(s_pake_sid));
  s_pake_sid_len = 0;
  s_pake_active = false;
}

static void sendspin_send_pair_abort(const char *reason) {
  ESP_LOGW(TAG, "pairing aborted: %s", reason);
  s_pair_pending = false;
  sodium_memzero(s_pending_long_term, sizeof(s_pending_long_term));
  sendspin_pake_reset();

  cJSON *payload = NULL;
  cJSON *root = sendspin_new_message("pair/abort", &payload);
  if (!root) {
    return;
  }
  cJSON_AddStringToObject(payload, "reason", reason);
  (void)sendspin_send_json(root);
}

/* Decode a base64url field of an exact expected length. Anything else is a
 * malformed message rather than something to be tolerated: every one of these
 * fields is a fixed-size key, share or tag. */
static bool sendspin_b64_field(const cJSON *payload, const char *key,
                               uint8_t *out, size_t expect_len) {
  const cJSON *item = cJSON_GetObjectItemCaseSensitive(payload, key);
  if (!cJSON_IsString(item)) {
    return false;
  }
  const char *b64 = cJSON_GetStringValue(item);
  size_t len = 0;
  if (sodium_base642bin(out, expect_len, b64, strlen(b64), NULL, &len, NULL,
                        sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
    return false;
  }
  return len == expect_len;
}

/* Send a fixed-size blob as a base64url string. */
static void sendspin_add_b64(cJSON *object, const char *key,
                             const uint8_t *data, size_t len) {
  char b64[sodium_base64_ENCODED_LEN(SENDSPIN_CPACE_TAG_LEN,
                                     sodium_base64_VARIANT_URLSAFE_NO_PADDING)];
  sodium_bin2base64(b64, sizeof(b64), data, len,
                    sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  cJSON_AddStringToObject(object, key, b64);
}

/* Pairing PSK is the whole of the method: there is no PAKE round, because the
 * operator has already carried the secret across by hand in the pairing
 * token. The one thing the client must check is that this connection really
 * is keyed with the pairing PSK -- otherwise anyone who can reach the device
 * over an unpaired session could ask to be adopted. */
static void sendspin_begin_pairing_psk(void) {
  if (s_psk_kind != SENDSPIN_PSK_PAIRING) {
    ESP_LOGW(TAG, "pairing asked for over a session that is not keyed with "
                  "the pairing PSK");
    sendspin_send_pair_abort("method_not_supported");
    return;
  }

  sendspin_psk_generate(s_pending_long_term);

  cJSON *out = NULL;
  cJSON *root = sendspin_new_message("client/pair-finalize", &out);
  if (!root) {
    sodium_memzero(s_pending_long_term, sizeof(s_pending_long_term));
    return;
  }

  /* Unwrapped: wrapping the key under the PAKE's shared secret only applies
   * to the pairing-code methods, which have one. */
  sendspin_add_b64(out, "long_term_psk", s_pending_long_term, SENDSPIN_PSK_LEN);

  if (!sendspin_send_json(root)) {
    sodium_memzero(s_pending_long_term, sizeof(s_pending_long_term));
    return;
  }
  s_pair_pending = true;
  ESP_LOGI(TAG, "pairing: offered a long-term PSK to %s", s_server_id);
}

/* Static PIN runs CPace over the 8 digits the operator reads off the device.
 * The PIN never reaches the wire; each attempt gets one guess at it, which is
 * what makes a secret this short usable at all. */
static void sendspin_begin_pairing_static_pin(void) {
  size_t n = 0;
  memcpy(s_pake_sid, SENDSPIN_PAKE_SID_LABEL,
         sizeof(SENDSPIN_PAKE_SID_LABEL) - 1);
  n += sizeof(SENDSPIN_PAKE_SID_LABEL) - 1;
  memcpy(s_pake_sid + n, sendspin_noise_handshake_hash(&s_noise),
         SENDSPIN_NOISE_HASH_LEN);
  n += SENDSPIN_NOISE_HASH_LEN;
  /* The server bumps its counter before it runs an attempt, so the first
   * pairing activation of a Noise session is index 1, not 0. It silently
   * discards a pair-init below its count and errors on one above it. */
  const uint32_t index = ++s_pairing_index;
  s_pake_sid[n++] = (uint8_t)(index >> 24);
  s_pake_sid[n++] = (uint8_t)(index >> 16);
  s_pake_sid[n++] = (uint8_t)(index >> 8);
  s_pake_sid[n++] = (uint8_t)index;
  s_pake_sid_len = n;

  const char *pin = sendspin_psk_static_pin();
  if (sendspin_cpace_start(&s_cpace, SENDSPIN_CPACE_RESPONDER,
                           (const uint8_t *)pin, strlen(pin), s_pake_sid,
                           s_pake_sid_len, (const uint8_t *)"client",
                           strlen("client")) != ESP_OK) {
    sendspin_send_pair_abort("method_not_supported");
    return;
  }

  cJSON *out = NULL;
  cJSON *root = sendspin_new_message("client/pair-init", &out);
  if (!root) {
    sendspin_pake_reset();
    return;
  }
  /* commit_B belongs to the dynamic-PIN flow; a server rejects it here. */
  cJSON_AddNumberToObject(out, "pairing_index", (double)index);
  if (!sendspin_send_json(root)) {
    sendspin_pake_reset();
    return;
  }

  s_pake_active = true;
  ESP_LOGI(TAG, "pairing: static PIN, attempt %u with %s", (unsigned)index,
           s_server_id);
}

static void sendspin_begin_pairing(const cJSON *payload) {
  const cJSON *pairing = cJSON_GetObjectItemCaseSensitive(payload, "pairing");
  const cJSON *method = cJSON_GetObjectItemCaseSensitive(pairing, "method");
  const char *method_str =
      cJSON_IsString(method) ? cJSON_GetStringValue(method) : "";

  if (strcmp(method_str, "static_pin") == 0) {
    sendspin_begin_pairing_static_pin();
  } else if (strcmp(method_str, "pairing_psk") == 0) {
    sendspin_begin_pairing_psk();
  } else {
    sendspin_send_pair_abort("method_not_supported");
  }
}

/* The server opens the PAKE with its share. Ours goes back before the shared
 * secret is derived, matching the reference client's ordering. */
static void sendspin_handle_pair_auth(const cJSON *payload) {
  if (!s_pake_active) {
    ESP_LOGW(TAG, "unsolicited server/pair-auth");
    return;
  }

  uint8_t peer_share[SENDSPIN_CPACE_SHARE_LEN];
  if (!sendspin_b64_field(payload, "pake_msg_1", peer_share,
                          sizeof(peer_share))) {
    sendspin_send_pair_abort("pin_mismatch");
    return;
  }

  cJSON *out = NULL;
  cJSON *root = sendspin_new_message("client/pair-auth", &out);
  if (!root) {
    sendspin_pake_reset();
    return;
  }
  sendspin_add_b64(out, "pake_msg_2", s_cpace.public_share,
                   SENDSPIN_CPACE_SHARE_LEN);
  if (!sendspin_send_json(root)) {
    sendspin_pake_reset();
    return;
  }

  if (sendspin_cpace_derive(&s_cpace, peer_share, (const uint8_t *)"server",
                            strlen("server")) != ESP_OK) {
    /* A degenerate share is indistinguishable from garbage to an operator,
     * and the abort reasons a client may send do not cover it; pin_mismatch
     * at least steers them to retry rather than to wait. */
    sendspin_send_pair_abort("pin_mismatch");
  }
}

/* Both sides now prove they reached the same key. The server goes first, so a
 * device that was given the wrong PIN says so without the operator having to
 * wait for a timeout. */
static void sendspin_handle_pair_confirm(const cJSON *payload) {
  if (!s_pake_active) {
    ESP_LOGW(TAG, "unsolicited server/pair-confirm");
    return;
  }

  uint8_t server_kc[SENDSPIN_CPACE_TAG_LEN];
  if (!sendspin_b64_field(payload, "server_kc", server_kc, sizeof(server_kc)) ||
      !sendspin_cpace_verify(&s_cpace, server_kc)) {
    ESP_LOGW(TAG, "pairing: the server did not prove it knew the PIN");
    sendspin_send_pair_abort("pin_mismatch");
    return;
  }

  uint8_t tag[SENDSPIN_CPACE_TAG_LEN];
  cJSON *out = NULL;
  cJSON *root = sendspin_new_message("client/pair-confirm", &out);
  if (!root || sendspin_cpace_tag(&s_cpace, tag) != ESP_OK) {
    cJSON_Delete(root);
    sendspin_pake_reset();
    return;
  }
  /* nonce_B belongs to the dynamic-PIN flow; a server rejects it here. */
  sendspin_add_b64(out, "client_kc", tag, sizeof(tag));
  if (!sendspin_send_json(root)) {
    sendspin_pake_reset();
    return;
  }

  /* Wrap the new long-term PSK under the PAKE output. The Noise session is
   * already encrypted, but it is only keyed with the Sentinel during a PIN
   * pairing, so this is what actually keeps the PSK away from a man in the
   * middle: only someone who knew the PIN can unwrap it. */
  uint8_t wrap_key[crypto_hash_sha256_BYTES];
  crypto_hash_sha256_state hash;
  crypto_hash_sha256_init(&hash);
  crypto_hash_sha256_update(&hash, (const uint8_t *)"sendspin-pair-psk-wrap-v1",
                            strlen("sendspin-pair-psk-wrap-v1"));
  crypto_hash_sha256_update(&hash, s_pake_sid, s_pake_sid_len);
  crypto_hash_sha256_update(&hash, sendspin_cpace_isk(&s_cpace),
                            SENDSPIN_CPACE_ISK_LEN);
  crypto_hash_sha256_final(&hash, wrap_key);

  sendspin_psk_generate(s_pending_long_term);

  /* An all-zero nonce is safe only because the key is single-use: the session
   * id it is derived from carries the Noise handshake hash and the attempt
   * index, so no two attempts ever share one. */
  static const uint8_t nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0};
  uint8_t wrapped[SENDSPIN_PSK_LEN + crypto_aead_chacha20poly1305_IETF_ABYTES];
  unsigned long long wrapped_len = 0;
  const int rc = crypto_aead_chacha20poly1305_ietf_encrypt(
      wrapped, &wrapped_len, s_pending_long_term, SENDSPIN_PSK_LEN, NULL, 0,
      NULL, nonce, wrap_key);
  sodium_memzero(wrap_key, sizeof(wrap_key));
  sodium_memzero(&hash, sizeof(hash));

  out = NULL;
  root = rc == 0 ? sendspin_new_message("client/pair-finalize", &out) : NULL;
  if (!root) {
    sodium_memzero(s_pending_long_term, sizeof(s_pending_long_term));
    sendspin_pake_reset();
    return;
  }
  sendspin_add_b64(out, "wrapped_psk", wrapped, (size_t)wrapped_len);
  sodium_memzero(wrapped, sizeof(wrapped));

  if (!sendspin_send_json(root)) {
    sodium_memzero(s_pending_long_term, sizeof(s_pending_long_term));
    sendspin_pake_reset();
    return;
  }
  s_pair_pending = true;
  ESP_LOGI(TAG, "pairing: PIN confirmed, offered a long-term PSK to %s",
           s_server_id);
}

/* The server acknowledges, and only then is the pairing real on both sides.
 * It re-handshakes to the new key afterwards -- either in band, or by
 * reconnecting, which lands on the same record either way. */
static void sendspin_handle_pair_finalize(void) {
  if (!s_pair_pending) {
    ESP_LOGW(TAG, "unsolicited server/pair-finalize");
    return;
  }
  s_pair_pending = false;

  if (sendspin_psk_add_record(s_server_id, s_pending_long_term) == ESP_OK) {
    ESP_LOGI(TAG, "paired with %s", s_server_id);
  }
  sodium_memzero(s_pending_long_term, sizeof(s_pending_long_term));
  sendspin_pake_reset();
}

/* server/activate declares what the connection is for. Roles arrive with the
 * first activation, and playback is only ever offered once the server's
 * operator has approved this client.  An empty activity set is not an error:
 * it is how a server parks a device whose operator has not approved it yet,
 * and the protocol's answer to that is to sit still, keep the clock
 * synchronised and wait. */
static void sendspin_handle_activate(const cJSON *payload) {
  const cJSON *activities =
      cJSON_GetObjectItemCaseSensitive(payload, "activities");
  const cJSON *roles =
      cJSON_GetObjectItemCaseSensitive(payload, "active_roles");

  bool playback = false;
  bool pairing = false;
  const cJSON *item = NULL;
  cJSON_ArrayForEach(item, activities) {
    if (!cJSON_IsString(item)) {
      continue;
    }
    const char *activity = cJSON_GetStringValue(item);
    if (strcmp(activity, "playback") == 0) {
      playback = true;
    } else if (strcmp(activity, "pairing") == 0) {
      pairing = true;
    }
  }

  /* active_roles is required on the first activation and persists across
   * later ones that omit it, so re-deriving it every time would silently
   * drop the roles the moment the server changed only its activity set. */
  if (cJSON_IsArray(roles)) {
    s_role_player = false;
    s_role_metadata = false;
    s_role_controller = false;
    cJSON_ArrayForEach(item, roles) {
      if (!cJSON_IsString(item)) {
        continue;
      }
      const char *role = cJSON_GetStringValue(item);
      if (strcmp(role, "player@v1") == 0) {
        s_role_player = true;
      } else if (strcmp(role, "metadata@v1") == 0) {
        s_role_metadata = true;
      } else if (strcmp(role, "controller@v1") == 0) {
        s_role_controller = true;
      }
    }
  }
  ESP_LOGI(TAG,
           "activated: playback=%s pairing=%s player@v1=%s metadata@v1=%s "
           "controller@v1=%s",
           playback ? "yes" : "no", pairing ? "yes" : "no",
           s_role_player ? "yes" : "no", s_role_metadata ? "yes" : "no",
           s_role_controller ? "yes" : "no");

  s_state = SENDSPIN_ACTIVATED;
  s_pairing_busy = pairing;

  /* A pairing activation carries no roles, so there is no player state worth
   * reporting and the exchange gets the connection to itself. */
  if (pairing) {
    sendspin_begin_pairing(payload);
    return;
  }

  /* The server must not send audio before this first report. */
  sendspin_send_state();
}

/* Volume is a perceived-loudness percentage, and the DAC drivers already
 * expand the firmware's -30..0 dB scale onto their own taper, so map straight
 * onto that scale rather than applying the spec's amplitude curve on top of a
 * curve. This is also the scale the buttons and the web UI report, which is
 * what keeps the three agreeing. */
static void sendspin_handle_command(const cJSON *payload) {
  const cJSON *player = cJSON_GetObjectItemCaseSensitive(payload, "player");
  if (!cJSON_IsObject(player)) {
    return;
  }
  const cJSON *command = cJSON_GetObjectItemCaseSensitive(player, "command");
  if (!cJSON_IsString(command)) {
    return;
  }
  const char *cmd = cJSON_GetStringValue(command);

  if (strcmp(cmd, "volume") == 0) {
    const cJSON *volume = cJSON_GetObjectItemCaseSensitive(player, "volume");
    if (!cJSON_IsNumber(volume)) {
      return;
    }
    int pct = (int)cJSON_GetNumberValue(volume);
    pct = pct < 0 ? 0 : (pct > 100 ? 100 : pct);
    playback_control_set_volume_percent(pct);
  } else if (strcmp(cmd, "mute") == 0) {
    const cJSON *mute = cJSON_GetObjectItemCaseSensitive(player, "mute");
    if (!cJSON_IsBool(mute)) {
      return;
    }
    playback_control_set_muted(cJSON_IsTrue(mute));
  } else {
    ESP_LOGD(TAG, "ignoring unsupported command %s", cmd);
    return;
  }

  /* "State updates must be sent whenever any state changes, including when
   * the volume was changed through a server/command." */
  s_state_dirty = true;
}

static void sendspin_handle_message(const char *json, size_t len,
                                    int64_t arrival_us) {
  cJSON *root = cJSON_ParseWithLength(json, len);
  if (!root) {
    ESP_LOGW(TAG, "unparseable message (%u bytes)", (unsigned)len);
    return;
  }

  const cJSON *type_item = cJSON_GetObjectItemCaseSensitive(root, "type");
  const char *type = cJSON_IsString(type_item) ? type_item->valuestring : NULL;
  const cJSON *payload = cJSON_GetObjectItemCaseSensitive(root, "payload");
  if (!type) {
    cJSON_Delete(root);
    return;
  }

  if (strcmp(type, "server/time") != 0) {
    ESP_LOGD(TAG, "rx %s", type);
  }

  /* Only the two cleartext handshake messages are legal before the split.
   * Anything else arriving in the clear is a downgrade attempt, whatever it
   * claims to be. */
  const bool handshake_msg =
      strcmp(type, "server/init") == 0 || strcmp(type, "noise/handshake") == 0;
  if (!sendspin_noise_ready(&s_noise) && !handshake_msg) {
    ESP_LOGW(TAG, "%s arrived before the handshake completed", type);
    sendspin_session_close("out-of-order message");
    cJSON_Delete(root);
    return;
  }

  if (strcmp(type, "server/init") == 0) {
    /* The prologue is the bytes as received, so it is captured before the
     * parse rather than rebuilt from it. */
    if (!sendspin_prologue_append(json, len)) {
      sendspin_session_close("server/init too large");
    } else {
      sendspin_handle_server_init(payload);
    }
  } else if (strcmp(type, "noise/handshake") == 0) {
    sendspin_handle_noise_handshake(payload);
  } else if (strcmp(type, "server/hello") == 0) {
    const cJSON *name = cJSON_GetObjectItemCaseSensitive(payload, "name");
    ESP_LOGI(TAG, "server \"%s\"",
             cJSON_IsString(name) ? cJSON_GetStringValue(name) : "?");
    s_state = SENDSPIN_READY;
    sendspin_send_hello();
  } else if (strcmp(type, "server/activate") == 0) {
    sendspin_handle_activate(payload);
  } else if (strcmp(type, "server/state") == 0) {
    sendspin_handle_server_state(payload);
  } else if (strcmp(type, "server/command") == 0) {
    sendspin_handle_command(payload);
  } else if (strcmp(type, "server/pair-auth") == 0) {
    sendspin_handle_pair_auth(payload);
  } else if (strcmp(type, "server/pair-confirm") == 0) {
    sendspin_handle_pair_confirm(payload);
  } else if (strcmp(type, "server/pair-finalize") == 0) {
    sendspin_handle_pair_finalize();
  } else if (strcmp(type, "pair/abort") == 0) {
    const cJSON *reason = cJSON_GetObjectItemCaseSensitive(payload, "reason");
    ESP_LOGW(TAG, "server aborted pairing: %s",
             cJSON_IsString(reason) ? cJSON_GetStringValue(reason)
                                    : "unspecified");
    s_pair_pending = false;
    sodium_memzero(s_pending_long_term, sizeof(s_pending_long_term));
    sendspin_pake_reset();
  } else if (strcmp(type, "server/time") == 0) {
    sendspin_handle_server_time(payload, arrival_us);
  } else if (strcmp(type, "stream/start") == 0) {
    sendspin_handle_stream_start(payload);
  } else if (strcmp(type, "stream/clear") == 0) {
    if (sendspin_role_selected(payload)) {
      sendspin_player_stream_clear();
    }
  } else if (strcmp(type, "stream/end") == 0) {
    if (sendspin_role_selected(payload)) {
      /* The stream may already be stopped -- something else took the output
       * and ended it -- but the event state still has to be cleared, and only
       * a stream we were actually rendering hands the output back. */
      const bool was_streaming = sendspin_player_is_streaming();
      if (was_streaming) {
        sendspin_player_stream_end();
      }
      sendspin_events_connected(false);
      if (was_streaming && s_activity_cb) {
        s_activity_cb(false);
      }
    }
  }

  cJSON_Delete(root);
}

/* Audio chunk: [4][timestamp:8 BE][send_ahead:4 BE][encoded audio]. */
static int64_t sendspin_read_be64(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) {
    v = (v << 8) | p[i];
  }
  return (int64_t)v;
}

static void sendspin_handle_binary(const uint8_t *data, size_t len,
                                   int64_t arrival_us);

/* Fragmented message: [1][flags][orig_type on the first only][data].
 * flags bit 1 = first fragment, bit 0 = last. */
static void sendspin_handle_fragment(const uint8_t *data, size_t len,
                                     int64_t arrival_us) {
  if (len < 2 || !s_asm) {
    return;
  }
  const uint8_t flags = data[1];
  const bool first = (flags & 0x02U) != 0U;
  const bool last = (flags & 0x01U) != 0U;
  if ((flags & 0xFCU) != 0U) {
    sendspin_session_close("reserved fragment flags set");
    return;
  }

  size_t offset = 2;
  if (first) {
    if (len < 3) {
      sendspin_session_close("truncated first fragment");
      return;
    }
    s_asm_type = data[2];
    if (s_asm_type == SENDSPIN_BIN_FRAGMENT) {
      sendspin_session_close("nested fragmentation");
      return;
    }
    offset = 3;
    s_asm_len = 0;
    s_asm_active = true;
    s_asm[s_asm_len++] = s_asm_type;
  } else if (!s_asm_active) {
    sendspin_session_close("continuation without a first fragment");
    return;
  }

  const size_t chunk = len - offset;
  if (s_asm_len + chunk > (size_t)CONFIG_SENDSPIN_RX_BUFFER_SIZE) {
    ESP_LOGW(TAG, "reassembly overflow, dropping message");
    s_asm_active = false;
    s_asm_len = 0;
    return;
  }
  memcpy(&s_asm[s_asm_len], &data[offset], chunk);
  s_asm_len += chunk;

  if (last) {
    s_asm_active = false;
    sendspin_handle_binary(s_asm, s_asm_len, arrival_us);
    s_asm_len = 0;
  }
}

static void sendspin_handle_binary(const uint8_t *data, size_t len,
                                   int64_t arrival_us) {
  if (len < 1) {
    return;
  }

  switch (data[0]) {
  case SENDSPIN_BIN_JSON:
    sendspin_handle_message((const char *)&data[1], len - 1, arrival_us);
    break;

  case SENDSPIN_BIN_FRAGMENT:
    sendspin_handle_fragment(data, len, arrival_us);
    break;

  case SENDSPIN_BIN_AUDIO_CHUNK:
    if (len > SENDSPIN_AUDIO_HEADER) {
      /* Header is a type byte and a big-endian int64 timestamp, and nothing
       * else -- send_ahead is a scheduling term the server keeps to itself. */
      sendspin_player_chunk(sendspin_read_be64(&data[1]),
                            &data[SENDSPIN_AUDIO_HEADER],
                            len - SENDSPIN_AUDIO_HEADER);
    }
    break;

  default:
    ESP_LOGD(TAG, "ignoring binary type %u", (unsigned)data[0]);
    break;
  }
}

/* ------------------------------------------------------------------ */
/*  WebSocket endpoint                                                 */
/* ------------------------------------------------------------------ */

/* The server answers the WebSocket handshake itself and deliberately does not
 * invoke the URI handler for it, so this is the only place a real client's
 * arrival can be observed. A plain GET still reaches the handler below, which
 * is why opening the session cannot live there: a bare HTTP probe would claim
 * a session that no WebSocket is behind. */
static esp_err_t sendspin_ws_connected(httpd_req_t *req) {
  const int fd = httpd_req_to_sockfd(req);
  if (!sendspin_lock()) {
    ESP_LOGE(TAG, "session lock timed out; rejecting fd=%d", fd);
    return ESP_FAIL;
  }

  if (s_fd >= 0 && s_fd != fd && sendspin_fd_is_live(s_fd)) {
    /* One server at a time. The protocol's own answer to a second one is
     * client/goodbye with reason another_server; dropping the newcomer is
     * the conservative version of that for a device with three sockets.
     * Only an incumbent that is demonstrably still connected gets to win,
     * or a dead one would lock the endpoint out until a reboot. */
    ESP_LOGW(TAG, "rejecting a second server on fd=%d", fd);
    sendspin_unlock();
    return ESP_FAIL;
  }
  if (s_fd >= 0 && s_fd != fd) {
    sendspin_session_close("replaced by a new server");
  }
  ESP_LOGI(TAG, "server connected on fd=%d", fd);
  sendspin_time_reset(&s_clock);
  sendspin_noise_reset(&s_noise);
  s_prologue_len = 0;
  s_asm_active = false;
  s_asm_len = 0;
  s_reported_available = false;
  s_fd = fd;
  /* client/init is sent from the housekeeping task rather than here, so that
   * it cannot race the handshake response onto the socket. */
  s_state = SENDSPIN_NEED_INIT;
  sendspin_unlock();
  return ESP_OK;
}

/* Acts on one received frame. Runs under s_lock, so it may read and write
 * session state freely. */
static void sendspin_ws_dispatch(const httpd_ws_frame_t *frame,
                                 int64_t arrival_us) {
  if (frame->type == HTTPD_WS_TYPE_TEXT) {
    if (sendspin_noise_ready(&s_noise)) {
      ESP_LOGE(TAG, "cleartext frame after the handshake");
      sendspin_session_close("cleartext in transport mode");
      return;
    }
    sendspin_handle_message((const char *)s_rx, frame->len, arrival_us);
    return;
  }

  if (frame->type != HTTPD_WS_TYPE_BINARY) {
    return;
  }
  if (!sendspin_noise_ready(&s_noise)) {
    ESP_LOGE(TAG, "binary frame before the handshake");
    sendspin_session_close("unencrypted binary frame");
    return;
  }

  size_t plain_len = 0;
  /* A single AEAD failure is terminal by design: the nonce counters have
   * diverged, so nothing after this frame would decrypt either. */
  if (sendspin_noise_decrypt(&s_noise, s_rx, frame->len, s_pt,
                             (size_t)CONFIG_SENDSPIN_RX_BUFFER_SIZE,
                             &plain_len) != ESP_OK) {
    ESP_LOGE(TAG, "transport decryption failed on a %u byte frame",
             (unsigned)frame->len);
    sendspin_session_close("decryption failed");
    return;
  }
  sendspin_handle_binary(s_pt, plain_len, arrival_us);
}

static esp_err_t sendspin_ws_handler(httpd_req_t *req) {
  if (req->method == HTTP_GET) {
    return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                               "WebSocket upgrade required");
  }

  /* Timestamped before anything else in the handler, the lock included, so
   * the clock estimate measures the network and not our own dispatch. */
  const int64_t arrival_us = esp_timer_get_time();

  httpd_ws_frame_t frame = {0};
  if (httpd_ws_recv_frame(req, &frame, 0) != ESP_OK) {
    return ESP_OK;
  }

  if (frame.type == HTTPD_WS_TYPE_CLOSE) {
    sendspin_locked_close("peer closed");
    return ESP_OK;
  }

  if (frame.len == 0) {
    return ESP_OK;
  }
  if (frame.len > (size_t)CONFIG_SENDSPIN_RX_BUFFER_SIZE) {
    /* The payload cannot be consumed, and leaving it in the socket
     * desynchronises every frame after it (see log_stream.c), so the session
     * has to go rather than the message. */
    ESP_LOGE(TAG, "frame of %u bytes exceeds the receive buffer",
             (unsigned)frame.len);
    sendspin_locked_close("frame too large");
    return ESP_FAIL;
  }

  /* Read the payload before taking the lock. A frame split across segments
   * blocks here, and waiting on the network is the one thing that must not
   * happen with the housekeeping task's lock held. */
  frame.payload = s_rx;
  if (httpd_ws_recv_frame(req, &frame,
                          (size_t)CONFIG_SENDSPIN_RX_BUFFER_SIZE) != ESP_OK) {
    return ESP_OK;
  }

  if (!sendspin_lock()) {
    ESP_LOGE(TAG, "session lock timed out; dropped a %u byte frame",
             (unsigned)frame.len);
    return ESP_OK;
  }
  sendspin_ws_dispatch(&frame, arrival_us);
  sendspin_unlock();
  return ESP_OK;
}

/* ------------------------------------------------------------------ */
/*  Housekeeping                                                       */
/* ------------------------------------------------------------------ */

static void sendspin_advertise(void) {
  if (s_mdns_advertised) {
    return;
  }
  /* mdns_init() is a no-op once the AirPlay advertisement has run, and works
   * standalone when it has not (Sendspin is registered before AirPlay
   * starts). */
  esp_err_t err = mdns_init();
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "mDNS init failed: %s", esp_err_to_name(err));
    return;
  }

  char name[65];
  settings_get_device_name(name, sizeof(name));

  mdns_txt_item_t txt[] = {
      {"path", SENDSPIN_WS_PATH},
      {"name", name},
  };
  err = mdns_service_add(name, "_sendspin", "_tcp", 80, txt,
                         sizeof(txt) / sizeof(txt[0]));
  if (err != ESP_OK) {
    /* Expected until something sets the mDNS hostname, which the AirPlay
     * advertisement does after us. The caller retries every tick, so the
     * signal to watch for is the absence of the success line below. */
    ESP_LOGD(TAG, "_sendspin._tcp not advertised yet: %s",
             esp_err_to_name(err));
    return;
  }
  s_mdns_advertised = true;
  ESP_LOGI(TAG, "_sendspin._tcp advertised on port 80, path " SENDSPIN_WS_PATH);
}

static void sendspin_task(void *arg) {
  (void)arg;

  while (1) {
    vTaskDelay(pdMS_TO_TICKS(SENDSPIN_TICK_MS));

    if (!s_mdns_advertised &&
        (ethernet_is_connected() || wifi_is_connected())) {
      sendspin_advertise();
    }

    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
      continue;
    }

    /* Reap a session that went away without saying so, before acting on it. */
    if (s_fd >= 0 && !sendspin_fd_is_live(s_fd)) {
      sendspin_session_close("socket gone");
    }

    switch (s_state) {
    case SENDSPIN_IDLE:
      break;

    case SENDSPIN_NEED_INIT:
      sendspin_send_init();
      s_state = SENDSPIN_INIT_SENT;
      break;

    case SENDSPIN_INIT_SENT:
    case SENDSPIN_HANDSHAKE:
    case SENDSPIN_ENCRYPTED:
    case SENDSPIN_READY:
      /* Nothing may leave the client between client/init and the first
       * server/activate -- not even a clock request. */
      break;

    case SENDSPIN_ACTIVATED: {
      if (s_pairing_busy) {
        /* The pairing exchange owns the connection until it settles. */
        break;
      }
      const int64_t now_us = esp_timer_get_time();
      const uint32_t interval_ms =
          sendspin_time_converged(&s_clock)
              ? (uint32_t)CONFIG_SENDSPIN_TIME_SYNC_INTERVAL_MS
              : SENDSPIN_TIME_BURST_MS;
      if (now_us - s_last_time_tx_us >= (int64_t)interval_ms * 1000LL) {
        sendspin_send_time_request();
      }
      const bool available =
          s_output_available && sendspin_time_converged(&s_clock);
      if (s_state_dirty || available != s_reported_available ||
          playback_control_get_level_percent() != s_reported_volume ||
          playback_control_is_muted() != s_reported_muted) {
        sendspin_send_state();
      }
      sendspin_meta_tick();
      sendspin_command_tick();
      break;
    }
    }

    xSemaphoreGive(s_lock);
  }
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

/* Undo a partial sendspin_init(). s_rx doubles as the "initialised" flag for
 * both the early return above and sendspin_register(), so every failure has
 * to leave it NULL or a half-built client is advertised on the network. */
static void sendspin_init_cleanup(void) {
  free(s_rx);
  free(s_asm);
  free(s_pt);
  free(s_tx_plain);
  free(s_tx_cipher);
  s_rx = NULL;
  s_asm = NULL;
  s_pt = NULL;
  s_tx_plain = NULL;
  s_tx_cipher = NULL;
  if (s_lock) {
    vSemaphoreDelete(s_lock);
    s_lock = NULL;
  }
  if (s_tx_lock) {
    vSemaphoreDelete(s_tx_lock);
    s_tx_lock = NULL;
  }
  if (s_cmd_queue) {
    vQueueDelete(s_cmd_queue);
    s_cmd_queue = NULL;
  }
}

esp_err_t sendspin_init(sendspin_activity_cb_t callback) {
  if (s_rx) {
    return ESP_OK;
  }

  if (sodium_init() < 0) {
    ESP_LOGE(TAG, "libsodium init failed");
    return ESP_FAIL;
  }

  s_lock = xSemaphoreCreateMutex();
  s_tx_lock = xSemaphoreCreateMutex();
  s_cmd_queue = xQueueCreate(4, sizeof(uint8_t));
  if (!s_lock || !s_tx_lock || !s_cmd_queue) {
    sendspin_init_cleanup();
    return ESP_ERR_NO_MEM;
  }

  s_rx = heap_caps_malloc((size_t)CONFIG_SENDSPIN_RX_BUFFER_SIZE,
                          MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  s_asm = heap_caps_malloc((size_t)CONFIG_SENDSPIN_RX_BUFFER_SIZE,
                           MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  s_pt = heap_caps_malloc((size_t)CONFIG_SENDSPIN_RX_BUFFER_SIZE,
                          MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  s_tx_plain = heap_caps_malloc(SENDSPIN_TX_PLAIN_MAX,
                                MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  s_tx_cipher = heap_caps_malloc(SENDSPIN_TX_PLAIN_MAX + SENDSPIN_NOISE_TAG_LEN,
                                 MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!s_rx || !s_asm || !s_pt || !s_tx_plain || !s_tx_cipher) {
    sendspin_init_cleanup();
    return ESP_ERR_NO_MEM;
  }

  esp_err_t err = sendspin_load_identity();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "identity setup failed: %s", esp_err_to_name(err));
    sendspin_init_cleanup();
    return err;
  }

  sendspin_time_reset(&s_clock);
  err = sendspin_player_init(&s_clock);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "player init failed: %s", esp_err_to_name(err));
    sendspin_init_cleanup();
    return err;
  }

  s_activity_cb = callback;
  ESP_LOGI(TAG, "client_id %s", s_client_id);
  /* The pairing token is a standing credential -- anyone who reads it can
   * adopt this device -- but it is only reachable by someone already on the
   * network with access to the console or the web UI, which is the same
   * "operator" trust boundary the specification assumes. */
  ESP_LOGI(TAG, "pairing token %s", sendspin_psk_token());
  ESP_LOGI(TAG, "pairing PIN %s", sendspin_psk_static_pin());
  return ESP_OK;
}

esp_err_t sendspin_register(httpd_handle_t server) {
  if (!s_rx) {
    return ESP_ERR_INVALID_STATE;
  }
  s_server = server;

  httpd_uri_t ws_uri = {
      .uri = SENDSPIN_WS_PATH,
      .method = HTTP_GET,
      .handler = sendspin_ws_handler,
      .is_websocket = true,
      .ws_post_handshake_cb = sendspin_ws_connected,
  };
  esp_err_t err = httpd_register_uri_handler(server, &ws_uri);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "failed to register " SENDSPIN_WS_PATH ": %s",
             esp_err_to_name(err));
    return err;
  }

  if (!s_task) {
    task_create_spiram(sendspin_task, "sendspin", SENDSPIN_TASK_STACK, NULL, 4,
                       &s_task, NULL);
  }
  ESP_LOGI(TAG, "listening on " SENDSPIN_WS_PATH);
  return ESP_OK;
}

bool sendspin_is_streaming(void) {
  return sendspin_player_is_streaming();
}

void sendspin_set_output_available(bool available) {
  if (!s_lock) {
    return; /* compiled in but never started */
  }
  /* Called from whichever task noticed the takeover -- the USB writer or the
   * Bluetooth stack -- so it races both the tick and the httpd task. */
  if (!sendspin_lock()) {
    ESP_LOGE(TAG, "session lock timed out; output availability not applied");
    return;
  }
  if (s_output_available == available) {
    sendspin_unlock();
    return;
  }
  s_output_available = available;
  ESP_LOGI(TAG, "output %s", available ? "released to Sendspin" : "taken over");

  bool end_stream = false;
  if (!available && sendspin_player_is_streaming()) {
    /* A player that simply reports available:false leaves the server's queue
     * stopped, and a stopped queue does not restart itself when the player
     * comes back. Pausing it first leaves something to resume. */
    if (s_role_controller && (s_ctrl_commands & (1U << SENDSPIN_CMD_PAUSE))) {
      sendspin_send_controller_command(SENDSPIN_CMD_PAUSE);
      s_resume_on_release = true;
    }
    /* Sendspin no longer holds the output, so it no longer holds the display
     * or the amplifier either. Without this the source stays PLAYING for ever
     * -- the server's own stream/end is gated on the player still running --
     * and the aggregate never reaches DISCONNECTED again. */
    sendspin_events_connected(false);
    end_stream = true;
  } else if (available && s_resume_on_release) {
    s_resume_on_release = false;
    /* Queued rather than sent here: the tick drains commands after the state
     * report, so the server sees the player available again before the play. */
    (void)sendspin_send_command(SENDSPIN_CMD_PLAY);
  }
  s_state_dirty = true;
  sendspin_unlock();

  /* Outside the lock: the stream end joins the playback task, which can take
   * longer than SENDSPIN_LOCK_WAIT_MS, and a caller that timed out on the lock
   * tears the session down. The renderer is still detached before this returns,
   * which is what whoever is taking the output is waiting for. */
  if (end_stream) {
    sendspin_player_stream_end();
  }
}

bool sendspin_send_command(sendspin_command_t cmd) {
  if (!s_cmd_queue || !s_role_controller || cmd >= SENDSPIN_CMD_COUNT) {
    return false;
  }
  if ((s_ctrl_commands & (1U << (uint32_t)cmd)) == 0) {
    return false;
  }
  const uint8_t item = (uint8_t)cmd;
  return xQueueSend(s_cmd_queue, &item, 0) == pdTRUE;
}

bool sendspin_is_playing(void) {
  return s_events_playing;
}

const char *sendspin_pairing_token(void) {
  return sendspin_psk_token();
}

const char *sendspin_pairing_pin(void) {
  return sendspin_psk_static_pin();
}

unsigned sendspin_paired_count(void) {
  return (unsigned)sendspin_psk_record_count();
}

esp_err_t sendspin_forget_pairings(void) {
  if (!s_lock) {
    return ESP_ERR_INVALID_STATE;
  }
  if (!sendspin_lock()) {
    return ESP_ERR_TIMEOUT;
  }
  const esp_err_t err = sendspin_psk_forget_all();
  sendspin_unlock();
  if (err != ESP_OK) {
    return err;
  }
  /* A session already keyed with a long-term PSK keeps running; the records
   * only decide what the *next* handshake can resolve. */
  ESP_LOGI(TAG, "pairing records cleared");
  return ESP_OK;
}

esp_err_t sendspin_reset_identity(void) {
  if (!s_lock) {
    return ESP_ERR_INVALID_STATE;
  }
  if (!sendspin_lock()) {
    return ESP_ERR_TIMEOUT;
  }

  uint8_t previous[sizeof(s_client_priv)];
  memcpy(previous, s_client_priv, sizeof(previous));

  randombytes_buf(s_client_priv, sizeof(s_client_priv));
  esp_err_t err = sendspin_store_identity();
  if (err != ESP_OK) {
    memcpy(s_client_priv, previous, sizeof(previous));
    sodium_memzero(previous, sizeof(previous));
    sendspin_unlock();
    return err;
  }
  sodium_memzero(previous, sizeof(previous));

  /* Records are only ever looked up under the old client_id, so no server can
   * reach them again.  Clear them before sendspin_derive_identity() reloads
   * the table from NVS. */
  err = sendspin_psk_forget_all();
  if (err == ESP_OK) {
    err = sendspin_derive_identity();
  }
  sendspin_unlock();
  if (err != ESP_OK) {
    return err;
  }
  ESP_LOGI(TAG, "new client identity %s", s_client_id);
  return ESP_OK;
}

bool sendspin_server_connected(void) {
  return s_fd >= 0 && s_state != SENDSPIN_IDLE;
}

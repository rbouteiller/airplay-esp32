#include "audio_output.h"
#include "audio_receiver.h"
#include "buttons.h"
#include "spiram_task.h"
#include "display.h"
#include "dns_server.h"
#include "ethernet.h"
#include "led.h"
#include "hap.h"
#include "mdns_airplay.h"
#include "nvs_flash.h"
#include "playback_control.h"
#include "ptp_clock.h"
#include "rtsp_server.h"
#include "settings.h"
#include "web_server.h"
#include "log_stream.h"
#include "wifi.h"
#include "spiffs_storage.h"

#ifdef CONFIG_BT_A2DP_ENABLE
#include "a2dp_sink.h"
#include "bt_coex.h"
#include "rtsp_events.h"
#endif

#ifdef CONFIG_DAC_TAS57XX
#include "dac_tas57xx.h"
#endif

#ifdef CONFIG_DAC_TAS58XX
#include "dac_tas58xx.h"
#endif

#include "iot_board.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "main";

// AP mode IP address (192.168.4.1 in network byte order)
#define AP_IP_ADDR 0x0104A8C0

static bool s_airplay_started = false;
static bool s_airplay_infrastructure_ready = false;

static void start_airplay_services(void) {
  if (s_airplay_started) {
    return;
  }

  ESP_LOGI(TAG, "Starting AirPlay services...");

  // One-time infrastructure init (PTP, HAP, audio receiver/output)
  if (!s_airplay_infrastructure_ready) {
    esp_err_t err = ptp_clock_init();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
      ESP_LOGE(TAG, "Failed to init PTP clock: %s", esp_err_to_name(err));
      s_airplay_started = false;
      return;
    }

    ESP_ERROR_CHECK(hap_init());
    ESP_ERROR_CHECK(audio_receiver_init());
    ESP_ERROR_CHECK(audio_output_init());
    mdns_airplay_init();
    s_airplay_infrastructure_ready = true;
  }

  audio_output_start();

  ESP_ERROR_CHECK(rtsp_server_start());

  s_airplay_started = true;
  playback_control_set_source(PLAYBACK_SOURCE_AIRPLAY);
  ESP_LOGI(TAG, "AirPlay ready");
}
#ifdef CONFIG_BT_A2DP_ENABLE
static void stop_airplay_services(void) {
  if (!s_airplay_started) {
    return;
  }

  ESP_LOGI(TAG, "Stopping AirPlay services...");

  rtsp_server_stop();
  audio_output_stop();

  s_airplay_started = false;
  playback_control_set_source(PLAYBACK_SOURCE_NONE);
  ESP_LOGI(TAG, "AirPlay stopped");
}
#endif

static void network_monitor_task(void *pvParameters) {
  (void)pvParameters;
  bool had_network = ethernet_is_connected() || wifi_is_connected();
  bool dns_running = !had_network;
  bool wifi_started = wifi_is_connected() || !ethernet_is_connected();
  bool had_eth = ethernet_is_connected();

  // Start captive portal DNS if no network yet
  if (dns_running) {
    dns_server_start(AP_IP_ADDR);
  }

  while (1) {
    vTaskDelay(pdMS_TO_TICKS(2000));

    bool eth_up = ethernet_is_connected();
    bool wifi_up = wifi_is_connected();
    bool has_network = eth_up || wifi_up;

    // Ethernet just came up — stop WiFi entirely
    if (eth_up && !had_eth && wifi_started) {
      ESP_LOGI(TAG, "Ethernet connected — stopping WiFi");
      wifi_stop();
      wifi_started = false;
      wifi_up = false;
    }

    // Ethernet dropped — bring up WiFi (AP + STA)
    if (!eth_up && had_eth) {
      ESP_LOGI(TAG, "Ethernet down — starting WiFi as fallback");
      wifi_init_apsta(NULL, NULL);
      wifi_started = true;
    }

    had_eth = eth_up;
    has_network = eth_up || wifi_is_connected();

    if (has_network == had_network) {
      continue;
    }

    if (has_network) {
      ESP_LOGI(TAG, "Network up (eth=%s, wifi=%s)", eth_up ? "yes" : "no",
               wifi_up ? "yes" : "no");
      start_airplay_services();
      if (dns_running) {
        dns_server_stop();
        dns_running = false;
      }
    } else {
      if (!dns_running) {
        dns_server_start(AP_IP_ADDR);
        dns_running = true;
      }
    }

    had_network = has_network;
  }
}

#ifdef CONFIG_BT_A2DP_ENABLE
static void on_bt_state_changed(bool connected) {
  if (connected) {
    ESP_LOGI(TAG, "BT connected — disabling AirPlay");
    stop_airplay_services();
    bt_coex_post(BT_COEX_EVT_BT_CONNECTED);
    playback_control_set_source(PLAYBACK_SOURCE_BLUETOOTH);
  } else {
    ESP_LOGI(TAG, "BT disconnected — re-enabling AirPlay");
    bt_coex_post(BT_COEX_EVT_BT_DISCONNECTED);
    playback_control_set_source(PLAYBACK_SOURCE_NONE);
    if (ethernet_is_connected() || wifi_is_connected()) {
      start_airplay_services();
    }
  }
}

static void on_airplay_client_event(rtsp_event_t event,
                                    const rtsp_event_data_t *data,
                                    void *user_data) {
  (void)data;
  (void)user_data;
  if (bt_a2dp_sink_is_connected()) {
    return;
  }
  switch (event) {
  case RTSP_EVENT_CLIENT_CONNECTED:
    ESP_LOGI(TAG, "AirPlay client connected — disabling BT");
    bt_a2dp_sink_set_discoverable(false);
    bt_coex_post(BT_COEX_EVT_AIRPLAY_CONNECTED);
    break;
  case RTSP_EVENT_PLAYING:
    bt_coex_post(BT_COEX_EVT_AIRPLAY_PLAYING);
    break;
  case RTSP_EVENT_PAUSED:
    // Session still active — BT stays suspended and hidden so the phone
    // reconnects to AirPlay rather than falling back to BT.
    ESP_LOGI(TAG, "AirPlay paused — keeping BT suspended and hidden");
    bt_coex_post(BT_COEX_EVT_AIRPLAY_PAUSED);
    break;
  case RTSP_EVENT_DISCONNECTED:
    ESP_LOGI(TAG, "AirPlay client disconnected — BT resumes after idle delay");
    bt_a2dp_sink_set_discoverable(true);
    bt_coex_post(BT_COEX_EVT_AIRPLAY_DISCONNECTED);
    break;
  default:
    break;
  }
}
#endif

void app_main(void) {
  ESP_LOGW(TAG, "Boot: reset reason %d", (int)esp_reset_reason());

  // Initialize NVS
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
      ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);
  ESP_ERROR_CHECK(settings_init());
#ifdef CONFIG_DAC_TAS57XX
  // Load persisted sub level offset (pre-init safe; applied on first volume).
  float sub_off;
  if (settings_get_sub_offset(&sub_off) == ESP_OK) {
    dac_tas57xx_set_sub_offset_db(sub_off);
  }
#elif defined(CONFIG_DAC_TAS58XX)
  // Load persisted sub level offset (pre-init safe; applied on first volume).
  float sub_off;
  if (settings_get_sub_offset(&sub_off) == ESP_OK) {
    dac_tas58xx_set_sub_offset_db(sub_off);
  }
  float sub_xo;
  if (settings_get_sub_crossover(&sub_xo) == ESP_OK) {
    dac_tas58xx_set_sub_crossover_hz(sub_xo);
  }
  static float sub_eq[2][SETTINGS_WAY_BANDS];
  if (settings_get_sub_eq(sub_eq) == ESP_OK) {
    dac_tas58xx_sub_eq_set_gains(TAS58XX_WAY_LOW, sub_eq[0]);
    dac_tas58xx_sub_eq_set_gains(TAS58XX_WAY_HIGH, sub_eq[1]);
  }
  // Second-amplifier role must be known before the DAC is initialised.
  uint8_t dual_mode;
  if (settings_get_dual_mode(&dual_mode) == ESP_OK) {
    if (!TAS58XX_BIAMP_SUPPORTED && dual_mode == TAS58XX_DUAL_BIAMP) {
      dual_mode = TAS58XX_DUAL_SUB;
    }
    dac_tas58xx_set_dual_mode((tas58xx_dual_mode_t)dual_mode);
  }
  float biamp_xo;
  if (settings_get_biamp_crossover(&biamp_xo) == ESP_OK) {
    dac_tas58xx_set_biamp_crossover_hz(biamp_xo);
  }
  bool biamp_swap;
  if (settings_get_biamp_swap(&biamp_swap) == ESP_OK) {
    dac_tas58xx_set_biamp_swap(biamp_swap);
  }
  static float biamp_eq[2][2][SETTINGS_WAY_BANDS];
  if (settings_get_biamp_eq(biamp_eq) == ESP_OK) {
    for (int spk = 0; spk < 2; spk++) {
      dac_tas58xx_biamp_set_gains(spk, TAS58XX_WAY_LOW, biamp_eq[spk][0]);
      dac_tas58xx_biamp_set_gains(spk, TAS58XX_WAY_HIGH, biamp_eq[spk][1]);
    }
  }
#endif
  spiffs_storage_init();
  log_stream_init();
  ESP_ERROR_CHECK(playback_control_init());
  led_init();

  // Initialize board-specific hardware (includes I2C/SPI bus for display and
  // DAC)
  ESP_LOGI(TAG, "Board: %s", iot_board_get_info());
  esp_err_t err = iot_board_init();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Board init failed: %s", esp_err_to_name(err));
  }

  // Pass the board-owned bus to the display so it reuses it rather than
  // creating a duplicate bus on the same pins.
#if defined(CONFIG_DISPLAY_BUS_SPI)
  display_init(iot_board_get_handle(BOARD_SPI_DISP_ID));
#else
  display_init(iot_board_get_handle(BOARD_I2C_DISP_ID));
#endif

  // Initialize LVGL-dependent board resources (e.g., touch input) after
  // display/LVGL port is ready.
  iot_board_init_lvgl_resources();

#if CONFIG_AUDIO_OUTPUT_USB_HOST
  // Bring the USB host up BEFORE the network waits below (ethernet up to
  // 15 s, WiFi up to 30 s). A bus-powered DAC keeps replaying its stale —
  // audibly noisy — buffer the whole time no host feeds it, so enumeration
  // and the silence stream must start as early in boot as possible; they
  // run in parallel with network bring-up. audio_output_init() is
  // idempotent — the later call in start_airplay_services() is a no-op.
  ESP_ERROR_CHECK(audio_output_init());
#endif

  // Try ethernet first
  bool eth_available = false;
  err = ethernet_init();
  if (err == ESP_OK) {
    // Wait for ethernet link + DHCP (up to 5s for link, then 10s more for DHCP)
    ESP_LOGI(TAG, "Waiting for ethernet...");
    for (int i = 0; i < 25 && !ethernet_is_link_up(); i++) {
      vTaskDelay(pdMS_TO_TICKS(200));
    }
    if (ethernet_is_link_up() && !ethernet_is_connected()) {
      ESP_LOGI(TAG, "Ethernet link up, waiting for DHCP...");
      for (int i = 0; i < 50 && !ethernet_is_connected(); i++) {
        vTaskDelay(pdMS_TO_TICKS(200));
      }
    }
    eth_available = ethernet_is_connected();
    if (eth_available) {
      ESP_LOGI(TAG, "Ethernet connected");
    } else {
      ESP_LOGI(TAG, "Ethernet not connected (cable?), will use WiFi");
    }
  } else if (err != ESP_ERR_NOT_SUPPORTED) {
    ESP_LOGW(TAG, "Ethernet init failed: %s", esp_err_to_name(err));
  }

  // Start WiFi only if ethernet is not available
  if (!eth_available) {
    wifi_init_apsta(NULL, NULL);

    // Wait for initial WiFi connection if credentials exist
    if (settings_has_wifi_credentials()) {
      if (!wifi_wait_connected(30000)) {
        ESP_LOGI(TAG, "Connect to 'ESP32-AirPlay-Setup' -> http://192.168.4.1");
      }
    } else {
      ESP_LOGI(TAG, "Connect to 'ESP32-AirPlay-Setup' -> http://192.168.4.1");
    }
  } else {
    ESP_LOGI(TAG, "Ethernet connected — skipping WiFi");
  }

  // Start services that work on any interface
  web_server_start(80);
  task_create_spiram(network_monitor_task, "net_mon", 4096, NULL, 5, NULL,
                     NULL);

  bool connected = eth_available || wifi_is_connected();
  if (connected) {
    start_airplay_services();
  }

#ifdef CONFIG_BT_A2DP_ENABLE
  // Initialize Bluetooth A2DP Sink
  {
    char bt_name[65];
    settings_get_device_name(bt_name, sizeof(bt_name));
    esp_err_t bt_err = bt_a2dp_sink_init(bt_name, on_bt_state_changed);
    if (bt_err != ESP_OK) {
      ESP_LOGE(TAG, "BT A2DP init failed: %s", esp_err_to_name(bt_err));
    } else {
      if (bt_coex_start() != ESP_OK) {
        ESP_LOGE(TAG, "BT coexistence task start failed");
      }
      rtsp_events_register(on_airplay_client_event, NULL);
    }
  }
#endif

  // Boot baseline: free internal DRAM once WiFi (and BT, where enabled) are
  // resident but before any stream is active.  Compare against the
  // "Buffered start" log to see the headroom available for WiFi/TCP buffers.
  ESP_LOGI(TAG,
           "Boot baseline: free heap %lu internal (largest block %lu), "
           "%lu SPIRAM",
           (unsigned long)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
           (unsigned long)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL),
           (unsigned long)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

  buttons_init();

  while (1) {
    vTaskDelay(pdMS_TO_TICKS(10000));
  }
}

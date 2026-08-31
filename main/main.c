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

#ifdef CONFIG_USB_AUDIO_SINK
#include "usb_audio_sink.h"
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
static bool s_audio_output_ready = false;

/* Task stacks and ordinary malloc() need byte-addressable internal RAM.
 * MALLOC_CAP_INTERNAL on its own also counts the leftover IRAM that is added
 * to the heap, which is 32-bit access only, so it reports headroom no stack
 * can ever use. */
#define MAIN_DRAM_CAPS (MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)

// DRAM is the binding constraint on ESP32 targets carrying WiFi and the BT
// controller at once.  Logging it per startup stage attributes a shortage to
// the subsystem that caused it instead of to whoever allocates next.
static void log_dram(const char *stage) {
  ESP_LOGI(TAG, "DRAM after %-14s: %6lu free, %6lu largest, %6lu SPIRAM", stage,
           (unsigned long)heap_caps_get_free_size(MAIN_DRAM_CAPS),
           (unsigned long)heap_caps_get_largest_free_block(MAIN_DRAM_CAPS),
           (unsigned long)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
}

// audio_output_init() creates the I2S channel and must run exactly once.
// AirPlay does it lazily, but it is not the only consumer: the USB sink
// writes to the same channel and can start with no network at all.
static esp_err_t ensure_audio_output(void) {
  if (s_audio_output_ready) {
    return ESP_OK;
  }
  esp_err_t err = audio_output_init();
  if (err == ESP_OK) {
    s_audio_output_ready = true;
  }
  return err;
}

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
    ESP_ERROR_CHECK(ensure_audio_output());
    mdns_airplay_init();
    s_airplay_infrastructure_ready = true;
  }

  audio_output_start();

  ESP_ERROR_CHECK(rtsp_server_start());

  s_airplay_started = true;
  playback_control_set_source(PLAYBACK_SOURCE_AIRPLAY);
  ESP_LOGI(TAG, "AirPlay ready");
  log_dram("airplay");
}
#if defined(CONFIG_BT_A2DP_ENABLE) || defined(CONFIG_USB_AUDIO_SINK)
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
      bool usb_owns_output = false;
#ifdef CONFIG_USB_AUDIO_SINK
      usb_owns_output = usb_audio_sink_is_streaming();
#endif
      // Starting AirPlay here would put its playback task back on I2S
      // underneath the USB writer; the sink starts it when the host goes idle.
      if (!usb_owns_output) {
        start_airplay_services();
      }
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

#ifdef CONFIG_USB_AUDIO_SINK
// The USB host and AirPlay cannot both drive I2S, so hand the output
// over for as long as the host is streaming.  Called from the sink's
// writer task.
static void on_usb_audio_state_changed(bool streaming) {
  if (streaming) {
    ESP_LOGI(TAG, "USB audio streaming — disabling AirPlay");
    stop_airplay_services();
    playback_control_set_source(PLAYBACK_SOURCE_USB);
  } else {
    ESP_LOGI(TAG, "USB audio idle — re-enabling AirPlay");
    playback_control_set_source(PLAYBACK_SOURCE_NONE);
#ifdef CONFIG_BT_A2DP_ENABLE
    if (bt_a2dp_sink_is_connected()) {
      // Bluetooth owns the output while connected; leave it alone.
      playback_control_set_source(PLAYBACK_SOURCE_BLUETOOTH);
      return;
    }
#endif
    if (ethernet_is_connected() || wifi_is_connected()) {
      start_airplay_services();
    }
  }
}
#endif

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
  float ch_trim[SETTINGS_CHANNELS];
  if (settings_get_channel_trim(ch_trim) == ESP_OK) {
    for (int ch = 0; ch < SETTINGS_CHANNELS; ch++) {
      dac_tas57xx_set_channel_trim_db(ch, ch_trim[ch]);
    }
  }
#elif defined(CONFIG_DAC_TAS58XX)
  // Second-amplifier wiring must be known before the DAC is initialised.
  bool second_pbtl;
  if (settings_get_second_pbtl(&second_pbtl) == ESP_OK) {
    dac_tas58xx_set_second_pbtl(second_pbtl);
  }
  // Per-output level and mute (pre-init safe; folded into the input mixer).
  float amp_gain[SETTINGS_AMP_OUTPUTS];
  if (settings_get_amp_gain(amp_gain) == ESP_OK) {
    for (int i = 0; i < SETTINGS_AMP_OUTPUTS; i++) {
      dac_tas58xx_set_gain_db(i / SETTINGS_AMP_CHANNELS,
                              i % SETTINGS_AMP_CHANNELS, amp_gain[i]);
    }
  }
  uint8_t amp_mute[SETTINGS_AMP_OUTPUTS];
  if (settings_get_amp_mute(amp_mute) == ESP_OK) {
    for (int i = 0; i < SETTINGS_AMP_OUTPUTS; i++) {
      dac_tas58xx_set_ch_mute(i / SETTINGS_AMP_CHANNELS,
                              i % SETTINGS_AMP_CHANNELS, amp_mute[i] != 0);
    }
  }
  // Input routing, likewise picked up when the chips are brought up.
  uint8_t amp_mix[SETTINGS_AMPS];
  if (settings_get_amp_mix(amp_mix) == ESP_OK) {
    for (int amp = 0; amp < SETTINGS_AMPS; amp++) {
      dac_tas58xx_set_mix(amp, (tas58xx_mix_t)amp_mix[amp]);
    }
  }
#endif
  spiffs_storage_init();
  log_stream_init();
  ESP_ERROR_CHECK(playback_control_init());
  led_init();
  log_dram("spiffs+log");

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
  log_dram("board+display");

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
  log_dram("ethernet");

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
  log_dram("eth+wifi");

  // Start services that work on any interface
  web_server_start(80);
  task_create_spiram(network_monitor_task, "net_mon", 4096, NULL, 5, NULL,
                     NULL);
  log_dram("web server");

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
  log_dram("bluetooth");
#endif

#ifdef CONFIG_USB_AUDIO_SINK
  {
    // The host can stream with no network configured, in which case
    // start_airplay_services() has never run and I2S is still unopened.
    esp_err_t out_err = ensure_audio_output();
    if (out_err != ESP_OK) {
      ESP_LOGE(TAG, "Audio output init failed: %s", esp_err_to_name(out_err));
    }
    esp_err_t usb_err = usb_audio_sink_init(on_usb_audio_state_changed);
    if (usb_err != ESP_OK) {
      ESP_LOGE(TAG, "USB audio sink init failed: %s", esp_err_to_name(usb_err));
    }
  }
#endif

  // Boot baseline: free internal DRAM once WiFi (and BT, where enabled) are
  // resident but before any stream is active.  Compare against the
  // "Buffered start" log to see the headroom available for WiFi/TCP buffers.
  log_dram("boot baseline");

  buttons_init();

  while (1) {
    vTaskDelay(pdMS_TO_TICKS(10000));
  }
}

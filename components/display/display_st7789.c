/**
 * @file display_st7789.c
 * @brief ST7789 TFT display driver using esp_lcd + LVGL 9 (esp_lvgl_port)
 *
 * Implements the display_init() API for ST7789-based TFT displays.
 * Display: 320x170 pixels, landscape orientation, SPI interface.
 *
 * Background image is loaded at startup from SPIFFS (/spiffs/bg/background.bin)
 * — a raw RGB565 little-endian binary file. If the file is absent, the display
 * initialises normally with a blank (black) background. The background can be
 * updated without reflashing by uploading a new file via the HTTP file API.
 *
 * GPIO assignments (configured via sdkconfig / menuconfig):
 *   CLK  -> CONFIG_DISPLAY_SPI_CLK  (default 18)
 *   MOSI -> CONFIG_DISPLAY_SPI_MOSI (default 17)
 *   CS   -> CONFIG_DISPLAY_SPI_CS   (default 15)
 *   DC   -> CONFIG_DISPLAY_SPI_DC   (default 16)
 *   RST  -> CONFIG_DISPLAY_SPI_RST  (default 21)
 *   BL   -> CONFIG_DISPLAY_BL_GPIO  (default 38)
 */

#include "display.h"
#include "rtsp_events.h"

#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lvgl_port.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lvgl.h"

#include <stdio.h>
#include <string.h>

static const char *TAG = "display_st7789";

// ============================================================================
// Hardware configuration
// ============================================================================

#define DISPLAY_WIDTH      320
#define DISPLAY_HEIGHT     170
#define LCD_HOST           SPI2_HOST
#define LCD_PIXEL_CLOCK_HZ (40 * 1000 * 1000)
#define DRAW_BUF_LINES     10

// Background image path on SPIFFS
#define BG_SPIFFS_PATH   "/spiffs/bg/background.bin"
#define BG_EXPECTED_SIZE ((long)DISPLAY_WIDTH * DISPLAY_HEIGHT * 2) // RGB565

// ============================================================================
// Layout constants
// ============================================================================
#define X_MARGIN   22
#define X_MARGIN_R (-22)
#define Y_TITLE    10
#define Y_ARTIST   44
#define Y_ALBUM    69
#define Y_PROGRESS 114
#define Y_TIME     132
#define BAR_HEIGHT 12

// ============================================================================
// Display state
// ============================================================================

typedef enum {
  DISPLAY_STATE_STANDBY,
  DISPLAY_STATE_CONNECTED,
  DISPLAY_STATE_PLAYING,
  DISPLAY_STATE_PAUSED,
} display_state_t;

static struct {
  char title[METADATA_STRING_MAX];
  char artist[METADATA_STRING_MAX];
  char album[METADATA_STRING_MAX];
  uint32_t duration_secs;
  uint32_t position_secs;
  display_state_t state;
  volatile bool dirty;  // written by RTSP callback, polled by display_task
  int64_t sync_time_us; // 64-bit — torn reads would cause position jumps
} s_display;

// Protects s_display against concurrent access from the RTSP event callback
// thread and the display_task. Must be held around any multi-field read or
// write (strings, sync_time_us, state+position together). Dirty is volatile
// so the polling loop picks up the flag without holding the mutex.
static SemaphoreHandle_t s_state_mutex = NULL;

#define STATE_LOCK()   xSemaphoreTake(s_state_mutex, portMAX_DELAY)
#define STATE_UNLOCK() xSemaphoreGive(s_state_mutex)

// ============================================================================
// LVGL handles and widgets
// ============================================================================

static lv_display_t *s_lvgl_disp = NULL;

static uint8_t *s_bg_buf = NULL;
static lv_image_dsc_t s_bg_dsc;

static lv_obj_t *s_label_title = NULL;
static lv_obj_t *s_label_artist = NULL;
static lv_obj_t *s_label_album = NULL;
static lv_obj_t *s_label_status = NULL;
static lv_obj_t *s_bar_progress = NULL;
static lv_obj_t *s_label_time_elapsed = NULL;
static lv_obj_t *s_label_time_remaining = NULL;

// ============================================================================
// Background loading
// ============================================================================

static bool bg_load_from_spiffs(void) {
  FILE *f = fopen(BG_SPIFFS_PATH, "rb");
  if (!f) {
    ESP_LOGI(TAG, "No background file at %s — using blank background",
             BG_SPIFFS_PATH);
    return false;
  }

  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);

  if (size != BG_EXPECTED_SIZE) {
    ESP_LOGW(TAG, "Background file wrong size: %ld (expected %d) — skipping",
             size, BG_EXPECTED_SIZE);
    fclose(f);
    return false;
  }

  s_bg_buf = heap_caps_malloc(size, MALLOC_CAP_SPIRAM);
  if (!s_bg_buf) {
    ESP_LOGE(TAG, "Failed to allocate %ld bytes in PSRAM for background", size);
    fclose(f);
    return false;
  }

  if (fread(s_bg_buf, 1, size, f) != (size_t)size) {
    ESP_LOGE(TAG, "Failed to read background file");
    fclose(f);
    heap_caps_free(s_bg_buf);
    s_bg_buf = NULL;
    return false;
  }

  fclose(f);

  memset(&s_bg_dsc, 0, sizeof(s_bg_dsc));
  s_bg_dsc.header.cf = LV_COLOR_FORMAT_RGB565;
  s_bg_dsc.header.magic = LV_IMAGE_HEADER_MAGIC;
  s_bg_dsc.header.w = DISPLAY_WIDTH;
  s_bg_dsc.header.h = DISPLAY_HEIGHT;
  s_bg_dsc.data_size = BG_EXPECTED_SIZE;
  s_bg_dsc.data = s_bg_buf;

  ESP_LOGI(TAG, "Background loaded from SPIFFS (%ld bytes, PSRAM)", size);
  return true;
}

// ============================================================================
// Helpers
// ============================================================================

static uint32_t get_estimated_position(void) {
  uint32_t pos = s_display.position_secs;
  if (s_display.state == DISPLAY_STATE_PLAYING && s_display.sync_time_us > 0) {
    int64_t elapsed_us = esp_timer_get_time() - s_display.sync_time_us;
    uint32_t elapsed_secs = (uint32_t)(elapsed_us / 1000000);
    pos += elapsed_secs;
    if (s_display.duration_secs > 0 && pos > s_display.duration_secs) {
      pos = s_display.duration_secs;
    }
  }
  return pos;
}

static void format_time(uint32_t secs, char *buf, size_t len) {
  snprintf(buf, len, "%lu:%02lu", secs / 60, secs % 60);
}

static void format_remaining(uint32_t remaining_secs, char *buf, size_t len) {
  snprintf(buf, len, "-%lu:%02lu", remaining_secs / 60, remaining_secs % 60);
}

// ============================================================================
// UI creation - called once after LVGL init, with lock held
// ============================================================================

static void ui_create(void) {
  lv_obj_t *scr = lv_screen_active();

  // Always set a solid black background — ensures a clean screen whether or
  // not a background image was loaded from SPIFFS. Without this, LVGL's
  // default theme leaves the screen white with unrendered display RAM noise.
  lv_obj_set_style_bg_color(scr, lv_color_black(), 0);
  lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);

  // Background image — loaded from SPIFFS at display_init() time.
  // If no file was found, s_bg_buf is NULL and we skip the image widget,
  // leaving the screen black. All other widgets render normally on top.
  if (s_bg_buf) {
    lv_obj_t *bg = lv_image_create(scr);
    lv_image_set_src(bg, &s_bg_dsc);
    lv_obj_align(bg, LV_ALIGN_TOP_LEFT, 0, 0);
  }

  // Title — largest font, white, scrolling
  s_label_title = lv_label_create(scr);
  lv_obj_set_width(s_label_title, DISPLAY_WIDTH - (X_MARGIN * 2));
  lv_label_set_long_mode(s_label_title, LV_LABEL_LONG_SCROLL_CIRCULAR);
  lv_obj_set_style_text_font(s_label_title, &lv_font_montserrat_24, 0);
  lv_obj_set_style_text_color(s_label_title, lv_color_white(), 0);
  lv_obj_align(s_label_title, LV_ALIGN_TOP_LEFT, X_MARGIN, Y_TITLE);
  lv_label_set_text(s_label_title, "AirPlay Ready");

  // Artist — medium font, light grey, scrolling
  s_label_artist = lv_label_create(scr);
  lv_obj_set_width(s_label_artist, DISPLAY_WIDTH - (X_MARGIN * 2));
  lv_label_set_long_mode(s_label_artist, LV_LABEL_LONG_SCROLL_CIRCULAR);
  lv_obj_set_style_text_font(s_label_artist, &lv_font_montserrat_16, 0);
  lv_obj_set_style_text_color(s_label_artist, lv_color_make(180, 180, 180), 0);
  lv_obj_align(s_label_artist, LV_ALIGN_TOP_LEFT, X_MARGIN, Y_ARTIST);
  lv_label_set_text(s_label_artist, "");

  // Album — small font, dimmer grey, scrolling
  s_label_album = lv_label_create(scr);
  lv_obj_set_width(s_label_album, DISPLAY_WIDTH - (X_MARGIN * 2) - 60);
  lv_label_set_long_mode(s_label_album, LV_LABEL_LONG_SCROLL_CIRCULAR);
  lv_obj_set_style_text_font(s_label_album, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(s_label_album, lv_color_make(140, 140, 140), 0);
  lv_obj_align(s_label_album, LV_ALIGN_TOP_LEFT, X_MARGIN, Y_ALBUM);
  lv_label_set_text(s_label_album, "");

  // Paused status indicator — right side at album row, amber
  s_label_status = lv_label_create(scr);
  lv_obj_set_style_text_font(s_label_status, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(s_label_status, lv_color_make(255, 200, 0), 0);
  lv_obj_align(s_label_status, LV_ALIGN_TOP_RIGHT, X_MARGIN_R, Y_ALBUM);
  lv_label_set_text(s_label_status, "");

  // Progress bar — inset from border on both sides, rounded
  s_bar_progress = lv_bar_create(scr);
  lv_obj_set_size(s_bar_progress, DISPLAY_WIDTH - (X_MARGIN * 2), BAR_HEIGHT);
  lv_obj_align(s_bar_progress, LV_ALIGN_TOP_LEFT, X_MARGIN, Y_PROGRESS);
  lv_bar_set_range(s_bar_progress, 0, 100);
  lv_bar_set_value(s_bar_progress, 0, LV_ANIM_OFF);
  lv_obj_set_style_bg_color(s_bar_progress, lv_color_make(20, 20, 40), 0);
  lv_obj_set_style_bg_opa(s_bar_progress, LV_OPA_80, 0);
  lv_obj_set_style_bg_color(s_bar_progress, lv_color_make(30, 144, 255),
                            LV_PART_INDICATOR);
  lv_obj_set_style_bg_opa(s_bar_progress, LV_OPA_COVER, LV_PART_INDICATOR);
  lv_obj_set_style_radius(s_bar_progress, 3, 0);
  lv_obj_set_style_radius(s_bar_progress, 3, LV_PART_INDICATOR);

  // Elapsed time — below bar, left aligned
  s_label_time_elapsed = lv_label_create(scr);
  lv_obj_set_style_text_font(s_label_time_elapsed, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(s_label_time_elapsed,
                              lv_color_make(150, 150, 150), 0);
  lv_obj_align(s_label_time_elapsed, LV_ALIGN_TOP_LEFT, X_MARGIN, Y_TIME);
  lv_label_set_text(s_label_time_elapsed, "");

  // Remaining time — below bar, right aligned
  s_label_time_remaining = lv_label_create(scr);
  lv_obj_set_style_text_font(s_label_time_remaining, &lv_font_montserrat_14, 0);
  lv_obj_set_style_text_color(s_label_time_remaining,
                              lv_color_make(150, 150, 150), 0);
  lv_obj_align(s_label_time_remaining, LV_ALIGN_TOP_RIGHT, X_MARGIN_R, Y_TIME);
  lv_label_set_text(s_label_time_remaining, "");
}

// ============================================================================
// UI update
// ============================================================================

static void ui_update(void) {
  // Snapshot shared state under s_state_mutex. This avoids torn reads of
  // sync_time_us (int64, two-word on Xtensa) and guarantees consistent
  // strings vs. state. The snapshot is then rendered without the state
  // mutex held, so the RTSP callback can't be blocked by LVGL rendering.
  char title[METADATA_STRING_MAX];
  char artist[METADATA_STRING_MAX];
  char album[METADATA_STRING_MAX];
  uint32_t duration_secs;
  uint32_t position_secs;
  int64_t sync_time_us;
  display_state_t state;

  STATE_LOCK();
  memcpy(title, s_display.title, sizeof(title));
  memcpy(artist, s_display.artist, sizeof(artist));
  memcpy(album, s_display.album, sizeof(album));
  duration_secs = s_display.duration_secs;
  position_secs = s_display.position_secs;
  sync_time_us = s_display.sync_time_us;
  state = s_display.state;
  STATE_UNLOCK();

  // Defensive NUL termination — if the RTSP producer ever fills all
  // METADATA_STRING_MAX bytes without a terminator, lv_label_set_text
  // would read off the end.
  title[METADATA_STRING_MAX - 1] = '\0';
  artist[METADATA_STRING_MAX - 1] = '\0';
  album[METADATA_STRING_MAX - 1] = '\0';

  if (!lvgl_port_lock(100)) {
    ESP_LOGW(TAG, "ui_update: lock timeout");
    return;
  }

  switch (state) {
  case DISPLAY_STATE_STANDBY:
    lv_label_set_text(s_label_title, "AirPlay Ready");
    lv_label_set_text(s_label_artist, "");
    lv_label_set_text(s_label_album, "");
    lv_label_set_text(s_label_status, "");
    lv_label_set_text(s_label_time_elapsed, "");
    lv_label_set_text(s_label_time_remaining, "");
    lv_bar_set_value(s_bar_progress, 0, LV_ANIM_OFF);
    break;

  case DISPLAY_STATE_CONNECTED:
    lv_label_set_text(s_label_title, "Connected");
    lv_label_set_text(s_label_artist, "");
    lv_label_set_text(s_label_album, "");
    lv_label_set_text(s_label_status, "");
    lv_label_set_text(s_label_time_elapsed, "");
    lv_label_set_text(s_label_time_remaining, "");
    lv_bar_set_value(s_bar_progress, 0, LV_ANIM_OFF);
    break;

  case DISPLAY_STATE_PLAYING:
  case DISPLAY_STATE_PAUSED: {
    lv_label_set_text(s_label_title, title[0] ? title : "---");
    lv_label_set_text(s_label_artist, artist[0] ? artist : "");
    lv_label_set_text(s_label_album, album[0] ? album : "");
    lv_label_set_text(s_label_status,
                      state == DISPLAY_STATE_PAUSED ? "|| " : "");

    uint32_t pos = position_secs;
    if (state == DISPLAY_STATE_PLAYING && sync_time_us > 0) {
      int64_t elapsed_us = esp_timer_get_time() - sync_time_us;
      uint32_t elapsed_secs = (uint32_t)(elapsed_us / 1000000);
      pos += elapsed_secs;
      if (duration_secs > 0 && pos > duration_secs) {
        pos = duration_secs;
      }
    }

    if (duration_secs > 0) {
      int pct = (int)((uint64_t)pos * 100 / duration_secs);
      lv_bar_set_value(s_bar_progress, pct, LV_ANIM_OFF);

      char elapsed_str[12];
      format_time(pos, elapsed_str, sizeof(elapsed_str));
      lv_label_set_text(s_label_time_elapsed, elapsed_str);

      uint32_t remaining = (pos <= duration_secs) ? duration_secs - pos : 0;
      char remaining_str[16];
      format_remaining(remaining, remaining_str, sizeof(remaining_str));
      lv_label_set_text(s_label_time_remaining, remaining_str);
    } else {
      lv_bar_set_value(s_bar_progress, 0, LV_ANIM_OFF);
      lv_label_set_text(s_label_time_elapsed, "");
      lv_label_set_text(s_label_time_remaining, "");
    }
    break;
  }
  }

  lvgl_port_unlock();
}

// ============================================================================
// RTSP event callback
// ============================================================================

static void on_rtsp_event(rtsp_event_t event, const rtsp_event_data_t *data,
                          void *user_data) {
  (void)user_data;

  // All mutations of s_display happen under the state mutex so reads in
  // display_task see a consistent snapshot. The callback runs in the RTSP
  // event thread (not an ISR), so blocking on a FreeRTOS mutex is safe.
  STATE_LOCK();

  switch (event) {
  case RTSP_EVENT_CLIENT_CONNECTED:
    s_display.state = DISPLAY_STATE_CONNECTED;
    memset(s_display.title, 0, sizeof(s_display.title));
    memset(s_display.artist, 0, sizeof(s_display.artist));
    memset(s_display.album, 0, sizeof(s_display.album));
    s_display.duration_secs = 0;
    s_display.position_secs = 0;
    s_display.sync_time_us = 0;
    s_display.dirty = true;
    break;

  case RTSP_EVENT_PLAYING:
    s_display.state = DISPLAY_STATE_PLAYING;
    s_display.sync_time_us = esp_timer_get_time();
    s_display.dirty = true;
    break;

  case RTSP_EVENT_PAUSED:
    s_display.position_secs = get_estimated_position();
    s_display.sync_time_us = 0;
    s_display.state = DISPLAY_STATE_PAUSED;
    s_display.dirty = true;
    break;

  case RTSP_EVENT_DISCONNECTED:
    s_display.state = DISPLAY_STATE_STANDBY;
    memset(s_display.title, 0, sizeof(s_display.title));
    memset(s_display.artist, 0, sizeof(s_display.artist));
    memset(s_display.album, 0, sizeof(s_display.album));
    s_display.duration_secs = 0;
    s_display.position_secs = 0;
    s_display.sync_time_us = 0;
    s_display.dirty = true;
    break;

  case RTSP_EVENT_METADATA:
    if (data) {
      bool track_changed = data->metadata.title[0] &&
                           strcmp(data->metadata.title, s_display.title) != 0;

      if (data->metadata.title[0]) {
        memcpy(s_display.title, data->metadata.title, METADATA_STRING_MAX);
        s_display.title[METADATA_STRING_MAX - 1] = '\0';
      }
      if (data->metadata.artist[0]) {
        memcpy(s_display.artist, data->metadata.artist, METADATA_STRING_MAX);
        s_display.artist[METADATA_STRING_MAX - 1] = '\0';
      }
      if (data->metadata.album[0]) {
        memcpy(s_display.album, data->metadata.album, METADATA_STRING_MAX);
        s_display.album[METADATA_STRING_MAX - 1] = '\0';
      }
      if (data->metadata.duration_secs) {
        s_display.duration_secs = data->metadata.duration_secs;
      }

      if (track_changed || data->metadata.position_secs ||
          s_display.position_secs == 0) {
        s_display.position_secs = data->metadata.position_secs;
      }

      s_display.sync_time_us = esp_timer_get_time();
      s_display.dirty = true;
    }
    break;
  }

  STATE_UNLOCK();
}

// ============================================================================
// Display task
// ============================================================================

static void display_task(void *pvParameters) {
  (void)pvParameters;

  while (1) {
    // Consume dirty under the state mutex so a concurrent set in the
    // RTSP callback is never lost (clear-after-set ordering).
    bool need_update = false;
    display_state_t state;
    STATE_LOCK();
    if (s_display.dirty) {
      s_display.dirty = false;
      need_update = true;
    }
    state = s_display.state;
    STATE_UNLOCK();

    if (need_update) {
      ui_update();
    }

    static TickType_t last_progress_update = 0;
    TickType_t now = xTaskGetTickCount();
    if (state == DISPLAY_STATE_PLAYING &&
        (now - last_progress_update) >= pdMS_TO_TICKS(1000)) {
      last_progress_update = now;
      ui_update();
    }

    vTaskDelay(pdMS_TO_TICKS(30));
  }
}

// ============================================================================
// Initialization
// ============================================================================

void display_init(void *bus) {
  s_state_mutex = xSemaphoreCreateMutex();
  assert(s_state_mutex != NULL);

  // The main/main.c contract (from PR #59) is:
  //   bus != NULL → a pre-initialised spi_host_device_t passed as
  //                 (void*)(intptr_t)host. Use it and skip our own
  //                 spi_bus_initialize() to share the board's SPI bus.
  //   bus == NULL → fall back to initialising our own SPI bus from the
  //                 GPIO pins in Kconfig. Used by boards that don't
  //                 expose a shared SPI bus for the display.
  spi_host_device_t spi_host =
      (bus != NULL) ? (spi_host_device_t)(intptr_t)bus : LCD_HOST;

  ESP_LOGI(TAG,
           "Initializing ST7789 (%dx%d landscape) host=%d "
           "CLK=%d MOSI=%d CS=%d DC=%d RST=%d BL=%d",
           DISPLAY_WIDTH, DISPLAY_HEIGHT, (int)spi_host, CONFIG_DISPLAY_SPI_CLK,
           CONFIG_DISPLAY_SPI_MOSI, CONFIG_DISPLAY_SPI_CS,
           CONFIG_DISPLAY_SPI_DC, CONFIG_DISPLAY_SPI_RST,
           CONFIG_DISPLAY_BL_GPIO);

  // Backlight GPIO is optional — a value of -1 means "not wired / always on",
  // which matches the Kconfig default. BIT64(-1) is undefined, and
  // gpio_set_level(-1, ...) returns ESP_ERR_INVALID_ARG, so skip the config
  // entirely when the pin is not set.
  if (CONFIG_DISPLAY_BL_GPIO >= 0) {
    gpio_config_t bl_cfg = {
        .pin_bit_mask = BIT64(CONFIG_DISPLAY_BL_GPIO),
        .mode = GPIO_MODE_OUTPUT,
    };
    ESP_ERROR_CHECK(gpio_config(&bl_cfg));
    gpio_set_level(CONFIG_DISPLAY_BL_GPIO, 0);
  }

  bg_load_from_spiffs();

  // Only initialise the SPI bus ourselves if the caller didn't pass a
  // pre-initialised one. Calling spi_bus_initialize() on a host that is
  // already initialised returns ESP_ERR_INVALID_STATE.
  if (bus == NULL) {
    spi_bus_config_t buscfg = {
        .mosi_io_num = CONFIG_DISPLAY_SPI_MOSI,
        .miso_io_num = -1,
        .sclk_io_num = CONFIG_DISPLAY_SPI_CLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = DISPLAY_WIDTH * DRAW_BUF_LINES * sizeof(uint16_t),
    };
    ESP_ERROR_CHECK(spi_bus_initialize(spi_host, &buscfg, SPI_DMA_CH_AUTO));
  }

  esp_lcd_panel_io_handle_t io_handle = NULL;
  esp_lcd_panel_io_spi_config_t io_cfg = {
      .dc_gpio_num = CONFIG_DISPLAY_SPI_DC,
      .cs_gpio_num = CONFIG_DISPLAY_SPI_CS,
      .pclk_hz = LCD_PIXEL_CLOCK_HZ,
      .lcd_cmd_bits = 8,
      .lcd_param_bits = 8,
      .spi_mode = 0,
      .trans_queue_depth = 4,
  };
  ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)spi_host,
                                           &io_cfg, &io_handle));

  esp_lcd_panel_handle_t panel_handle = NULL;
  esp_lcd_panel_dev_config_t panel_cfg = {
      .reset_gpio_num = CONFIG_DISPLAY_SPI_RST,
      .rgb_endian = LCD_RGB_ENDIAN_RGB,
      .bits_per_pixel = 16,
  };
  ESP_ERROR_CHECK(
      esp_lcd_new_panel_st7789(io_handle, &panel_cfg, &panel_handle));
  ESP_ERROR_CHECK(esp_lcd_panel_reset(panel_handle));
  ESP_ERROR_CHECK(esp_lcd_panel_init(panel_handle));
  ESP_ERROR_CHECK(esp_lcd_panel_invert_color(panel_handle, true));
  ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(panel_handle, true));

  // Pin the LVGL task to Core 0. Default task_affinity=-1 allows migration
  // to Core 1 where it interferes with the audio task (priority 7).
  const lvgl_port_cfg_t lvgl_cfg = {
      .task_priority = 4,
      .task_stack = 6144,
      .task_affinity = 0,
      .task_max_sleep_ms = 500,
      .timer_period_ms = 5,
  };
  ESP_ERROR_CHECK(lvgl_port_init(&lvgl_cfg));

  // buff_dma=true, buff_spiram=false: draw buffers in DMA-capable internal
  // SRAM. esp_lvgl_port passes the buffer pointer directly to
  // esp_lcd_panel_draw_bitmap — PSRAM buffers cause SPI master to allocate
  // a private DMA buffer at runtime, which fails under memory pressure.
  const lvgl_port_display_cfg_t disp_cfg = {
      .io_handle = io_handle,
      .panel_handle = panel_handle,
      .buffer_size = DISPLAY_WIDTH * DRAW_BUF_LINES,
      .double_buffer = true,
      .trans_size = 0,
      .hres = DISPLAY_WIDTH,
      .vres = DISPLAY_HEIGHT,
      .monochrome = false,
      .flags =
          {
              .buff_dma = true,
              .buff_spiram = false,
              .swap_bytes = true,
          },
  };
  s_lvgl_disp = lvgl_port_add_disp(&disp_cfg);
  assert(s_lvgl_disp != NULL);

  // Rotation MUST be applied after lvgl_port_add_disp() — the port resets
  // the ST7789 MADCTL register during display registration.
  ESP_ERROR_CHECK(esp_lcd_panel_swap_xy(panel_handle, true));
  ESP_ERROR_CHECK(esp_lcd_panel_mirror(panel_handle, true, false));
  ESP_ERROR_CHECK(esp_lcd_panel_set_gap(panel_handle, 0, 35));

  // Acquire the LVGL port mutex before touching LVGL widgets. The port task
  // is already running at this point, so we must wait on the lock rather
  // than pass 0 (non-waiting try). If the lock cannot be acquired within a
  // generous timeout, init has gone wrong — abort rather than corrupt LVGL
  // state by calling ui_create() unlocked.
  if (lvgl_port_lock(1000)) {
    ui_create();
    lvgl_port_unlock();
  } else {
    ESP_LOGE(TAG, "Failed to acquire LVGL lock during init — UI not built");
    abort();
  }

  if (CONFIG_DISPLAY_BL_GPIO >= 0) {
    gpio_set_level(CONFIG_DISPLAY_BL_GPIO, 1);
  }

  s_display.state = DISPLAY_STATE_STANDBY;
  s_display.dirty = true;

  rtsp_events_register(on_rtsp_event, NULL);

  // Pinned to Core 0 — audio runs on Core 1
  xTaskCreatePinnedToCore(display_task, "display", 4096, NULL, 3, NULL, 0);

  ESP_LOGI(TAG, "ST7789 display initialized (LVGL 9 + esp_lvgl_port)");
}

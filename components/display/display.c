#include "display.h"
#include "rtsp_events.h"

#include "u8g2.h"
#include "u8g2_esp32_hal.h"

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <stdio.h>
#include <string.h>

static const char *TAG = "display";

// ============================================================================
// Display state (protected by copy-on-event, read by render task)
// ============================================================================

typedef enum {
  DISPLAY_STATE_STANDBY,
  DISPLAY_STATE_CONNECTED,
  DISPLAY_STATE_PLAYING,
  DISPLAY_STATE_PAUSED,
} display_state_t;

static u8g2_t s_u8g2;

static struct {
  char title[METADATA_STRING_MAX];
  char artist[METADATA_STRING_MAX];
  char album[METADATA_STRING_MAX];
  uint32_t duration_secs;
  uint32_t position_secs;
  display_state_t state;
  bool dirty; // set by event callback, cleared by render
} s_display;

#if defined(CONFIG_DISPLAY_HEIGHT_32)
// Scroll state for compact 128x32 layout
#define SCROLL_PX_PER_TICK 2
#define SCROLL_PAUSE_TICKS 20 // pause before scrolling restarts
#define SCROLL_GAP_PX      30 // pixel gap before text wraps
#define SCROLL_INTERVAL_MS 50 // render interval during active scroll

static struct {
  int offset;
  int text_width;
  int pause_ticks;
  bool active;
} s_scroll;
#endif

// ============================================================================
// Helpers
// ============================================================================

/**
 * Draw a UTF-8 string clipped to the display width.
 */
static void draw_text_line(u8g2_t *u8g2, int y, const char *str) {
  u8g2_DrawUTF8(u8g2, 0, y, str);
}

/**
 * Draw the progress bar: [====>          ] with time on each side.
 */
static void draw_progress(u8g2_t *u8g2, int y, uint32_t pos, uint32_t dur) {
  char pos_str[8], dur_str[8];
  rtsp_format_time_mmss(pos, pos_str, sizeof(pos_str));
  rtsp_format_time_mmss(dur, dur_str, sizeof(dur_str));

  // Measure time string widths
  int pos_w = u8g2_GetUTF8Width(u8g2, pos_str);
  int dur_w = u8g2_GetUTF8Width(u8g2, dur_str);

  // Draw position time on the left
  u8g2_DrawUTF8(u8g2, 0, y, pos_str);
  // Draw duration time on the right
  u8g2_DrawUTF8(u8g2, 128 - dur_w, y, dur_str);

  // Progress bar between the time strings
  int bar_x = pos_w + 3;
  int bar_w = 128 - dur_w - 3 - bar_x;
  int bar_y = y - 5; // bar height ~5px, top-aligned to text baseline
  int bar_h = 5;

  if (bar_w > 0) {
    // Outline
    u8g2_DrawFrame(u8g2, bar_x, bar_y, bar_w, bar_h);
    // Fill proportional to position
    if (dur > 0 && pos <= dur) {
      int fill = (int)((uint64_t)(bar_w - 2) * pos / dur);
      if (fill > 0) {
        u8g2_DrawBox(u8g2, bar_x + 1, bar_y + 1, fill, bar_h - 2);
      }
    }
  }
}

// ============================================================================
// Rendering
// ============================================================================

static void display_render(void) {
  u8g2_ClearBuffer(&s_u8g2);

  switch (s_display.state) {
  case DISPLAY_STATE_STANDBY:
    u8g2_SetFont(&s_u8g2, u8g2_font_7x14_tf);
#if defined(CONFIG_DISPLAY_HEIGHT_32)
    u8g2_DrawUTF8(&s_u8g2, 0, 20, "AirPlay Ready");
#else
    u8g2_DrawUTF8(&s_u8g2, 0, 32, "AirPlay Ready");
#endif
    break;

  case DISPLAY_STATE_CONNECTED:
    u8g2_SetFont(&s_u8g2, u8g2_font_7x14_tf);
#if defined(CONFIG_DISPLAY_HEIGHT_32)
    u8g2_DrawUTF8(&s_u8g2, 0, 20, "Connected");
#else
    u8g2_DrawUTF8(&s_u8g2, 0, 32, "Connected");
#endif
    break;

  case DISPLAY_STATE_PLAYING:
  case DISPLAY_STATE_PAUSED: {
#if defined(CONFIG_DISPLAY_HEIGHT_32)
    // Compact 2-line layout: "Title - Artist" (scrolling) + progress bar
    char line[METADATA_STRING_MAX * 2 + 4];
    const char *title = s_display.title[0] ? s_display.title : "---";
    const char *artist = s_display.artist[0] ? s_display.artist : "";
    if (artist[0]) {
      snprintf(line, sizeof(line), "%s - %s", title, artist);
    } else {
      snprintf(line, sizeof(line), "%s", title);
    }

    u8g2_SetFont(&s_u8g2, u8g2_font_6x13_tf);
    int text_w = u8g2_GetUTF8Width(&s_u8g2, line);
    int disp_w = u8g2_GetDisplayWidth(&s_u8g2);

    if (text_w <= disp_w) {
      // Fits on screen — no scrolling needed
      u8g2_DrawUTF8(&s_u8g2, 0, 13, line);
      s_scroll.active = false;
      s_scroll.offset = 0;
    } else {
      // Horizontal scroll
      s_scroll.active = true;
      s_scroll.text_width = text_w;
      u8g2_DrawUTF8(&s_u8g2, -s_scroll.offset, 13, line);

      if (s_scroll.pause_ticks > 0) {
        s_scroll.pause_ticks--;
      } else {
        s_scroll.offset += SCROLL_PX_PER_TICK;
        if (s_scroll.offset > text_w - disp_w + SCROLL_GAP_PX) {
          s_scroll.offset = 0;
          s_scroll.pause_ticks = SCROLL_PAUSE_TICKS;
        }
      }
    }

    // Paused indicator
    if (s_display.state == DISPLAY_STATE_PAUSED) {
      u8g2_SetFont(&s_u8g2, u8g2_font_5x8_tf);
      const char *paused_str = "||";
      int w = u8g2_GetUTF8Width(&s_u8g2, paused_str);
      u8g2_DrawUTF8(&s_u8g2, disp_w - w, 8, paused_str);
    }

    // Line 2: Progress bar
    u8g2_SetFont(&s_u8g2, u8g2_font_5x8_tf);
    draw_progress(&s_u8g2, 30, s_display.position_secs,
                  s_display.duration_secs);
#else
    // Full 4-line layout for 128x64 displays
    // Line 1: Title (larger font)
    u8g2_SetFont(&s_u8g2, u8g2_font_7x14B_tf);
    draw_text_line(&s_u8g2, 13, s_display.title[0] ? s_display.title : "---");

    // Line 2: Artist
    u8g2_SetFont(&s_u8g2, u8g2_font_6x13_tf);
    draw_text_line(&s_u8g2, 28, s_display.artist[0] ? s_display.artist : "");

    // Line 3: Album
    draw_text_line(&s_u8g2, 42, s_display.album[0] ? s_display.album : "");

    // Line 4: Progress bar with times
    u8g2_SetFont(&s_u8g2, u8g2_font_5x8_tf);
    draw_progress(&s_u8g2, 62, s_display.position_secs,
                  s_display.duration_secs);

    // Paused indicator
    if (s_display.state == DISPLAY_STATE_PAUSED) {
      u8g2_SetFont(&s_u8g2, u8g2_font_5x8_tf);
      const char *paused_str = "||";
      int w = u8g2_GetUTF8Width(&s_u8g2, paused_str);
      u8g2_DrawUTF8(&s_u8g2, 128 - w, 8, paused_str);
    }
#endif
    break;
  }
  }

  u8g2_SendBuffer(&s_u8g2);
}

// ============================================================================
// RTSP event callback
// ============================================================================

static void on_rtsp_event(rtsp_event_t event, const rtsp_event_data_t *data,
                          void *user_data) {
  (void)user_data;

  switch (event) {
  case RTSP_EVENT_CLIENT_CONNECTED:
    s_display.state = DISPLAY_STATE_CONNECTED;
    memset(s_display.title, 0, sizeof(s_display.title));
    memset(s_display.artist, 0, sizeof(s_display.artist));
    memset(s_display.album, 0, sizeof(s_display.album));
    s_display.duration_secs = 0;
    s_display.position_secs = 0;
    s_display.dirty = true;
#if defined(CONFIG_DISPLAY_HEIGHT_32)
    s_scroll.offset = 0;
    s_scroll.active = false;
#endif
    break;

  case RTSP_EVENT_PLAYING:
    s_display.state = DISPLAY_STATE_PLAYING;
    s_display.dirty = true;
    break;

  case RTSP_EVENT_PAUSED:
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
    s_display.dirty = true;
#if defined(CONFIG_DISPLAY_HEIGHT_32)
    s_scroll.offset = 0;
    s_scroll.active = false;
#endif
    break;

  case RTSP_EVENT_METADATA:
    if (data) {
      memcpy(s_display.title, data->metadata.title, METADATA_STRING_MAX);
      memcpy(s_display.artist, data->metadata.artist, METADATA_STRING_MAX);
      memcpy(s_display.album, data->metadata.album, METADATA_STRING_MAX);
      s_display.duration_secs = data->metadata.duration_secs;
      s_display.position_secs = data->metadata.position_secs;
      s_display.dirty = true;
#if defined(CONFIG_DISPLAY_HEIGHT_32)
      s_scroll.offset = 0;
      s_scroll.pause_ticks = SCROLL_PAUSE_TICKS;
#endif
    }
    break;
  }
}

// ============================================================================
// Display task
// ============================================================================

static void display_task(void *pvParameters) {
  (void)pvParameters;
  const TickType_t interval = pdMS_TO_TICKS(CONFIG_DISPLAY_UPDATE_MS);
#if defined(CONFIG_DISPLAY_HEIGHT_32)
  const TickType_t scroll_interval = pdMS_TO_TICKS(SCROLL_INTERVAL_MS);
#endif

  // Initial render
  display_render();

  while (1) {
#if defined(CONFIG_DISPLAY_HEIGHT_32)
    if (s_scroll.active) {
      vTaskDelay(scroll_interval);
      display_render();
      if (s_display.dirty) {
        s_display.dirty = false;
      }
      continue;
    }
#endif
    vTaskDelay(interval);
    if (s_display.dirty) {
      s_display.dirty = false;
      display_render();
    }
  }
}

// ============================================================================
// Initialization
// ============================================================================

void display_init(void) {
  ESP_LOGI(TAG, "Initializing OLED display (SDA=%d SCL=%d addr=0x%02x)",
           CONFIG_DISPLAY_I2C_SDA, CONFIG_DISPLAY_I2C_SCL,
           CONFIG_DISPLAY_I2C_ADDR);

  // Configure the ESP32 HAL for I2C
  u8g2_esp32_hal_t hal = U8G2_ESP32_HAL_DEFAULT;
  hal.bus.i2c.sda = CONFIG_DISPLAY_I2C_SDA;
  hal.bus.i2c.scl = CONFIG_DISPLAY_I2C_SCL;
  u8g2_esp32_hal_init(hal);

  // Setup u8g2 for the selected display driver and height
#if defined(CONFIG_DISPLAY_DRIVER_SH1106)
#if defined(CONFIG_DISPLAY_HEIGHT_32)
  u8g2_Setup_sh1106_i2c_128x32_visionox_f(
      &s_u8g2, U8G2_R0, u8g2_esp32_i2c_byte_cb, u8g2_esp32_gpio_and_delay_cb);
#else
  u8g2_Setup_sh1106_i2c_128x64_noname_f(&s_u8g2, U8G2_R0,
                                         u8g2_esp32_i2c_byte_cb,
                                         u8g2_esp32_gpio_and_delay_cb);
#endif
#elif defined(CONFIG_DISPLAY_DRIVER_SSD1309)
  u8g2_Setup_ssd1309_i2c_128x64_noname0_f(&s_u8g2, U8G2_R0,
                                           u8g2_esp32_i2c_byte_cb,
                                           u8g2_esp32_gpio_and_delay_cb);
#else // SSD1306 (default)
#if defined(CONFIG_DISPLAY_HEIGHT_32)
  u8g2_Setup_ssd1306_i2c_128x32_univision_f(
      &s_u8g2, U8G2_R0, u8g2_esp32_i2c_byte_cb, u8g2_esp32_gpio_and_delay_cb);
#else
  u8g2_Setup_ssd1306_i2c_128x64_noname_f(&s_u8g2, U8G2_R0,
                                          u8g2_esp32_i2c_byte_cb,
                                          u8g2_esp32_gpio_and_delay_cb);
#endif
#endif

  // Set I2C address (u8x8 expects left-shifted 7-bit address)
  u8x8_SetI2CAddress(&s_u8g2.u8x8, CONFIG_DISPLAY_I2C_ADDR << 1);

  u8g2_InitDisplay(&s_u8g2);
  u8g2_SetPowerSave(&s_u8g2, 0);

#ifdef CONFIG_DISPLAY_FLIP
  u8g2_SetFlipMode(&s_u8g2, 1);
#endif

  u8g2_ClearBuffer(&s_u8g2);
  u8g2_SendBuffer(&s_u8g2);

  // Initialize state
  s_display.state = DISPLAY_STATE_STANDBY;
  s_display.dirty = true;

  // Register for RTSP events
  rtsp_events_register(on_rtsp_event, NULL);

  // Start display refresh task
  xTaskCreate(display_task, "display", 4096, NULL, 3, NULL);

  ESP_LOGI(TAG, "OLED display initialized");
}

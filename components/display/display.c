#include "display.h"
#include "rtsp_events.h"

#include "u8g2.h"
#include "u8g2_esp32_hal.h"

#include "esp_log.h"
#include "esp_timer.h"
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
  bool dirty;           // set by event callback, cleared by render
  int64_t sync_time_us; // esp_timer_get_time() when position was last synced
} s_display;

// Scroll configuration
#define SCROLL_PX_PER_TICK 2
#define SCROLL_PAUSE_TICKS 3 // pause before scrolling restarts
#define SCROLL_GAP_PX      30 // pixel gap before text wraps
#define SCROLL_INTERVAL_MS 50 // render interval during active scroll
#define PAUSE_INDICATOR_W  14 // reserved width for "||" + gap

#if defined(CONFIG_DISPLAY_HEIGHT_32)
#define NUM_SCROLL_LINES 1
#else
#define NUM_SCROLL_LINES 3
#endif

static struct {
  int offset[NUM_SCROLL_LINES];
  int pause_ticks[NUM_SCROLL_LINES];
  bool active; // true if any line is scrolling
} s_scroll;

static void scroll_reset(void) {
  memset(&s_scroll, 0, sizeof(s_scroll));
}

static void scroll_restart(void) {
  for (int i = 0; i < NUM_SCROLL_LINES; i++) {
    s_scroll.offset[i] = 0;
    s_scroll.pause_ticks[i] = SCROLL_PAUSE_TICKS;
  }
}

// ============================================================================
// Helpers
// ============================================================================

/**
 * Draw a separator bar in the gap between wrapped copies of the text.
 */
static void draw_scroll_separator(u8g2_t *u8g2, int x, int y) {
  int ascent = u8g2_GetAscent(u8g2);
  int h = ascent;
  u8g2_DrawVLine(u8g2, x, y - h + 1, h);
}

/**
 * Draw a text line with continuous horizontal scrolling when content exceeds
 * max_w.  The text wraps seamlessly: a vertical bar separator and the text's
 * beginning scroll in from the right before the end scrolls off the left,
 * creating a smooth loop with no snap-back.
 */
static void draw_scrolling_line(u8g2_t *u8g2, int idx, int y, const char *str,
                                int max_w) {
  if (!str || !str[0])
    return;

  int text_w = u8g2_GetUTF8Width(u8g2, str);

  if (text_w <= max_w) {
    u8g2_DrawUTF8(u8g2, 0, y, str);
    s_scroll.offset[idx] = 0;
    return;
  }

  // Total loop length: text + gap (the gap holds the separator bar)
  int loop_w = text_w + SCROLL_GAP_PX;

  s_scroll.active = true;
  int ascent = u8g2_GetAscent(u8g2);
  int descent = u8g2_GetDescent(u8g2);
  u8g2_SetClipWindow(u8g2, 0, y - ascent, max_w, y - descent + 1);

  int off = s_scroll.offset[idx];

  // Draw the primary copy
  u8g2_DrawUTF8(u8g2, -off, y, str);
  // Draw separator bar in the gap
  draw_scroll_separator(u8g2, text_w + SCROLL_GAP_PX / 2 - off, y);
  // Draw the wrapped copy (appears from the right)
  u8g2_DrawUTF8(u8g2, loop_w - off, y, str);

  u8g2_SetMaxClipWindow(u8g2);

  if (s_scroll.pause_ticks[idx] > 0) {
    s_scroll.pause_ticks[idx]--;
  } else {
    s_scroll.offset[idx] += SCROLL_PX_PER_TICK;
    if (s_scroll.offset[idx] >= loop_w) {
      s_scroll.offset[idx] = 0;
    }
  }
}

/**
 * Draw the progress bar: [====>          ] with time on each side.
 */
/**
 * Get the estimated playback position based on wall-clock interpolation.
 */
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
    s_scroll.active = false;
    bool paused = (s_display.state == DISPLAY_STATE_PAUSED);
    int disp_w = u8g2_GetDisplayWidth(&s_u8g2);
    int top_max_w = paused ? disp_w - PAUSE_INDICATOR_W : disp_w;

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
    draw_scrolling_line(&s_u8g2, 0, 13, line, top_max_w);

    // Line 2: Progress bar
    u8g2_SetFont(&s_u8g2, u8g2_font_5x8_tf);
    draw_progress(&s_u8g2, 30, get_estimated_position(),
                  s_display.duration_secs);
#else
    // Full 4-line layout for 128x64 displays
    // Line 1: Title (larger font, clipped for pause indicator)
    u8g2_SetFont(&s_u8g2, u8g2_font_7x14B_tf);
    draw_scrolling_line(&s_u8g2, 0, 13,
                        s_display.title[0] ? s_display.title : "---",
                        top_max_w);

    // Line 2: Artist
    u8g2_SetFont(&s_u8g2, u8g2_font_6x13_tf);
    draw_scrolling_line(&s_u8g2, 1, 28,
                        s_display.artist[0] ? s_display.artist : "", disp_w);

    // Line 3: Album
    draw_scrolling_line(&s_u8g2, 2, 42,
                        s_display.album[0] ? s_display.album : "", disp_w);

    // Line 4: Progress bar with times
    u8g2_SetFont(&s_u8g2, u8g2_font_5x8_tf);
    draw_progress(&s_u8g2, 62, get_estimated_position(),
                  s_display.duration_secs);
#endif

    // Paused indicator (top-right)
    if (paused) {
      u8g2_SetFont(&s_u8g2, u8g2_font_5x8_tf);
      const char *paused_str = "||";
      int w = u8g2_GetUTF8Width(&s_u8g2, paused_str);
      u8g2_DrawUTF8(&s_u8g2, disp_w - w, 8, paused_str);
    }
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
    s_display.sync_time_us = 0;
    s_display.dirty = true;
    scroll_reset();
    break;

  case RTSP_EVENT_PLAYING:
    s_display.state = DISPLAY_STATE_PLAYING;
    s_display.sync_time_us = esp_timer_get_time();
    s_display.dirty = true;
    break;

  case RTSP_EVENT_PAUSED:
    // Freeze position at current estimate before pausing
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
    scroll_reset();
    break;

  case RTSP_EVENT_METADATA:
    if (data) {
      // Only overwrite text fields when the event actually carries them;
      // progress-only updates arrive with zeroed strings.
      if (data->metadata.title[0]) {
        memcpy(s_display.title, data->metadata.title, METADATA_STRING_MAX);
      }
      if (data->metadata.artist[0]) {
        memcpy(s_display.artist, data->metadata.artist, METADATA_STRING_MAX);
      }
      if (data->metadata.album[0]) {
        memcpy(s_display.album, data->metadata.album, METADATA_STRING_MAX);
      }
      if (data->metadata.duration_secs) {
        s_display.duration_secs = data->metadata.duration_secs;
      }
      s_display.position_secs = data->metadata.position_secs;
      s_display.sync_time_us = esp_timer_get_time();
      s_display.dirty = true;
      scroll_restart();
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
  const TickType_t one_sec = pdMS_TO_TICKS(1000);
  const TickType_t scroll_interval = pdMS_TO_TICKS(SCROLL_INTERVAL_MS);

  // Initial render
  display_render();

  while (1) {
    bool is_playing = (s_display.state == DISPLAY_STATE_PLAYING);
    if (s_scroll.active) {
      vTaskDelay(scroll_interval);
      s_display.dirty = false;
      display_render();
      continue;
    }
    if (is_playing) {
      vTaskDelay(one_sec);
      s_display.dirty = false;
      display_render();
      continue;
    }
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
#if defined(CONFIG_DISPLAY_BUS_SPI)
  ESP_LOGI(
      TAG, "Initializing OLED display (SPI: CLK=%d MOSI=%d CS=%d DC=%d RST=%d)",
      CONFIG_DISPLAY_SPI_CLK, CONFIG_DISPLAY_SPI_MOSI, CONFIG_DISPLAY_SPI_CS,
      CONFIG_DISPLAY_SPI_DC, CONFIG_DISPLAY_SPI_RST);

  u8g2_esp32_hal_t hal = U8G2_ESP32_HAL_DEFAULT;
  hal.bus.spi.clk = CONFIG_DISPLAY_SPI_CLK;
  hal.bus.spi.mosi = CONFIG_DISPLAY_SPI_MOSI;
  hal.bus.spi.cs = CONFIG_DISPLAY_SPI_CS;
  hal.dc = CONFIG_DISPLAY_SPI_DC;
  hal.reset = CONFIG_DISPLAY_SPI_RST;
  u8g2_esp32_hal_init(hal);

  // Setup u8g2 for the selected display driver and height (SPI)
#if defined(CONFIG_DISPLAY_DRIVER_SH1106)
#if defined(CONFIG_DISPLAY_HEIGHT_32)
  u8g2_Setup_sh1106_128x32_visionox_f(&s_u8g2, U8G2_R0, u8g2_esp32_spi_byte_cb,
                                      u8g2_esp32_gpio_and_delay_cb);
#else
  u8g2_Setup_sh1106_128x64_noname_f(&s_u8g2, U8G2_R0, u8g2_esp32_spi_byte_cb,
                                    u8g2_esp32_gpio_and_delay_cb);
#endif
#elif defined(CONFIG_DISPLAY_DRIVER_SSD1309)
  u8g2_Setup_ssd1309_128x64_noname0_f(&s_u8g2, U8G2_R0, u8g2_esp32_spi_byte_cb,
                                      u8g2_esp32_gpio_and_delay_cb);
#else // SSD1306 (default)
#if defined(CONFIG_DISPLAY_HEIGHT_32)
  u8g2_Setup_ssd1306_128x32_univision_f(
      &s_u8g2, U8G2_R0, u8g2_esp32_spi_byte_cb, u8g2_esp32_gpio_and_delay_cb);
#else
  u8g2_Setup_ssd1306_128x64_vcomh0_f(&s_u8g2, U8G2_R0, u8g2_esp32_spi_byte_cb,
                                     u8g2_esp32_gpio_and_delay_cb);
#endif
#endif

#else // I2C (default)
  ESP_LOGI(TAG, "Initializing OLED display (I2C: SDA=%d SCL=%d addr=0x%02x)",
           CONFIG_DISPLAY_I2C_SDA, CONFIG_DISPLAY_I2C_SCL,
           CONFIG_DISPLAY_I2C_ADDR);

  // Configure the ESP32 HAL for I2C
  u8g2_esp32_hal_t hal = U8G2_ESP32_HAL_DEFAULT;
  hal.bus.i2c.sda = CONFIG_DISPLAY_I2C_SDA;
  hal.bus.i2c.scl = CONFIG_DISPLAY_I2C_SCL;
  u8g2_esp32_hal_init(hal);

  // Setup u8g2 for the selected display driver and height (I2C)
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
#endif // DISPLAY_BUS

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

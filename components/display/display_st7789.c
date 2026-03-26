/**
 * @file display_st7789.c
 * @brief ST7789 TFT display driver using esp_lcd + LVGL 9 (esp_lvgl_port)
 *
 * Implements the display_init() API for ST7789-based TFT displays.
 * Display: 320x170 pixels, landscape orientation, SPI interface.
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
#include "lvgl.h"

#include <stdio.h>
#include <string.h>

static const char *TAG = "display_st7789";

// ============================================================================
// Hardware configuration
// ============================================================================

// Landscape 320x170. Hardware rotation (swap_xy + mirror_x) is applied via
// esp_lcd panel calls AFTER lvgl_port_add_disp().
//
// Important: esp_lvgl_port internally calls panel operations during
// lvgl_port_add_disp() that reset the ST7789 MADCTL register (which controls
// pixel addressing direction), wiping any rotation set before that call.
// Applying swap_xy/mirror/set_gap after lvgl_port_add_disp() ensures the
// correct landscape orientation is preserved. This is an ST7789 + esp_lvgl_port
// interaction and applies regardless of ESP32 variant.
#define DISPLAY_WIDTH        320
#define DISPLAY_HEIGHT       170
#define LCD_HOST             SPI2_HOST
#define LCD_PIXEL_CLOCK_HZ   (40 * 1000 * 1000)
#define DRAW_BUF_LINES       20
#define TRANS_BUF_LINES      2

// ============================================================================
// Layout constants — adjust these to tune vertical spacing
// ============================================================================
#define Y_TITLE       8
#define Y_ARTIST      38
#define Y_ALBUM       64
#define Y_PROGRESS    104
#define Y_TIME        122
#define BAR_HEIGHT    12

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
    bool dirty;
    int64_t sync_time_us;
} s_display;

// ============================================================================
// LVGL handles and widgets
// ============================================================================

static lv_display_t  *s_lvgl_disp  = NULL;

static lv_obj_t *s_label_title          = NULL;
static lv_obj_t *s_label_artist         = NULL;
static lv_obj_t *s_label_album          = NULL;
static lv_obj_t *s_label_status         = NULL;
static lv_obj_t *s_bar_progress         = NULL;
static lv_obj_t *s_label_time_elapsed   = NULL;
static lv_obj_t *s_label_time_remaining = NULL;

// ============================================================================
// Helpers
// ============================================================================

static uint32_t get_estimated_position(void)
{
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

static void format_time(uint32_t secs, char *buf, size_t len)
{
    snprintf(buf, len, "%lu:%02lu", secs / 60, secs % 60);
}

static void format_remaining(uint32_t remaining_secs, char *buf, size_t len)
{
    snprintf(buf, len, "-%lu:%02lu", remaining_secs / 60, remaining_secs % 60);
}

// ============================================================================
// UI creation - called once after LVGL init, with lock held
// ============================================================================

static void ui_create(void)
{
    lv_obj_t *scr = lv_screen_active();

    // Gradient background: dark blue-black at top fading to black at bottom
    lv_obj_set_style_bg_color(scr, lv_color_make(10, 10, 30), 0);
    lv_obj_set_style_bg_grad_color(scr, lv_color_black(), 0);
    lv_obj_set_style_bg_grad_dir(scr, LV_GRAD_DIR_VER, 0);
    lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);

    // Title — largest font, white, scrolling
    s_label_title = lv_label_create(scr);
    lv_obj_set_width(s_label_title, DISPLAY_WIDTH - 10);
    lv_label_set_long_mode(s_label_title, LV_LABEL_LONG_SCROLL_CIRCULAR);
    lv_obj_set_style_text_font(s_label_title, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(s_label_title, lv_color_white(), 0);
    lv_obj_align(s_label_title, LV_ALIGN_TOP_LEFT, 5, Y_TITLE);
    lv_label_set_text(s_label_title, "AirPlay Ready");

    // Artist — medium font, light grey, scrolling
    s_label_artist = lv_label_create(scr);
    lv_obj_set_width(s_label_artist, DISPLAY_WIDTH - 10);
    lv_label_set_long_mode(s_label_artist, LV_LABEL_LONG_SCROLL_CIRCULAR);
    lv_obj_set_style_text_font(s_label_artist, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_color(s_label_artist, lv_color_make(180, 180, 180), 0);
    lv_obj_align(s_label_artist, LV_ALIGN_TOP_LEFT, 5, Y_ARTIST);
    lv_label_set_text(s_label_artist, "");

    // Album — small font, dimmer grey, scrolling
    // Width leaves room on the right for the paused indicator
    s_label_album = lv_label_create(scr);
    lv_obj_set_width(s_label_album, DISPLAY_WIDTH - 80);
    lv_label_set_long_mode(s_label_album, LV_LABEL_LONG_SCROLL_CIRCULAR);
    lv_obj_set_style_text_font(s_label_album, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(s_label_album, lv_color_make(110, 110, 110), 0);
    lv_obj_align(s_label_album, LV_ALIGN_TOP_LEFT, 5, Y_ALBUM);
    lv_label_set_text(s_label_album, "");

    // Paused status indicator — right side at album row, amber
    s_label_status = lv_label_create(scr);
    lv_obj_set_style_text_font(s_label_status, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(s_label_status, lv_color_make(255, 200, 0), 0);
    lv_obj_align(s_label_status, LV_ALIGN_TOP_RIGHT, -5, Y_ALBUM);
    lv_label_set_text(s_label_status, "");

    // Progress bar — full width minus margins, rounded
    s_bar_progress = lv_bar_create(scr);
    lv_obj_set_size(s_bar_progress, DISPLAY_WIDTH - 10, BAR_HEIGHT);
    lv_obj_align(s_bar_progress, LV_ALIGN_TOP_LEFT, 5, Y_PROGRESS);
    lv_bar_set_range(s_bar_progress, 0, 100);
    lv_bar_set_value(s_bar_progress, 0, LV_ANIM_OFF);
    lv_obj_set_style_bg_color(s_bar_progress, lv_color_make(50, 50, 50), 0);
    lv_obj_set_style_bg_color(s_bar_progress, lv_color_make(30, 144, 255), LV_PART_INDICATOR);
    lv_obj_set_style_radius(s_bar_progress, 3, 0);
    lv_obj_set_style_radius(s_bar_progress, 3, LV_PART_INDICATOR);

    // Elapsed time — below bar, left aligned
    s_label_time_elapsed = lv_label_create(scr);
    lv_obj_set_style_text_font(s_label_time_elapsed, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(s_label_time_elapsed, lv_color_make(150, 150, 150), 0);
    lv_obj_align(s_label_time_elapsed, LV_ALIGN_TOP_LEFT, 5, Y_TIME);
    lv_label_set_text(s_label_time_elapsed, "");

    // Remaining time — below bar, right aligned, with leading minus sign
    s_label_time_remaining = lv_label_create(scr);
    lv_obj_set_style_text_font(s_label_time_remaining, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(s_label_time_remaining, lv_color_make(150, 150, 150), 0);
    lv_obj_align(s_label_time_remaining, LV_ALIGN_TOP_RIGHT, -5, Y_TIME);
    lv_label_set_text(s_label_time_remaining, "");
}

// ============================================================================
// UI update
// ============================================================================

static void ui_update(void)
{
    if (!lvgl_port_lock(100)) {
        ESP_LOGW(TAG, "ui_update: lock timeout");
        return;
    }

    switch (s_display.state) {
        case DISPLAY_STATE_STANDBY:
            lv_label_set_text(s_label_title,          "AirPlay Ready");
            lv_label_set_text(s_label_artist,          "");
            lv_label_set_text(s_label_album,           "");
            lv_label_set_text(s_label_status,          "");
            lv_label_set_text(s_label_time_elapsed,    "");
            lv_label_set_text(s_label_time_remaining,  "");
            lv_bar_set_value(s_bar_progress, 0, LV_ANIM_OFF);
            break;

        case DISPLAY_STATE_CONNECTED:
            lv_label_set_text(s_label_title,          "Connected");
            lv_label_set_text(s_label_artist,          "");
            lv_label_set_text(s_label_album,           "");
            lv_label_set_text(s_label_status,          "");
            lv_label_set_text(s_label_time_elapsed,    "");
            lv_label_set_text(s_label_time_remaining,  "");
            lv_bar_set_value(s_bar_progress, 0, LV_ANIM_OFF);
            break;

        case DISPLAY_STATE_PLAYING:
        case DISPLAY_STATE_PAUSED: {
            lv_label_set_text(s_label_title,
                s_display.title[0]  ? s_display.title  : "---");
            lv_label_set_text(s_label_artist,
                s_display.artist[0] ? s_display.artist : "");
            lv_label_set_text(s_label_album,
                s_display.album[0]  ? s_display.album  : "");
            lv_label_set_text(s_label_status,
                s_display.state == DISPLAY_STATE_PAUSED ? "|| " : "");

            uint32_t pos = get_estimated_position();

            if (s_display.duration_secs > 0) {
                // Progress bar
                int pct = (int)((uint64_t)pos * 100 / s_display.duration_secs);
                lv_bar_set_value(s_bar_progress, pct, LV_ANIM_OFF);

                // Elapsed time (left)
                char elapsed_str[12];
                format_time(pos, elapsed_str, sizeof(elapsed_str));
                lv_label_set_text(s_label_time_elapsed, elapsed_str);

                // Remaining time (right) with leading minus sign
                uint32_t remaining = (pos <= s_display.duration_secs)
                                     ? s_display.duration_secs - pos : 0;
                char remaining_str[14];
                format_remaining(remaining, remaining_str, sizeof(remaining_str));
                lv_label_set_text(s_label_time_remaining, remaining_str);
            } else {
                lv_bar_set_value(s_bar_progress, 0, LV_ANIM_OFF);
                lv_label_set_text(s_label_time_elapsed,   "");
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
                          void *user_data)
{
    (void)user_data;

    switch (event) {
        case RTSP_EVENT_CLIENT_CONNECTED:
            s_display.state = DISPLAY_STATE_CONNECTED;
            memset(s_display.title,  0, sizeof(s_display.title));
            memset(s_display.artist, 0, sizeof(s_display.artist));
            memset(s_display.album,  0, sizeof(s_display.album));
            s_display.duration_secs = 0;
            s_display.position_secs = 0;
            s_display.sync_time_us  = 0;
            s_display.dirty = true;
            break;

        case RTSP_EVENT_PLAYING:
            s_display.state = DISPLAY_STATE_PLAYING;
            s_display.sync_time_us = esp_timer_get_time();
            s_display.dirty = true;
            break;

        case RTSP_EVENT_PAUSED:
            s_display.position_secs = get_estimated_position();
            s_display.sync_time_us  = 0;
            s_display.state = DISPLAY_STATE_PAUSED;
            s_display.dirty = true;
            break;

        case RTSP_EVENT_DISCONNECTED:
            s_display.state = DISPLAY_STATE_STANDBY;
            memset(s_display.title,  0, sizeof(s_display.title));
            memset(s_display.artist, 0, sizeof(s_display.artist));
            memset(s_display.album,  0, sizeof(s_display.album));
            s_display.duration_secs = 0;
            s_display.position_secs = 0;
            s_display.sync_time_us  = 0;
            s_display.dirty = true;
            break;

        case RTSP_EVENT_METADATA:
            if (data) {
                bool track_changed = data->metadata.title[0] &&
                                     strcmp(data->metadata.title, s_display.title) != 0;

                if (data->metadata.title[0])
                    memcpy(s_display.title,  data->metadata.title, METADATA_STRING_MAX);
                if (data->metadata.artist[0])
                    memcpy(s_display.artist, data->metadata.artist, METADATA_STRING_MAX);
                if (data->metadata.album[0])
                    memcpy(s_display.album,  data->metadata.album, METADATA_STRING_MAX);
                if (data->metadata.duration_secs)
                    s_display.duration_secs = data->metadata.duration_secs;

                if (track_changed || data->metadata.position_secs ||
                        s_display.position_secs == 0)
                    s_display.position_secs = data->metadata.position_secs;

                s_display.sync_time_us  = esp_timer_get_time();
                s_display.dirty = true;
            }
            break;
    }
}

// ============================================================================
// Display task
// ============================================================================

static void display_task(void *pvParameters)
{
    (void)pvParameters;

    while (1) {
        if (s_display.dirty) {
            s_display.dirty = false;
            ui_update();
        }

        static TickType_t last_progress_update = 0;
        TickType_t now = xTaskGetTickCount();
        if (s_display.state == DISPLAY_STATE_PLAYING &&
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

void display_init(void)
{
    ESP_LOGI(TAG,
             "Initializing ST7789 (%dx%d landscape) "
             "CLK=%d MOSI=%d CS=%d DC=%d RST=%d BL=%d",
             DISPLAY_WIDTH, DISPLAY_HEIGHT,
             CONFIG_DISPLAY_SPI_CLK,  CONFIG_DISPLAY_SPI_MOSI,
             CONFIG_DISPLAY_SPI_CS,   CONFIG_DISPLAY_SPI_DC,
             CONFIG_DISPLAY_SPI_RST,  CONFIG_DISPLAY_BL_GPIO);

    // ---- Backlight OFF during init ----------------------------------------
    gpio_config_t bl_cfg = {
        .pin_bit_mask = BIT64(CONFIG_DISPLAY_BL_GPIO),
        .mode         = GPIO_MODE_OUTPUT,
    };
    ESP_ERROR_CHECK(gpio_config(&bl_cfg));
    gpio_set_level(CONFIG_DISPLAY_BL_GPIO, 0);

    // ---- SPI bus ------------------------------------------------------------
    spi_bus_config_t buscfg = {
        .mosi_io_num     = CONFIG_DISPLAY_SPI_MOSI,
        .miso_io_num     = -1,
        .sclk_io_num     = CONFIG_DISPLAY_SPI_CLK,
        .quadwp_io_num   = -1,
        .quadhd_io_num   = -1,
        .max_transfer_sz = DISPLAY_WIDTH * DRAW_BUF_LINES * sizeof(uint16_t),
    };
    ESP_ERROR_CHECK(spi_bus_initialize(LCD_HOST, &buscfg, SPI_DMA_CH_AUTO));

    // ---- LCD panel IO (SPI) -------------------------------------------------
    esp_lcd_panel_io_handle_t io_handle = NULL;
    esp_lcd_panel_io_spi_config_t io_cfg = {
        .dc_gpio_num       = CONFIG_DISPLAY_SPI_DC,
        .cs_gpio_num       = CONFIG_DISPLAY_SPI_CS,
        .pclk_hz           = LCD_PIXEL_CLOCK_HZ,
        .lcd_cmd_bits      = 8,
        .lcd_param_bits    = 8,
        .spi_mode          = 0,
        .trans_queue_depth = 4,
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi(
        (esp_lcd_spi_bus_handle_t)LCD_HOST, &io_cfg, &io_handle));

    // ---- ST7789 panel -------------------------------------------------------
    esp_lcd_panel_handle_t panel_handle = NULL;
    esp_lcd_panel_dev_config_t panel_cfg = {
        .reset_gpio_num = CONFIG_DISPLAY_SPI_RST,
        .rgb_endian     = LCD_RGB_ENDIAN_RGB,
        .bits_per_pixel = 16,
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_st7789(io_handle, &panel_cfg, &panel_handle));
    ESP_ERROR_CHECK(esp_lcd_panel_reset(panel_handle));
    ESP_ERROR_CHECK(esp_lcd_panel_init(panel_handle));
    ESP_ERROR_CHECK(esp_lcd_panel_invert_color(panel_handle, true));
    ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(panel_handle, true));
    // NOTE: swap_xy, mirror and set_gap applied AFTER lvgl_port_add_disp.
    // See comment at top of file for explanation.

    // ---- esp_lvgl_port init -------------------------------------------------
    // Pin the LVGL task to Core 0 (same as our display task).
    // The default task_affinity = -1 (no affinity) allows the LVGL task to
    // migrate to Core 1, where it interferes with the audio playback task
    // (priority 7). Pinning to Core 0 keeps Core 1 clean for audio.
    const lvgl_port_cfg_t lvgl_cfg = {
        .task_priority     = 4,
        .task_stack        = 6144,
        .task_affinity     = 0,   // Core 0 — keep Core 1 free for audio
        .task_max_sleep_ms = 500,
        .timer_period_ms   = 5,
    };
    ESP_ERROR_CHECK(lvgl_port_init(&lvgl_cfg));

    // ---- Add display to esp_lvgl_port ---------------------------------------
    const lvgl_port_display_cfg_t disp_cfg = {
        .io_handle     = io_handle,
        .panel_handle  = panel_handle,
        .buffer_size   = DISPLAY_WIDTH * DRAW_BUF_LINES,
        .double_buffer = true,
        .trans_size    = DISPLAY_WIDTH * TRANS_BUF_LINES,
        .hres          = DISPLAY_WIDTH,
        .vres          = DISPLAY_HEIGHT,
        .monochrome    = false,
        .flags = {
            .buff_spiram = true,
            .swap_bytes  = true,
        },
    };
    s_lvgl_disp = lvgl_port_add_disp(&disp_cfg);
    assert(s_lvgl_disp != NULL);

    // ---- Apply hardware rotation AFTER lvgl_port_add_disp ------------------
    // See comment at top of file for explanation.
    ESP_ERROR_CHECK(esp_lcd_panel_swap_xy(panel_handle, true));
    ESP_ERROR_CHECK(esp_lcd_panel_mirror(panel_handle, true, false));
    ESP_ERROR_CHECK(esp_lcd_panel_set_gap(panel_handle, 0, 35));

    // ---- Build initial UI ---------------------------------------------------
    lvgl_port_lock(0);
    ui_create();
    lvgl_port_unlock();

    // ---- Backlight ON -------------------------------------------------------
    gpio_set_level(CONFIG_DISPLAY_BL_GPIO, 1);

    // ---- Init state ---------------------------------------------------------
    s_display.state = DISPLAY_STATE_STANDBY;
    s_display.dirty = true;

    // ---- Register for RTSP events -------------------------------------------
    rtsp_events_register(on_rtsp_event, NULL);

    // ---- Start display task (state updates, progress tick) ------------------
    // Pinned to Core 0; audio runs on Core 1. Both the LVGL port task above
    // and this task are on Core 0, keeping Core 1 entirely free for audio.
    xTaskCreatePinnedToCore(display_task, "display", 4096, NULL, 3, NULL, 0);

    ESP_LOGI(TAG, "ST7789 display initialized (LVGL 9 + esp_lvgl_port)");
}

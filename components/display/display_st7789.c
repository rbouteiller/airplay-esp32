/**
 * @file display_st7789.c
 * @brief ST7789 TFT display driver using esp_lcd + LVGL 8.3
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

#define DISPLAY_WIDTH        320
#define DISPLAY_HEIGHT       170
#define LCD_HOST             SPI2_HOST
#define LCD_PIXEL_CLOCK_HZ   (40 * 1000 * 1000)
#define DRAW_BUF_LINES       20     // Lines per flush buffer — tune if needed

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

static SemaphoreHandle_t s_lvgl_mutex = NULL;

static lv_obj_t *s_label_title   = NULL;
static lv_obj_t *s_label_artist  = NULL;
static lv_obj_t *s_label_status  = NULL;
static lv_obj_t *s_bar_progress  = NULL;
static lv_obj_t *s_label_time    = NULL;

// ============================================================================
// LVGL flush callback
// ============================================================================

static void lvgl_flush_cb(lv_disp_drv_t *drv, const lv_area_t *area,
                          lv_color_t *color_map)
{
    esp_lcd_panel_handle_t panel = (esp_lcd_panel_handle_t)drv->user_data;
    esp_lcd_panel_draw_bitmap(panel,
                              area->x1, area->y1,
                              area->x2 + 1, area->y2 + 1,
                              color_map);
    lv_disp_flush_ready(drv);
}

// ============================================================================
// LVGL tick — incremented every 1ms by esp_timer
// ============================================================================

static void lvgl_tick_cb(void *arg)
{
    (void)arg;
    lv_tick_inc(1);
}

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

// ============================================================================
// UI creation — called once after LVGL init
// ============================================================================

static void ui_create(void)
{
    lv_obj_t *scr = lv_scr_act();
    lv_obj_set_style_bg_color(scr, lv_color_black(), 0);
    lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);

    // Title — large font, top of screen, circular scroll when too long
    s_label_title = lv_label_create(scr);
    lv_obj_set_width(s_label_title, DISPLAY_WIDTH - 10);
    lv_label_set_long_mode(s_label_title, LV_LABEL_LONG_SCROLL_CIRCULAR);
    lv_obj_set_style_text_font(s_label_title, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(s_label_title, lv_color_white(), 0);
    lv_obj_align(s_label_title, LV_ALIGN_TOP_LEFT, 5, 8);
    lv_label_set_text(s_label_title, "AirPlay Ready");

    // Artist — slightly smaller, muted colour, circular scroll
    s_label_artist = lv_label_create(scr);
    lv_obj_set_width(s_label_artist, DISPLAY_WIDTH - 10);
    lv_label_set_long_mode(s_label_artist, LV_LABEL_LONG_SCROLL_CIRCULAR);
    lv_obj_set_style_text_font(s_label_artist, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_color(s_label_artist, lv_color_make(180, 180, 180), 0);
    lv_obj_align(s_label_artist, LV_ALIGN_TOP_LEFT, 5, 42);
    lv_label_set_text(s_label_artist, "");

    // Progress bar — thin, accent colour fill
    s_bar_progress = lv_bar_create(scr);
    lv_obj_set_size(s_bar_progress, DISPLAY_WIDTH - 10, 6);
    lv_obj_align(s_bar_progress, LV_ALIGN_TOP_LEFT, 5, 118);
    lv_bar_set_range(s_bar_progress, 0, 100);
    lv_bar_set_value(s_bar_progress, 0, LV_ANIM_OFF);
    lv_obj_set_style_bg_color(s_bar_progress, lv_color_make(60, 60, 60), 0);
    lv_obj_set_style_bg_color(s_bar_progress,
                              lv_color_make(30, 144, 255),
                              LV_PART_INDICATOR);

    // Time label — bottom left, muted
    s_label_time = lv_label_create(scr);
    lv_obj_set_style_text_font(s_label_time, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(s_label_time, lv_color_make(150, 150, 150), 0);
    lv_obj_align(s_label_time, LV_ALIGN_TOP_LEFT, 5, 140);
    lv_label_set_text(s_label_time, "");

    // Status label — top right, yellow (paused indicator)
    s_label_status = lv_label_create(scr);
    lv_obj_set_style_text_font(s_label_status, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(s_label_status,
                                lv_color_make(255, 200, 0), 0);
    lv_obj_align(s_label_status, LV_ALIGN_TOP_RIGHT, -5, 8);
    lv_label_set_text(s_label_status, "");
}

// ============================================================================
// UI update — reflects current s_display state onto LVGL widgets
// ============================================================================

static void ui_update(void)
{
    if (xSemaphoreTake(s_lvgl_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        ESP_LOGW(TAG, "ui_update: mutex timeout");
        return;
    }

    switch (s_display.state) {
        case DISPLAY_STATE_STANDBY:
            lv_label_set_text(s_label_title, "AirPlay Ready");
            lv_label_set_text(s_label_artist, "");
            lv_label_set_text(s_label_status, "");
            lv_label_set_text(s_label_time, "");
            lv_bar_set_value(s_bar_progress, 0, LV_ANIM_OFF);
            break;

        case DISPLAY_STATE_CONNECTED:
            lv_label_set_text(s_label_title, "Connected");
            lv_label_set_text(s_label_artist, "");
            lv_label_set_text(s_label_status, "");
            lv_label_set_text(s_label_time, "");
            lv_bar_set_value(s_bar_progress, 0, LV_ANIM_OFF);
            break;

        case DISPLAY_STATE_PLAYING:
        case DISPLAY_STATE_PAUSED: {
            lv_label_set_text(s_label_title,
                s_display.title[0] ? s_display.title : "---");
            lv_label_set_text(s_label_artist,
                s_display.artist[0] ? s_display.artist : "");
            lv_label_set_text(s_label_status,
                s_display.state == DISPLAY_STATE_PAUSED ? "|| PAUSED" : "");

            // Progress bar
            uint32_t pos = get_estimated_position();
            if (s_display.duration_secs > 0) {
                int pct = (int)((uint64_t)pos * 100 / s_display.duration_secs);
                lv_bar_set_value(s_bar_progress, pct, LV_ANIM_OFF);
            }

            // Time string: "m:ss / m:ss"
            if (s_display.duration_secs > 0) {
                char pos_str[12], dur_str[12], time_buf[32];
                format_time(pos, pos_str, sizeof(pos_str));
                format_time(s_display.duration_secs, dur_str, sizeof(dur_str));
                snprintf(time_buf, sizeof(time_buf), "%s / %s", pos_str, dur_str);
                lv_label_set_text(s_label_time, time_buf);
            } else {
                lv_label_set_text(s_label_time, "");
            }
            break;
        }
    }

    xSemaphoreGive(s_lvgl_mutex);
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
            // Detect track change before updating title
            bool track_changed = data->metadata.title[0] &&
                                strcmp(data->metadata.title, s_display.title) != 0;

            if (data->metadata.title[0])
                memcpy(s_display.title,  data->metadata.title,
                    METADATA_STRING_MAX);
            if (data->metadata.artist[0])
                memcpy(s_display.artist, data->metadata.artist,
                    METADATA_STRING_MAX);
            if (data->metadata.album[0])
                memcpy(s_display.album,  data->metadata.album,
                    METADATA_STRING_MAX);
            if (data->metadata.duration_secs)
                s_display.duration_secs = data->metadata.duration_secs;

            // Reset position on track change, ignore spurious zeros mid-song
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
// Display task — drives lv_timer_handler and periodic UI updates
// ============================================================================

static void display_task(void *pvParameters)
{
    (void)pvParameters;

    while (1) {
        // Drive LVGL (animations, scrolling, redraws)
        if (xSemaphoreTake(s_lvgl_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
            lv_timer_handler();
            xSemaphoreGive(s_lvgl_mutex);
        }

        // Apply pending state changes
        if (s_display.dirty) {
            s_display.dirty = false;
            ui_update();
        }

        // Update progress every second while playing
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
    ESP_ERROR_CHECK(esp_lcd_new_panel_st7789(io_handle, &panel_cfg,
                                             &panel_handle));

    ESP_ERROR_CHECK(esp_lcd_panel_reset(panel_handle));
    ESP_ERROR_CHECK(esp_lcd_panel_init(panel_handle));

    // Orientation: landscape 320x170
    // NOTE: invert_color, mirror and gap may need tuning for your specific
    // board revision. If the image appears offset or mirrored, adjust here.
    ESP_ERROR_CHECK(esp_lcd_panel_invert_color(panel_handle, true));
    ESP_ERROR_CHECK(esp_lcd_panel_swap_xy(panel_handle, true));
    ESP_ERROR_CHECK(esp_lcd_panel_mirror(panel_handle, true, false));
    ESP_ERROR_CHECK(esp_lcd_panel_set_gap(panel_handle, 0, 35));

    ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(panel_handle, true));

    // ---- LVGL init ----------------------------------------------------------
    lv_init();

    // Draw buffers — allocate from PSRAM (S3 has 8MB available)
    size_t buf_size = DISPLAY_WIDTH * DRAW_BUF_LINES * sizeof(lv_color_t);
    lv_color_t *buf1 = heap_caps_malloc(buf_size, MALLOC_CAP_SPIRAM);
    lv_color_t *buf2 = heap_caps_malloc(buf_size, MALLOC_CAP_SPIRAM);
    assert(buf1 != NULL && buf2 != NULL);

    static lv_disp_draw_buf_t draw_buf;
    lv_disp_draw_buf_init(&draw_buf, buf1, buf2,
                          DISPLAY_WIDTH * DRAW_BUF_LINES);

    static lv_disp_drv_t disp_drv;
    lv_disp_drv_init(&disp_drv);
    disp_drv.hor_res   = DISPLAY_WIDTH;
    disp_drv.ver_res   = DISPLAY_HEIGHT;
    disp_drv.flush_cb  = lvgl_flush_cb;
    disp_drv.draw_buf  = &draw_buf;
    disp_drv.user_data = panel_handle;
    lv_disp_drv_register(&disp_drv);

    // ---- LVGL tick timer (1ms) ----------------------------------------------
    const esp_timer_create_args_t tick_args = {
        .callback = lvgl_tick_cb,
        .name     = "lvgl_tick",
    };
    esp_timer_handle_t tick_timer;
    ESP_ERROR_CHECK(esp_timer_create(&tick_args, &tick_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(tick_timer, 1000));

    // ---- Mutex for LVGL thread safety ---------------------------------------
    s_lvgl_mutex = xSemaphoreCreateMutex();
    assert(s_lvgl_mutex != NULL);

    // ---- Build initial UI ---------------------------------------------------
    ui_create();

    // ---- Backlight ON -------------------------------------------------------
    gpio_set_level(CONFIG_DISPLAY_BL_GPIO, 1);

    // ---- Init state ---------------------------------------------------------
    s_display.state = DISPLAY_STATE_STANDBY;
    s_display.dirty = true;

    // ---- Register for RTSP events -------------------------------------------
    rtsp_events_register(on_rtsp_event, NULL);

    // ---- Start display task -------------------------------------------------
    xTaskCreatePinnedToCore(display_task, "display", 8192, NULL, 3, NULL, 0);

    ESP_LOGI(TAG, "ST7789 display initialized");
}
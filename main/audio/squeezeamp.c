#include "squeezeamp.h"

#include "dac_tas57xx.h"
#include "driver/gpio.h"
#include "driver/ledc.h"
#include "esp_check.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"

#define I2C_PORT_0 0

static const char TAG[] = "SqueezeAMP";
static squeezeamp_state_e state = SQUEEZEAMP_STANDBY;

#define LEDC_TIMER     LEDC_TIMER_0
#define LEDC_MODE      LEDC_LOW_SPEED_MODE
#define LEDC_DUTY_RES  LEDC_TIMER_8_BIT
#define LEDC_FREQUENCY 1000 // 1 kHz PWM frequency

#define LEDC_GREEN_CHANNEL LEDC_CHANNEL_0
#define LEDC_RED_CHANNEL   LEDC_CHANNEL_1

static struct led_t {
  gpio_num_t gpio; // GPIO to use
  int channel;
  uint8_t duty; // LED on duty brightness percentage
  bool is_on;
  uint32_t on_ms;  // on time
  uint32_t off_ms; // off time
  TimerHandle_t timer;
} leds[] = {{.gpio = CONFIG_LED_GREEN_GPIO,
             .channel = LEDC_GREEN_CHANNEL,
             .duty = 10,
             .is_on = false,
             .on_ms = 250,
             .off_ms = 250,
             .timer = NULL},
            {.gpio = CONFIG_LED_RED_GPIO,
             .channel = LEDC_RED_CHANNEL,
             .duty = 40,
             .is_on = false,
             .on_ms = 0,
             .off_ms = 0,
             .timer = NULL}};

static esp_err_t init_leds(void);
static esp_err_t init_gpio(void);

static void flash_led(uint8_t id, uint32_t on_ms, uint32_t off_ms);

esp_err_t squeezeamp_init(void) {
  esp_err_t err = ESP_OK;

  // Initialize I2C for DAC control
  err = tas57xx_init(I2C_PORT_0, CONFIG_DAC_I2C_SDA, CONFIG_DAC_I2C_SCL);
  if (ESP_OK != err) {
    ESP_LOGE(TAG, "Failed to initialize TAS57xx: %s", esp_err_to_name(err));
  };

  // Set up status LEDs
  err = init_leds();

  // Configure other GPIO
  err = init_gpio();

  return err;
}

static esp_err_t init_leds(void) {
  esp_err_t err = ESP_OK;

  // Configure LEDC timer
  ledc_timer_config_t ledc_timer = {
      .speed_mode = LEDC_MODE,
      .duty_resolution = LEDC_DUTY_RES,
      .timer_num = LEDC_TIMER,
      .freq_hz = LEDC_FREQUENCY,
      .clk_cfg = LEDC_AUTO_CLK,
  };
  err = ledc_timer_config(&ledc_timer);
  ESP_RETURN_ON_ERROR(err, TAG, "Failed to configure LEDC timer");

  // Configure red LED channel
  ledc_channel_config_t red_channel = {
      .gpio_num = CONFIG_LED_RED_GPIO,
      .speed_mode = LEDC_MODE,
      .channel = LEDC_RED_CHANNEL,
      .intr_type = LEDC_INTR_DISABLE,
      .timer_sel = LEDC_TIMER,
      .duty = 0,
      .flags = {.output_invert = true},
      .hpoint = 0,
  };
  err = ledc_channel_config(&red_channel);
  ESP_RETURN_ON_ERROR(err, TAG, "Failed to configure red LED channel");
  ESP_LOGI(TAG, "Red LED initialized on GPIO %d", CONFIG_LED_RED_GPIO);

  // Configure green LED channel
  ledc_channel_config_t green_channel = {
      .gpio_num = CONFIG_LED_GREEN_GPIO,
      .speed_mode = LEDC_MODE,
      .channel = LEDC_GREEN_CHANNEL,
      .intr_type = LEDC_INTR_DISABLE,
      .timer_sel = LEDC_TIMER,
      .duty = 0,
      .flags = {.output_invert = true},
      .hpoint = 0,
  };
  err = ledc_channel_config(&green_channel);
  ESP_RETURN_ON_ERROR(err, TAG, "Failed to configure green LED channel");
  ESP_LOGI(TAG, "Green LED initialized on GPIO %d", CONFIG_LED_GREEN_GPIO);
  flash_led(LEDC_GREEN_CHANNEL, 250, 250);

  return err;
}

static esp_err_t init_gpio() {
  esp_err_t err = ESP_OK;

  // Configure the SPDIF output GPIO to off
#if CONFIG_SPDIF_DO_IO >= 0
  gpio_config_t spdif_gpio_cfg = {
      .pin_bit_mask = (1ULL << CONFIG_SPDIF_DO_IO),
      .mode = GPIO_MODE_OUTPUT,
      .pull_up_en = GPIO_PULLUP_DISABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_DISABLE,
  };
  err = gpio_config(&spdif_gpio_cfg);
  ESP_RETURN_ON_ERROR(err, TAG, "Failed to configure SPDIF GPIO");
  gpio_set_level(CONFIG_SPDIF_DO_IO, 0);
#endif
  return err;
}

esp_err_t squeezeamp_deinit() {
  tas57xx_enable_speaker(false);
  tas57xx_set_power_mode(TAS57XX_AMP_OFF);
  return ESP_OK;
}

squeezeamp_state_e squeezeamp_get_state() {
  return state;
}

void squeezeamp_set_state(squeezeamp_state_e new_state) {
  ESP_LOGD(TAG, "State change: %d -> %d", state, new_state);
  state = new_state;

  switch (new_state) {
  case SQUEEZEAMP_STANDBY:
    tas57xx_enable_speaker(true);
    tas57xx_set_power_mode(TAS57XX_AMP_OFF);
    flash_led(LEDC_GREEN_CHANNEL, 100, 2500);
    break;

  case SQUEEZEAMP_PLAYING:
    tas57xx_set_power_mode(TAS57XX_AMP_ON);
    flash_led(LEDC_GREEN_CHANNEL, 1, 0);
    break;

  case SQUEEZEAMP_PAUSED:
    flash_led(LEDC_GREEN_CHANNEL, 500, 500);
    tas57xx_set_power_mode(TAS57XX_AMP_STANDBY);
    break;

  case SQUEEZEAMP_ERROR:
    tas57xx_enable_speaker(false);
    tas57xx_set_power_mode(TAS57XX_AMP_OFF);

    ledc_set_duty(LEDC_MODE, LEDC_RED_CHANNEL, 80);
    ledc_update_duty(LEDC_MODE, LEDC_RED_CHANNEL);
    break;

  default:
    ESP_LOGE(TAG, "Unhandled state: %d", new_state);
    break;
  }
}

static void led_cb(TimerHandle_t xTimer) {
  struct led_t *led = (struct led_t *)pvTimerGetTimerID(xTimer);
  if (!led->timer)
    return;

  led->is_on = !led->is_on;

  ledc_set_duty(LEDC_MODE, led->channel, led->is_on ? led->duty : 0);
  ledc_update_duty(LEDC_MODE, led->channel);

  // If off_ms is 0, keep LED on (solid) - don't restart timer
  if (!led->is_on && led->off_ms == 0)
    return;

  // regular blinking - ensure at least 1 tick
  uint32_t period_ms = led->is_on ? led->on_ms : led->off_ms;
  TickType_t period_ticks = pdMS_TO_TICKS(period_ms);
  if (period_ticks == 0)
    period_ticks = 1;
  xTimerChangePeriod(xTimer, period_ticks, 10);
}

static void flash_led(uint8_t id, uint32_t on_ms, uint32_t off_ms) {
  if (leds[id].gpio < 0) {
    return;
  }

  ESP_LOGD(TAG, "flash_led: channel=%d, on_ms=%lu, off_ms=%lu", id, on_ms,
           off_ms);

  leds[id].on_ms = on_ms;
  leds[id].off_ms = off_ms;

  // For solid-on (off_ms == 0), just set the LED and don't use timer
  if (off_ms == 0) {
    if (leds[id].timer && xTimerIsTimerActive(leds[id].timer)) {
      xTimerStop(leds[id].timer, 10);
    }
    leds[id].is_on = true;
    ledc_set_duty(LEDC_MODE, leds[id].channel, leds[id].duty);
    ledc_update_duty(LEDC_MODE, leds[id].channel);
    ESP_LOGD(TAG, "LED channel %d set to solid on", id);
    return;
  }

  // Ensure at least 1 tick for timer period
  TickType_t period_ticks = pdMS_TO_TICKS(on_ms);
  if (period_ticks == 0)
    period_ticks = 1;

  if (!leds[id].timer) {
    leds[id].timer =
        xTimerCreate("led", period_ticks, pdFALSE, (void *)&leds[id], led_cb);
    leds[id].is_on = true;
  }
  if (!xTimerIsTimerActive(leds[id].timer)) {
    xTimerStart(leds[id].timer, 10);
  }
}
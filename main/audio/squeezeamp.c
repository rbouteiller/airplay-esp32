#include "squeezeamp.h"

#include "dac_tas57xx.h"
#include "driver/gpio.h"
#include "driver/ledc.h"
#include "esp_check.h"
#include "esp_log.h"

#define I2C_PORT_0 0

static const char TAG[] = "SqueezeAMP";
static squeezeamp_state_e state = SQUEEZEAMP_STANDBY;

#define LEDC_TIMER     LEDC_TIMER_0
#define LEDC_MODE      LEDC_LOW_SPEED_MODE
#define LEDC_DUTY_RES  LEDC_TIMER_8_BIT
#define LEDC_FREQUENCY 1000 // 1 kHz PWM frequency

#define LEDC_GREEN_CHANNEL LEDC_CHANNEL_0
#define LEDC_RED_CHANNEL   LEDC_CHANNEL_1

static esp_err_t init_leds(void);
static esp_err_t init_gpio(void);

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
#if CONFIG_LED_GREEN_GPIO >= 0 || CONFIG_LED_RED_GPIO >= 0
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

#if CONFIG_LED_RED_GPIO >= 0
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
#endif

#if CONFIG_LED_GREEN_GPIO >= 0
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
#endif

  return err;
#else
  ESP_LOGI(TAG, "No LEDs configured");
  return ESP_OK;
#endif
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

void squeezeamp_set_state(squeezeamp_state_e state) {
  switch (state) {
  case SQUEEZEAMP_STANDBY:
    /* code */
    tas57xx_set_power_mode(TAS57XX_AMP_ON);
    tas57xx_enable_speaker(true);
    break;
  case SQUEEZEAMP_CLIENT_CONNECTED:
    /* code */
    break;
  case SQUEEZEAMP_PLAYING:
    tas57xx_set_power_mode(TAS57XX_AMP_ON);
    tas57xx_enable_speaker(true);
    break;
  case SQUEEZEAMP_PAUSED:
    tas57xx_enable_speaker(false);
    tas57xx_set_power_mode(TAS57XX_AMP_STANDBY);

    break;
  case SQUEEZEAMP_ERROR:
    // TODO: turn on red LED
    break;
  default:
    ESP_LOGE(TAG, "Unhandled state: %d", state);
    break;
  }
}

void set_green_led() {
  
}
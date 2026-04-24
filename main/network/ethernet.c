#include "sdkconfig.h"

#ifdef CONFIG_ETH_W5500_ENABLED

#include "ethernet.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_eth.h"
#include "esp_eth_mac.h"
#include "esp_eth_mac_spi.h"
#include "esp_eth_netif_glue.h"
#include "esp_eth_phy.h"
#include "esp_mac.h"
#include "iot_board.h"

#include <string.h>

static const char *TAG = "ethernet";

#define ETH_SPI_CLOCK_MHZ 20

static esp_netif_t *s_eth_netif = NULL;
static esp_eth_handle_t s_eth_handle = NULL;
static bool s_eth_connected = false;
static bool s_eth_link_up = false;

static void eth_event_handler(void *arg, esp_event_base_t event_base,
                              int32_t event_id, void *event_data) {
  (void)arg;
  switch (event_id) {
  case ETHERNET_EVENT_CONNECTED:
    s_eth_link_up = true;
    ESP_LOGI(TAG, "Ethernet link up");
    break;
  case ETHERNET_EVENT_DISCONNECTED:
    s_eth_link_up = false;
    s_eth_connected = false;
    ESP_LOGW(TAG, "Ethernet link down");
    break;
  case ETHERNET_EVENT_START:
    ESP_LOGI(TAG, "Ethernet started");
    break;
  case ETHERNET_EVENT_STOP:
    s_eth_connected = false;
    ESP_LOGI(TAG, "Ethernet stopped");
    break;
  default:
    break;
  }
}

static void eth_got_ip_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data) {
  (void)arg;
  ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
  if (event->esp_netif == s_eth_netif) {
    ESP_LOGI(TAG, "Ethernet got IP: " IPSTR, IP2STR(&event->ip_info.ip));
    s_eth_connected = true;
  }
}

esp_err_t ethernet_init(void) {
  if (s_eth_handle != NULL) {
    ESP_LOGW(TAG, "Ethernet already initialized");
    return ESP_OK;
  }

  // Verify SPI bus is ready (board.c must have initialized it)
  if (iot_board_get_handle(BOARD_SPI_ETH_ID) == NULL) {
    ESP_LOGE(TAG, "SPI bus not initialized — cannot init W5500");
    return ESP_ERR_INVALID_STATE;
  }

  // Ensure netif and event loop are initialized
  esp_err_t ret = esp_netif_init();
  if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
    return ret;
  }
  ret = esp_event_loop_create_default();
  if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
    return ret;
  }

  // Register event handlers
  ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID,
                                             &eth_event_handler, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP,
                                             &eth_got_ip_handler, NULL));

  // Create default ethernet netif
  esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
  s_eth_netif = esp_netif_new(&netif_cfg);

  // Hardware reset the W5500 before SPI communication
#if BOARD_ETH_RST_GPIO >= 0
  gpio_config_t rst_cfg = {
      .pin_bit_mask = (1ULL << BOARD_ETH_RST_GPIO),
      .mode = GPIO_MODE_OUTPUT,
      .pull_up_en = GPIO_PULLUP_DISABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_DISABLE,
  };
  gpio_config(&rst_cfg);
  gpio_set_level(BOARD_ETH_RST_GPIO, 0);
  vTaskDelay(pdMS_TO_TICKS(10));
  gpio_set_level(BOARD_ETH_RST_GPIO, 1);
  vTaskDelay(pdMS_TO_TICKS(10));
  ESP_LOGI(TAG, "W5500 hardware reset complete (GPIO %d)", BOARD_ETH_RST_GPIO);
#endif

  // Configure SPI device for W5500 (bus already initialized by board.c)
  spi_device_interface_config_t spi_devcfg = {
      .mode = 0,
      .clock_speed_hz = ETH_SPI_CLOCK_MHZ * 1000 * 1000,
      .queue_size = 16,
      .spics_io_num = BOARD_ETH_CS_GPIO,
  };

  eth_w5500_config_t w5500_config =
      ETH_W5500_DEFAULT_CONFIG(BOARD_SPI_HOST, &spi_devcfg);
  w5500_config.int_gpio_num = BOARD_ETH_INT_GPIO;
#if BOARD_ETH_INT_GPIO < 0
  w5500_config.poll_period_ms = 10;
#endif

  // Create MAC instance
  eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
  mac_config.rx_task_stack_size = 4096;
  esp_eth_mac_t *mac = esp_eth_mac_new_w5500(&w5500_config, &mac_config);
  if (mac == NULL) {
    ESP_LOGE(TAG, "Failed to create W5500 MAC");
    esp_netif_destroy(s_eth_netif);
    s_eth_netif = NULL;
    return ESP_FAIL;
  }

  // Create PHY instance
  eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
  phy_config.reset_gpio_num = -1; // We already did HW reset above
  esp_eth_phy_t *phy = esp_eth_phy_new_w5500(&phy_config);
  if (phy == NULL) {
    ESP_LOGE(TAG, "Failed to create W5500 PHY");
    mac->del(mac);
    esp_netif_destroy(s_eth_netif);
    s_eth_netif = NULL;
    return ESP_FAIL;
  }

  // Install Ethernet driver
  esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
  ret = esp_eth_driver_install(&eth_config, &s_eth_handle);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Ethernet driver install failed: %s", esp_err_to_name(ret));
    phy->del(phy);
    mac->del(mac);
    esp_netif_destroy(s_eth_netif);
    s_eth_netif = NULL;
    return ret;
  }

  // W5500 has no factory MAC — derive one from the ESP32's base MAC
  uint8_t eth_mac[6];
  esp_read_mac(eth_mac, ESP_MAC_ETH);
  esp_eth_ioctl(s_eth_handle, ETH_CMD_S_MAC_ADDR, eth_mac);
  ESP_LOGI(TAG, "Ethernet MAC: %02X:%02X:%02X:%02X:%02X:%02X", eth_mac[0],
           eth_mac[1], eth_mac[2], eth_mac[3], eth_mac[4], eth_mac[5]);

  // Attach netif glue
  esp_eth_netif_glue_handle_t glue = esp_eth_new_netif_glue(s_eth_handle);
  ESP_ERROR_CHECK(esp_netif_attach(s_eth_netif, glue));

  // Start Ethernet
  ret = esp_eth_start(s_eth_handle);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Ethernet start failed: %s", esp_err_to_name(ret));
    return ret;
  }

  ESP_LOGI(TAG, "W5500 Ethernet initialized (CS=%d, INT=%d, RST=%d)",
           BOARD_ETH_CS_GPIO, BOARD_ETH_INT_GPIO, BOARD_ETH_RST_GPIO);
  return ESP_OK;
}

bool ethernet_is_connected(void) {
  return s_eth_connected;
}

bool ethernet_is_link_up(void) {
  return s_eth_link_up;
}

esp_err_t ethernet_get_ip_str(char *ip_str, size_t len) {
  if (!s_eth_netif || !ip_str || len == 0) {
    return ESP_ERR_INVALID_ARG;
  }
  esp_netif_ip_info_t ip_info;
  esp_err_t err = esp_netif_get_ip_info(s_eth_netif, &ip_info);
  if (err == ESP_OK) {
    snprintf(ip_str, len, IPSTR, IP2STR(&ip_info.ip));
  }
  return err;
}

void ethernet_get_mac_str(char *mac_str, size_t len) {
  if (!mac_str || len == 0) {
    return;
  }
  if (!s_eth_handle) {
    mac_str[0] = '\0';
    return;
  }
  uint8_t mac[6];
  if (esp_eth_ioctl(s_eth_handle, ETH_CMD_G_MAC_ADDR, mac) == ESP_OK) {
    snprintf(mac_str, len, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1],
             mac[2], mac[3], mac[4], mac[5]);
  } else {
    mac_str[0] = '\0';
  }
}

#endif // CONFIG_ETH_W5500_ENABLED

#pragma once

#include "esp_err.h"
#include "sdkconfig.h"
#include <stdbool.h>

#ifdef CONFIG_ETH_W5500_ENABLED

esp_err_t ethernet_init(void);
bool ethernet_is_connected(void);
bool ethernet_is_link_up(void);
esp_err_t ethernet_get_ip_str(char *ip_str, size_t len);
void ethernet_get_mac_str(char *mac_str, size_t len);

#else // !CONFIG_ETH_W5500_ENABLED

static inline esp_err_t ethernet_init(void) {
  return ESP_ERR_NOT_SUPPORTED;
}
static inline bool ethernet_is_connected(void) {
  return false;
}
static inline bool ethernet_is_link_up(void) {
  return false;
}
static inline esp_err_t ethernet_get_ip_str(char *ip_str, size_t len) {
  if (ip_str && len > 0)
    ip_str[0] = '\0';
  return ESP_ERR_NOT_SUPPORTED;
}
static inline void ethernet_get_mac_str(char *mac_str, size_t len) {
  if (mac_str && len > 0)
    mac_str[0] = '\0';
}

#endif // CONFIG_ETH_W5500_ENABLED

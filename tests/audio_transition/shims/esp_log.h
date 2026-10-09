#pragma once
#include <stdio.h>
#define HOST_LOG_NOOP(tag, ...) do { \
  (void)(tag); \
  if (0) fprintf(stderr, __VA_ARGS__); \
} while (0)
#define ESP_LOGI(...) HOST_LOG_NOOP(__VA_ARGS__)
#define ESP_LOGW(...) HOST_LOG_NOOP(__VA_ARGS__)
#define ESP_LOGE(...) HOST_LOG_NOOP(__VA_ARGS__)
#define ESP_LOGD(...) HOST_LOG_NOOP(__VA_ARGS__)

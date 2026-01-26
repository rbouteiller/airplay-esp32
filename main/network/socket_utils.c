#include "socket_utils.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "esp_log.h"

static const char *TAG = "sock_utils";

int socket_utils_bind_udp(uint16_t port, int recv_timeout_sec,
                          int recvbuf_size, uint16_t *bound_port) {
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) {
    ESP_LOGE(TAG, "Failed to create UDP socket");
    return -1;
  }

  if (recv_timeout_sec > 0) {
    struct timeval tv = {.tv_sec = recv_timeout_sec, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  }

  if (recvbuf_size > 0) {
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &recvbuf_size,
               sizeof(recvbuf_size));
  }

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);

  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    ESP_LOGE(TAG, "Failed to bind UDP socket to port %u: %d", port, errno);
    close(sock);
    return -1;
  }

  if (bound_port) {
    socklen_t addr_len = sizeof(addr);
    getsockname(sock, (struct sockaddr *)&addr, &addr_len);
    *bound_port = ntohs(addr.sin_port);
  }

  return sock;
}

int socket_utils_bind_tcp_listener(uint16_t port, int backlog,
                                   bool nonblocking, uint16_t *bound_port) {
  int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0) {
    ESP_LOGE(TAG, "Failed to create TCP socket");
    return -1;
  }

  int opt = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);

  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    ESP_LOGE(TAG, "Failed to bind TCP socket to port %u: %d", port, errno);
    close(sock);
    return -1;
  }

  if (listen(sock, backlog) < 0) {
    ESP_LOGE(TAG, "Failed to listen on TCP socket: %d", errno);
    close(sock);
    return -1;
  }

  if (nonblocking) {
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
  }

  if (bound_port) {
    socklen_t addr_len = sizeof(addr);
    getsockname(sock, (struct sockaddr *)&addr, &addr_len);
    *bound_port = ntohs(addr.sin_port);
  }

  return sock;
}

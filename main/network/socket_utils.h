#pragma once

#include <stdbool.h>
#include <stdint.h>

int socket_utils_bind_udp(uint16_t port, int recv_timeout_sec,
                          int recvbuf_size, uint16_t *bound_port);
int socket_utils_bind_tcp_listener(uint16_t port, int backlog,
                                   bool nonblocking, uint16_t *bound_port);

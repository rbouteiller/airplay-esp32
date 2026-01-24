#include "rtsp_message.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "esp_log.h"
#include "rtsp_crypto.h"

static const char *TAG = "rtsp_message";

const uint8_t *rtsp_find_header_end(const uint8_t *data, size_t len) {
    for (size_t i = 0; i + 3 < len; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' &&
            data[i + 3] == '\n') {
            return data + i;
        }
    }
    return NULL;
}

int rtsp_parse_cseq(const char *request) {
    const char *cseq = strstr(request, "CSeq:");
    if (cseq) {
        return atoi(cseq + 5);
    }
    return 1;
}

int rtsp_parse_content_length(const char *request) {
    const char *cl = strstr(request, "Content-Length:");
    if (!cl) {
        cl = strstr(request, "content-length:");
    }
    if (cl) {
        return atoi(cl + 15);
    }
    return 0;
}

const uint8_t *rtsp_get_body(const char *request, size_t request_len,
                              size_t *body_len) {
    const char *body = strstr(request, "\r\n\r\n");
    if (body) {
        body += 4;
        *body_len = request_len - (body - request);
        return (const uint8_t *)body;
    }
    *body_len = 0;
    return NULL;
}

int rtsp_request_parse(const uint8_t *data, size_t len, rtsp_request_t *req) {
    if (!data || !req || len == 0) {
        return -1;
    }

    memset(req, 0, sizeof(*req));

    // Find header end
    const uint8_t *header_end = rtsp_find_header_end(data, len);
    if (!header_end) {
        return -1;
    }

    // Parse first line: METHOD PATH PROTOCOL
    if (sscanf((const char *)data, "%31s %255s", req->method, req->path) < 1) {
        return -1;
    }

    // Parse CSeq
    req->cseq = rtsp_parse_cseq((const char *)data);

    // Parse Content-Length
    req->content_length = (size_t)rtsp_parse_content_length((const char *)data);

    // Parse Content-Type
    const char *ct = strstr((const char *)data, "Content-Type:");
    if (ct) {
        sscanf(ct, "Content-Type: %63s", req->content_type);
    }

    // Get body
    req->body = rtsp_get_body((const char *)data, len, &req->body_len);

    return 0;
}

// Internal: send all data, handling partial sends
static int send_all(int socket, const uint8_t *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int r = send(socket, data + sent, len - sent, 0);
        if (r <= 0) {
            return -1;
        }
        sent += (size_t)r;
    }
    return 0;
}

int rtsp_send_response(int socket, rtsp_conn_t *conn,
                       int status_code, const char *status_text,
                       int cseq, const char *extra_headers,
                       const char *body, size_t body_len) {
    char header[1024];
    int header_len;

    if (extra_headers && body && body_len > 0) {
        header_len =
            snprintf(header, sizeof(header),
                     "RTSP/1.0 %d %s\r\n"
                     "CSeq: %d\r\n"
                     "Server: AirTunes/377.40.00\r\n"
                     "%s"
                     "Content-Length: %zu\r\n"
                     "\r\n",
                     status_code, status_text, cseq, extra_headers, body_len);
    } else if (extra_headers) {
        header_len = snprintf(header, sizeof(header),
                              "RTSP/1.0 %d %s\r\n"
                              "CSeq: %d\r\n"
                              "Server: AirTunes/377.40.00\r\n"
                              "%s"
                              "\r\n",
                              status_code, status_text, cseq, extra_headers);
    } else if (body && body_len > 0) {
        header_len =
            snprintf(header, sizeof(header),
                     "RTSP/1.0 %d %s\r\n"
                     "CSeq: %d\r\n"
                     "Server: AirTunes/377.40.00\r\n"
                     "Content-Length: %zu\r\n"
                     "\r\n",
                     status_code, status_text, cseq, body_len);
    } else {
        header_len = snprintf(header, sizeof(header),
                              "RTSP/1.0 %d %s\r\n"
                              "CSeq: %d\r\n"
                              "Server: AirTunes/377.40.00\r\n"
                              "\r\n",
                              status_code, status_text, cseq);
    }

    // Build complete response
    size_t total_len = (size_t)header_len + body_len;
    uint8_t *response = malloc(total_len);
    if (!response) {
        ESP_LOGE(TAG, "Failed to allocate response buffer");
        return -1;
    }

    memcpy(response, header, (size_t)header_len);
    if (body && body_len > 0) {
        memcpy(response + header_len, body, body_len);
    }

    // Send encrypted or plain depending on mode
    int result;
    if (conn && conn->encrypted_mode) {
        result = rtsp_crypto_write_frame(socket, conn, response, total_len);
    } else {
        result = (send_all(socket, response, total_len) < 0) ? -1 : 0;
        if (result < 0) {
            ESP_LOGE(TAG, "Failed to send RTSP response");
        }
    }

    free(response);
    return result;
}

int rtsp_send_ok(int socket, rtsp_conn_t *conn, int cseq) {
    return rtsp_send_response(socket, conn, 200, "OK", cseq, NULL, NULL, 0);
}

int rtsp_send_http_response(int socket, rtsp_conn_t *conn,
                            int status_code, const char *status_text,
                            const char *content_type,
                            const char *body, size_t body_len) {
    char header[512];
    int header_len = snprintf(header, sizeof(header),
                              "HTTP/1.1 %d %s\r\n"
                              "Content-Type: %s\r\n"
                              "Content-Length: %zu\r\n"
                              "Server: AirTunes/377.40.00\r\n"
                              "CSeq: 1\r\n"
                              "\r\n",
                              status_code, status_text, content_type, body_len);

    // Build complete response
    size_t total_len = (size_t)header_len + body_len;
    uint8_t *response = malloc(total_len);
    if (!response) {
        ESP_LOGE(TAG, "Failed to allocate response buffer");
        return -1;
    }

    memcpy(response, header, (size_t)header_len);
    if (body && body_len > 0) {
        memcpy(response + header_len, body, body_len);
    }

    // Send encrypted or plain depending on mode
    int result;
    if (conn && conn->encrypted_mode) {
        result = rtsp_crypto_write_frame(socket, conn, response, total_len);
    } else {
        result = (send_all(socket, response, total_len) < 0) ? -1 : 0;
        if (result < 0) {
            ESP_LOGE(TAG, "Failed to send HTTP response");
        }
    }

    free(response);
    return result;
}

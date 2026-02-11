#include "softether_socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/tcp.h>
#include <android/log.h>

#define TAG "SoftEtherSocket"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

softether_socket_t* socket_create(int type) {
    softether_socket_t* sock = (softether_socket_t*)calloc(1, sizeof(softether_socket_t));
    if (sock == NULL) {
        LOGE("Failed to allocate socket structure");
        return NULL;
    }
    
    int socket_type = (type == SOCKET_TYPE_UDP) ? SOCK_DGRAM : SOCK_STREAM;
    sock->fd = socket(AF_INET, socket_type, 0);
    if (sock->fd < 0) {
        LOGE("Failed to create socket: %s", strerror(errno));
        free(sock);
        return NULL;
    }
    
    sock->type = type;
    sock->connected = 0;
    sock->timeout_ms = SOCKET_TIMEOUT_MS;
    
    // Set non-blocking mode initially
    int flags = fcntl(sock->fd, F_GETFL, 0);
    fcntl(sock->fd, F_SETFL, flags | O_NONBLOCK);
    
    LOGD("Socket created: fd=%d, type=%d", sock->fd, type);
    return sock;
}

void socket_destroy(softether_socket_t* sock) {
    if (sock == NULL) {
        return;
    }
    
    if (sock->fd >= 0) {
        close(sock->fd);
        LOGD("Socket closed: fd=%d", sock->fd);
    }
    
    free(sock);
}

int resolve_hostname(const char* hostname, char* ip_buffer, size_t buffer_size) {
    struct hostent* host = gethostbyname(hostname);
    if (host == NULL) {
        LOGE("Failed to resolve hostname: %s", hostname);
        return -1;
    }
    
    struct in_addr** addr_list = (struct in_addr**)host->h_addr_list;
    if (addr_list[0] == NULL) {
        LOGE("No addresses found for hostname: %s", hostname);
        return -1;
    }
    
    strncpy(ip_buffer, inet_ntoa(*addr_list[0]), buffer_size - 1);
    ip_buffer[buffer_size - 1] = '\0';
    
    LOGD("Resolved %s to %s", hostname, ip_buffer);
    return 0;
}

int socket_connect_timeout(softether_socket_t* sock, const char* host, int port, int timeout_ms) {
    if (sock == NULL || sock->fd < 0) {
        LOGE("Invalid socket");
        return -1;
    }
    
    char ip_str[64];
    if (resolve_hostname(host, ip_str, sizeof(ip_str)) != 0) {
        return -1;
    }
    
    memset(&sock->addr, 0, sizeof(sock->addr));
    sock->addr.sin_family = AF_INET;
    sock->addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip_str, &sock->addr.sin_addr) <= 0) {
        LOGE("Invalid address: %s", ip_str);
        return -1;
    }
    
    int result = connect(sock->fd, (struct sockaddr*)&sock->addr, sizeof(sock->addr));
    
    if (result < 0 && errno == EINPROGRESS) {
        // Connection in progress, wait for it
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock->fd, &fdset);
        
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        
        result = select(sock->fd + 1, NULL, &fdset, NULL, &tv);
        
        if (result < 0) {
            LOGE("Select failed: %s", strerror(errno));
            return -1;
        } else if (result == 0) {
            LOGE("Connection timeout");
            return -1;
        }
        
        // Check if connection succeeded
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        
        if (so_error != 0) {
            LOGE("Connection failed: %s", strerror(so_error));
            return -1;
        }
    } else if (result < 0) {
        LOGE("Connect failed: %s", strerror(errno));
        return -1;
    }
    
    // Set back to blocking mode
    int flags = fcntl(sock->fd, F_GETFL, 0);
    fcntl(sock->fd, F_SETFL, flags & ~O_NONBLOCK);
    
    sock->connected = 1;
    sock->timeout_ms = timeout_ms;
    
    LOGD("Connected to %s:%d", ip_str, port);
    return 0;
}

int socket_connect(softether_socket_t* sock, const char* host, int port) {
    return socket_connect_timeout(sock, host, port, SOCKET_TIMEOUT_MS);
}

int socket_disconnect(softether_socket_t* sock) {
    if (sock == NULL) {
        return -1;
    }
    
    if (sock->fd >= 0) {
        shutdown(sock->fd, SHUT_RDWR);
        close(sock->fd);
        sock->fd = -1;
    }
    
    sock->connected = 0;
    LOGD("Socket disconnected");
    return 0;
}

int socket_send_all(softether_socket_t* sock, const uint8_t* data, size_t len, int timeout_ms) {
    if (sock == NULL || !sock->connected) {
        LOGE("Socket not connected");
        return -1;
    }
    
    size_t total_sent = 0;
    
    while (total_sent < len) {
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock->fd, &fdset);
        
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        
        int result = select(sock->fd + 1, NULL, &fdset, NULL, &tv);
        if (result < 0) {
            LOGE("Select failed: %s", strerror(errno));
            return -1;
        } else if (result == 0) {
            LOGE("Send timeout");
            return -1;
        }
        
        ssize_t sent = send(sock->fd, data + total_sent, len - total_sent, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOGE("Send failed: %s", strerror(errno));
            return -1;
        }
        
        total_sent += sent;
    }
    
    return (int)total_sent;
}

int socket_send(softether_socket_t* sock, const uint8_t* data, size_t len) {
    return socket_send_all(sock, data, len, sock->timeout_ms);
}

int socket_recv_all(softether_socket_t* sock, uint8_t* buffer, size_t len, int timeout_ms) {
    if (sock == NULL || !sock->connected) {
        LOGE("Socket not connected");
        return -1;
    }
    
    size_t total_received = 0;
    
    while (total_received < len) {
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock->fd, &fdset);
        
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        
        int result = select(sock->fd + 1, &fdset, NULL, NULL, &tv);
        if (result < 0) {
            LOGE("Select failed: %s", strerror(errno));
            return -1;
        } else if (result == 0) {
            LOGE("Receive timeout");
            return -1;
        }
        
        ssize_t received = recv(sock->fd, buffer + total_received, len - total_received, 0);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOGE("Receive failed: %s", strerror(errno));
            return -1;
        } else if (received == 0) {
            LOGE("Connection closed by peer");
            return -1;
        }
        
        total_received += received;
    }
    
    return (int)total_received;
}

int socket_recv(softether_socket_t* sock, uint8_t* buffer, size_t max_len) {
    return socket_recv_all(sock, buffer, max_len, sock->timeout_ms);
}

int socket_set_timeout(softether_socket_t* sock, int timeout_ms) {
    if (sock == NULL) {
        return -1;
    }
    
    sock->timeout_ms = timeout_ms;
    
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    return 0;
}

int socket_set_nodelay(softether_socket_t* sock, int enable) {
    if (sock == NULL) {
        return -1;
    }
    
    return setsockopt(sock->fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));
}

int socket_set_keepalive(softether_socket_t* sock, int enable) {
    if (sock == NULL) {
        return -1;
    }
    
    return setsockopt(sock->fd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable));
}

int socket_is_connected(softether_socket_t* sock) {
    if (sock == NULL) {
        return 0;
    }
    return sock->connected;
}

int socket_get_error(softether_socket_t* sock) {
    if (sock == NULL || sock->fd < 0) {
        return EBADF;
    }
    
    int so_error;
    socklen_t len = sizeof(so_error);
    getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
    return so_error;
}

const char* socket_error_string(int error) {
    return strerror(error);
}

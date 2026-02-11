#ifndef SOFTETHER_SOCKET_H
#define SOFTETHER_SOCKET_H

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

// Socket types
#define SOCKET_TYPE_TCP     0
#define SOCKET_TYPE_UDP     1

// Socket timeout options
#define SOCKET_TIMEOUT_MS   30000

// Socket structure
typedef struct {
    int fd;
    int type;
    struct sockaddr_in addr;
    int connected;
    int timeout_ms;
} softether_socket_t;

// Function prototypes

// Socket creation and management
softether_socket_t* socket_create(int type);
void socket_destroy(softether_socket_t* sock);

// Connection
int socket_connect(softether_socket_t* sock, const char* host, int port);
int socket_connect_timeout(softether_socket_t* sock, const char* host, int port, int timeout_ms);
int socket_disconnect(softether_socket_t* sock);

// I/O operations
int socket_send(softether_socket_t* sock, const uint8_t* data, size_t len);
int socket_send_all(softether_socket_t* sock, const uint8_t* data, size_t len, int timeout_ms);
int socket_recv(softether_socket_t* sock, uint8_t* buffer, size_t max_len);
int socket_recv_all(softether_socket_t* sock, uint8_t* buffer, size_t len, int timeout_ms);

// Socket options
int socket_set_timeout(softether_socket_t* sock, int timeout_ms);
int socket_set_nodelay(softether_socket_t* sock, int enable);
int socket_set_keepalive(softether_socket_t* sock, int enable);

// Utility functions
int socket_is_connected(softether_socket_t* sock);
int socket_get_error(softether_socket_t* sock);
const char* socket_error_string(int error);

// Address resolution
int resolve_hostname(const char* hostname, char* ip_buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_SOCKET_H

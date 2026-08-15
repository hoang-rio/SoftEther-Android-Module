#ifndef SOFTETHER_RUDP_TRANSPORT_H
#define SOFTETHER_RUDP_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// RUDP transport client: implements SoftEther's R-UDP over UDP protocol
// (virtual TCP over UDP). Used to reach a server behind NAT/CGNAT after a
// NAT-T rendezvous. Only the segment path is implemented (V1 framing:
// SHA1 signature + RC4 stream encryption). The bulk V2 fast path is an
// UdpAccel-only optimization and is not used for a direct VPN connection.
//
// The transport owns a bound UDP socket plus an AF_UNIX SOCK_STREAM socket
// pair. One pair end is pumped by a background worker thread between the
// UDP socket and the other end, which is returned to the caller as a
// byte-stream fd. The caller treats that fd like an already-connected TCP
// socket (TLS handshake etc.).
//
// Ownership: the caller must close the fd returned by rudp_transport_get_fd()
// and then destroy the transport via rudp_transport_destroy().

#define RUDP_T_SHA1_SIZE            20

// Timing constants (mirror Mayaqua/Network.h)
#define RUDP_T_RESEND_TIMER         200
#define RUDP_T_RESEND_TIMER_MAX     4792
#define RUDP_T_KEEPALIVE_MIN        2500
#define RUDP_T_KEEPALIVE_MAX        4792
#define RUDP_T_TIMEOUT_MS           12000
#define RUDP_T_LOOP_WAIT_MS         100
#define RUDP_T_MAX_SEGMENT_SIZE     512
#define RUDP_T_MAX_NUM_ACK          64
#define RUDP_T_MAX_FIFO_SIZE        (512 * 1024)
#define RUDP_T_MAX_PACKET_SIZE      (RUDP_T_MAX_SEGMENT_SIZE + 8 * RUDP_T_MAX_NUM_ACK + \
                                     RUDP_T_SHA1_SIZE * 2 + 8 * 4 + 4 + 255)

// Error codes (mirror RUDP_ERROR_*)
#define RUDP_T_ERR_OK               0
#define RUDP_T_ERR_UNKNOWN          1
#define RUDP_T_ERR_TIMEOUT          2

typedef struct rudp_transport rudp_transport_t;

typedef struct {
    uint32_t server_ip;          // network byte order
    uint16_t server_port;        // host byte order
    int udp_fd;                  // bound UDP socket to reuse (from nat_t), or -1
    uint32_t connect_timeout_ms; // 0 => RUDP_T_TIMEOUT_MS
} rudp_transport_config_t;

// Create an empty transport object.
rudp_transport_t* rudp_transport_create(void);

// Destroy the transport. Joins the worker thread, closes the UDP socket and
// both socket-pair ends. The caller must have closed the app-facing fd first.
void rudp_transport_destroy(rudp_transport_t* t);

// Connect over RUDP. Blocks until the session is established (first valid
// segment received from the server) or fails. Returns 0 on success.
// On success the app-facing fd is available via rudp_transport_get_fd().
int rudp_transport_connect(rudp_transport_t* t, const rudp_transport_config_t* cfg);

// App-facing byte-stream fd (valid after a successful connect). -1 otherwise.
int rudp_transport_get_fd(rudp_transport_t* t);

// UDP socket used by the transport session (valid after connect returns 0,
// and during the whole established session). -1 otherwise. The caller must
// VpnService.protect() this fd so the RUDP/NAT-T traffic bypasses the TUN.
int rudp_transport_get_udp_fd(rudp_transport_t* t);

// Last error code (RUDP_T_ERR_*).
int rudp_transport_get_error(rudp_transport_t* t);

// Ask the transport to shut down. Signals the worker to send the graceful
// disconnect segments (if the session is established), then stops it.
void rudp_transport_disconnect(rudp_transport_t* t);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_RUDP_TRANSPORT_H

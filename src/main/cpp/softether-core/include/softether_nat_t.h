#ifndef SOFTETHER_NAT_T_H
#define SOFTETHER_NAT_T_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// NAT-T (UDP hole punching via SoftEther's global relay) constants.
#define NAT_T_PORT               5004
#define NAT_T_SVC_NAME           "SoftEther_VPN"
#define NAT_T_TRAVERSAL_VERSION  1
#define NAT_T_DEFAULT_TIMEOUT_MS 12000
#define NAT_T_CONNECT_INTERVAL   200
#define NAT_T_MAX_BACKOFF_EXP    6   // mirrors MAX(num_tries, 6) in upstream

// NAT-T result/error codes (mirror RUDP_ERROR_* from Mayaqua/Network.h)
#define NAT_T_ERR_OK              0   // Success
#define NAT_T_ERR_UNKNOWN         1   // Unknown error
#define NAT_T_ERR_TIMEOUT         2   // Time-out
#define NAT_T_ERR_GETIP_FAILED    3   // Could not resolve the relay hostname
#define NAT_T_ERR_NO_RESPONSE     4   // No response from the NAT-T server
#define NAT_T_ERR_TWO_OR_MORE     5   // Two or more hosts behind the destination IP
#define NAT_T_ERR_NOT_FOUND       6   // Host does not exist at the destination IP

typedef struct {
    uint32_t result_ip;     // Public UDP address of the target (network byte order)
    uint16_t result_port;   // Public UDP port of the target (host byte order)
    int same_lan;           // 1 if the server reported same-LAN direct mode
    int udp_fd;             // Bound UDP socket to reuse for the RUDP session
                            // (-1 when same_lan: caller must create a fresh one)
    int error_code;         // NAT_T_ERR_* on failure
} softether_nat_t_result_t;

// Derive the NAT-T relay hostname for a target IPv4 address.
// server_ip_net: target IP in network byte order (sin_addr.s_addr).
// dst must hold at least 96 bytes.
int nat_t_build_hostname(uint32_t server_ip_net, char* dst, size_t dst_size);

// Perform NAT-T rendezvous with the SoftEther relay to learn the server's
// public UDP address. On success returns 0 and fills result (result->udp_fd
// is a valid, bound UDP socket unless same_lan is set). On failure returns
// -1 and sets result->error_code.
int nat_t_connect(uint32_t server_ip_net, const char* svc_name,
                  uint32_t timeout_ms, softether_nat_t_result_t* result);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_NAT_T_H

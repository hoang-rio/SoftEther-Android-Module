/*
 * Minimal DHCP Client for SoftEther VPN L2 tunnel
 *
 * Sends DHCP DISCOVER/REQUEST and parses OFFER/ACK to obtain IP configuration
 * from the SoftEther virtual hub's SecureNAT DHCP server.
 *
 * All frames are sent/received as Ethernet frames through the SoftEther data channel.
 */
#include "softether_protocol.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <android/log.h>

#define TAG "SoftEtherDHCP"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Ethernet
#define ETH_HLEN        14
#define ETH_P_IP        0x0800

// IP
#define IP_HLEN         20
#define IP_PROTO_UDP    17

// UDP
#define UDP_HLEN        8

// DHCP
#define DHCP_BOOTREQUEST    1
#define DHCP_BOOTREPLY      2
#define DHCP_HTYPE_ETH      1
#define DHCP_HLEN_ETH       6
#define DHCP_MAGIC_COOKIE   0x63825363
#define DHCP_MIN_LEN        236

// DHCP message types (option 53)
#define DHCP_DISCOVER   1
#define DHCP_OFFER      2
#define DHCP_REQUEST    3
#define DHCP_ACK        5
#define DHCP_NAK        6

// DHCP options
#define OPT_SUBNET_MASK     1
#define OPT_ROUTER          3
#define OPT_DNS_SERVER      6
#define OPT_REQUESTED_IP    50
#define OPT_LEASE_TIME      51
#define OPT_MSG_TYPE        53
#define OPT_SERVER_ID       54
#define OPT_PARAM_REQUEST   55
#define OPT_END             255

#define DHCP_MAX_FRAME      600
#define DHCP_TIMEOUT_MS     5000
#define DHCP_MAX_RETRIES    3

static uint16_t ip_checksum(const void* data, int len) {
    const uint16_t* ptr = (const uint16_t*)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(const uint8_t*)ptr;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

// Build a DHCP frame (Ethernet + IP + UDP + DHCP)
static int build_dhcp_frame(uint8_t* frame, size_t max_len,
                            const uint8_t* src_mac,
                            uint32_t xid,
                            uint8_t msg_type,
                            uint32_t requested_ip,
                            uint32_t server_id) {
    memset(frame, 0, max_len > DHCP_MAX_FRAME ? DHCP_MAX_FRAME : max_len);

    // Build DHCP payload
    uint8_t dhcp[308];
    memset(dhcp, 0, sizeof(dhcp));
    int pos = 0;

    dhcp[pos++] = DHCP_BOOTREQUEST;
    dhcp[pos++] = DHCP_HTYPE_ETH;
    dhcp[pos++] = DHCP_HLEN_ETH;
    dhcp[pos++] = 0;  // hops

    dhcp[pos++] = (xid >> 24) & 0xFF;
    dhcp[pos++] = (xid >> 16) & 0xFF;
    dhcp[pos++] = (xid >> 8) & 0xFF;
    dhcp[pos++] = xid & 0xFF;

    // secs = 0, flags = 0x8000 (broadcast)
    dhcp[pos++] = 0; dhcp[pos++] = 0;
    dhcp[pos++] = 0x80; dhcp[pos++] = 0x00;

    // ciaddr/yiaddr/siaddr/giaddr = 0
    pos = 28;
    memcpy(dhcp + pos, src_mac, 6);
    pos = 236;

    // Magic cookie
    dhcp[pos++] = 0x63; dhcp[pos++] = 0x82;
    dhcp[pos++] = 0x53; dhcp[pos++] = 0x63;

    // Option 53: DHCP Message Type
    dhcp[pos++] = OPT_MSG_TYPE;
    dhcp[pos++] = 1;
    dhcp[pos++] = msg_type;

    if (msg_type == DHCP_REQUEST) {
        if (requested_ip != 0) {
            dhcp[pos++] = OPT_REQUESTED_IP;
            dhcp[pos++] = 4;
            dhcp[pos++] = (requested_ip >> 24) & 0xFF;
            dhcp[pos++] = (requested_ip >> 16) & 0xFF;
            dhcp[pos++] = (requested_ip >> 8) & 0xFF;
            dhcp[pos++] = requested_ip & 0xFF;
        }
        if (server_id != 0) {
            dhcp[pos++] = OPT_SERVER_ID;
            dhcp[pos++] = 4;
            dhcp[pos++] = (server_id >> 24) & 0xFF;
            dhcp[pos++] = (server_id >> 16) & 0xFF;
            dhcp[pos++] = (server_id >> 8) & 0xFF;
            dhcp[pos++] = server_id & 0xFF;
        }
    }

    // Option 55: Parameter Request List
    dhcp[pos++] = OPT_PARAM_REQUEST;
    dhcp[pos++] = 4;
    dhcp[pos++] = OPT_SUBNET_MASK;
    dhcp[pos++] = OPT_ROUTER;
    dhcp[pos++] = OPT_DNS_SERVER;
    dhcp[pos++] = OPT_LEASE_TIME;

    dhcp[pos++] = OPT_END;
    int dhcp_len = pos;

    // Build UDP
    int udp_len = UDP_HLEN + dhcp_len;
    uint8_t udp[8];
    udp[0] = 0; udp[1] = 68;   // src port 68
    udp[2] = 0; udp[3] = 67;   // dst port 67
    udp[4] = (udp_len >> 8) & 0xFF;
    udp[5] = udp_len & 0xFF;
    udp[6] = 0; udp[7] = 0;    // checksum 0

    // Build IP
    int ip_total_len = IP_HLEN + udp_len;
    uint8_t ip[20];
    memset(ip, 0, sizeof(ip));
    ip[0] = 0x45;
    ip[2] = (ip_total_len >> 8) & 0xFF;
    ip[3] = ip_total_len & 0xFF;
    ip[4] = (uint8_t)(rand() & 0xFF);
    ip[5] = (uint8_t)(rand() & 0xFF);
    ip[8] = 128;               // TTL
    ip[9] = IP_PROTO_UDP;
    // src = 0.0.0.0, dst = 255.255.255.255
    ip[16] = 255; ip[17] = 255; ip[18] = 255; ip[19] = 255;
    uint16_t cksum = ip_checksum(ip, 20);
    memcpy(ip + 10, &cksum, 2);  // Store in native byte order (matches ip_checksum computation)

    // Build Ethernet
    int total_len = ETH_HLEN + ip_total_len;
    if ((size_t)total_len > max_len) return -1;

    memset(frame, 0xFF, 6);           // dst = broadcast
    memcpy(frame + 6, src_mac, 6);    // src = client MAC
    frame[12] = (ETH_P_IP >> 8) & 0xFF;
    frame[13] = ETH_P_IP & 0xFF;

    memcpy(frame + ETH_HLEN, ip, IP_HLEN);
    memcpy(frame + ETH_HLEN + IP_HLEN, udp, UDP_HLEN);
    memcpy(frame + ETH_HLEN + IP_HLEN + UDP_HLEN, dhcp, dhcp_len);

    return total_len;
}

// Parse a DHCP response from an Ethernet frame
static int parse_dhcp_response(const uint8_t* frame, uint32_t frame_len,
                               uint32_t expected_xid,
                               const uint8_t* client_mac,
                               dhcp_result_t* result,
                               uint32_t* server_id_out) {
    if (frame_len < ETH_HLEN + IP_HLEN + UDP_HLEN + DHCP_MIN_LEN + 4)
        return 0;

    uint16_t ethertype = ((uint16_t)frame[12] << 8) | frame[13];
    if (ethertype != ETH_P_IP) return 0;

    const uint8_t* ip = frame + ETH_HLEN;
    if ((ip[0] >> 4) != 4) return 0;
    if (ip[9] != IP_PROTO_UDP) return 0;

    int ip_hlen = (ip[0] & 0x0F) * 4;
    const uint8_t* udp = ip + ip_hlen;
    uint16_t src_port = ((uint16_t)udp[0] << 8) | udp[1];
    uint16_t dst_port = ((uint16_t)udp[2] << 8) | udp[3];
    if (src_port != 67 || dst_port != 68) return 0;

    const uint8_t* dhcp = udp + UDP_HLEN;
    uint32_t dhcp_len = frame_len - ETH_HLEN - ip_hlen - UDP_HLEN;
    if (dhcp_len < DHCP_MIN_LEN + 4) return 0;

    if (dhcp[0] != DHCP_BOOTREPLY) return 0;

    uint32_t xid = ((uint32_t)dhcp[4] << 24) | ((uint32_t)dhcp[5] << 16) |
                   ((uint32_t)dhcp[6] << 8) | dhcp[7];
    if (xid != expected_xid) return 0;

    if (memcmp(dhcp + 28, client_mac, 6) != 0) return 0;

    // yiaddr
    result->assigned_ip = ((uint32_t)dhcp[16] << 24) | ((uint32_t)dhcp[17] << 16) |
                          ((uint32_t)dhcp[18] << 8) | dhcp[19];

    // Magic cookie
    uint32_t magic = ((uint32_t)dhcp[236] << 24) | ((uint32_t)dhcp[237] << 16) |
                     ((uint32_t)dhcp[238] << 8) | dhcp[239];
    if (magic != DHCP_MAGIC_COOKIE) return 0;

    // Parse options
    int msg_type = 0;
    uint32_t opt_pos = 240;
    while (opt_pos < dhcp_len) {
        uint8_t opt = dhcp[opt_pos++];
        if (opt == OPT_END) break;
        if (opt == 0) continue;
        if (opt_pos >= dhcp_len) break;
        uint8_t opt_len = dhcp[opt_pos++];
        if (opt_pos + opt_len > dhcp_len) break;

        switch (opt) {
            case OPT_MSG_TYPE:
                if (opt_len >= 1) msg_type = dhcp[opt_pos];
                break;
            case OPT_SUBNET_MASK:
                if (opt_len >= 4)
                    result->subnet_mask = ((uint32_t)dhcp[opt_pos] << 24) | ((uint32_t)dhcp[opt_pos+1] << 16) |
                                          ((uint32_t)dhcp[opt_pos+2] << 8) | dhcp[opt_pos+3];
                break;
            case OPT_ROUTER:
                if (opt_len >= 4)
                    result->gateway = ((uint32_t)dhcp[opt_pos] << 24) | ((uint32_t)dhcp[opt_pos+1] << 16) |
                                      ((uint32_t)dhcp[opt_pos+2] << 8) | dhcp[opt_pos+3];
                break;
            case OPT_DNS_SERVER:
                if (opt_len >= 4)
                    result->dns_server = ((uint32_t)dhcp[opt_pos] << 24) | ((uint32_t)dhcp[opt_pos+1] << 16) |
                                         ((uint32_t)dhcp[opt_pos+2] << 8) | dhcp[opt_pos+3];
                if (opt_len >= 8)
                    result->dns_server2 = ((uint32_t)dhcp[opt_pos+4] << 24) | ((uint32_t)dhcp[opt_pos+5] << 16) |
                                          ((uint32_t)dhcp[opt_pos+6] << 8) | dhcp[opt_pos+7];
                break;
            case OPT_LEASE_TIME:
                if (opt_len >= 4)
                    result->lease_time = ((uint32_t)dhcp[opt_pos] << 24) | ((uint32_t)dhcp[opt_pos+1] << 16) |
                                         ((uint32_t)dhcp[opt_pos+2] << 8) | dhcp[opt_pos+3];
                break;
            case OPT_SERVER_ID:
                if (opt_len >= 4 && server_id_out)
                    *server_id_out = ((uint32_t)dhcp[opt_pos] << 24) | ((uint32_t)dhcp[opt_pos+1] << 16) |
                                     ((uint32_t)dhcp[opt_pos+2] << 8) | dhcp[opt_pos+3];
                break;
        }
        opt_pos += opt_len;
    }

    return msg_type;
}

// Wait for a DHCP response with timeout
static int wait_dhcp_response(softether_connection_t* conn,
                              uint32_t xid,
                              dhcp_result_t* result,
                              uint32_t* server_id,
                              int timeout_ms) {
    uint8_t frame[2048];
    int elapsed = 0;
    int poll_interval = 100;

    while (elapsed < timeout_ms) {
        // Check receive queue first (may have frames from multi-block message)
        int has_queued = (conn->recv_queue_count > 0);

        if (!has_queued && conn->socket_fd >= 0) {
            struct pollfd pfds[2 + MAX_SE_CONNECTIONS];
            nfds_t nfds = 0;

            // Primary socket — only poll if it can receive (BOTH or S2C)
            if (conn->primary_direction == TCP_DIRECTION_BOTH ||
                conn->primary_direction == TCP_DIRECTION_SERVER_TO_CLIENT) {
                pfds[nfds].fd = conn->socket_fd;
                pfds[nfds].events = POLLIN;
                pfds[nfds].revents = 0;
                nfds++;
            }

            // Additional sockets — poll if they can receive
            for (int i = 0; i < MAX_SE_CONNECTIONS; i++) {
                softether_tcp_sock_t* ts = &conn->additional[i];
                if (!ts->active || ts->socket_fd < 0) continue;
                int d = ts->direction;
                if (d != TCP_DIRECTION_BOTH && d != TCP_DIRECTION_SERVER_TO_CLIENT) continue;
                pfds[nfds].fd = ts->socket_fd;
                pfds[nfds].events = POLLIN;
                pfds[nfds].revents = 0;
                nfds++;
            }

            // Also poll UDP socket when RUDP is active
            int udp_fd = -1;
            if (conn->rudp && conn->rudp_enabled) {
                udp_fd = rudp_get_udp_fd(conn->rudp);
                if (udp_fd >= 0) {
                    pfds[nfds].fd = udp_fd;
                    pfds[nfds].events = POLLIN;
                    pfds[nfds].revents = 0;
                    nfds++;
                }
            }

            if (nfds == 0) {
                // No receive-capable socket available, just wait
                usleep(poll_interval * 1000);
                elapsed += poll_interval;
                continue;
            }

            int poll_result = poll(pfds, nfds, poll_interval);
            if (poll_result < 0) return -1;
            if (poll_result == 0) {
                elapsed += poll_interval;
                continue;
            }
        }

        uint32_t frame_len = 0;
        int ret = softether_receive_raw(conn, frame, sizeof(frame), &frame_len);
        if (ret < 0) return -1;
        if (frame_len == 0) {
            elapsed += poll_interval;
            continue;
        }

        int msg_type = parse_dhcp_response(frame, frame_len, xid,
                                           conn->client_mac, result, server_id);
        if (msg_type > 0) return msg_type;
    }

    return 0;
}

// Full DHCP exchange over SoftEther tunnel
int softether_do_dhcp(softether_connection_t* conn, dhcp_result_t* result) {
    if (conn == NULL || result == NULL) return -1;
    if (conn->state != STATE_CONNECTED) {
        LOGE("Cannot do DHCP: not connected");
        return -1;
    }

    memset(result, 0, sizeof(dhcp_result_t));
    uint32_t xid = ((uint32_t)rand() << 16) ^ (uint32_t)rand();
    uint32_t server_id = 0;

    LOGD("Starting DHCP (xid=0x%08X, MAC=%02X:%02X:%02X:%02X:%02X:%02X)",
         xid, conn->client_mac[0], conn->client_mac[1], conn->client_mac[2],
         conn->client_mac[3], conn->client_mac[4], conn->client_mac[5]);

    for (int retry = 0; retry < DHCP_MAX_RETRIES; retry++) {
        uint8_t frame[DHCP_MAX_FRAME];
        int frame_len = build_dhcp_frame(frame, sizeof(frame), conn->client_mac,
                                          xid, DHCP_DISCOVER, 0, 0);
        if (frame_len < 0) {
            LOGE("Failed to build DHCP DISCOVER");
            return -1;
        }

        LOGD("Sending DHCP DISCOVER (attempt %d/%d)", retry + 1, DHCP_MAX_RETRIES);
        if (softether_send_raw(conn, frame, frame_len) < 0) {
            LOGE("Failed to send DHCP DISCOVER");
            return -1;
        }

        int msg_type = wait_dhcp_response(conn, xid, result, &server_id, DHCP_TIMEOUT_MS);
        if (msg_type < 0) return -1;
        if (msg_type != DHCP_OFFER) {
            LOGD("No DHCP OFFER received (type=%d), retrying...", msg_type);
            continue;
        }

        LOGD("DHCP OFFER: IP=%u.%u.%u.%u",
             (result->assigned_ip >> 24) & 0xFF, (result->assigned_ip >> 16) & 0xFF,
             (result->assigned_ip >> 8) & 0xFF, result->assigned_ip & 0xFF);

        frame_len = build_dhcp_frame(frame, sizeof(frame), conn->client_mac,
                                      xid, DHCP_REQUEST, result->assigned_ip, server_id);
        if (frame_len < 0) return -1;

        LOGD("Sending DHCP REQUEST");
        if (softether_send_raw(conn, frame, frame_len) < 0) return -1;

        msg_type = wait_dhcp_response(conn, xid, result, &server_id, DHCP_TIMEOUT_MS);
        if (msg_type < 0) return -1;
        if (msg_type == DHCP_ACK) {
            result->success = 1;
            LOGD("DHCP SUCCESS: IP=%u.%u.%u.%u mask=%u.%u.%u.%u gw=%u.%u.%u.%u dns=%u.%u.%u.%u",
                 (result->assigned_ip >> 24) & 0xFF, (result->assigned_ip >> 16) & 0xFF,
                 (result->assigned_ip >> 8) & 0xFF, result->assigned_ip & 0xFF,
                 (result->subnet_mask >> 24) & 0xFF, (result->subnet_mask >> 16) & 0xFF,
                 (result->subnet_mask >> 8) & 0xFF, result->subnet_mask & 0xFF,
                 (result->gateway >> 24) & 0xFF, (result->gateway >> 16) & 0xFF,
                 (result->gateway >> 8) & 0xFF, result->gateway & 0xFF,
                 (result->dns_server >> 24) & 0xFF, (result->dns_server >> 16) & 0xFF,
                 (result->dns_server >> 8) & 0xFF, result->dns_server & 0xFF);
            return 0;
        }
        if (msg_type == DHCP_NAK) {
            LOGE("DHCP NAK received");
            return -1;
        }
        LOGD("No DHCP ACK (type=%d), retrying...", msg_type);
    }

    LOGE("DHCP failed after %d retries", DHCP_MAX_RETRIES);
    return -1;
}

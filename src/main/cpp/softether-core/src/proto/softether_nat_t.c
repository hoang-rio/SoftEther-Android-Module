#include "softether_nat_t.h"
#include "softether_pack.h"
#include "softether_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <android/log.h>

#define TAG "SoftEtherNatT"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

#define NAT_T_RESP_BUF_SIZE 4096
#define NAT_T_HOSTNAME_MAX  96

static uint64_t nat_t_tick_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void nat_t_ip_to_str(uint32_t ip_net, char* dst, size_t dst_size) {
    struct in_addr a;
    a.s_addr = ip_net;
    if (inet_ntop(AF_INET, &a, dst, (socklen_t)dst_size) == NULL) {
        if (dst_size > 0) {
            dst[0] = '\0';
        }
    }
}

int nat_t_build_hostname(uint32_t server_ip_net, char* dst, size_t dst_size) {
    if (dst == NULL || dst_size < NAT_T_HOSTNAME_MAX) {
        return -1;
    }

    uint8_t ip_be[4];
    memcpy(ip_be, &server_ip_net, sizeof(ip_be));

    uint8_t hash[20];
    sha1_hash(ip_be, sizeof(ip_be), hash);

    // BinToStr(hash, 2) -> 4 uppercase hex chars, then StrLower.
    static const char* hex = "0123456789abcdef";
    char tmp[8];
    tmp[0] = hex[(hash[0] >> 4) & 0xF];
    tmp[1] = hex[hash[0] & 0xF];
    tmp[2] = hex[(hash[1] >> 4) & 0xF];
    tmp[3] = hex[hash[1] & 0xF];
    tmp[4] = '\0';

    snprintf(dst, dst_size, "x%c.x%c.servers.nat-traversal.softether-network.net.",
             tmp[2], tmp[3]);
    return 0;
}

// Resolve the relay hostname to a single IPv4 address (first A record).
static int nat_t_resolve_relay(const char* hostname, uint32_t* out_ip) {
    struct addrinfo hints;
    struct addrinfo* res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int rc = getaddrinfo(hostname, NULL, &hints, &res);
    if (rc != 0 || res == NULL) {
        LOGE("nat_t: failed to resolve relay %s (%s)", hostname, gai_strerror(rc));
        return -1;
    }

    struct addrinfo* ai = res;
    while (ai != NULL && ai->ai_family != AF_INET) {
        ai = ai->ai_next;
    }
    if (ai == NULL) {
        LOGE("nat_t: relay %s has no IPv4 address", hostname);
        freeaddrinfo(res);
        return -1;
    }

    *out_ip = ((struct sockaddr_in*)ai->ai_addr)->sin_addr.s_addr;
    char ip_str[INET_ADDRSTRLEN];
    nat_t_ip_to_str(*out_ip, ip_str, sizeof(ip_str));
    LOGD("nat_t: relay %s resolved to %s", hostname, ip_str);
    freeaddrinfo(res);
    return 0;
}

static int nat_t_create_udp_socket(int* out_fd) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOGE("nat_t: socket failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = 0;
    if (bind(fd, (struct sockaddr*)&local, sizeof(local)) != 0) {
        LOGE("nat_t: bind failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    *out_fd = fd;
    return 0;
}

// Parse a relay response. Returns:
//   1  -> success (result filled in)
//   0  -> ignore (no match / not for us)
//  -1  -> definite error (result->error_code set)
static int nat_t_parse_response(const uint8_t* buf, uint32_t len, uint64_t tran_id,
                                uint64_t* current_cookie, softether_nat_t_result_t* result) {
    uint64_t cookie = 0;
    if (pack_get_int64(buf, len, "cookie", &cookie) == 0 && cookie != 0) {
        *current_cookie = cookie;
    }

    uint64_t resp_tran_id = 0;
    if (pack_get_int64(buf, len, "tran_id", &resp_tran_id) != 0 ||
        resp_tran_id != tran_id) {
        return 0;  // not our transaction
    }

    char opcode[64] = {0};
    if (pack_get_str(buf, len, "opcode", opcode, sizeof(opcode)) != 0 ||
        strcmp(opcode, "nat_t_connect_request") != 0) {
        return 0;  // unexpected opcode
    }

    uint32_t ok = 0;
    pack_get_int(buf, len, "ok", &ok);
    if (ok != 0) {
        uint32_t multi_candidates = 0;
        pack_get_int(buf, len, "multi_candidates", &multi_candidates);
        if (multi_candidates != 0) {
            result->error_code = NAT_T_ERR_TWO_OR_MORE;
            return -1;
        }

        char result_ip_str[INET_ADDRSTRLEN] = {0};
        if (pack_get_str(buf, len, "result_ip", result_ip_str,
                         sizeof(result_ip_str)) != 0) {
            return 0;
        }

        uint32_t result_port = 0;
        if (pack_get_int(buf, len, "result_port", &result_port) != 0 ||
            result_port == 0 || result_port > 65535) {
            return 0;
        }

        struct in_addr a;
        if (inet_pton(AF_INET, result_ip_str, &a) != 1 ||
            a.s_addr == htonl(INADDR_ANY)) {
            return 0;
        }

        result->result_ip = a.s_addr;
        result->result_port = (uint16_t)result_port;
        result->same_lan = 0;
        pack_get_int(buf, len, "same_lan", (uint32_t*)&result->same_lan);
        result->error_code = NAT_T_ERR_OK;
        LOGD("nat_t: rendezvous ok: ip=%s port=%u same_lan=%d",
             result_ip_str, result_port, result->same_lan);
        return 1;
    }

    uint32_t multi_candidates = 0;
    pack_get_int(buf, len, "multi_candidates", &multi_candidates);
    result->error_code = (multi_candidates != 0) ? NAT_T_ERR_TWO_OR_MORE
                                                 : NAT_T_ERR_NOT_FOUND;
    return -1;
}

int nat_t_connect(uint32_t server_ip_net, const char* svc_name,
                  uint32_t timeout_ms, softether_nat_t_result_t* result) {
    if (result == NULL) {
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->udp_fd = -1;
    result->error_code = NAT_T_ERR_UNKNOWN;

    if (timeout_ms == 0) {
        timeout_ms = NAT_T_DEFAULT_TIMEOUT_MS;
    }
    if (svc_name == NULL || svc_name[0] == '\0') {
        svc_name = NAT_T_SVC_NAME;
    }

    char relay_hostname[NAT_T_HOSTNAME_MAX];
    if (nat_t_build_hostname(server_ip_net, relay_hostname, sizeof(relay_hostname)) != 0) {
        LOGE("nat_t: failed to build relay hostname");
        return -1;
    }

    uint32_t relay_ip = 0;
    if (nat_t_resolve_relay(relay_hostname, &relay_ip) != 0) {
        result->error_code = NAT_T_ERR_GETIP_FAILED;
        return -1;
    }

    int fd = -1;
    if (nat_t_create_udp_socket(&fd) != 0) {
        return -1;
    }

    char dest_ip_str[INET_ADDRSTRLEN];
    nat_t_ip_to_str(server_ip_net, dest_ip_str, sizeof(dest_ip_str));

    uint64_t tran_id = 0;
    {
        uint8_t rnd[8];
        generate_random_bytes(rnd, sizeof(rnd));
        for (int i = 0; i < 8; i++) {
            tran_id = (tran_id << 8) | rnd[i];
        }
        if (tran_id == 0) {
            tran_id = 0x9E3779B97F4A7C15ULL;  // unlikely, but avoid 0
        }
    }

    struct sockaddr_in relay_addr;
    memset(&relay_addr, 0, sizeof(relay_addr));
    relay_addr.sin_family = AF_INET;
    relay_addr.sin_addr.s_addr = relay_ip;
    relay_addr.sin_port = htons(NAT_T_PORT);

    uint64_t giveup_tick = nat_t_tick_ms() + timeout_ms;
    uint64_t next_send_tick = 0;  // send immediately on first iteration
    uint64_t current_cookie = 0;
    int num_tries = 0;
    int fd_valid = 1;

    while (1) {
        uint64_t now = nat_t_tick_ms();
        if (now >= giveup_tick) {
            result->error_code = NAT_T_ERR_NO_RESPONSE;
            break;
        }

        // Drain any pending response packets.
        int have_pending = 1;
        while (have_pending) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            struct timeval tv = {0, 0};
            int s = select(fd + 1, &rfds, NULL, NULL, &tv);
            if (s <= 0) {
                have_pending = 0;
                break;
            }

            uint8_t buf[NAT_T_RESP_BUF_SIZE];
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);
            ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                                 (struct sockaddr*)&from, &from_len);
            if (n <= 0) {
                have_pending = 0;
                break;
            }

            // Only accept packets from the relay's IP:port.
            if (from.sin_family != AF_INET ||
                from.sin_addr.s_addr != relay_ip ||
                ntohs(from.sin_port) != NAT_T_PORT) {
                continue;
            }

            int st = nat_t_parse_response(buf, (uint32_t)n, tran_id,
                                          &current_cookie, result);
            if (st == 1) {
                result->udp_fd = (result->same_lan) ? -1 : fd;
                if (result->same_lan) {
                    close(fd);
                    fd_valid = 0;
                }
                return 0;
            } else if (st < 0) {
                close(fd);
                fd_valid = 0;
                return -1;
            }
        }

        // Send (or resend) the connect request when due.
        if (next_send_tick == 0 || now >= next_send_tick) {
            char ip_str[INET_ADDRSTRLEN];
            nat_t_ip_to_str(server_ip_net, ip_str, sizeof(ip_str));

            softether_pack_t* p = pack_new();
            if (p != NULL) {
                pack_add_str(p, "opcode", "nat_t_connect_request");
                pack_add_int64(p, "tran_id", tran_id);
                pack_add_str(p, "dest_ip", ip_str);
                pack_add_int64(p, "cookie", current_cookie);
                pack_add_str(p, "svc_name", svc_name);
                pack_add_int(p, "nat_traversal_version", NAT_T_TRAVERSAL_VERSION);

                ssize_t sent = sendto(fd, pack_data(p), pack_length(p), 0,
                                      (struct sockaddr*)&relay_addr,
                                      sizeof(relay_addr));
                if (sent < 0) {
                    LOGE("nat_t: sendto failed: %s", strerror(errno));
                }
                pack_free(p);
            }

            uint32_t exp = (num_tries < NAT_T_MAX_BACKOFF_EXP)
                               ? NAT_T_MAX_BACKOFF_EXP
                               : (uint32_t)num_tries;
            uint64_t interval = (uint64_t)NAT_T_CONNECT_INTERVAL * (1ULL << exp);
            next_send_tick = now + interval;
            num_tries++;
        }

        // Wait up to 50 ms before re-checking (mirrors upstream loop).
        uint64_t wait_ms = 50;
        if (next_send_tick > now) {
            uint64_t d = next_send_tick - now;
            if (d < wait_ms) {
                wait_ms = d;
            }
        }
        struct timeval tv;
        tv.tv_sec = (time_t)(wait_ms / 1000);
        tv.tv_usec = (suseconds_t)((wait_ms % 1000) * 1000);
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        select(fd + 1, &rfds, NULL, NULL, &tv);
    }

    if (fd_valid && fd >= 0) {
        close(fd);
    }
    return -1;
}

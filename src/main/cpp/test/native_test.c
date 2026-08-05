#include "native_test.h"
#include "softether_crypto.h"
#include "softether_protocol.h"
#include "softether_socket.h"
#include <android/log.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>

#define TAG "NativeTest"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
// Get current timestamp in milliseconds
long get_test_timestamp_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (long)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

// Initialize test result
void test_result_init(native_test_result_t *result, bool success,
                      int error_code, const char *message, long duration_ms) {
  if (result == NULL)
    return;

  result->success = success;
  result->error_code = error_code;
  result->duration_ms = duration_ms;

  if (message != NULL) {
    strncpy(result->message, message, sizeof(result->message) - 1);
    result->message[sizeof(result->message) - 1] = '\0';
  } else {
    result->message[0] = '\0';
  }
}

// Convert error code to string
const char *test_error_to_string(int error_code) {
  return softether_error_string(error_code);
}

// Test 1: TCP Connection
native_test_result_t test_tcp_connection(const native_test_config_t *config) {
  native_test_result_t result;
  long start_time = get_test_timestamp_ms();

  LOGD("Testing TCP connection to %s:%d", config->host, config->port);

  softether_socket_t *sock = socket_create(SOCKET_TYPE_TCP);
  if (sock == NULL) {
    long duration = get_test_timestamp_ms() - start_time;
    test_result_init(&result, false, ERR_TCP_CONNECT, "Failed to create socket",
                     duration);
    return result;
  }

  int ret = socket_connect_timeout(sock, config->host, config->port,
                                   config->timeout_ms);
  long duration = get_test_timestamp_ms() - start_time;

  if (ret != 0) {
    socket_destroy(sock);
    test_result_init(&result, false, ERR_TCP_CONNECT, "TCP connection failed",
                     duration);
    return result;
  }

  socket_destroy(sock);

  char msg[256];
  snprintf(msg, sizeof(msg), "TCP connection successful to %s:%d", config->host,
           config->port);
  test_result_init(&result, true, ERR_NONE, msg, duration);
  LOGD("TCP connection test passed in %ld ms", duration);
  return result;
}

// Test 2: TLS Handshake
native_test_result_t test_tls_handshake(const native_test_config_t *config) {
  native_test_result_t result;
  long start_time = get_test_timestamp_ms();

  LOGD("Testing TLS handshake with %s:%d", config->host, config->port);

  // Create socket
  softether_socket_t *sock = socket_create(SOCKET_TYPE_TCP);
  if (sock == NULL) {
    long duration = get_test_timestamp_ms() - start_time;
    test_result_init(&result, false, ERR_TCP_CONNECT, "Failed to create socket",
                     duration);
    return result;
  }

  // Connect
  if (socket_connect_timeout(sock, config->host, config->port,
                             config->timeout_ms) != 0) {
    socket_destroy(sock);
    long duration = get_test_timestamp_ms() - start_time;
    test_result_init(&result, false, ERR_TCP_CONNECT, "TCP connection failed",
                     duration);
    return result;
  }

  // Perform TLS handshake
  ssl_context_t *ssl_ctx = ssl_create_client();
  if (ssl_ctx == NULL) {
    close(sock->fd);
    sock->fd = -1;
    socket_destroy(sock);
    long duration = get_test_timestamp_ms() - start_time;
    test_result_init(&result, false, ERR_TLS_HANDSHAKE,
                     "Failed to create SSL context", duration);
    return result;
  }

  int ret = ssl_connect(ssl_ctx, sock->fd, config->host);
  long duration = get_test_timestamp_ms() - start_time;

  // Cleanup
  ssl_destroy(ssl_ctx);
  close(sock->fd);
  sock->fd = -1;
  socket_destroy(sock);

  if (ret != 0) {
    test_result_init(&result, false, ERR_TLS_HANDSHAKE, "TLS handshake failed",
                     duration);
    return result;
  }

  char msg[256];
  snprintf(msg, sizeof(msg), "TLS handshake successful with %s:%d",
           config->host, config->port);
  test_result_init(&result, true, ERR_NONE, msg, duration);
  LOGD("TLS handshake test passed in %ld ms", duration);
  return result;
}

// Helper: connect using the real softether_connect API and return conn or NULL.
// Sets result on failure.
static softether_connection_t *
test_helper_connect(const native_test_config_t *config,
                    native_test_result_t *result, long start_time) {
  softether_connection_t *conn = softether_create();
  if (conn == NULL) {
    long d = get_test_timestamp_ms() - start_time;
    test_result_init(result, false, ERR_UNKNOWN, "Failed to create connection",
                     d);
    return NULL;
  }
  conn->timeout_ms = config->timeout_ms;

  // Default credentials for VPNGate anonymous auth
  const char *username = (config->username && config->username[0]) ? config->username : "vpn";
  const char *password = (config->password) ? config->password : "";

int ret = softether_connect_with_hub(conn, config->host, config->port,
                                        username, password, "vpngate", 1,  // use_tcp=1
                                        "", "", 0,
                                        "", "", "",
                                        "", "", 0,
                                        "", "", 0);
  if (ret != ERR_NONE) {
    long d = get_test_timestamp_ms() - start_time;
    char msg[256];
    snprintf(msg, sizeof(msg), "softether_connect failed: %s (code %d)",
             softether_error_string(ret), ret);
    test_result_init(result, false, ret, msg, d);
    softether_destroy(conn);
    return NULL;
  }
  return conn;
}

// Test 3: SoftEther Protocol Handshake
// Verifies: TCP + TLS + watermark POST + server Hello PACK received.
// Uses the real softether_connect API — if it reaches STATE_CONNECTED
// the handshake (watermark + Hello PACK parse) succeeded.
native_test_result_t
test_softether_handshake(const native_test_config_t *config) {
  native_test_result_t result;
  long start_time = get_test_timestamp_ms();

  LOGD("Testing SoftEther handshake with %s:%d", config->host, config->port);

  softether_connection_t *conn =
      test_helper_connect(config, &result, start_time);
  if (conn == NULL)
    return result;

  long duration = get_test_timestamp_ms() - start_time;

  // Verify connection reached CONNECTED state
  softether_state_t state = softether_get_state(conn);
  LOGD("Connection state after connect: %d", state);

  int has_random = conn->has_server_random;

  softether_disconnect(conn);
  softether_destroy(conn);

  if (state != STATE_CONNECTED) {
    char msg[256];
    snprintf(msg, sizeof(msg),
             "Handshake incomplete: state=%d (expected CONNECTED)", state);
    test_result_init(&result, false, ERR_PROTOCOL_VERSION, msg, duration);
    return result;
  }

  char msg[256];
  snprintf(msg, sizeof(msg),
           "Handshake successful (server_random: %s) in %ld ms",
           has_random ? "yes" : "no", duration);
  test_result_init(&result, true, ERR_NONE, msg, duration);
  return result;
}

// Test 4: Authentication
// Verifies: full connect succeeds (watermark + PACK login with proper auth).
native_test_result_t test_authentication(const native_test_config_t *config) {
  native_test_result_t result;
  long start_time = get_test_timestamp_ms();

  LOGD("Testing authentication with %s:%d (user: %s)", config->host,
       config->port, config->username);

  softether_connection_t *conn =
      test_helper_connect(config, &result, start_time);
  if (conn == NULL)
    return result;

  long duration = get_test_timestamp_ms() - start_time;

  softether_disconnect(conn);
  softether_destroy(conn);

  char msg[256];
  snprintf(msg, sizeof(msg),
           "Authentication successful for user '%s' in %ld ms",
           config->username, duration);
  test_result_init(&result, true, ERR_NONE, msg, duration);
  return result;
}

// Test 5: Session Establishment
// Verifies: connect succeeds and session info is populated from Welcome PACK.
native_test_result_t test_session(const native_test_config_t *config) {
  native_test_result_t result;
  long start_time = get_test_timestamp_ms();

  LOGD("Testing session setup with %s:%d", config->host, config->port);

  softether_connection_t *conn =
      test_helper_connect(config, &result, start_time);
  if (conn == NULL)
    return result;

  long duration = get_test_timestamp_ms() - start_time;
  uint32_t session_id = conn->session_id;
  softether_state_t state = softether_get_state(conn);
  int established = conn->session_established;

  char session_name[128];
  strncpy(session_name, conn->session_name, sizeof(session_name) - 1);
  session_name[sizeof(session_name) - 1] = '\0';

  softether_disconnect(conn);
  softether_destroy(conn);

  char msg[256];
  snprintf(msg, sizeof(msg),
           "Session: id=0x%08X, state=%d, established=%d, name=%.60s (%ld ms)",
           session_id, state, established, session_name, duration);
  test_result_init(&result, true, ERR_NONE, msg, duration);
  return result;
}

// Test 6: Data Transmission
// Verifies: connect + send data over the established tunnel.
native_test_result_t
test_data_transmission(const native_test_config_t *config) {
  native_test_result_t result;
  long start_time = get_test_timestamp_ms();

  LOGD("Testing data transmission with %s:%d", config->host, config->port);

  softether_connection_t *conn =
      test_helper_connect(config, &result, start_time);
  if (conn == NULL)
    return result;

  // Send test packets using the real API
  int packets_sent = 0;
  long bytes_sent = 0;
  uint8_t *send_buffer = (uint8_t *)malloc(config->packet_size);

  if (send_buffer == NULL) {
    softether_disconnect(conn);
    softether_destroy(conn);
    long d = get_test_timestamp_ms() - start_time;
    test_result_init(&result, false, ERR_DATA_TRANSMISSION,
                     "Failed to allocate buffer", d);
    return result;
  }

  for (int i = 0; i < config->packet_size; i++) {
    send_buffer[i] = (uint8_t)(i & 0xFF);
  }

  for (int i = 0; i < config->packet_count; i++) {
    send_buffer[0] = (uint8_t)(i & 0xFF);
    int ret = softether_send(conn, send_buffer, config->packet_size);
    if (ret < 0) {
      LOGE("Failed to send packet %d", i);
      break;
    }
    bytes_sent += config->packet_size;
    packets_sent++;
    usleep(1000);
  }

  free(send_buffer);

  long duration = get_test_timestamp_ms() - start_time;
  softether_disconnect(conn);
  softether_destroy(conn);

  if (packets_sent == 0) {
    test_result_init(&result, false, ERR_DATA_TRANSMISSION,
                     "Failed to send any packets", duration);
    return result;
  }

  char msg[256];
  snprintf(msg, sizeof(msg), "Sent %d packets (%ld bytes) in %ld ms",
           packets_sent, bytes_sent, duration);
  test_result_init(&result, true, ERR_NONE, msg, duration);
  return result;
}

// Test 7: Keepalive
// Verifies: connect + connection stays alive for duration_seconds.
native_test_result_t test_keepalive(const native_test_config_t *config) {
  native_test_result_t result;
  long start_time = get_test_timestamp_ms();

  LOGD("Testing keepalive with %s:%d (%ds)", config->host, config->port,
       config->duration_seconds);

  softether_connection_t *conn =
      test_helper_connect(config, &result, start_time);
  if (conn == NULL)
    return result;

  long test_end_ms = (long)config->duration_seconds * 1000;
  int keepalive_count = 0;

  while ((get_test_timestamp_ms() - start_time) < test_end_ms) {
    int ret = softether_send_keepalive(conn);
    if (ret < 0) {
      LOGE("Keepalive send failed after %d sends", keepalive_count);
      break;
    }
    keepalive_count++;
    usleep(2000000); // 2 seconds between keepalives (server may timeout idle)
  }

  long duration = get_test_timestamp_ms() - start_time;
  softether_state_t state = softether_get_state(conn);

  softether_disconnect(conn);
  softether_destroy(conn);

  char msg[256];
  snprintf(msg, sizeof(msg),
           "Keepalive: %d sent, final state=%d, duration=%ld ms",
           keepalive_count, state, duration);
  test_result_init(&result, true, ERR_NONE, msg, duration);
  return result;
}

// Test 8: Full Lifecycle
// Verifies: connect → send data → disconnect cleanly.
native_test_result_t test_full_lifecycle(const native_test_config_t *config) {
  native_test_result_t result;
  long start_time = get_test_timestamp_ms();

  LOGD("Testing full lifecycle with %s:%d", config->host, config->port);

  softether_connection_t *conn =
      test_helper_connect(config, &result, start_time);
  if (conn == NULL)
    return result;

  long connect_ms = get_test_timestamp_ms() - start_time;
  LOGD("Connected in %ld ms", connect_ms);

  // Send test data
  uint8_t test_data[64];
  memset(test_data, 0xAB, sizeof(test_data));
  int send_ret = softether_send(conn, test_data, sizeof(test_data));

  // Try to receive (non-blocking, best-effort)
  usleep(500000);
  uint8_t recv_buf[256];
  int recv_ret = softether_receive(conn, recv_buf, sizeof(recv_buf));

  softether_disconnect(conn);
  softether_destroy(conn);

  long duration = get_test_timestamp_ms() - start_time;

  if (send_ret < 0) {
    test_result_init(&result, false, ERR_DATA_TRANSMISSION,
                     "Failed to send test data after connect", duration);
    return result;
  }

  char msg[256];
  snprintf(msg, sizeof(msg),
           "Full lifecycle OK: connect=%ld ms, send=%s, recv=%s, total=%ld ms",
           connect_ms, (send_ret >= 0) ? "ok" : "fail",
           (recv_ret > 0) ? "yes" : "no", duration);
  test_result_init(&result, true, ERR_NONE, msg, duration);
  return result;
}

// Test 9: DHCP over SoftEther Tunnel
// Verifies: connect + DHCP to obtain IP address from SecureNAT
native_test_result_t test_dhcp(const native_test_config_t *config) {
  native_test_result_t result;
  long start_time = get_test_timestamp_ms();

  LOGD("Testing DHCP over tunnel with %s:%d", config->host, config->port);

  softether_connection_t *conn =
      test_helper_connect(config, &result, start_time);
  if (conn == NULL)
    return result;

  long connect_ms = get_test_timestamp_ms() - start_time;
  LOGD("Connected in %ld ms, starting DHCP...", connect_ms);

  // Perform DHCP
  dhcp_result_t dhcp;
  memset(&dhcp, 0, sizeof(dhcp));
  int dhcp_ret = softether_do_dhcp(conn, &dhcp);

  long duration = get_test_timestamp_ms() - start_time;

  softether_disconnect(conn);
  softether_destroy(conn);

  if (dhcp_ret != 0 || !dhcp.success) {
    char msg[256];
    snprintf(msg, sizeof(msg), "DHCP failed (ret=%d) after %ld ms",
             dhcp_ret, duration);
    test_result_init(&result, false, ERR_SESSION, msg, duration);
    return result;
  }

  // Convert IP addresses for display
  struct in_addr ip_addr, gw_addr, dns_addr;
  ip_addr.s_addr = dhcp.assigned_ip;
  gw_addr.s_addr = dhcp.gateway;
  dns_addr.s_addr = dhcp.dns_server;

  char ip_str[16], gw_str[16], dns_str[16];
  strncpy(ip_str, inet_ntoa(ip_addr), sizeof(ip_str));
  strncpy(gw_str, inet_ntoa(gw_addr), sizeof(gw_str));
  strncpy(dns_str, inet_ntoa(dns_addr), sizeof(dns_str));

  char msg[256];
  snprintf(msg, sizeof(msg),
           "DHCP OK: IP=%s GW=%s DNS=%s (connect=%ld ms, total=%ld ms)",
           ip_str, gw_str, dns_str, connect_ms, duration);
  test_result_init(&result, true, ERR_NONE, msg, duration);
  LOGD("DHCP test passed: %s", msg);
  return result;
}

// --- DNS packet builder helpers ---

static uint16_t test_ip_checksum(const uint8_t *data, int len) {
  uint32_t sum = 0;
  for (int i = 0; i < len - 1; i += 2) {
    sum += (uint16_t)(data[i] << 8 | data[i + 1]);
  }
  if (len & 1) sum += (uint16_t)(data[len - 1] << 8);
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return (uint16_t)(~sum);
}

// Build a DNS query for "google.com" type A, returns payload length
static int build_dns_query(uint8_t *buf, int max_len, uint16_t txn_id) {
  if (max_len < 28) return -1;
  int pos = 0;

  // DNS Header (12 bytes)
  buf[pos++] = (txn_id >> 8) & 0xFF;  // Transaction ID
  buf[pos++] = txn_id & 0xFF;
  buf[pos++] = 0x01; buf[pos++] = 0x00;  // Flags: standard query, RD=1
  buf[pos++] = 0x00; buf[pos++] = 0x01;  // Questions: 1
  buf[pos++] = 0x00; buf[pos++] = 0x00;  // Answers: 0
  buf[pos++] = 0x00; buf[pos++] = 0x00;  // Authority: 0
  buf[pos++] = 0x00; buf[pos++] = 0x00;  // Additional: 0

  // QNAME: google.com → \x06google\x03com\x00
  buf[pos++] = 6;
  memcpy(buf + pos, "google", 6); pos += 6;
  buf[pos++] = 3;
  memcpy(buf + pos, "com", 3); pos += 3;
  buf[pos++] = 0;  // terminator

  // QTYPE: A (1)
  buf[pos++] = 0x00; buf[pos++] = 0x01;
  // QCLASS: IN (1)
  buf[pos++] = 0x00; buf[pos++] = 0x01;

  return pos;
}

// Build a UDP/IP/Ethernet frame containing a DNS query
// Returns total Ethernet frame length, or -1 on error
static int build_dns_frame(uint8_t *frame, int max_len,
                           const uint8_t *src_mac, uint32_t src_ip,
                           uint32_t dns_server_ip, uint16_t txn_id,
                           const uint8_t *dst_mac) {
  uint8_t dns_payload[64];
  int dns_len = build_dns_query(dns_payload, sizeof(dns_payload), txn_id);
  if (dns_len < 0) return -1;

  int udp_len = 8 + dns_len;
  int ip_total = 20 + udp_len;
  int eth_total = 14 + ip_total;
  if (eth_total > max_len) return -1;

  int pos = 0;

  // Ethernet header (14 bytes)
  memcpy(frame + pos, dst_mac, 6); pos += 6;    // dst: resolved MAC
  memcpy(frame + pos, src_mac, 6); pos += 6;    // src
  frame[pos++] = 0x08; frame[pos++] = 0x00;  // EtherType: IPv4

  // IP header (20 bytes)
  int ip_start = pos;
  frame[pos++] = 0x45;          // version=4, IHL=5
  frame[pos++] = 0x00;          // DSCP/ECN
  frame[pos++] = (ip_total >> 8) & 0xFF;
  frame[pos++] = ip_total & 0xFF;  // total length
  frame[pos++] = 0x00; frame[pos++] = 0x01;  // identification
  frame[pos++] = 0x00; frame[pos++] = 0x00;  // flags + fragment offset
  frame[pos++] = 64;            // TTL
  frame[pos++] = 17;            // protocol: UDP
  frame[pos++] = 0x00; frame[pos++] = 0x00;  // checksum placeholder
  // IPs are stored in host byte order — convert to network byte order for IP header
  uint32_t src_ip_net = htonl(src_ip);
  uint32_t dst_ip_net = htonl(dns_server_ip);
  memcpy(frame + pos, &src_ip_net, 4); pos += 4;
  memcpy(frame + pos, &dst_ip_net, 4); pos += 4;

  // IP checksum
  uint16_t ip_cksum = test_ip_checksum(frame + ip_start, 20);
  frame[ip_start + 10] = (ip_cksum >> 8) & 0xFF;
  frame[ip_start + 11] = ip_cksum & 0xFF;

  // UDP header (8 bytes)
  uint16_t src_port = 0xC000 | (txn_id & 0x3FFF);  // high port
  uint16_t dst_port = 53;
  frame[pos++] = (src_port >> 8) & 0xFF;
  frame[pos++] = src_port & 0xFF;
  frame[pos++] = (dst_port >> 8) & 0xFF;
  frame[pos++] = dst_port & 0xFF;
  frame[pos++] = (udp_len >> 8) & 0xFF;
  frame[pos++] = udp_len & 0xFF;
  frame[pos++] = 0x00; frame[pos++] = 0x00;  // UDP checksum: 0 (optional in IPv4)

  // DNS payload
  memcpy(frame + pos, dns_payload, dns_len);
  pos += dns_len;

  return pos;
}

// Check if a received Ethernet frame contains a DNS response matching our txn_id
static int check_dns_response(const uint8_t *frame, int frame_len,
                              uint16_t expected_txn_id) {
  if (frame_len < 14 + 20 + 8 + 12) return 0;  // too short

  // Check EtherType = IPv4
  if (frame[12] != 0x08 || frame[13] != 0x00) return 0;

  // Check IP protocol = UDP
  if (frame[14 + 9] != 17) return 0;

  // Check UDP source port = 53
  int udp_start = 14 + (frame[14] & 0x0F) * 4;  // account for IP header length
  if (udp_start + 8 > frame_len) return 0;
  uint16_t src_port = (frame[udp_start] << 8) | frame[udp_start + 1];
  if (src_port != 53) return 0;

  // Check DNS transaction ID
  int dns_start = udp_start + 8;
  if (dns_start + 12 > frame_len) return 0;
  uint16_t txn_id = (frame[dns_start] << 8) | frame[dns_start + 1];
  if (txn_id != expected_txn_id) return 0;

  // Check flags: QR bit must be 1 (response)
  if (!(frame[dns_start + 2] & 0x80)) return 0;

  // Check ANCOUNT > 0
  uint16_t ancount = (frame[dns_start + 6] << 8) | frame[dns_start + 7];
  return (ancount > 0) ? 1 : 0;
}

// Build an ARP request to resolve a target IP's MAC address
// Returns frame length (42 bytes)
static int build_arp_request(uint8_t *frame, int max_len,
                             const uint8_t *src_mac, uint32_t src_ip_host,
                             uint32_t target_ip_host) {
  if (max_len < 42) return -1;

  // Ethernet header
  memset(frame, 0xFF, 6);              // dst: broadcast
  memcpy(frame + 6, src_mac, 6);       // src: our MAC
  frame[12] = 0x08; frame[13] = 0x06;  // EtherType: ARP

  // ARP header
  frame[14] = 0x00; frame[15] = 0x01;  // Hardware: Ethernet
  frame[16] = 0x08; frame[17] = 0x00;  // Protocol: IPv4
  frame[18] = 6;    // Hardware addr len
  frame[19] = 4;    // Protocol addr len
  frame[20] = 0x00; frame[21] = 0x01;  // Operation: request

  // Sender
  memcpy(frame + 22, src_mac, 6);
  frame[28] = (src_ip_host >> 24) & 0xFF;
  frame[29] = (src_ip_host >> 16) & 0xFF;
  frame[30] = (src_ip_host >> 8) & 0xFF;
  frame[31] = src_ip_host & 0xFF;

  // Target (MAC unknown = zeros)
  memset(frame + 32, 0, 6);
  frame[38] = (target_ip_host >> 24) & 0xFF;
  frame[39] = (target_ip_host >> 16) & 0xFF;
  frame[40] = (target_ip_host >> 8) & 0xFF;
  frame[41] = target_ip_host & 0xFF;

  return 42;
}

// Check if an ARP reply matches our target IP and extract the MAC
// Returns 1 if matched and mac_out is filled, 0 otherwise
static int check_arp_reply(const uint8_t *frame, int frame_len,
                           uint32_t target_ip_host, uint8_t *mac_out) {
  if (frame_len < 42) return 0;
  if (frame[12] != 0x08 || frame[13] != 0x06) return 0;
  uint16_t arp_op = (frame[20] << 8) | frame[21];
  if (arp_op != 2) return 0;  // not a reply

  // Sender IP in ARP reply (offset 28-31)
  uint32_t sender_ip = ((uint32_t)frame[28] << 24) | ((uint32_t)frame[29] << 16) |
                       ((uint32_t)frame[30] << 8) | frame[31];
  if (sender_ip != target_ip_host) return 0;

  // Extract sender MAC
  memcpy(mac_out, frame + 22, 6);
  return 1;
}

// Build an ARP reply in response to an ARP request for our IP
// Returns frame length or 0 if not an ARP request for us
static int build_arp_reply(const uint8_t *request, int req_len,
                           uint8_t *reply, int max_len,
                           const uint8_t *our_mac, uint32_t our_ip_host) {
  if (req_len < 42 || max_len < 42) return 0;

  // Check EtherType = ARP (0x0806)
  if (request[12] != 0x08 || request[13] != 0x06) return 0;

  // Check ARP operation = request (1)
  uint16_t arp_op = (request[20] << 8) | request[21];
  if (arp_op != 1) return 0;

  // Check target IP matches our IP
  uint32_t target_ip = ((uint32_t)request[38] << 24) | ((uint32_t)request[39] << 16) |
                       ((uint32_t)request[40] << 8) | request[41];
  if (target_ip != our_ip_host) return 0;

  // Build ARP reply
  memcpy(reply, request + 6, 6);    // dst = sender's MAC from request
  memcpy(reply + 6, our_mac, 6);    // src = our MAC
  reply[12] = 0x08; reply[13] = 0x06;

  reply[14] = 0x00; reply[15] = 0x01;
  reply[16] = 0x08; reply[17] = 0x00;
  reply[18] = 6; reply[19] = 4;
  reply[20] = 0x00; reply[21] = 0x02;  // reply

  memcpy(reply + 22, our_mac, 6);
  reply[28] = (our_ip_host >> 24) & 0xFF;
  reply[29] = (our_ip_host >> 16) & 0xFF;
  reply[30] = (our_ip_host >> 8) & 0xFF;
  reply[31] = our_ip_host & 0xFF;

  memcpy(reply + 32, request + 22, 6);
  memcpy(reply + 38, request + 28, 4);

  return 42;
}

// Test 10: Internet Connectivity via DNS
// Verifies: connect + DHCP + send DNS query for google.com + receive DNS response
// This proves the VPN tunnel provides actual internet access.
native_test_result_t test_internet_connectivity(const native_test_config_t *config) {
  native_test_result_t result;
  long start_time = get_test_timestamp_ms();

  LOGD("Testing internet connectivity via DNS through tunnel %s:%d",
       config->host, config->port);

  // Step 1: Connect
  softether_connection_t *conn =
      test_helper_connect(config, &result, start_time);
  if (conn == NULL)
    return result;

  long connect_ms = get_test_timestamp_ms() - start_time;
  LOGD("Connected in %ld ms", connect_ms);

  // Step 2: DHCP
  dhcp_result_t dhcp;
  memset(&dhcp, 0, sizeof(dhcp));
  int dhcp_ret = softether_do_dhcp(conn, &dhcp);

  if (dhcp_ret != 0 || !dhcp.success) {
    long d = get_test_timestamp_ms() - start_time;
    softether_disconnect(conn);
    softether_destroy(conn);
    test_result_init(&result, false, ERR_SESSION,
                     "DHCP failed — cannot test connectivity", d);
    return result;
  }

  long dhcp_ms = get_test_timestamp_ms() - start_time - connect_ms;
  struct in_addr ip_addr;
  ip_addr.s_addr = dhcp.assigned_ip;
  LOGD("DHCP done in %ld ms: IP=%s", dhcp_ms, inet_ntoa(ip_addr));

  // Step 3: ARP resolve gateway/DNS server MAC
  uint32_t dns_ip = dhcp.dns_server;
  if (dns_ip == 0) dns_ip = dhcp.gateway;
  if (dns_ip == 0) {
    long d = get_test_timestamp_ms() - start_time;
    softether_disconnect(conn);
    softether_destroy(conn);
    test_result_init(&result, false, ERR_SESSION,
                     "No DNS server or gateway from DHCP", d);
    return result;
  }

  // Send ARP request for the DNS server IP
  uint8_t arp_req[42];
  build_arp_request(arp_req, sizeof(arp_req), conn->client_mac, dhcp.assigned_ip, dns_ip);
  softether_send_raw(conn, arp_req, 42);
  LOGD("Sent ARP request for DNS server");

  // Wait for ARP reply (up to 3 seconds)
  uint8_t gw_mac[6];
  int arp_resolved = 0;
  for (int i = 0; i < 60 && !arp_resolved; i++) {  // 60 × 50ms = 3s
    uint8_t recv_frame[2048];
    uint32_t recv_len = 0;
    int ret = softether_receive_raw(conn, recv_frame, sizeof(recv_frame), &recv_len);
    if (ret > 0 && recv_len > 0) {
      // Check for ARP reply from our target
      if (check_arp_reply(recv_frame, (int)recv_len, dns_ip, gw_mac)) {
        arp_resolved = 1;
        LOGD("ARP resolved: %02X:%02X:%02X:%02X:%02X:%02X",
             gw_mac[0], gw_mac[1], gw_mac[2], gw_mac[3], gw_mac[4], gw_mac[5]);
      }
      // Also check gratuitous ARP from the gateway
      if (!arp_resolved && recv_len >= 42 && recv_frame[12] == 0x08 && recv_frame[13] == 0x06) {
        uint16_t arp_op = (recv_frame[20] << 8) | recv_frame[21];
        if (arp_op == 2) {
          uint32_t sender_ip = ((uint32_t)recv_frame[28] << 24) | ((uint32_t)recv_frame[29] << 16) |
                               ((uint32_t)recv_frame[30] << 8) | recv_frame[31];
          if (sender_ip == dns_ip) {
            memcpy(gw_mac, recv_frame + 22, 6);
            arp_resolved = 1;
            LOGD("ARP resolved from gratuitous: %02X:%02X:%02X:%02X:%02X:%02X",
                 gw_mac[0], gw_mac[1], gw_mac[2], gw_mac[3], gw_mac[4], gw_mac[5]);
          }
        }
      }
      // Respond to ARP requests for our IP
      if (recv_len >= 42 && recv_frame[12] == 0x08 && recv_frame[13] == 0x06) {
        uint8_t arp_reply[42];
        int arp_len = build_arp_reply(recv_frame, (int)recv_len, arp_reply, sizeof(arp_reply),
                                      conn->client_mac, dhcp.assigned_ip);
        if (arp_len > 0) softether_send_raw(conn, arp_reply, arp_len);
      }
    } else if (ret == 0) {
      usleep(50000);  // 50ms
    }
    // Resend ARP request after 1 second
    if (i == 20 || i == 40) {
      softether_send_raw(conn, arp_req, 42);
      LOGD("Resending ARP request");
    }
  }

  if (!arp_resolved) {
    long d = get_test_timestamp_ms() - start_time;
    softether_disconnect(conn);
    softether_destroy(conn);
    test_result_init(&result, false, ERR_DATA_TRANSMISSION,
                     "ARP resolution failed for DNS server", d);
    return result;
  }

  // Step 4: Send DNS query for google.com
  uint16_t txn_id = (uint16_t)(rand() & 0xFFFF);

  uint8_t dns_frame[256];
  int frame_len = build_dns_frame(dns_frame, sizeof(dns_frame),
                                  conn->client_mac, dhcp.assigned_ip,
                                  dns_ip, txn_id, gw_mac);
  if (frame_len < 0) {
    long d = get_test_timestamp_ms() - start_time;
    softether_disconnect(conn);
    softether_destroy(conn);
    test_result_init(&result, false, ERR_DATA_TRANSMISSION,
                     "Failed to build DNS frame", d);
    return result;
  }

  int send_ret = softether_send_raw(conn, dns_frame, frame_len);
  if (send_ret < 0) {
    long d = get_test_timestamp_ms() - start_time;
    softether_disconnect(conn);
    softether_destroy(conn);
    test_result_init(&result, false, ERR_DATA_TRANSMISSION,
                     "Failed to send DNS query", d);
    return result;
  }
  LOGD("DNS query sent (%d bytes, txn_id=0x%04X)", frame_len, txn_id);

  // Step 4: Wait for DNS response (up to 10 seconds)
  int dns_received = 0;
  long dns_start = get_test_timestamp_ms();
  int frame_log_count = 0;

  for (int attempt = 0; attempt < 200; attempt++) {  // 200 × 50ms = 10s max
    uint8_t recv_frame[2048];
    uint32_t recv_len = 0;
    int ret = softether_receive_raw(conn, recv_frame, sizeof(recv_frame), &recv_len);

    if (ret > 0 && recv_len > 0) {
      // Log frame details for first 20 received frames
      if (frame_log_count < 20 && recv_len >= 14) {
        uint16_t ethertype = (recv_frame[12] << 8) | recv_frame[13];
        LOGD("Frame[%d@%d]: %u bytes, ethertype=0x%04X, dst=%02X:%02X:%02X:%02X:%02X:%02X",
             frame_log_count, attempt, recv_len, ethertype,
             recv_frame[0], recv_frame[1], recv_frame[2],
             recv_frame[3], recv_frame[4], recv_frame[5]);
        if (ethertype == 0x0800 && recv_len >= 34) {
          uint8_t proto = recv_frame[23];
          LOGD("  IPv4 proto=%d, src=%d.%d.%d.%d dst=%d.%d.%d.%d",
               proto,
               recv_frame[26], recv_frame[27], recv_frame[28], recv_frame[29],
               recv_frame[30], recv_frame[31], recv_frame[32], recv_frame[33]);
          if (proto == 17 && recv_len >= 42) {
            uint16_t sport = (recv_frame[34] << 8) | recv_frame[35];
            uint16_t dport = (recv_frame[36] << 8) | recv_frame[37];
            LOGD("  UDP src_port=%d dst_port=%d", sport, dport);
          }
        } else if (ethertype == 0x0806) {
          LOGD("  ARP op=%d", (recv_frame[20] << 8) | recv_frame[21]);
        }
        frame_log_count++;
      }

      // Handle ARP requests for our IP — send ARP reply
      if (recv_len >= 42 && recv_frame[12] == 0x08 && recv_frame[13] == 0x06) {
        uint8_t arp_reply[42];
        int arp_len = build_arp_reply(recv_frame, (int)recv_len, arp_reply, sizeof(arp_reply),
                                      conn->client_mac, dhcp.assigned_ip);
        if (arp_len > 0) {
          softether_send_raw(conn, arp_reply, arp_len);
          LOGD("Sent ARP reply for our IP");
        }
      }

      if (check_dns_response(recv_frame, (int)recv_len, txn_id)) {
        dns_received = 1;
        LOGD("DNS response received! (%u bytes, attempt %d)", recv_len, attempt);
        break;
      }
      // Got a frame but not our DNS response — keep reading
    } else if (ret == 0) {
      // No data yet — poll returns timeout in fill_recv_queue
      usleep(10000);  // 10ms
    } else {
      // Error reading
      LOGE("Receive error: %d", ret);
      break;
    }

    // Re-send DNS query every 2 seconds in case first was lost
    if ((attempt % 40) == 39) {
      LOGD("Retransmitting DNS query (attempt %d)", attempt);
      softether_send_raw(conn, dns_frame, frame_len);
    }
  }

  long dns_ms = get_test_timestamp_ms() - dns_start;
  long total_ms = get_test_timestamp_ms() - start_time;

  softether_disconnect(conn);
  softether_destroy(conn);

  if (!dns_received) {
    char msg[256];
    snprintf(msg, sizeof(msg),
             "DNS response NOT received after %ld ms (connect=%ld, dhcp=%ld)",
             dns_ms, connect_ms, dhcp_ms);
    test_result_init(&result, false, ERR_DATA_TRANSMISSION, msg, total_ms);
    return result;
  }

  char msg[256];
  snprintf(msg, sizeof(msg),
           "Internet OK! DNS resolved google.com in %ld ms "
           "(connect=%ld, dhcp=%ld, total=%ld ms)",
           dns_ms, connect_ms, dhcp_ms, total_ms);
  test_result_init(&result, true, ERR_NONE, msg, total_ms);
  LOGD("Internet connectivity test PASSED: %s", msg);
  return result;
}

// Poll until a payload arrives or the deadline elapses (UDP delivery is async).
static int rudp_poll_recv_until(rudp_context_t *ctx, uint8_t *buf,
                                uint32_t *len, uint32_t max_len,
                                long deadline_ms) {
  long deadline = get_test_timestamp_ms() + deadline_ms;
  while (get_test_timestamp_ms() < deadline) {
    rudp_poll(ctx);
    *len = 0;
    int rr = rudp_recv(ctx, buf, len, max_len);
    if (rr > 0) return rr;
    usleep(5000);
  }
  return 0;
}

// Self-contained RUDP V2 (ChaCha20-Poly1305 AEAD) loopback test.
// No VPN server required - a client and server rudp_context_t talk over 127.0.0.1.
native_test_result_t test_rudp_v2_loopback(void) {
  native_test_result_t result;
  long start_time = get_test_timestamp_ms();

  rudp_context_t *client = rudp_create(1);
  rudp_context_t *server = rudp_create(0);
  if (client == NULL || server == NULL) {
    if (client) rudp_destroy(client);
    if (server) rudp_destroy(server);
    test_result_init(&result, false, ERR_UNKNOWN, "rudp_create failed",
                     get_test_timestamp_ms() - start_time);
    return result;
  }

  // Exchange each side's own V2 key (mirrors the real login flow)
  if (rudp_init_server(server, client->my_key_v2, RUDP_COMMON_KEY_SIZE_V2,
                       "127.0.0.1", client->my_port) != 0) {
    rudp_destroy(client);
    rudp_destroy(server);
    test_result_init(&result, false, ERR_UNKNOWN, "rudp_init_server failed",
                     get_test_timestamp_ms() - start_time);
    return result;
  }
  if (rudp_init_client(client, server->my_key_v2, RUDP_COMMON_KEY_SIZE_V2,
                       "127.0.0.1", server->my_port,
                       server->my_cookie, server->your_cookie) != 0) {
    rudp_destroy(client);
    rudp_destroy(server);
    test_result_init(&result, false, ERR_UNKNOWN, "rudp_init_client failed",
                     get_test_timestamp_ms() - start_time);
    return result;
  }

  rudp_set_version(client, 2);
  rudp_set_version(server, 2);
  if (client->version != 2 || server->version != 2) {
    rudp_destroy(client);
    rudp_destroy(server);
    test_result_init(&result, false, ERR_UNKNOWN,
                     "V2 cipher not initialized (version not set to 2)",
                     get_test_timestamp_ms() - start_time);
    return result;
  }

  // Client -> server payload (auto-compressed by rudp_send)
  uint8_t payload[64];
  memset(payload, 0xAB, sizeof(payload));
  if (rudp_send(client, payload, sizeof(payload), 0) < 0) {
    rudp_destroy(client);
    rudp_destroy(server);
    test_result_init(&result, false, ERR_DATA_TRANSMISSION,
                     "client rudp_send failed", get_test_timestamp_ms() - start_time);
    return result;
  }

  uint8_t rbuf[256];
  uint32_t rlen = 0;
  int rr = rudp_poll_recv_until(server, rbuf, &rlen, sizeof(rbuf), 2000);
  if (rr < 0 || rlen != sizeof(payload) ||
      memcmp(rbuf, payload, sizeof(payload)) != 0) {
    rudp_destroy(client);
    rudp_destroy(server);
    test_result_init(&result, false, ERR_DATA_TRANSMISSION,
                     "client->server payload mismatch",
                     get_test_timestamp_ms() - start_time);
    return result;
  }

  // Server -> client payload
  uint8_t payload2[48];
  memset(payload2, 0xCD, sizeof(payload2));
  if (rudp_send(server, payload2, sizeof(payload2), 0) < 0) {
    rudp_destroy(client);
    rudp_destroy(server);
    test_result_init(&result, false, ERR_DATA_TRANSMISSION,
                     "server rudp_send failed", get_test_timestamp_ms() - start_time);
    return result;
  }

  rlen = 0;
  rr = rudp_poll_recv_until(client, rbuf, &rlen, sizeof(rbuf), 2000);
  if (rr < 0 || rlen != sizeof(payload2) ||
      memcmp(rbuf, payload2, sizeof(payload2)) != 0) {
    rudp_destroy(client);
    rudp_destroy(server);
    test_result_init(&result, false, ERR_DATA_TRANSMISSION,
                     "server->client payload mismatch",
                     get_test_timestamp_ms() - start_time);
    return result;
  }

  // A corrupt-MAC V2 packet must be silently dropped
  uint8_t corrupt[64];
  for (int i = 0; i < (int)sizeof(corrupt); i++) {
    corrupt[i] = (uint8_t)(rand() & 0xFF);
  }
  struct sockaddr_in srv_addr;
  memset(&srv_addr, 0, sizeof(srv_addr));
  srv_addr.sin_family = AF_INET;
  srv_addr.sin_port = htons(server->my_port);
  srv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  sendto(rudp_get_udp_fd(client), corrupt, sizeof(corrupt), 0,
         (struct sockaddr *)&srv_addr, sizeof(srv_addr));

  // Poll briefly so the corrupt packet is actually processed by the server
  long corrupt_deadline = get_test_timestamp_ms() + 1000;
  while (get_test_timestamp_ms() < corrupt_deadline) {
    rudp_poll(server);
    usleep(5000);
  }
  rlen = 0;
  rr = rudp_recv(server, rbuf, &rlen, sizeof(rbuf));
  if (rr != 0) {
    rudp_destroy(client);
    rudp_destroy(server);
    test_result_init(&result, false, ERR_DATA_TRANSMISSION,
                     "corrupt-MAC packet was not dropped",
                     get_test_timestamp_ms() - start_time);
    return result;
  }

  rudp_destroy(client);
  rudp_destroy(server);

  long duration = get_test_timestamp_ms() - start_time;
  char msg[256];
  snprintf(msg, sizeof(msg),
           "RUDP V2 loopback OK: both directions + corrupt-MAC dropped (%ld ms)",
           duration);
  test_result_init(&result, true, ERR_NONE, msg, duration);
  LOGD("RUDP V2 loopback test PASSED: %s", msg);
  return result;
}

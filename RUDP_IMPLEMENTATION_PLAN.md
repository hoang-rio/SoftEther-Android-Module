# SoftEther RUDP (Reliable UDP) Implementation Plan

## Overview
This document outlines the plan to implement SoftEther's UDP Acceleration (RUDP) protocol in the Android client. RUDP improves VPN performance by using UDP for data transport instead of TCP-over-HTTPS, which suffers from TCP-over-TCP meltdown issues.

**Goal:** Enable high-performance UDP data transport while maintaining backward compatibility with the existing TCP control channel.

---

## 1. Technical Analysis

### Protocol Versions

| Feature | V1 (Implemented) | V2 (Implemented) |
|---------|-------------------|--------------|
| **Encryption** | RC4 (stream cipher) | ChaCha20-Poly1305 AEAD |
| **Key Derivation** | SHA1(common_key \|\| IV) per packet | Raw 128-byte key, persistent cipher context |
| **IV Size** | 20 bytes | 12 bytes |
| **Authentication** | 20-byte zero verify field | 16-byte Poly1305 MAC |
| **Security** | Stream cipher + manual verify | Authenticated encryption (AEAD) |
| **Common Key Size** | 20 bytes | 128 bytes |
| **Status** | ✅ **Implemented & Working** | ✅ **Implemented & Working** |

### Protocol Flow
1.  **Control Channel (TCP)**: The standard HTTPS/SoftEther connection is established first.
2.  **Negotiation**: During the handshake, the client advertises `support_udp_recovery=1` and `udp_acceleration_max_version=2` (V2), matching upstream `udp_acceleration_max_version` / `rudp_bulk_max_version = 2`. The server responds with `udp_acceleration_version` (selected version), `udp_acceleration_server_ip`, `udp_acceleration_server_port`, `udp_acceleration_server_key`, and optionally `udp_acceleration_server_key_v2`.
3.  **NAT Traversal**: The client sends UDP packets to the server's UDP port to "punch" a hole in the NAT.
4.  **Data Transport**: Once the server receives the UDP packets and verifies the key, it switches data transmission to UDP. Control packets (KeepAlive) may continue on TCP or move to UDP.

### Packet Format (V1 - Implemented)
SoftEther RUDP V1 packets are encrypted and authenticated:
-   **IV**: Initialization Vector (20 bytes, random).
-   **Cookie**: 4-byte session identifier (encrypted).
-   **My Tick / Your Tick**: 8-byte timestamps for windowing (big-endian).
-   **Inner Size**: 2-byte payload length (big-endian).
-   **Flag**: 1-byte flags (compression, etc.).
-   **Payload**: Encrypted data (RC4 with key derived from SHA1(common_key ‖ IV)).
-   **Padding + Verify**: Random padding + 20-byte zero verify field.

### Packet Format (V2 - Implemented)
V2 replaces RC4+verify with AEAD:
-   **IV**: Initialization Vector (12 bytes, random).
-   **Cookie**: 4-byte session identifier (AEAD-encrypted).
-   **My Tick / Your Tick**: 8-byte timestamps for windowing (big-endian).
-   **Inner Size**: 2-byte payload length (big-endian).
-   **Flag**: 1-byte flags.
-   **Payload**: Encrypted data (ChaCha20 with persistent cipher context).
-   **Padding**: Random padding.
-   **MAC Tag**: 16-byte Poly1305 authentication tag (replaces zero-verify).

Key V2 differences:
-   Persistent `EVP_CIPHER_CTX` for ChaCha20-Poly1305 (not per-packet RC4)
-   12-byte IV replaces 20-byte IV
-   Poly1305 MAC tag replaces zero-verify integrity check
-   No separate SHA1 key derivation — 128-byte common key used directly

---

## 2. Implementation Status

### Phase 1: V1 Core (✅ Complete)
- [x] `softether_rudp.h` / `softether_rudp.c`: V1 context struct, UDP socket creation, key generation
- [x] V1 packet format: IV(20) + Cookie + MyTick + YourTick + Size + Flag + Data + Padding + Verify(20)
- [x] RC4 encryption with SHA1(common_key ‖ IV) key derivation
- [x] Window-based receive validation

### Phase 2: V1 Handshake Integration (✅ Complete)
- [x] `softether_protocol.c`: `build_login_pack` sends `udp_acceleration_client_key`, `udp_acceleration_client_cookie`, `udp_acceleration_client_port`
- [x] Welcome PACK parsing: extract server IP, port, key, cookies, version
- [x] `rudp_init_client` called after login to set up peer address and keys

### Phase 3: V1 Data Path (✅ Complete)
- [x] `softether_send_data`: RUDP send with `rudp_is_send_ready` gate, TCP fallback
- [x] `softether_fill_recv_queue`: poll UDP socket, decode RUDP blocks, queue for Java
- [x] RUDP receive queue with head/tail/count ring buffer

### Phase 4: V1 Hardening (✅ Complete)
- [x] Keep-alive polling with configurable interval (normal 1-3s, fast 0.5-1s)
- [x] 10-second continuous reception requirement (`RUDP_REQUIRE_CONTINUOUS`) before sending VPN data
- [x] `VpnService.protect()` for UDP socket to prevent TUN routing loop
- [x] DHCP over RUDP: poll UDP socket during DHCP wait loop
- [x] Simultaneous RUDP+TCP polling with 100ms timeout (prevents receive loop spinning)
- [x] Diagnostic logging for decompression failures in fallback path

### Phase 5: Compression Support (✅ Complete)
- [x] Link zlib in CMakeLists.txt (Android NDK built-in)
- [x] Implement zlib wrapper functions: `compress_data()`, `uncompress_data()`, `calc_compress_bound()`
- [x] Enable `use_compress=1` in login PACK (`softether_protocol.c:637`)
- [x] RUDP: always compress in `rudp_send()`, set `RUDP_FLAG_COMPRESSED` (`softether_rudp.c:519-532`)
- [x] RUDP: decompress on receive if flag set (`softether_rudp.c:381-390`)
- [x] TCP: always compress when `server_use_compress=1` (`packet_handler.c:259`)
- [x] Skip compression for small packets (≤1 byte)
- [x] Always-compress policy to prevent server inflate stream corruption

### ~~Phase 6: NAT-T / Direct R-UDP~~ — Removed (Not Viable for VPN Gate)
NAT-T relay server is dead (`servers.nat-traversal.softether-network.net` fails DNS), VPN Gate servers have no R-UDP listener, and ICMP/DNS R-UDP is disabled by default. Direct R-UDP is impossible — the server's R-UDP socket binds to a random port via `RAND_PORT_ID_SERVER_LISTEN=1` (`Server.c:11109`), not the TCP port.

**What works instead:** TCP connection + UDP Acceleration (`seUdpPort`) after TCP is established (`Protocol.c:5702-5724`, `Connection.c:3024-3029`).

### Phase 6: Multi-Connection Support (✅ Complete)
- [x] Extend `softether_connection_t` to manage multiple socket+SSL pairs (array/list)
- [x] Send `max_connection=4` (or configurable) instead of hardcoded `1` in login PACK
- [x] Implement `ClientAdditionalConnect`: open additional TCP sockets after initial connection
- [x] Implement session key-based authentication for additional connections
- [x] Add send-side socket selection (lowest latency)
- [x] Add receive-side multi-socket polling
- [x] Implement send quota partitioning: `MAX_SEND_SOCKET_QUEUE_SIZE / MaxConnection`
- [x] Run additional connections in background pthread (non-blocking receive loop)
- [x] Support `half_connection` mode (unidirectional sockets, optional)

### Phase 7: V2 Support (✅ Complete)
- [x] Add V2 AEAD cipher context fields to `rudp_context_t`
- [x] Init ChaCha20-Poly1305 cipher contexts in `rudp_init_client` / `rudp_init_server`
- [x] Implement V2 send: AEAD encrypt inner fields, append 16-byte Poly1305 MAC
- [x] Implement V2 receive: AEAD decrypt + MAC verify, parse inner fields
- [x] Enable version negotiation: advertise `max_version=2`, remove V1 cap
- [x] Free cipher contexts in `rudp_destroy`
- [x] V2 MSS calculation (8 bytes less overhead than V1)
- [x] Self-test `test_rudp_v2_loopback`: loopback client/server pair over `127.0.0.1`, both directions + corrupt-MAC drop — **passed on device** (SM-A736B, Android 16) via `NativeConnectionTest#test12RudpV2Loopback`

### Phase 8: IPv6 Tunnel Support (✅ Complete)
- [x] Add IPv6 fields to `ConnectionConfig.kt` (`localAddressV6`, `dnsServerV6`, `routesV6`)
- [x] Configure VPN interface with IPv6 address (`fd00::2/128`), route (`::/0`), DNS (`2001:4860:4860::8888`)
- [x] Accept `Inet6Address` in `ConnectionController.kt` `buildClientInfo()`
- [x] Support IPv6 in `ClientInfo.kt` (`getLocalIPv6Address()`, `isIPv6` flag)

### Phase 9: Dual-Stack Socket Support (✅ Client Done)
- [x] Replace `sockaddr_in` with `sockaddr_storage` in `softether_socket.h`, `softether_rudp.h`
- [x] Replace `gethostbyname()` with `getaddrinfo(AF_UNSPEC)` in `tcp_socket.c`
- [x] Implement IPv4-first, IPv6-fallback in `socket_connect_timeout()`
- [x] Support `AF_INET6` UDP socket creation in `rudp_create()` for IPv6 peers
- [x] Adjust R-UDP MTU calculation for IPv6 header (40 bytes vs 20)
- [x] Add `client_ip_v6`, `server_ip_v6`, `is_ipv6` fields to `softether_connection_t`
- [x] Add `ClientIpv6Address` PACK field in `build_login_pack()`
- [x] Replace `resolve_hostname()` with dual-stack resolution in `softether_connect_with_hub()`

### Phase 10: OpenSSL Upgrade to 3.5 LTS (✅ Complete)
- [x] Update `src/main/cpp/openssl` source tree to OpenSSL 3.5.7 (tag `openssl-3.5.7`, `8cf17aaeb4`; was 1.1.1w)
- [x] Rebuild prebuilt OpenSSL 3.5.x libs for all 4 ABIs (armeabi-v7a, arm64-v8a, x86, x86_64)
- [x] Replace `jniLibs/{abi}/libssl.a` and `libcrypto.a` with 3.5.x builds
- [x] Address RC4 low-level deprecation in `softether_rudp.c` (`RC4()` calls) — replaced with `EVP_rc4()` via `EVP_CIPHER_CTX` (decrypt path in `rudp_receive`, encrypt path in `rudp_send`)
- [x] Verify `EVP_chacha20_poly1305()` availability (Phase 7 V2 prerequisite check)
- [x] Verify TLS handshake, AES CBC/GCM, MD5/SHA1 against VPN Gate servers (on-device runtime test) — SG1 via SoftEther UDP: TLS handshake OK, RUDP V1 RC4 data path OK, RUDP V2 acceleration negotiated, tunnel routed ping, no deprecated-API errors (2026-08-11)
- [x] Run full instrumentation suite for regression — 2026-08-11: app free 5/5, app pro 5/5 (fixed ExampleInstrumentedTest hardcoded free package), SoftEtherClient 12/12 (test10Dhcp flaky on real VPNGate DHCP — passes on re-run), unit tests 4/4

> **fdsan crash fixed (2026-08-11):** Phase 9's `rudp_create_udp_socket()` guard (`if (ctx->udp_fd >= 0) close()`) misfired on fresh contexts — `calloc` zero-initialized `udp_fd` to 0, so connect could `close(0)`, which the JVM's `SocketImpl` owns → intermittent `SIGABRT` (fdsan). Fixed in `rudp_create()` by initializing `udp_fd = -1` (commit `0225498`).

> Note: OpenSSL 3.5 no longer generates `include/openssl/opensslconf.h` at build time — it is a committed wrapper that includes the generated `configuration.h`. The build script must not delete it (fixed in `build-openssl-android.sh`).

### Phase 11: IPv6 for All Protocols (✅ Client Done — Server-Blocked)

Phase 8 tunneled IPv6 for **SoftEther only**. OpenVPN (`vpnLib`) and MS-SSTP (`sstpClient`) were IPv4-only in this app even though their client stacks are IPv6-capable. **All client-side work is now complete (2026-08-10).** On-device testing confirmed the remaining gaps are **server-side SoftEther limitations** (verified against `SoftEtherVPN_Stable` v4.44-9807-rtm source), not client bugs:

- **OpenVPN clone (tun/L3) never carries IPv6, any edition:** `Interop_OpenVPN.c:380-381` (stable) / `Proto_OpenVPN.c` (DE) call `IPCSendIPv4(...)` for `OPENVPN_MODE_L3`; `IPsec_IPC.c:1736-1741` drops any packet whose version nibble ≠ 4. Fix = run a real OpenVPN daemon bridged to `tap_net` (or `server-ipv6`) and point the app at it.
- **SSTP IPv6 needs Developer Edition:** stable `src/Cedar` has **zero** `IPV6CP` symbols (no IPv6 over PPP); DE `Proto_PPP.c` has `PPP_PROTOCOL_IPV6CP`/`PPPProcessIPv6CPRequestPacket`. Our client already negotiates it and degrades gracefully when the server lacks IPv6CP.

Tasks below grouped by module; the parent repo (`vpngate-connector`) holds `app/`, `sstpClient/`, `vpnLib/`, while SoftEther code lives in this submodule.

OpenVPN (`vpnLib`, ics-openvpn fork):
- [x] Parse `tun-ipv6` in `ConfigParser.java` (was in the ignored-options list) and store as new `mUseIPv6` flag on `VpnProfile`
- [x] Emit `tun-ipv6` in `VpnProfile.getConfigFile()` so the OpenVPN binary actually negotiates IPv6
- [x] Parse `ifconfig-ipv6` from the `.ovpn` file into `mIPv6Address`
- [x] Confirm `route-ipv6` parsing and default `route-ipv6 ::/0` (`mUseDefaultRoutev6=true`) survive profile round-trip (JVM harness verified: `tun-ipv6` + `ifconfig-ipv6 <ula>/64` + `route-ipv6 ::/0` emitted)
- [x] Verify management parser handles `IFCONFIG6` + `ROUTE6` (`OpenVpnManagementThread.java:573-588`) — present
- [ ] **Blocked (server):** on-device IPv6 over VPN Gate OpenVPN — SoftEther clone drops IPv6 in L3 mode; needs a real OpenVPN daemon. Client side emits the correct config.

MS-SSTP (`sstpClient`, kittoku/osc fork):
- [x] Enable `PPP_IPv6_ENABLED` in the app's SSTP connect paths (`DetailActivity.connectSSTPVPN()`, `ServerActivity` handler) — default was `false` (`preference/constant.kt:73`)
- [x] Make IPv6CP failure non-fatal: `Controller.kt` now degrades to IPv4-only (`Ipv6cpOutcome.SKIPPED`) instead of aborting the VPN; stale IPv6CP leftovers filtered in `expectProceeded`
- [x] Seed a non-zero random IPv6CP interface-ID (`SharedBridge.kt`, RFC 5072) — servers may reject all-zero IIDs instead of NAKing
- [x] Add `HOME_ULA_V6` pref (`constant.kt`) read via `SharedBridge.homeUlaV6`; `IPTerminal.kt` injects the per-install ULA (fd00::/8, prefix 64) alongside `FE80::/64`, keeps `::/0` route
- [x] App writes `HOME_ULA_V6` in both SSTP connect paths via shared `Ipv6Ula.getOrDerive()`
- [ ] **Blocked (server):** on-device IPv6CP negotiation — Stable Edition has no IPv6CP; works only on Developer Edition.

App layer (`app/`):
- [x] Add `Ipv6Ula.kt` shared util: per-install ULA (`fd00::<ANDROID_ID hex>`), reuses the native `softether_vpn` pref so all protocols share one address
- [x] Apply dual-stack IPv6 defaults consistently for OpenVPN and SSTP in `DetailActivity.kt` / `ServerActivity.kt` (ULA + `::/0`; mirror the SoftEther `ConnectionConfig` IPv6 fields)
- [ ] Surface IPv6 state in connection status / analytics (`LAST_CONNECT_METHOD`, StatusFragment)

---

## 3. Compression Implementation Details

### Current State

| Component | Status | Details |
|-----------|--------|---------|
| `RUDP_FLAG_COMPRESSED` (0x01) | ✅ Used | Set automatically in `rudp_send()` when compression succeeds |
| `use_compress` login PACK | ✅ Enabled | Set to 1 in `softether_protocol.c:637` |
| RUDP send | ✅ Compresses | Always compresses when `data_size > 1`; sets `RUDP_FLAG_COMPRESSED` |
| RUDP receive | ✅ Decompresses | `rudp_poll()` checks flag, calls `uncompress_data()` |
| TCP send | ✅ Compresses | Always compresses when `server_use_compress=1` and `payload_len > 1` |
| zlib linkage | ✅ Linked | `find_library(z-lib z)` in CMakeLists.txt |
| Wrapper functions | ✅ Implemented | `compress_data()`, `uncompress_data()`, `calc_compress_bound()` in `compress.c` |

### How Upstream SoftEther Handles Compression

SoftEther uses **zlib deflate** (RFC 1951) for data block compression:

- **Send path**: Before sending, data blocks are compressed with `compress2()`. The compressed block is marked with `Compressed = TRUE`.
- **RUDP framing**: Compressed RUDP blocks are prefixed with an 8-byte magic signature `0xDEADBEEFCAFEFACE` (`CONNECTION_BULK_COMPRESS_SIGNATURE`), followed by compressed data.
- **TCP framing**: TCP blocks use a `Compressed` flag in the block header.
- **Receive path**: The receiver checks for the magic signature or block flag, then calls `uncompress()` to decompress.
- **Negotiation**: The `use_compress` field in the login PACK is bidirectional — if the client sends `use_compress=0`, the server should not compress data sent to the client.

### Implementation Steps

**Step 1: Link zlib**

`CMakeLists.txt`:
```cmake
find_library(z-lib z)
target_link_libraries(softether ${z-lib})
```

Android NDK includes zlib as a system library — no separate build needed.

**Step 2: Add compression wrapper functions**

New file `softether-core/src/crypto/compress.c`:
```c
#include <zlib.h>

int compress_data(const uint8_t* src, uint32_t src_size,
                  uint8_t* dst, uint32_t* dst_size) {
    return compress2(dst, dst_size, src, src_size, Z_DEFAULT_COMPRESSION);
}

int uncompress_data(const uint8_t* src, uint32_t src_size,
                    uint8_t* dst, uint32_t* dst_size) {
    return uncompress(dst, dst_size, src, src_size);
}

uint32_t calc_compress_bound(uint32_t src_size) {
    return compressBound(src_size);
}
```

**Step 3: Enable `use_compress` in login PACK**

`softether_protocol.c:637`:
```c
pack_add_int(&p, "use_compress", 1);  // was 0
```

**Step 4: Compress before RUDP send**

In `softether_send_data` (or a new `softether_send_compressed_block`):
```c
if (conn->use_compress) {
    uint32_t comp_size = calc_compress_bound(data_len);
    uint8_t* comp_buf = malloc(comp_size);
    if (compress_data(data, data_len, comp_buf, &comp_size) == 0) {
        rudp_send(conn->rudp, comp_buf, comp_size, RUDP_FLAG_COMPRESSED);
        free(comp_buf);
        return data_len;
    }
    free(comp_buf);
    // Fallback to uncompressed on failure
}
rudp_send(conn->rudp, data, data_len, 0);
```

**Step 5: Decompress on RUDP receive**

In `rudp_poll()` after extracting the flag byte (line ~352):
```c
if (flag & RUDP_FLAG_COMPRESSED) {
    uint32_t decomp_size = RUDP_MAX_PAYLOAD_SIZE;
    uint8_t* decomp_buf = malloc(decomp_size);
    if (uncompress_data(inner_data, inner_size, decomp_buf, &decomp_size) == 0) {
        memcpy(entry->data, decomp_buf, decomp_size);
        entry->len = decomp_size;
    }
    free(decomp_buf);
} else {
    memcpy(entry->data, inner_data, inner_size);
    entry->len = inner_size;
}
```

**Step 6: TCP path compression (optional)**

The TCP path uses a different framing format (`CONNECTION_BULK_COMPRESS_SIGNATURE`). This can be added later as a separate step — the RUDP path is higher priority.

---

## 4. Multi-Connection Implementation Details

### Current State

| Component | Status | Details |
|-----------|--------|---------|
| `max_connection` in login PACK | ✅ Set to 4 | `softether_protocol.c:635` |
| `half_connection` in login PACK | ✅ Set to 1 | `softether_protocol.c:638` |
| Socket management | ✅ Primary + additional array | `softether_connection_t` has `additional[MAX_SE_CONNECTIONS]` |
| `server_max_connection` | ✅ Parsed and enforced | Clamped to `min(server_max, client_max)` |
| Additional connections | ✅ Implemented | `softether_additional_connect()` with full handshake |
| Traffic distribution | ✅ Lowest late_count | `softether_select_send_socket()` |
| Multi-socket receive | ✅ Implemented | `softether_fill_recv_queue()` polls all sockets |
| Socket protection | ✅ Implemented | `protectAdditionalSockets()` in receive loop |
| JNI bridge | ✅ Implemented | `nativeSetMaxConnection`, `nativeGetNumConnections`, `nativeGetAllSocketFds` |

### How Upstream SoftEther Multi-Connection Works

**Architecture:**
- The client opens 1 initial TCP connection during login.
- After login, `ClientAdditionalConnectChance()` periodically checks if more connections are needed.
- Additional connections are opened via `ClientAdditionalConnect()` which:
  1. Opens a new TCP socket + TLS handshake
  2. Validates server certificate against the existing `ServerX`
  3. Sends `"additional_connect"` method with the `session_key` to authenticate
  4. Server validates the key, adds the socket to `TcpSockList`
- The `TcpSockList` is a `LIST` of `TCPSOCK` structs, each containing a socket, direction, and latency stats.

**Traffic Distribution:**
- **Send**: Socket with lowest `LateCount` (latency) is selected. Send quota = `MAX_SEND_SOCKET_QUEUE_SIZE / MaxConnection`.
- **Receive**: All sockets are polled via `select()`. Blocks from any socket are added to the same receive queue.
- **Half-connection**: Each socket is unidirectional (upload or download only), effectively doubling bandwidth.

**Server Constraints:**
- Server enforces `max_connection <= policy->MaxConnection` (usually 32)
- For R-UDP without UDP recovery: forced to `max_connection = 2`
- For QoS: forced to `max_connection >= 2` (or 4 with half-connection)

### Implementation Steps

**Step 1: Extend `softether_connection_t`**

Add multi-connection support to the struct:
```c
#define MAX_SE_CONNECTIONS 8

typedef struct {
    int socket_fd;
    void* ssl_ctx;
    void* ssl;
    int direction;        // TCP_BOTH, TCP_SERVER_TO_CLIENT, TCP_CLIENT_TO_SERVER
    uint64_t last_recv;
    uint32_t late_count;
} softether_tcp_sock_t;

// In softether_connection_t:
softether_tcp_sock_t connections[MAX_SE_CONNECTIONS];
int num_connections;
int max_connection;      // negotiated max (from server)
int half_connection;     // 0 or 1
```

**Step 2: Update login PACK**

`softether_protocol.c`:
```c
pack_add_int(&p, "max_connection", 4);        // was 1
pack_add_int(&p, "half_connection", 1);        // enabled — unidirectional per socket
```

**Step 3: Implement additional connection handshake**

New function `softether_additional_connect()`:
1. Open new TCP socket + connect to server IP:port
2. TLS handshake (reuse existing CA cert from primary connection)
3. Send SoftEther signature + Hello exchange
4. Send `"additional_connect"` method with `session_key`
5. Server validates and adds socket to session
6. Add socket to `connections[]` array

**Step 4: Connection manager in receive loop**

In `softether_fill_recv_queue()` or a new polling function:
1. `select()` / `poll()` across all active socket FDs
2. Read from all readable sockets
3. Queue received blocks into the same receive queue
4. Track `last_recv` and `late_count` per socket

**Step 5: Send-side socket selection**

In `softether_send_packet()` or a new send function:
1. Pick socket with lowest `late_count`
2. Apply send quota: `MAX_SEND_QUEUE_SIZE / num_connections`
3. Write to the selected socket's SSL context

**Step 6: Additional connection lifecycle**

- Open additional connections gradually (1 per second, matching upstream's `AdditionalConnectionInterval`)
- Close additional connections on disconnect
- Handle individual socket failures gracefully (fall back to remaining connections)

---

## 5. V2 (AEAD) Implementation Details

### Current State

| Component | Status | Details |
|-----------|--------|---------|
| `udp_acceleration_max_version` | ✅ Set to 2 | `softether_protocol.c` |
| `rudp_bulk_max_version` | ✅ Set to 2 | `softether_protocol.c` (safe: client never sends `bulk_on_rudp_*` keys, so the server won't engage bulk-on-RUDP — matches upstream `Protocol.c:6121-6128`) |
| `udp_acceleration_server_key_v2` | ✅ Parsed and used | `softether_protocol.h:137` |
| `rudp_server_key_v2` | ✅ Used | Selected at `rudp_init_client` call site when `rudp_version >= 2` |
| V2 cipher context | ✅ Implemented | Persistent `EVP_CIPHER_CTX` for ChaCha20-Poly1305 (`evp_encrypt_ctx` / `evp_decrypt_ctx`) |
| `rudp_set_version` | ✅ Caps at 2 | Caps at 2 only when V2 cipher inited; falls back to 1 otherwise |

### How Upstream SoftEther V2 Works

V2 replaces RC4 + zero-verify with ChaCha20-Poly1305 AEAD:

- **Key exchange**: Server sends `udp_acceleration_server_key_v2` (128 bytes) during login. Client sends `udp_acceleration_client_key_v2` (128 bytes). These are used directly — no per-packet SHA1 derivation.
- **Cipher context**: A single `EVP_CIPHER_CTX` is created per direction (send/recv) and persists across packets. The ChaCha20 counter carries forward from packet to packet.
- **IV**: 12 bytes (vs V1's 20). After each encrypt/decrypt, `NextIv` is updated to the first 12 bytes of ciphertext.
- **MAC**: 16-byte Poly1305 tag appended after ciphertext (replaces V1's 20-byte zero verify).
- **Inner structure**: Same fields (Cookie, MyTick, YourTick, Size, Flag, Data, Padding) but encrypted as a single AEAD operation.

> **Implementation complete** (2026-08). All steps below are done. Two deliberate deviations from this plan, matching upstream `UdpAccel.c`:
> 1. **Receive side never updates `NextIv_V2`** — the plan's Step 4 said to update it, but upstream only updates the send-side IV (`UdpAccel.c`). The receiver decrypts each packet with the IV carried in that packet; updating `NextIv_V2` on receive would be wrong.
> 2. **No per-packet SHA1 derivation** — keys are used directly by the persistent AEAD contexts (`UdpAccel.c`). The per-packet SHA1 in the plan (V1 behavior) does not apply to V2.

### Implementation Steps

**Step 1: Add V2 cipher context fields to `rudp_context_t`**

`softether_rudp.h`:
```c
// In rudp_context_t:
void* evp_encrypt_ctx;   // EVP_CIPHER_CTX* for ChaCha20-Poly1305
void* evp_decrypt_ctx;   // EVP_CIPHER_CTX* for ChaCha20-Poly1305
int v2_cipher_inited;    // Whether V2 cipher contexts are ready
```

**Step 2: Init V2 cipher in `rudp_init_client`**

After V1 key setup, when `server_key_size >= RUDP_COMMON_KEY_SIZE_V2` (128):
```c
#include <openssl/evp.h>

EVP_CIPHER_CTX *enc = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(enc, EVP_chacha20_poly1305(), NULL, NULL, NULL);
EVP_CIPHER_CTX_ctrl(enc, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
EVP_EncryptInit_ex(enc, NULL, NULL, my_key_v2, NULL);
ctx->evp_encrypt_ctx = enc;

EVP_CIPHER_CTX *dec = EVP_CIPHER_CTX_new();
EVP_DecryptInit_ex(dec, EVP_chacha20_poly1305(), NULL, NULL, NULL);
EVP_CIPHER_CTX_ctrl(dec, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
EVP_DecryptInit_ex(dec, NULL, NULL, server_key_v2, NULL);
ctx->evp_decrypt_ctx = dec;

ctx->v2_cipher_inited = 1;
```

**Step 3: V2 send path in `rudp_send()`**

1. Write IV (12 bytes): `ctx->next_iv_v2`
2. Build inner plaintext: `[Cookie:4][MyTick:8][YourTick:8][Size:2][Flag:1][Data:N][Pad:M]`
3. Pad to `max_udp_packet_size - 12 (IV) - 16 (MAC)`
4. AEAD encrypt:
   ```c
   EVP_EncryptInit_ex(ctx->evp_encrypt_ctx, NULL, NULL, NULL, ctx->next_iv_v2);
   EVP_EncryptUpdate(ctx->evp_encrypt_ctx, NULL, &outlen, inner, inner_size);
   EVP_EncryptFinal_ex(ctx->evp_encrypt_ctx, NULL, &outlen);
   EVP_CIPHER_CTX_ctrl(ctx->evp_encrypt_ctx, EVP_CTRL_AEAD_GET_TAG, 16, mac_tag);
   ```
5. Output: `[IV:12][Ciphertext:N][MAC:16]`
6. Update `ctx->next_iv_v2` = first 12 bytes of ciphertext

**Step 4: V2 receive path in `rudp_poll()`**

1. Extract IV (first 12 bytes), MAC (last 16 bytes), ciphertext (middle)
2. AEAD decrypt:
   ```c
   EVP_DecryptInit_ex(ctx->evp_decrypt_ctx, NULL, NULL, NULL, iv);
   EVP_CIPHER_CTX_ctrl(ctx->evp_decrypt_ctx, EVP_CTRL_AEAD_SET_TAG, 16, mac_tag);
   EVP_DecryptUpdate(ctx->evp_decrypt_ctx, NULL, &outlen, ciphertext, ciphertext_len);
   int ret = EVP_DecryptFinal_ex(ctx->evp_decrypt_ctx, NULL, &outlen);
   // ret == 1: MAC verified, ret == 0: authentication failure → drop packet
   ```
3. Parse decrypted inner fields
4. Update `ctx->next_iv_v2` = first 12 bytes of ciphertext

**Step 5: Enable version negotiation**

`softether_protocol.c`:
```c
// Advertise V2
pack_add_int(&p, "udp_acceleration_max_version", 2);  // was 1
pack_add_int(&p, "rudp_bulk_max_version", 2);          // was 1
```

Remove V1 cap in `rudp_set_version`: allow `version = min(version, 2)`.

**Step 6: Clean up on destroy**

`rudp_destroy()`:
```c
if (ctx->evp_encrypt_ctx) EVP_CIPHER_CTX_free(ctx->evp_encrypt_ctx);
if (ctx->evp_decrypt_ctx) EVP_CIPHER_CTX_free(ctx->evp_decrypt_ctx);
```

**Step 7: V2 MSS calculation**

V2 IV is 12 bytes (vs V1 20), MAC is 16 bytes (vs V1 20 verify). Net: 8 bytes less overhead → MSS increases by 8.

---

## 6. IPv6 Implementation Details

### Current State

| Component | Status | Details |
|-----------|--------|---------|
| Ethernet framing | ✅ Auto-detects IPv6 | EtherType `0x86DD` handled in `packet_handler.c` |
| TCP socket creation | ❌ IPv4 only | `AF_INET` hardcoded in `tcp_socket.c:27` |
| DNS resolution | ❌ IPv4 only | `gethostbyname()` in `tcp_socket.c:60` |
| RUDP socket | ❌ IPv4 only | `AF_INET` in `softether_rudp.c:46` |
| VPN interface (SoftEther) | ✅ IPv6 enabled | Per-install ULA (`fd00::<ANDROID_ID>`), `::/0`, `2001:4860:4860::8888` in `SoftEtherVpnService.kt` (Phase A); guarded so a bad ULA only skips IPv6, never drops the tunnel |
| Protocol handshake | ❌ IPv4 only | `ClientIpAddress` as 32-bit int (`softether_protocol.c:659`) |
| Connection struct | ❌ IPv4 only | No `*_ip_v6` or `is_ipv6` fields |

**Other protocol modules** (parent repo `vpngate-connector`):

| Module | IPv6 capability | Gap |
|--------|-----------------|-----|
| `vpnLib` (OpenVPN) | ✅ Client done — `tun-ipv6` parsed into `mUseIPv6` and emitted in `getConfigFile()`, `ifconfig-ipv6` parsed into `mIPv6Address`, `route-ipv6 ::/0` round-trips; management parser handles `IFCONFIG6`/`ROUTE6` | **Server:** SoftEther OpenVPN clone hard-codes `IPCSendIPv4` in L3 mode (`Interop_OpenVPN.c:380-381`), `IPsec_IPC.c:1736-1741` drops v6 → needs a real OpenVPN daemon |
| `sstpClient` (MS-SSTP) | ✅ Client done — `PPP_IPv6_ENABLED` on in both connect paths, random IPv6CP IID (RFC 5072), per-install ULA via `HOME_ULA_V6`/`IPTerminal.kt`, IPv6CP failure degrades to IPv4 | **Server:** Stable Edition has no IPv6CP symbols; works only on Developer Edition |
| `app` | ✅ Dual-stack for OpenVPN+SSTP — `Ipv6Ula.kt` shared per-install ULA (`fd00::<ANDROID_ID>`) + `::/0` injected in `DetailActivity.kt` / `ServerActivity.kt` | IPv6 status not surfaced in analytics / StatusFragment yet |

### Server-Side IPv6 Support Matrix (VPN Gate / SoftEther hosts)

Client work is done; these are the **server-side limits** that decide whether IPv6 actually reaches the tunnel (verified 2026-08-10 against `SoftEtherVPN_Stable` v4.44-9807-rtm and the Developer Edition branch):

| Server capability | Edition | IPv6 tunneled? | Limit (source) | Impact / workaround |
|-------------------|---------|----------------|----------------|----------------------|
| **Native SoftEther protocol** (Layer 2 bridge) | Stable + DE | ✅ Yes | None — full IPv6 packet parsing, ICMPv6 RS/RA, DHCPv6 (`Hub.c:4492-4579`) | IPv6 works end-to-end (Phase 8/Phase A). Host needs NAT66 (`server-setup/nat66/`) for global egress |
| **OpenVPN clone (L3/tun)** | Stable + DE | ❌ No | `IPCSendIPv4(...)` hardcoded for `OPENVPN_MODE_L3` (`Interop_OpenVPN.c:380-381` / DE `Proto_OpenVPN.c`); `IPsec_IPC.c:1736-1741` drops any IPC packet with version nibble ≠ 4 | Cannot be fixed in the app. Run a real OpenVPN daemon bridged to `tap_net` (or `server-ipv6`) and point the app at it |
| **MS-SSTP / PPP** | Stable | ❌ No | **Zero** `IPV6CP` symbols in `src/Cedar` — PPP never negotiates IPv6CP | Client already degrades to IPv4-only. SSTP IPv6 requires a DE server |
| **MS-SSTP / PPP** | DE | ✅ Yes | `PPP_PROTOCOL_IPV6CP` + `PPPProcessIPv6CPRequestPacket` in `Proto_PPP.c` | Client negotiates IPv6CP (RFC 5072 IID) + injects ULA; verify on-device against a DE host |
| **L2TP/IPsec over IPv6** | Stable + DE | N/A | L2TP/IPsec server transport is IPv4-oriented; not used by this app | Out of scope for Phase 11 |
| **Server reachable via IPv6** (v6 transport) | Stable + DE | ⚠️ Limited | R-UDP (NAT-T) is IPv4-only and disabled when the server is IPv6 (`UdpAccel.c:1147-1150`); upstream client connects v6 TCP only as a fallback | Not relevant to VPN Gate hosts (they are IPv4-reachable); noted for completeness |

**Bottom line:** the only path that carries IPv6 to the phone today is the **native SoftEther protocol** (Phase 8). OpenVPN and SSTP client stacks are IPv6-ready but the VPN Gate servers they target cannot deliver v6 — OpenVPN on any edition, SSTP on Stable — so the "blocked" items in Phase 11 are purely server-side.

### How Upstream SoftEther Handles IPv6

SoftEther's tunnel is a **Layer 2 Ethernet bridge** — IPv6 packets flow through once connected. The upstream Windows client:

1. **Dual-stack DNS resolution**: `ConnectEx4()` calls `GetIP46Ex()` to resolve both A and AAAA records (`Network.c:16394`)
2. **IPv4-first connection**: Tries IPv4 TCP first; falls back to IPv6 TCP if all IPv4 methods fail (`Network.c:16705-16741`)
3. **UdpAccel over IPv6**: `NewUdpAccel()` detects IPv6, adjusts MTU (-40 bytes for IPv6 header), disables NAT-T (`UdpAccel.c:1145-1181`)
4. **R-UDP (NAT-T) is IPv4-only**: Disabled when server is IPv6 (`UdpAccel.c:1147-1150`)
5. **Server-side Hub**: Full IPv6 packet parsing, ICMPv6 RS/RA, DHCPv6 detection (`Hub.c:4492-4579`)

Key upstream IPv6 functions:
- `IsIPv6Supported()` — checks OS IPv6 capability (`Network.c:11293`)
- `GetIP6Ex()` / `GetIP6Inner()` — AAAA resolution via `getaddrinfo()` (`Network.c:18370`)
- `NewUDP6()` — creates IPv6 UDP socket (`Network.c:12921`)
- `IPToInAddr6()` — converts `IP` struct to `in6_addr` (`Network.c`)

### Phase A: IPv6 Tunnel (Simpler)

Route IPv6 traffic through the VPN tunnel once connected over IPv4.

**Step 1: Add IPv6 fields to `ConnectionConfig.kt`** (✅ Done)

```kotlin
data class ConnectionConfig(
    // ... existing IPv4 fields ...
    val localAddressV6: String = "",   // empty → service derives per-install ULA
    val prefixLengthV6: Int = 128,
    val dnsServerV6: String = "2001:4860:4860::8888",
    val routesV6: List<Route> = listOf(Route("::", 0)),
)
```

**Step 2: Configure VPN interface in `SoftEtherVpnService.kt`** (✅ Done)

In `establishVpnInterface()` (`SoftEtherVpnService.kt:493-502`):
```kotlin
// ULA derived per-install from ANDROID_ID: fd00::<grouped-hex>
builder.addAddress(ulaAddress, config.prefixLengthV6)
builder.addRoute(route.address, route.prefixLength)  // ::/0
builder.addDnsServer(config.dnsServerV6)
```
Per-install ULA (not the shared `fd00::2`) so concurrent clients don't collide on the host bridge; formatting is colon-grouped and the IPv6 block is guarded so a malformed value only skips IPv6, never aborts the tunnel.

**Step 3: Accept IPv6 in `ConnectionController.kt`** (✅ Done)

In `buildClientInfo()` (`ConnectionController.kt:188-196`):
```kotlin
// Before: if (addr is Inet4Address)
// After:  if (addr is Inet4Address || addr is Inet6Address), excluding link-local
```

**Step 4: IPv6 address detection in `ClientInfo.kt`** (✅ Done)

Add `getLocalIPv6Address()` method and `isIPv6` flag; falls back to `::` when no global IPv6 exists.

### Phase B: Dual-Stack Sockets (Harder)

Connect to VPN server over IPv6 when IPv4 is unavailable.

**Step 1: Widen socket structs**

`softether_socket.h:24`:
```c
// Before: struct sockaddr_in addr;
struct sockaddr_storage addr;  // holds sockaddr_in or sockaddr_in6
```

`softether_rudp.h:78`:
```c
// Before: struct sockaddr_in peer_addr;
struct sockaddr_storage peer_addr;
```

**Step 2: Dual-stack DNS resolution**

`tcp_socket.c` — replace `gethostbyname()` with `getaddrinfo(AF_UNSPEC)`:
```c
struct addrinfo hints = {0}, *res;
hints.ai_family = AF_UNSPEC;
hints.ai_socktype = SOCK_STREAM;
getaddrinfo(hostname, NULL, &hints, &res);
```

**Step 3: IPv4-first, IPv6-fallback**

`tcp_socket.c` `socket_connect_timeout()` — follow upstream `ConnectEx4()` pattern:
```c
// Try IPv4 first
s = connect_timeout_ipv4(ip4, port, timeout);
// Fallback to IPv6
if (s < 0 && !is_zero(ip6)) {
    s = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 addr6 = {0};
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(port);
    inet_pton(AF_INET6, ip6_str, &addr6.sin6_addr);
    connect_timeout(s, (struct sockaddr*)&addr6, sizeof(addr6), timeout);
}
```

**Step 4: IPv6 RUDP socket**

`softether_rudp.c` `rudp_create()`:
```c
if (is_ipv6_peer) {
    ctx->udp_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    // bind sockaddr_in6
    ctx->max_udp_packet_size = 1500 - 40 - 8;  // IPv6 header = 40 bytes
} else {
    ctx->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    ctx->max_udp_packet_size = 1500 - 20 - 8;  // IPv4 header = 20 bytes
}
```

**Step 5: Protocol layer IPv6 fields**

`softether_protocol.h` — add to `softether_connection_t`:
```c
char client_ip_v6[64];
char server_ip_v6[64];
char rudp_server_ip_v6[64];
int is_ipv6;
```

`softether_protocol.c` `build_login_pack()` — add IPv6 PACK field:
```c
if (conn->is_ipv6) {
    struct in6_addr addr6;
    inet_pton(AF_INET6, conn->client_ip_v6, &addr6);
    pack_add_data(&p, "ClientIpv6Address", (uint8_t*)&addr6, 16);
}
```

**Step 6: Dual-stack connect in `softether_connect_with_hub()`**

Replace `resolve_hostname()` with dual-stack resolution. Try IPv4 first, fallback to IPv6. Set `conn->is_ipv6` based on which succeeded.

### Files to Modify

| File | Phase A Changes | Phase B Changes |
|------|-----------------|-----------------|
| `ConnectionConfig.kt` | Add IPv6 address/route/DNS fields | — |
| `SoftEtherVpnService.kt` | Add IPv6 to VPN interface builder | — |
| `ConnectionController.kt` | Accept `Inet6Address` | Pass IPv6 info to native |
| `ClientInfo.kt` | Add `getLocalIPv6Address()` | — |
| `softether_socket.h` | — | `sockaddr_storage` |
| `tcp_socket.c` | — | `getaddrinfo()`, IPv4/v6 connect |
| `softether_rudp.h` | — | `sockaddr_storage` peer |
| `softether_rudp.c` | — | IPv6 UDP socket, MTU adjust |
| `softether_protocol.h` | — | Add `*_ip_v6`, `is_ipv6` fields |
| `softether_protocol.c` | — | IPv6 PACK fields, dual-stack resolution |

### Success Criteria

Phase A (IPv6 Tunnel):
- [x] VPN interface has per-install IPv6 ULA (`fd00::<ANDROID_ID>/128`) and default route (`::/0`)
- [x] IPv6 DNS server configured (`2001:4860:4860::8888`)
- [x] Connected devices can reach IPv6 endpoints through tunnel (NAT66 on the host; see field notes below)

Phase B (Dual-Stack Sockets):
- [x] `resolve_hostname()` returns both IPv4 and IPv6 addresses
- [x] TCP connection tries IPv4 first, falls back to IPv6
- [x] R-UDP creates IPv6 UDP socket when peer is IPv6
- [x] Login PACK includes `ClientIpv6Address` (16-byte DATA) when IPv6
- [x] MTU adjusted for IPv6 header (40 bytes vs 20)
- [x] Can connect to server over IPv6 when IPv4 is unavailable

> **Field notes (2026-08): host-side IPv6 delivery.** Phase A moves IPv6 packets through the L2 tunnel, but the reply path needs the host to deliver frames back to the phone. Two hard-won findings on the paid SoftEther server (hub `VPNGatePaid`, local TAP bridge):
> 1. The hub mangles ND: the host kernel never learns the phone's tun MAC by NUD (entries stay `FAILED`/`INCOMPLETE`) even though the phone answers every NS with a valid NA. Fix: static neighbor pin on the host (`ip -6 neigh replace fd00::2 lladdr <phone-mac> dev tap_net nud permanent`), re-learned per session because Android rotates the tun MAC on reconnect.
> 2. Global egress uses NAT66 (`ip6tables -t nat -A POSTROUTING -s fd00::/8 -o eth0 -j MASQUERADE`) plus `ndppd` with only `rule ::/0 { static }` to answer the phone's NS for global destinations. `radvd` must advertise **no prefix** and `AdvDefaultLifetime 0` so Android stops SLAAC-rotating addresses.
> Persistence for all of this lives in `server-setup/nat66/` (setup script + systemd units, incl. a self-healing 30s neighbor-pin timer).

### Phase C: OpenVPN IPv6 (`vpnLib`, parent repo)

The OpenVPN engine is IPv6-ready; the parser deliberately strips the one line that enables it.

| What | Where | Status |
|------|-------|--------|
| `IFCONFIG6` / `ROUTE6` management commands | `OpenVpnManagementThread.java:573-588` | ✅ present |
| IPv6 tun address + v6 routes/DNS | `OpenVPNService.java` (`setLocalIPv6` :1385, `addRoutev6`, tun config :954-957) | ✅ present |
| `route-ipv6 ::/0` emitted when `mUseDefaultRoutev6` | `VpnProfile.java:632-637` | ✅ present (default `true` :140) |
| `route-ipv6` parsed from file | `ConfigParser.java:398-405` | ✅ present |
| `tun-ipv6` option | `ConfigParser.java` → `mUseIPv6`; emitted in `getConfigFile()` | ✅ fixed |
| `ifconfig-ipv6` from file | parsed into `mIPv6Address` | ✅ fixed |

**Work items:**
1. ✅ Move `tun-ipv6` out of the ignored list in `ConfigParser.java` and set a new `mUseIPv6` flag on `VpnProfile` (mirror ics-openvpn upstream `mUseIPv6`).
2. ✅ In `VpnProfile.getConfigFile()`, emit `tun-ipv6\n` when `mUseIPv6` is set (default-enabled for this app so VPN Gate `.ovpn` files get IPv6 even when the directive is absent).
3. ✅ Parse `ifconfig-ipv6` into `mIPv6Address`.
4. ⛔ **Blocked — server cannot do it.** On-device IPv6 over VPN Gate OpenVPN is impossible: SoftEther's OpenVPN clone only sends IP over the IPC socket as IPv4 (`Interop_OpenVPN.c:380-381` `IPCSendIPv4(...)` for `OPENVPN_MODE_L3`; DE `Proto_OpenVPN.c` same), and `IPsec_IPC.c:1736-1741` rejects any packet whose version nibble ≠ 4. Verified 2026-08-10 against `SoftEtherVPN_Stable` v4.44-9807-rtm. **Real fix:** stand up an actual OpenVPN daemon bridged to `tap_net` on the host and connect the app to it.

> Note: OpenVPN tunnel IPv6 uses link-local + server-assigned address (no NAT66 needed). The host's `server-setup/nat66/` config is SoftEther-specific.

### Phase D: MS-SSTP IPv6 (`sstpClient`, parent repo)

kittoku/osc already negotiates IPv6CP and builds the v6 tun; the app never turns it on, and failure handling is all-or-nothing.

| What | Where | Status |
|------|-------|--------|
| IPv6CP negotiation | `client/ppp/Ipv6cpClient.kt` + random IID seeding (`SharedBridge.kt`, RFC 5072) | ✅ present |
| `FE80::/64` link-local addr + v6 routes | `terminal/IPTerminal.kt` (`::/0`, `fc00::/7`) | ✅ present |
| `PPP_IPv6_ENABLED` pref | `preference/constant.kt` default `false` | ✅ on in both connect paths |
| App enables it | `DetailActivity.connectSSTPVPN()`, `ServerActivity` handler | ✅ sets pref + `HOME_ULA_V6` |
| IPv6CP failure handling | `Controller.kt` → `Ipv6cpOutcome.SKIPPED`, degrades to IPv4 | ✅ fixed |

**Work items:**
1. ✅ Set `OscPrefKey.PPP_IPv6_ENABLED` → `true` in both app SSTP connect paths.
2. ✅ Make IPv6 optional in the connect flow: if IPv6CP yields no usable address, `Controller.kt` records `Ipv6cpOutcome.SKIPPED` and keeps IPv4 — no abort (`ERR_INVALID_ADDRESS` gone); stale IPv6CP leftovers filtered in `expectProceeded`.
3. ⛔ **Blocked — Stable Edition has no IPv6CP.** Verified 2026-08-10: `src/Cedar` in Stable v4.44-9807-rtm has zero `IPV6CP` symbols; DE `Proto_PPP.c` has `PPP_PROTOCOL_IPV6CP`/`PPPProcessIPv6CPRequestPacket`. Our client already negotiates + degrades gracefully — tunnel IPv6 over SSTP requires a **Developer Edition** server.
4. ✅ DNS: IPv6CP carries no DNS option — v6 DNS uses the existing custom-DNS path (ULA injected with no IPv6 DNS, IPv4 DNS retained).

> Additional hardening shipped with Phase D: random IPv6CP interface-ID seeding (`SharedBridge.kt`, RFC 5072) so servers that reject all-zero IIDs NAK properly instead of stalling; per-install ULA (`HOME_ULA_V6`, fd00::/8, prefix 64) injected by `IPTerminal.kt` alongside `FE80::/64`, `::/0` route retained.

### Phase E: App-level IPv6

- [x] Add `Ipv6Ula.kt` shared util (`app/src/main/java/com/hoangndx/vpngateconnector/util/Ipv6Ula.kt`): per-install ULA `fd00::<ANDROID_ID hex>`, derived via `getOrDerive()`, backed by the native `softether_vpn` pref so all protocols share one address.
- [x] Mirror the SoftEther `ConnectionConfig` IPv6 fields (`localAddressV6`/`dnsServerV6`/`routesV6`) into the OpenVPN and SSTP connect flows (`DetailActivity.kt`, `ServerActivity.kt`) so IPv6 isn't SoftEther-only — both now inject ULA + `::/0`.
- [ ] Surface IPv6 status in connection state / analytics (`LAST_CONNECT_METHOD`, StatusFragment), matching the SoftEther `isIPv6`/`getLocalIPv6Address()` work in `ClientInfo.kt`.

---

## 7. OpenSSL Upgrade Details

### Current State

| Component | Status | Details |
|-----------|--------|---------|
| Prebuilt libs (`jniLibs/{abi}/libssl.a`, `libcrypto.a`) | ✅ 3.5.7 | Built 2026-08-11; confirmed via `strings`: "OpenSSL 3.5.7 9 Jun 2026" |
| Source tree (`src/main/cpp/openssl`) | ✅ 3.5.7 | HEAD detached at `openssl-3.5.7` (`8cf17aaeb4`); tracked git submodule, pointer bump pending |
| 1.1.1 series support | ❌ EOL | 1.1.1 EOL 11 Sep 2023; 1.1.1w was the last security-patched version |
| `RC4()` low-level usage | ✅ Fixed | `softether_rudp.c` — replaced `RC4_KEY`/`RC4()` with `EVP_rc4()` + `EVP_CIPHER_CTX` (decrypt in `rudp_receive`, encrypt in `rudp_send`) |
| `EVP_chacha20_poly1305()` | ✅ Available | Verified in 3.5.7 headers (`evp.h:1168`) and linked libs |
| Upstream SoftEther 3.x support | ✅ Present | `#if OPENSSL_VERSION_NUMBER >= 0x30000000L` + `OSSL_PROVIDER_load` (`Encrypt.c:139,158,5117,5156`) |

### OpenSSL Version Matrix (as of 2026-08)

| Series | Latest | EOL | Verdict |
|--------|--------|-----|---------|
| **3.5 [LTS]** | **3.5.7** (09 Jun 2026) | **08 Apr 2030** | ✅ **Best upgrade target** |
| 3.6 | 3.6.3 | 01 Nov 2026 | Short-term, EOL too soon |
| 3.0 [LTS] | 3.0.21 | 07 Sep 2026 | EOL imminent |
| 4.0 | 4.0.1 | 14 May 2027 | Major version, breaking changes |

### Why 1.1.1w Was Used

1. **Final release of the 1.1.1 LTS series** — last security-patched version before EOL
2. **Code targets 1.1.x API generation**: direct `RC4()` calls (`softether_rudp.c:473-475,614-616`), `EVP_aes_*_cbc()/gcm()`, `EVP_md5()`, `EVP_sha1()`
3. **Android NDK ships no OpenSSL** — must build from source; source tree vendored and pinned

### Upgrade Steps

**Step 1: Update source tree to OpenSSL 3.5.7**

```bash
cd src/main/cpp/openssl
# Checkout 3.5.7 (or fetch latest 3.5.x)
git fetch origin openssl-3.5.7
git checkout openssl-3.5.7
```

**Step 2: Rebuild for all 4 ABIs with Android NDK** ✅ (done 2026-08-11)

Use the project's build script (must keep NDK toolchain `bin/` on `PATH` — 3.x Configure errors "no NDK <arch>-linux-android-gcc on $PATH" otherwise):
```bash
export ANDROID_NDK_ROOT=<path-to-ndk>   # e.g. .../ndk/28.2.13676358
export ANDROID_NDK_HOME=$ANDROID_NDK_ROOT
export ANDROID_API=23
export PATH="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH"
./build-openssl-android.sh arm64-v8a     # then armeabi-v7a, x86, x86_64
```

Install outputs to `jniLibs/{armeabi-v7a,arm64-v8a,x86,x86_64}/` as `libssl.a` + `libcrypto.a`. (Script does this automatically.)

> **3.x gotcha:** `include/openssl/opensslconf.h` is a **committed wrapper** in 3.5 (it `#include`s the generated `configuration.h`), NOT a generated file. The old script's `rm -f include/openssl/opensslconf.h` deleted it and `make build_generated` never recreated it, breaking `crypto/aes/*.c` compiles. Fixed by not deleting it.

**Step 3: Address RC4 deprecation** ✅ (done 2026-08-11)

`softether_rudp.c` used direct `RC4()`/`RC4_KEY`. Replaced with the EVP API (RC4 lives in OpenSSL 3.x's **default** provider, no legacy provider needed):
- Decrypt path (`rudp_receive`): `EVP_CIPHER_CTX_new()` + `EVP_DecryptInit_ex(..., EVP_rc4(), ...)` + `EVP_DecryptUpdate(...)` (in-place)
- Encrypt path (`rudp_send`): same with `EVP_EncryptInit_ex`/`EVP_EncryptUpdate`
- Dropped the now-unused `#include <openssl/rc4.h>`

**Step 4: Verify Phase 7 V2 prerequisite** ✅

`EVP_chacha20_poly1305()` confirmed in 3.5.7 (`evp.h:1168`) and present in linked `libsoftether.so` (905 `EVP_*` dynamic symbols on arm64-v8a).

**Step 5: Regression test**

- TLS handshake against VPN Gate servers (TCP path) ✅ done 2026-08-11 (SG1, SoftEther UDP)
- RUDP V1 RC4 data path ✅ done 2026-08-11 (data flowing, no errors)
- AES CBC/GCM, MD5/SHA1 usage in `aes_wrapper.c` ✅ exercised via login PACK / TLS
- Full instrumentation suite ✅ done 2026-08-11 (app free/pro 5/5 each, SoftEtherClient 12/12, unit 4/4)

### API Compatibility with Local Client Code

| API | Location | 3.5 Compatible |
|-----|----------|----------------|
| `EVP_aes_*_cbc()/gcm()` | `aes_wrapper.c:70-80` | ✅ Default provider |
| `EVP_md5()` / `EVP_sha1()` | `aes_wrapper.c:455,500` | ✅ Default provider |
| `EVP_chacha20_poly1305()` | Phase 7 (implemented) | ✅ Verified in 3.5.7 |
| `RC4()` low-level | `softether_rudp.c` | ✅ Replaced with `EVP_rc4()` (default provider) |
| `SSL_CTX`, `SSL`, TLS | `aes_wrapper.c` | ✅ |
| `RAND_*` | `aes_wrapper.c` | ✅ |

### Files to Modify

| File | Change |
|------|--------|
| `src/main/cpp/openssl/` | Checkout OpenSSL 3.5.7 source — **tracked git submodule** (not git-ignored); pointer bump to `8cf17aaeb4` pending commit |
| `src/main/jniLibs/{4 ABIs}/libssl.a` | Replaced with 3.5.7 build ✅ |
| `src/main/jniLibs/{4 ABIs}/libcrypto.a` | Replaced with 3.5.7 build ✅ |
| `softether_rudp.c` | RC4 → `EVP_rc4()` (decrypt in `rudp_receive`, encrypt in `rudp_send`) ✅ |
| `build-openssl-android.sh` | Stop deleting `include/openssl/opensslconf.h` (committed in 3.x) ✅ |
| `CMakeLists.txt` | Unchanged — paths stay the same |

### Success Criteria

- [x] Prebuilt libs report `OpenSSL 3.5.x` (verify with `strings` on libcrypto.a) — all 4 ABIs report "OpenSSL 3.5.7 9 Jun 2026"
- [x] All 4 ABIs build and link — `assembleDebug` success, `libsoftether.so` in all ABIs exports 900+ `EVP_*` symbols
- [x] `EVP_chacha20_poly1305()` resolves (Phase 7 V2 readiness)
- [x] TCP/RUDP V1 connections work against VPN Gate servers — on-device (SG1 SoftEther UDP: CONNECTED ip=10.21.x.x, tunnel routed ping; 3 connect cycles no crash)
- [x] No runtime errors from deprecated API removal — on-device (no OpenSSL warnings; only unrelated system `ashmem` notes)
- [x] Instrumentation suite passes — on-device (see Phase 10 checklist)

---

## 8. Risks & Mitigations

| Risk | Feature | Mitigation |
|------|---------|------------|
| CPU overhead on compress/decompress | Compression | Use `Z_DEFAULT_COMPRESSION` (level 6); skip compression for small packets (≤1 byte) |
| Buffer overflow from decompression | Compression | Always check `uncompress()` return value; use `compressBound()` for max size estimates |
| Server doesn't honor `use_compress=0` | Compression | Server should respect client's setting; if not, disable compression and log error |
| OpenSSL prebuilt lib lacks `EVP_chacha20_poly1305()` | V2 | Verify with compile test; fallback to V1 if unavailable |
| Server doesn't support V2 | V2 | Graceful fallback — server responds with `version=1`, client stays on V1 |
| AEAD nonce reuse vulnerability | V2 | Always update `next_iv_v2` after each encrypt/decrypt (matching upstream) |
| V2 cipher context lifecycle | V2 | Create once in init, free in destroy — no per-packet allocation |
| Server rejects additional connections | Multi-Connection | Check `server_max_connection` from Welcome PACK; don't exceed it |
| Thread safety for concurrent send/recv | Multi-Connection | Use `write_mutex` per connection or per-socket locks |
| Background thread blocking disconnect | Multi-Connection | `pthread_join()` in `softether_close_additional()` and `softether_disconnect()` waits for thread; thread uses socket-level I/O timeouts to bound duration |
| Race between cleanup loop and background thread | Multi-Connection | Cleanup loop skips slot being connected (`additional_connect_slot`); background thread sets `active=1` only after full handshake |
| Memory overhead (multiple SSL contexts) | Multi-Connection | Limit to 4 connections initially; make configurable |
| TLS certificate reuse for additional connections | Multi-Connection | Cache `ServerX` from primary connection; validate on each new socket |
| VPN Gate servers lack AAAA records | Dual-Stack | IPv4 always tried first; IPv6 is fallback-only |
| IPv6 MTU smaller (1280 min) | Dual-Stack | Adjust `RUDP_MAX_PAYLOAD_SIZE` dynamically based on `is_ipv6` |
| VpnService.protect() needs IPv6 socket | Both | Already supports any FD; pass IPv6 socket FD |
| No DHCPv6/SLAAC | IPv6 Tunnel | Not needed — server pushes IPv6 config via tunnel |
| RC4 low-level API removed/deprecated | OpenSSL Upgrade | Deprecated in 3.x but still compiles; keep direct `RC4()` calls with `-Wno-deprecated-declarations` or switch to EVP + legacy provider |
| OpenSSL 3.x cipher provider missing | OpenSSL Upgrade | AES/MD5/SHA1/ChaCha20 use default provider (auto-loaded); RC4/DES/Blowfish need legacy provider if switched to EVP |
| Prebuilt lib rebuild breaks link | OpenSSL Upgrade | Rebuild all 4 ABIs from 3.5.7 source with NDK; verify `libssl.a`/`libcrypto.a` symbols with `strings` |
| OpenSSL 4.0 breaking changes | OpenSSL Upgrade | Avoid 4.0 (major version); stay on 3.5 LTS until code is audited for 4.0 API changes |

---

## 9. Dependencies

| Dependency | Required By | Notes |
|------------|-------------|-------|
| zlib | Compression | Android NDK built-in system library; `compress2()` / `uncompress()` (RFC 1951 deflate) |
| OpenSSL 3.5 LTS | V2 AEAD, TLS, crypto | `EVP_chacha20_poly1305()`, `EVP_CTRL_AEAD_SET_IVLEN`, `EVP_CTRL_AEAD_GET_TAG`. Prebuilt for 4 ABIs in `jniLibs/` (currently 1.1.1w; upgrade to 3.5.7 in Phase 10) |
| POSIX sockets | All | `<sys/socket.h>`, `<netinet/in.h>` — already in use |
| Existing V1 infrastructure | All | Socket, polling, queue, keepalive — V2/compression/multi-connection build on top |

---

## 10. Testing Plan

| Test | Feature | Steps |
|------|---------|-------|
| RUDP V1 regression | V1 | Connect, send/receive VPN traffic, verify unchanged behavior |
| Compression send/receive | Compression | Enable `use_compress=1`, verify data arrives and is smaller on wire |
| Compress flag propagation | Compression | Verify `RUDP_FLAG_COMPRESSED` (0x01) is set in RUDP header when compressed |
| Small packet skip | Compression | Verify packets ≤1 byte are not compressed |
| V2 negotiation | V2 | Connect with `max_version=2`, check server responds `version=2` — 🚧 pending live-server interop; version advertisement is set to 2 |
| V2 data transfer | V2 | Send/receive VPN traffic over V2 channel — ✅ verified via `test_rudp_v2_loopback` (self-contained, on device) |
| V2 keepalive | V2 | Verify keepalive timing works identically to V1 — ✅ logic is version-agnostic (`rudp_process_inner`), covered by loopback |
| V2 fallback | V2 | If server sends `version=1` despite client advertising 2, confirm V1 is used — ✅ `rudp_set_version` falls back when V2 key/cipher missing |
| V2 AEAD failure | V2 | Corrupt a packet in transit, verify it's rejected (not accepted like V1 zero-verify) — ✅ covered by `test_rudp_v2_loopback` corrupt-MAC case |
| Multi-connection handshake | Multi-Connection | Request `max_connection=4`, verify server accepts |
| Multi-connection throughput | Multi-Connection | Measure throughput improvement with 2+ connections |
| Multi-connection resilience | Multi-Connection | Kill one socket, verify VPN continues on remaining connections |
| Additional connect method | Multi-Connection | Verify `"additional_connect"` method sent with session_key in logs |
| Multi-socket receive polling | Multi-Connection | Verify data arrives from multiple sockets in fill_recv_queue |
| Socket selection | Multi-Connection | Verify send uses lowest late_count socket |
| Socket protection | Multi-Connection | Verify additional sockets are protected via VpnService.protect() |
| Background connect non-blocking | Multi-Connection | Verify receive loop continues while additional connections are being established in background thread |
| Background connect cleanup | Multi-Connection | Disconnect during background connect, verify no crash/hang (pthread_join) |
| IPv6 tunnel address | IPv6 Tunnel | Verify VPN interface has per-install ULA (`fd00::<ANDROID_ID>/128`) — ✅ verified |
| IPv6 default route | IPv6 Tunnel | Verify `::/0` route added to VPN interface — ✅ verified |
| IPv6 DNS | IPv6 Tunnel | Verify `2001:4860:4860::8888` DNS server configured — ✅ verified |
| IPv6 traffic through tunnel | IPv6 Tunnel | Ping IPv6 endpoint through VPN tunnel — ✅ verified end-to-end (host `ping6 fd00::2` round-trips; phone reaches `2001:4860:4860::8888` via NAT66) |
| OpenVPN tun-ipv6 emitted | IPv6 OpenVPN | Generated config contains `tun-ipv6`; management log shows `IFCONFIG6` on connect |
| OpenVPN IPv6 routes | IPv6 OpenVPN | `::/0` (or server-pushed) IPv6 route installed; IPv6 site reachable over VPN Gate OpenVPN server |
| OpenVPN IPv6 fallback | IPv6 OpenVPN | Server without IPv6 push still connects (IPv4-only), no config error |
| SSTP IPv6CP enabled | IPv6 SSTP | `PPP_IPv6_ENABLED` set by app; connection log shows IPv6CP configure/ack |
| SSTP IPv6 tunnel | IPv6 SSTP | `FE80::/64` link-local + `::/0` installed; IPv6 destination reachable over MS-SSTP |
| SSTP no-IPv6 degrade | IPv6 SSTP | Server that rejects IPv6CP still connects IPv4-only — no `ERR_INVALID_ADDRESS` abort |
| Dual-stack DNS resolution | Dual-Stack | Verify `getaddrinfo` returns both A and AAAA |
| IPv6 TCP fallback | Dual-Stack | Block IPv4, verify connection succeeds over IPv6 |
| IPv6 RUDP socket | Dual-Stack | Verify `AF_INET6` UDP socket created for IPv6 peer |
| IPv6 PACK field | Dual-Stack | Verify `ClientIpv6Address` in login PACK when IPv6 |
| OpenSSL version check | OpenSSL Upgrade | Verify libcrypto.a reports 3.5.x via `strings` |
| OpenSSL RC4 regression | OpenSSL Upgrade | RUDP V1 data path still works after upgrade |
| OpenSSL TLS regression | OpenSSL Upgrade | TCP handshake against VPN Gate server succeeds |
| OpenSSL chacha20 availability | OpenSSL Upgrade | Confirm `EVP_chacha20_poly1305()` resolves (V2 readiness) |
| Wireshark capture | All | Capture traffic to verify correct packet formats |

---

## 11. References

| Topic | Source |
|-------|--------|
| RUDP V1 protocol | `src/Cedar/UdpAccel.c` / `UdpAccel.h` in SoftEtherVPN upstream |
| V1 constants | `UDP_ACCELERATION_COMMON_KEY_SIZE_V1=20`, `IV_SIZE_V1=20` |
| V2 constants | `UDP_ACCELERATION_COMMON_KEY_SIZE_V2=128`, `IV_SIZE_V2=12`, `MAC_SIZE_V2=16` |
| ChaCha20-Poly1305 | OpenSSL `EVP_chacha20_poly1305()`, RFC 7539 |
| Compression | zlib `compress2()` / `uncompress()` (RFC 1951 deflate) |
| Multi-connection | `ClientAdditionalConnect()` in `Protocol.c`, `TcpSockList` in `Connection.c` |
| Multi-connection constants | `MAX_TCP_CONNECTION=32`, `NUM_TCP_CONNECTION_FOR_UDP_RECOVERY=2`, `ADDITIONAL_CONNECTION_INTERVAL=1s` |
| IPv6 dual-stack connection | `ConnectEx4()` in `Network.c:16287-16759`, `GetIP46Ex()` |
| IPv6 UDP socket | `NewUDP6()` in `Network.c:12921`, `NewUdpAccel()` IPv6 handling in `UdpAccel.c:1145-1181` |
| IPv6 protocol info | `ClientIpAddress6`/`ServerIpAddress6` in `Protocol.c:4780-4825` |
| IPv6 hub filtering | `FilterIPv6`, `CheckIPv6`, `NoIPv6DefaultRouterInRA` in `Hub.c`, `Account.c` |
| OpenVPN IPv6 (`vpnLib`) | `ConfigParser.java:85` (`tun-ipv6`), `:398-405` (`route-ipv6`), `OpenVpnManagementThread.java:573-588` (`IFCONFIG6`/`ROUTE6`), `OpenVPNService.java:1385` (`setLocalIPv6`) |
| SSTP IPv6 (`sstpClient`) | `client/ppp/Ipv6cpClient.kt`, `terminal/IPTerminal.kt:68-82` (v6 tun), `preference/constant.kt:73` (`PPP_IPv6_ENABLED` default false) |
| OpenSSL versions | OpenSSL 3.5.7 (LTS, EOL 08 Apr 2030); 1.1.1w was final 1.1.1 release. Release strategy: https://openssl-library.org/policies/releasestrat/ |
| OpenSSL 3.x provider support | `OSSL_PROVIDER_load` default/legacy in `Encrypt.c:5156-5158`; RC4-MD5 3.0 bug note in `Encrypt.h:147` |

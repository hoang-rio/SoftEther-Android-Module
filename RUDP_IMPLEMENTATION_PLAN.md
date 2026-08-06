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
- `softether_rudp.h` / `softether_rudp.c`: V1 context struct, UDP socket creation, key generation
- V1 packet format: IV(20) + Cookie + MyTick + YourTick + Size + Flag + Data + Padding + Verify(20)
- RC4 encryption with SHA1(common_key ‖ IV) key derivation
- Window-based receive validation

### Phase 2: V1 Handshake Integration (✅ Complete)
- `softether_protocol.c`: `build_login_pack` sends `udp_acceleration_client_key`, `udp_acceleration_client_cookie`, `udp_acceleration_client_port`
- Welcome PACK parsing: extract server IP, port, key, cookies, version
- `rudp_init_client` called after login to set up peer address and keys

### Phase 3: V1 Data Path (✅ Complete)
- `softether_send_data`: RUDP send with `rudp_is_send_ready` gate, TCP fallback
- `softether_fill_recv_queue`: poll UDP socket, decode RUDP blocks, queue for Java
- RUDP receive queue with head/tail/count ring buffer

### Phase 4: V1 Hardening (✅ Complete)
- Keep-alive polling with configurable interval (normal 1-3s, fast 0.5-1s)
- 10-second continuous reception requirement (`RUDP_REQUIRE_CONTINUOUS`) before sending VPN data
- `VpnService.protect()` for UDP socket to prevent TUN routing loop
- DHCP over RUDP: poll UDP socket during DHCP wait loop
- Simultaneous RUDP+TCP polling with 100ms timeout (prevents receive loop spinning)
- Diagnostic logging for decompression failures in fallback path

### Phase 5: Compression Support (✅ Complete)
- ✅ Link zlib in CMakeLists.txt (Android NDK built-in)
- ✅ Implement zlib wrapper functions: `compress_data()`, `uncompress_data()`, `calc_compress_bound()`
- ✅ Enable `use_compress=1` in login PACK (`softether_protocol.c:637`)
- ✅ RUDP: always compress in `rudp_send()`, set `RUDP_FLAG_COMPRESSED` (`softether_rudp.c:519-532`)
- ✅ RUDP: decompress on receive if flag set (`softether_rudp.c:381-390`)
- ✅ TCP: always compress when `server_use_compress=1` (`packet_handler.c:259`)
- ✅ Skip compression for small packets (≤1 byte)
- ✅ Always-compress policy to prevent server inflate stream corruption

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

### Phase 9: Dual-Stack Socket Support (📋 Planned)
- [ ] Replace `sockaddr_in` with `sockaddr_storage` in `softether_socket.h`, `softether_rudp.h`
- [ ] Replace `gethostbyname()` with `getaddrinfo(AF_UNSPEC)` in `tcp_socket.c`
- [ ] Implement IPv4-first, IPv6-fallback in `socket_connect_timeout()`
- [ ] Support `AF_INET6` UDP socket creation in `rudp_create()` for IPv6 peers
- [ ] Adjust R-UDP MTU calculation for IPv6 header (40 bytes vs 20)
- [ ] Add `client_ip_v6`, `server_ip_v6`, `is_ipv6` fields to `softether_connection_t`
- [ ] Add `ClientIpv6Address` PACK field in `build_login_pack()`
- [ ] Replace `resolve_hostname()` with dual-stack resolution in `softether_connect_with_hub()`

### Phase 10: OpenSSL Upgrade to 3.5 LTS (📋 Planned)
- [ ] Rebuild prebuilt OpenSSL 3.5.x libs for all 4 ABIs (armeabi-v7a, arm64-v8a, x86, x86_64)
- [ ] Update `src/main/cpp/openssl` source tree to OpenSSL 3.5.7
- [ ] Replace `jniLibs/{abi}/libssl.a` and `libcrypto.a` with 3.5.x builds
- [ ] Address RC4 low-level deprecation in `softether_rudp.c` (`RC4()` calls)
- [ ] Verify `EVP_chacha20_poly1305()` availability (Phase 7 V2 prerequisite check)
- [ ] Verify TLS handshake, AES CBC/GCM, MD5/SHA1 against VPN Gate servers
- [ ] Run full instrumentation suite for regression

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
| VPN interface | ✅ IPv6 enabled | `fd00::2/128`, `::/0`, `2001:4860:4860::8888` in `SoftEtherVpnService.kt` |
| Protocol handshake | ❌ IPv4 only | `ClientIpAddress` as 32-bit int (`softether_protocol.c:659`) |
| Connection struct | ❌ IPv4 only | No `*_ip_v6` or `is_ipv6` fields |

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
    val localAddressV6: String = "fd00::2",
    val prefixLengthV6: Int = 128,
    val dnsServerV6: String = "2001:4860:4860::8888",
    val routesV6: List<Route> = listOf(Route("::", 0)),
)
```

**Step 2: Configure VPN interface in `SoftEtherVpnService.kt`** (✅ Done)

In `establishVpnInterface()` (`SoftEtherVpnService.kt:493-502`):
```kotlin
builder.addAddress(config.localAddressV6, config.prefixLengthV6)
builder.addRoute(route.address, route.prefixLength)  // ::/0
builder.addDnsServer(config.dnsServerV6)
```

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
- [x] VPN interface has IPv6 address (`fd00::2/128`) and default route (`::/0`)
- [x] IPv6 DNS server configured (`2001:4860:4860::8888`)
- [x] Connected devices can reach IPv6 endpoints through tunnel (NAT66 on the host; see field notes below)

Phase B (Dual-Stack Sockets):
- [ ] `resolve_hostname()` returns both IPv4 and IPv6 addresses
- [ ] TCP connection tries IPv4 first, falls back to IPv6
- [ ] R-UDP creates IPv6 UDP socket when peer is IPv6
- [ ] Login PACK includes `ClientIpv6Address` (16-byte DATA) when IPv6
- [ ] MTU adjusted for IPv6 header (40 bytes vs 20)
- [ ] Can connect to server over IPv6 when IPv4 is unavailable

> **Field notes (2026-08): host-side IPv6 delivery.** Phase A moves IPv6 packets through the L2 tunnel, but the reply path needs the host to deliver frames back to the phone. Two hard-won findings on the paid SoftEther server (hub `VPNGatePaid`, local TAP bridge):
> 1. The hub mangles ND: the host kernel never learns the phone's tun MAC by NUD (entries stay `FAILED`/`INCOMPLETE`) even though the phone answers every NS with a valid NA. Fix: static neighbor pin on the host (`ip -6 neigh replace fd00::2 lladdr <phone-mac> dev tap_net nud permanent`), re-learned per session because Android rotates the tun MAC on reconnect.
> 2. Global egress uses NAT66 (`ip6tables -t nat -A POSTROUTING -s fd00::/8 -o eth0 -j MASQUERADE`) plus `ndppd` with only `rule ::/0 { static }` to answer the phone's NS for global destinations. `radvd` must advertise **no prefix** and `AdvDefaultLifetime 0` so Android stops SLAAC-rotating addresses.
> Persistence for all of this lives in `server-setup/nat66/` (setup script + systemd units, incl. a self-healing 30s neighbor-pin timer).

---

## 7. OpenSSL Upgrade Details

### Current State

| Component | Status | Details |
|-----------|--------|---------|
| Prebuilt libs (`jniLibs/{abi}/libssl.a`, `libcrypto.a`) | ❌ 1.1.1w | Confirmed via `strings`; 11 Sep 2023 final 1.1.1 release |
| Source tree (`src/main/cpp/openssl`) | ❌ 1.1.1w | HEAD detached at `OpenSSL_1_1_1w`; git-ignored (local build artifact) |
| 1.1.1 series support | ❌ EOL | 1.1.1 EOL 11 Sep 2023; 1.1.1w is the last security-patched version |
| `RC4()` low-level usage | ⚠️ Deprecated in 3.x | `softether_rudp.c:473-475,614-616` — direct calls, still compile in 3.x |
| `EVP_chacha20_poly1305()` | ✅ Available | Needed for Phase 7 V2; present in 1.1.1 and 3.x |
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

**Step 2: Rebuild for all 4 ABIs with Android NDK**

Configure with Android NDK toolchain for each ABI:
```bash
export ANDROID_NDK_HOME=<path-to-ndk>
export ANDROID_API=23
perl Configure android-arm64 -D__ANDROID_API__=$ANDROID_API
make depend && make -j$(nproc)
# Repeat for android-arm, android-x86, android-x86_64
```

Install outputs to `jniLibs/{armeabi-v7a,arm64-v8a,x86,x86_64}/` as `libssl.a` + `libcrypto.a`.

**Step 3: Address RC4 deprecation**

`softether_rudp.c` uses direct `RC4()` calls. In OpenSSL 3.x these still compile but emit deprecation warnings. Options:
- **Keep direct calls** (simplest) — works in 3.x, suppress warnings with `-Wno-deprecated-declarations` for the file
- **Switch to EVP + legacy provider** (upstream approach) — load "legacy" provider, use `EVP_rc4()`/`EVP_CipherInit_ex`; requires provider init at startup

**Step 4: Verify Phase 7 V2 prerequisite**

`EVP_chacha20_poly1305()` must be confirmed available in the rebuilt 3.5.7 libs (it is, since OpenSSL 1.1.0).

**Step 5: Regression test**

- TLS handshake against VPN Gate servers (TCP path)
- RUDP V1 RC4 data path
- AES CBC/GCM, MD5/SHA1 usage in `aes_wrapper.c`
- Full instrumentation suite

### API Compatibility with Local Client Code

| API | Location | 3.5 Compatible |
|-----|----------|----------------|
| `EVP_aes_*_cbc()/gcm()` | `aes_wrapper.c:70-80` | ✅ Default provider |
| `EVP_md5()` / `EVP_sha1()` | `aes_wrapper.c:455,500` | ✅ Default provider |
| `EVP_chacha20_poly1305()` | Phase 7 (implemented) | ✅ Both 1.1.1 and 3.x |
| `RC4()` low-level | `softether_rudp.c:473-475,614-616` | ⚠️ Deprecated, still compiles |
| `SSL_CTX`, `SSL`, TLS | `aes_wrapper.c` | ✅ |
| `RAND_*` | `aes_wrapper.c` | ✅ |

### Files to Modify

| File | Change |
|------|--------|
| `src/main/cpp/openssl/` | Checkout OpenSSL 3.5.7 source (git-ignored, local only) |
| `src/main/jniLibs/{4 ABIs}/libssl.a` | Replace with 3.5.7 build |
| `src/main/jniLibs/{4 ABIs}/libcrypto.a` | Replace with 3.5.7 build |
| `softether_rudp.c` | Address RC4 deprecation (keep direct calls or switch to EVP+legacy) |
| `CMakeLists.txt` | Unchanged — paths stay the same |

### Success Criteria

- [ ] Prebuilt libs report `OpenSSL 3.5.x` (verify with `strings` on libcrypto.a)
- [ ] All 4 ABIs build and link
- [ ] `EVP_chacha20_poly1305()` resolves (Phase 7 V2 readiness)
- [ ] TCP/RUDP V1 connections work against VPN Gate servers
- [ ] No runtime errors from deprecated API removal
- [ ] Instrumentation suite passes

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
| IPv6 tunnel address | IPv6 Tunnel | Verify VPN interface has `fd00::2/128` address — ✅ verified |
| IPv6 default route | IPv6 Tunnel | Verify `::/0` route added to VPN interface — ✅ verified |
| IPv6 DNS | IPv6 Tunnel | Verify `2001:4860:4860::8888` DNS server configured — ✅ verified |
| IPv6 traffic through tunnel | IPv6 Tunnel | Ping IPv6 endpoint through VPN tunnel — ✅ verified end-to-end (host `ping6 fd00::2` round-trips; phone reaches `2001:4860:4860::8888` via NAT66) |
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
| OpenSSL versions | OpenSSL 3.5.7 (LTS, EOL 08 Apr 2030); 1.1.1w was final 1.1.1 release. Release strategy: https://openssl-library.org/policies/releasestrat/ |
| OpenSSL 3.x provider support | `OSSL_PROVIDER_load` default/legacy in `Encrypt.c:5156-5158`; RC4-MD5 3.0 bug note in `Encrypt.h:147` |

# SoftEther RUDP (Reliable UDP) Implementation Plan

## Overview
This document outlines the plan to implement SoftEther's UDP Acceleration (RUDP) protocol in the Android client. RUDP improves VPN performance by using UDP for data transport instead of TCP-over-HTTPS, which suffers from TCP-over-TCP meltdown issues.

**Goal:** Enable high-performance UDP data transport while maintaining backward compatibility with the existing TCP control channel.

---

## 1. Technical Analysis

### Protocol Versions

| Feature | V1 (Implemented) | V2 (Planned) |
|---------|-------------------|--------------|
| **Encryption** | RC4 (stream cipher) | ChaCha20-Poly1305 AEAD |
| **Key Derivation** | SHA1(common_key \|\| IV) per packet | Raw 128-byte key, persistent cipher context |
| **IV Size** | 20 bytes | 12 bytes |
| **Authentication** | 20-byte zero verify field | 16-byte Poly1305 MAC |
| **Security** | Stream cipher + manual verify | Authenticated encryption (AEAD) |
| **Common Key Size** | 20 bytes | 128 bytes |
| **Status** | ✅ **Implemented & Working** | 📋 **Planned** |

### Protocol Flow
1.  **Control Channel (TCP)**: The standard HTTPS/SoftEther connection is established first.
2.  **Negotiation**: During the handshake, the client advertises `support_udp_recovery=1` and `udp_acceleration_max_version=1` (will be `2` once V2 is implemented). The server responds with `udp_acceleration_version` (selected version), `udp_acceleration_server_ip`, `udp_acceleration_server_port`, `udp_acceleration_server_key`, and optionally `udp_acceleration_server_key_v2`.
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

### Packet Format (V2 - Planned)
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
- TCP poll timeout reduction (5ms) when RUDP active

### Phase 5: Compression Support (✅ Complete)
- ✅ Link zlib in CMakeLists.txt (Android NDK built-in)
- ✅ Implement zlib wrapper functions: `compress_data()`, `uncompress_data()`, `calc_compress_bound()`
- ✅ Enable `use_compress=1` in login PACK (`softether_protocol.c:636`)
- ✅ RUDP: auto-compress in `rudp_send()`, set `RUDP_FLAG_COMPRESSED` when smaller (`softether_rudp.c:447-455`)
- ✅ RUDP: decompress on receive if flag set (`softether_rudp.c:409-418`)
- ✅ TCP: compress when `server_use_compress` set (`packet_handler.c:173-183`)
- ✅ Skip compression for small packets (≤1 byte)

### Phase 6: NAT-T / NAT Traversal (📋 Planned)
- NAT-T server integration for clients behind symmetric NAT
- Port mapping discovery via NAT-T server
- Fallback to NAT-T when direct UDP fails

### Phase 7: Multi-Connection Support (📋 Planned)
- [ ] Extend `softether_connection_t` to manage multiple socket+SSL pairs (array/list)
- [ ] Send `max_connection=4` (or configurable) instead of hardcoded `1` in login PACK
- [ ] Implement `ClientAdditionalConnect`: open additional TCP sockets after initial connection
- [ ] Implement session key-based authentication for additional connections
- [ ] Add send-side socket selection (lowest latency)
- [ ] Add receive-side multi-socket polling
- [ ] Implement send quota partitioning: `MAX_SEND_SOCKET_QUEUE_SIZE / MaxConnection`
- [ ] Support `half_connection` mode (unidirectional sockets, optional)

### Phase 8: V2 Support (📋 Planned)
- [ ] Add V2 AEAD cipher context fields to `rudp_context_t`
- [ ] Init ChaCha20-Poly1305 cipher contexts in `rudp_init_client` / `rudp_init_server`
- [ ] Implement V2 send: AEAD encrypt inner fields, append 16-byte Poly1305 MAC
- [ ] Implement V2 receive: AEAD decrypt + MAC verify, parse inner fields
- [ ] Enable version negotiation: advertise `max_version=2`, remove V1 cap
- [ ] Free cipher contexts in `rudp_destroy`
- [ ] V2 MSS calculation (8 bytes less overhead than V1)

---

## 3. Compression Implementation Details

### Current State

| Component | Status | Details |
|-----------|--------|---------|
| `RUDP_FLAG_COMPRESSED` (0x01) | ✅ Used | Set automatically in `rudp_send()` when compressed payload is smaller |
| `use_compress` login PACK | ✅ Enabled | Set to 1 in `softether_protocol.c:636` |
| RUDP send | ✅ Compresses | `rudp_send()` auto-compresses, sets `RUDP_FLAG_COMPRESSED` flag |
| RUDP receive | ✅ Decompresses | `rudp_poll()` checks flag, calls `uncompress_data()` |
| TCP send | ✅ Compresses | `packet_handler.c` compresses when `server_use_compress` is set |
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

`softether_protocol.c:636`:
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
| `max_connection` in login PACK | Hardcoded to 1 | `softether_protocol.c:634` |
| `half_connection` in login PACK | Hardcoded to 0 | `softether_protocol.c:637` |
| Socket management | Single `socket_fd` / `ssl` / `ssl_ctx` | `softether_connection_t` has no array |
| `server_max_connection` | Parsed but never used | `softether_protocol.h:82` |
| Additional connections | Not implemented | No equivalent of `ClientAdditionalConnect()` |
| Traffic distribution | N/A | Single connection |

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
pack_add_int(&p, "half_connection", 0);        // keep 0 initially
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
| `udp_acceleration_max_version` | Hardcoded to 1 | `softether_protocol.c` |
| `rudp_bulk_max_version` | Hardcoded to 1 | `softether_protocol.c` |
| `udp_acceleration_server_key_v2` | Parsed but unused | `softether_protocol.h:83` |
| `v2_common_key` | Parsed but unused | `softether_connection_t` |
| V2 cipher context | Not implemented | No `EVP_CIPHER_CTX` for ChaCha20-Poly1305 |
| `rudp_set_version` | Caps at 1 | `softether_rudp.c` |

### How Upstream SoftEther V2 Works

V2 replaces RC4 + zero-verify with ChaCha20-Poly1305 AEAD:

- **Key exchange**: Server sends `udp_acceleration_server_key_v2` (128 bytes) during login. Client sends `udp_acceleration_client_key_v2` (128 bytes). These are used directly — no per-packet SHA1 derivation.
- **Cipher context**: A single `EVP_CIPHER_CTX` is created per direction (send/recv) and persists across packets. The ChaCha20 counter carries forward from packet to packet.
- **IV**: 12 bytes (vs V1's 20). After each encrypt/decrypt, `NextIv` is updated to the first 12 bytes of ciphertext.
- **MAC**: 16-byte Poly1305 tag appended after ciphertext (replaces V1's 20-byte zero verify).
- **Inner structure**: Same fields (Cookie, MyTick, YourTick, Size, Flag, Data, Padding) but encrypted as a single AEAD operation.

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

## 6. Risks & Mitigations

| Risk | Feature | Mitigation |
|------|---------|------------|
| CPU overhead on compress/decompress | Compression | Use `Z_DEFAULT_COMPRESSION` (level 6); skip compression for small packets (< 256 bytes) |
| Buffer overflow from decompression | Compression | Always check `uncompress()` return value; use `compressBound()` for max size estimates |
| Server doesn't honor `use_compress=0` | Compression | Server should respect client's setting; if not, disable compression and log error |
| OpenSSL prebuilt lib lacks `EVP_chacha20_poly1305()` | V2 | Verify with compile test; fallback to V1 if unavailable |
| Server doesn't support V2 | V2 | Graceful fallback — server responds with `version=1`, client stays on V1 |
| AEAD nonce reuse vulnerability | V2 | Always update `next_iv_v2` after each encrypt/decrypt (matching upstream) |
| V2 cipher context lifecycle | V2 | Create once in init, free in destroy — no per-packet allocation |
| Server rejects additional connections | Multi-Connection | Check `server_max_connection` from Welcome PACK; don't exceed it |
| Thread safety for concurrent send/recv | Multi-Connection | Use `write_mutex` per connection or per-socket locks |
| Memory overhead (multiple SSL contexts) | Multi-Connection | Limit to 4 connections initially; make configurable |
| TLS certificate reuse for additional connections | Multi-Connection | Cache `ServerX` from primary connection; validate on each new socket |

---

## 7. Dependencies

| Dependency | Required By | Notes |
|------------|-------------|-------|
| zlib | Compression | Android NDK built-in system library; `compress2()` / `uncompress()` (RFC 1951 deflate) |
| OpenSSL 1.1.1+ | V2 AEAD | `EVP_chacha20_poly1305()`, `EVP_CTRL_AEAD_SET_IVLEN`, `EVP_CTRL_AEAD_GET_TAG`. Android NDK bundles compatible version |
| POSIX sockets | All | `<sys/socket.h>`, `<netinet/in.h>` — already in use |
| Existing V1 infrastructure | All | Socket, polling, queue, keepalive — V2/compression/multi-connection build on top |

---

## 8. Testing Plan

| Test | Feature | Steps |
|------|---------|-------|
| RUDP V1 regression | V1 | Connect, send/receive VPN traffic, verify unchanged behavior |
| Compression send/receive | Compression | Enable `use_compress=1`, verify data arrives and is smaller on wire |
| Compress flag propagation | Compression | Verify `RUDP_FLAG_COMPRESSED` (0x01) is set in RUDP header when compressed |
| Small packet skip | Compression | Verify packets < 256 bytes are not compressed |
| V2 negotiation | V2 | Connect with `max_version=2`, check server responds `version=2` |
| V2 data transfer | V2 | Send/receive VPN traffic over V2 channel |
| V2 keepalive | V2 | Verify keepalive timing works identically to V1 |
| V2 fallback | V2 | If server sends `version=1` despite client advertising 2, confirm V1 is used |
| V2 AEAD failure | V2 | Corrupt a packet in transit, verify it's rejected (not accepted like V1 zero-verify) |
| Multi-connection handshake | Multi-Connection | Request `max_connection=4`, verify server accepts |
| Multi-connection throughput | Multi-Connection | Measure throughput improvement with 2+ connections |
| Multi-connection resilience | Multi-Connection | Kill one socket, verify VPN continues on remaining connections |
| Wireshark capture | All | Capture traffic to verify correct packet formats |

---

## 9. References

| Topic | Source |
|-------|--------|
| RUDP V1 protocol | `src/Cedar/UdpAccel.c` / `UdpAccel.h` in SoftEtherVPN upstream |
| V1 constants | `UDP_ACCELERATION_COMMON_KEY_SIZE_V1=20`, `IV_SIZE_V1=20` |
| V2 constants | `UDP_ACCELERATION_COMMON_KEY_SIZE_V2=128`, `IV_SIZE_V2=12`, `MAC_SIZE_V2=16` |
| ChaCha20-Poly1305 | OpenSSL `EVP_chacha20_poly1305()`, RFC 7539 |
| Compression | zlib `compress2()` / `uncompress()` (RFC 1951 deflate) |
| Multi-connection | `ClientAdditionalConnect()` in `Protocol.c`, `TcpSockList` in `Connection.c` |
| Multi-connection constants | `MAX_TCP_CONNECTION=32`, `NUM_TCP_CONNECTION_FOR_UDP_RECOVERY=2`, `ADDITIONAL_CONNECTION_INTERVAL=1s` |

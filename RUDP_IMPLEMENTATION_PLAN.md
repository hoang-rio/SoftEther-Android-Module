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
2.  **Negotiation**: During the handshake, the client advertises `support_udp_recovery=1` and `udp_acceleration_max_version=2`. The server responds with `udp_acceleration_version` (selected version), `udp_acceleration_server_ip`, `udp_acceleration_server_port`, `udp_acceleration_server_key`, and `udp_acceleration_server_key_v2`.
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

### Phase 5: V2 Support (📋 Planned)
- [ ] Add V2 AEAD cipher context fields to `rudp_context_t`
- [ ] Init ChaCha20-Poly1305 cipher contexts in `rudp_init_client` / `rudp_init_server`
- [ ] Implement V2 send: AEAD encrypt inner fields, append 16-byte Poly1305 MAC
- [ ] Implement V2 receive: AEAD decrypt + MAC verify, parse inner fields
- [ ] Enable version negotiation: advertise `max_version=2`, remove V1 cap
- [ ] Free cipher contexts in `rudp_destroy`
- [ ] V2 MSS calculation (8 bytes less overhead than V1)

### Phase 6: NAT-T / NAT Traversal (📋 Planned)
- NAT-T server integration for clients behind symmetric NAT
- Port mapping discovery via NAT-T server
- Fallback to NAT-T when direct UDP fails

---

## 3. V2 Implementation Details

### Files Modified

| File | Changes |
|---|---|
| `softether_rudp.h` | Add V2 cipher context fields (`evp_encrypt_ctx`, `evp_decrypt_ctx`, `v2_cipher_inited`) to `rudp_context_t` |
| `softether_rudp.c` | V2 send, V2 receive, V2 cipher init/destroy, version logic, MSS calculation |
| `softether_protocol.c` | Advertise `udp_acceleration_max_version=2`, `rudp_bulk_max_version=2` |

### Step 1: Add V2 cipher context to `rudp_context_t`

**File**: `softether_rudp.h`

Add to the context struct:
```c
// V2 AEAD cipher contexts (persistent, not per-packet)
void* evp_encrypt_ctx;   // EVP_CIPHER_CTX* for ChaCha20-Poly1305 encrypt
void* evp_decrypt_ctx;   // EVP_CIPHER_CTX* for ChaCha20-Poly1305 decrypt
int v2_cipher_inited;    // Whether V2 cipher contexts are ready
```

**Why persistent**: V2 keeps the cipher context alive across packets (unlike V1 which creates RC4 per-packet). The `NextIv_V2` is updated after each send/recv, and the cipher state carries the ChaCha20 counter forward.

### Step 2: Implement V2 cipher init in `rudp_init_client`

**File**: `softether_rudp.c`

After V1 key setup, when `server_key_size >= RUDP_COMMON_KEY_SIZE_V2`:
1. Create `EVP_CIPHER_CTX` for encrypt using `EVP_chacha20_poly1305()`
2. Set encrypt key = `ctx->my_key_v2` (our 128-byte key)
3. Set decrypt key = `server_key` (server's 128-byte key)
4. Store in `ctx->evp_encrypt_ctx` / `ctx->evp_decrypt_ctx`
5. Set `ctx->v2_cipher_inited = 1`

**OpenSSL API**:
```c
#include <openssl/evp.h>
EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();
EVP_EncryptInit_ex(enc_ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);
EVP_CIPHER_CTX_ctrl(enc_ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
EVP_EncryptInit_ex(enc_ctx, NULL, NULL, my_key_v2, NULL);
```

**Note**: OpenSSL 1.1.1+ supports `EVP_chacha20_poly1305()`. Android NDK bundles OpenSSL 1.1.1+.

### Step 3: Implement V2 send path

**File**: `softether_rudp.c` — `rudp_send()`

1. Write IV (12 bytes): `ctx->next_iv_v2`
2. Build inner plaintext: `[Cookie:4][MyTick:8][YourTick:8][Size:2][Flag:1][Data:N][Pad:M]`
3. Pad to `max_udp_packet_size - 12 (IV) - 16 (MAC)`
4. Encrypt + authenticate with AEAD:
   ```c
   EVP_EncryptInit_ex(ctx->evp_encrypt_ctx, NULL, NULL, NULL, ctx->next_iv_v2);
   EVP_EncryptUpdate(ctx->evp_encrypt_ctx, NULL, &outlen, inner, inner_size);
   EVP_EncryptFinal_ex(ctx->evp_encrypt_ctx, NULL, &outlen);
   EVP_CIPHER_CTX_ctrl(ctx->evp_encrypt_ctx, EVP_CTRL_AEAD_GET_TAG, 16, mac_tag);
   ```
5. Append 16-byte Poly1305 MAC tag
6. Update `ctx->next_iv_v2` = first 12 bytes of ciphertext (matching upstream)
7. Send via `sendto()`

### Step 4: Implement V2 receive path

**File**: `softether_rudp.c` — inside `rudp_poll()` receive loop

1. Extract IV (12 bytes) from packet start
2. Extract MAC tag (16 bytes) from packet end
3. Extract ciphertext (everything between IV and MAC)
4. Decrypt + verify with AEAD:
   ```c
   EVP_DecryptInit_ex(ctx->evp_decrypt_ctx, NULL, NULL, NULL, iv);
   EVP_CIPHER_CTX_ctrl(ctx->evp_decrypt_ctx, EVP_CTRL_AEAD_SET_TAG, 16, mac_tag);
   EVP_DecryptUpdate(ctx->evp_decrypt_ctx, NULL, &outlen, ciphertext, ciphertext_len);
   int ret = EVP_DecryptFinal_ex(ctx->evp_decrypt_ctx, NULL, &outlen);
   // ret == 1 means MAC verified, ret == 0 means authentication failure
   ```
5. Parse decrypted inner fields: Cookie, MyTick, YourTick, Size, Flag, Data
6. Update `ctx->next_iv_v2` = first 12 bytes of ciphertext
7. Queue data if present

### Step 5: Enable V2 version negotiation

**File**: `softether_protocol.c`

1. Advertise V2 capability: change `udp_acceleration_max_version` from `1` to `2`
2. Change `rudp_bulk_max_version` from `1` to `2`
3. Remove V1 cap in `rudp_set_version`: allow `version = min(version, 2)`

### Step 6: Clean up cipher contexts on destroy

**File**: `softether_rudp.c` — `rudp_destroy()`

```c
if (ctx->evp_encrypt_ctx) EVP_CIPHER_CTX_free(ctx->evp_encrypt_ctx);
if (ctx->evp_decrypt_ctx) EVP_CIPHER_CTX_free(ctx->evp_decrypt_ctx);
```

### Step 7: V2 MSS calculation

V2 IV is 12 bytes (vs V1 20), MAC is 16 bytes (vs V1 20 verify). Net: 8 bytes less overhead → MSS increases by 8.

---

## 4. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| OpenSSL prebuilt lib lacks `EVP_chacha20_poly1305()` | Verify with compile test; fallback to libsodium if unavailable |
| Server doesn't support V2 | Graceful fallback — server responds with `version=1`, client stays on V1 |
| AEAD nonce reuse vulnerability | Always update `next_iv_v2` after each encrypt/decrypt (matching upstream) |
| V2 cipher context lifecycle | Create once in init, free in destroy — no per-packet allocation |

---

## 5. Dependencies
*   **POSIX Sockets**: Standard `<sys/socket.h>`, `<netinet/in.h>`.
*   **OpenSSL 1.1.1+**: `EVP_chacha20_poly1305()` for V2 AEAD. Android NDK bundles compatible version.
*   **Existing V1**: V2 builds on top of V1 infrastructure (socket, polling, queue, keepalive).

---

## 6. Testing Plan
1.  **V1 Regression**: Connect with `max_version=1`, verify V1 still works unchanged.
2.  **V2 Negotiation**: Connect with `max_version=2`, check server responds `version=2`.
3.  **V2 Data**: Send/receive VPN traffic over V2 channel.
4.  **V2 Keepalive**: Verify keepalive timing works identically.
5.  **V2 Fallback**: If server sends `version=1` despite client advertising 2, confirm V1 is used.
6.  **V2 AEAD Failure**: Corrupt a packet in transit, verify it's rejected (not accepted like V1 zero-verify).
7.  **Wireshark**: Capture traffic to verify correct V1/V2 packet format.

---

## 7. References
- SoftEtherVPN Source: `src/Cedar/UdpAccel.c` / `UdpAccel.h`
- V1 constants: `UDP_ACCELERATION_COMMON_KEY_SIZE_V1=20`, `UDP_ACCELERATION_PACKET_IV_SIZE_V1=20`
- V2 constants: `UDP_ACCELERATION_COMMON_KEY_SIZE_V2=128`, `UDP_ACCELERATION_PACKET_IV_SIZE_V2=12`, `UDP_ACCELERATION_PACKET_MAC_SIZE_V2=16`
- OpenSSL API: `EVP_chacha20_poly1305()`, `EVP_CTRL_AEAD_SET_IVLEN`, `EVP_CTRL_AEAD_GET_TAG`, `EVP_CTRL_AEAD_SET_TAG`

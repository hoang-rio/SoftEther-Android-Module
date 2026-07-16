# SoftEther RUDP (Reliable UDP) Implementation Plan

## Overview
This document outlines the plan to implement SoftEther's UDP Acceleration (RUDP) protocol in the Android client. RUDP improves VPN performance by using UDP for data transport instead of TCP-over-HTTPS, which suffers from TCP-over-TCP meltdown issues.

**Goal:** Enable high-performance UDP data transport while maintaining backward compatibility with the existing TCP control channel.

---

## 1. Technical Analysis

### Protocol Versions

| Feature | V1 (Current) | V2 (Planned) |
|---------|--------------|--------------|
| **Encryption** | RC4 (stream cipher) | ChaCha20-Poly1305 AEAD |
| **Key Derivation** | SHA1(common_key \|\| IV) | HKDF-like with 128-byte keys |
| **IV Size** | 20 bytes | 12 bytes |
| **Authentication** | 20-byte zero verify field | 16-byte Poly1305 MAC |
| **Security** | Stream cipher + manual verify | Authenticated encryption (AEAD) |
| **Key Size** | 20 bytes | 128 bytes |
| **Status** | ✅ **Implemented & Working** | 📋 **Planned** |

### Protocol Flow
1.  **Control Channel (TCP)**: The standard HTTPS/SoftEther connection is established first.
2.  **Negotiation**: During the handshake, the client advertises `support_udp_recovery=1`. The server responds with `udp_acceleration_server_ip`, `udp_acceleration_server_port`, `udp_acceleration_server_key`, and `udp_acceleration_client_key`.
3.  **NAT Traversal**: The client sends UDP packets to the server's UDP port to "punch" a hole in the NAT.
4.  **Data Transport**: Once the server receives the UDP packets and verifies the key, it switches data transmission to UDP. Control packets (KeepAlive) may continue on TCP or move to UDP.

### Packet Format (V1 - Implemented)
SoftEther RUDP V1 packets are encrypted and authenticated:
-   **IV**: Initialization Vector (20 bytes, random).
-   **Cookie**: 4-byte session identifier (encrypted).
-   **My Tick / Your Tick**: 8-byte timestamps for windowing (big-endian).
-   **Inner Size**: 2-byte payload length (big-endian).
-   **Flag**: 1-byte flags (compression, etc.).
-   **Payload**: Encrypted data (RC4 with key derived from SHA1(common_key \|\| IV)).
-   **Padding + Verify**: Random padding + 20-byte zero verify field.
-   **Reliability**: Sequence numbers and ACKs ensure delivery and ordering, mimicking a TCP stream over UDP.

---

## 2. Implementation Status

### Phase 1-4: V1 Implementation (✅ **Complete**)
- `softether_rudp.h` / `softether_rudp.c`: V1 context, packet build/parse, encryption/decryption
- Handshake integration in `softether_protocol.c`: parse Welcome PACK for UDP params
- Data path integration: `softether_send_data` / `softether_receive_data` with UDP/TCP fallback
- Keep-alive polling: `rudp_poll` in receive loop
- DHCP support over RUDP: poll UDP socket in DHCP wait loop
- Socket protection: `VpnService.protect()` for RUDP UDP fd to prevent TUN routing loop

### Phase 5: V2 Support (📋 **Planned**)
- Implement ChaCha20-Poly1305 AEAD encryption
- 128-byte common keys + HKDF key derivation
- 12-byte IV + 16-byte Poly1305 MAC
- V2 packet format (different from V1)
- Version negotiation (server supports both, client selects highest common)

### Phase 6: NAT-T / NAT Traversal (📋 **Planned**)
- NAT-T server integration for clients behind symmetric NAT
- Port mapping discovery via NAT-T server
- Fallback to NAT-T when direct UDP fails

---

## 3. Dependencies
*   **POSIX Sockets**: Use standard `<sys/socket.h>`, `<netinet/in.h>`.
*   **OpenSSL**: Use existing `softether_crypto` wrappers for RC4/AES and HMAC-SHA1.
*   **Threads**: Use `pthread` for background keep-alive if necessary (or integrate into main non-blocking loop).
*   **V2**: Will require ChaCha20-Poly1305 implementation (OpenSSL 1.1.1+ or libsodium).

---

## 4. Testing Plan
1.  **Unit Test**: Create a mock UDP server to verify packet formatting and encryption.
2.  **Integration Test**: Connect to a known SoftEther server with UDP enabled.
3.  **Wireshark**: Capture traffic to verify UDP packets are flowing and falling back to TCP when blocked.
4.  **V2 Test**: Once implemented, test V2 handshake and AEAD packet format.

---

## 5. References
- SoftEtherVPN Source: `src/Cedar/UdpAccel.c` / `UdpAccel.h`
- Official protocol constants match: `UDP_ACCELERATION_COMMON_KEY_SIZE_V1=20`, `UDP_ACCELERATION_PACKET_IV_SIZE_V1=20`, etc.
# SoftEther RUDP (Reliable UDP) Implementation Plan

## Overview
This document outlines the plan to implement SoftEther's UDP Acceleration (RUDP) protocol in the Android client. RUDP improves VPN performance by using UDP for data transport instead of TCP-over-HTTPS, which suffers from TCP-over-TCP meltdown issues.

**Goal:** Enable high-performance UDP data transport while maintaining backward compatibility with the existing TCP control channel.

---

## 1. Technical Analysis

### Protocol Flow
1.  **Control Channel (TCP)**: The standard HTTPS/SoftEther connection is established first.
2.  **Negotiation**: During the handshake, the client advertises `support_udp_recovery=1`. The server responds with `udp_acceleration_server_ip`, `udp_acceleration_server_port`, `udp_acceleration_server_key`, and `udp_acceleration_client_key`.
3.  **NAT Traversal**: The client sends UDP packets to the server's UDP port to "punch" a hole in the NAT.
4.  **Data Transport**: Once the server receives the UDP packets and verifies the key, it switches data transmission to UDP. Control packets (KeepAlive) may continue on TCP or move to UDP.

### Packet Format (Based on SoftEther Source)
SoftEther RUDP packets are encrypted and authenticated.
-   **IV**: Initialization Vector (random).
-   **MAC**: Message Authentication Code (HMAC-SHA1 or similar).
-   **Payload**: Encrypted data (likely RC4 or AES, depending on negotiation).
-   **Reliability**: Sequence numbers and ACKs are used to ensure delivery and ordering, mimicking a TCP stream over UDP.

---

## 2. Implementation Steps

### Phase 1: Data Structures & Infrastructure
Create `softether_rudp.h` and `softether_rudp.c`.

*   **`softether_rudp_context_t`**:
    *   `int udp_socket_fd`: The UDP socket.
    *   `struct sockaddr_in server_addr`: Server's UDP address.
    *   `uint8_t client_key[20]`: Key for sending.
    *   `uint8_t server_key[20]`: Key for receiving.
    *   `uint32_t my_cookie`: Client session ID.
    *   `uint32_t your_cookie`: Server session ID.
    *   `uint64_t next_iv`: For encryption.
    *   `uint32_t seq_num`: Outgoing sequence number.
    *   `uint32_t ack_num`: Incoming ACK number.
    *   `bool active`: Flag indicating if UDP is currently working.

### Phase 2: Handshake Integration
Modify `softether_protocol.c`: `softether_connect_with_hub`.

*   **Parsing**: After the main login PACK is processed, check for:
    *   `udp_acceleration_server_ip`
    *   `udp_acceleration_server_port`
    *   `udp_acceleration_server_key`
    *   `udp_acceleration_client_key`
    *   `udp_acceleration_server_cookie`
    *   `udp_acceleration_client_cookie`
*   **Initialization**: If parameters are present, call `softether_rudp_init()` to set up the UDP socket and context.

### Phase 3: RUDP Protocol Logic
Implement core functions in `softether_rudp.c`.

*   **`softether_rudp_handshake()`**:
    *   Send initial "Hello" packets to the server's UDP port.
    *   These packets contain the `client_cookie` and `server_cookie` to verify identity.
    *   Repeat until a valid response is received or timeout.

*   **`softether_rudp_send(ctx, data, len)`**:
    *   Encapsulate data: `IV + MAC + Encrypt(Payload)`.
    *   Send via `sendto()`.
    *   Handle sequence numbers (if using full reliable mode) or raw tunneling.

*   **`softether_rudp_receive(ctx, buffer, max_len)`**:
    *   Receive via `recvfrom()`.
    *   Verify MAC.
    *   Decrypt payload.
    *   Check sequence numbers (deduplication/ordering).

### Phase 4: Integration with Data Loop
Modify the main data loop in `softether_protocol.c` (or `ConnectionController` logic).

*   **`softether_send_data()`**:
    *   Check `conn->rudp->active`.
    *   If active, try `softether_rudp_send()`.
    *   If RUDP send fails or is inactive, fall back to `softether_send_packet()` (TCP).

*   **`softether_read_data()`**:
    *   Use `poll()` or `select()` to listen on **both** the TCP socket and the UDP socket.
    *   If UDP socket is readable -> `softether_rudp_receive()`.
    *   If TCP socket is readable -> `softether_receive_raw()`.

### Phase 5: Keep-Alive & Reliability
*   **Heartbeat**: Send periodic UDP keep-alives (empty packets or special command) to keep the NAT mapping open.
*   **Failover**: If UDP packets stop arriving (timeout), set `rudp->active = false` and revert to TCP. Retry RUDP handshake periodically.

---

## 3. Dependencies
*   **POSIX Sockets**: Use standard `<sys/socket.h>`, `<netinet/in.h>`.
*   **OpenSSL**: Use existing `softether_crypto` wrappers for RC4/AES and HMAC-SHA1.
*   **Threads**: Use `pthread` for background keep-alive if necessary (or integrate into main non-blocking loop).

## 4. Testing Plan
1.  **Unit Test**: Create a mock UDP server to verify packet formatting and encryption.
2.  **Integration Test**: Connect to a known SoftEther server with UDP enabled.
3.  **Wireshark**: Capture traffic to verify UDP packets are flowing and falling back to TCP when blocked.

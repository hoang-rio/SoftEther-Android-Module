# SoftEther VPN Protocol Implementation Plan

## Overview
This document outlines the plan for implementing SoftEther VPN protocol in C language within the SoftEtherClient Android module.

**Target Repository:** `git@github.com:hoang-rio/SoftEtherVPN_Stable.git`  
**Submodule:** `SoftEtherClient/` (points to `git@github.com:hoang-rio/SoftEther-Android-Module.git`)  
**Integration:** Android VPN app with existing OpenVPN and SSTP support

---

## Progress Tracker

- [x] Analyze existing project structure and VPN implementation patterns
- [x] Create comprehensive implementation plan for SoftEther VPN protocol
- [x] Design Android instrumentation tests for JNI level testing
- [x] Phase 1: Set up SoftEtherClient module structure and build system
  - [x] Create build.gradle with NDK configuration
  - [x] Create CMakeLists.txt for native build
  - [x] Create AndroidManifest.xml
  - [x] Create proguard-rules.pro
  - [x] Create consumer-rules.pro
  - [x] Create directory structure
  - [x] Create JNI headers
  - [x] Create Kotlin service and model classes
  - [x] Create instrumentation test framework
- [x] Phase 2: Implement C/C++ native code with JNI bridge
  - [x] softether_jni.h - JNI bridge header with all native method declarations
  - [x] softether_jni.c - JNI bridge implementation
  - [x] softether_protocol.h - Core protocol definitions and structures
  - [x] softether_protocol.c - Protocol implementation (connect, auth, session)
  - [x] softether_crypto.h - Crypto wrapper header
  - [x] aes_wrapper.c - AES encryption/decryption, SHA256, HMAC, SSL/TLS
  - [x] softether_socket.h - Socket wrapper header
  - [x] tcp_socket.c - TCP socket operations with timeout support
  - [x] serializer.c - Packet serialization/deserialization
  - [x] packet_handler.c - Packet send/receive handling
  - [x] native_test.h - Native test framework header
  - [x] native_test.c - Native test implementations
  - [x] test_jni_bridge.c - JNI bridge for instrumentation tests
- [x] Phase 3: Implement Kotlin/Java layer (VPN service, controller, client)
  - [x] SoftEtherClient.kt - JNI bridge wrapper with high-level API
  - [x] SoftEtherVpnService.kt - Android VPN service with notifications
  - [x] ConnectionController.kt - Connection lifecycle management with data forwarding
  - [x] ConnectionConfig.kt - Configuration data class with Parcelable
  - [x] Exceptions.kt - Custom exceptions and error codes
  - [x] Protocol package:
    - [x] PacketHandler.kt - Packet handling and SoftEtherPacket data class
    - [x] HandshakeManager.kt - Protocol handshake management
    - [x] KeepAliveManager.kt - Keepalive management with statistics
  - [x] Auth package:
    - [x] AuthManager.kt - Authentication management with credentials
  - [x] Terminal package:
    - [x] SSLTerminal.kt - SSL/TLS utilities and certificate pinning
    - [x] TunTerminal.kt - TUN interface management
  - [x] Util package:
    - [x] ByteBufferUtil.kt - ByteBuffer operations and hex dump
    - [x] CryptoUtil.kt - Cryptographic utilities and Android Keystore integration
- [x] Phase 4: Implement protocol-specific logic (handshake, auth, data tunnel)
  - [x] Native data tunnel functions (softether_send_data, softether_receive_data)
  - [x] Reconnection support (softether_reconnect, softether_set_reconnect_enabled)
  - [x] ConnectionController data forwarding loops (TUN <-> VPN)
  - [x] Automatic reconnection logic with retry and backoff
  - [x] Keepalive handling and connection monitoring
  - [x] Connection statistics tracking
- [ ] Phase 5: Integrate with main Android app
- [ ] Phase 6: Implement Android instrumentation tests for native code
- [ ] Phase 7: Testing and validation against vpngate.net servers
- [ ] Documentation and code review

---

## Phase 4 Summary: Protocol-Specific Logic Implementation

Phase 4 has been completed with the following implementations:

### Native Layer (C/C++)

**softether_protocol.h:**
- Added data tunnel operation declarations:
  - `softether_send_data()` - Send data packets through VPN tunnel
  - `softether_receive_data()` - Receive data packets with command type detection
- Added reconnection support:
  - `softether_set_reconnect_enabled()` - Enable/disable auto-reconnect
  - `softether_reconnect()` - Reconnect using stored credentials

**softether_protocol.c:**
- Implemented `softether_send_data()` - Sends raw data as DATA packets
- Implemented `softether_receive_data()` - Handles DATA, KEEPALIVE, DISCONNECT commands
- Implemented `softether_set_reconnect_enabled()` - Configures reconnection preference
- Implemented `softether_reconnect()` - Attempts reconnection with stored credentials

### Kotlin Layer

**ConnectionController.kt:**
- Complete data forwarding implementation:
  - Send loop: TUN → VPN
  - Receive loop: VPN → TUN
- Automatic reconnection logic with configurable max attempts
- Connection statistics tracking (bytes/packets)
- Keepalive monitoring with timeout detection

**PacketHandler.kt:**
- Added `pollSendQueue()` method for non-blocking packet retrieval

### Key Features
1. **Protocol Handshake**: TCP → TLS → Version negotiation → Auth → Session setup
2. **Data Tunnel**: Bidirectional packet forwarding
3. **Auto-Reconnection**: Configurable retry with exponential backoff
4. **Keepalive**: Proper keepalive packet exchange
5. **Statistics**: Real-time bytes/packets tracking

---

## Architecture Analysis

### Existing Pattern (from sstpClient module)

| Component | File | Responsibility |
|-----------|------|----------------|
| VPN Service | `SstpVpnService.kt` | Android VpnService lifecycle, notifications, permissions |
| Controller | `Controller.kt` | Connection lifecycle manager coordinating all components |
| Protocol Client | `SstpClient.kt` | Protocol-specific implementation (SSTP packets, handshakes) |
| SSL Terminal | `SSLTerminal.kt` | TLS/SSL socket handling |
| IP Terminal | `IPTerminal.kt` | Android VPN interface (Tun) management |
| PPP Clients | `LCPClient.kt`, `PAPClient.kt`, etc. | Authentication and IP configuration |

### SoftEther VPN Protocol Characteristics

- **SSL-VPN over HTTPS**: Uses HTTP upgrade mechanism similar to WebSocket
- **VPN over ICMP**: Optional ICMP tunneling
- **VPN over DNS**: Optional DNS tunneling
- **Native SoftEther Protocol**: Custom binary protocol over TCP
- **Encryption**: AES, RSA, TLS 1.2/1.3
- **Authentication**: Password, Certificate, RADIUS, LDAP

---

## Phase 1: Project Structure & Build System

### 1.1 Module Directory Structure

```
SoftEtherClient/
├── build.gradle                    # Android library build config with NDK
├── CMakeLists.txt                  # CMake build for C code
├── proguard-rules.pro              # ProGuard configuration
├── src/
│   ├── androidTest/                # Instrumentation tests
│   │   └── java/vn/unlimit/softether/test/
│   │       ├── NativeConnectionTest.kt
│   │       ├── VpngateServerProvider.kt
│   │       ├── TestConfig.kt
│   │       └── model/
│   │           └── NativeTestResult.kt
│   ├── main/
│   │   ├── AndroidManifest.xml     # VPN service permissions
│   │   ├── java/
│   │   │   └── vn/unlimit/softether/
│   │   │       ├── SoftEtherVpnService.kt
│   │   │       ├── controller/
│   │   │       │   └── ConnectionController.kt
│   │   │       ├── client/
│   │   │       │   ├── SoftEtherClient.kt
│   │   │       │   ├── protocol/
│   │   │       │   │   ├── PacketHandler.kt
│   │   │       │   │   ├── HandshakeManager.kt
│   │   │       │   │   └── KeepAliveManager.kt
│   │   │       │   └── auth/
│   │   │       │       ├── AuthManager.kt
│   │   │       │       ├── PasswordAuth.kt
│   │   │       │       └── CertificateAuth.kt
│   │   │       ├── terminal/
│   │   │       │   ├── SSLTerminal.kt
│   │   │       │   └── TunTerminal.kt
│   │   │       ├── model/
│   │   │       │   ├── ConnectionConfig.kt
│   │   │       │   ├── ServerInfo.kt
│   │   │       │   └── SessionState.kt
│   │   │       └── util/
│   │   │           ├── ByteBufferUtil.kt
│   │   │           └── CryptoUtil.kt
│   │   └── cpp/
│   │       ├── CMakeLists.txt
│   │       ├── softether-core/
│   │       │   ├── src/
│   │       │   │   ├── proto/
│   │       │   │   │   └── softether_protocol.c
│   │       │   │   ├── crypto/
│   │       │   │   │   └── aes_wrapper.c
│   │       │   │   ├── socket/
│   │       │   │   │   └── tcp_socket.c
│   │       │   │   └── packet/
│   │       │   │       ├── packet_handler.c
│   │       │   │       └── serializer.c
│   │       │   └── include/
│   │       │       ├── softether_protocol.h
│   │       │       ├── softether_crypto.h
│   │       │       └── softether_socket.h
│   │       ├── jni/
│   │       │   ├── softether_jni.c
│   │       │   └── softether_jni.h
│   │       └── test/
│   │           ├── native_test.c
│   │           ├── native_test.h
│   │           └── test_jni_bridge.c
│   └── test/
│       └── java/
└── libs/                           # Prebuilt libs if needed
```

---

## Phase 4: Protocol Implementation

### 4.1 SoftEther SSL-VPN Protocol Flow

```
Client                              Server
  |                                   |
  |-------- TCP Connect ------------->|
  |-------- TLS Handshake ---------->|
  |<-------- TLS Handshake ---------|
  |-------- HELLO (Version) -------->|
  |<-------- HELLO_ACK (Version) ----|
  |-------- AUTH_REQUEST ----------->|
  |<-------- AUTH_CHALLENGE ---------|
  |-------- AUTH_RESPONSE ---------->|
  |<-------- AUTH_SUCCESS/FAIL -----|
  |-------- SESSION_REQUEST -------->|
  |<-------- SESSION_ASSIGN ---------|
  |-------- CONFIG_REQUEST --------->|
  |<-------- CONFIG_RESPONSE --------|
  |<====== Data Tunnel ============>>|
  |-------- KEEPALIVE -------------->|
  |<-------- KEEPALIVE_ACK ---------|
  |-------- DISCONNECT ------------->|
  |<-------- DISCONNECT_ACK --------|
```

### 4.2 Authentication Methods

- Anonymous (certificate only)
- Password (MS-CHAPv2, PAP)
- Certificate + Password

---

## Technical Considerations

### NDK & Native Code
- Use NDK r25c or newer
- Target API 21+ (Android 5.0)
- Support 4 architectures: armeabi-v7a, arm64-v8a, x86, x86_64

### Security
- Pin server certificates
- Use TLS 1.3 when available
- Secure credential storage (Android Keystore)
- Memory scrubbing for sensitive data

### Performance
- Use native sockets for better performance
- Implement proper buffering
- Consider multi-threading for I/O

### Compatibility
- SoftEther VPN Server 4.x and 5.x
- Various authentication methods
- Different virtual hub configurations

---

*Last Updated: 2026-02-12*
*Status: Phase 4 Complete - Ready for Phase 5 (Main App Integration)*

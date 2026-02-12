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
- [x] Phase 5: Integrate with main Android app
- [x] Phase 6: Implement Android instrumentation tests for native code
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

## Phase 5 Summary: Main App Integration

Phase 5 has been completed with full integration of SoftEther VPN into the main Android app:

### Issue Fixed: Cancel Button During Connection
**Problem:** When pressing the cancel button while SoftEther was connecting, the disconnect request was not being sent to the SoftEther VPN service, causing the connection to continue in the background.

**Solution:**
1. Added `isSoftEtherConnecting` flag in `DetailActivity.kt` to track when a SoftEther connection is in progress
2. Modified the cancel button handler to check this flag and call `disconnectSoftEther()` instead of `stopVpn()` when appropriate
3. Updated `SoftEtherVpnService.kt` to:
   - Track the connection coroutine job (`connectionJob`) for proper cancellation
   - Handle `CancellationException` when user cancels during connection
   - Properly clean up resources in `onDestroy()`
4. Updated `ConnectionController.kt` to:
   - Check `isCancelled` flag at key points during connection
   - Throw `CancellationException` when cancelled during connection
   - Properly handle disconnect during connection state

**Files Modified:**
- `app/src/main/java/vn/unlimit/vpngate/activities/DetailActivity.kt`
- `SoftEtherClient/src/main/java/vn/unlimit/softether/SoftEtherVpnService.kt`
- `SoftEtherClient/src/main/java/vn/unlimit/softether/controller/ConnectionController.kt`


### UI Components

**VpnProtocolSelectionDialog.kt:**
- Bottom sheet dialog for selecting VPN protocol
- Shows available protocols: OpenVPN (TCP/UDP) and SoftEther VPN
- Protocol availability indicators with port information
- Clean Material Design 3 UI with card-based layout
- Server info display (hostname, location)

**dialog_vpn_protocol_selection.xml:**
- Header with server name and close button
- Server info section with icon and details
- Three protocol options in card format:
  - OpenVPN TCP with port status
  - OpenVPN UDP with port status  
  - SoftEther VPN with protocol type
- Visual feedback for unavailable protocols (dimmed)
- Navigation arrows for each option

### Connection Management

**SoftEtherConnectionHelper.kt:**
- Manages SoftEther VPN connection lifecycle
- VPN permission handling with ActivityResultLauncher
- Connection state broadcast receiver
- SharedPreferences for connection persistence
- Excluded apps support for split tunneling

**Key Features:**
- `connect()` - Initiates connection with VPN permission check
- `disconnect()` - Clean disconnect from VPN
- `isConnected()` - Check current connection state
- `isConnectedTo()` - Check if connected to specific server
- Connection state listener interface for UI updates

**Integration with DetailActivity:**
The existing DetailActivity has been extended to support SoftEther:
- Protocol selection dialog on connect button press
- SoftEther connection state management
- UI updates for SoftEther connection status
- Disconnect handling for SoftEther connections
- Firebase Analytics tracking for SoftEther connections

### String Resources

**New strings added:**
- `select_vpn_protocol` - Dialog title
- `available_protocols` - Section header
- `openvpn_tcp`, `openvpn_udp`, `softether_vpn` - Protocol names
- `protocol_available_port` - Port info format
- `softether_available` - Status text
- `connecting_softether`, `softether_connected` - Connection status
- `softether_disconnected`, `softether_disconnected_by_error` - Disconnection status

### Connection Flow

```
User taps Connect button
        ↓
Protocol Selection Dialog opens
        ↓
User selects SoftEther VPN
        ↓
VPN Permission Check
        ↓
SoftEtherVpnService starts with connection extras
        ↓
Connection established → UI updates with status
        ↓
Broadcast sent → HomeFragment/StatusFragment update
```

### Compatibility

- **OpenVPN**: Existing OpenVPN integration remains unchanged
- **SSTP**: MS-SSTP integration remains unchanged
- **L2TP**: L2TP instructions remain unchanged
- **SoftEther**: New protocol added alongside existing options

### Key Design Decisions

1. **Bottom Sheet Dialog**: Used instead of new buttons to keep UI clean and consistent with Material Design 3
2. **Protocol Selection**: Users can see all available protocols in one place
3. **Availability Indicators**: Protocols not available for a server are shown but disabled
4. **State Persistence**: Connection state saved in SharedPreferences for app restart handling
5. **Broadcast Communication**: Uses LocalBroadcastManager for service-to-activity communication
6. **Helper Pattern**: SoftEtherConnectionHelper follows same pattern as existing SSTP integration

---

## Phase 6 Summary: Android Instrumentation Tests

Phase 6 has been completed with comprehensive Android instrumentation tests for native code:

### Native Test Layer (C/C++)

**native_test.h:**
- Test result structure with success status, error code, message, and duration
- Test configuration structure with host, port, credentials, timeouts
- Function declarations for 8 test types:
  - `test_tcp_connection()` - Basic TCP connectivity
  - `test_tls_handshake()` - TLS/SSL handshake validation
  - `test_softether_handshake()` - Protocol version negotiation
  - `test_authentication()` - User credential validation
  - `test_session()` - Full session establishment
  - `test_data_transmission()` - Data packet send/receive
  - `test_keepalive()` - Keepalive packet exchange
  - `test_full_lifecycle()` - Complete connection flow

**native_test.c:**
- Complete implementations for all 8 test types
- Proper resource management and cleanup
- Detailed logging with Android logcat
- Support for VPNGate server testing with "vpn"/"vpn" credentials
- Keepalive testing with configurable duration
- Data transmission testing with packet count and size parameters

**test_jni_bridge.c:**
- JNI bridge for all native test functions
- Proper Java string to C string conversion
- NativeTestResult object creation for Kotlin interop
- Error handling and resource cleanup

### Kotlin Test Layer

**NativeConnectionTest.kt:**
- JUnit4 instrumentation test runner
- 9 comprehensive test methods:
  - `testTcpConnection()` - Verify TCP connectivity
  - `testTlsHandshake()` - Verify TLS handshake
  - `testSoftEtherHandshake()` - Verify protocol handshake
  - `testAuthentication()` - Verify authentication
  - `testSessionEstablishment()` - Verify session setup
  - `testDataTransmission()` - Verify data transfer
  - `testKeepalive()` - Verify keepalive handling
  - `testFullConnectionLifecycle()` - Verify complete flow
  - `testMultipleServers()` - Test against multiple servers
- Native library loading with error handling
- VPNGate server provider integration

**VpngateServerProvider.kt:**
- Fetches server list from VPNGate API
- Caching with 5-minute TTL
- CSV parsing for server data
- Server filtering by score, ping, speed
- SoftEther compatibility detection

**ServerAvailabilityChecker.kt:**
- Pre-test server availability validation
- TCP connectivity checks
- TLS handshake verification
- Batch availability checking
- Server availability status reporting

**TestResultReporter.kt:**
- Comprehensive test result reporting
- Markdown report generation
- File output with automatic cleanup
- Test run summary with success rates
- Device and Android version logging

**TestConfig.kt:**
- Test timeout constants (10s - 40s)
- Default packet parameters (10 packets, 1024 bytes)
- Keepalive test duration (30 seconds)
- Retry settings (3 retries, 2s delay)
- VPNGate default credentials (vpn/vpn)
- Server filtering criteria

**NativeTestResult.kt:**
- Parcelable data class for native test results
- Error code constants matching native implementation
- Secondary constructor for JNI compatibility
- Error message resolution

### Model Classes

**SessionState.kt:**
- Parcelable session state data class
- Session ID, IP addresses, DNS servers
- Traffic statistics (bytes/packets)
- Connection timing information
- SessionStatistics helper class for tracking

### Build Configuration

**CMakeLists.txt:**
- Separate libraries: `softether` (main) and `softether_test` (test)
- OpenSSL linking for both libraries
- Prebuilt library support
- Debug/Release compiler flags

**build.gradle:**
- Test instrumentation runner configuration
- Native library build configuration
- Test dependencies (JUnit, Espresso, Coroutines)

### Test Execution

Tests can be run via:
```bash
./gradlew :SoftEtherClient:connectedAndroidTest
```

Or specific test classes:
```bash
./gradlew :SoftEtherClient:connectedAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=vn.unlimit.softether.test.NativeConnectionTest
```

### Key Features
1. **Real Server Testing**: Tests run against live VPNGate servers
2. **Comprehensive Coverage**: 8 test types covering all protocol layers
3. **Detailed Reporting**: Markdown reports with full test history
4. **Server Availability**: Pre-check servers before testing
5. **Error Classification**: Native error codes map to meaningful messages
6. **Resource Management**: Proper cleanup in all test paths

---

*Last Updated: 2026-02-12*
*Status: Phase 5 & 6 Complete - Ready for Phase 7 (Testing & Validation)*

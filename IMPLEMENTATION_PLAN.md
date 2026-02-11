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
- [ ] Phase 4: Implement protocol-specific logic (handshake, auth, data tunnel)
- [ ] Phase 5: Integrate with main Android app
- [ ] Phase 6: Implement Android instrumentation tests for native code
- [ ] Phase 7: Testing and validation against vpngate.net servers
- [ ] Documentation and code review

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

### 1.2 Build Configuration

#### SoftEtherClient/build.gradle
```gradle
plugins {
    id 'com.android.library'
}

android {
    namespace 'vn.unlimit.softether'
    compileSdk = project.ext.compileSdkVersion

    defaultConfig {
        minSdkVersion project.ext.minSdkVersion
        targetSdkVersion project.ext.targetSdkVersion

        externalNativeBuild {
            cmake {
                cppFlags "-O2 -fPIC"
                cFlags "-O2 -fPIC"
                arguments "-DANDROID_STL=c++_shared"
            }
        }
        ndk {
            abiFilters 'armeabi-v7a', 'arm64-v8a', 'x86', 'x86_64'
        }
    }

    externalNativeBuild {
        cmake {
            path "src/main/cpp/CMakeLists.txt"
            version "3.22.1"
        }
    }

    buildTypes {
        release {
            minifyEnabled false
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
    }
}

dependencies {
    implementation 'androidx.core:core-ktx:1.12.0'
    implementation 'org.bouncycastle:bcprov-jdk15on:1.70'
    
    // Test dependencies
    androidTestImplementation 'androidx.test.ext:junit:1.1.5'
    androidTestImplementation 'androidx.test:runner:1.5.2'
    androidTestImplementation 'androidx.test:rules:1.5.0'
    androidTestImplementation 'org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3'
}
```

#### SoftEtherClient/src/main/cpp/CMakeLists.txt
```cmake
cmake_minimum_required(VERSION 3.22.1)
project("softetherclient")

# Find packages
find_library(log-lib log)
find_library(android-lib android)

# OpenSSL for crypto
find_package(OpenSSL REQUIRED)

# Source files for main library
set(SOURCES
    jni/softether_jni.c
    softether-core/src/proto/softether_protocol.c
    softether-core/src/crypto/aes_wrapper.c
    softether-core/src/socket/tcp_socket.c
    softether-core/src/packet/packet_handler.c
    softether-core/src/packet/serializer.c
)

# Create main shared library
add_library(softether SHARED ${SOURCES})

target_include_directories(softether PRIVATE
    softether-core/include
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(softether
    ${log-lib}
    ${android-lib}
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Test library
set(TEST_SOURCES
    test/native_test.c
    test/test_jni_bridge.c
    ${SOURCES}
)

add_library(softether_test SHARED ${TEST_SOURCES})

target_include_directories(softether_test PRIVATE
    softether-core/include
    ${OPENSSL_INCLUDE_DIR}
    test
)

target_link_libraries(softether_test
    ${log-lib}
    ${android-lib}
    OpenSSL::SSL
    OpenSSL::Crypto
)
```

### 1.3 Main App Integration

Add to `app/build.gradle`:
```gradle
dependencies {
    // ... existing dependencies
    implementation project(path: ':SoftEtherClient')
}
```

---

## Phase 2: C/C++ Native Implementation

### 2.1 JNI Bridge Header

**src/main/cpp/jni/softether_jni.h**
```c
#ifndef SOFTETHER_JNI_H
#define SOFTETHER_JNI_H

#include <jni.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Connection management
JNIEXPORT jlong JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeCreate(
    JNIEnv *env, jobject thiz);

JNIEXPORT void JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeDestroy(
    JNIEnv *env, jobject thiz, jlong handle);

JNIEXPORT jint JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeConnect(
    JNIEnv *env, jobject thiz, jlong handle, jstring host, jint port, 
    jstring username, jstring password);

JNIEXPORT void JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeDisconnect(
    JNIEnv *env, jobject thiz, jlong handle);

// Data I/O
JNIEXPORT jint JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeSend(
    JNIEnv *env, jobject thiz, jlong handle, jbyteArray data, jint length);

JNIEXPORT jint JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeReceive(
    JNIEnv *env, jobject thiz, jlong handle, jbyteArray buffer, jint maxLength);

// Configuration
JNIEXPORT void JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeSetOption(
    JNIEnv *env, jobject thiz, jlong handle, jint option, jlong value);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_JNI_H
```

### 2.2 Protocol Packet Structure

```c
typedef struct {
    uint32_t signature;      // 'SETH' = 0x53455448
    uint16_t version;
    uint16_t command;
    uint32_t payload_length;
    uint32_t session_id;
    uint32_t sequence_num;
    uint8_t  payload[];
} softether_packet_header_t;

// Command types
#define CMD_CONNECT         0x0001
#define CMD_AUTH            0x0002
#define CMD_SESSION         0x0003
#define CMD_DATA            0x0004
#define CMD_KEEPALIVE       0x0005
#define CMD_DISCONNECT      0x0006
#define CMD_ERROR           0x00FF
```

---

## Phase 3: Kotlin/Java Layer

### 3.1 Key Components

| Component | Purpose |
|-----------|---------|
| `SoftEtherVpnService` | Android VpnService implementation |
| `ConnectionController` | Orchestrates connection flow |
| `SoftEtherClient` | JNI bridge wrapper |
| `SSLTerminal` | TLS socket management |
| `TunTerminal` | Android TUN interface |

### 3.2 Connection Flow

```
1. Initialize SSL/TLS terminal
2. Perform SoftEther handshake
3. Authenticate user
4. Configure VPN interface (TUN)
5. Start data forwarding loops
6. Handle reconnection logic
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

## Phase 6: Android Instrumentation Tests

### 6.1 Test Architecture

Test native implementation directly without requiring VPN Service:
- Connect to real SoftEther VPN servers from vpngate.net
- Validate handshake, authentication, and data transmission at socket level

### 6.2 Test Files

| File | Purpose |
|------|---------|
| `NativeConnectionTest.kt` | Main test suite |
| `VpngateServerProvider.kt` | Fetch servers from vpngate.net |
| `TestConfig.kt` | Test configuration constants |
| `NativeTestResult.kt` | Test result data class |
| `native_test.c` | Native test implementations |
| `test_jni_bridge.c` | JNI bridge for tests |

### 6.3 Test Coverage

| Test | Description | Validates |
|------|-------------|-----------|
| `testTcpConnection` | Basic TCP socket connection | Network connectivity |
| `testTlsHandshake` | TLS/SSL handshake | Certificate validation |
| `testSoftEtherHandshake` | SoftEther protocol hello | Protocol compatibility |
| `testAuthentication` | User authentication | Auth methods |
| `testSession` | Session establishment | Virtual hub, IP allocation |
| `testDataTransmission` | Send/receive packets | Data integrity, throughput |
| `testKeepalive` | Connection stability | Keepalive mechanism |
| `testFullConnectionLifecycle` | Complete flow | End-to-end implementation |
| `testMultipleServers` | Cross-server testing | Server compatibility |

### 6.4 Running Tests

```bash
# Run all instrumentation tests
./gradlew :SoftEtherClient:connectedAndroidTest

# Run specific test class
./gradlew :SoftEtherClient:connectedAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=vn.unlimit.softether.test.NativeConnectionTest

# Run specific test method
./gradlew :SoftEtherClient:connectedAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=vn.unlimit.softether.test.NativeConnectionTest#testFullConnectionLifecycle
```

---

## Phase 7: Testing Against vpngate.net

### 7.1 VPNGate Server Configuration

VPNGate servers typically use:
- **Username:** `vpn`
- **Password:** `vpn`
- **Ports:** 443 (HTTPS), 992, 5555
- **Protocol:** SoftEther SSL-VPN

### 7.2 Test Scenarios

1. Connect to multiple VPNGate servers
2. Test different authentication methods
3. Validate data throughput
4. Test connection stability
5. Verify proper disconnection

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

## Implementation Timeline

| Phase | Task | Estimated Time |
|-------|------|----------------|
| 1 | Module structure and build.gradle | 2 hours |
| 1 | CMakeLists.txt configuration | 3 hours |
| 2 | JNI bridge headers | 4 hours |
| 2 | Core protocol implementation in C | 40 hours |
| 2 | OpenSSL crypto integration | 8 hours |
| 3 | SoftEtherVpnService implementation | 6 hours |
| 3 | ConnectionController implementation | 10 hours |
| 3 | SoftEtherClient Kotlin layer | 8 hours |
| 4 | Protocol testing and debugging | 20 hours |
| 5 | Main app integration | 6 hours |
| 6 | Android instrumentation tests | 12 hours |
| 7 | vpngate.net testing | 8 hours |
| 8 | Documentation and review | 6 hours |
| **Total** | | **~133 hours** |

---

## References

1. **SoftEther VPN Protocol:** https://github.com/SoftEtherVPN/SoftEtherVPN
2. **Android VPN Service:** https://developer.android.com/reference/android/net/VpnService
3. **Android NDK:** https://developer.android.com/ndk/guides
4. **VPNGate API:** http://www.vpngate.net/api/iphone/
5. **SoftEther VPN_Stable:** `git@github.com:hoang-rio/SoftEtherVPN_Stable.git`

---

## Notes

- This implementation focuses on SSL-VPN protocol (HTTPS over port 443)
- ICMP and DNS tunneling modes are not in scope for initial implementation
- Native tests can run without VPN Service permission
- All tests should pass against real VPNGate servers before production release

---

*Last Updated: 2026-02-11*
*Status: Planning Phase*

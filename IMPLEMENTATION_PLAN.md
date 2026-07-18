# SoftEther VPN Protocol Implementation Plan

## Overview
This document outlines the plan for implementing SoftEther VPN protocol in C language within the SoftEtherClient Android module.

**Target Repository:** https://github.com/SoftEtherVPN/SoftEtherVPN_Stable  
**Submodule:** `SoftEtherClient/` (points to `https://github.com/hoang-rio/SoftEther-Android-Module.git`)  
**Integration:** Android VPN app with existing OpenVPN and SSTP support

---

## Progress Tracker

- [x] Analyze existing project structure and VPN implementation patterns
- [x] Create comprehensive implementation plan for SoftEther VPN protocol
- [x] Design Android instrumentation tests for JNI level testing
- [x] Phase 1: Set up SoftEtherClient module structure and build system
- [x] Phase 2: Implement C/C++ native code with JNI bridge
- [x] Phase 3: Implement Kotlin/Java layer (VPN service, controller, client)
- [x] Phase 4: Implement protocol-specific logic (handshake, auth, data tunnel)
- [x] Phase 5: Integrate with main Android app
- [x] Phase 6: Implement Android instrumentation tests for native code
- [x] Phase 7: Testing and validation against vpngate.net servers
- [x] Root cause analysis and protocol fixes

---

## Current Status (2026-03-09)

### Implementation Complete ✅

All core implementation phases are complete and stable:
- ✅ Protocol implementation with VPNGate HTTP POST steps
- ✅ JNI bridge and native libraries
- ✅ Kotlin/Java VPN service and controller
- ✅ Android instrumentation tests
- ✅ App integration with OpenVPN, SoftEther, and MS-SSTP
- ✅ Domain-to-IP resolution before TLS handshake (matching SoftEther client behavior)
- ✅ Redundant DNS lookup elimination in TCP socket layer
- ✅ Enhanced SSL error logging with errno and OpenSSL error details

### Key Improvements (2026-02-27 → 2026-03-09)

**1. TLS Domain Resolution (softether_protocol.c):**
- Resolve domain to IP upfront in `softether_connect_with_hub()` 
- Use resolved IP for both TCP connect and TLS handshake
- Eliminates duplicate DNS lookups and matches original SoftEther client behavior

**2. TCP Socket Optimization (tcp_socket.c):**
- `socket_connect_timeout()` now uses `inet_pton()` to detect if host is already a dotted-decimal IP
- Skips redundant `resolve_hostname()` call when host is pure IP string
- Result: single "Resolved X to X" log for both IP and domain inputs

**3. SSL Error Diagnostics (aes_wrapper.c):**
- Enhanced `SSL_ERROR_SYSCALL` logging with errno, strerror, and ERR_get_error() details
- Helps identify handshake failures (connection reset, EOF, timeout, etc.)

**4. UI/State Logging Cleanup (SoftEtherVpnService.kt, DetailActivity.kt):**
- Omit empty `ip=` suffix when assigned IP is not yet populated
- Clean logs for CONNECTING/DISCONNECTING states (only show `ip=` in CONNECTED state)

**5. MS-SSTP Protocol Dialog Integration (VpnProtocolSelectionDialog.kt, DetailActivity.kt):**
- Merged standalone MS-SSTP button into protocol selection dialog
- Protocol order: SoftEther TCP → SoftEther UDP → OpenVPN TCP → OpenVPN UDP → MS-SSTP
- Full button state lifecycle for SSTP (Cancel while connecting, Disconnect while connected)
- Wired SSTP connect/disconnect through protocol dialog callback

### Protocol Support

| Transport | Status |
|-----------|--------|
| TCP (SoftEther over HTTPS/TLS) | ✅ Supported |
| UDP (SoftEther RUDP) | ✅ V1 Working (See [RUDP_IMPLEMENTATION_PLAN.md](RUDP_IMPLEMENTATION_PLAN.md)) |

**TCP** connects via the SoftEther HTTPS/TLS channel on the server's SE-VPN TCP port.

**UDP (RUDP) V1** is implemented and working. Data is transported via UDP with RC4 encryption, keepalive polling, and TCP fallback. V2 (ChaCha20-Poly1305 AEAD) is planned.

---

## Protocol Flow (COMPLETE)

```
Client                              Server
  |                                   |
  |-------- TCP Connect ------------->|
  |-------- TLS Handshake ----------->|
  |<-------- TLS Handshake ----------|
  |-------- HTTP GET / X-VPN: 1 ----->|  (HTTP Detection)
  |<-------- HTTP 403 Forbidden -----|
  |-------- POST /vpnsvc/connect.cgi -->|  (Watermark)
  |<-------- HTTP 200 + Hello PACK --|  ← Server sends Hello here!
  |-------- POST /vpnsvc/vpn.cgi ----->|  (AUTH via HTTP)
  |<-------- HTTP 200 + AUTH_OK -----|  ← Auth success!
  |-------- POST /vpnsvc/vpn.cgi ----->|  (SESSION via HTTP) ← NEW!
  |<-------- HTTP 200 + SESSION -----|  ← Session established!
  ...
```

---

## Files Modified (2026-03-09)

### Native C Code
- `SoftEtherClient/src/main/cpp/softether-core/src/proto/softether_protocol.c`
  - Resolve domain to IP upfront via `resolve_hostname()` in `softether_connect_with_hub()`
  - Pass resolved IP (not domain) to both `socket_connect_timeout()` and `perform_tls_handshake()`
  
- `SoftEtherClient/src/main/cpp/softether-core/src/socket/tcp_socket.c`
  - Add `inet_pton()` check before DNS lookup in `socket_connect_timeout()`
  - Skip redundant `resolve_hostname()` when host is already a dotted-decimal IP

- `SoftEtherClient/src/main/cpp/softether-core/src/crypto/aes_wrapper.c`
  - Enhanced `SSL_ERROR_SYSCALL` logging: errno, strerror, ERR_get_error() details

### Kotlin Layer
- `SoftEtherClient/src/main/java/vn/unlimit/softether/SoftEtherVpnService.kt`
  - Omit `ip=` suffix when assigned IP is empty in state logs
  
- `SoftEtherClient/src/main/java/vn/unlimit/softether/controller/ConnectionController.kt`
  - (No changes in 2026-03-09; maintains existing state management)

### App Module (Main App Integration)
- `app/src/main/java/vn/unlimit/vpngate/dialog/VpnProtocolSelectionDialog.kt`
  - Add MS-SSTP to protocol enum
  - Reorder protocols: SoftEther TCP/UDP first, OpenVPN TCP/UDP second, MS-SSTP last
  - Show/hide MS-SSTP card based on `connection.isSSTPSupport()`

- `app/src/main/res/layout/dialog_vpn_protocol_selection.xml`
  - Reorder protocol cards to match new preference order

- `app/src/main/java/vn/unlimit/vpngate/activities/DetailActivity.kt`
  - Update `connectSSTPVPN()`: set button state (Cancel + orange) while connecting
  - Update `initSSTP()`: set button state on connection/disconnection in prefs listener
  - Update `handleSSTPBtn()`: set button state (Connect) when disconnecting
  - Handle SSTP connected state in `onClick()` → `handleSSTPBtn()`
  - Handle SSTP cancel in `isConnecting` path → `startVpnSSTPService(DISCONNECT)`
  - Remove standalone `btn_sstp_connect` button from `activity_detail.xml`

- `app/src/main/res/layout/activity_detail.xml`
  - Remove `ln_sstp_btn` LinearLayout and `btn_sstp_connect` Button

- `app/src/main/res/values/strings.xml`
  - Add `ms_sstp` string resource

### Documentation
- `SoftEtherClient/README.md`
  - Add Protocol Support section documenting TCP (supported) and UDP (planned)
  
- `SoftEtherClient/IMPLEMENTATION_PLAN.md` (this file)
  - Updated status, key improvements, protocol support table

---

## Build Commands
```bash
./gradlew :SoftEtherClient:assembleDebug
./gradlew :SoftEtherClient:installDebugAndroidTest
./gradlew :SoftEtherClient:connectedDebugAndroidTest
```

### APK Output
- `SoftEtherClient/build/outputs/apk/androidTest/debug/SoftEtherClient-debug-androidTest.apk`

---

## Remaining Tasks

1. **UDP (RUDP) Support**
   - Implement reliable UDP transport layer with sequence numbers, ACKs, retransmission
   - Add NAT traversal support
   - Integrate with existing native layer

2. **Additional Stability & Testing**
   - Run full instrumentation suite periodically
   - Validate behavior across diverse VPNGate server profiles
   - Monitor for any edge cases in domain resolution or SSL handshakes

3. **Optional Cleanup (Non-blocking)**
   - Address compiler warnings (unused helpers, deprecated connectivity broadcast)

---

*Last Updated: 2026-03-09*
*Status: ✅ TCP protocol fully working, dialog merged, domain→IP resolution implemented, button states consistent with OpenVPN/SoftEther*

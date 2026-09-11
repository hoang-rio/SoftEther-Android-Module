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

## Current Status

### Implementation Complete ✅

All core phases (1–7) done. Key deliverables:
- SoftEther protocol (TCP + RUDP V1/V2), JNI bridge, Kotlin VPN service, instrumentation tests
- App integration with OpenVPN, SoftEther, MS-SSTP
- Compression, simultaneous RUDP+TCP polling, `protect(rudpFd)` routing fix

### Protocol Support

| Transport | Status |
|-----------|--------|
| TCP (SoftEther over HTTPS/TLS) | ✅ Supported |
| UDP (SoftEther RUDP) | ✅ V1 + V2 Working (See [RUDP_IMPLEMENTATION_PLAN.md](RUDP_IMPLEMENTATION_PLAN.md)) |

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

1. **V2 (ChaCha20-Poly1305 AEAD)** — ✅ **Complete (2026-08)** — See [RUDP_IMPLEMENTATION_PLAN.md](RUDP_IMPLEMENTATION_PLAN.md) Phase 7
2. **Additional Stability & Testing** — run instrumentation suite periodically, validate across VPNGate profiles, monitor edge cases

---

## Optimization Findings (2026-09-10)

Audit of `SoftEtherClient` (Kotlin + native C) vs the official `SoftEtherVPN_Stable` reference (`Mayaqua/Network.c`, `Cedar/Protocol.c`, `Cedar/Listener.c`). Ranked by priority.

### P0 — Correctness / Crash — ✅ All done (2026-09-10)

| # | Issue | Commit |
|---|-------|--------|
| 1 | `disconnect()` `tryLock()` guard for `unlock()` | `6650927` |
| 2 | Native error codes mapped via `SoftEtherError.getErrorString()` | `1ca0e00` |
| 3 | `attemptReconnect()` sets `STATE_ERROR` before disconnect | `95e01d4` |
| 4 | `protectedFds` cleared on teardown, `synchronizedSet` | `ec6cc00` |

### P1 — Performance — #6,#7 done (2026-09-10)

| # | Issue | Location | Fix | Status |
|---|-------|----------|-----|--------|
| 5 | TX globally serialized by single `write_mutex` — even full-duplex (4× BOTH) sends one packet at a time | `packet_handler.c:356` | Split to per-connection transmit locks (Phase 17.1 in RUDP plan) | ⏳ |
| 6 | `Thread.sleep(200)` destroy heuristic — `nativeDestroy` can block on `connect_mutex` if TLS read is slow | `ConnectionController.kt:626` | Replace with a CountDownLatch or CompletableDeferred signaled by the connect flow | ✅ `b6060c6` |
| 7 | Duplicate `SoftEtherError`/`ConnectionException` definitions — file-level shadows model imports, drift risk | `SoftEtherClient.kt:456,461` vs `model/Exceptions.kt:6,26` | Keep only `model/` versions; remove file-level duplicates | ✅ `f876db8` |

### P2 — Parity with Official Client

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 8 | ARP reply for LAN-side queries — proxy ARP reply exists (`softether_reply_arp_request` in `softether_protocol.c:2904-2930`), but gratuitous ARP advertisement is still missing | `softether_protocol.c` (reply), `dhcp_client.c` (no gratuitous) | Add gratuitous ARP broadcast after IP assignment (see `SoftEtherVPN_Stable/src/Cedar/Virtual.c`) |
| 9 | ~~RUDP keepalive interval not randomized~~ | `softether_rudp.c:728-729` | ✅ Done — `rand() % (ka_max - ka_min) + ka_min` already in direct RUDP + NAT-T paths |
| 10 | ~~RUDP `current_rtt` dedup only on `your_tick` advance~~ | `rudp_transport.c:627-634` | ✅ Done — sampled on `latest_recv_my_tick` advance, deduped via `latest_recv_my_tick2` (see RUDP plan Open Item 4) |

### P3 — Code Quality / Dead Code

| # | Issue | Location | Fix |
|---|-------|----------|-----|
| 11 | 7 dead Kotlin files never referenced from main code | `PacketHandler.kt`, `HandshakeManager.kt`, `AuthManager.kt`, `SSLTerminal.kt`, `SessionState.kt`, `ByteBufferUtil.kt`, `CryptoUtil.kt` | Delete; `PacketHandler.kt` has wrong wire-format model (20-byte `SETH`) that misleads readers |
| 12 | Dead legacy path in `SoftEtherClient.kt` | `connect()` :35-120, `setAuthType` :126, `setMaxConnection` :141, `getNumConnections` :160, `setKeepAliveInterval` :283, `setMtu` :294, `cleanup` :303 | Remove; live path goes through `ConnectionController.performConnectInner()` → `nativeConnectWithHub` |
| 13 | ~~JNI test natives declared in header but no C implementation~~ | `softether_jni.h:63-97` | ✅ Done — implemented in `cpp/test/test_jni_bridge.c`, compiled into `softether_test` lib, loaded by androidTest |
| 14 | Two TODO no-ops in JNI (keepalive interval, MTU) | `softether_jni.c:473,477` | Implement or remove the option codes |
| 15 | `@Suppress("DEPRECATION")` ×4 in VpnService | `SoftEtherVpnService.kt:146/:262/:421/:847` | Migrate to `ContextCompat` equivalents |
| 16 | Two `mainHandler` instances (companion + instance) | `SoftEtherVpnService.kt:90` vs `:734` | Consolidate into one |

---

### Recommended execution order

```
P0 correctness (#1–#4) ✅ → P1 perf (#5–#7, #6/#7 done) → P2 parity (#8–#10, #9/#10 done) → P3 cleanup (#11–#16, #13 done)
```

Multi-connection support from the original Remaining Tasks is superseded by the throughput optimization plan in [RUDP_IMPLEMENTATION_PLAN.md](RUDP_IMPLEMENTATION_PLAN.md) Phase 13–17.

---

*Last Updated: 2026-09-11*
*Status: ✅ TCP + RUDP V1 + V2 working, compression implemented; P0 done, P1 done (#5 pending), P2 partially done (#8 partial, #9/#10 done), P3 partially done (#13 done)*

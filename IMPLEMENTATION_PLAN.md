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

## Optimization Findings — ✅ all done (2026-09-21)

Audit of `SoftEtherClient` (Kotlin + native C) vs the official `SoftEtherVPN_Stable` reference (`Mayaqua/Network.c`, `Cedar/Protocol.c`, `Cedar/Listener.c`). All items shipped; full per-item rationale lives in git history (commits below).

### P0 — Correctness / Crash — ✅ `6650927`, `1ca0e00`, `95e01d4`, `ec6cc00`

| # | Issue |
|---|-------|
| 1 | `disconnect()` `tryLock()` guard for `unlock()` |
| 2 | Native error codes mapped via `SoftEtherError.getErrorString()` |
| 3 | `attemptReconnect()` sets `STATE_ERROR` before disconnect |
| 4 | `protectedFds` cleared on teardown, `synchronizedSet` |

### P1 — Performance — ✅ `d225f44`, `b6060c6`, `f876db8`

| # | Issue |
|---|-------|
| 5 | TX globally serialized by single `write_mutex` → per-link I/O locks (`conn->io_mutex` + `additional[i].io_mutex`): I/O on different links now independent, slow `SSL_write` can't stall staging/reads/keepalives on healthy links; `write_mutex` kept for `send_block` staging + teardown, slot retirement holds the same `io_mutex` (order `ssl_lifetime → write_mutex → io`, io a leaf) |
| 6 | `Thread.sleep(200)` destroy heuristic → latch signaled by the connect flow |
| 7 | Duplicate `SoftEtherError`/`ConnectionException` definitions — file-level shadows removed |

### P2 — Parity with Official Client — ✅ `f463b41`

| # | Issue |
|---|-------|
| 8 | Gratuitous ARP broadcast after IP assignment |
| 9 | RUDP keepalive interval — already randomized (`rand() % (ka_max - ka_min) + ka_min` in direct RUDP + NAT-T) |
| 10 | RUDP `current_rtt` dedup — already sampled on `latest_recv_my_tick` advance |

### P3 — Code Quality / Dead Code — ✅ `b035495`, `0e44c67`, `415873e`, `35c5060`, `a00469b`

| # | Issue |
|---|-------|
| 11 | 7 dead Kotlin files deleted (incl. wrong 20-byte `SETH` wire model in `PacketHandler.kt`) |
| 12 | Dead legacy path removed from `SoftEtherClient.kt`; live path is `ConnectionController.performConnectInner()` → `nativeConnectWithHub` |
| 13 | JNI test natives implemented in `cpp/test/test_jni_bridge.c` (compiled into `softether_test` lib) |
| 14 | Two TODO no-ops in JNI removed (keepalive interval, MTU) |
| 15 | `@Suppress("DEPRECATION")` ×4 in VpnService → AndroidX equivalents |
| 16 | Duplicate `mainHandler` consolidated |

---

### Execution order

```
P0 correctness (#1–#4) ✅ → P1 perf (#5–#7) ✅ → P2 parity (#8–#10) ✅ → P3 cleanup (#11–#16) ✅
```

Multi-connection support from the original Remaining Tasks is superseded by the throughput optimization plan in [RUDP_IMPLEMENTATION_PLAN.md](RUDP_IMPLEMENTATION_PLAN.md) Phase 13–17 (all done).

---

*Last Updated: 2026-09-21*
*Status: ✅ TCP + RUDP V1 + V2 working, compression implemented; P0–P3 all done. Only open item: periodic on-device instrumentation / regression runs (Remaining Tasks §2).*

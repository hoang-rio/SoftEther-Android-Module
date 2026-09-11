# SoftEther RUDP Implementation Plan

## Overview

Android client for VPN Gate servers using SoftEther's UDP transport protocols.

**Key architectural finding (2026-08-19):** OpenVPN UDP and SoftEther R-UDP are **separate independent listeners** on the VPN server. The CSV column `SEUdpPort` does NOT mean SoftEther R-UDP is available on that port. For "UDP-only" servers (`SETcpPort=0`), the R-UDP/NAT-T transport is broken — the only working UDP is OpenVPN (listed separately on vpngate.net). The VPN Gate official client has no private API; `VGate.c` is an empty DLL stub. "UDP: Supported" under SSL-VPN on vpngate.net refers to R-UDP via NAT-T relay, which fails for UDP-only servers.

---

## Server Architecture (VPN Gate)

```
VPN Server
├── SoftEther TCP (port X)           ← SSL-VPN TCP (works)
├── SoftEther R-UDP (port 0=random)  ← SSL-VPN UDP (registered with NAT-T relay)
│   └── For UDP-only servers: registration fails → unreachable
├── OpenVPN TCP (port Y)             ← separate listener
├── OpenVPN UDP (port Z)             ← separate listener (works for UDP-only servers!)
├── L2TP/IPsec                       ← separate listener
└── SSTP                             ← separate listener
```

**CSV columns (v2):** 0=HostName, 1=IP, 14=OpenVPN_ConfigData_Base64, 15=TcpPort, 16=UdpPort, 19=SETcpPort, 20=SEUdpPort

**"UDP: Supported" on vpngate.net = SoftEther R-UDP via NAT-T relay**, NOT OpenVPN. For UDP-only servers this is a lie — the relay returns error=6 (NOT_FOUND).

---

## Connection Flow (Current)

### TCP-available servers (SETcpPort > 0)
1. TCP connect → TLS → PACK login
2. If login rejected → auto fallback to parallel UDP race

### UDP-only servers (SETcpPort = 0, udp_only flag)
1. **Parallel transport race** (TCP thread skipped):
   - R-UDP direct to `SEUdpPort` (delay 0ms)
   - NAT-T relay (delay 30ms)
   - DNS tunnel to port 53 (delay 100ms)
   - ICMP raw socket (delay 200ms, requires root)
2. First to complete TLS handshake wins
3. Losers cancelled via shared `cancel_flag`

### What actually works for UDP-only servers
**Nothing.** Across 3 sweeps of different CSV snapshots (30+ unique servers):
- Our client: 0% success
- Official SoftEther client v4.44: 0% success
- OpenVPN: **works** on same port (proven: `vpn420429830` at 77.90.61.102:45032)

The only viable path for UDP-only servers is **OpenVPN fallback** using `OpenVPN_ConfigData_Base64` (column 14).

---

## Implementation Status

### Completed Phases

| Phase | Description | Status |
|-------|-------------|--------|
| 1-5 | V1 R-UDP core, handshake, data path, hardening, compression | ✅ Complete |
| 6 | ~~NAT-T / Direct R-UDP~~ → replaced by Phase 12 | ✅ Done |
| 7 | V2 AEAD (ChaCha20-Poly1305) | ✅ Complete |
| 8 | IPv6 tunnel | ✅ Complete |
| 9 | Dual-stack socket support | ✅ Complete |
| 10 | OpenSSL 3.5 LTS upgrade | ✅ Complete |
| 11 | IPv6 for all protocols (server-blocked for OpenVPN/SSTP) | ✅ Client done |
| 12A | Sequential stages (TCP → R-UDP → NAT-T) | ✅ Complete |
| 12B | Parallel transport race | ✅ Complete |
| 12C | DNS transport (`RUDP_T_MODE_DNS`) | ✅ Complete |
| 12D | ICMP transport (`RUDP_T_MODE_ICMP`, requires root) | ✅ Complete |
| 12E | UI label cleanup | ✅ Complete |

### Key Implementation Details

- **Parallel race:** `transport_result_t` with atomic CAS winner claim. Staggered delays match official `ConnectEx4`.
- **DNS transport:** Normal UDP socket to server port 53. 36-byte query / 42-byte response framing. No special privileges.
- **ICMP transport:** Raw socket with `CAP_NET_RAW`. 28-byte overhead. Graceful EPERM on non-root.
- **Host harness:** Pre-compiled `.o` files in `/tmp/opencode/tsbuild/`. System OpenSSL headers (not bundled).
- **Commit conventions:** submodule (no prefix) → `origin` main; parent `[pro]` prefix → `gh` master; doc-only parent `[skip ci]`.

### Open Items

1. **OpenVPN fallback for UDP-only servers** — parse column 14 base64 OpenVPN config, connect via OpenVPN library. This is the only viable path for UDP-only servers.
3. **On-device regression** — ICMP transport gracefully fails on production Android without root. Full NDK/SDK test not possible on this machine.

### Key Source References

| Topic | Location |
|-------|----------|
| Parallel race | `softether_protocol.c:softether_connect_parallel_race()` |
| NAT-T relay | `softether_nat_t.c:nat_t_connect()` — UDP to relay port 5004 |
| R-UDP transport | `rudp_transport.c` — CONNECT_SENT → ESTABLISHED |
| DNS framing | `rudp_transport.c` — `RUDP_T_MODE_DNS` |
| ICMP framing | `rudp_transport.c` — `RUDP_T_MODE_ICMP` |
| Official `ConnectEx4` | `SoftEtherVPN_Stable/src/Mayaqua/Network.c:16287` |
| OpenVPN listener (server) | `SoftEtherVPN_Stable/src/Cedar/Interop_OpenVPN.c:2760` |
| R-UDP listener (server) | `SoftEtherVPN_Stable/src/Cedar/Server.c:11107` (port 0, random) |
| NAT-T error codes | `softether_nat_t.h` (0=OK, 5=TWO_OR_MORE, 6=NOT_FOUND) |

---

## RUDP Connection Parity Audit vs Official Client (2026-09-08)

Audit of `softether_nat_t.c` / `rudp_transport.c` against the official client (`SoftEtherVPN_Stable/src/Mayaqua/Network.c`, `Cedar/Protocol.c`, `Cedar/Listener.c`), focused on the **no-TCP connect path** (`NewRUDPClientDirect(VPN_RUDP_SVC_NAME, …)` for `PortUDP ≠ 0`, and `ConnectEx4` parallel race for `PortUDP == 0`).

### Verified identical (no work needed)

| Mechanism | Official | Ours |
|-----------|----------|------|
| Session key derivation | `Network.c:4110-4184` (`"zurukko"`→key1, `"yasushineko"`→key2; `Magic_KeepAliveRequest/Response`; client-only `Magic_Disconnect = 0xffffffff00000000 \| Rand32`) | `rudp_transport.c:949-995` |
| 39-byte init (`Key_Init` + 19 random), resent every 200 ms; server creates session on `<40B` pkt | `Network.c:2750-2789`, `:2077` | `rudp_transport.c:694-703` |
| V1 segment framing `[Sign][IV][RC4(iv‖Key, hdr+payload)][1..255 pad]` + RC4 keying | `RUDPProcessRecvPacket` (`Network.c:3360-3540`) | `rt_send_segment_now` / `rt_handle_udp_packet` |
| First payload = BE(`Magic_Disconnect`) | `Network.c:2400` | `rudp_transport.c:1109-1113` |
| Keepalive + retransmit backoff `RTT*1.2*2^shift` / `200ms*2^shift`, cap 4792 | `Network.c:2680-2682` | `rudp_transport.c:772-793` |
| NAT-T: relay hostname derivation (SHA1(ip) → 4 lowercase hex), port 5004, version 1, interval 200, backoff `200 * 2^max(tries,6)`, error map, `svc_name` | `Network.c:4627-4663`, `Network.h:765-804` | `softether_nat_t.c` |
| NAT-T rendezvous socket reuse except same-LAN | `Network.c:5526-5539` | `softether_protocol.c:1643` + `:1937` |
| Connect flow: UDP-only → parallel race; TCP-available → sequential TCP (IPv4/IPv6 fallback) + TLS → race fallback | `Cedar/Protocol.c:7577` (`PortUDP` split), `Network.c:16287` | `softether_protocol.c:2396-2479` |
| `svc_name` constant | `VPN_RUDP_SVC_NAME == "SoftEther_VPN"` (`Cedar.h:304`) | `NAT_T_SVC_NAME` (`softether_nat_t.h:13`) |

### Gaps (all implemented 2026-09-08)

1. **SvcNameHash XOR** — DNS/ICMP signature XOR with SHA1(svc_name). `rudp_transport.c`
2. **`current_rtt` dedup** — sampled on tick advance, deduped via `latest_recv_my_tick2`. `rudp_transport.c`
3. **ICMP client parity** — random Echo keep-alive, init as type 0+7, receive types 0/7/8/15. `rudp_transport.c`
4. **ALT relay fallback** — failover to `.uxcom.jp` on DNS failure. `softether_nat_t.c`
5. **`hint`/`target_hostname`** — forwarded via `nat_t_connect_ex`. `softether_nat_t.c` + `softether_protocol.c`
6. **`ok` priority over `multi_candidates`** — response parser fix. `softether_nat_t.c`

### Recommended fix scope

All 6 parity gaps implemented; no remaining recommended fixes.

---

## Throughput Optimization Plan (Phase 13)

**Benchmark finding (2026-08-23):** Throughput ranks OpenVPN UDP > OpenVPN TCP ≈ MS-SSTP > SoftEther TCP > SoftEther RUDP. Root causes are implementation overheads in the client data path, not the SoftEther protocol itself.

**Root causes found (all addressed):** unconditional per-packet logging, zlib negotiated ON, ~5 copies + 2 mallocs per packet, lossy RUDP with no recovery, and 1-packet-per-JNI loop granularity with a 1 ms idle spin.

### Phases

| Phase | Description | Priority | Status |
|-------|-------------|----------|--------|
| 13A | Compile-time gate for hot-path logs | P0 | ✅ Done |
| 13B | Disable session compression | P0 | ✅ Done |
| 13C | Zero-alloc send path | P0 | ✅ Done |
| 13D | Receive-path copy elimination + batching | P1 | ✅ Done |
| 13E | Java loop fixes (delay, copyOf, blocking receive) | P1 | ✅ Done |
| 13F | RUDP loss recovery + buffer tuning | P1 | ✅ Done |
| 13G | Benchmark harness + acceptance criteria | P0 | ✅ Done (on-device matrix recorded) |
| 14  | RUDP loss-adaptive send window + sticky fallback | P1 | ✅ Done (validated on device) |
| 15  | Post-Phase-14 stability fixes (races, failover, ARP) | P0 | ✅ Done (device-verified) |
| 16  | TLS shared-SSL_CTX heap corruption fix | P1 | ✅ Done (hardened; deep-concurrency caveat documented) |
| 17  | Half/full-duplex auto-selection (device-tier) | P2 | ✅ Done (device-validated: full beats half on SM-A736B) |

#### 14 — RUDP loss-adaptive window + sticky fallback (P1) — DONE

Loss-adaptive token-bucket send window (256 KB start, 32 KB–8 MB range, +4 MB/s refill) + sticky fallback with exponential backoff (30s → ×8 cap, 5 min reset). `RUDP_RECV_QUEUE_SIZE` 64→256. Validated on device: UDP ≥ TCP throughput.

#### 15 — Post-Phase-14 stability fixes (P0) — DONE (device-verified)

Fixed 5 regression issues: batched RX eth processing, TCP failover, write_mutex race, stable MAC (SHA-256 derived), RUDP recursive lock. Device-verified: 77 MB up / 102 MB down, session alive after speedtest.

#### 16 — TLS shared-SSL_CTX heap corruption (P1) — DONE

Per-connection `SSL_CTX` + process-wide TLS I/O lock. Caveat: prebuilt OpenSSL 3.5.8 has internal multiblock race under extreme concurrency — production single-session unaffected. Verified: paired-session 60s full-duplex, no scudo aborts.

#### 17 — Half/full-duplex auto-selection (device-tier) (P2) — DONE

`DuplexModeSelector.kt` selects full-duplex (cores≥4, RAM≥4GB, strong link) or half-duplex. JNI `nativeSetHalfConnection`, native `conn->half_connection` flag. Validated on SM-A736B: full beats half.

#### 13A–13G — Completed (compacted)

All seven phases are done; details live in git history (`86cd1af` plan, per-phase commits). Summary:

- **13A** Hot-path logging gated behind `SE_TRACE_PACKETS` (default off).
- **13B** Session zlib negotiation off (~2.7x TX on its own; encrypted traffic is incompressible).
- **13C** Zero-alloc send path: prebuilt `send_block` staging + single-write transmit.
- **13D** RX batching: blocks read straight into queue slots, `softether_receive_batch()` drains up to 32 frames/JNI crossing, slice writes to TUN. `MAX_QUEUED_FRAME` 1600→2048.
- **13E** Java loops: blocking native receive (100 ms idle poll), zero-copy TUN slices both directions, direct send from TUN thread.
- **13F** RUDP robustness: SO_RCVBUF/SO_SNDBUF 2 MB, overflow counters, keepalive-all over C2S sockets.
- **13G** Benchmark harness (`ThroughputBenchmarkTest` androidTest) + matrices:
  - Host loopback (pre/post): base 34.9 Mbps TX → HEAD 130.8 Mbps (+275%), CPU −33%.
  - On device (SM-A736B ↔ local server, full-duplex paired flood): TCP 44.3/40.6 Mbps TX/RX vs UDP 48.7/44.4 Mbps.

Host-loopback limitation to remember: the local server only forwards ~150–600 pps to a receiving session regardless of transport, so loopback runs compare variants but cannot measure absolute goodput — use the on-device matrix for that.

### Execution order & risk

1. **13G** (harness/baseline) → **13A** → **13B**: trivial risk, immediate measurable gains.
2. **13C** → **13D** → **13E**: medium risk (touch thread-safety invariants around `write_mutex`, disconnect races). Preserve existing fd/SSL capture patterns (`__sync_synchronize` barriers) when restructuring.
3. **13F**: highest complexity; ship recovery-based fallback before attempting a full ACK layer.

All phases are client-side only — no server changes required.

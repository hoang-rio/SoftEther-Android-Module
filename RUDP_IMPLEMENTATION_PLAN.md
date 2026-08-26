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
2. **SvcNameHash XOR** — DNS/ICMP transports XOR SHA1 signature with `SvcNameHash`. Not implemented — may cause server-side rejection.
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

#### 14 — RUDP loss-adaptive window + sticky fallback (P1) — DONE

- On-device UDP-mode goodput collapsed to ~1/10 of TCP: the wire format has no seq/ack fields, so every lost datagram is a silently lost IP packet and inner TCP collapses; the fixed 30 s suspension re-probe then oscillated between fast-TCP and lossy-UDP forever.
- Implemented (`softether_rudp.c/.h`, `packet_handler.c`):
  - Loss-adaptive token-bucket send window (start 256 KB, min 32 KB, max 8 MB, +4 MB/s refill). Peer-tick gaps, recv overflows, and KA timeouts halve it; `rudp_is_send_ready` returns 0 when exhausted so excess blocks ride TCP until refill.
  - Sticky fallback with exponential backoff: consecutive failed probes suspend UDP data 30 s → ×8 cap; 5 clean minutes reset backoff.
  - `RUDP_RECV_QUEUE_SIZE` 64 → 256 (absorbs bursts instead of dropping).
  - `fill_recv_queue` now drains all buffered RUDP frames per call (was one), matching the Phase 13D batched RX path.
- Acceptance for device run: iperf3 over UDP mode within ~30% of TCP mode on Wi-Fi; `stats:` log shows `ovf`/`gaps` stable (not climbing) and `susp=false` during steady state.
- **Validated on device** (SM-A736B, Wi-Fi ↔ local SoftEther server via docker, paired-session full-duplex flood through `ThroughputBenchmarkTest`, 12 s window): TCP 44.3/40.6 Mbps TX/RX vs UDP 48.7/44.4 Mbps — UDP ≥ TCP, zero overflows, no suspension. Acceptance met.
- Known follow-up: concurrent SSL I/O across two connections sharing the cached SSL_CTX can corrupt the TLS layer (scudo abort in EVP_MD_CTX_free) — production keeps one connection's I/O mostly serialized per direction but this needs a proper fix (per-connection CTX or global TLS lock).

#### 15 — Post-Phase-14 stability fixes (P0) — DONE (device-verified)

Real-world regression reports after shipping 13/14, root-caused and fixed one by one:

| Symptom | Root cause | Fix |
|---|---|---|
| Batched RX wrote raw Ethernet frames to TUN → `write failed: EINVAL`, no network at all | `softether_receive_batch` skipped softether_receive's per-frame processing (eth strip, ARP reply, EtherType filter, link housekeeping) | Same processing in batch path; shared helpers (`softether_reply_arp_request`, `softether_maintain_links`) (`5d61d59` predecessor, commit `3e05d12` family) |
| TCP: single dead additional socket → burst of send failures → full teardown + reconnect storms | `softether_transmit_block` returned -1 on first write error | Candidate-list failover; retire dead additional sockets, retry healthy ones (`ebbd99c`) |
| Connected-but-no-network after heavy use on local-bridge servers | **Phase 13C race**: TUN path built into shared `send_block` staging without write_mutex while ARP/raw path built under it → corrupted blocks → server kills session | Both staging paths hold write_mutex across build+transmit (`5d61d59`); transmit split into nolock core + wrapper |
| Same IP flapping between MACs of zombie + live sessions on local-bridge LANs → router ARP entry flaps, downstream lands on dead MACs | Random client MAC per reconnect | MAC derived from SHA-256(server host:port), stable across reconnects; `nativeSetClientMac` JNI (`02c3d8b`) |
| UDP mode: "connected but no network" after one speedtest — upstream silently dead while downstream control traffic still arrives | **RUDP had no locking**: rudp_poll/rudp_send called from RX thread AND TUN thread; concurrent sends raced the shared `next_iv` cipher chaining (corrupted upstream datagrams servers silently drop), concurrent polls interleaved recv-queue indices | Recursive lock in `rudp_context_t` guarding poll/send/is_send_ready/recv (`f37cce1`) |

**Device verification (SM-A736B, paid local-bridge server, UDP profile, one-shot speedtest):**
- Before fixes: ~19 MB into the test then total silence — counters frozen, gateway ARP-storming for our IP, ping 100% loss until manual reconnect.
- After fixes: 77 MB up / 102 MB down through the tunnel; RUDP carried the initial burst with ~4.2k recv-queue drops under sustained flood, Phase 14 suspension engaged (`susp=true`), traffic continued over TCP; **ping after test 128–159 ms — session alive**.

Remaining tuning item (optional, cosmetic): during the RUDP phase of a speedtest, throughput dips while overflows accumulate before suspension engages (~4k drops @ ~50 Mbps). Candidates: faster RUDP queue drain under load or earlier suspension threshold.



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

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

**Root causes (ranked by impact):**

1. **Per-packet formatted logging in release builds.** `LOGD` is an unconditional `__android_log_print(ANDROID_LOG_DEBUG, ...)`; CMakeLists.txt sets only `-O2`, no log stripping. Hot path pays ~4 log writes per TX packet (`packet_handler.c:57-73,347`, `softether_protocol.c:3047`) and several per RX message (`packet_handler.c:915-1041`), plus one per RUDP datagram each way (`softether_rudp.c:524,795`).
2. **Session-level zlib negotiated ON.** Login PACK sends `use_compress=1` (`softether_protocol.c:645`); VPN Gate servers accept it → every block deflate/inflate-attempted per packet on already-encrypted, incompressible traffic (`packet_handler.c:273-286,437-482,979-1013`; `softether_rudp.c:651` for RUDP).
3. **Heap churn and copies per packet.** TX: `malloc`+memcpy of whole block per packet (`packet_handler.c:291`) plus Ethernet-frame copy (`softether_protocol.c:2706`). RX: `malloc` per block → queue copy → output copy stripping Eth header (`softether_protocol.c:2886`) → Kotlin `copyOf` (`ConnectionController.kt:666`) → two JNI copies. ~5 copies + 2+ mallocs per ~1.4 KB.
4. **RUDP has no reliability or recovery.** Pure lossy `sendto()` with no seq/ACK/retransmit/congestion control; silent drops when queues overflow (`softether_rudp.c:517`) and blocks >1600 B skipped (`packet_handler.c:1023`). Advertises `support_udp_recovery=1` but implements no fallback → inner TCP collapses on loss. This explains RUDP ranking last.
5. **Loop granularity.** One IP packet per JNI crossing both directions; `delay(1ms)` spin when idle (`ConnectionController.kt:47`); RUDP RX drains at most one block per poll cycle.
6. Minor: mutex take/release around every 4-byte header read (`packet_handler.c:157-168`); RUDP MSS ~1355 vs ~1460 TCP payload; no explicit SO_RCVBUF/SO_SNDBUF sizing on the UDP socket.

### Phases

| Phase | Description | Priority | Status |
|-------|-------------|----------|--------|
| 13A | Compile-time gate for hot-path logs | P0 | ✅ Done |
| 13B | Disable session compression | P0 | ✅ Done |
| 13C | Zero-alloc send path | P0 | ✅ Done |
| 13D | Receive-path copy elimination + batching | P1 | ✅ Done |
| 13E | Java loop fixes (delay, copyOf, blocking receive) | P1 | ✅ Done |
| 13F | RUDP loss recovery + buffer tuning | P1 | ✅ Done |
| 13G | Benchmark harness + acceptance criteria | P0 | 🟡 Partial |

#### 13A — Hot-path logging (P0) — DONE

- Add a compile-time switch, e.g. `SE_TRACE_PACKETS` (default off), wrapping every per-packet `LOGD` in: `ssl_write_all` hexdump/progress (`packet_handler.c:57,73`), "Sent N data block(s)" (:347), "Sent data block via TCP/RUDP" (`softether_protocol.c:3033,3047`), all `fill_recv_queue` per-message logs (`packet_handler.c:915,947,985,1003,1034,1041`), keepalive logs, and RUDP per-datagram logs (`softether_rudp.c:95,231,262,510,524,692-706,791-795`).
- Keep connect/handshake/error logs unconditional.
- Acceptance: zero `__android_log_print` calls on the steady-state data path (verify with logcat during iperf).
- Implemented: `LOGT` macro added to `packet_handler.c`, `softether_protocol.c`, `softether_rudp.c`, `aes_wrapper.c`; ~25 per-packet/steady-state sites converted; CMake option `SE_TRACE_PACKETS` (OFF by default). Warnings/errors and rare anomaly logs unchanged.

#### 13B — Session compression (P0) — DONE

- Send `use_compress=0` in login PACK (`softether_protocol.c:645`) or make it config-driven (default off).
- Keep the decompress fallback paths intact for servers that force compression.
- Skip the zlib compress attempt in `rudp_send` unconditionally when session compression is off (`softether_rudp.c:649-656`).
- Acceptance: `server_use_compress==0` in logs against VPN Gate server; CPU time per MB (simple `perf`/`simpleperf` smoke) measurably lower.
- Implemented: login PACK advertises `use_compress=0`; new `rudp_context_t.use_compress` (default 0) + `rudp_set_compress()`, synced from the Welcome PACK so RUDP only compresses when the session negotiates it; TCP paths already gate on `server_use_compress`. Decompress fallbacks kept (TCP magic/session-header heuristics, RUDP `RUDP_FLAG_COMPRESSED`). Live acceptance (`server_use_compress==0`, CPU/MB) to be confirmed in next benchmark run.

#### 13C — Zero-alloc send path (P0) — DONE

- Preallocate one `uint8_t send_block[8 + ETH_HEADER_SIZE + 65535]` in `softether_connection_t`.
- Build Ethernet frame directly into `send_block + 8` (removes `build_ethernet_frame` stack copy, `softether_protocol.c:2706`) then write header in place; single SSL_write per packet (`packet_handler.c:243-349`).
- Remove per-packet `malloc/free` of `buf`/`comp_buf`.
- Lock `write_mutex` once around build+write instead of per-chunk revalidation.
- Acceptance: no heap allocations in `softether_send_packet` steady state (instrument with malloc hook or review), throughput ≥ +20% TX vs baseline.
- Implemented: `send_block` staging buffer allocated once in `softether_create()` (freed in `softether_destroy()`, survives reconnects). `softether_send` now assembles `[block hdr][eth hdr][ip]` directly into it (payload copied exactly once, no 64 KB stack frame) and sends via new `softether_send_data_block`: RUDP carries the frame pointer, TCP transmits the prebuilt block via new `softether_transmit_block` (mutex + socket selection + single write, zero copies). `softether_send_packet` (DHCP/ARP raw path) builds into the same scratch under `write_mutex`; only the negotiated-compression fallback branch still allocates.

#### 13D — Receive-path copy elimination + batching (P1) — DONE

- Read blocks straight into `entry->data` (queue slot) via a resize-free path: replace `tmp_block` malloc+copy with direct `data_read_all_sock(... entry->data ...)` where possible; decompress directly into the slot (`packet_handler.c:964-1022`).
- Raise `MAX_QUEUED_FRAME` to ≥ 2048 so jumbo-ish server blocks are never silently skipped (`softether_protocol.h:106`, drop path `packet_handler.c:1023`); log-and-count skips instead of silence.
- New JNI API `nativeReceiveBatch(handle, buffer, maxLength, int[] lengths, int maxPackets)` returning multiple frames per crossing; drain entire `recv_queue` / rudp queue per call. Keep single-packet API as compat shim.
- Acceptance: ≤ 2 memcpys per RX packet end-to-end; batch API moves ≥ 8 packets/call under load.
- Implemented: uncompressed sessions (default since 13B) now read straight into the queue slot (SSL → slot, zero temps); compressed sessions keep the tmp+decompress path. `MAX_QUEUED_FRAME` 1600 → 2048 + new `conn->rx_skipped_blocks` counter logged on drops. New `softether_receive_batch()` drains the whole queue per call (`receive_raw` = shim); JNI `nativeReceiveBatch` + Kotlin `receiveBatch()`; `TunTerminal.write(buffer, offset, len)` slice write; RX loop in ConnectionController consumes batches with no `copyOf`.
- Measured (host loopback, 1400 B flood): batch drain 822 pps vs 660 best single-frame (+25%), RX CPU 0.135 s. Batch depth averaged only ~1.0 frame/call (max 5) because the local server sends ≈1 frame per protocol message — the ≥8/call acceptance depends on server-side message batching and should be re-checked against a real VPN Gate server on device. End-to-end copies per packet now 2 (SSL → slot → output/TUN).

#### 13E — Java loop fixes (P1) — DONE

- Replace `result == 0 → delay(1ms)` with blocking behavior: expose socket fd(s) already available (`nativeGetSocketFd`) and add a blocking receive variant with timeout, or poll inside native (`ConnectionController.kt:47,682`).
- Write to TUN without `copyOf`: add `TunTerminal.write(buffer, len)` writing a slice (`ConnectionController.kt:666`, `TunTerminal.kt:74-85`).
- Use the batch receive API from 13D; write frames back-to-back.
- Move traffic-snapshot publishing fully behind its 1 s throttle (already throttled — ensure no per-packet work remains).
- Acceptance: idle-loop wakeups < 20/s; no per-packet allocations on Kotlin side.
- Implemented: native `fill_recv_queue` poll idle timeout unified at 100 ms for TCP and RUDP paths — poll wakes immediately on data, so this only bounds idle wakeups to ~10/s; the Kotlin RX loop's `delay(1ms)` on `total == 0` removed entirely. TUN read loop now invokes the consumer with `(buffer, offset, length)` slices of its scratch buffer (no `copyOf`), and sends go **directly from the TUN read thread** via new `SoftEtherClient.send(buffer, offset, length)` → JNI `nativeSendSlice` → `softether_send` (write-mutex serialized) — the queue + dedicated send coroutine are gone; slow-link backpressure now blocks the TUN read instead of growing a queue. Traffic-snapshot publishing verified already throttled to 1 s.
- Measured: idle connection CPU over 3 s ≈ 0 (blocked in poll); paired flood run TX 110 Mbps / batched RX 20.5 Mbps–1807 pps (best recorded on host loopback). Per-packet Kotlin allocations: zero both directions (RX: reused batch buffer since 13D; TX: slice send).

#### 13F — RUDP reliability/recovery + tuning (P1)

- Implement upstream-style **UDP recovery**: track per-direction tick gaps / queue-overflow counters in `rudp_process_inner` (`softether_rudp.c:412-529`); after N losses in window M, set `fatal_error`-like flag → `softether_send_data`/`fill_recv_queue` route data over TCP while RUDP keeps only keepalives; periodically re-probe RUDP (e.g. every 30 s).
- Size the UDP socket buffers explicitly (`SO_RCVBUF` ≥ 1–2 MB) in `rudp_create_udp_socket` (`softether_rudp.c:39-97`) to absorb bursts between polls.
- Optional (P2): true reliable layer (seq + ACK + retransmit with small window) mirroring NAT-T R-UDP semantics; evaluate only if recovery alone doesn't close the gap.
- Acceptance: under 2% random UDP loss (tc/netem), RUDP throughput within 30% of SoftEther TCP and no stall; 0% silent IP-packet drops counted at queue boundaries.
- **Diagnosis (host loopback, traced run)**: earlier "RUDP never ready" was a bench artifact — harness passed `use_tcp=1`, which skips RUDP init entirely ("TCP mode - skipping RUDP initialization"); production passes use_tcp=false. With RUDP enabled it engages correctly after the ~10 s stability gate, then collapses under flood: RX goodput 1.7 Mbps vs 110+ over TCP, 28% of blocks oscillate back to TCP mid-stream (inbound gaps > KA_TIMEOUT reset `first_stable_receive_tick`, softether_rudp.c:550-554), zero SO_RCVBUF/SO_SNDBUF sizing → kernel-buffer loss, and full `recv_queue` silently discards frames (softether_rudp.c:529-530). So 13F = robustness layer + counters, not a logic fix.
- Implemented:
  - `SO_RCVBUF`/`SO_SNDBUF` = `RUDP_SOCK_BUF_SIZE` (2 MB request) in `rudp_create_udp_socket`, actual value logged. Host kernel capped at 416 KB (`net.core.rmem_max`) — still ~2× default; Android typically honors larger values.
  - Overflow counting: recv-queue-full frames now increment `recv_queue_overflow_count` + `recent_overflows` and LOGW instead of dropping silently.
  - **Recovery**: `recent_overflows >= RUDP_OVERFLOW_SUSPEND_THRESHOLD (8)` → `udp_data_suspended=1` for `RUDP_UDP_SUSPEND_MS` (30 s) — data routes over TCP while keepalives continue on UDP; auto re-probe after suspension with counter reset (`rudp_is_send_ready`).
  - Peer-tick gap detection: wire `my_tick` is the peer's clock; jumps > `RUDP_PEER_TICK_LOSS_GAP` (10 s) counted as `peer_tick_gap_events`.
  - `rudp_stats_t` + `rudp_get_stats()` snapshot API for 13G `nativeGetStats`.
- Verified: all TUs compile; TCP-mode regression run unchanged (TX 107 Mbps, batched RX healthy); RUDP-mode connect + data flow clean, buffer-sizing log confirmed. Loopback flood goodput remains server-delivery-limited (~150–600 pps ceiling observed in ALL modes incl. pure TCP) — the host loopback cannot discriminate RUDP-vs-TCP goodput.
- Acceptance note: tc/netem unavailable in the build container (kernel lacks NETEM qdisc) — the 2 %-loss matrix must run on device/lab hardware (fold into 13G device testing). Silent-drop acceptance is now satisfiable by construction: drops are counted (`recv_queue_overflow_count`), surfaced via stats, and trigger recovery instead of stalling.

#### 13G — Benchmark harness (P0, do first) — PARTIAL

- Controlled setup: local SoftEther server (see `/server-setup`) + `iperf3` over each protocol; record Mbps + CPU% (simpleperf) + battery-neutral runs.
- Baseline matrix before any change; re-run after each phase. Compare against OpenVPN TCP/UDP on same link.
- Add permanent counters exposed via `nativeGetStats`: packets/bytes in-out, queue-full drops, skip-drops, compress ratio, log-suppression counter.
- Acceptance: final matrix shows SoftEther TCP ≥ 80% of SSTP/OpenVPN TCP; SoftEther RUDP ≥ SoftEther TCP on clean links and degrades gracefully under loss.
- **Host-loopback matrix done (2026-08-24):** local vpnserver v4.44 (repo submodule) on loopback:5555, hub BENCH; two harness processes running the real client stack built from four commits (git worktrees); one session floods 1400 B Ethernet-framed packets via `softether_send`, the other drains via `softether_receive_raw`; 10 s per run (harness + logs in `/tmp/opencode/bench`).

| Variant | TX Mbps | TX pps | TX CPU user+sys | vs baseline |
|---|---|---|---|---|
| base (c889c28, pre-13A/B/C) | 34.9 | 3,120 | 3.99 s | — |
| +13A trace-log gate | 45.7 | 4,084 | 3.96 s | +31% |
| +13B compression off | 125.3 | 11,186 | 2.69 s | +259% |
| +13C zero-alloc send (HEAD, af15e55) | **130.8** | **11,676** | **2.66 s** | **+275%** |

Rerun for stability: base 41.0 Mbps / CPU 4.64 s vs HEAD 92.8 Mbps / CPU 2.05 s — same ordering.

Findings:
- Largest single win is 13B (zlib negotiation off): ~2.7× TX throughput and −45% sys CPU on its own.
- **RUDP readiness gap confirmed:** UDP accel negotiated fully (v2, keys exchanged) but `rudp_is_send_ready` never became ready even on zero-loss loopback → 100% of data fell back to TCP. Reinforces 13F as the blocker for RUDP viability.
- RX delivery ceiling: server forwarded only ~200–600 pps to the receiving session regardless of client variant (zero client-side drops/skips logged). Likely server-side broadcast-forwarding behavior; investigate separately.
- Remaining for full acceptance: on-device iperf3 matrix vs OpenVPN TCP/UDP (needs phone + VPS), permanent `nativeGetStats` counters.

### Execution order & risk

1. **13G** (harness/baseline) → **13A** → **13B**: trivial risk, immediate measurable gains.
2. **13C** → **13D** → **13E**: medium risk (touch thread-safety invariants around `write_mutex`, disconnect races). Preserve existing fd/SSL capture patterns (`__sync_synchronize` barriers) when restructuring.
3. **13F**: highest complexity; ship recovery-based fallback before attempting a full ACK layer.

All phases are client-side only — no server changes required.

# SoftEther-Android-Module

SoftEther-Android-Module for [vpngate-connector](https://github.com/hoang-rio/vpngate-connector)

# Protocol Support

| Transport | Status |
|-----------|--------|
| TCP (SoftEther over HTTPS/TLS) | ✅ Supported |
| UDP (SoftEther RUDP) | 🚧 Planned |

**TCP** is the only currently supported transport. It connects via the SoftEther HTTPS/TLS channel on the server's SE-VPN TCP port.

**UDP (RUDP)** support is planned for a future release. The SoftEther RUDP transport requires a full reliable-UDP layer including NAT traversal, sequence numbers, ACKs, retransmission, and HMAC signatures (~5000+ lines in the reference implementation).

# Source Version

This module implements the SoftEther VPN protocol based on the reference source:

**Repository:** https://github.com/SoftEtherVPN/SoftEtherVPN_Stable

**Version:** [v4.44-9807-rtm](https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases/tag/v4.44-9807-rtm)

Key reference files used:
- `src/Cedar/Protocol.c` — SoftEther protocol handshake, auth PACK fields (`ClientUploadAuth`)
- `src/Cedar/Connection.c` — Data channel send/receive format
- `src/Mayaqua/Network.c` — HTTP transport, PACK serialization, keepalive

# LICENSE

This project is under Apache License 2.0 ([LICENSE](LICENSE))

This project use another open source project as library detail bellow.
* [**SoftEtherVPN**](https://github.com/SoftEtherVPN/SoftEtherVPN_Stable) under Apache License 2.0 (https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/blob/master/LICENSE)

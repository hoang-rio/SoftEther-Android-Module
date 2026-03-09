# SoftEther-Android-Module

SoftEther-Android-Module for [vpngate-connector](https://github.com/hoang-rio/vpngate-connector)

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

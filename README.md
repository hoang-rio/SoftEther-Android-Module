# SoftEther-Android-Module

SoftEther-Android-Module for [vpngate-connector](https://github.com/hoang-rio/vpngate-connector)

# Protocol Support

| Transport | Status |
|-----------|--------|
| TCP (SoftEther over HTTPS/TLS) | ✅ Supported |
| UDP (SoftEther RUDP) | ✅ V1 + V2 Working |

**TCP** connects via the SoftEther HTTPS/TLS channel on the server's SE-VPN TCP port.

**UDP (RUDP)** V1 (RC4 + SHA1 key derivation) and V2 (ChaCha20-Poly1305 AEAD, 128-byte key, 12-byte IV + 16-byte Poly1305 MAC) are implemented and working. The client advertises `udp_acceleration_max_version=2` and falls back to V1 when the server only supports V1. See the [RUDP Implementation Plan](RUDP_IMPLEMENTATION_PLAN.md) for details.

# Implementation Status

For detailed progress tracking and future roadmap, see the [Implementation Plan](IMPLEMENTATION_PLAN.md).

# Authentication Methods

| Method | `AuthMethod` enum | Status | Notes |
|--------|-------------------|--------|-------|
| Anonymous | `AuthMethod.ANONYMOUS` | ✅ Supported | No credentials required; server hub must allow anonymous login |
| Hashed Password | `AuthMethod.PASSWORD` | ✅ Supported | `CLIENT_AUTHTYPE_PASSWORD` — password hashed as `SHA1(SHA1(pw + UPPER(user)) + server_random)` |
| Plain Password (RADIUS) | `AuthMethod.PLAIN_PASSWORD` | ✅ Supported | `CLIENT_AUTHTYPE_PLAIN_PASSWORD` — plaintext password forwarded by server to a RADIUS backend |
| Auto-detect | `AuthMethod.AUTO` | ✅ Supported | Selects `PASSWORD` when password is non-empty, `ANONYMOUS` otherwise |
| Certificate | — | 🚧 Not supported | `CLIENT_AUTHTYPE_CERT` — requires client certificate and private key handling |
| Windows NT / AD | — | 🚧 Not supported | `CLIENT_AUTHTYPE_SECURE` — Windows-specific secure device auth |

**Usage in `ConnectionConfig`:**
```kotlin
// Free VPNGate server (auto-detect)
ConnectionConfig(username = "vpn", password = "vpn", authMethod = AuthMethod.AUTO, ...)

// Paid server with RADIUS
ConnectionConfig(username = "user", password = "secret", authMethod = AuthMethod.PLAIN_PASSWORD, ...)

// Anonymous hub
ConnectionConfig(username = "", password = "", authMethod = AuthMethod.ANONYMOUS, ...)
```

# Source Version

This module implements the SoftEther VPN protocol based on the reference source:

**Repository:** https://github.com/SoftEtherVPN/SoftEtherVPN_Stable

**Version:** [v4.44-9807-rtm](https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases/tag/v4.44-9807-rtm)

Key reference files used:
- `src/Cedar/Protocol.c` — SoftEther protocol handshake, auth PACK fields (`ClientUploadAuth`)
- `src/Cedar/Connection.c` — Data channel send/receive format
- `src/Mayaqua/Network.c` — HTTP transport, PACK serialization, keepalive

# LICENSE

This project is under Apache License 2.0 ([LICENSE](LICENSE)) for all original code.

Third-party components retain their original licenses:
* [**SoftEtherVPN**](https://github.com/SoftEtherVPN/SoftEtherVPN_Stable) under Apache License 2.0 (https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/blob/master/LICENSE)
* [**OpenSSL**](https://github.com/openssl/openssl) under Apache License 2.0 (https://github.com/openssl/openssl/blob/openssl-3.5.7/LICENSE.txt)

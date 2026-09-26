# Changelog

## 0.2.0 (unreleased)

A rebuild onto the macula 12 wire. 0.1.0 spoke the retired classical wire,
which the fleet refuses.

### Changed

- macula-py is now a `ctypes` binding over macula-go's shared C ABI
  (ABI 1) instead of a pure-Python protocol implementation. The wire, the
  post-quantum handshake (ML-KEM hybrid key exchange) and ML-DSA-87 /
  LAMPS composite identities come from macula-go.
- New asyncio API mirroring macula-ts: `NodeKey`, `Pool`, `Subscription`,
  `Served`, `Stream`, typed errors, `RecordType`, `StreamMode`.
- Distributed as `py3-none-<platform>` wheels for Linux x86-64/arm64
  (manylinux_2_28), macOS 13 arm64/x86-64 and Windows x86-64. No sdist and no
  runtime dependencies.

### Removed

- The 0.1.0 modules (`connection`, `identity`, `frame`, `cbor`, `bolt4`,
  `blake3_hash`, `content`, `manifest`) and the `aioquic`, `cryptography` and
  `blake3` dependencies.

## 0.1.0 (2026-09-05)

First release: a pure-Python client of the pre-12 wire over aioquic.

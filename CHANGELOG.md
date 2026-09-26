# Changelog

## 0.3.0 (2026-09-26)

On macula-go v0.17.0's C ABI (was v0.13.0).

### Added

- UCANs (macula 12, D7): `NodeKey.ucan` mints a token for the node that will
  present it; `Pool.call` and `Pool.open_stream` take `ucan=` and `proofs=`;
  `Pool.serve` and `Pool.serve_stream` take `policy=` (`UcanRequired`,
  `RealmMemberRequired`), and the provider refuses what the policy does not
  accept with `unauthorized` (or `malformed_frame` for a proof no token
  names). `macula_py.ucan.proof_id` and `key_id`, held to macula's UCAN
  vectors.
- `NodeKey.device_request_proof` (realm proof v2, macula-realm#29) and
  `macula_py.device_request.device_request_message`, held to the realm's
  vector; a proof made here is accepted by the realm's own verifier
  (`scripts/interop/device_request.sh`).
- `NodeKey.ownership_proof` (v2, mcl-om#7) and
  `macula_py.ownership_proof.ownership_proof_message`, held to mcl_om's
  vector; a payload signed here, delivered through a station, is accepted by
  mcl_om's own verifier and refused changed or replayed
  (`scripts/interop/ownership_proof.sh`).
- `NoProviderError`, for the `no_provider` kind: no provider the realm trusts
  advertises the procedure.

### Changed

- Stopping a served procedure answers each call it still holds with the
  provider error `handler_error` and the detail "the procedure was
  withdrawn", from the library, before the handler's own cancellation.
- A handler's request payload never holds a "caller" its sender wrote: who
  called is `request.caller`, the verified signer.
- A device request or ownership-proven payload carrying a "caller" is
  refused (`InvalidArgumentError`).
- `open_stream`'s `deadline_ms` bounds the provider's admission of the open,
  not the stream's life, as the contract says.

## 0.2.0 (2026-09-26)

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

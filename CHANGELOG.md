# Changelog

## 0.4.0 (2026-09-29)

On macula-go v0.20.0's C ABI (was v0.18.2): macula 13's end-to-end sealing,
the caller's seal report, and handshake v5.

### Added

- **Sealed calls and streams** (macula 13's E2E seal scheme 1, macula-go
  v0.18.0). `Pool.connect(kem_advertise=True)` names the node's KEM key in the
  advertisements of what it serves confidentially; it is off by default.
  `serve` and `serve_stream` take `confidential=` (`"preferred"`, the default,
  `"required"` or `"off"`), and `request.sealed` says whether a call came
  sealed. `call` and `open_stream` take `confidential=` (`"preferred"`, the
  default, seals whenever the provider's advertisement names a key;
  `"required"` never calls one that names none; `"off"` is refused). What
  could not be kept confidential raises `ConfidentialityError` (`reason`,
  `named`, `found`).
- **The seal report** (macula's DESIGN_E2E_SEAL_REPORT, macula-go v0.19.0):
  `Pool.call_report` returns `Reported(result, report)`, and `Stream.report()`
  a caller stream's; a `SealReport` has `sealed`, `provider` and
  `seal_key_id`. A stream's raises `NotSettledError` before it settles and
  `NotACallerError` on a served stream.
- `scripts/interop/v5.sh` and `scripts/interop/sealed.sh`: handshake v5
  against a macula station, and sealed calls and streams with their seal
  reports both ways against a macula node.

### Changed

- **Handshake v5** (macula-go v0.20.0): every link binds its session to its
  TLS channel and carries no per-frame neighbour signature after HELLO. It
  comes with the library; nothing in the Python API changes.
- The library floor is macula-go v0.20.0. `call`, `serve`, `serve_stream` and
  `open_stream` go through the ABI's `*_opts` functions, whose one options set
  carries a UCAN, its proofs and the confidentiality.

## 0.3.1 (2026-09-29)

On macula-go v0.18.2's C ABI (was v0.17.0), for two fixes a Python caller
gets from the library:

### Fixed

- **A call enters a provider's handler at most once** (macula-go#8, fixed in
  v0.18.1). A call used to move to the next provider after any failure but a
  provider's answer, a timeout included, and a provider slower than one
  candidate's share of the deadline was called again elsewhere: **a handler
  that is not idempotent could run twice**. Now the call moves on only when a
  provider's station cannot be reached, before anything is sent; once the
  call has gone out, its outcome is returned as it is. A reply that is lost
  ends in a timeout, and the handler ran once or not at all.
- **No call goes out with a provider deadline past its caller's**
  (macula-go#12, v0.18.2).

### Changed

- The library floor is macula-go v0.18.2: an older library lacks these
  fixes. `abi/macula.h` is v0.18.2's, and `macula_py._abi` declares its four
  `*_opts` functions (sealing, v0.18.0) because the header has them. Nothing
  in the Python API uses them yet: sealed calls and streams, and the seal
  report, come in the release on macula-go v0.19.0.

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

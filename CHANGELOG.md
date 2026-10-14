# Changelog

## Unreleased

Documentation only, of what already shipped in 0.6.0rc2. The group docs said a
member's subscription "opens every event under the group", which is not what
the library does or can do: a *clear* event under the group's prefix is refused
only under a group whose own policy is `required`, which the distributor sets
and not the subscriber, so under any other policy any realm member's clear
event arrives with `Event.sealed` false. `Pool.subscribe_group`'s docstring,
`Event`'s docstring and the README's sealed-group section now say so, and that
an app wanting sealed events alone checks `Event.sealed`. No code changed, and
no version was released for this.

## 0.6.0rc2 (2026-10-14)

On macula-go v0.27.0-rc.3's C ABI (was v0.27.0-rc.1): sealed group pub/sub, the
member's side. Still a pre-release, and still wire 1.0 alone.

### Added

- **Sealed group pub/sub** (macula 13.2's sealed groups, macula-go#34).
  `Group(prefix, ucan=None, distributor=None)` names a realm group, a topic
  prefix whose second segment is the org whose distributor serves it;
  `Pool.publish_group(realm, topic, payload, group)` publishes under it
  sealed, and `Pool.subscribe_group(realm, topic, group)` subscribes as a
  member. Each joins the group first, pulling its epoch from the org's
  distributor over a sealed call with the org's `group_keys` grant, so each
  takes a timeout like a call. A member's subscription opens every event the
  group seals: `Event.sealed` and `Event.seal_key_id` name the epoch it
  arrived under, and one that cannot be opened arrives once with `payload`
  None and `Event.unopened` naming why. A refusal, or a publication that
  cannot be sealed, raises `GroupError`: its `reason` is one of macula's
  closed set, and `group_held` (a clear publish under a prefix this node
  holds a key for) also names the group's `prefix`.
- `scripts/interop/groups.sh`: sealed groups both ways against a compiled
  macula 15, macula's own distributor and an Erlang member each opening the
  other's sealed event under one epoch, and a Python node the distributor
  removed refused `not_a_member`.

### Changed

- The library floor is macula-go v0.27.0-rc.3. The rc.1 library speaks wire
  1.0 but has no group call at all, so `macula_pool_publish_group` and
  `macula_pool_subscribe_group` now fail the declarations naming the floor
  instead of linking a release that cannot seal a group's publication.
  `abi/macula.h` is v0.27.0-rc.3's.

### Tests

- **The group-key vectors (E2E_SEAL_V1, package 5), as values.** The C ABI
  hands values and never CBOR, so the vectors are held where they cross:
  the epoch's id and key through the event's `seal_key_id` and the payload
  that opens under them, a pull's CALL field for field, and each of the six
  `realm_member_required` cases against a live gated distributor, where the
  org's grant is accepted and an impostor refused. Byte-for-byte vector
  replay and the cases' named refusals stay macula-go's own
  (`group/vectors_test.go`), as they are PHP's.
- The tests are run against the released rc.3 asset, SHA256SUMS verified,
  never a locally built library.

## 0.6.0rc1 (2026-10-13)

On macula-go v0.27.0-rc.1's C ABI (was v0.26.0). A pre-release: it speaks
wire 1.0 and nothing older, so a plain `pip install macula-py` keeps
resolving 0.5.0, on the macula 12 wire, until wire 1.0 ships on the fleet.

### Changed

- **Wire 1.0** (macula#83, macula-go#30). The library speaks wire 1.0
  (macula 15) alone, so this pre-release reaches a wire 1.0 station and
  never the 14.x fleet. macula-go v0.27.0-rc.1's C ABI adds
  `macula_library_version` and `macula_wire_version`; `_abi` declares both,
  and `LIBRARY_FLOOR` is v0.27.0-rc.1, so a library from before it fails
  the declarations naming the floor instead of linking silently.
  `abi/macula.h` is v0.27.0-rc.1's.
- **A library speaking another wire is refused at load** (macula.h's
  `MACULA_WIRE_VERSION`; cabi's CONTRACT.md). `Native` reads
  `macula_wire_version()` and fails naming the library's release and wire
  when its major is another (`_abi.speaks_our_wire`: every wire 1.x peer
  shares the frozen core, so a 1.1 library reaches this node without an
  upgrade), so the wheel proves which wire it links even when
  `MACULA_LIBRARY_PATH` points it at someone else's library. `_abi.WIRE_VERSION`
  is the header's, which `tests/test_abi_declarations.py` holds it to.
- The project summary no longer names a wire (the `description` in
  `pyproject.toml`, and the README's tagline), as macula-ts's does not: a
  0.6.0rc1 wheel's metadata would otherwise claim the macula 12 mesh this
  pre-release does not speak.

## 0.5.0 (2026-10-09)

On macula-go v0.26.0's C ABI (was v0.23.0).

### Security

- **A UCAN whose issuer did:key is over 4,400 characters is refused at once**
  (macula#87, macula-go#27). Base58 decodes in time quadratic in its length,
  ahead of the signature check: on v0.23.0 a gated procedure decoding a
  300,000-character issuer outlasted a 5 s call. It is now refused
  `unauthorized` before the handler runs. The library also refuses, at every
  link of a chain, an `exp` more than ten years past now (macula#68,
  v0.25.0), and `NodeKey.ucan` will not mint one (v0.24.0).
- `LIBRARY_FLOOR` is v0.26.0: an older library would silently lack the bound.

### Tests

- The UCAN vectors are macula v14.5.0's `ucan_v1.json` (was 0e2724cc), with
  `did_key_length`, which a test holds to 4,400.

## 0.4.1 (2026-10-06)

On macula-go v0.23.0's C ABI (was v0.20.0). Closes #5.

### Changed

- **Every connection negotiates SecP384r1MLKEM1024** (macula-go#20). Before,
  this SDK landed on SecP256r1MLKEM768 with every station: Go's crypto/tls
  ignores the order of the groups it is given and offered SecP256r1MLKEM768
  first, with the only key share, and a station takes the client's first
  group. libmacula now offers SecP384r1MLKEM1024 alone, so a station that
  accepts only SecP256r1MLKEM768 fails in the TLS handshake. Every macula 12
  station accepts SecP384r1MLKEM1024.
- The library floor is macula-go v0.23.0: an older library would land on
  SecP256r1MLKEM768. `abi/macula.h` is v0.23.0's, which adds
  `macula_signed_object_verify` (macula-go v0.22.0); `_abi` declares it, and
  the Python API does not use it yet.

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

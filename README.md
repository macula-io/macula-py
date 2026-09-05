# macula-py

[![CI](https://img.shields.io/github/actions/workflow/status/macula-io/macula-py/ci.yml?branch=main&label=CI)](https://github.com/macula-io/macula-py/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](#license)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://python.org)

**Python port of the Macula mesh wire protocol.**

## What is this?

A native Python implementation of the client half of Macula's wire
protocol -- the same protocol [`macula-io/macula`](https://github.com/macula-io/macula)
(the Erlang/OTP SDK) speaks, and the same protocol
[`macula-go`](https://github.com/macula-io/macula-go) and
[`macula-rust`](https://github.com/macula-io/macula-rust) already port.
Macula is a federated mesh for sovereign, end-to-end-encrypted
application networks; a **station** is the relay/DHT node, and this
package is what a **leaf** -- anything that isn't itself a station --
uses to join it.

## Status, 2026-09-05 (streaming RPC -- phase 1 basics complete)

**In progress, greenfield build.** Built and verified so far, in the
order every sibling SDK was built in:

- **Identity** (`macula.identity`) -- Ed25519 keypairs, S/Kademlia
  puzzle-hardened generation (matches `macula_identity.erl`'s own
  default: puzzle-hardened by default, no unhardened shortcut exposed),
  sign/verify, atomic key-file persistence in the exact wire format
  `macula_identity:save/2` uses.
- **Deterministic CBOR** (`macula.cbor`) -- a hand-rolled codec matching
  `macula_record_cbor.erl` exactly, NOT a generic CBOR library (this
  wire's rules diverge from RFC 8949's own canonical form: floats are
  always full binary64 never the shorter widths, map keys sort by their
  own encoded bytes, and there is no boolean simple value on this wire
  at all -- every SDK's convention is 1/0). Verified byte-for-byte
  against the real Erlang encoder itself (see
  `tests/test_cbor_golden_vectors.py`), not just self-consistency.
- **BLAKE3** (`macula.blake3_hash`) -- content-addressing, backed by the
  same Rust `blake3` crate `macula_crypto_nif` uses (not Erlang's own
  pure fallback, which its own source documents as NOT cryptographically
  real BLAKE3). Cross-verified against the real NIF's output.
- **The frame envelope** (`macula.frame`) -- Ed25519-signed frame
  construction/verification and the length-prefixed wire codec, matching
  `macula_frame.erl` exactly, including its frame-level
  boolean-as-text-string convention (distinct from `macula.cbor`'s own
  payload-level 1/0 convention -- these are two different rules for two
  different layers, confirmed by reading the Erlang source directly). A
  signed CONNECT frame built entirely by this module was independently
  decoded and signature-verified by the real, unmodified Erlang
  `macula_frame` module -- genuine cross-language wire and cryptographic
  compatibility, not just self-consistency.
- **QUIC transport + CONNECT/HELLO handshake** (`macula.connection`) --
  built on `aioquic`. **Live-verified against the real production
  station fleet** (`station-de-frankfurt.macula.io`): a real handshake
  completes, the HELLO's signature verifies, `accepted` is `true`.
- **Unary RPC, both roles** (`Session.call`/`Session.advertise`/
  `Session.serve_one_call`) -- BOLT#4 error taxonomy (`macula.bolt4`).
  **Live-verified to the standard this org's own SDK work holds real
  proof to**: not just "reached the call stage with a clean
  `unknown_next_peer`" (which only proves the caller's own path works),
  but a genuine advertise+serve+call round trip returning an actual
  RESULT payload from an actual running handler, plus a handler that
  raises correctly reporting `unknown_error` with detail.
- **PubSub, both roles** (`Session.publish`/`Session.subscribe`/
  `Session.unsubscribe`/`Session.recv_event`). **Live-verified**: a real
  publish/subscribe round trip within one session, a real cross-session
  delivery (separate identities, separate connections), and unsubscribe
  actually stopping delivery. Real finding, root-caused: SUBSCRIBE needs
  a moment to register at the station before a PUBLISH sent immediately
  afterward is reliably delivered -- same shape as RPC's own
  ADVERTISE-needs-a-moment finding, documented in
  `tests/test_pubsub_live.py`.

- **Content transfer** (`macula.manifest`, `macula.content`) -- fixed-size
  chunking, Merkle-root computation, and MCID derivation matching
  `macula_manifest.erl` exactly (cross-verified byte-for-byte against the
  real Erlang implementation for a 3-chunk input, including the
  odd-chunk-paired-with-itself fold case), plus `put`/`get` over the
  `_content.*` RPCs on a dedicated QUIC stream. **Live-verified**: single
  block and chunked (multi-block) put/get round trips, not_found
  handling, and cross-session put/get all pass against the real fleet.
  Found and fixed a genuine bug along the way in **macula-station**
  itself (not this SDK, and not SDK-specific -- it affected every
  client): `_content.put_manifest` crashed with a generic
  `temporary_relay_failure` for any manifest whose `name` wasn't already
  an interned Erlang atom, i.e. any real content name. Root-caused via a
  standalone reproduction against the real unmodified station code,
  fixed at the source (macula-io/macula-station), and confirmed live
  against the production fleet before calling this piece done.

- **Streaming RPC, both caller and provider roles** (`Session.open_stream`/
  `Session.accept_stream`, `macula.connection.StreamHandle`) --
  STREAM_OPEN/DATA/END/ERROR/REPLY over their own dedicated QUIC stream
  (like content transfer, not the control stream), matching
  `macula_frame.erl`'s constructors and `macula_station_link.erl`'s own
  open/dispatch sequencing exactly, including the `signer`/`responded_by`
  fields non-OPEN stream frames carry for cross-hop authentication.
  Cross-verified in both directions against real Erlang-signed frames
  (this module decodes and signature-verifies frames built by the actual
  `macula_frame:stream_*/1` + `sign/2`; frames this module builds decode
  and verify cleanly against the real Erlang `macula_frame:decode/1` too)
  -- see `tests/test_frame_streaming.py`. A stream procedure is
  advertised exactly like a unary one (`Session.advertise`): the wire's
  ADVERTISE frame doesn't distinguish them, and what disambiguates on
  the receiving end is that STREAM_OPEN always arrives on a fresh
  dedicated stream while CALL always arrives on the control stream.
  **Live-verified**: a real `server_stream` round trip against the
  production fleet -- provider sends chunks, caller receives them plus
  the terminal STREAM_REPLY.

  `client_stream`/`bidi` mode is code-complete and wire-correct (the
  provider genuinely receives every chunk and its `set_reply()` call
  raises nothing) but its full round trip is marked `xfail` against the
  live fleet, not claimed working: macula-station's own stream-route
  lifecycle (`macula_station_peer_observer.erl`) drops the *entire*
  bidirectional route on the first terminal frame it sees for a
  stream_id rather than tracking each direction separately -- its own
  comment documents this as deliberate for now, scoped to the
  `server_stream` mode its test suite exercises. A `client_stream`
  caller's own half-close (`STREAM_END(role=send)`) hits exactly this
  gap: the route (and both dedicated QUIC streams) close before the
  provider's reply can be relayed back. This is a station-side relay
  gap, not something fixable in this SDK -- reported upstream.

**Not yet built**: direct-dial, periodic re-advertise, UCAN, cert-chain
verification, and the supervised pubsub wrapper are explicitly OUT of
scope for this first pass, matching the order every other Macula SDK
was built and reviewed in. RPC telemetry facts are likewise deferred.

## Development

```sh
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest              # offline tests only
.venv/bin/pytest -m live      # + live-fleet tests (dials the real production fleet)
```

This repo pins Python 3.13 via `.tool-versions` -- `aioquic`'s C
extension dependencies do not currently build against free-threaded
Python 3.14 builds (confirmed: `pylsqpack`'s limited-API usage hits
missing internal refcounting symbols under `3.14t`). 3.13 and non-free-
threaded 3.14 both build cleanly; 3.13 is pinned for reproducibility.

## License

Apache-2.0. See [LICENSE](LICENSE).

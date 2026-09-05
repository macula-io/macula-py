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

## Status, 2026-09-05

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

**Not yet built**: BLAKE3 content-addressing, the QUIC transport and
CONNECT/HELLO handshake, unary RPC, PubSub, content transfer, and
streaming RPC (all four, both caller and provider roles) -- the rest of
this phase's scope. Direct-dial, periodic re-advertise, UCAN, cert-chain
verification, the supervised pubsub wrapper, and RPC telemetry facts are
explicitly OUT of scope for this first pass, matching the order every
other Macula SDK was built and reviewed in.

No live-fleet verification has happened yet -- there is no network layer
to verify against. `pytest -m live` will dial the real production
station fleet once the transport exists.

## Development

```sh
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest              # offline tests only
.venv/bin/pytest -m live      # + live-fleet tests, once they exist
```

This repo pins Python 3.13 via `.tool-versions` -- `aioquic`'s C
extension dependencies do not currently build against free-threaded
Python 3.14 builds (confirmed: `pylsqpack`'s limited-API usage hits
missing internal refcounting symbols under `3.14t`). 3.13 and non-free-
threaded 3.14 both build cleanly; 3.13 is pinned for reproducibility.

## License

Apache-2.0. See [LICENSE](LICENSE).

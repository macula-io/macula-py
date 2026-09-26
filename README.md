# macula-py

[![CI](https://img.shields.io/github/actions/workflow/status/macula-io/macula-py/ci.yml?branch=main&label=CI)](https://github.com/macula-io/macula-py/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](#license)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![GitHub Sponsors](https://img.shields.io/badge/GitHub%20Sponsors-support-ea4aaa.svg?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/rgfaber)

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/macula-py-full-dark.svg">
    <img src="assets/macula-py-full-light.svg" alt="Macula" width="320">
  </picture>
</p>

<p align="center">
  <strong>A Python node on the macula 12 mesh, over macula-go's C ABI</strong>
</p>

---

> **Status, 2026-09-26:** on the **macula 12** wire: ML-DSA-87 identities (as
> the ML-DSA-87 + RSA-PSS-4096 composite in `pq_hybrid`, the fleet's profile),
> ML-KEM hybrid key exchange, signed requests. Calls and streams by direct dial,
> serving (under an org or in a node's own namespace, open or gated on a
> post-quantum UCAN), publish/subscribe, the DHT and node-served content are
> tested against two in-process macula 12 stations on every CI run. Device
> request proofs (realm join) and ownership proofs are held to their
> verifiers' vectors, and checked once through the realm's and mcl_om's own
> verifiers. 0.1.0 spoke the retired classical wire and cannot reach the
> current fleet.

## What is this?

A Python SDK for the Macula mesh: a node's key, a pool of links to stations
it pins by node_id, calls and streams that reach a provider by direct dial,
serving procedures, publish/subscribe, the DHT and node-served content, all
as asyncio coroutines.

Macula is a federated mesh for sovereign application networks. A **station**
relays and holds the DHT; a **node** is anything else that joins, and this
package is a node.

It is a binding, not a reimplementation. The protocol lives in
[macula-go](https://github.com/macula-io/macula-go), which exports it as a C
ABI (`cabi/macula.h`, contract in `cabi/CONTRACT.md`) shared by every SDK not
written in Go. macula-py loads that library with `ctypes`, so the wire,
the post-quantum handshake and the signing rules are the ones macula-go
already checks byte for byte against macula itself.

## Install

```sh
pip install macula-py
```

Wheels exist for Linux x86-64 and arm64 (glibc 2.28 or later), macOS 13 or
later on Apple silicon and Intel, and Windows x86-64. Each carries macula-go's
library; nothing compiles at install time and there are no runtime Python
dependencies. On any other platform pip finds no wheel.

## Quick start

```python
import asyncio

from macula_py import NodeKey, Pool, Seed

STATION = Seed("station-fi-helsinki.macula.io", 4433,
               "004d1f470097ccf8826ce291900e882fdb1f20375e53901facaec0f23eb4efd8")
REALM = "abb81b5a614b63551b400b810648c0c8a78efad845442630c94b46cc95d2fcd1"  # io.macula
REALM_KEY = "..."  # io.macula's public realm key, hex


async def main() -> None:
    key = await NodeKey.load_or_create("node.key")  # pq_hybrid; the puzzle takes a second
    async with await Pool.connect(key, [STATION], realm_trust={REALM: REALM_KEY}) as pool:
        print(await pool.call(REALM, "mcl-echo/echo", "hello"))


asyncio.run(main())
```

A seed is pinned: the station must prove the node_id you give. A realm's key
decides which advertisements in it you trust; procedures in a node's own
namespace (`~<node_id>/<name>`, see `Pool.own_procedure`) need none.

## The API

| | |
|---|---|
| `NodeKey` | `generate`, `load`, `load_or_create`, `save`, `node_id`, `public_key`, `profile`, `sign`, `verify`, `free`; `ucan`, `device_request_proof`, `ownership_proof` (below) |
| `Pool.connect` | seeds, `realm_trust`, and the pool's tuning; `async with` closes it |
| calls | `call`, `providers`; `call(..., ucan=, proofs=)` presents a UCAN |
| serving | `serve(realm, procedure, handler, policy=None)`: handler(request) returns the result, directly or as an awaitable; an exception reaches the caller as a `ProviderError` of code `handler_error` |
| streams | `open_stream`, `serve_stream`; a `Stream` has `send`, `send_value`, `close_send`, `reply`, `abort`, `close`, `recv`, and iterates its frames |
| pub/sub | `publish`, `subscribe`; a `Subscription` iterates its events, or `next(timeout_ms)` |
| content | `share_content`, `unshare_content`, `get_content` |
| DHT | `find_record`, `find_records`, `find_records_by_type`, `put_record` |

### UCANs

A procedure served with a `policy` answers only callers presenting a UCAN
(macula 12's post-quantum capability token) the policy accepts; the provider
checks each call and stream open before the handler sees it, as macula does,
and answers the rest `unauthorized` (or `malformed_frame` for a proof no
token in the chain names):

```python
from macula_py import UcanRequired
from macula_py.ucan import proof_id

served = await provider.serve(realm, procedure, handler, policy=UcanRequired(root.node_id()))

token = root.ucan(caller.node_id(), [{"with": "mri:org:io.macula/acme", "can": "invoke"}],
                  exp=int(time.time()) + 3600)
await caller.call(realm, procedure, payload, ucan=token)

# Delegated: alice hands the caller one procedure, naming her grant as its parent.
sub = alice.ucan(caller.node_id(), [{"with": "mri:proc:io.macula/acme/count_v1", "can": "invoke"}],
                 exp=int(time.time()) + 600, prf=[proof_id(to_alice)])
await caller.call(realm, procedure, payload, ucan=sub, proofs=[to_alice])
```

A token is minted for the node that will present it. `RealmMemberRequired(key_id, can)`
gates on a realm key instead, named by `macula_py.ucan.key_id(realm_public_key, profile)`
(the key as carried, bytes).
macula's `test/vectors/UCAN_V1.md` is the contract.

### Proofs for a realm and for a service

`NodeKey.device_request_proof(realm, procedure, request, rule)` signs a
device's request to a realm (realm proof v2): a join session's body
(`rule="http"`, a mapping or the body text exactly as sent) or a membership
UCAN request over the mesh (`rule="mesh"`). `NodeKey.ownership_proof(realm,
procedure, payload)` returns the payload with the `asserted_by` block that
authorises its fields to a service such as mcl_om; send it as the payload.
Neither signs a `"caller"`: the caller is the verified signer, so a request or
payload carrying one is refused.

Payloads are what macula's wire carries: `str`, `int` within int64, `float`,
`None`, `bytes`, lists and dicts with `str` keys. There is no boolean on the
wire: send 1 and 0. A Python `bool` is refused before it leaves, since
Python treats it as an int.

Every networked method is a coroutine, and each native call runs on a
thread of its own, so long waits never starve other calls. The methods that
take `timeout_ms`, and every wait for an event, a served call or a stream
frame, carry a cancel token: cancelling the task (or `asyncio.wait_for`
timing out) ends the native call at once. The rest (`publish`, `subscribe`,
`serve`, `stop`, `close`, and a stream's sends and ends) are short native
calls without one; cancelling stops the waiting and the call runs to its
end.

Errors are typed: `ProviderError`, `RelayError`, `StreamError`,
`NotSharedError`, `ContentUnavailableError`, `NoProviderError`, `MaculaTimeoutError` (also a
`TimeoutError`), `InvalidArgumentError` (also a `ValueError`),
`ClosedError`, `RefusedError`, all `MaculaError`.

## Development

Needs Go 1.27 and a C compiler to build macula-go's library locally.

```sh
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
eval "$(scripts/build_native.sh)"   # the library and teststation, from abi/MACULA_GO_REF
.venv/bin/pytest
```

`abi/macula.h` is macula-go's header at the ref in `abi/MACULA_GO_REF`;
`tests/test_abi_declarations.py` holds the ctypes declarations to it
function for function, and `build_native.sh` refuses a header that differs
from the ref's.

`scripts/live_check.sh` runs `tests/live/` against one fleet station
(helsinki and io.macula by default) with keys made for the run and never
saved. It publishes once, and advertises one UCAN-gated procedure in its own
namespace under a throwaway realm. CI never runs it.

`scripts/interop/ownership_proof.sh` and `scripts/interop/device_request.sh`
check proofs this binding signs against the verifiers themselves: mcl_om's
(in macula's pinned CI image), after the payload has crossed a station as a
provider receives it, and the realm's. See `scripts/interop/README.md`.

A `v*` tag publishes to PyPI through Trusted Publishing, using only
macula-go's released libraries, each checked against the release's
`SHA256SUMS` and its build provenance attestation.

## License

Apache-2.0. See [LICENSE](LICENSE).

---

<p align="center">
  <sub>Built on macula-go, for Python -- <a href="https://github.com/sponsors/rgfaber">sponsor the work</a> if this saved you some time</sub>
</p>

"""macula-py's side of sealed calls and streams across macula 13 and Python
(E2E seal scheme 1, through macula-go's shared library), for macula-go's
scripts/interop/erlang_sealed.escript, through one station. The Python twin of
macula-go's gosealed and tssealed.

    python pysealed.py <host:port@node_id hex> <profile> <realm hex> serve <hold s>
    python pysealed.py <host:port@node_id hex> <profile> <realm hex> call <provider node_id hex> [<peer>]

serve connects a pool with kem_advertise, serves ~<self>/vault (a call) and
~<self>/watch (a server stream), both confidential "required", refuses any
request that did not arrive sealed, prints "node <hex>" and "serving" and
holds. call calls ~<provider>/vault with call_report and opens
~<provider>/watch, both confidential "required", expecting the peer's texts
("kept by <peer>", "chunk from <peer>", "streamed by <peer>", peer "erlang" by
default), and requires each seal report to say sealed, the provider called and
a 16-hex key id; then checks that confidential "off" is refused
(InvalidArgumentError). It prints each outcome and exits 1 on any other.

Like tssealed, call makes no clear call to an explicit target: macula-py has no
API for one. That the provider refuses a clear call sealed_required is checked
in the other direction, by erlang_sealed.escript's call_station/8 against
serve.
"""

from __future__ import annotations

import asyncio
import re
import sys

from macula_py import (
    InvalidArgumentError,
    NodeKey,
    NoProviderError,
    Pool,
    SealReport,
    Seed,
    StreamData,
    StreamEnd,
    StreamMode,
    StreamReply,
)

KEY_ID = re.compile(r"^[0-9a-f]{16}$")


def seed_of(text: str) -> Seed:
    m = re.fullmatch(r"(.+):(\d+)@([0-9a-fA-F]{64})", text)
    if not m:
        raise SystemExit(f"pysealed: the station is host:port@<node_id hex>, not {text!r}")
    return Seed(m[1].strip("[]"), int(m[2]), m[3])


def own(node: str, name: str) -> str:
    return f"~{node}/{name}"


def as_text(body: object) -> str:
    return body.decode() if isinstance(body, bytes) else str(body)


def sealed_to(report: SealReport | None, provider: str) -> bool:
    return (
        report is not None
        and report.sealed
        and report.provider == provider
        and KEY_ID.match(report.seal_key_id or "") is not None
    )


async def serve(pool: Pool, realm: str, hold: str) -> int:
    this = pool.node_id()

    def vault(request):
        if not request.sealed:
            raise RuntimeError("a clear request reached the handler")
        return "kept by py"

    async def watch(stream):
        if not stream.request.sealed:
            raise RuntimeError("a clear session reached the handler")
        await stream.send(b"chunk from py")
        await stream.reply("streamed by py")

    await pool.serve(realm, own(this, "vault"), vault, confidential="required")
    await pool.serve_stream(realm, own(this, "watch"), StreamMode.SERVER, watch, confidential="required")
    print("serving", flush=True)
    await asyncio.sleep(float(hold))
    return 0


async def call(pool: Pool, realm: str, provider: str, peer: str) -> int:
    vault, watch = own(provider, "vault"), own(provider, "watch")
    reported: object = None
    for _ in range(150):
        try:
            reported = await pool.call_report(realm, vault, {"n": 1}, confidential="required", timeout_ms=10_000)
            break
        except NoProviderError as e:
            reported = e
            await asyncio.sleep(0.2)
        except Exception as e:  # printed as the outcome, which fails the verdict
            reported = e
            break
    called = reported if isinstance(reported, Exception) else reported.result
    print(f"sealed call: {called!r}")
    call_report = None if isinstance(reported, Exception) else reported.report
    print(f"call report: {call_report!r}")
    ok = called == f"kept by {peer}" and sealed_to(call_report, provider)

    chunk = reply = stream_report = None
    async with await pool.open_stream(
        realm, watch, StreamMode.SERVER, {}, confidential="required", timeout_ms=10_000
    ) as stream:
        try:
            for _ in range(4):
                frame = await stream.recv(timeout_ms=10_000)
                if isinstance(frame, StreamData):
                    chunk = as_text(frame.body)
                if isinstance(frame, StreamReply):
                    reply = frame.payload
                    break
                if isinstance(frame, StreamEnd) and frame.role == "both":
                    break
            # Settled on the provider's first chunk opened under the stream's
            # key, and kept after the end.
            stream_report = stream.report()
        except Exception as e:
            print(f"sealed stream error: {e!r}")
    print(f"sealed stream: chunk {chunk!r}, reply {reply!r}")
    print(f"stream report: {stream_report!r}")
    ok = ok and chunk == f"chunk from {peer}" and reply == f"streamed by {peer}" and sealed_to(stream_report, provider)

    # Off is refused, never ignored: a clear call is an explicit target's, and
    # macula-py offers none.
    try:
        off: object = await pool.call(realm, vault, {"n": 1}, confidential="off", timeout_ms=10_000)  # type: ignore[arg-type]
    except InvalidArgumentError as e:
        off = e
    print(f"off: {'refused invalid_argument' if isinstance(off, InvalidArgumentError) else repr(off)}")
    ok = ok and isinstance(off, InvalidArgumentError)
    print(f"verdict: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


async def main(station: str, profile: str, realm: str, mode: str, arg: str, peer: str = "erlang") -> int:
    key = await NodeKey.generate(profile)
    pool = await Pool.connect(key, [seed_of(station)], kem_advertise=mode == "serve", timeout_ms=60_000)
    print(f"node {pool.node_id()}", flush=True)
    async with pool:
        if mode == "serve":
            return await serve(pool, realm, arg)
        if mode == "call":
            return await call(pool, realm, arg, peer)
    print(f"pysealed: mode {mode!r} is serve or call", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main(*sys.argv[1:])))

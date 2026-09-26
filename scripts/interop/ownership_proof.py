"""Signs an ownership proof (v2, mcl-om#7) with macula-py and sends it the
real way: macula-py's JSON, libmacula's CBOR, a signed CALL, a station, and
a provider (scripts/interop/capture) that writes the payload as it received
it. macula-go's scripts/interop/erlang_ownership_proof.escript verify then
has mcl_om's own verifier accept it once, refuse it with one field changed,
and refuse it sent again. scripts/interop/ownership_proof.sh runs both.

    python scripts/interop/ownership_proof.py <capture binary> <out file>

Needs MACULA_TESTSTATION, as the tests do.
"""

from __future__ import annotations

import asyncio
import hashlib
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from macula_py import NodeKey, Pool, Seed  # noqa: E402
from tests.stations import TestStations  # noqa: E402

REALM = hashlib.sha256(b"io.macula").digest()
PROCEDURE = "mcl-graph/learn_link"
# Every type a payload carries; the escript changes "weight" to check a
# changed field is refused.
FIELDS = {
    "subject": "entity:alpha",
    "predicate": "knows",
    "object": "entity:beta",
    "confidence": 0.75,
    "weight": 3,
    "offset": -7,
    "digest": b"\x01\x02\x03",
    "note": None,
    "tags": ["a", "b"],
    "metadata": {"source": "field-notes", "page": 12},
}


async def main(capture: str, out: str) -> None:
    stations = TestStations("pq_hybrid")
    try:
        s0, s1 = stations.stations
        provider = subprocess.Popen(
            [capture, "-station", f"{s0.host}:{s0.port}@{s0.node_id}", "-profile", "pq_hybrid", "-out", out,
             "-realm", REALM.hex(), "-procedure", PROCEDURE],
            stdout=subprocess.PIPE, text=True,
        )
        capture_id = provider.stdout.readline().strip()
        key = await NodeKey.generate("pq_hybrid")
        async with await Pool.connect(key, [Seed(s1.host, s1.port, s1.node_id)]) as caller:
            signed = key.ownership_proof(REALM, PROCEDURE, FIELDS)
            # A sender may write a caller; the station link replaces it with
            # the one it authenticated, and it is never a signed field.
            signed["caller"] = "written by the sender"
            for _ in range(100):
                try:
                    reply = await caller.call(bytes(32), f"~{capture_id}/capture", signed)
                    break
                except Exception as e:  # the advertisement reaches the other station in its own time
                    last = e
                    await asyncio.sleep(0.2)
            else:
                raise RuntimeError(f"the capture was never reached: {last}")
        assert reply == "captured", reply
        if provider.wait(timeout=30) != 0:
            raise RuntimeError("capture failed")
        print(f"py-signed payload captured by {capture_id[:16]}: {out}")
    finally:
        stations.stop()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], sys.argv[2]))

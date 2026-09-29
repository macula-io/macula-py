"""macula-py's side of the live handshake v5 check (scripts/interop/v5.sh): a
pool linked to one running macula station, held while the station probes the
link with liveness_ping, then closed with a GOODBYE. It exits non-zero unless
the link came up and was still up after the hold; the station's verdict says
which handshake version the link spoke.

    python pyv5link.py <host> <port> <node_id hex> <profile> <hold s>
"""

from __future__ import annotations

import asyncio
import sys

from macula_py import NodeKey, Pool, Seed


async def main(host: str, port: str, node: str, profile: str, hold: str) -> int:
    key = await NodeKey.generate(profile)
    async with await Pool.connect(key, [Seed(host, int(port), node)], timeout_ms=30_000) as pool:
        print(f"linked as {pool.node_id()}: {pool.status()}")
        await asyncio.sleep(float(hold))
        up = [s for s in pool.status() if s.station == node and s.up]
        print(f"after {hold} s: {pool.status()}")
    print(f"verdict: {'PASS' if up else 'FAIL'}")
    return 0 if up else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main(*sys.argv[1:])))

"""Signs a join session's body (realm proof v2, macula-realm#29) with
macula-py and writes what the realm receives, for
scripts/interop/realm_device_request.exs: the carried public key, the realm
id, the procedure, the proof, and the body exactly as sent, one per line.

    python scripts/interop/device_request.py <out file>
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from macula_py import NodeKey  # noqa: E402
from macula_py.device_request import JOIN_SESSION  # noqa: E402

REALM = hashlib.sha256(b"io.macula").digest()


async def main(out: str) -> None:
    key = await NodeKey.generate("pq_hybrid")
    body = json.dumps(
        {"public_key": key.public_key().hex(), "device_info": {"hostname": "py.local", "note": None}, "n": 2}
    )
    proof = key.device_request_proof(REALM, JOIN_SESSION, body, "http")
    Path(out).write_text(
        "\n".join([key.public_key().hex(), REALM.hex(), JOIN_SESSION, json.dumps(proof), body]) + "\n"
    )
    print(f"py-signed join session for {key.node_id_hex()[:16]}: {out}")


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))

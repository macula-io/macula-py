"""A live run against one macula 12 station: the pool connects pinned, reads
the DHT, calls mcl-echo/echo by direct dial, and hears its own publication.

Runs only with MACULA_PY_LIVE set (scripts/live_check.sh); it puts nothing in
the DHT and publishes once. The key is generated for the run and never saved.
Once MACULA_PY_LIVE is set, every other variable is required: a missing one
fails naming itself, it never skips.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest

from macula_py import NodeKey, Pool, RecordType, Seed

pytestmark = pytest.mark.skipif(not os.environ.get("MACULA_PY_LIVE"), reason="MACULA_PY_LIVE not set")


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"macula-py live check: {name} is not set")
    return value


def _seed(text: str) -> tuple[str, int]:
    host, _, port = text.rpartition(":")
    return host.strip("[]"), int(port)


@pytest.fixture(scope="module")
def live():
    host, port = _seed(_required("MACULA_PY_LIVE_SEED"))
    return {
        "host": host,
        "port": port,
        "node_id": _required("MACULA_PY_LIVE_STATION_ID"),
        "realm": _required("MACULA_PY_LIVE_REALM"),
        "realm_key": _required("MACULA_PY_LIVE_REALM_KEY"),
    }


@pytest.fixture
async def pool(live):
    key = await NodeKey.generate("pq_hybrid")
    pool = await Pool.connect(
        key,
        [Seed(live["host"], live["port"], live["node_id"])],
        realm_trust={live["realm"]: live["realm_key"]},
        timeout_ms=60_000,
    )
    try:
        yield pool
    finally:
        await pool.close()
        key.free()


async def test_holds_verified_node_records(pool):
    found = await pool.find_records_by_type(RecordType.NODE_RECORD, timeout_ms=30_000)
    assert len(found.records) > 0


async def test_reaches_mcl_echo_by_direct_dial(pool, live):
    assert await pool.call(live["realm"], "mcl-echo/echo", "hello", timeout_ms=15_000) == "hello"


async def test_hears_its_own_publication(pool, live):
    topic = f"mcl-py/live/check/publication_heard_v1/{uuid.uuid4().hex}"
    async with await pool.subscribe(live["realm"], topic) as subscription:
        await asyncio.sleep(0.3)
        await pool.publish(live["realm"], topic, "heard")
        event = await asyncio.wait_for(anext(aiter(subscription)), timeout=10)
    assert event.payload == "heard"

"""A live run against one macula 12 station: the pool connects pinned, reads
the DHT, calls mcl-echo/echo by direct dial, hears its own publication, and
serves a UCAN-gated procedure that the station routes to it.

Runs only with MACULA_PY_LIVE set (scripts/live_check.sh). It publishes once,
and the gated check advertises one procedure in its own namespace under a
throwaway realm, withdrawn when it ends. Keys are generated for the run and
never saved.
Once MACULA_PY_LIVE is set, every other variable is required: a missing one
fails naming itself, it never skips.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import time
import uuid

import pytest

from macula_py import NodeKey, Pool, ProviderError, RecordType, Seed, UcanRequired

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


async def test_a_gated_procedure_is_served_to_its_grant_alone(live):
    # A named throwaway realm (its id the name's SHA-256), a procedure in the
    # provider's own namespace gated on a root key made for the run.
    realm_name = f"macula-py-live-{uuid.uuid4().hex[:12]}"
    realm = hashlib.sha256(realm_name.encode()).digest()
    seeds = [Seed(live["host"], live["port"], live["node_id"])]
    provider_key, caller_key, root = [await NodeKey.generate("pq_hybrid") for _ in range(3)]
    async with await Pool.connect(provider_key, seeds, timeout_ms=60_000) as provider, await Pool.connect(
        caller_key, seeds, timeout_ms=60_000
    ) as caller:
        procedure = provider.own_procedure("gated")
        async with await provider.serve(
            realm, procedure, lambda request: "served", policy=UcanRequired(root.node_id())
        ):
            grant = root.ucan(
                caller.node_id(), [{"with": f"mri:realm:{realm_name}", "can": "invoke"}], exp=int(time.time()) + 300
            )
            deadline = time.monotonic() + 30
            while True:
                try:
                    assert await caller.call(realm, procedure, {}, ucan=grant, timeout_ms=15_000) == "served"
                    break
                except ProviderError as e:
                    if e.code != "unknown_next_peer" or time.monotonic() > deadline:
                        raise
                    await asyncio.sleep(0.5)
            with pytest.raises(ProviderError) as refused:
                await caller.call(realm, procedure, {}, timeout_ms=15_000)
            assert refused.value.code == "unauthorized"

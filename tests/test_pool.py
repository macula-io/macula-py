"""The Python API over macula-go's C ABI, against two in-process macula 12
stations (tests/stations.py): calls by direct dial and their errors,
providers, a node's own namespace, streams (and that every stream is
released), pubsub, content, the DHT, and cancellation."""

from __future__ import annotations

import asyncio
import time

import pytest

from macula_py import (
    ContentUnavailableError,
    InvalidArgumentError,
    NodeKey,
    NotSharedError,
    Pool,
    ProviderError,
    RecordType,
    Seed,
    StreamData,
    StreamEnd,
    StreamMode,
    StreamReply,
)
from tests.stations import TestStations


@pytest.fixture(scope="module")
def env():
    stations = TestStations("pq_pure")
    yield stations
    stations.stop()


def seed(env, i: int) -> Seed:
    s = env.stations[i]
    return Seed(s.host, s.port, s.node_id)


async def node(env, station: int, admitted: bool = False, trusted: bool = True) -> Pool:
    key = await NodeKey.generate("pq_pure")
    if admitted:
        env.admit(key.node_id_hex())
    trust = {env.realm_id: env.realm_key} if trusted else None
    return await Pool.connect(key, [seed(env, station)], realm_trust=trust)


async def eventually(what: str, ok, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await ok() if asyncio.iscoroutinefunction(ok) else ok():
            return
        await asyncio.sleep(0.025)
    raise AssertionError(f"never: {what}")


class TestCalls:
    async def test_reach_a_provider_on_another_station_and_bring_its_error_back(self, env):
        provider = await node(env, 0, admitted=True)
        procedure = f"{env.org}/echo"

        def echo(request):
            if request.payload == "fail":
                raise RuntimeError("refused by the handler")
            return {"echo": request.payload, "caller": request.caller}

        caller = await node(env, 1)
        async with provider, caller, await provider.serve(env.realm_id, procedure, echo):
            result = await caller.call(env.realm_id, procedure, "hello")
            assert result == {"echo": "hello", "caller": caller.node_id()}
            with pytest.raises(ProviderError) as refused:
                await caller.call(env.realm_id, procedure, "fail")
            assert (refused.value.code, refused.value.detail) == ("handler_error", "refused by the handler")
            providers = await caller.providers(env.realm_id, procedure)
            assert provider.node_id() in [p.node for p in providers]

    async def test_an_async_handler_answers_and_bytes_cross_both_ways_unchanged(self, env):
        provider = await node(env, 0, admitted=True)
        procedure = f"{env.org}/bytes_back"

        async def back(request):
            await asyncio.sleep(0.01)
            return {"got": request.payload, "big": 2**64 - 1}

        caller = await node(env, 1)
        async with provider, caller, await provider.serve(env.realm_id, procedure, back):
            result = await caller.call(env.realm_id, procedure, b"\x00\x01\xff")
            assert result == {"got": b"\x00\x01\xff", "big": 2**64 - 1}

    async def test_refuse_an_unpinned_realm_and_find_no_provider_for_what_nobody_serves(self, env):
        async with await node(env, 0) as caller:
            with pytest.raises(Exception, match="realm key"):
                await caller.call("11" * 32, f"{env.org}/echo", {})
            with pytest.raises(Exception, match="no trusted provider"):
                await caller.call(env.realm_id, f"{env.org}/nothing", {})

    async def test_a_boolean_payload_is_refused_before_it_leaves(self, env):
        async with await node(env, 0) as caller:
            with pytest.raises(TypeError, match="no boolean"):
                await caller.call(env.realm_id, f"{env.org}/echo", {"ok": True})


class TestOwnNamespace:
    async def test_is_served_and_called_with_no_realm_key_pinned_on_either_side(self, env):
        provider = await node(env, 0, trusted=False)
        ring = provider.own_procedure("ring")
        assert ring == f"~{provider.node_id()}/ring"
        caller = await node(env, 1, trusted=False)
        async with provider, caller, await provider.serve(env.realm_id, ring, lambda r: {"rung_by": r.caller}):
            assert await caller.call(env.realm_id, ring, {}) == {"rung_by": caller.node_id()}
            assert [p.node for p in await caller.providers(env.realm_id, ring)] == [provider.node_id()]

    async def test_refuses_to_serve_in_another_nodes_namespace(self, env):
        async with await node(env, 0, trusted=False) as p:
            with pytest.raises(Exception, match="own namespace"):
                await p.serve(env.realm_id, f"~{'01' * 32}/ring", lambda r: 1)


class TestStreams:
    async def test_a_server_streams_chunks_arrive_and_nothing_stays_relayed(self, env):
        provider = await node(env, 0, admitted=True)
        procedure = f"{env.org}/watch"

        async def watch(stream):
            for chunk in (b"one", b"two", b"three"):
                await stream.send(chunk)

        caller = await node(env, 1)
        async with provider, caller, await provider.serve_stream(env.realm_id, procedure, StreamMode.SERVER, watch):
            got = []
            async with await caller.open_stream(env.realm_id, procedure, StreamMode.SERVER) as stream:
                async for frame in stream:
                    if isinstance(frame, StreamData):
                        got.append(frame.body)
                    if isinstance(frame, StreamEnd):
                        break
            assert got == [b"one", b"two", b"three"]
            await eventually("every stream released", lambda: env.relayed() == 0)

    async def test_a_client_stream_is_answered_with_the_providers_reply(self, env):
        provider = await node(env, 0, admitted=True)
        procedure = f"{env.org}/count"

        async def count(stream):
            total = 0
            async for frame in stream:
                if isinstance(frame, StreamData):
                    total += len(frame.body)
                if isinstance(frame, StreamEnd):
                    break
            await stream.reply(total)

        caller = await node(env, 0)
        async with provider, caller, await provider.serve_stream(env.realm_id, procedure, StreamMode.CLIENT, count):
            async with await caller.open_stream(env.realm_id, procedure, StreamMode.CLIENT) as stream:
                for chunk in (b"ab", b"cde", b"f"):
                    await stream.send(chunk)
                await stream.close_send()
                assert await stream.recv(timeout_ms=5_000) == StreamReply(payload=6)
            await eventually("every stream released", lambda: env.relayed() == 0)


class TestPubSub:
    async def test_a_publication_is_heard_once_by_a_subscriber_on_the_same_station(self, env):
        listener = await node(env, 0)
        publisher = await node(env, 0)
        topic = "mcl-py/tests/greeting_sent_v1"
        async with listener, publisher:
            async with await listener.subscribe(env.realm_id, topic) as subscription:
                await asyncio.sleep(0.2)
                await publisher.publish(env.realm_id, topic, "hi")
                event = await subscription.next(timeout_ms=10_000)
                assert event is not None
                assert (event.payload, event.topic, event.publisher) == ("hi", topic, publisher.node_id())
                assert await subscription.next(timeout_ms=300) is None
                assert subscription.dropped() == 0


class TestContent:
    @staticmethod
    def pattern(n: int) -> bytes:
        return bytes(i % 251 for i in range(n))

    async def test_is_shared_by_one_node_and_fetched_by_another_until_it_is_unshared(self, env):
        sharer = await node(env, 0, trusted=False)
        fetcher = await node(env, 1, trusted=False)
        async with sharer, fetcher:
            for size in (10_000, 600_000):
                data = self.pattern(size)
                mcid = await sharer.share_content(env.realm_id, data, "blob.bin")
                assert len(mcid) == 50 and mcid[0] == 0x02 and mcid[1] in (0x55, 0x56)
                assert await fetcher.get_content(env.realm_id, mcid) == data
                await sharer.unshare_content(env.realm_id, mcid)
                with pytest.raises(NotSharedError):
                    await fetcher.get_content(env.realm_id, mcid)

    async def test_refuses_content_over_the_bounds_and_an_id_that_is_not_one(self, env):
        sharer = await node(env, 0, trusted=False)
        fetcher = await node(env, 1, trusted=False)
        async with sharer, fetcher:
            mcid = await sharer.share_content(env.realm_id, self.pattern(600_000), "big.bin")
            with pytest.raises(ContentUnavailableError, match="over the bounds"):
                await fetcher.get_content(env.realm_id, mcid, max_bytes=500_000)
            with pytest.raises(ValueError, match="content id"):
                await fetcher.get_content(env.realm_id, "02" + "55" * 10)


class TestDht:
    async def test_finds_the_stations_own_endpoint_records_verified(self, env):
        async with await node(env, 0) as p:
            found = await p.find_records_by_type(RecordType.STATION_ENDPOINT)
            assert found.dropped == 0
            assert sorted(r.key_id for r in found.records) == sorted(s.node_id for s in env.stations)
            assert await p.find_record("22" * 32) is None


class TestPool:
    async def test_status_names_the_seed_link_up(self, env):
        async with await node(env, 0) as p:
            links = p.status()
            assert [(link.station, link.up) for link in links if link.station == env.stations[0].node_id] == [
                (env.stations[0].node_id, True)
            ]

    async def test_a_closed_pool_is_refused_loudly(self, env):
        p = await node(env, 0)
        await p.close()
        with pytest.raises(Exception, match="closed"):
            p.node_id()

    async def test_a_malformed_seed_is_refused_as_an_invalid_argument(self, env):
        key = await NodeKey.generate("pq_pure")
        with pytest.raises((ValueError, InvalidArgumentError)):
            await Pool.connect(key, [Seed("127.0.0.1", 1, "zz")])


class TestCancellation:
    async def test_cancelling_a_waiting_subscription_ends_the_native_wait_at_once(self, env):
        async with await node(env, 0) as p:
            async with await p.subscribe(env.realm_id, "mcl-py/tests/nothing_said_v1") as subscription:
                waiting = asyncio.create_task(subscription.next(timeout_ms=0))
                await asyncio.sleep(0.1)
                started = time.monotonic()
                waiting.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await waiting
                assert time.monotonic() - started < 1.0

    async def test_a_timed_out_call_on_a_task_wait_for_is_cancelled_not_left_running(self, env):
        provider = await node(env, 0, admitted=True)
        procedure = f"{env.org}/slow"

        async def slow(_request):
            await asyncio.sleep(3)
            return "late"

        caller = await node(env, 1)
        async with provider, caller, await provider.serve(env.realm_id, procedure, slow):
            started = time.monotonic()
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(caller.call(env.realm_id, procedure, {}, timeout_ms=10_000), 0.3)
            assert time.monotonic() - started < 1.5

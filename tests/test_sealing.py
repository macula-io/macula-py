"""Sealing (macula 13's E2E seal scheme 1, macula-go v0.18.0) and the
caller's seal report (macula's DESIGN_E2E_SEAL_REPORT, macula-go v0.19.0)
through the Python API, against two in-process stations (tests/stations.py):
a provider that names its KEM key is called sealed, one that names none in
the clear, what cannot be kept confidential fails as a ConfidentialityError,
and a caller learns whether the exchange behind its result was sealed, to
which provider and key."""

from __future__ import annotations

import asyncio
import re
import time

import pytest

from macula_py import (
    ConfidentialityError,
    InvalidArgumentError,
    NodeKey,
    NoProviderError,
    NotACallerError,
    NotSettledError,
    Pool,
    Reported,
    SealReport,
    Seed,
    StreamData,
    StreamEnd,
    StreamMode,
    StreamReply,
)
from macula_py.ucan import UcanRequired
from tests.stations import TestStations

KEY_ID = re.compile(r"^[0-9a-f]{16}$")


@pytest.fixture(scope="module")
def env():
    stations = TestStations("pq_pure")
    yield stations
    stations.stop()


async def node(env, station: int, *, kem_advertise: bool = False, admitted: bool = False) -> Pool:
    key = await NodeKey.generate("pq_pure")
    if admitted:
        env.admit(key.node_id_hex())
    s = env.stations[station]
    return await Pool.connect(
        key, [Seed(s.host, s.port, s.node_id)], realm_trust={env.realm_id: env.realm_key}, kem_advertise=kem_advertise
    )


async def until_served(attempt):
    """attempt() until the provider, not the DHT's reach, answers: an
    advertisement reaches the other station's DHT in its own time."""
    deadline = time.monotonic() + 20
    while True:
        try:
            return await attempt()
        except NoProviderError:
            if time.monotonic() > deadline:
                raise
            await asyncio.sleep(0.1)


class TestConnect:
    async def test_kem_advertise_is_a_bool_and_off_by_default(self, env):
        s = env.stations[0]
        key = await NodeKey.generate("pq_pure")
        try:
            with pytest.raises(TypeError):
                await Pool.connect(key, [Seed(s.host, s.port, s.node_id)], kem_advertise=1)
        finally:
            key.free()
        # Off by default: serving required needs it, and says so.
        provider = await node(env, 0)
        async with provider:
            with pytest.raises(ConfidentialityError) as refused:
                await provider.serve(env.realm_id, provider.own_procedure("x"), lambda r: 1, confidential="required")
            assert refused.value.reason == "kem_advertise_disabled"
            with pytest.raises(ConfidentialityError) as refused:
                await provider.serve_stream(
                    env.realm_id, provider.own_procedure("y"), StreamMode.SERVER, _nothing, confidential="required"
                )
            assert refused.value.reason == "kem_advertise_disabled"


class TestSealedCalls:
    async def test_a_provider_that_names_its_key_is_called_sealed_by_default_and_required(self, env):
        provider = await node(env, 0, kem_advertise=True)
        procedure = provider.own_procedure("sealed_echo")
        caller = await node(env, 1)
        async with provider, caller, await provider.serve(
            env.realm_id, procedure, lambda r: {"echoed": r.payload, "sealed": int(r.sealed)}, confidential="required"
        ):
            assert await caller.call(env.realm_id, procedure, {"word": "hush"}, confidential="required") == {
                "echoed": {"word": "hush"},
                "sealed": 1,
            }
            assert await caller.call(env.realm_id, procedure, {"word": "again"}) == {
                "echoed": {"word": "again"},
                "sealed": 1,
            }

    async def test_a_pinned_provider_is_called_sealed_and_no_other(self, env):
        provider = await node(env, 0, kem_advertise=True)
        other = await node(env, 0, kem_advertise=True)
        procedure = provider.own_procedure("pinned")
        caller = await node(env, 1)
        async with provider, other, caller, await provider.serve(env.realm_id, procedure, lambda r: provider.node_id()):
            assert (
                await caller.call(env.realm_id, procedure, {}, provider=provider.node_id(), confidential="required")
                == provider.node_id()
            )
            with pytest.raises(NoProviderError):
                await caller.call(env.realm_id, procedure, {}, provider=other.node_id())

    async def test_a_provider_that_names_no_key_is_called_clear_and_required_refuses_it(self, env):
        provider = await node(env, 0)
        procedure = provider.own_procedure("clear_echo")
        caller = await node(env, 1)
        async with provider, caller, await provider.serve(env.realm_id, procedure, lambda r: {"sealed": int(r.sealed)}):
            assert await caller.call(env.realm_id, procedure, {}) == {"sealed": 0}
            with pytest.raises(ConfidentialityError) as refused:
                await caller.call(env.realm_id, procedure, {}, confidential="required")
            assert (refused.value.reason, refused.value.named, refused.value.found) == ("no_kem_key", None, None)

    async def test_off_and_anything_unknown_are_refused_on_the_callers_side(self, env):
        caller = await node(env, 1)
        async with caller:
            for confidential in ("off", "maybe"):
                with pytest.raises(InvalidArgumentError):
                    await caller.call(env.realm_id, caller.own_procedure("x"), {}, confidential=confidential)
                with pytest.raises(InvalidArgumentError):
                    await caller.open_stream(
                        env.realm_id, caller.own_procedure("x"), StreamMode.SERVER, confidential=confidential
                    )

    async def test_a_gated_procedure_is_called_sealed_with_its_ucan(self, env):
        # The presentation and the confidentiality travel in one options set.
        provider = await node(env, 0, kem_advertise=True, admitted=True)
        procedure = f"{env.org}/sealed_gated"
        caller = await node(env, 1)
        root = await NodeKey.generate("pq_pure")
        token = root.ucan(
            caller.node_id(), [{"with": f"mri:org:{env.realm_name}/{env.org}", "can": "invoke"}], exp=int(time.time()) + 300
        )
        async with provider, caller, await provider.serve(
            env.realm_id,
            procedure,
            lambda r: {"sealed": int(r.sealed)},
            policy=UcanRequired(root.node_id()),
            confidential="required",
        ):
            reported = await until_served(
                lambda: caller.call_report(env.realm_id, procedure, {}, ucan=token, confidential="required")
            )
            assert reported.result == {"sealed": 1}
            assert reported.report.sealed is True


class TestServing:
    async def test_off_serves_clear_even_from_a_node_that_names_its_key(self, env):
        provider = await node(env, 0, kem_advertise=True)
        procedure = provider.own_procedure("off_echo")
        caller = await node(env, 1)
        async with provider, caller, await provider.serve(
            env.realm_id, procedure, lambda r: {"sealed": int(r.sealed)}, confidential="off"
        ):
            assert await caller.call(env.realm_id, procedure, {}) == {"sealed": 0}

    async def test_an_unknown_confidentiality_is_refused(self, env):
        provider = await node(env, 0, kem_advertise=True)
        async with provider:
            with pytest.raises(InvalidArgumentError):
                await provider.serve(env.realm_id, provider.own_procedure("x"), lambda r: 1, confidential="maybe")
            with pytest.raises(InvalidArgumentError):
                await provider.serve_stream(
                    env.realm_id, provider.own_procedure("y"), StreamMode.SERVER, _nothing, confidential="maybe"
                )


async def _nothing(stream) -> None:
    return None


class TestSealedStreams:
    async def test_a_stream_opens_sealed_to_a_provider_that_names_its_key_and_its_session_says_so(self, env):
        provider = await node(env, 0, kem_advertise=True)
        procedure = provider.own_procedure("sealed_count")

        async def count(stream):
            total = 0
            async for frame in stream:
                if isinstance(frame, StreamData):
                    total += len(frame.body)
                if isinstance(frame, StreamEnd):
                    break
            await stream.reply({"total": total, "sealed": int(stream.request.sealed)})

        caller = await node(env, 1)
        async with provider, caller, await provider.serve_stream(
            env.realm_id, procedure, StreamMode.CLIENT, count, confidential="required"
        ):
            async with await caller.open_stream(
                env.realm_id, procedure, StreamMode.CLIENT, confidential="required"
            ) as stream:
                for chunk in (b"ab", b"cde"):
                    await stream.send(chunk)
                await stream.close_send()
                assert await stream.recv(timeout_ms=5_000) == StreamReply(payload={"total": 5, "sealed": 1})

    async def test_required_will_not_open_one_to_a_provider_that_names_no_key(self, env):
        provider = await node(env, 0)
        procedure = provider.own_procedure("clear_watch")
        caller = await node(env, 1)
        async with provider, caller, await provider.serve_stream(env.realm_id, procedure, StreamMode.SERVER, _nothing):
            with pytest.raises(ConfidentialityError) as refused:
                await caller.open_stream(env.realm_id, procedure, StreamMode.SERVER, confidential="required")
            assert refused.value.reason == "no_kem_key"


class TestSealReport:
    async def test_a_call_to_a_provider_that_names_its_key_reports_sealed_to_that_provider_and_key(self, env):
        provider = await node(env, 0, kem_advertise=True)
        procedure = provider.own_procedure("reported")
        caller = await node(env, 1)
        async with provider, caller, await provider.serve(env.realm_id, procedure, lambda r: {"echoed": r.payload}):
            reported = await caller.call_report(env.realm_id, procedure, {"word": "hush"})
            assert isinstance(reported, Reported)
            result, report = reported
            assert result == {"echoed": {"word": "hush"}}
            assert report.sealed is True
            assert report.provider == provider.node_id()
            assert report.seal_key_id is not None and KEY_ID.match(report.seal_key_id)

    async def test_a_pinned_call_reports_the_provider_pinned(self, env):
        provider = await node(env, 0, kem_advertise=True)
        other = await node(env, 0, kem_advertise=True)
        procedure = provider.own_procedure("reported_pinned")
        caller = await node(env, 1)
        async with provider, other, caller, await provider.serve(env.realm_id, procedure, lambda r: 1):
            result, report = await caller.call_report(
                env.realm_id, procedure, {}, provider=provider.node_id(), confidential="required"
            )
            assert result == 1
            assert (report.sealed, report.provider) == (True, provider.node_id())
            with pytest.raises(NoProviderError):
                await caller.call_report(env.realm_id, procedure, {}, provider=other.node_id())

    async def test_a_call_to_a_provider_that_names_no_key_reports_clear_with_no_key_id(self, env):
        provider = await node(env, 0)
        procedure = provider.own_procedure("reported_clear")
        caller = await node(env, 1)
        async with provider, caller, await provider.serve(env.realm_id, procedure, lambda r: 1):
            assert await caller.call_report(env.realm_id, procedure, {}) == Reported(
                1, SealReport(sealed=False, provider=provider.node_id(), seal_key_id=None)
            )

    async def test_a_streams_report_settles_on_the_first_chunk_stays_after_the_end_and_the_provider_has_none(
        self, env
    ):
        provider = await node(env, 0, kem_advertise=True)
        procedure = provider.own_procedure("reported_watch")
        provider_side: list[object] = []
        # The provider holds its chunk until the caller has seen the report
        # unsettled, so the order is by construction, not by a timer.
        released = asyncio.Event()

        async def watch(stream):
            try:
                provider_side.append(stream.report())
            except NotACallerError as e:
                provider_side.append(e)
            await released.wait()
            await stream.send(b"one")

        caller = await node(env, 1)
        async with provider, caller, await provider.serve_stream(
            env.realm_id, procedure, StreamMode.SERVER, watch, confidential="required"
        ):
            async with await caller.open_stream(
                env.realm_id, procedure, StreamMode.SERVER, confidential="required"
            ) as stream:
                with pytest.raises(NotSettledError):
                    stream.report()
                released.set()
                assert isinstance(await stream.recv(timeout_ms=5_000), StreamData)
                settled = stream.report()
                assert settled.sealed is True
                assert settled.provider == provider.node_id()
                assert settled.seal_key_id is not None and KEY_ID.match(settled.seal_key_id)
                assert isinstance(await stream.recv(timeout_ms=5_000), StreamEnd)
                assert stream.report() == settled
            assert len(provider_side) == 1 and isinstance(provider_side[0], NotACallerError)

    async def test_a_sealed_stream_the_provider_ends_before_any_chunk_has_no_report(self, env):
        provider = await node(env, 0, kem_advertise=True)
        procedure = provider.own_procedure("ended_unsettled")
        caller = await node(env, 1)
        async with provider, caller, await provider.serve_stream(
            env.realm_id, procedure, StreamMode.SERVER, _nothing, confidential="required"
        ):
            async with await caller.open_stream(
                env.realm_id, procedure, StreamMode.SERVER, confidential="required"
            ) as stream:
                assert isinstance(await stream.recv(timeout_ms=5_000), StreamEnd)
                with pytest.raises(NotSettledError):
                    stream.report()

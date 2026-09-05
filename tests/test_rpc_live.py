"""Dials the real production demo fleet. Same fleet-flakiness caveat as
test_connection_live.py.

Provider and caller use SEPARATE identities and SEPARATE Sessions --
confirmed elsewhere in this org's own live SDK work that a station kicks
a second connection under the SAME identity, so sharing one here would
make the provider's own connection (and its advertised procedure) die
the moment the caller's connection to the same station opened.
"""

import asyncio
import uuid

import pytest

from macula_py import bolt4, frame
from macula_py.connection import Session
from macula_py.identity import KeyPair

STATION_HOST = "station-de-frankfurt.macula.io"
STATION_PORT = 4433


@pytest.mark.live
async def test_unary_call_against_a_nonexistent_procedure_reports_unknown_next_peer():
    identity = KeyPair.generate()
    session = await Session.connect(STATION_HOST, STATION_PORT, identity)
    try:
        realm = bytes(32)
        response = await session.call(
            f"macula_py.definitely_not_a_real_procedure.{uuid.uuid4().hex}",
            realm,
            "hello",
            frame.current_millis() + 10_000,
            timeout=10.0,
        )
        assert isinstance(response, frame.CallError)
        assert response.name == "unknown_next_peer"
        assert response.code == bolt4.UNKNOWN_NEXT_PEER
    finally:
        await session.close()


@pytest.mark.live
async def test_advertise_serve_and_call_round_trip_gets_a_real_result():
    # This is the standard this org's own SDK work holds real proof to:
    # "reached the call stage with a clean unknown_next_peer" only proves
    # the caller's own path works, NOT that serving is reachable. The
    # only real proof is an actual RESULT payload from an actual running
    # handler -- so this test drives both roles for real.
    provider_id = KeyPair.generate()
    caller_id = KeyPair.generate()
    realm = bytes(32)
    procedure = f"macula_py.test_echo.{uuid.uuid4().hex}"

    provider = await Session.connect(STATION_HOST, STATION_PORT, provider_id)
    caller = await Session.connect(STATION_HOST, STATION_PORT, caller_id)
    try:
        await provider.advertise(realm, procedure)
        await asyncio.sleep(0.5)  # let the advertisement land before calling

        async def echo_handler(payload):
            return {"echoed": payload}

        def lookup(_realm: bytes, proc: str):
            return echo_handler if proc == procedure else None

        serve_task = asyncio.create_task(provider.serve_one_call(lookup, timeout=15.0))
        response = await caller.call(procedure, realm, "hello from the caller", frame.current_millis() + 10_000, timeout=10.0)
        await serve_task  # propagate any exception from the serve side

        assert isinstance(response, frame.CallResult), f"expected a real RESULT, got {response!r}"
        assert response.payload == {"echoed": "hello from the caller"}
        assert response.responded_by == provider_id.node_id()
    finally:
        await provider.unadvertise(realm, procedure)
        await provider.close()
        await caller.close()


@pytest.mark.live
async def test_a_handler_that_raises_reports_unknown_error_with_detail():
    provider_id = KeyPair.generate()
    caller_id = KeyPair.generate()
    realm = bytes(32)
    procedure = f"macula_py.test_raise.{uuid.uuid4().hex}"

    provider = await Session.connect(STATION_HOST, STATION_PORT, provider_id)
    caller = await Session.connect(STATION_HOST, STATION_PORT, caller_id)
    try:
        await provider.advertise(realm, procedure)
        await asyncio.sleep(0.5)

        async def failing_handler(_payload):
            raise ValueError("boom")

        def lookup(_realm: bytes, proc: str):
            return failing_handler if proc == procedure else None

        serve_task = asyncio.create_task(provider.serve_one_call(lookup, timeout=15.0))
        response = await caller.call(procedure, realm, None, frame.current_millis() + 10_000, timeout=10.0)
        await serve_task

        assert isinstance(response, frame.CallError)
        assert response.name == "unknown_error"
        assert response.detail == "boom"
    finally:
        await provider.unadvertise(realm, procedure)
        await provider.close()
        await caller.close()

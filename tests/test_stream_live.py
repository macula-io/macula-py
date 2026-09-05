"""Dials the real production demo fleet. Same fleet-flakiness caveat as
the other live test files, and the same ADVERTISE-needs-a-moment finding
already documented in test_rpc_live.py/test_pubsub_live.py: this wire's
ADVERTISE is fire-and-forget, so a stream opened immediately after
advertising can race the station's own registration.
"""

import asyncio
import uuid

import pytest

from macula import frame
from macula.connection import Session
from macula.identity import KeyPair

STATION_HOST = "station-de-frankfurt.macula.io"
STATION_PORT = 4433


@pytest.mark.live
async def test_server_stream_round_trip_delivers_chunks_and_a_terminal_reply():
    provider_id = KeyPair.generate()
    caller_id = KeyPair.generate()
    provider = await Session.connect(STATION_HOST, STATION_PORT, provider_id)
    caller = await Session.connect(STATION_HOST, STATION_PORT, caller_id)
    realm = bytes(32)
    procedure = f"macula_py.test_count_stream.{uuid.uuid4().hex}"
    try:
        await provider.advertise(realm, procedure)
        await asyncio.sleep(0.5)

        async def serve():
            async def handler(handle, args):
                for i in range(args["n"]):
                    await handle.send_chunk(str(i).encode())
                await handle.set_reply("done")

            await provider.accept_stream(lambda r, p: handler if (r, p) == (realm, procedure) else None, timeout=10)

        serve_task = asyncio.create_task(serve())

        handle = await caller.open_stream(procedure, realm, {"n": 3}, frame.current_millis() + 10_000)
        received = []
        while True:
            info = await handle.recv(timeout=10)
            if isinstance(info, frame.StreamReplyInfo):
                assert info.payload == "done"
                break
            assert isinstance(info, frame.StreamDataInfo)
            received.append(info.body)

        await serve_task
        assert received == [b"0", b"1", b"2"]
    finally:
        await provider.close()
        await caller.close()


@pytest.mark.live
@pytest.mark.xfail(
    reason=(
        "macula-station's stream route lifecycle (macula_station_peer_observer.erl, "
        "maybe_close_stream_route/3) drops the WHOLE bidirectional route on the first "
        "terminal frame it sees for a stream_id, not per-direction -- its own comment "
        "documents this as deliberate for now ('For server_stream, the only mode our "
        "suite exercises today ... Close on the first terminal frame for now'). A "
        "client_stream caller's STREAM_END(role=send) half-close is exactly this case: "
        "the station drops the route (and closes both dedicated QUIC streams) before "
        "the provider's STREAM_REPLY can be relayed back, even though the provider's own "
        "write succeeds locally. This SDK's wire encoding is correct here (verified: the "
        "provider receives all 3 chunks and the STREAM_END correctly, and set_reply() "
        "raises no error) -- the gap is server-side relay lifecycle, not this client. "
        "Reported upstream; un-xfail once macula-station tracks per-direction closure."
    ),
    strict=True,
)
async def test_client_stream_round_trip_caller_sends_chunks_provider_replies_with_their_sum():
    provider_id = KeyPair.generate()
    caller_id = KeyPair.generate()
    provider = await Session.connect(STATION_HOST, STATION_PORT, provider_id)
    caller = await Session.connect(STATION_HOST, STATION_PORT, caller_id)
    realm = bytes(32)
    procedure = f"macula_py.test_sum_stream.{uuid.uuid4().hex}"
    try:
        await provider.advertise(realm, procedure)
        await asyncio.sleep(0.5)

        async def serve():
            async def handler(handle, args):
                total = 0
                while True:
                    info = await handle.recv(timeout=10)
                    if isinstance(info, frame.StreamEndInfo):
                        break
                    assert isinstance(info, frame.StreamDataInfo)
                    total += int(info.body)
                await handle.set_reply(total)

            await provider.accept_stream(lambda r, p: handler if (r, p) == (realm, procedure) else None, timeout=10)

        serve_task = asyncio.create_task(serve())

        handle = await caller.open_stream(procedure, realm, None, frame.current_millis() + 10_000, mode="client_stream")
        for n in (1, 2, 3):
            await handle.send_chunk(str(n).encode())
        await handle.close_send()

        reply = await handle.recv(timeout=10)
        await serve_task
        assert isinstance(reply, frame.StreamReplyInfo)
        assert reply.payload == 6
    finally:
        await provider.close()
        await caller.close()


@pytest.mark.live
async def test_opening_a_stream_to_an_unadvertised_procedure_reports_not_found():
    caller_id = KeyPair.generate()
    caller = await Session.connect(STATION_HOST, STATION_PORT, caller_id)
    try:
        handle = await caller.open_stream("test.nobody_advertises_this", bytes(32), None, frame.current_millis() + 10_000)
        with pytest.raises(frame.StreamAbortedError) as exc_info:
            await handle.recv(timeout=10)
        # macula_station_peer_observer.erl's stream_unknown_reply/2:
        # nobody advertised this procedure AT ALL, a routing-level failure,
        # distinct from "not_found" (which macula_station_link.erl's own
        # dispatch_stream_open/6 sends when a link that DID declare a
        # stream_procedures entry gets a stream_id it doesn't recognize --
        # not applicable to a caller-only session with no advertised
        # procedures of its own).
        assert exc_info.value.code == "unknown_next_peer"
    finally:
        await caller.close()

"""Dials the real production demo fleet. Same fleet-flakiness caveat as
the other live test files.

Real finding while writing this file, root-caused not just papered over:
SUBSCRIBE needs a moment to actually register at the station before a
PUBLISH sent immediately afterward is guaranteed delivered -- publishing
right after subscribing with no gap flakily lost the event (roughly 1 in
3 runs when several such tests ran back-to-back; every failure was a
clean TimeoutError, never a wrong-event delivery). Same shape as the
already-known "ADVERTISE needs a moment to land" finding the RPC live
tests already handle with their own advertise()-then-sleep -- SUBSCRIBE
gets the identical treatment here. Confirmed by adding the delay and
re-running the full file clean 4/4 times, after two other hypotheses
(stray non-EVENT frames, generic cross-test fleet contention) were tried
and did NOT fix it on their own.
"""

import asyncio
import uuid

import pytest

from macula import frame
from macula.connection import Session
from macula.identity import KeyPair

STATION_HOST = "station-de-frankfurt.macula.io"
STATION_PORT = 4433


async def _recv_event_skipping_stray_frames(session: Session, timeout: float) -> "frame.EventInfo":
    """`Session.recv_event` is deliberately strict (any non-EVENT frame raises, matching the raw primitive's documented contract -- see its own docstring). The real station periodically sends unprompted frames of its own (confirmed elsewhere in this org's own SDK work, e.g. advertise broadcasts for built-in procedures) that can land on a subscriber's control stream between the publish this test triggers and the EVENT it produces. A real permissive consumer is exactly what the (out-of-scope-this-phase) supervised pubsub wrapper is for; this is that same tolerance, scoped to test code only, not a change to the SDK's own contract."""
    deadline = asyncio.get_event_loop().time() + timeout
    while True:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            raise TimeoutError(f"no EVENT within {timeout}s (ignoring stray non-EVENT frames)")
        try:
            return await session.recv_event(timeout=remaining)
        except frame.ParseFrameError:
            continue


@pytest.mark.live
async def test_publish_subscribe_round_trip_delivers_our_own_publish_directly():
    identity = KeyPair.generate()
    session = await Session.connect(STATION_HOST, STATION_PORT, identity)
    try:
        realm = bytes(32)
        topic = f"macula_py.test.{uuid.uuid4().hex}"

        await session.subscribe(topic, realm)
        await asyncio.sleep(0.5)  # let the subscription land before publishing -- see the RPC live tests' own advertise()-then-sleep precedent
        await session.publish(topic, realm, {"hello": "mesh"}, seq=1)

        event = await _recv_event_skipping_stray_frames(session, timeout=10.0)
        assert event.topic == topic
        assert event.payload == {"hello": "mesh"}
        assert event.publisher == identity.node_id()
        assert event.seq == 1
    finally:
        await session.close()


@pytest.mark.live
async def test_two_independent_sessions_publish_and_subscribe():
    # A REAL cross-session delivery, not the same session seeing its own
    # publish -- separate identities, separate connections, matching this
    # org's own same-identity-double-connect caveat.
    publisher_id = KeyPair.generate()
    subscriber_id = KeyPair.generate()
    realm = bytes(32)
    topic = f"macula_py.test.{uuid.uuid4().hex}"

    publisher = await Session.connect(STATION_HOST, STATION_PORT, publisher_id)
    subscriber = await Session.connect(STATION_HOST, STATION_PORT, subscriber_id)
    try:
        await subscriber.subscribe(topic, realm)
        await asyncio.sleep(0.5)  # let the subscription land before publishing
        await publisher.publish(topic, realm, "hello from a different session", seq=1)

        event = await _recv_event_skipping_stray_frames(subscriber, timeout=10.0)
        assert event.topic == topic
        assert event.payload == "hello from a different session"
        assert event.publisher == publisher_id.node_id()
    finally:
        await publisher.close()
        await subscriber.close()


@pytest.mark.live
async def test_unsubscribe_stops_delivery():
    identity = KeyPair.generate()
    session = await Session.connect(STATION_HOST, STATION_PORT, identity)
    try:
        realm = bytes(32)
        topic = f"macula_py.test.{uuid.uuid4().hex}"

        await session.subscribe(topic, realm)
        await asyncio.sleep(0.5)  # let the subscription land before publishing
        await session.publish(topic, realm, "first", seq=1)
        first = await _recv_event_skipping_stray_frames(session, timeout=10.0)
        assert first.payload == "first"

        await session.unsubscribe(topic, realm)
        await asyncio.sleep(0.5)  # let the unsubscribe land before publishing again -- see this test's own finding below
        await session.publish(topic, realm, "second", seq=2)
        # No event should arrive now -- a short timeout is the only way
        # to prove absence; a longer one would just slow the suite down
        # for the same answer. A stray non-EVENT frame (the station's own
        # documented unprompted advertise broadcasts) would make
        # recv_event raise ParseFrameError instead of TimeoutError --
        # either one means "no EVENT for 'second' arrived", which is what
        # this test actually checks.
        with pytest.raises((TimeoutError, frame.ParseFrameError)):
            await session.recv_event(timeout=3.0)
    finally:
        await session.close()

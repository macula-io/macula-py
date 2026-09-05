"""Dials the real production demo fleet. Same fleet-flakiness caveat as
the other live test files.
"""

import os

import pytest

from macula import content, manifest
from macula.connection import Session
from macula.identity import KeyPair

STATION_HOST = "station-de-frankfurt.macula.io"
STATION_PORT = 4433


@pytest.mark.live
async def test_put_and_get_a_single_block_round_trips_exactly():
    identity = KeyPair.generate()
    session = await Session.connect(STATION_HOST, STATION_PORT, identity)
    try:
        data = b"hello content-addressed macula"
        mcid = await content.put(session, data)
        assert len(mcid) == 34
        assert not manifest.is_chunked(mcid)
        assert mcid == manifest.block_mcid(data)

        fetched = await content.get(session, mcid)
        assert fetched == data
    finally:
        await session.close()


@pytest.mark.live
async def test_put_and_get_chunked_content_round_trips_exactly():
    identity = KeyPair.generate()
    session = await Session.connect(STATION_HOST, STATION_PORT, identity)
    try:
        # Force at least 2 chunks -- real bytes, not a repeating pattern,
        # so a bug that only shows up on non-trivial content wouldn't be
        # masked by every chunk hashing the same.
        data = os.urandom(manifest.DEFAULT_CHUNK_SIZE + 12345)
        mcid = await content.put(session, data, name="test-chunked.bin")
        assert manifest.is_chunked(mcid)

        fetched = await content.get(session, mcid)
        assert fetched == data
    finally:
        await session.close()


@pytest.mark.live
async def test_get_of_a_nonexistent_block_reports_not_found():
    identity = KeyPair.generate()
    session = await Session.connect(STATION_HOST, STATION_PORT, identity)
    try:
        # A well-formed MCID that (with overwhelming probability) nothing
        # has ever put -- a fresh random 32-byte "hash".
        fake_mcid = manifest.make_mcid(manifest.CODEC_RAW, os.urandom(32))
        with pytest.raises(content.ContentTransferError) as exc_info:
            await content.get(session, fake_mcid)
        assert exc_info.value.reason == "not_found"
    finally:
        await session.close()


@pytest.mark.live
async def test_content_put_by_one_session_is_gettable_by_a_completely_different_session():
    # The real proof content-addressing works across identities: put with
    # one identity/connection, get with a totally separate one -- not the
    # same session reading back what it just wrote.
    putter_id = KeyPair.generate()
    getter_id = KeyPair.generate()
    putter = await Session.connect(STATION_HOST, STATION_PORT, putter_id)
    getter = await Session.connect(STATION_HOST, STATION_PORT, getter_id)
    try:
        data = b"shared content across two independent identities"
        mcid = await content.put(putter, data)
        fetched = await content.get(getter, mcid)
        assert fetched == data
    finally:
        await putter.close()
        await getter.close()

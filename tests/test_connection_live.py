"""Dials the real production demo fleet -- no uptime guarantee, must never
block an unrelated CI run. Excluded from the default run via the "live"
marker (see pyproject.toml); run explicitly with `pytest -m live`.
"""

import pytest

from macula_py.connection import ConnectRefusedError, Session
from macula_py.identity import KeyPair

STATION_HOST = "station-de-frankfurt.macula.io"
STATION_PORT = 4433


@pytest.mark.live
async def test_connect_completes_a_real_handshake_against_the_live_fleet():
    identity = KeyPair.generate()
    session = await Session.connect(STATION_HOST, STATION_PORT, identity)
    try:
        assert session.remote_info.accepted is True
        assert len(session.remote_info.node_id) == 32
        # The station's own node_id must not equal ours -- a sanity check
        # that we're actually talking to a distinct peer, not looped back.
        assert session.remote_info.node_id != identity.node_id()
    finally:
        await session.close()


@pytest.mark.live
async def test_connect_can_be_used_as_an_async_context_manager():
    identity = KeyPair.generate()
    async with await Session.connect(STATION_HOST, STATION_PORT, identity) as session:
        assert session.remote_info.accepted is True


@pytest.mark.live
async def test_two_independent_sessions_get_independent_handshakes():
    # Two DIFFERENT identities to the same station -- confirmed elsewhere
    # in this org's own live testing that a station kicks a SECOND
    # connection under the SAME identity, so this must use two.
    id_a = KeyPair.generate()
    id_b = KeyPair.generate()
    session_a = await Session.connect(STATION_HOST, STATION_PORT, id_a)
    session_b = await Session.connect(STATION_HOST, STATION_PORT, id_b)
    try:
        assert session_a.remote_info.accepted is True
        assert session_b.remote_info.accepted is True
    finally:
        await session_a.close()
        await session_b.close()


@pytest.mark.live
async def test_close_is_idempotent():
    identity = KeyPair.generate()
    session = await Session.connect(STATION_HOST, STATION_PORT, identity)
    await session.close()
    await session.close()  # must not raise

"""Who a served procedure is served to, in the source: ABI 2 refuses serve
options that name no policy (macula-go#57, #60), so ``policy`` is a required
argument of Pool.serve and Pool.serve_stream, and Open() is the line that says
anyone.

The ABI's own refusal is reached here through the binding's own handle: the
options are judged before the pool handle is looked up, so no pool and no
station is involved.
"""

from __future__ import annotations

import pytest

from macula_py import InvalidArgumentError, NoProviderError, Open, Pool, StreamMode
from macula_py._native import native
from tests.stations import TestStations
from tests.test_pool import node

REALM_32 = bytes(32)


@pytest.fixture(scope="module")
def env():
    stations = TestStations("pq_pure")
    yield stations
    stations.stop()


def _served(request) -> dict:
    return {"served": request.caller}


async def _nothing(stream) -> None:
    """A stream handler that sends nothing: this test never opens the stream."""


async def test_a_serve_that_names_no_policy_is_refused_at_the_call(env):
    async with await node(env, 0) as provider, await node(env, 1) as caller:
        procedure = provider.own_procedure("unnamed")
        with pytest.raises(TypeError, match="policy"):
            await provider.serve(env.realm_id, procedure, _served)
        # Nothing was advertised: the call never reached the station, so the
        # DHT has nobody to offer and providers() refuses rather than answers [].
        with pytest.raises(NoProviderError):
            await caller.providers(env.realm_id, procedure)


async def test_a_serve_stream_that_names_no_policy_is_refused_at_the_call(env):
    async with await node(env, 0) as provider:
        procedure = provider.own_procedure("unnamed_stream")
        with pytest.raises(TypeError, match="policy"):
            await provider.serve_stream(env.realm_id, procedure, StreamMode.SERVER, _nothing)


async def test_an_open_policy_is_the_statement_that_serves_anyone(env):
    async with await node(env, 0) as provider, await node(env, 1) as caller:
        procedure = provider.own_procedure("open_to_all")
        async with await provider.serve(env.realm_id, procedure, _served, policy=Open()):
            assert await caller.call(env.realm_id, procedure, {}) == {"served": caller.node_id()}


def test_the_open_policy_is_the_line_the_abi_asks_for():
    assert Open().json() == {"kind": "open"}


def test_the_abi_refuses_serve_options_that_name_no_policy():
    with pytest.raises(InvalidArgumentError) as refused:
        native().invoke("macula_pool_serve_opts", 0, REALM_32, b"acme/echo", b'{"confidential":"preferred"}')
    message = str(refused.value)
    assert "policy is required" in message, "the refusal names no policy"
    assert '{"policy":{"kind":"open"}}' in message, "the refusal does not name the open policy"
    assert "macula_pool_serve_gated" in message, "the refusal does not name the gated door"


def test_the_abi_refuses_stream_serve_options_that_name_no_policy():
    with pytest.raises(InvalidArgumentError) as refused:
        native().invoke("macula_pool_serve_stream_opts", 0, REALM_32, b"acme/watch", int(StreamMode.SERVER), b"{}")
    assert "policy is required" in str(refused.value)

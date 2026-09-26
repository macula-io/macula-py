"""macula 12's UCANs (D7) through this binding: tokens minted here, proof ids
as macula's vectors have them (tests/fixtures/ucan), and procedures served
gated on a policy, whose provider judges every call and stream open as
macula's link does. The verdicts themselves are held to macula's vectors in
macula-go, whose gate this binding's provider runs; here each is reached end
to end, over two in-process stations, in both profiles."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from pathlib import Path

import pytest

from macula_py import InvalidArgumentError, NodeKey, Pool, ProviderError, Seed, StreamError, StreamMode, StreamReply
from macula_py.ucan import RealmMemberRequired, UcanRequired, key_id, proof_id
from tests.stations import TestStations

VECTORS = Path(__file__).parent / "fixtures" / "ucan" / "ucan_v1.json"
# macula's test/vectors/ucan_v1.json at 0e2724cc97a5689542b8da7b06d392cf0d34b205.
VECTORS_SHA256 = "b64cb27aa639ea7ec103523b808e766c656220610f9a26a7801af31fe7c3b296"


def vectors() -> dict:
    data = VECTORS.read_bytes()
    assert hashlib.sha256(data).hexdigest() == VECTORS_SHA256, "ucan_v1.json drifted from the pinned bytes"
    return json.loads(data)


def test_proof_ids_are_macula_s():
    profiles = vectors()["profiles"]
    assert sorted(profiles) == ["pq_hybrid", "pq_pure"]
    for profile in profiles.values():
        assert profile["proof_ids"]
        for entry in profile["proof_ids"]:
            assert proof_id(entry["token"]) == entry["proof_id"]


def test_a_malformed_policy_or_grant_is_refused():
    with pytest.raises(ValueError):
        UcanRequired("00")
    with pytest.raises(ValueError):
        RealmMemberRequired("ab" * 32, "")


def test_minting_refuses_what_it_cannot_express():
    # A token naming two parents is minted, as macula's create/4 mints it; the
    # provider refuses it (chain_not_linear). What is refused here is what
    # cannot be written at all.
    key = asyncio.run(NodeKey.generate("pq_pure"))
    exp = int(time.time()) + 60
    with pytest.raises(ValueError):
        key.ucan("ab" * 32, [{"with": "mri:realm:x"}], exp=exp)
    with pytest.raises(ValueError):
        key.ucan("ab" * 31, [], exp=exp)
    with pytest.raises(InvalidArgumentError):
        key.ucan("ab" * 32, [{"with": "mri:realm:x", "can": "invoke"}], exp=exp, fct={"ok": float("nan")})


@pytest.fixture(scope="module", params=["pq_pure", "pq_hybrid"])
def env(request):
    stations = TestStations(request.param)
    yield stations
    stations.stop()


async def node(env: TestStations, station: int, *, admitted: bool = False) -> Pool:
    key = await NodeKey.generate(env.profile)
    if admitted:
        env.admit(key.node_id_hex())
    s = env.stations[station]
    return await Pool.connect(key, [Seed(s.host, s.port, s.node_id)], realm_trust={env.realm_id: env.realm_key})


async def gated_world(env: TestStations):
    """A provider admitted on one station, a caller on the other, the root a
    policy names, and a second node the root has granted to."""
    provider = await node(env, 0, admitted=True)
    caller = await node(env, 1)
    root = await NodeKey.generate(env.profile)
    alice = await NodeKey.generate(env.profile)
    return provider, caller, root, alice


def presentations(env: TestStations, caller: Pool, root: NodeKey, alice: NodeKey, procedure: str):
    """What a caller presents, and the provider's answer: None to serve it,
    else the code it refuses with."""
    exp = int(time.time()) + 300
    org = f"mri:org:{env.realm_name}/{env.org}"
    direct = root.ucan(caller.node_id(), [{"with": org, "can": "invoke"}], exp=exp)
    to_alice = root.ucan(alice.node_id(), [{"with": org, "can": "invoke"}], exp=exp)
    chained = alice.ucan(
        caller.node_id(), [{"with": f"mri:proc:{env.realm_name}/{procedure}", "can": "invoke"}], exp=exp,
        prf=[proof_id(to_alice)],
    )
    other = alice.ucan(caller.node_id(), [{"with": org, "can": "invoke"}], exp=exp)
    return {
        "a root grant": (direct, [], None),
        "a delegated chain": (chained, [to_alice], None),
        "no token": (None, [], "unauthorized"),
        "another issuer": (other, [], "unauthorized"),
        "a chain without its proof": (chained, [], "unauthorized"),
        "a proof no token names": (direct, [to_alice], "malformed_frame"),
    }


async def until_served(attempt):
    """attempt() until the provider, not the DHT's reach, answers: the
    advertisement reaches the other station's DHT in its own time."""
    deadline = time.monotonic() + 20
    while True:
        try:
            return await attempt()
        except (ProviderError, StreamError) as e:
            if e.code not in ("unknown_next_peer",) or time.monotonic() > deadline:
                raise
        except Exception:
            if time.monotonic() > deadline:
                raise
        await asyncio.sleep(0.2)


async def test_a_gated_procedure_judges_each_call(env):
    provider, caller, root, alice = await gated_world(env)
    procedure = f"{env.org}/count"
    async with provider, caller, await provider.serve(
        env.realm_id, procedure, lambda request: "served", policy=UcanRequired(root.node_id())
    ):
        for name, (token, proofs, refused) in presentations(env, caller, root, alice, procedure).items():
            try:
                result = await until_served(
                    lambda t=token, p=proofs: caller.call(env.realm_id, procedure, {}, ucan=t, proofs=p)
                )
                assert refused is None and result == "served", name
            except ProviderError as e:
                assert e.code == refused, f"{name}: {e.code}"


async def test_a_gated_stream_judges_each_open(env):
    provider, caller, root, alice = await gated_world(env)
    procedure = f"{env.org}/watch"

    async def watch(stream):
        await stream.reply("served")

    async def opened(token, proofs):
        # A refused open is raised by recv as the provider's StreamError.
        async with await caller.open_stream(
            env.realm_id, procedure, StreamMode.SERVER, {}, ucan=token, proofs=proofs
        ) as stream:
            return await stream.recv(timeout_ms=10_000)

    async with provider, caller, await provider.serve_stream(
        env.realm_id, procedure, StreamMode.SERVER, watch, policy=UcanRequired(root.node_id())
    ):
        for name, (token, proofs, refused) in presentations(env, caller, root, alice, procedure).items():
            try:
                frame = await until_served(lambda t=token, p=proofs: opened(t, p))
                assert refused is None and isinstance(frame, StreamReply) and frame.payload == "served", name
            except StreamError as e:
                assert e.code == refused and not e.relay, f"{name}: {e.code}"


async def test_a_realm_member_procedure_needs_the_realms_grant(env):
    # The harness's realm key is not this test's to sign with: a key of the
    # test's own stands in for the realm, named by its key id.
    provider, caller, realm_key, _ = await gated_world(env)
    procedure = f"{env.org}/member"
    grant = f"mri:realm:{env.realm_name}"
    exp = int(time.time()) + 300
    policy = RealmMemberRequired(key_id(realm_key.public_key(), env.profile), "count")
    async with provider, caller, await provider.serve(env.realm_id, procedure, lambda request: "served", policy=policy):
        token = realm_key.ucan(caller.node_id(), [{"with": grant, "can": "count"}], exp=exp)
        assert await until_served(lambda: caller.call(env.realm_id, procedure, {}, ucan=token)) == "served"
        other = realm_key.ucan(caller.node_id(), [{"with": grant, "can": "invoke"}], exp=exp)
        with pytest.raises(ProviderError) as refused:
            await caller.call(env.realm_id, procedure, {}, ucan=other)
        assert refused.value.code == "unauthorized"


_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _carried(did_key: str) -> bytes:
    """The key a did:key carries: base58btc, then past the multicodec varint."""
    assert did_key.startswith("did:key:z")
    text = did_key[len("did:key:z"):]
    n = 0
    for ch in text:
        n = n * 58 + _BASE58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = bytes(len(text) - len(text.lstrip("1"))) + raw
    i = 0
    while raw[i] & 0x80:
        i += 1
    return raw[i + 1:]


def test_key_ids_are_macula_s():
    for name, profile in vectors()["profiles"].items():
        for key in profile["keys"].values():
            assert key_id(_carried(key["did_key"]), name) == bytes.fromhex(key["key_id"]), key["did_key"][:24]

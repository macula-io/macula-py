"""macula 13.2's sealed groups (DESIGN_E2E_SEALED_PUBSUB.md, package 5 of
macula's seal vectors) through this binding: a Python app publishes under a
realm group and opens its events, pulling the group's epoch keys from the org's
distributor over a sealed call, presenting the org's grant.

The C ABI hands values, never bytes: Python builds no CALL payload and reads no
CBOR, so macula's vectors (tests/fixtures/groups) are reached here as values —
the epoch's 8-byte id and 32-byte key as the event proves them (the vector's
seal_key_id, opened under the vector's key), every field of a pull's payloads
at the distributor, and the verdict macula's gate gives a grant. What is
macula-go's alone is held there and named here: the vectors' CBOR byte for byte
(group/vectors_test.go) and the six cases' named refusals (the wire carries
only unauthorized, and a refused pull reads to a member as no_distributor).

The distributor is a stand-in a Python app serves (macula's own is Elixir):
<org>/group_keys_v1, always sealed. The org's grant is real: the test station
mints it with the org key, whose key id the distributor's policy names.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import pytest

from macula_py import Group, GroupError, InvalidArgumentError, NodeKey, Pool, ProviderError, Seed
from macula_py.ucan import Policy, RealmMemberRequired, key_id
from tests.stations import TestStations

VECTORS = Path(__file__).parent / "fixtures" / "groups" / "e2e_seal_v1_group_keys.json"
# macula's test/vectors/e2e_seal_v1_group_keys.json at v15.0.0-rc.2 (42b60269).
VECTORS_SHA256 = "e2f9f9a35eab8931cae260301f0034fe5a9b6a6b6d5776b480f242b1b2a6d7a2"

# An epoch's accept_until is its publish_until plus the life of an event
# (asserted against the vector below).
EVENT_LIFE_MS = 65 * 60_000
ID_SIZE, KEY_SIZE = 8, 32
HEX64 = 64


def vectors() -> dict:
    data = VECTORS.read_bytes()
    assert hashlib.sha256(data).hexdigest() == VECTORS_SHA256, "e2e_seal_v1_group_keys.json drifted from the pinned bytes"
    return json.loads(data)


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def test_the_vectors_are_macula_s():
    v = vectors()
    assert v["spec"] == "test/vectors/E2E_SEAL_V1.md"
    assert v["generator"] == "scripts/generate-seal-group-keys-vectors.sh"
    assert v["realm_name"] == "io.macula"
    assert v["refusals"] == [
        "not_a_member", "membership_unknown", "unknown_epoch", "epoch_expired", "unknown_group",
    ]
    assert sorted(v["profiles"]) == ["pq_hybrid", "pq_pure"]
    for name, profile in v["profiles"].items():
        assert [case["name"] for case in profile["cases"]] == [
            "ok_procedure_grant", "ok_org_grant", "missing_capability", "not_the_issuer", "not_the_audience", "expired",
        ], name
        # Each case's verdict is its name, the two macula admits first.
        assert [case["verdict"] for case in profile["cases"]] == [
            "ok", "ok", "missing_capability", "not_the_issuer", "not_the_audience", "expired",
        ], name
        for case in profile["cases"]:
            assert case["context"]["procedure"] == "acme/group_keys_v1", name
            # The gate these cases turn on: the org key's id, and group_keys.
            assert case["policy"]["kind"] == "realm_member_required", name
            assert case["policy"]["can"] == "group_keys", name
            assert len(case["policy"]["key_id"]) == HEX64, name
            assert len(case["context"]["realm"]) == HEX64, name
    result = v["payloads"]["result"]
    assert (result["prefix"], result["policy"]) == ("io.macula/acme/chat", "required")
    assert result["prefix"] == v["payloads"]["call_current"]["prefix"] == v["payloads"]["call_by_id"]["prefix"]
    assert v["payloads"]["call_current"]["epoch"] == "current"
    assert v["payloads"]["call_by_id"]["epoch_id"] == result["epochs"][0]["id"]
    for epoch in result["epochs"]:
        assert len(bytes.fromhex(epoch["id"])) == ID_SIZE
        assert len(bytes.fromhex(epoch["key"])) == KEY_SIZE
        assert int(epoch["accept_until"]) - int(epoch["publish_until"]) == EVENT_LIFE_MS
    # The second epoch is issued exactly as the first stops publishing.
    first, second = result["epochs"]
    assert int(second["issued_at"]) == int(first["publish_until"])


@dataclass(frozen=True)
class Epoch:
    """One of a distributor's epochs as this binding's handler answers it: an
    id and a key as bytes (the ABI's path from JSON to CBOR), the times a
    distributor sets."""

    id: bytes
    key: bytes
    issued_at: int
    publish_until: int
    accept_until: int

    def wire(self) -> dict:
        return {
            "id": self.id,
            "key": self.key,
            "issued_at": self.issued_at,
            "publish_until": self.publish_until,
            "accept_until": self.accept_until,
        }


def epoch_at(index: int, *, issued_at: int) -> Epoch:
    """The vector's epoch ``index``, live: its id, key and durations are
    macula's, only its times move. The vector's own window closed in September
    2026, so a test issues the epoch when it needs it — the first as the
    group's current one, the second as the rotation after it."""
    e = vectors()["payloads"]["result"]["epochs"][index]
    rotation = int(e["publish_until"]) - int(e["issued_at"])
    life = int(e["accept_until"]) - int(e["publish_until"])
    return Epoch(
        bytes.fromhex(e["id"]), bytes.fromhex(e["key"]), issued_at, issued_at + rotation, issued_at + rotation + life
    )


class Distributor:
    """The org's distributor as a Python app serves it: ``<org>/group_keys_v1``
    sealed (``confidential="required"``: a member's pull is always sealed to
    the KEM key the advertisement names), under ``policy``.

    ``serves`` is what it hands out — a pull of ``current`` gets all of it, a
    pull by id the epoch that id names, and an id it does not have is refused
    ``unknown_epoch``. ``refuse`` names a refusal from macula's closed set,
    which travels as the pull's handler_error detail and is all a member reads
    of it. ``transform`` is a last look at a reply before it goes out, for
    tests of replies that are not the protocol's. ``seen`` has every pull's
    payload — a member's CALL, field for field — and ``sealed`` whether each
    came sealed."""

    def __init__(self, pool: Pool, prefix: str, policy: Policy, *, serves: list[Epoch]) -> None:
        self.pool = pool
        self.prefix = prefix
        self.policy = policy
        self.serves = serves
        self.refuse: str | None = None
        self.transform: Callable[[dict], dict] = lambda reply: reply
        self.seen: list[Any] = []
        self.sealed: list[bool] = []

    @property
    def publishing(self) -> Epoch:
        """The epoch a publisher seals under now: the newest handed out that
        has started and not stopped publishing (macula-go's forPublish)."""
        now = now_ms()
        return [e for e in self.serves if e.issued_at <= now < e.publish_until][-1]

    def answer(self, request) -> dict:
        self.seen.append(request.payload)
        self.sealed.append(request.sealed)
        if self.refuse is not None:
            raise RuntimeError(self.refuse)
        asked = request.payload.get("epoch")
        epochs = self.serves if asked == "current" else [e for e in self.serves if e.id == asked]
        if not epochs:
            raise RuntimeError("unknown_epoch")
        return self.transform({"prefix": self.prefix, "policy": "required", "epochs": [e.wire() for e in epochs]})

    async def served(self, env: TestStations):
        """The distributor's procedure, served sealed under its policy: what a
        test awaits into an ``async with``. The policy is what makes a pull a
        pull — a distributor with none serves the keys to anyone."""
        return await self.pool.serve(
            env.realm_id,
            f"{env.org}/group_keys_v1",
            self.answer,
            policy=self.policy,
            confidential="required",
        )

    def member_group(self, env: TestStations, member: Pool) -> Group:
        """A member's group: the prefix, and the org's grant for that node,
        minted by the org key the distributor's policy names."""
        return Group(self.prefix, env.grant(member.node_id()))


def group_prefix(env: TestStations, name: str) -> str:
    """A group under this harness's own org: a group's second segment is its
    org, whose distributor serves the group_keys_v1 procedure."""
    return f"{env.realm_name}/{env.org}/{name}"


@pytest.fixture(scope="module", params=["pq_pure", "pq_hybrid"])
def env(request):
    stations = TestStations(request.param)
    yield stations
    stations.stop()


async def node(env: TestStations, station: int, *, admitted: bool = False, kem_advertise: bool = False) -> Pool:
    key = await NodeKey.generate(env.profile)
    if admitted:
        env.admit(key.node_id_hex())
    s = env.stations[station]
    return await Pool.connect(
        key, [Seed(s.host, s.port, s.node_id)], realm_trust={env.realm_id: env.realm_key}, kem_advertise=kem_advertise
    )


async def until_joined(attempt):
    """attempt() until the distributor, not the DHT's reach, answers: an
    advertisement reaches the other station's DHT in its own time
    (test_ucan.until_served). A pull a distributor refused for a reason that
    is not one of its named refusals reads as no_distributor, so only
    no_distributor is retried."""
    deadline = time.monotonic() + 20
    while True:
        try:
            return await attempt()
        except GroupError as e:
            if e.reason != "no_distributor" or time.monotonic() > deadline:
                raise
        await asyncio.sleep(0.2)


async def until_served(attempt):
    """attempt() until the provider, not the DHT's reach, answers."""
    deadline = time.monotonic() + 20
    while True:
        try:
            return await attempt()
        except ProviderError as e:
            if e.code != "unknown_next_peer" or time.monotonic() > deadline:
                raise
        except Exception:
            if time.monotonic() > deadline:
                raise
        await asyncio.sleep(0.2)


async def test_a_member_publishes_under_the_vectors_epoch_and_opens_the_event(env):
    prefix = group_prefix(env, "opened")
    topic = f"{prefix}/said_v1"
    policy = RealmMemberRequired(env.org_key_id, "group_keys")
    standin = await node(env, 0, admitted=True, kem_advertise=True)
    distributor = Distributor(standin, prefix, policy, serves=[epoch_at(0, issued_at=now_ms() - 1_000)])
    async with standin, await distributor.served(env):
        publisher, reader = await node(env, 0), await node(env, 0)
        async with publisher, reader:
            subscription = await until_joined(
                lambda: reader.subscribe_group(env.realm_id, topic, distributor.member_group(env, reader))
            )
            async with subscription:
                await publisher.publish_group(
                    env.realm_id, topic, {"said": "hush"}, distributor.member_group(env, publisher)
                )
                event = await subscription.next(timeout_ms=15_000)
            assert event is not None
            assert event.topic == topic and event.unopened is None
            assert event.sealed is True
            # The vector's own id, and the event opened under the key that id
            # names: the epoch's 32 bytes crossed the ABI as the vector has
            # them, or the GCM tag would not verify.
            assert event.seal_key_id == distributor.publishing.id.hex()
            assert event.seal_key_id == vectors()["payloads"]["call_by_id"]["epoch_id"]
            assert event.payload == {"said": "hush"}
    # A member's pull is always sealed, and made in the vector's own shape: one
    # per node that joined the group, the reader's and the publisher's, each
    # field the vector's call_current — a node holding a group does not pull it
    # again.
    assert distributor.sealed and all(distributor.sealed)
    assert distributor.seen == [{"prefix": prefix, "epoch": "current"}] * 2


async def holder_publishing_clear_is_refused(
    publisher: Pool, env: TestStations, topic: str, prefix: str
) -> None:
    """A node that holds the group's key may not publish clear under it:
    macula refuses that as group_held, naming the group's prefix."""
    with pytest.raises(GroupError) as refused:
        await publisher.publish(env.realm_id, topic, "clear")
    assert (refused.value.reason, refused.value.prefix) == ("group_held", prefix)


async def test_a_plain_subscription_hears_the_event_unopened(env):
    prefix = group_prefix(env, "plain")
    topic = f"{prefix}/said_v1"
    policy = RealmMemberRequired(env.org_key_id, "group_keys")
    standin = await node(env, 0, admitted=True, kem_advertise=True)
    distributor = Distributor(standin, prefix, policy, serves=[epoch_at(0, issued_at=now_ms() - 1_000)])
    async with standin, await distributor.served(env):
        publisher, member, outsider = await node(env, 0), await node(env, 0), await node(env, 0)
        async with publisher, member, outsider:
            subscription = await until_joined(
                lambda: member.subscribe_group(env.realm_id, topic, distributor.member_group(env, member))
            )
            plain = await outsider.subscribe(env.realm_id, topic)
            async with subscription, plain:
                await publisher.publish_group(
                    env.realm_id, topic, {"said": "hush"}, distributor.member_group(env, publisher)
                )
                opened = await subscription.next(timeout_ms=15_000)
                heard = await plain.next(timeout_ms=15_000)
                # A node that holds no key for the group hears the same event
                # once, with nothing of its payload: no_group.
                assert heard is not None and heard.topic == topic
                assert (heard.payload, heard.unopened) == (None, "no_group")
                assert opened is not None and opened.payload == {"said": "hush"}
                # And a node holding the group may not publish clear under it.
                await holder_publishing_clear_is_refused(publisher, env, topic, prefix)


async def test_an_event_under_a_new_epoch_is_pulled_by_id_and_opened(env):
    """The reader joins under one epoch and the distributor rotates to the
    next, which the reader never receives: the event arrives sealed under a
    key it does not hold, and the member's CALL names the id the event named
    (the vector's call_by_id payload, field for field)."""
    prefix = group_prefix(env, "rotated")
    topic = f"{prefix}/said_v1"
    policy = RealmMemberRequired(env.org_key_id, "group_keys")
    started = now_ms()
    first, second = epoch_at(0, issued_at=started - 1_000), epoch_at(1, issued_at=started)
    standin = await node(env, 0, admitted=True, kem_advertise=True)
    distributor = Distributor(standin, prefix, policy, serves=[first])
    async with standin, await distributor.served(env):
        reader, publisher = await node(env, 0), await node(env, 0)
        async with reader, publisher:
            subscription = await until_joined(
                lambda: reader.subscribe_group(env.realm_id, topic, distributor.member_group(env, reader))
            )
            async with subscription:
                distributor.serves = [first, second]
                await publisher.publish_group(
                    env.realm_id, topic, {"said": "again"}, distributor.member_group(env, publisher)
                )
                event = await subscription.next(timeout_ms=15_000)
                assert event is not None and event.unopened is None
                assert event.seal_key_id == second.id.hex()
                assert event.payload == {"said": "again"}
                assert distributor.seen[0] == {"prefix": prefix, "epoch": "current"}
                assert {"prefix": prefix, "epoch": second.id} in distributor.seen
                assert all(distributor.sealed)


async def test_the_stations_org_grant_is_accepted(env):
    """The org's own grant, minted by the test station's org key over
    mri:org:<realm>/<org>, presented to a distributor whose policy names that
    key's id: the join pulls an epoch and the group's events open."""
    prefix = group_prefix(env, "granted")
    topic = f"{prefix}/said_v1"
    policy = RealmMemberRequired(env.org_key_id, "group_keys")
    standin = await node(env, 0, admitted=True, kem_advertise=True)
    distributor = Distributor(standin, prefix, policy, serves=[epoch_at(0, issued_at=now_ms() - 1_000)])
    async with standin, await distributor.served(env):
        publisher, reader = await node(env, 0), await node(env, 0)
        async with publisher, reader:
            group = distributor.member_group(env, reader)
            assert group.ucan is not None
            subscription = await until_joined(lambda: reader.subscribe_group(env.realm_id, topic, group))
            async with subscription:
                await publisher.publish_group(
                    env.realm_id, topic, {"said": "granted"}, distributor.member_group(env, publisher)
                )
                event = await subscription.next(timeout_ms=15_000)
            assert event is not None and event.payload == {"said": "granted"}


def grants(env: TestStations, member: Pool, root: NodeKey, impostor: NodeKey) -> dict[str, tuple[str, str | None]]:
    """The vector's six cases as live tokens for member, by their names: the
    two macula admits (its two ``with`` forms, one capability) and the four it
    refuses, each for its own reason. Every refusal reaches this binding as
    unauthorized — the wire carries no more of a gated verdict than that —
    which is why the cases are named after macula's (its group/vectors_test.go)."""
    exp = int(time.time()) + 300
    org = f"mri:org:{env.realm_name}/{env.org}"
    procedure = f"mri:proc:{env.realm_name}/{env.org}/group_keys_v1"
    capability = {"with": org, "can": "group_keys"}
    return {
        "ok_procedure_grant": (root.ucan(member.node_id(), [{"with": procedure, "can": "group_keys"}], exp=exp), None),
        "ok_org_grant": (root.ucan(member.node_id(), [capability], exp=exp), None),
        "missing_capability": (root.ucan(member.node_id(), [{"with": org, "can": "invoke"}], exp=exp), "unauthorized"),
        "not_the_issuer": (impostor.ucan(member.node_id(), [capability], exp=exp), "unauthorized"),
        "not_the_audience": (root.ucan(impostor.node_id(), [capability], exp=exp), "unauthorized"),
        "expired": (root.ucan(member.node_id(), [capability], exp=int(time.time()) - 60), "unauthorized"),
    }


async def grant_case_reaches_its_verdict(
    member: Pool, env: TestStations, prefix: str, distributor: Distributor, name: str, case: tuple[str, str | None]
) -> None:
    """One of grants()' cases through the pull's own CALL, the vector's
    call_current payload, so a verdict here is the verdict the join would get:
    a refusal must be the case's own, and an admitted token must bring back the
    epoch as it crossed the ABI (an 8-byte id, the 32-byte key under it)."""
    token, refused = case
    call = lambda: member.call(
        env.realm_id, f"{env.org}/group_keys_v1", {"prefix": prefix, "epoch": "current"}, ucan=token,
        confidential="required",
    )
    try:
        reply = await until_served(call)
    except ProviderError as e:
        assert e.code == refused, f"{name}: {e.code}"
        return
    assert refused is None, name
    # The epoch as it crossed the ABI, the vector's bytes: an 8-byte id, the
    # 32-byte key under it, the times above it.
    epoch = reply["epochs"][0]
    assert (reply["prefix"], reply["policy"]) == (prefix, "required")
    assert (epoch["id"], epoch["key"]) == (distributor.publishing.id, distributor.publishing.key)
    assert (len(epoch["id"]), len(epoch["key"])) == (ID_SIZE, KEY_SIZE)


async def test_each_of_the_vectors_grant_cases_reaches_its_verdict(env):
    root, impostor = await NodeKey.generate(env.profile), await NodeKey.generate(env.profile)
    prefix = group_prefix(env, "judged")
    # The harness's org key is not this test's to sign with: a key of the
    # test's own stands in for the org, named by its key id.
    policy = RealmMemberRequired(key_id(root.public_key(), env.profile), "group_keys")
    standin = await node(env, 0, admitted=True, kem_advertise=True)
    distributor = Distributor(standin, prefix, policy, serves=[epoch_at(0, issued_at=now_ms() - 1_000)])
    async with standin, await distributor.served(env):
        member = await node(env, 0)
        async with member:
            for name, case in grants(env, member, root, impostor).items():
                await grant_case_reaches_its_verdict(member, env, prefix, distributor, name, case)
    assert all(distributor.sealed)


async def a_member_with_a_grant_of_its_own_joins(
    env: TestStations, prefix: str, topic: str, capability: dict, root: NodeKey
) -> None:
    """A member with a grant of its own joins the same group right after:
    what refused the expired token was the gate, not a dead distributor."""
    late = await node(env, 0)
    async with late:
        granted = Group(prefix, root.ucan(late.node_id(), [capability], exp=int(time.time()) + 300))
        async with await until_joined(lambda: late.subscribe_group(env.realm_id, topic, granted)):
            pass


async def test_a_grant_macula_refuses_does_not_join_at_publish_or_subscribe(env):
    """The six cases above are pulled through ``call``, which stands in for the
    join. This is the same verdict at the API an app calls: after the
    distributor has answered with a grant of its own (so what refuses next is
    the token, not the DHT's reach), an expired one leaves the group unjoined,
    and both publish_group and subscribe_group raise rather than publish clear
    or hand back an inbox nothing opens. What the reason reads as is
    macula-go's (a gated refusal reaches it as the same no_distributor a
    missing distributor gives), so this holds the raise, not the reason."""
    root = await NodeKey.generate(env.profile)
    prefix = group_prefix(env, "refused_grant")
    topic = f"{prefix}/said_v1"
    # A key of the test's own stands in for the org: the harness's org key is
    # not this test's to sign with, which is what leaves it free to mint a
    # token that has already expired.
    policy = RealmMemberRequired(key_id(root.public_key(), env.profile), "group_keys")
    standin = await node(env, 0, admitted=True, kem_advertise=True)
    distributor = Distributor(standin, prefix, policy, serves=[epoch_at(0, issued_at=now_ms() - 1_000)])
    async with standin, await distributor.served(env):
        member = await node(env, 0)
        async with member:
            capability = {"with": f"mri:org:{env.realm_name}/{env.org}", "can": "group_keys"}
            now = int(time.time())
            admitted = root.ucan(member.node_id(), [capability], exp=now + 300)
            await until_served(
                lambda: member.call(
                    env.realm_id, f"{env.org}/group_keys_v1", {"prefix": prefix, "epoch": "current"},
                    ucan=admitted, confidential="required",
                )
            )
            expired = Group(prefix, root.ucan(member.node_id(), [capability], exp=now - 60))
            with pytest.raises(GroupError) as published:
                await member.publish_group(env.realm_id, topic, {"said": "clear"}, expired, timeout_ms=5_000)
            # The gate's own code, which a dial failure or a dead distributor
            # does not carry: the same reason covers all three, so the message
            # is what says the token was judged.
            assert "unauthorized" in str(published.value), published.value
            with pytest.raises(GroupError) as subscribed:
                await member.subscribe_group(env.realm_id, topic, expired, timeout_ms=5_000)
            assert "unauthorized" in str(subscribed.value), subscribed.value
            # The distributor was alive at the verdict: the refused node's pull
            # never reached its handler, and a member with a grant of its own
            # joins the same group right after.
            assert distributor.seen == [{"prefix": prefix, "epoch": "current"}]
            await a_member_with_a_grant_of_its_own_joins(env, prefix, topic, capability, root)


async def test_a_node_the_distributor_removed_is_refused(env):
    """A distributor may refuse a pull for a node it does not hold as a member
    (macula's not_a_member), and a member reads it by that name: the refusal
    travels as the pull's handler_error detail."""
    prefix = group_prefix(env, "removed")
    topic = f"{prefix}/said_v1"
    policy = RealmMemberRequired(env.org_key_id, "group_keys")
    standin = await node(env, 0, admitted=True, kem_advertise=True)
    distributor = Distributor(standin, prefix, policy, serves=[epoch_at(0, issued_at=now_ms() - 1_000)])
    async with standin, await distributor.served(env):
        member = await node(env, 0)
        async with member:
            subscription = await until_joined(
                lambda: member.subscribe_group(env.realm_id, topic, distributor.member_group(env, member))
            )
            await subscription.stop()
        # The same distributor, finding the next node no member at all.
        distributor.refuse = "not_a_member"
        removed = await node(env, 0)
        async with removed:
            with pytest.raises(GroupError) as refused:
                await removed.subscribe_group(env.realm_id, topic, distributor.member_group(env, removed))
            assert refused.value.reason == "not_a_member"
    assert distributor.seen[-1] == {"prefix": prefix, "epoch": "current"}


def malformed(epoch: dict) -> dict[str, Callable[[dict], dict]]:
    """Replies that are not group_keys_v1's, each refused by a member that
    holds nothing of the group (macula-go's ErrMalformedReply): the asked
    prefix not echoed, no policy of the three, no epoch at all, and an epoch
    whose accept_until is not an event's life past its publish_until."""
    return {
        "another prefix": lambda r: {**r, "prefix": "io.macula/somewhere_else/chat"},
        "no policy of the three": lambda r: {**r, "policy": "maybe"},
        "no epoch": lambda r: {**r, "epochs": []},
        "an epoch that is not the protocol's": lambda r: {
            **r,
            "epochs": [{**epoch, "accept_until": epoch["accept_until"] + 1}],
        },
    }


async def a_malformed_reply_is_refused(
    member: Pool, env: TestStations, topic: str, distributor: Distributor, name: str, transform: Callable[[dict], dict]
) -> None:
    """One of malformed()' replies, refused by a member that holds nothing of
    the group: the same no_distributor a missing distributor gives."""
    distributor.transform = transform
    with pytest.raises(GroupError) as refused:
        await member.subscribe_group(env.realm_id, topic, distributor.member_group(env, member))
    assert refused.value.reason == "no_distributor", name


async def test_a_reply_that_is_not_the_protocols_is_refused(env):
    prefix = group_prefix(env, "malformed")
    topic = f"{prefix}/said_v1"
    policy = RealmMemberRequired(env.org_key_id, "group_keys")
    standin = await node(env, 0, admitted=True, kem_advertise=True)
    distributor = Distributor(standin, prefix, policy, serves=[epoch_at(0, issued_at=now_ms() - 1_000)])
    async with standin, await distributor.served(env):
        member = await node(env, 0)
        async with member:
            # Reachable, answering the protocol's own reply.
            await until_served(
                lambda: member.call(
                    env.realm_id, f"{env.org}/group_keys_v1", {"prefix": prefix, "epoch": "current"},
                    ucan=env.grant(member.node_id()), confidential="required",
                )
            )
            for name, transform in malformed(distributor.serves[0].wire()).items():
                await a_malformed_reply_is_refused(member, env, topic, distributor, name, transform)
            # The control: the same procedure, the same member, only the reply
            # back to the protocol's — and the join is held.
            distributor.transform = lambda reply: reply
            subscription = await until_joined(
                lambda: member.subscribe_group(env.realm_id, topic, distributor.member_group(env, member))
            )
            async with subscription:
                await member.publish_group(
                    env.realm_id, topic, {"said": "held"}, distributor.member_group(env, member)
                )


async def test_the_group_and_its_options_are_checked(env):
    """What this binding refuses before the library sees it (a group is a
    macula_py.Group, its distributor 32 bytes or 64 hex), and what it hands
    the library to refuse: a prefix with no org segment is macula's own
    invalid_argument."""
    prefix = group_prefix(env, "checked")
    s = env.stations[0]
    key = await NodeKey.generate(env.profile)
    pool = await Pool.connect(key, [Seed(s.host, s.port, s.node_id)], realm_trust={env.realm_id: env.realm_key})
    async with pool:
        with pytest.raises(TypeError):
            await pool.subscribe_group(env.realm_id, f"{prefix}/said_v1", {"prefix": prefix})  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await pool.subscribe_group(env.realm_id, f"{prefix}/said_v1", Group(prefix, distributor="00"))
        with pytest.raises(InvalidArgumentError):
            await pool.subscribe_group(env.realm_id, "chat/said_v1", Group("chat"))

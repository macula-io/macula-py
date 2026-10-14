"""macula-py's side of sealed groups across macula (15.0.0-rc.1 on, wire 1.0)
and Python, for macula-go's scripts/interop/erlang_groups.escript, through one
station and macula's own distributor (macula_group_keys), driven by
scripts/interop/groups.sh. The Python twin of macula-go's gogroups.

    python pygroups.py <host:port@node_id hex> <profile> <realm hex> <realm key hex> \
        <work dir> <prefix> <topic> member
    python pygroups.py ... stranger

Both connect a pool, print "node <hex>", and wait for <work>/grant.<hex>, the
org's grant the script minted for this node. member subscribes to topic under
the group prefix, pulling its epoch from the Erlang distributor over a sealed
call, writes the counterpart seat's barrier, waits for the Erlang member's,
publishes its marker sealed under the group, and waits for the Erlang member's
marker to arrive opened. The Erlang member is macula's own, and the counterpart
seat is the one erlang_groups.escript names "go" — its barrier file ready.go
and the text it waits for — so a Python member takes that seat as it stands and
macula's side needs no change. stranger, a node the distributor's removed set
names, checks its subscribe is refused not_a_member. Each prints its outcome and
exits 1 on any other.
"""

from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path

from macula_py import Group, GroupError, NodeKey, Pool, Seed, Subscription

BARRIER_OWN = "ready.go"
BARRIER_OTHER = "ready.erlang"
SAYS_OWN = "from go"
SAYS_OTHER = "from erlang"
KEY_ID = re.compile(r"^[0-9a-f]{16}$")


def seed_of(text: str) -> Seed:
    m = re.fullmatch(r"(.+):(\d+)@([0-9a-fA-F]{64})", text)
    if not m:
        raise SystemExit(f"pygroups: the station is host:port@<node_id hex>, not {text!r}")
    return Seed(m[1].strip("[]"), int(m[2]), m[3])


async def waited(work: Path, name: str) -> str:
    """A file the orchestrating script writes, read once it is there."""
    for _ in range(900):
        try:
            return (work / name).read_text()
        except FileNotFoundError:
            await asyncio.sleep(0.2)
    raise SystemExit(f"pygroups: no {work / name}")


async def subscribed(pool: Pool, realm: str, topic: str, group: Group) -> Subscription:
    """Subscribing under group, waiting while the distributor's advertisement
    has not reached the DHT yet (macula-go's subscribed: only no_distributor is
    the DHT's own reach, every other reason is macula's)."""
    for _ in range(150):
        try:
            return await pool.subscribe_group(realm, topic, group)
        except GroupError as e:
            if e.reason != "no_distributor":
                raise
            await asyncio.sleep(0.2)
    return await pool.subscribe_group(realm, topic, group)


async def member(pool: Pool, realm: str, work: Path, prefix: str, topic: str, grant: str) -> int:
    group = Group(prefix, grant)
    subscription = await subscribed(pool, realm, topic, group)
    print("subscribed", flush=True)
    (work / BARRIER_OWN).write_text("")
    await waited(work, BARRIER_OTHER)
    await pool.publish_group(realm, topic, SAYS_OWN, group)
    print("published", flush=True)
    async with subscription:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            event = await subscription.next(timeout_ms=5_000)
            if event is None or event.payload == SAYS_OWN:
                continue
            if event.unopened is not None:
                print(f"unopened: {event.unopened}")
                return 1
            if event.sealed and event.payload == SAYS_OTHER and KEY_ID.match(event.seal_key_id or ""):
                print(f"opened from erlang under {event.seal_key_id}")
                return 0
            print(f"unexpected: sealed {event.sealed}, payload {event.payload!r}")
            return 1
    print("nothing from erlang")
    return 1


async def stranger(pool: Pool, realm: str, work: Path, prefix: str, topic: str, grant: str) -> int:
    """A node the Erlang distributor's removed set names: the group it holds no
    key for must not be joined, and the refusal must travel by name."""
    try:
        subscription = await subscribed(pool, realm, topic, Group(prefix, grant))
    except GroupError as e:
        print(f"stranger subscribe: {e}")
        return 0 if e.reason == "not_a_member" else 1
    async with subscription:
        print("stranger subscribe: served")
    return 1


async def main(
    station: str, profile: str, realm: str, realm_key: str, work: str, prefix: str, topic: str, mode: str
) -> int:
    key = await NodeKey.generate(profile)
    pool = await Pool.connect(
        key, [seed_of(station)], realm_trust={realm: realm_key}, timeout_ms=60_000
    )
    print(f"node {pool.node_id()}", flush=True)
    async with pool:
        grant = (await waited(Path(work), f"grant.{pool.node_id()}")).strip()
        if mode == "member":
            return await member(pool, realm, Path(work), prefix, topic, grant)
        if mode == "stranger":
            return await stranger(pool, realm, Path(work), prefix, topic, grant)
    print(f"pygroups: mode {mode!r} is member or stranger", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main(*sys.argv[1:])))

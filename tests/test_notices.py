"""What a subscription hands back: an Event for a fact, and a Notice when the
library reports that events may have been missed.

Every subscription item carries a ``kind`` (cabi/CONTRACT.md, "Inboxes"), and a
notice has none of an event's fields: read as an Event it was a TypeError on
the first link lost, and the gap that says to resync was lost the same way. The
item is handed to next() itself here, through the inbox read: a lost link is
the one thing a station cannot be asked to produce on demand, and next() is
where the item used to be misread.
"""

from __future__ import annotations

import pytest

from macula_py import Event, MaculaError, Notice
from macula_py.pool import NOTICE_GAP, NOTICE_INTERRUPTED, Subscription

PUBLISHER = "ab" * 32
REALM = "cd" * 32


def _reading(monkeypatch, *items: dict) -> Subscription:
    """A subscription whose next() reads the items the library would have
    handed over, one per call and then nothing."""
    queue = list(items)

    async def take(*_args, **_kwargs):
        if queue:
            return queue.pop(0), False
        return None, True

    monkeypatch.setattr("macula_py.pool._next_item", take)
    return Subscription(0)


async def test_a_lost_link_is_a_notice_and_not_an_event(monkeypatch):
    item = await _reading(
        monkeypatch, {"kind": NOTICE_INTERRUPTED, "from_ms": 1_700_000_000_000, "reason": "liveness_lost"}
    ).next()

    assert isinstance(item, Notice), "a notice was handed back as an event"
    assert item.kind == NOTICE_INTERRUPTED
    assert item.from_ms == 1_700_000_000_000
    assert item.to_ms is None, "an interruption names no time it was carried again"
    assert item.reason == "liveness_lost"


async def test_a_gap_is_a_notice_naming_both_times(monkeypatch):
    item = await _reading(
        monkeypatch,
        {"kind": NOTICE_GAP, "from_ms": 1_700_000_000_000, "to_ms": 1_700_000_060_000, "reason": "goodbye"},
    ).next()

    assert isinstance(item, Notice), "a gap was handed back as an event"
    assert item.kind == NOTICE_GAP
    assert item.from_ms == 1_700_000_000_000
    assert item.to_ms == 1_700_000_060_000
    assert item.reason == "goodbye"


async def test_an_event_is_still_an_event(monkeypatch):
    item = await _reading(
        monkeypatch,
        {
            "kind": "event",
            "publisher": PUBLISHER,
            "realm": REALM,
            "topic": "acme/demo/greeting_sent_v1",
            "seq": 7,
            "published_at": 1_700_000_000_123,
            "payload": {"text": "hi"},
            "delivered_via": "direct",
        },
    ).next()

    assert isinstance(item, Event), "an event was not handed back as one"
    assert item.topic == "acme/demo/greeting_sent_v1"
    assert item.seq == 7
    assert item.payload == {"text": "hi"}


async def test_an_item_of_a_kind_this_binding_does_not_read_is_refused_by_name(monkeypatch):
    subscription = _reading(monkeypatch, {"kind": "later_notice", "from_ms": 1})
    with pytest.raises(MaculaError, match="later_notice"):
        await subscription.next()


async def test_iterating_a_subscription_hands_over_the_notice_too(monkeypatch):
    subscription = _reading(
        monkeypatch,
        {
            "kind": "event",
            "publisher": PUBLISHER,
            "realm": REALM,
            "topic": "acme/demo/greeting_sent_v1",
            "seq": 1,
            "published_at": 2,
            "payload": {"text": "hi"},
            "delivered_via": "direct",
        },
        {"kind": NOTICE_INTERRUPTED, "from_ms": 1_700_000_000_000, "reason": "liveness_lost"},
    )

    heard = [item async for item in subscription]
    assert isinstance(heard[0], Event), "the event did not survive the walk"
    assert isinstance(heard[1], Notice), "the notice did not survive the walk"
    assert len(heard) == 2

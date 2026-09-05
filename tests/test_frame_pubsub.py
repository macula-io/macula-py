import pytest

from macula import frame
from macula.identity import KeyPair


def test_build_publish_encodes_topic_as_bytes_not_text():
    publisher = KeyPair.generate(puzzle=False)
    p = frame.build_publish("macula.test.topic", bytes(32), publisher.node_id(), 1, "hi", frame.current_millis())
    assert p["topic"] == b"macula.test.topic"
    assert isinstance(p["topic"], bytes)


def test_build_publish_defaults_ttl_to_none():
    publisher = KeyPair.generate(puzzle=False)
    p = frame.build_publish("t", bytes(32), publisher.node_id(), 0, None, 0)
    assert p["ttl_ms"] is None


def test_build_publish_with_ttl():
    publisher = KeyPair.generate(puzzle=False)
    p = frame.build_publish("t", bytes(32), publisher.node_id(), 0, None, 0, ttl_ms=60_000)
    assert p["ttl_ms"] == 60_000


def test_publish_sign_verify_round_trip():
    publisher = KeyPair.generate(puzzle=False)
    p = frame.build_publish("t", bytes(32), publisher.node_id(), 5, {"n": 1}, frame.current_millis())
    signed = frame.sign(p, publisher)
    frame.verify(signed, publisher.node_id())


def test_build_subscribe_and_unsubscribe():
    subscriber = KeyPair.generate(puzzle=False)
    sub = frame.build_subscribe("t", bytes(32), subscriber.node_id())
    assert sub["topic"] == b"t"
    assert sub["filter"] is None
    assert sub["options"] == {}

    unsub = frame.build_unsubscribe("t", bytes(32), subscriber.node_id())
    assert unsub["frame_type"] == "unsubscribe"
    assert unsub["topic"] == b"t"


def _event_frame(*, delivered_via="plumtree", topic=b"t", payload="hello"):
    ev = frame.base("event")
    ev.update(
        {
            "topic": topic,
            "realm": bytes(32),
            "publisher": bytes(32),
            "seq": 7,
            "payload": payload,
            "delivered_via": delivered_via,
        }
    )
    return ev


def test_parse_event_round_trip():
    info = frame.parse_event(_event_frame())
    assert info.topic == "t"
    assert info.seq == 7
    assert info.payload == "hello"
    assert info.delivered_via == "plumtree"


@pytest.mark.parametrize("via", ["plumtree", "dht", "direct"])
def test_parse_event_accepts_every_delivered_via_value(via):
    info = frame.parse_event(_event_frame(delivered_via=via))
    assert info.delivered_via == via


def test_parse_event_rejects_an_unknown_delivered_via():
    with pytest.raises(frame.ParseFrameError):
        frame.parse_event(_event_frame(delivered_via="teleport"))


def test_parse_event_rejects_wrong_frame_type():
    with pytest.raises(frame.ParseFrameError):
        frame.parse_event(frame.base("hello"))


def test_parse_event_rejects_non_utf8_topic():
    with pytest.raises(frame.ParseFrameError):
        frame.parse_event(_event_frame(topic=b"\xff\xfe"))

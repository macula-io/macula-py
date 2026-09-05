import pytest

from macula_py import bolt4, frame
from macula_py.identity import KeyPair


def _call_id() -> bytes:
    return bytes(range(16))


def test_build_call_encodes_procedure_as_bytes_not_text():
    call = frame.build_call(_call_id(), "hecate_mail.initiate_mailbox", bytes(32), {"x": 1}, 1234, bytes(32))
    assert call["procedure"] == b"hecate_mail.initiate_mailbox"
    assert isinstance(call["procedure"], bytes)


def test_build_call_defaults():
    call = frame.build_call(_call_id(), "p", bytes(32), None, 0, bytes(32))
    assert call["source_route"] == b""
    assert call["retry_budget"] == 0
    assert call["ucan_token"] == b""
    assert call["frame_type"] == "call"


def test_call_sign_verify_and_parse_round_trip():
    caller = KeyPair.generate(puzzle=False)
    call = frame.build_call(_call_id(), "echo", bytes(32), {"n": 42}, frame.current_millis() + 5000, caller.node_id())
    signed = frame.sign(call, caller)
    frame.verify(signed, caller.node_id())

    info = frame.parse_call(signed)
    assert info.call_id == _call_id()
    assert info.procedure == "echo"
    assert info.payload == {"n": 42}
    assert info.caller == caller.node_id()
    assert info.ucan_token == b""


def test_parse_call_rejects_wrong_frame_type():
    with pytest.raises(frame.ParseFrameError):
        frame.parse_call(frame.base("hello"))


def test_result_round_trip_via_parse_call_response():
    responder = KeyPair.generate(puzzle=False)
    result = frame.build_result(_call_id(), {"answer": 42}, responder.node_id())
    signed = frame.sign(result, responder)
    frame.verify(signed, responder.node_id())

    parsed = frame.parse_call_response(signed)
    assert isinstance(parsed, frame.CallResult)
    assert parsed.payload == {"answer": 42}
    assert parsed.responded_by == responder.node_id()


def test_error_round_trip_via_parse_call_response():
    reporter = KeyPair.generate(puzzle=False)
    err = frame.build_call_error(_call_id(), bolt4.UNKNOWN_NEXT_PEER, reporter.node_id())
    signed = frame.sign(err, reporter)

    parsed = frame.parse_call_response(signed)
    assert isinstance(parsed, frame.CallError)
    assert parsed.code == bolt4.UNKNOWN_NEXT_PEER
    assert parsed.name == "unknown_next_peer"
    assert parsed.reported_by == reporter.node_id()
    assert parsed.detail is None


def test_error_with_detail_round_trips_as_utf8_text():
    reporter = KeyPair.generate(puzzle=False)
    err = frame.build_call_error(_call_id(), bolt4.UNKNOWN_ERROR, reporter.node_id(), detail="handler raised ValueError: boom")
    assert err["detail"] == b"handler raised ValueError: boom"

    parsed = frame.parse_call_response(err)
    assert isinstance(parsed, frame.CallError)
    assert parsed.detail == "handler raised ValueError: boom"


def test_build_call_error_derives_name_from_code():
    reporter_id = bytes(32)
    err = frame.build_call_error(_call_id(), bolt4.UNAUTHORIZED, reporter_id)
    assert err["name"] == "unauthorized"


def test_frame_call_id_extracts_regardless_of_frame_type():
    call = frame.build_call(_call_id(), "p", bytes(32), None, 0, bytes(32))
    result = frame.build_result(_call_id(), None, bytes(32))
    err = frame.build_call_error(_call_id(), bolt4.UNKNOWN_ERROR, bytes(32))
    for f in (call, result, err):
        assert frame.frame_call_id(f) == _call_id()


def test_frame_call_id_returns_none_for_a_frame_with_no_call_id():
    assert frame.frame_call_id(frame.base("hello")) is None
    assert frame.frame_call_id("not even a dict") is None


def test_parse_call_response_rejects_an_unrelated_frame_type():
    with pytest.raises(frame.ParseFrameError):
        frame.parse_call_response(frame.base("hello"))

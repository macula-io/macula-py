"""
Beyond the tests below: a signed CONNECT frame built and wire-encoded
entirely by this module was independently decoded and signature-verified
by the REAL, unmodified Erlang macula_frame module (macula_frame:decode/1
+ macula_frame:verify/2 against the actual macula checkout) -- confirming
genuine cross-language wire AND cryptographic compatibility for the
envelope layer, not just internal self-consistency. Reproduce with:

    python -c "
    from macula_py import frame
    from macula_py.identity import KeyPair
    identity = KeyPair.generate(puzzle=False)
    signed = frame.sign(frame.build_connect(identity.node_id(), identity.puzzle_evidence()), identity)
    open('/tmp/connect.bin', 'wb').write(frame.encode_frame(signed))
    open('/tmp/node_id.bin', 'wb').write(identity.node_id())
    "

then, against a macula checkout with beam files built (ASDF_ERLANG_VERSION=28.4.2, not the default OTP on this box -- see project_macula_10_19_tooling_bump memory for why):

    #!/usr/bin/env escript
    %% -*- erlang -*-
    main([WirePath, NodeIdPath]) ->
        code:add_path("<macula checkout>/_build/default/lib/macula/ebin"),
        {ok, Wire} = file:read_file(WirePath),
        {ok, NodeId} = file:read_file(NodeIdPath),
        {ok, Frame, <<>>} = macula_frame:decode(Wire),
        {ok, _} = macula_frame:verify(Frame, NodeId),
        io:format("SIGNATURE_VERIFY: OK~n").
"""

import pytest

from macula_py import cbor, frame
from macula_py.identity import KeyPair


def test_fresh_frame_id_is_16_bytes_and_looks_like_a_uuidv7():
    fid = frame.fresh_frame_id()
    assert len(fid) == 16
    assert (fid[6] >> 4) == 0x7  # version nibble
    assert (fid[8] >> 6) == 0b10  # variant bits


def test_fresh_frame_id_is_unique_across_calls():
    ids = {frame.fresh_frame_id() for _ in range(100)}
    assert len(ids) == 100


def test_bool_text_matches_frame_level_convention_not_payload_1_0():
    # Confirmed by reading macula_frame.erl's to_wire/1 directly: frame-level
    # atoms (including true/false) round-trip as CBOR TEXT STRINGS, unlike
    # the payload-level "no boolean, use 1/0" convention this codec's own
    # cbor.py implements for application data.
    assert frame.bool_text(True) == "true"
    assert frame.bool_text(False) == "false"
    assert frame.parse_bool_text("true", "x") is True
    assert frame.parse_bool_text("false", "x") is False
    with pytest.raises(frame.ParseFrameError):
        frame.parse_bool_text("nope", "x")
    with pytest.raises(frame.ParseFrameError):
        frame.parse_bool_text(1, "x")


def test_base_envelope_has_the_expected_sentinel_fields():
    envelope = frame.base("connect", 7)
    assert envelope["version"] == frame.PROTOCOL_VERSION
    assert envelope["frame_type"] == "connect"
    assert envelope["capabilities"] == 7
    assert envelope["realm"] is None
    assert envelope["call_id"] is None
    assert envelope["source_route"] is None
    assert len(envelope["frame_id"]) == 16
    assert isinstance(envelope["sent_at_ms"], int)


def test_sign_and_verify_round_trip():
    identity = KeyPair.generate(puzzle=False)
    unsigned = frame.build_connect(identity.node_id(), identity.puzzle_evidence())
    signed = frame.sign(unsigned, identity)
    assert len(signed["signature"]) == 64
    frame.verify(signed, identity.node_id())  # does not raise


def test_verify_rejects_a_tampered_field():
    identity = KeyPair.generate(puzzle=False)
    signed = frame.sign(frame.build_connect(identity.node_id(), identity.puzzle_evidence()), identity)
    tampered = {**signed, "capabilities": signed["capabilities"] + 1}
    with pytest.raises(frame.SignatureInvalidError):
        frame.verify(tampered, identity.node_id())


def test_verify_rejects_wrong_node_id():
    a = KeyPair.generate(puzzle=False)
    b = KeyPair.generate(puzzle=False)
    signed = frame.sign(frame.build_connect(a.node_id(), a.puzzle_evidence()), a)
    with pytest.raises(frame.SignatureInvalidError):
        frame.verify(signed, b.node_id())


def test_verify_rejects_a_missing_signature():
    with pytest.raises(frame.ParseFrameError):
        frame.verify(frame.base("connect"), b"\x00" * 32)


def test_signature_field_is_excluded_from_its_own_signable_bytes():
    identity = KeyPair.generate(puzzle=False)
    unsigned = frame.build_connect(identity.node_id(), identity.puzzle_evidence())
    signed_once = frame.sign(unsigned, identity)
    # Re-signing (as if a signature already existed) must produce signable
    # bytes identical to signing from scratch -- signature/publisher_sig
    # are excluded from what gets signed, so attaching one must not
    # change the bytes a verifier re-derives.
    assert frame.signable_bytes(signed_once) == frame.signable_bytes(unsigned)


def test_encode_decode_frame_round_trip():
    identity = KeyPair.generate(puzzle=False)
    signed = frame.sign(frame.build_connect(identity.node_id(), identity.puzzle_evidence()), identity)
    wire = frame.encode_frame(signed)
    decoded = frame.decode_frame(wire)
    assert decoded.complete
    assert decoded.consumed == len(wire)
    assert decoded.frame == signed


def test_decode_frame_reports_incomplete_buffers_without_raising():
    identity = KeyPair.generate(puzzle=False)
    wire = frame.encode_frame(frame.sign(frame.build_connect(identity.node_id(), identity.puzzle_evidence()), identity))

    too_short_for_length = frame.decode_frame(wire[:2])
    assert not too_short_for_length.complete
    assert too_short_for_length.need_more == 2

    too_short_for_body = frame.decode_frame(wire[:-1])
    assert not too_short_for_body.complete
    assert too_short_for_body.need_more == 1


def test_decode_frame_rejects_a_length_prefix_over_the_cap():
    over_cap = (frame.MAX_FRAME_BYTES + 1).to_bytes(4, "big")
    with pytest.raises(frame.ParseFrameError):
        frame.decode_frame(over_cap)


def test_build_connect_uses_node_id_as_station_id_for_a_plain_dial():
    identity = KeyPair.generate(puzzle=False)
    connect = frame.build_connect(identity.node_id(), identity.puzzle_evidence())
    assert connect["station_id"] == connect["node_id"] == identity.node_id()
    assert connect["realms"] == []
    assert connect["addresses"] == []
    assert connect["site"] is None
    assert connect["endorsements"] == []
    assert connect["puzzle_evidence"] == identity.puzzle_evidence()


def test_parse_hello_accepted():
    station_id = bytes(range(32))
    node_id = bytes(range(1, 33))
    hello = frame.base("hello")
    hello.update(
        {
            "node_id": node_id,
            "station_id": station_id,
            "realms": [bytes(32)],
            "capabilities": 3,
            "addresses": [],
            "site": None,
            "accepted": "true",
            "refusal_code": None,
            "negotiated_capabilities": 1,
        }
    )
    info = frame.parse_hello(hello)
    assert info.accepted is True
    assert info.node_id == node_id
    assert info.station_id == station_id
    assert info.realms == [bytes(32)]
    assert info.capabilities == 3
    assert info.negotiated_capabilities == 1
    assert info.refusal_code is None


def test_parse_hello_refused_with_a_refusal_code():
    hello = frame.base("hello")
    hello.update(
        {
            "node_id": bytes(32),
            "station_id": bytes(32),
            "realms": [],
            "capabilities": 0,
            "accepted": "false",
            "refusal_code": 42,
            "negotiated_capabilities": 0,
        }
    )
    info = frame.parse_hello(hello)
    assert info.accepted is False
    assert info.refusal_code == 42


def test_parse_hello_rejects_wrong_frame_type():
    with pytest.raises(frame.ParseFrameError):
        frame.parse_hello(frame.base("connect"))


def test_parse_hello_rejects_a_cbor_boolean_style_accepted_field():
    # Confirms parse_hello enforces the TEXT-string convention and would
    # reject a payload-style bool if one somehow arrived.
    hello = frame.base("hello")
    hello.update(
        {
            "node_id": bytes(32),
            "station_id": bytes(32),
            "realms": [],
            "capabilities": 0,
            "accepted": True,  # wrong shape -- should be "true"/"false"
            "refusal_code": None,
            "negotiated_capabilities": 0,
        }
    )
    with pytest.raises(frame.ParseFrameError):
        frame.parse_hello(hello)

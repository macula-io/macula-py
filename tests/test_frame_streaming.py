"""STREAM_OPEN/DATA/END/ERROR/REPLY: parse-side unit tests, plus a
golden-vector cross-check against frames signed by the real Erlang
macula_frame:stream_*/1 + sign/2 (generated via escript,
ASDF_ERLANG_VERSION=28.4.2) -- proving this module's parsers and
signature verification agree with the reference implementation, not
just with themselves.
"""

import pytest

from macula import frame

_NODE_ID = bytes.fromhex("E07428AAF95D59E24EF819B5570EF1DA1E8CB0B219A17FD3B7A3555FC2960CC2")
_STREAM_ID = bytes([1]) * 16
_REALM = bytes([2]) * 32

_GOLDEN_OPEN = "00000182B06461726773A1616E05646D6F64656D7365727665725F73747265616D657265616C6D582002020202020202020202020202020202020202020202020202020202020202026663616C6C65725820E07428AAF95D59E24EF819B5570EF1DA1E8CB0B219A17FD3B7A3555FC2960CC26763616C6C5F6964F66776657273696F6E02686672616D655F69645001A071648D3C73659FB6CBBCE7D09D1E6970726F6365647572654C6C6F67732E7461696C5F7631697369676E61747572655840B6B5C7484F2BE320FC2448F5F8EBF56EED328AE3ECD8AB4BF4BBA280B460D17D3258CD844E7B345F401F11E876BB067D705DAF17A935FF1E0B4DA0772FF1E0006973747265616D5F696450010101010101010101010101010101016A6672616D655F747970656B73747265616D5F6F70656E6A73656E745F61745F6D731B000001A071648D3C6B646561646C696E655F6D731B000001A070DE1E006C6361706162696C6974696573006C72657472795F627564676574006C736F757263655F726F75746540"
_GOLDEN_DATA = "0000012CAE637365710064626F6479496368756E6B2D6F6E65657265616C6DF6667369676E65725820E07428AAF95D59E24EF819B5570EF1DA1E8CB0B219A17FD3B7A3555FC2960CC26763616C6C5F6964F66776657273696F6E0268656E636F64696E6763726177686672616D655F69645001A071648D4D7F2F8B273A52543D7980697369676E617475726558406F5DD2A6BBB30BFCDAD5D834FF13F594E4B4B2C7442CC66456FE5D9B612AEFE9B5A96F75CBDBD8EEA95B28315CFBBF7CB863D5EA166120E7389612C8F4FE55036973747265616D5F696450010101010101010101010101010101016A6672616D655F747970656B73747265616D5F646174616A73656E745F61745F6D731B000001A071648D4D6C6361706162696C6974696573006C736F757263655F726F757465F6"
_GOLDEN_END = "00000114AC64726F6C6564626F7468657265616C6DF6667369676E65725820E07428AAF95D59E24EF819B5570EF1DA1E8CB0B219A17FD3B7A3555FC2960CC26763616C6C5F6964F66776657273696F6E02686672616D655F69645001A071648D4D7A829354F61BD5B50826697369676E617475726558400E3DE36F45E703A8DADAA63C442C9206E73ED46E6277674BB88A794E9CA520173609A2F96D81F486E7523546C0C9653B80CF2F46D81E3CEBB7085023D24C830E6973747265616D5F696450010101010101010101010101010101016A6672616D655F747970656A73747265616D5F656E646A73656E745F61745F6D731B000001A071648D4D6C6361706162696C6974696573006C736F757263655F726F757465F6"
_GOLDEN_ERROR = "0000013DAD64636F6465496E6F745F666F756E64657265616C6DF6667369676E65725820E07428AAF95D59E24EF819B5570EF1DA1E8CB0B219A17FD3B7A3555FC2960CC26763616C6C5F6964F6676D657373616765581870726F636564757265206E6F7420616476657274697365646776657273696F6E02686672616D655F69645001A071648D4D7CF1B493E74614B4918D697369676E61747572655840C4447B9CDD5A4F4B61120E94E37DD669C53EA689F5CFF1BC033BF930C67DDE152D3BD44EEEE304E1A64DD59C495F663B06893AFC5200A3E03F9F256D43C970096973747265616D5F696450010101010101010101010101010101016A6672616D655F747970656C73747265616D5F6572726F726A73656E745F61745F6D731B000001A071648D4D6C6361706162696C6974696573006C736F757263655F726F757465F6"
_GOLDEN_REPLY = "00000122AC657265616C6DF66763616C6C5F6964F6677061796C6F6164A165746F74616C056776657273696F6E02686672616D655F69645001A071648D4D7D199F35606780DD0D2A697369676E617475726558406AB6E7DE844D42ADA9B44E49DC51435FDB62C950B0D752EC3FD467076E4DB33D3556616BC35CC88AA09EA49650E594C106C0C19501A8C2832EBEF80642485D046973747265616D5F696450010101010101010101010101010101016A6672616D655F747970656C73747265616D5F7265706C796A73656E745F61745F6D731B000001A071648D4D6C6361706162696C6974696573006C726573706F6E6465645F62795820E07428AAF95D59E24EF819B5570EF1DA1E8CB0B219A17FD3B7A3555FC2960CC26C736F757263655F726F757465F6"


def _decode_and_verify(hex_bytes: str) -> dict:
    decoded = frame.decode_frame(bytes.fromhex(hex_bytes))
    assert decoded.complete
    frame.verify(decoded.frame, _NODE_ID)
    return decoded.frame


def test_stream_open_golden_vector_from_real_erlang():
    value = _decode_and_verify(_GOLDEN_OPEN)
    info = frame.parse_stream_open(value)
    assert info.stream_id == _STREAM_ID
    assert info.procedure == "logs.tail_v1"
    assert info.realm == _REALM
    assert info.mode == "server_stream"
    assert info.args == {"n": 5}
    assert info.caller == _NODE_ID


def test_stream_data_golden_vector_from_real_erlang():
    value = _decode_and_verify(_GOLDEN_DATA)
    info = frame.parse_stream_data(value)
    assert info.stream_id == _STREAM_ID
    assert info.seq == 0
    assert info.encoding == "raw"
    assert info.body == b"chunk-one"


def test_stream_end_golden_vector_from_real_erlang():
    value = _decode_and_verify(_GOLDEN_END)
    info = frame.parse_stream_end(value)
    assert info.stream_id == _STREAM_ID
    assert info.role == "both"


def test_stream_error_golden_vector_from_real_erlang():
    value = _decode_and_verify(_GOLDEN_ERROR)
    error = frame.parse_stream_error(value)
    assert error.code == "not_found"
    assert error.message == "procedure not advertised"


def test_stream_reply_golden_vector_from_real_erlang():
    value = _decode_and_verify(_GOLDEN_REPLY)
    info = frame.parse_stream_reply(value)
    assert info.stream_id == _STREAM_ID
    assert info.payload == {"total": 5}
    assert info.responded_by == _NODE_ID


def test_parse_stream_inbound_dispatches_data_end_and_reply():
    assert isinstance(frame.parse_stream_inbound(_decode_and_verify(_GOLDEN_DATA)), frame.StreamDataInfo)
    assert isinstance(frame.parse_stream_inbound(_decode_and_verify(_GOLDEN_END)), frame.StreamEndInfo)
    assert isinstance(frame.parse_stream_inbound(_decode_and_verify(_GOLDEN_REPLY)), frame.StreamReplyInfo)


def test_parse_stream_inbound_raises_stream_aborted_for_stream_error():
    with pytest.raises(frame.StreamAbortedError):
        frame.parse_stream_inbound(_decode_and_verify(_GOLDEN_ERROR))


def test_build_stream_open_rejects_an_invalid_mode():
    with pytest.raises(ValueError):
        frame.build_stream_open(_STREAM_ID, "foo", _REALM, "not_a_mode", None, 0, bytes(32))


def test_build_stream_data_rejects_non_bytes_body_for_raw_encoding():
    with pytest.raises(ValueError):
        frame.build_stream_data(_STREAM_ID, 0, "not bytes", bytes(32), encoding="raw")


def test_build_stream_data_accepts_arbitrary_term_for_msgpack_encoding():
    built = frame.build_stream_data(_STREAM_ID, 0, {"n": 1}, bytes(32), encoding="msgpack")
    info = frame.parse_stream_data(built)
    assert info.body == {"n": 1}


def test_build_stream_end_rejects_an_invalid_role():
    with pytest.raises(ValueError):
        frame.build_stream_end(_STREAM_ID, "sideways", bytes(32))


def test_round_trip_through_this_modules_own_sign_and_verify():
    from macula.identity import KeyPair

    identity = KeyPair.generate(puzzle=False)
    built = frame.sign(frame.build_stream_reply(_STREAM_ID, "done", identity.node_id()), identity)
    wire = frame.encode_frame(built)
    decoded = frame.decode_frame(wire)
    assert decoded.complete
    frame.verify(decoded.frame, identity.node_id())
    info = frame.parse_stream_reply(decoded.frame)
    assert info.payload == "done"

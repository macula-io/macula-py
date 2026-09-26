"""The shapes every part of the API shares: payloads as the native layer takes
them, ids, bytes output modes, and the errors a call or a fetch ends with."""

import json

import pytest

from macula_py import (
    ContentUnavailableError,
    NotSharedError,
    ProviderError,
    RelayError,
)
from macula_py._wire import (
    bytes_mode_for,
    call_error,
    content_error,
    decode_payload,
    encode_payload,
    id32,
    mcid50,
)


class TestEncodePayload:
    def test_plain_values_pass_through_as_json(self):
        assert json.loads(encode_payload({"a": [1, "x", None, 2.5]})) == {"a": [1, "x", None, 2.5]}

    def test_bytes_go_in_as_the_tagged_base64_object(self):
        assert json.loads(encode_payload(b"\x01\x02\x03")) == {"$bytes": "AQID"}

    def test_nested_bytes_are_tagged_too(self):
        assert json.loads(encode_payload({"k": [b"\xff"]})) == {"k": [{"$bytes": "/w=="}]}

    @pytest.mark.parametrize("value", [True, False, {"flag": True}, [1, False]])
    def test_a_boolean_anywhere_is_refused_naming_the_rule(self, value):
        with pytest.raises(TypeError, match="no boolean"):
            encode_payload(value)

    def test_a_non_text_map_key_is_refused(self):
        with pytest.raises(TypeError, match="map keys"):
            encode_payload({1: "x"})

    def test_an_unencodable_value_is_refused(self):
        with pytest.raises(TypeError, match="set"):
            encode_payload({1, 2})

    def test_tuples_are_lists(self):
        assert json.loads(encode_payload((1, 2))) == [1, 2]


class TestDecodePayload:
    def test_json_text_becomes_python_values(self):
        assert decode_payload('{"a":[1,"0xff",null]}') == {"a": [1, "0xff", None]}

    def test_tagged_bytes_come_out_as_bytes(self):
        assert decode_payload('{"k":{"$bytes":"AQID"}}') == {"k": b"\x01\x02\x03"}

    def test_an_object_with_other_keys_beside_bytes_stays_a_dict(self):
        assert decode_payload('{"$bytes":"AQID","x":1}') == {"$bytes": "AQID", "x": 1}


class TestBytesMode:
    def test_hex_is_the_default(self):
        assert bytes_mode_for(None) == 0
        assert bytes_mode_for("hex") == 0

    def test_tagged(self):
        assert bytes_mode_for("tagged") == 1

    def test_anything_else_is_refused(self):
        with pytest.raises(ValueError, match="'hex' or 'tagged'"):
            bytes_mode_for("raw")


class TestId32:
    def test_hex_text(self):
        assert id32("ab" * 32) == b"\xab" * 32

    def test_uppercase_hex_text(self):
        assert id32("AB" * 32) == b"\xab" * 32

    def test_bytes(self):
        assert id32(b"\x01" * 32) == b"\x01" * 32

    @pytest.mark.parametrize("bad", ["ab" * 31, "zz" * 32, b"\x00" * 31])
    def test_wrong_shapes_are_refused_naming_what(self, bad):
        with pytest.raises(ValueError, match="realm"):
            id32(bad, "realm")


class TestMcid50:
    def test_hex_text(self):
        assert mcid50("02" * 50) == b"\x02" * 50

    def test_wrong_length_is_refused(self):
        with pytest.raises(ValueError, match="50 bytes"):
            mcid50(b"\x02" * 49)


class TestCallError:
    def test_provider_error_carries_code_and_detail(self):
        e = call_error("provider_error:handler_error:boom: with colon")
        assert isinstance(e, ProviderError)
        assert (e.code, e.detail) == ("handler_error", "boom: with colon")

    def test_relay_error_carries_code(self):
        e = call_error("relay_error:unknown_next_peer")
        assert isinstance(e, RelayError)
        assert e.code == "unknown_next_peer"

    def test_other_text_is_a_plain_macula_error(self):
        e = call_error("timeout")
        assert type(e).__name__ == "MaculaError"
        assert "timeout" in str(e)


class TestContentError:
    def test_not_shared(self):
        assert isinstance(content_error("not_shared"), NotSharedError)

    def test_unavailable_carries_detail(self):
        e = content_error("unavailable:node a unreachable")
        assert isinstance(e, ContentUnavailableError)
        assert e.detail == "node a unreachable"

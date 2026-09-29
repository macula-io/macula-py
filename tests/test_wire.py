"""The shapes every part of the API shares: payloads as the native layer takes
them, ids, bytes output modes, and the errors a call or a fetch ends with."""

import json

import pytest

from macula_py import (
    ConfidentialityError,
    ContentUnavailableError,
    NotACallerError,
    NotSettledError,
    NotSharedError,
    ProviderError,
    RelayError,
)
from macula_py._blocking import NativeCancelled
from macula_py._wire import (
    AlreadyAnsweredError,
    ClosedError,
    InvalidHandleError,
    MaculaError,
    MaculaTimeoutError,
    NotFoundError,
    RefusedError,
    decode_payload,
    encode_payload,
    id32,
    mcid50,
    native_error,
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

    @pytest.mark.parametrize("value", [2**63 - 1, -(2**63)])
    def test_the_int64_bounds_pass_exactly(self, value):
        assert json.loads(encode_payload({"n": value})) == {"n": value}

    @pytest.mark.parametrize("value", [2**63, -(2**63) - 1, 2**64 - 1])
    def test_an_integer_outside_int64_is_refused_naming_the_rule(self, value):
        with pytest.raises(ValueError, match="int64"):
            encode_payload([value])

    def test_a_non_finite_float_is_refused(self):
        with pytest.raises(ValueError):
            encode_payload(float("nan"))

    def test_tuples_are_lists(self):
        assert json.loads(encode_payload((1, 2))) == [1, 2]


class TestDecodePayload:
    def test_json_text_becomes_python_values(self):
        assert decode_payload('{"a":[1,"0xff",null]}') == {"a": [1, "0xff", None]}

    def test_tagged_bytes_come_out_as_bytes(self):
        assert decode_payload('{"k":{"$bytes":"AQID"}}') == {"k": b"\x01\x02\x03"}

    def test_an_object_with_other_keys_beside_bytes_stays_a_dict(self):
        assert decode_payload('{"$bytes":"AQID","x":1}') == {"$bytes": "AQID", "x": 1}


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


class TestNativeError:
    def test_provider_error_carries_code_and_detail(self):
        e = native_error('{"kind":"provider_error","message":"m","code":"handler_error","detail":"boom"}')
        assert isinstance(e, ProviderError)
        assert (e.code, e.detail) == ("handler_error", "boom")

    def test_provider_error_detail_may_be_null(self):
        e = native_error('{"kind":"provider_error","message":"m","code":"expired","detail":null}')
        assert (e.code, e.detail) == ("expired", "")

    def test_relay_error_carries_code(self):
        e = native_error('{"kind":"relay_error","message":"m","code":"unknown_next_peer"}')
        assert isinstance(e, RelayError)
        assert e.code == "unknown_next_peer"

    def test_unavailable_carries_every_failure(self):
        e = native_error('{"kind":"unavailable","message":"m","failures":["a: unreachable","b: wrong hash"]}')
        assert isinstance(e, ContentUnavailableError)
        assert e.failures == ["a: unreachable", "b: wrong hash"]

    def test_confidentiality_carries_reason_and_both_key_ids(self):
        e = native_error(
            '{"kind":"confidentiality","message":"m","reason":"key_mismatch",'
            '"named":"0102030405060708","found":"1112131415161718"}'
        )
        assert isinstance(e, ConfidentialityError)
        assert (e.reason, e.named, e.found) == ("key_mismatch", "0102030405060708", "1112131415161718")

    def test_confidentiality_key_ids_may_be_null_or_absent(self):
        e = native_error('{"kind":"confidentiality","message":"m","reason":"no_kem_key","named":null}')
        assert (e.reason, e.named, e.found) == ("no_kem_key", None, None)

    def test_timeout_is_a_timeout_error(self):
        e = native_error('{"kind":"timeout","message":"call timed out"}')
        assert isinstance(e, MaculaTimeoutError)
        assert isinstance(e, TimeoutError)

    def test_cancelled_is_the_native_cancelled_signal(self):
        assert isinstance(native_error('{"kind":"cancelled","message":"m"}'), NativeCancelled)

    def test_invalid_argument_is_a_value_error(self):
        e = native_error('{"kind":"invalid_argument","message":"a JSON boolean"}')
        assert isinstance(e, ValueError)
        assert "a JSON boolean" in str(e)

    @pytest.mark.parametrize(
        ("kind", "cls"),
        [
            ("invalid_handle", InvalidHandleError),
            ("not_found", NotFoundError),
            ("not_shared", NotSharedError),
            ("answered", AlreadyAnsweredError),
            ("closed", ClosedError),
            ("refused", RefusedError),
            ("not_settled", NotSettledError),
            ("not_a_caller", NotACallerError),
            ("failed", MaculaError),
        ],
    )
    def test_each_kind_maps_to_its_class(self, kind, cls):
        e = native_error(f'{{"kind":"{kind}","message":"the message"}}')
        assert type(e) is cls
        assert isinstance(e, MaculaError)
        assert "the message" in str(e)

    def test_an_unknown_kind_is_loud_naming_it(self):
        e = native_error('{"kind":"brand_new","message":"m"}')
        assert type(e) is MaculaError
        assert "brand_new" in str(e)

    def test_text_that_is_not_the_contracts_json_is_loud(self):
        e = native_error("plain text")
        assert type(e) is MaculaError
        assert "plain text" in str(e)

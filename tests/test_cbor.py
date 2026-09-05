import math
import struct

import pytest

from macula_py import cbor


# Byte-exact vectors matching macula_record_cbor.erl's own encoding rules
# (RFC 8949 4.2.1 smallest-length-prefix) -- the same class of vectors every
# sibling Macula SDK's own CBOR codec test suite uses, since this encoding
# is language-agnostic ground truth, not something Python gets to reinterpret.
@pytest.mark.parametrize(
    "value,expected",
    [
        (0, b"\x00"),
        (1, b"\x01"),
        (23, b"\x17"),
        (24, b"\x18\x18"),
        (255, b"\x18\xff"),
        (256, b"\x19\x01\x00"),
        (65535, b"\x19\xff\xff"),
        (65536, b"\x1a\x00\x01\x00\x00"),
        (4294967295, b"\x1a\xff\xff\xff\xff"),
        (4294967296, b"\x1b\x00\x00\x00\x01\x00\x00\x00\x00"),
        (cbor.MAX_UINT64, b"\x1b\xff\xff\xff\xff\xff\xff\xff\xff"),
    ],
)
def test_uint_uses_minimal_length_encoding(value, expected):
    assert cbor.encode(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        (-1, b"\x20"),
        (-24, b"\x37"),
        (-25, b"\x38\x18"),
        (cbor.MIN_INT64, b"\x3b\xff\xff\xff\xff\xff\xff\xff\xff"),
    ],
)
def test_negative_int_uses_minimal_length_encoding(value, expected):
    assert cbor.encode(value) == expected


def test_bool_encodes_as_plain_integer_one_or_zero_not_a_cbor_boolean():
    # This wire has NO CBOR boolean simple value (major 7, AI 20/21) --
    # confirmed by reading macula_record_cbor.erl's decoder directly, which
    # has no matching clause for it. True/False must round-trip as 1/0.
    assert cbor.encode(True) == cbor.encode(1) == b"\x01"
    assert cbor.encode(False) == cbor.encode(0) == b"\x00"


def test_null_is_major_7_simple_value_22():
    assert cbor.encode(None) == b"\xf6"


def test_float_is_always_binary64_even_when_it_would_round_trip_through_less():
    # 1.0 would fit a much shorter representation under RFC 8949's own
    # canonical rules; this wire deliberately does NOT take the shortest
    # width -- always 1 (major/AI byte) + 8 (binary64) = 9 bytes.
    encoded = cbor.encode(1.0)
    assert len(encoded) == 9
    assert encoded[0] == (7 << 5) | 27
    assert struct.unpack(">d", encoded[1:])[0] == 1.0


def test_float_round_trips_exactly():
    for value in (0.0, -0.0, 1.5, -1.5, math.pi, 1e300, 5e-300):
        assert cbor.decode(cbor.encode(value)) == value or (value == 0.0 and cbor.decode(cbor.encode(value)) == 0.0)


def test_byte_string_round_trips_as_python_bytes():
    data = bytes(range(256))
    assert cbor.decode(cbor.encode(data)) == data
    assert isinstance(cbor.decode(cbor.encode(data)), bytes)


def test_text_string_round_trips_as_python_str_utf8():
    text = "hello ☃ macula"  # includes a non-ASCII codepoint
    encoded = cbor.encode(text)
    assert encoded[0] >> 5 == 3  # major type 3
    assert cbor.decode(encoded) == text


def test_empty_byte_string_and_text_string_and_array_and_map():
    assert cbor.decode(cbor.encode(b"")) == b""
    assert cbor.decode(cbor.encode("")) == ""
    assert cbor.decode(cbor.encode([])) == []
    assert cbor.decode(cbor.encode({})) == {}


def test_array_round_trips_preserving_order():
    value = [1, "two", b"three", 4.0, None, [5, 6]]
    assert cbor.decode(cbor.encode(value)) == value


def test_map_keys_are_sorted_by_their_own_encoded_bytes():
    # "b" (0x61 0x62) encodes to LARGER bytes than the single-byte
    # integer key 1 (0x01), so integer key 1 must sort first regardless
    # of insertion order -- this is the deterministic-CBOR canonicalization
    # rule (sort by encoded key bytes), not insertion order or key type.
    value = {"b": 1, 1: "a"}
    encoded = cbor.encode(value)
    key_one_pos = encoded.index(cbor.encode(1))
    key_b_pos = encoded.index(cbor.encode("b"))
    assert key_one_pos < key_b_pos


def test_map_with_mixed_key_types_round_trips():
    value = {1: "int-key", "s": "str-key", b"raw": "bytes-key"}
    assert cbor.decode(cbor.encode(value)) == value


def test_nested_structure_round_trips():
    value = {
        "realm": bytes(32),
        "topic": "macula.test",
        "seq": 42,
        "payload": {"nested": [1, 2, {"deep": True}]},
        "ttl_ms": None,
    }
    assert cbor.decode(cbor.encode(value)) == value


def test_encoding_is_deterministic_across_repeated_calls():
    value = {"z": 1, "a": 2, "m": [1, 2, 3], "realm": bytes(range(32))}
    assert cbor.encode(value) == cbor.encode(value)


def test_out_of_range_integer_is_rejected():
    with pytest.raises(ValueError):
        cbor.encode(cbor.MAX_UINT64 + 1)
    with pytest.raises(ValueError):
        cbor.encode(cbor.MIN_INT64 - 1)


def test_is_encodable_int_matches_encode_admissibility():
    assert cbor.is_encodable_int(cbor.MAX_UINT64)
    assert not cbor.is_encodable_int(cbor.MAX_UINT64 + 1)
    assert cbor.is_encodable_int(cbor.MIN_INT64)
    assert not cbor.is_encodable_int(cbor.MIN_INT64 - 1)


def test_unsupported_type_raises_type_error():
    with pytest.raises(TypeError):
        cbor.encode(object())
    with pytest.raises(TypeError):
        cbor.encode({1, 2, 3})  # a set has no CBOR mapping on this wire


def test_decode_accepts_half_and_single_precision_floats_even_though_we_never_emit_them():
    # RFC 8949 half-float 1.5 = 0x3E00.
    half = bytes([(7 << 5) | 25, 0x3E, 0x00])
    assert cbor.decode(half) == 1.5
    # Single precision 1.5 = 0x3FC00000.
    single = bytes([(7 << 5) | 26]) + struct.pack(">f", 1.5)
    assert cbor.decode(single) == 1.5


def test_decode_rejects_trailing_bytes():
    encoded = cbor.encode(1) + b"\x00"
    with pytest.raises(cbor.DecodeError):
        cbor.decode(encoded)


def test_decode_rejects_truncated_buffer():
    encoded = cbor.encode("a longer text string that needs a length prefix byte")
    with pytest.raises(cbor.DecodeError):
        cbor.decode(encoded[:-1])


def test_decode_rejects_a_cbor_boolean_simple_value():
    # major 7, additional info 21 = CBOR `true` -- valid RFC 8949, but this
    # wire's own decoder (macula_record_cbor.erl) has no clause for it and
    # would reject it too. Confirms we don't silently accept the thing the
    # "no bool on the wire" rule exists to keep off it.
    with pytest.raises(cbor.DecodeError):
        cbor.decode(bytes([(7 << 5) | 21]))


def test_encode_rejects_nan_and_infinity():
    # Erlang arithmetic structurally cannot produce either -- confirmed
    # live that the real station's decoder rejects both with bad_frame,
    # not a value. A caller must find out at encode time, not silently
    # send bytes the peer will only ever drop.
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            cbor.encode(bad)


def test_decode_rejects_nan_and_infinity_at_every_float_width():
    import struct as _struct

    nan64 = bytes([(7 << 5) | 27]) + _struct.pack(">d", float("nan"))
    inf32 = bytes([(7 << 5) | 26]) + _struct.pack(">f", float("inf"))
    with pytest.raises(cbor.DecodeError):
        cbor.decode(nan64)
    with pytest.raises(cbor.DecodeError):
        cbor.decode(inf32)


def test_decode_of_deeply_nested_input_raises_decode_error_not_recursion_error():
    # ~1500 levels of single-element nested arrays -- adversarial/corrupt
    # input, not anything a real macula frame would ever contain.
    depth = 1500
    encoded = bytes([0x81]) * depth + cbor.encode(0)
    with pytest.raises(cbor.DecodeError):
        cbor.decode(encoded)


def test_decode_of_a_map_with_an_unhashable_key_raises_decode_error_not_type_error():
    # major 5 (map, 1 pair), key = major 4 empty array, value = 1.
    # Erlang has no restriction on map key types; Python dict keys must
    # be hashable, so a decoded list/dict key can't become one.
    encoded = bytes([0xA1, 0x80, 0x01])
    with pytest.raises(cbor.DecodeError):
        cbor.decode(encoded)


def test_decode_one_reports_how_many_bytes_it_consumed():
    encoded = cbor.encode(42) + cbor.encode("trailer")
    value, consumed = cbor.decode_one(encoded)
    assert value == 42
    assert encoded[consumed:] == cbor.encode("trailer")

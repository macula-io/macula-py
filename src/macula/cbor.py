"""Deterministic CBOR encoder/decoder.

Ports ``macula_record_cbor.erl`` (macula-io/macula, src/record/) exactly --
NOT a generic CBOR library (Python's own ``cbor2``/stdlib would diverge:
shortest-float-width canonicalization per RFC 8949 Appendix, boolean simple
values, indefinite-length items). Macula's wire format enforces its own,
narrower deterministic subset:

- Definite lengths only, smallest length-prefix encoding (RFC 8949 4.2.1).
- Map keys sorted by BYTEWISE order of their own encoded bytes, not by the
  key's own natural ordering.
- Floats ALWAYS emitted as IEEE 754 binary64 (major 7, additional info 27)
  -- never the shorter half/single forms, even when a value would round-trip
  through them. Determinism requires one canonical width per value, not the
  shortest one that happens to work.
- NO boolean simple values (CBOR major 7, additional info 20/21) exist on
  this wire at all -- the station's own decoder has no clause for them.
  Every sibling Macula SDK's convention is the same: encode true/false as
  the integers 1/0. This module doesn't special-case Python `bool` at all;
  it falls through the plain integer branch naturally (`bool` is an `int`
  subclass in Python), which already produces exactly that encoding.

Python's own type system maps onto Macula's wire types with no wrapper
class needed, unlike Erlang (which needs a `{text, binary()}` tag to tell a
text string apart from a byte string -- both are just `binary()`
otherwise): `bytes`/`bytearray` -> byte string (major 2), `str` -> UTF-8
text string (major 3), each already a distinct native Python type.
"""

from __future__ import annotations

import struct

MAX_UINT64 = 0xFFFFFFFFFFFFFFFF
MIN_INT64 = -(MAX_UINT64 + 1)

Value = None | bool | int | float | bytes | bytearray | str | list | dict


class DecodeError(Exception):
    """Raised when a buffer isn't a valid deterministic-CBOR encoding of a supported value."""


def is_encodable_int(n: int) -> bool:
    """Can this integer be rendered as major 0 / major 1 on this wire?

    Exported so a caller that must decide admissibility BEFORE encoding
    (payload validation) can ask rather than restate the bound.
    """
    return MIN_INT64 <= n <= MAX_UINT64


def encode(value: Value) -> bytes:
    """Encode `value` as deterministic CBOR. Raises TypeError/ValueError for anything this wire can't carry."""
    out = bytearray()
    _encode_into(value, out)
    return bytes(out)


def _encode_into(value: Value, out: bytearray) -> None:
    if value is None:
        out.append(0xF6)  # major 7, simple value 22 (null)
    elif isinstance(value, int):
        # `bool` is an `int` subclass in Python, so True/False fall
        # through here too -- isinstance(True, int) is True, and
        # True >= 0 / int(True) == 1 both hold. That is deliberate: this
        # wire has no CBOR-boolean simple value at all (see module doc),
        # and encoding True/False as the plain integers 1/0 is exactly
        # the convention every sibling Macula SDK follows. Do not add a
        # dedicated `isinstance(value, bool)` branch above this one.
        if not is_encodable_int(value):
            raise ValueError(f"integer {value} does not fit this wire's 64-bit signed/unsigned range")
        if value >= 0:
            _encode_head_into(0, value, out)
        else:
            _encode_head_into(1, -1 - value, out)
    elif isinstance(value, float):
        # ALWAYS binary64 -- see module doc. struct.pack('>d', ...) gives
        # the big-endian IEEE 754 binary64 bytes RFC 8949 major 7 wants.
        out.append((7 << 5) | 27)
        out.extend(struct.pack(">d", value))
    elif isinstance(value, (bytes, bytearray)):
        _encode_head_into(2, len(value), out)
        out.extend(value)
    elif isinstance(value, str):
        encoded = value.encode("utf-8")
        _encode_head_into(3, len(encoded), out)
        out.extend(encoded)
    elif isinstance(value, (list, tuple)):
        _encode_head_into(4, len(value), out)
        for item in value:
            _encode_into(item, out)
    elif isinstance(value, dict):
        _encode_map_into(value, out)
    else:
        raise TypeError(f"value of type {type(value).__name__} cannot be encoded on this wire")


def _encode_map_into(value: dict, out: bytearray) -> None:
    # Encode each key/value independently, then sort pairs by the KEY'S
    # OWN ENCODED BYTES (bytewise comparison) -- exactly what the
    # deterministic-CBOR spec requires, matching macula_record_cbor.erl's
    # own `lists:sort/1` over `{encode(K), encode(V)}` pairs.
    pairs = [(encode(k), encode(v)) for k, v in value.items()]
    pairs.sort(key=lambda pair: pair[0])
    _encode_head_into(5, len(value), out)
    for k_bytes, v_bytes in pairs:
        out.extend(k_bytes)
        out.extend(v_bytes)


def _encode_head_into(major_type: int, n: int, out: bytearray) -> None:
    mt = major_type << 5
    if n <= 23:
        out.append(mt | n)
    elif n <= 0xFF:
        out.append(mt | 24)
        out.append(n)
    elif n <= 0xFFFF:
        out.append(mt | 25)
        out.extend(struct.pack(">H", n))
    elif n <= 0xFFFFFFFF:
        out.append(mt | 26)
        out.extend(struct.pack(">I", n))
    elif n <= MAX_UINT64:
        out.append(mt | 27)
        out.extend(struct.pack(">Q", n))
    else:
        raise ValueError(f"length/count {n} exceeds 64 bits")


def decode(data: bytes) -> Value:
    """Decode a single deterministic-CBOR value. The ENTIRE buffer must be one value -- trailing bytes raise DecodeError."""
    value, consumed = decode_one(data)
    if consumed != len(data):
        raise DecodeError(f"{len(data) - consumed} trailing byte(s) after a complete value")
    return value


def decode_one(data: bytes, offset: int = 0) -> tuple[Value, int]:
    """Decode exactly one value starting at `offset`. Returns (value, new_offset) -- new_offset is where the NEXT value would start, not a count.

    Exposed (not just `decode`) so a frame-stream reader can parse one
    length-prefixed frame's body without first knowing exactly where it
    ends.
    """
    if offset >= len(data):
        raise DecodeError("unexpected end of buffer")
    first = data[offset]
    major = first >> 5
    ai = first & 0x1F
    offset += 1

    if major == 7:
        if ai == 22:
            return None, offset
        if ai == 25:
            return _decode_half_float(data, offset)
        if ai == 26:
            return _decode_struct(data, offset, ">f", 4)
        if ai == 27:
            return _decode_struct(data, offset, ">d", 8)
        raise DecodeError(f"unsupported major-7 additional info {ai} (no boolean/undefined/indefinite on this wire)")

    count, offset = _decode_count(ai, data, offset)

    if major == 0:
        return count, offset
    if major == 1:
        return -1 - count, offset
    if major == 2:
        _require(data, offset, count)
        return bytes(data[offset : offset + count]), offset + count
    if major == 3:
        _require(data, offset, count)
        raw = data[offset : offset + count]
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise DecodeError(f"text string is not valid UTF-8: {e}") from e
        return text, offset + count
    if major == 4:
        items = []
        for _ in range(count):
            item, offset = decode_one(data, offset)
            items.append(item)
        return items, offset
    if major == 5:
        result: dict = {}
        for _ in range(count):
            key, offset = decode_one(data, offset)
            val, offset = decode_one(data, offset)
            result[key] = val
        return result, offset

    raise DecodeError(f"unsupported major type {major}")


def _decode_count(ai: int, data: bytes, offset: int) -> tuple[int, int]:
    if ai <= 23:
        return ai, offset
    if ai == 24:
        _require(data, offset, 1)
        return data[offset], offset + 1
    if ai == 25:
        _require(data, offset, 2)
        return struct.unpack_from(">H", data, offset)[0], offset + 2
    if ai == 26:
        _require(data, offset, 4)
        return struct.unpack_from(">I", data, offset)[0], offset + 4
    if ai == 27:
        _require(data, offset, 8)
        return struct.unpack_from(">Q", data, offset)[0], offset + 8
    raise DecodeError(f"unsupported additional info {ai} (indefinite-length items are not on this wire)")


def _decode_struct(data: bytes, offset: int, fmt: str, size: int) -> tuple[float, int]:
    _require(data, offset, size)
    return struct.unpack_from(fmt, data, offset)[0], offset + size


def _decode_half_float(data: bytes, offset: int) -> tuple[float, int]:
    # We only ever EMIT binary64, but a conforming peer may send the
    # shorter forms, so this codec accepts them on decode. Python's
    # struct module has no native IEEE 754 binary16, so unpack by hand.
    _require(data, offset, 2)
    bits = struct.unpack_from(">H", data, offset)[0]
    sign = -1.0 if (bits & 0x8000) else 1.0
    exponent = (bits >> 10) & 0x1F
    fraction = bits & 0x3FF
    if exponent == 0:
        value = sign * (2.0**-14) * (fraction / 1024.0)
    elif exponent < 31:
        value = sign * (2.0 ** (exponent - 15)) * (1 + fraction / 1024.0)
    else:
        raise DecodeError("half-float NaN/infinity has no representation this codec accepts")
    return value, offset + 2


def _require(data: bytes, offset: int, n: int) -> None:
    if offset + n > len(data):
        raise DecodeError("unexpected end of buffer")

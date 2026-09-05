"""The Macula application-frame envelope: construction, Ed25519
signing/verification, and the length-prefixed wire codec.

Ports ``macula_frame.erl`` (macula-io/macula, src/peering/), cross-checked
against ``macula-go``'s own port (``frame/envelope.go``, ``sign.go``,
``codec.go``) since it already ported this exactly once -- but every wire
constant here (the signature domain, protocol version, frame size cap, and
the boolean-as-text-string convention) was verified against the Erlang
source directly, not inferred from Go alone.

A wire frame is ``<Length:4 bytes big-endian><CBOR>``, where CBOR is the
deterministic encoding (:mod:`macula.cbor`) of a single map. Every frame
carries a common envelope -- version, frame_type, frame_id (UUIDv7),
sent_at_ms, capabilities, plus realm/call_id/source_route set to null
unless the specific frame type populates them -- and every frame is
Ed25519-signed over its own canonical bytes with signature/publisher_sig
stripped first.

Frame-level booleans (e.g. HELLO's ``accepted``) are NOT this wire's
payload-level "no boolean, use 1/0" convention -- confirmed by reading
``macula_frame.erl``'s own ``to_wire/1`` and its doc comment directly:
Erlang atoms (which is what ``true``/``false`` are) round-trip through
this frame layer as CBOR TEXT STRINGS ``"true"``/``"false"``, the same as
any other atom. The 1/0 convention applies to application PAYLOAD data
governed by a different validation path, not to a frame's own structural
fields. Confirmed independently in macula-go's own ``boolValue`` helper.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from . import cbor
from .identity import KeyPair

SIG_DOMAIN = b"macula-v2-frame\x00"
PROTOCOL_VERSION = 2
# Matches ?MAX_FRAME_BYTES exactly: 16 MiB minus one byte.
MAX_FRAME_BYTES = 0x00FF_FFFF

_LENGTH_PREFIX_SIZE = 4


class ParseFrameError(Exception):
    """Raised when a decoded CBOR value isn't a well-formed frame of the expected type."""


def current_millis() -> int:
    return int(time.time() * 1000)


def fresh_frame_id() -> bytes:
    """A fresh 16-byte UUIDv7 (RFC 9562): 48-bit big-endian unix-ms timestamp,
    version nibble 0111, 12 random bits, variant bits 10, 62 random bits.

    Python's stdlib `uuid` module gains `uuid7()` only in 3.14+; this repo
    targets 3.13 (see README), so a minimal generator matching the RFC is
    used instead of a third-party dependency for one function.
    """
    unix_ts_ms = int(time.time() * 1000)
    rand = os.urandom(10)
    b = bytearray(16)
    b[0:6] = unix_ts_ms.to_bytes(6, "big")
    b[6] = 0x70 | (rand[0] & 0x0F)  # version 7, top nibble of rand_a
    b[7] = rand[1]
    b[8] = 0x80 | (rand[2] & 0x3F)  # variant 10, top 2 bits of rand_b
    b[9:16] = rand[3:10]
    return bytes(b)


def bool_text(value: bool) -> str:
    """Frame-level boolean -> CBOR text string, matching macula_frame.erl's to_wire/1 (atoms round-trip as text)."""
    return "true" if value else "false"


def parse_bool_text(value: cbor.Value, field: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise ParseFrameError(f"field {field!r} is not a frame-level boolean text string")


def base(frame_type: str, capabilities: int = 0, *, frame_id: bytes | None = None, sent_at_ms: int | None = None) -> dict:
    """The envelope every frame carries. Field order doesn't matter -- deterministic CBOR re-sorts by encoded key bytes at encode time regardless."""
    return {
        "version": PROTOCOL_VERSION,
        "frame_type": frame_type,
        "frame_id": frame_id if frame_id is not None else fresh_frame_id(),
        "sent_at_ms": sent_at_ms if sent_at_ms is not None else current_millis(),
        "capabilities": capabilities,
        "realm": None,
        "call_id": None,
        "source_route": None,
    }


def signable_bytes(frame: dict) -> bytes:
    """SIG_DOMAIN || canonical_cbor(frame minus signature/publisher_sig)."""
    unsigned = {k: v for k, v in frame.items() if k not in ("signature", "publisher_sig")}
    return SIG_DOMAIN + cbor.encode(unsigned)


def sign(frame: dict, identity: KeyPair) -> dict:
    """Sign `frame` with `identity`, returning a NEW dict with its `signature` field set (64 bytes)."""
    sig = identity.sign(signable_bytes(frame))
    return {**frame, "signature": sig}


class SignatureInvalidError(Exception):
    """Raised by :func:`verify` when a frame's signature does not verify against the given pubkey."""


def verify(frame: dict, node_id: bytes) -> None:
    """Verify `frame`'s `signature` field against `node_id`. Raises ParseFrameError (missing/malformed) or SignatureInvalidError (doesn't verify)."""
    sig = frame.get("signature")
    if not isinstance(sig, bytes) or len(sig) != 64:
        raise ParseFrameError("frame has no valid 64-byte signature field")
    if not KeyPair.verify(node_id, signable_bytes(frame), sig):
        raise SignatureInvalidError("signature does not verify against the given node_id")


def encode_frame(frame: dict) -> bytes:
    """Wrap `frame` as <Length:4 bytes big-endian><CBOR>."""
    payload = cbor.encode(frame)
    if len(payload) > MAX_FRAME_BYTES:
        raise ValueError(f"frame is {len(payload)} bytes, exceeding the {MAX_FRAME_BYTES}-byte cap")
    return len(payload).to_bytes(_LENGTH_PREFIX_SIZE, "big") + payload


@dataclass
class DecodedFrame:
    """Result of decoding one length-prefixed frame from the head of a buffer."""

    frame: dict | None
    consumed: int
    complete: bool
    need_more: int = 0


def decode_frame(buf: bytes) -> DecodedFrame:
    """Decode one length-prefixed frame from the head of `buf`. Does not raise for an incomplete buffer -- check `.complete`."""
    if len(buf) < _LENGTH_PREFIX_SIZE:
        return DecodedFrame(None, 0, False, need_more=_LENGTH_PREFIX_SIZE - len(buf))
    length = int.from_bytes(buf[:_LENGTH_PREFIX_SIZE], "big")
    if length > MAX_FRAME_BYTES:
        raise ParseFrameError(f"claimed frame length {length} exceeds the {MAX_FRAME_BYTES}-byte cap")
    total = _LENGTH_PREFIX_SIZE + length
    if len(buf) < total:
        return DecodedFrame(None, 0, False, need_more=total - len(buf))
    value, consumed = cbor.decode_one(buf, _LENGTH_PREFIX_SIZE)
    if consumed != total:
        raise ParseFrameError(f"cbor consumed {consumed - _LENGTH_PREFIX_SIZE} bytes, frame declared {length}")
    if not isinstance(value, dict):
        raise ParseFrameError("a frame must be a CBOR map at the top level")
    return DecodedFrame(value, total, True)


def frame_type_of(value: cbor.Value) -> str | None:
    return value.get("frame_type") if isinstance(value, dict) else None


#: ---------------------------------------------------------------------
#: CONNECT / HELLO -- the handshake pair. Every other frame type
#: (CALL/RESULT/PUBLISH/etc.) is deferred to a later increment; these two
#: are the ones needed to prove a live handshake works at all.
#: ---------------------------------------------------------------------


def build_connect(node_id: bytes, puzzle_evidence: bytes, *, capabilities: int = 0) -> dict:
    """Build an unsigned CONNECT frame for a plain dial-out leaf client -- no realm memberships claimed, no advertised addresses.

    `station_id` = `node_id`: macula_frame.erl's own send_connect/2
    convention for a plain peer/daemon dial (confirmed in macula-go's
    NewConnectSpec, itself matching the reference), not something a leaf
    client picks independently.
    """
    frame = base("connect", capabilities)
    frame.update(
        {
            "node_id": node_id,
            "station_id": node_id,
            "realms": [],
            "addresses": [],
            "site": None,
            "puzzle_evidence": puzzle_evidence,
            "endorsements": [],
        }
    )
    return frame


@dataclass
class HelloInfo:
    node_id: bytes
    station_id: bytes
    realms: list[bytes]
    capabilities: int
    accepted: bool
    negotiated_capabilities: int
    refusal_code: int | None


def _require_bytes(frame: dict, field: str, size: int) -> bytes:
    value = frame.get(field)
    if not isinstance(value, bytes) or len(value) != size:
        raise ParseFrameError(f"field {field!r} must be a {size}-byte string")
    return value


def _require_bytes32_list(frame: dict, field: str) -> list[bytes]:
    value = frame.get(field)
    if not isinstance(value, list):
        raise ParseFrameError(f"field {field!r} must be a list")
    out = []
    for item in value:
        if not isinstance(item, bytes) or len(item) != 32:
            raise ParseFrameError(f"field {field!r} must be a list of 32-byte strings")
        out.append(item)
    return out


def _require_uint(frame: dict, field: str) -> int:
    value = frame.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ParseFrameError(f"field {field!r} must be a non-negative integer")
    return value


def parse_hello(frame: cbor.Value) -> HelloInfo:
    """Parse a decoded frame as HELLO."""
    if not isinstance(frame, dict) or frame.get("frame_type") != "hello":
        raise ParseFrameError("frame_type is not \"hello\"")

    refusal_code = frame.get("refusal_code")
    if refusal_code is not None and (not isinstance(refusal_code, int) or isinstance(refusal_code, bool)):
        raise ParseFrameError("field 'refusal_code' must be an integer or null")

    return HelloInfo(
        node_id=_require_bytes(frame, "node_id", 32),
        station_id=_require_bytes(frame, "station_id", 32),
        realms=_require_bytes32_list(frame, "realms"),
        capabilities=_require_uint(frame, "capabilities"),
        accepted=parse_bool_text(frame.get("accepted"), "accepted"),
        negotiated_capabilities=_require_uint(frame, "negotiated_capabilities"),
        refusal_code=refusal_code,
    )

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

from . import bolt4, cbor
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


#: ---------------------------------------------------------------------
#: CALL / RESULT / ERROR -- unary RPC, both caller and provider roles.
#: `procedure` is `binary()` on the wire in the Erlang spec (a raw byte
#: string, major 2), not text (major 3) -- confirmed by macula_frame.erl's
#: own `call/1` guard (`is_binary(Proc)`, no atom-to-text conversion
#: applied to it, unlike frame_type/accepted/etc.), so it's UTF-8-encoded
#: bytes here, not passed through cbor.py's `str`-as-text-string path.
#: ---------------------------------------------------------------------


def build_call(
    call_id: bytes,
    procedure: str,
    realm: bytes,
    payload: cbor.Value,
    deadline_ms: int,
    caller: bytes,
    *,
    source_route: bytes = b"",
    retry_budget: int = 0,
    ucan_token: bytes = b"",
) -> dict:
    frame = base("call", 0)
    frame.update(
        {
            "call_id": call_id,
            "procedure": procedure.encode("utf-8"),
            "realm": realm,
            "payload": payload,
            "deadline_ms": deadline_ms,
            "caller": caller,
            "source_route": source_route,
            "retry_budget": retry_budget,
            "ucan_token": ucan_token,
        }
    )
    return frame


def build_result(call_id: bytes, payload: cbor.Value, responded_by: bytes, *, source_route_reverse: bytes = b"") -> dict:
    frame = base("result", 0)
    frame.update(
        {
            "call_id": call_id,
            "payload": payload,
            "responded_by": responded_by,
            "source_route_reverse": source_route_reverse,
        }
    )
    return frame


def build_call_error(
    call_id: bytes,
    code: int,
    reported_by: bytes,
    *,
    detail: str | None = None,
    offending_hop: bytes | None = None,
    source_route_partial: bytes = b"",
) -> dict:
    frame = base("error", 0)
    frame.update(
        {
            "call_id": call_id,
            "code": code,
            "name": bolt4.name_for_code(code),
            "reported_by": reported_by,
            # `detail => binary() | undefined` on the wire -- bytes, not text.
            "detail": detail.encode("utf-8") if detail is not None else None,
            "offending_hop": offending_hop,
            "source_route_partial": source_route_partial,
        }
    )
    return frame


@dataclass
class CallInfo:
    """The fields a provider needs from an inbound CALL."""

    call_id: bytes
    procedure: str
    realm: bytes
    payload: cbor.Value
    deadline_ms: int
    caller: bytes
    ucan_token: bytes


def parse_call(frame: cbor.Value) -> CallInfo:
    if not isinstance(frame, dict) or frame.get("frame_type") != "call":
        raise ParseFrameError("frame_type is not \"call\"")
    call_id = _require_bytes(frame, "call_id", 16)
    procedure_bytes = frame.get("procedure")
    if not isinstance(procedure_bytes, bytes):
        raise ParseFrameError("field 'procedure' must be a byte string")
    try:
        procedure = procedure_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ParseFrameError("field 'procedure' is not valid UTF-8") from e
    realm = _require_bytes(frame, "realm", 32)
    if "payload" not in frame:
        raise ParseFrameError("field 'payload' is required")
    deadline_ms = frame.get("deadline_ms")
    if not isinstance(deadline_ms, int) or isinstance(deadline_ms, bool):
        raise ParseFrameError("field 'deadline_ms' must be an integer")
    caller = _require_bytes(frame, "caller", 32)
    ucan_token = frame.get("ucan_token")
    if ucan_token is None:
        ucan_token = b""
    elif not isinstance(ucan_token, bytes):
        raise ParseFrameError("field 'ucan_token' must be a byte string")
    return CallInfo(call_id, procedure, realm, frame["payload"], deadline_ms, caller, ucan_token)


#: Result of parsing a RESULT or ERROR frame, correlated by call_id.
@dataclass
class CallResult:
    payload: cbor.Value
    responded_by: bytes


@dataclass
class CallError:
    code: int
    name: str
    reported_by: bytes
    detail: str | None


CallResponse = CallResult | CallError


def frame_call_id(value: cbor.Value) -> bytes | None:
    """Extract this frame's call_id, regardless of frame type -- 16 bytes, or None if absent/malformed."""
    if not isinstance(value, dict):
        return None
    call_id = value.get("call_id")
    return call_id if isinstance(call_id, bytes) and len(call_id) == 16 else None


def parse_call_response(value: cbor.Value) -> CallResponse:
    """Parse a decoded frame as a RESULT or ERROR response to a CALL."""
    if not isinstance(value, dict):
        raise ParseFrameError("a call response must be a CBOR map")
    frame_type = value.get("frame_type")
    if frame_type == "result":
        if "payload" not in value:
            raise ParseFrameError("field 'payload' is required")
        return CallResult(value["payload"], _require_bytes(value, "responded_by", 32))
    if frame_type == "error":
        code = value.get("code")
        if not isinstance(code, int) or isinstance(code, bool) or not (0 <= code <= 255):
            raise ParseFrameError("field 'code' must be an integer in 0..255")
        name = value.get("name")
        if not isinstance(name, str):
            raise ParseFrameError("field 'name' must be a text string")
        reported_by = _require_bytes(value, "reported_by", 32)
        detail_bytes = value.get("detail")
        if detail_bytes is not None and not isinstance(detail_bytes, bytes):
            raise ParseFrameError("field 'detail' must be a byte string or null")
        detail = detail_bytes.decode("utf-8") if detail_bytes is not None else None
        return CallError(code, name, reported_by, detail)
    raise ParseFrameError(f"frame_type {frame_type!r} is not a call response")


#: ---------------------------------------------------------------------
#: ADVERTISE / UNADVERTISE -- registers this connection as the handler
#: for (realm, procedure). Fire-and-forget on the wire; the station then
#: routes inbound CALLs for that procedure back to this connection.
#: ---------------------------------------------------------------------


def build_advertise(realm: bytes, procedure: str, advertiser: bytes) -> dict:
    frame = base("advertise", 0)
    frame.update(
        {
            "realm": realm,
            "procedure": procedure.encode("utf-8"),
            "advertiser": advertiser,
            "options": {},
        }
    )
    return frame


def build_unadvertise(realm: bytes, procedure: str, advertiser: bytes) -> dict:
    frame = base("unadvertise", 0)
    frame.update(
        {
            "realm": realm,
            "procedure": procedure.encode("utf-8"),
            "advertiser": advertiser,
        }
    )
    return frame


#: ---------------------------------------------------------------------
#: PUBLISH / SUBSCRIBE / UNSUBSCRIBE / EVENT -- PubSub, both roles.
#: `topic` is `binary()` on the wire (confirmed: macula_frame.erl's own
#: `publish/1`/`subscribe/1` guards use `is_binary(T)`, no atom/text
#: conversion) -- UTF-8-encoded bytes here, same convention as `procedure`.
#: `publisher_sig` (the separate end-to-end signature surviving relay
#: beyond one hop) is NOT implemented this phase -- deferred alongside
#: direct-dial/UCAN/re-advertise, not silently dropped.
#: ---------------------------------------------------------------------


def build_publish(topic: str, realm: bytes, publisher: bytes, seq: int, payload: cbor.Value, published_at_ms: int, *, ttl_ms: int | None = None) -> dict:
    frame = base("publish", 0)
    frame.update(
        {
            "topic": topic.encode("utf-8"),
            "realm": realm,
            "publisher": publisher,
            "seq": seq,
            "payload": payload,
            "published_at_ms": published_at_ms,
            "ttl_ms": ttl_ms,
        }
    )
    return frame


def build_subscribe(topic: str, realm: bytes, subscriber: bytes) -> dict:
    frame = base("subscribe", 0)
    frame.update(
        {
            "topic": topic.encode("utf-8"),
            "realm": realm,
            "subscriber": subscriber,
            "filter": None,
            "options": {},
        }
    )
    return frame


def build_unsubscribe(topic: str, realm: bytes, subscriber: bytes) -> dict:
    frame = base("unsubscribe", 0)
    frame.update(
        {
            "topic": topic.encode("utf-8"),
            "realm": realm,
            "subscriber": subscriber,
        }
    )
    return frame


@dataclass
class EventInfo:
    """What a subscriber actually receives -- parsed fields of an EVENT frame."""

    topic: str
    realm: bytes
    publisher: bytes
    seq: int
    payload: cbor.Value
    delivered_via: str


def _require_topic_bytes(frame: dict, field: str = "topic") -> str:
    value = frame.get(field)
    if not isinstance(value, bytes):
        raise ParseFrameError(f"field {field!r} must be a byte string")
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ParseFrameError(f"field {field!r} is not valid UTF-8") from e


#: ---------------------------------------------------------------------
#: STREAM_OPEN / STREAM_DATA / STREAM_END / STREAM_ERROR / STREAM_REPLY --
#: streaming RPC, both caller and provider roles. Every stream frame
#: travels on its own dedicated QUIC stream (opened fresh for STREAM_OPEN,
#: exactly like content transfer's dedicated stream) rather than the
#: shared control stream; `stream_id' alone correlates the rest of that
#: stream's frames, since there's only ever one stream session per
#: dedicated QUIC stream. `mode'/`role'/`encoding' are Erlang atoms at
#: the frame-envelope level (like `frame_type'/`accepted'/`delivered_via'
#: elsewhere in this module) so they round-trip as plain CBOR text --
#: ordinary Python `str` here, no special encode/decode helper needed.
#: `code'/`message' in STREAM_ERROR are `binary()' on the wire per
#: macula_frame.erl's own guards (`is_binary'), the same convention as
#: `procedure'/`topic': UTF-8-encoded bytes, exposed here as `str' to
#: match this SDK's own `CallError.detail' ergonomics.
#:
#: `signer' (STREAM_DATA/END/ERROR) and `responded_by' (STREAM_REPLY) are
#: a SEPARATE field from the frame's own whole-frame `signature' --
#: needed on the real mesh so a multi-hop relay can verify a chunk
#: against its ORIGINAL emitter rather than the immediate peering
#: connection's identity (macula_station_link.erl's `finalise_stream_spec/3`
#: doc comment). This SDK doesn't do multi-hop relay, but the station
#: still expects the field populated on outbound frames, and always
#: populates it on inbound ones -- required here, not optional, matching
#: how every real call site actually uses it.
#: ---------------------------------------------------------------------

STREAM_MODES = ("server_stream", "client_stream", "bidi")
STREAM_END_ROLES = ("send", "both")
STREAM_ENCODINGS = ("raw", "msgpack")


class StreamAbortedError(Exception):
    """Raised when the peer sends a STREAM_ERROR -- the stream is closed, both sides."""

    def __init__(self, code: str, message: str):
        super().__init__(f"stream aborted: {code}: {message}")
        self.code = code
        self.message = message


def build_stream_open(
    stream_id: bytes,
    procedure: str,
    realm: bytes,
    mode: str,
    args: cbor.Value,
    deadline_ms: int,
    caller: bytes,
    *,
    source_route: bytes = b"",
    retry_budget: int = 0,
) -> dict:
    if mode not in STREAM_MODES:
        raise ValueError(f"mode must be one of {STREAM_MODES}, got {mode!r}")
    frame = base("stream_open", 0)
    frame.update(
        {
            "stream_id": stream_id,
            "procedure": procedure.encode("utf-8"),
            "realm": realm,
            "mode": mode,
            "args": args,
            "deadline_ms": deadline_ms,
            "caller": caller,
            "source_route": source_route,
            "retry_budget": retry_budget,
        }
    )
    return frame


@dataclass
class StreamOpenInfo:
    stream_id: bytes
    procedure: str
    realm: bytes
    mode: str
    args: cbor.Value
    deadline_ms: int
    caller: bytes


def parse_stream_open(value: cbor.Value) -> StreamOpenInfo:
    if not isinstance(value, dict) or value.get("frame_type") != "stream_open":
        raise ParseFrameError("frame_type is not \"stream_open\"")
    mode = value.get("mode")
    if mode not in STREAM_MODES:
        raise ParseFrameError(f"field 'mode' must be one of {STREAM_MODES}")
    procedure_bytes = value.get("procedure")
    if not isinstance(procedure_bytes, bytes):
        raise ParseFrameError("field 'procedure' must be a byte string")
    try:
        procedure = procedure_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ParseFrameError("field 'procedure' is not valid UTF-8") from e
    deadline_ms = value.get("deadline_ms")
    if not isinstance(deadline_ms, int) or isinstance(deadline_ms, bool):
        raise ParseFrameError("field 'deadline_ms' must be an integer")
    if "args" not in value:
        raise ParseFrameError("field 'args' is required")
    return StreamOpenInfo(
        stream_id=_require_bytes(value, "stream_id", 16),
        procedure=procedure,
        realm=_require_bytes(value, "realm", 32),
        mode=mode,
        args=value["args"],
        deadline_ms=deadline_ms,
        caller=_require_bytes(value, "caller", 32),
    )


def build_stream_data(stream_id: bytes, seq: int, body: cbor.Value, signer: bytes, *, encoding: str = "raw") -> dict:
    if encoding not in STREAM_ENCODINGS:
        raise ValueError(f"encoding must be one of {STREAM_ENCODINGS}, got {encoding!r}")
    if encoding == "raw" and not isinstance(body, bytes):
        raise ValueError("body must be bytes when encoding is 'raw'")
    frame = base("stream_data", 0)
    frame.update({"stream_id": stream_id, "seq": seq, "encoding": encoding, "body": body, "signer": signer})
    return frame


@dataclass
class StreamDataInfo:
    stream_id: bytes
    seq: int
    encoding: str
    body: cbor.Value


def parse_stream_data(value: cbor.Value) -> StreamDataInfo:
    if not isinstance(value, dict) or value.get("frame_type") != "stream_data":
        raise ParseFrameError("frame_type is not \"stream_data\"")
    encoding = value.get("encoding", "raw")
    if encoding not in STREAM_ENCODINGS:
        raise ParseFrameError(f"field 'encoding' must be one of {STREAM_ENCODINGS}")
    return StreamDataInfo(
        stream_id=_require_bytes(value, "stream_id", 16),
        seq=_require_uint(value, "seq"),
        encoding=encoding,
        body=value.get("body", b""),
    )


def build_stream_end(stream_id: bytes, role: str, signer: bytes) -> dict:
    if role not in STREAM_END_ROLES:
        raise ValueError(f"role must be one of {STREAM_END_ROLES}, got {role!r}")
    frame = base("stream_end", 0)
    frame.update({"stream_id": stream_id, "role": role, "signer": signer})
    return frame


@dataclass
class StreamEndInfo:
    stream_id: bytes
    role: str


def parse_stream_end(value: cbor.Value) -> StreamEndInfo:
    if not isinstance(value, dict) or value.get("frame_type") != "stream_end":
        raise ParseFrameError("frame_type is not \"stream_end\"")
    role = value.get("role", "both")
    if role not in STREAM_END_ROLES:
        raise ParseFrameError(f"field 'role' must be one of {STREAM_END_ROLES}")
    return StreamEndInfo(stream_id=_require_bytes(value, "stream_id", 16), role=role)


def build_stream_error(stream_id: bytes, code: str, message: str, signer: bytes) -> dict:
    frame = base("stream_error", 0)
    frame.update(
        {
            "stream_id": stream_id,
            "code": code.encode("utf-8"),
            "message": message.encode("utf-8"),
            "signer": signer,
        }
    )
    return frame


def _require_text_bytes(value: dict, field: str, default: str = "") -> str:
    raw = value.get(field)
    if raw is None:
        return default
    if not isinstance(raw, bytes):
        raise ParseFrameError(f"field {field!r} must be a byte string")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ParseFrameError(f"field {field!r} is not valid UTF-8") from e


def parse_stream_error(value: cbor.Value) -> StreamAbortedError:
    if not isinstance(value, dict) or value.get("frame_type") != "stream_error":
        raise ParseFrameError("frame_type is not \"stream_error\"")
    return StreamAbortedError(
        code=_require_text_bytes(value, "code"),
        message=_require_text_bytes(value, "message"),
    )


def build_stream_reply(stream_id: bytes, payload: cbor.Value, responded_by: bytes) -> dict:
    frame = base("stream_reply", 0)
    frame.update({"stream_id": stream_id, "payload": payload, "responded_by": responded_by})
    return frame


@dataclass
class StreamReplyInfo:
    stream_id: bytes
    payload: cbor.Value
    responded_by: bytes


def parse_stream_reply(value: cbor.Value) -> StreamReplyInfo:
    if not isinstance(value, dict) or value.get("frame_type") != "stream_reply":
        raise ParseFrameError("frame_type is not \"stream_reply\"")
    if "payload" not in value:
        raise ParseFrameError("field 'payload' is required")
    return StreamReplyInfo(
        stream_id=_require_bytes(value, "stream_id", 16),
        payload=value["payload"],
        responded_by=_require_bytes(value, "responded_by", 32),
    )


#: What a stream reader gets back from one inbound frame: a data chunk,
#: end-of-stream (with which side closed), or a terminal reply.
StreamInbound = StreamDataInfo | StreamEndInfo | StreamReplyInfo


def parse_stream_inbound(value: cbor.Value) -> StreamInbound:
    """Parse a decoded frame arriving on an open stream session -- STREAM_DATA, STREAM_END, or STREAM_REPLY. Raises StreamAbortedError for STREAM_ERROR (the stream is over) rather than returning it."""
    if not isinstance(value, dict):
        raise ParseFrameError("a stream frame must be a CBOR map")
    frame_type = value.get("frame_type")
    if frame_type == "stream_data":
        return parse_stream_data(value)
    if frame_type == "stream_end":
        return parse_stream_end(value)
    if frame_type == "stream_reply":
        return parse_stream_reply(value)
    if frame_type == "stream_error":
        raise parse_stream_error(value)
    raise ParseFrameError(f"frame_type {frame_type!r} is not a stream delivery")


def parse_event(value: cbor.Value) -> EventInfo:
    """Parse a decoded frame as an EVENT. Any non-EVENT frame is an error, not silently skipped -- a caller waiting specifically for a pubsub delivery has no reason to expect anything else to legitimately arrive first."""
    if not isinstance(value, dict) or value.get("frame_type") != "event":
        raise ParseFrameError("frame_type is not \"event\"")
    delivered_via = value.get("delivered_via")
    if delivered_via not in ("plumtree", "dht", "direct"):
        raise ParseFrameError("field 'delivered_via' must be one of plumtree/dht/direct")
    if "payload" not in value:
        raise ParseFrameError("field 'payload' is required")
    return EventInfo(
        topic=_require_topic_bytes(value),
        realm=_require_bytes(value, "realm", 32),
        publisher=_require_bytes(value, "publisher", 32),
        seq=_require_uint(value, "seq"),
        payload=value["payload"],
        delivered_via=delivered_via,
    )

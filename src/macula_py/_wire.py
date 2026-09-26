"""The shapes every part of the API shares: payloads, ids, and the errors a
call, a stream or a fetch ends with.

A payload is what macula's wire CBOR carries: str, int (within int64), float,
None, bytes, lists (or tuples) and dicts with str keys. There is no boolean on the wire;
encode true/false as 1/0 yourself. Python's bool is an int, so a bool
reaching the wire is refused here rather than silently sent as JSON true.

Bytes go in as ``bytes`` and come out as ``bytes``, so a value received can
be sent back unchanged.

Errors: the native layer reports each failure as JSON with a fixed ``kind``
(macula-go's cabi/CONTRACT.md "Errors"); native_error maps each kind to its
class here.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Union

from macula_py._blocking import NativeCancelled

JsonValue = Union[str, int, float, None, bytes, list["JsonValue"], tuple, dict[str, "JsonValue"]]
Id = Union[str, bytes]
Mcid = Union[str, bytes]

DEFAULT_CALL_TIMEOUT_MS = 5_000
DEFAULT_CONTENT_TIMEOUT_MS = 300_000


class MaculaError(Exception):
    """A failure the native layer reported (kind ``failed``), and the base of
    every macula-py error."""


class MaculaTimeoutError(MaculaError, TimeoutError):
    """The call's timeout ran out."""


class InvalidArgumentError(MaculaError, ValueError):
    """A malformed id, JSON, profile, mode, size or payload."""


class InvalidHandleError(MaculaError):
    """A handle this process does not hold (freed, closed, or of another kind)."""


class NotFoundError(MaculaError):
    """No DHT record under that key."""


class AlreadyAnsweredError(MaculaError):
    """A served call was answered already."""


class ClosedError(MaculaError):
    """The pool, subscription, served procedure or stream has ended."""


class RefusedError(MaculaError):
    """The network refused it: an advertisement, an admission, a key."""


class ProviderError(MaculaError):
    """A provider's own ERROR for a call: ``handler_error`` with the handler's
    text, ``temporary_relay_failure`` for a handler that crashed,
    ``unknown_next_peer`` for a procedure it does not serve, or an admission
    refusal (``expired``, ``request_copy``, ``caller_quota``, ...)."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"macula-py: the provider answered {code}" + (f": {detail}" if detail else ""))
        self.code = code
        self.detail = detail


class RelayError(MaculaError):
    """A station's signed relay error for a call: it could not relay it."""

    def __init__(self, code: str) -> None:
        super().__init__(f"macula-py: the station could not relay the call: {code}")
        self.code = code


class StreamError(MaculaError):
    """A stream ended by a STREAM_ERROR: the peer's, a relay error from the
    station (``relay``), or this side's own (e.g. ``resource_exhausted``)."""

    def __init__(self, code: str, detail: str, relay: bool) -> None:
        super().__init__(f"macula-py: stream error {code}" + (f": {detail}" if detail else ""))
        self.code = code
        self.detail = detail
        self.relay = relay


class NotSharedError(MaculaError):
    """Content no node announces in the realm."""


class ContentUnavailableError(MaculaError):
    """Content every announcing node failed to give; ``failures`` names each
    failure (unreachable, not the content asked for, over the bounds, ...)."""

    def __init__(self, failures: list[str]) -> None:
        super().__init__("macula-py: no sharer gave the content: " + "; ".join(failures))
        self.failures = failures


_INT64_MIN, _INT64_MAX = -(2**63), 2**63 - 1


def _to_wire(value: object) -> object:
    if isinstance(value, bool):
        raise TypeError("macula-py: no boolean on the macula wire; encode true/false as 1/0")
    if isinstance(value, int):
        if not _INT64_MIN <= value <= _INT64_MAX:
            raise ValueError(f"macula-py: {value} is outside int64, the integers macula's wire carries")
        return value
    if value is None or isinstance(value, (str, float)):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"$bytes": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, (list, tuple)):
        return [_to_wire(v) for v in value]
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError(f"macula-py: map keys must be str, got {type(k).__name__}")
            out[k] = _to_wire(v)
        return out
    raise TypeError(f"macula-py: a {type(value).__name__} has no macula wire form")


def encode_payload(value: object) -> str:
    """value as the JSON text the native layer converts to wire CBOR."""
    return json.dumps(_to_wire(value), separators=(",", ":"), allow_nan=False)


def _from_wire(obj: dict) -> object:
    if len(obj) == 1 and isinstance(obj.get("$bytes"), str):
        return base64.b64decode(obj["$bytes"], validate=True)
    return obj


def decode_payload(text: str) -> object:
    """JSON text from the native layer as Python values, tagged bytes as bytes."""
    return json.loads(text, object_hook=_from_wire)


_HEX64 = re.compile(r"[0-9a-fA-F]{64}")
_HEX100 = re.compile(r"[0-9a-fA-F]{100}")


def id32(value: Id, what: str = "id") -> bytes:
    """A 32-byte id (node_id, realm id, record key) from 64 hex chars or 32 bytes."""
    if isinstance(value, str):
        if not _HEX64.fullmatch(value):
            raise ValueError(f"macula-py: {what} must be 64 hex characters")
        return bytes.fromhex(value)
    if len(value) != 32:
        raise ValueError(f"macula-py: {what} must be 32 bytes, got {len(value)}")
    return bytes(value)


def mcid50(value: Mcid) -> bytes:
    """A content id (MCID) from 100 hex chars or 50 bytes."""
    if isinstance(value, str):
        if not _HEX100.fullmatch(value):
            raise ValueError("macula-py: a content id is 100 hex characters (50 bytes)")
        return bytes.fromhex(value)
    if len(value) != 50:
        raise ValueError(f"macula-py: a content id is 50 bytes, got {len(value)}")
    return bytes(value)


_KINDS: dict[str, type[MaculaError]] = {
    "timeout": MaculaTimeoutError,
    "invalid_argument": InvalidArgumentError,
    "invalid_handle": InvalidHandleError,
    "not_found": NotFoundError,
    "not_shared": NotSharedError,
    "answered": AlreadyAnsweredError,
    "closed": ClosedError,
    "refused": RefusedError,
    "failed": MaculaError,
}


def native_error(text: str) -> Exception:
    """The native layer's error JSON as the class its kind names. A kind this
    binding does not know, or text that is not the contract's JSON, comes out
    as a MaculaError naming it, never silently as something else."""
    try:
        error = json.loads(text)
        kind = error["kind"]
        message = str(error.get("message") or kind)
    except (ValueError, KeyError, TypeError):
        return MaculaError(f"macula-py: the native layer failed with {text!r}")
    if kind == "cancelled":
        return NativeCancelled(message)
    if kind == "provider_error":
        return ProviderError(str(error.get("code") or ""), str(error.get("detail") or ""))
    if kind == "relay_error":
        return RelayError(str(error.get("code") or ""))
    if kind == "unavailable":
        return ContentUnavailableError([str(f) for f in error.get("failures") or []])
    cls = _KINDS.get(kind)
    if cls is None:
        return MaculaError(f"macula-py: the native layer failed with unknown kind {kind!r}: {message}")
    return cls(f"macula-py: {message}")

"""The shapes every part of the API shares: payloads, ids, bytes output modes,
and the errors a call, a stream or a fetch ends with.

A payload is what macula's wire CBOR carries: str, int, float, None, bytes,
lists (or tuples) and dicts with str keys. There is no boolean on the wire;
encode true/false as 1/0 yourself. Python's bool is an int, so a bool
reaching the wire is refused here rather than silently sent as JSON true.

Bytes go in as ``bytes``. Coming out, bytes are a "0x"-prefixed lowercase hex
string by default, or ``bytes`` when you ask for ``bytes_output="tagged"``.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Literal, Union

JsonValue = Union[str, int, float, None, bytes, list["JsonValue"], tuple, dict[str, "JsonValue"]]
BytesOutput = Literal["hex", "tagged"]
Id = Union[str, bytes]
Mcid = Union[str, bytes]

DEFAULT_CALL_TIMEOUT_MS = 5_000
DEFAULT_CONTENT_TIMEOUT_MS = 300_000


class MaculaError(Exception):
    """An error the native layer reported, as its text."""


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

    def __init__(self) -> None:
        super().__init__("macula-py: no node shares that content in that realm")


class ContentUnavailableError(MaculaError):
    """Content every announcing node failed to give; ``detail`` names each
    failure (unreachable, not the content asked for, over the bounds, ...)."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"macula-py: no sharer gave the content: {detail}")
        self.detail = detail


def _to_wire(value: object) -> object:
    if isinstance(value, bool):
        raise TypeError("macula-py: no boolean on the macula wire; encode true/false as 1/0")
    if value is None or isinstance(value, (str, int, float)):
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


def bytes_mode_for(bytes_output: BytesOutput | None) -> int:
    """BytesOutput as the integer the native layer takes."""
    if bytes_output is None or bytes_output == "hex":
        return 0
    if bytes_output == "tagged":
        return 1
    raise ValueError(f"macula-py: bytes_output must be 'hex' or 'tagged', got {bytes_output!r}")


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


_PROVIDER = re.compile(r"provider_error:([^:]*):(.*)", re.DOTALL)
_RELAY = re.compile(r"relay_error:(.*)", re.DOTALL)
_UNAVAILABLE = re.compile(r"unavailable:(.*)", re.DOTALL)


def call_error(message: str) -> MaculaError:
    """The native layer's call error text as the class it names."""
    if m := _PROVIDER.fullmatch(message):
        return ProviderError(m[1], m[2])
    if m := _RELAY.fullmatch(message):
        return RelayError(m[1])
    return MaculaError(f"macula-py: {message}")


def content_error(message: str) -> MaculaError:
    """The native layer's content error text as the class it names."""
    if message == "not_shared":
        return NotSharedError()
    if m := _UNAVAILABLE.fullmatch(message):
        return ContentUnavailableError(m[1])
    return MaculaError(f"macula-py: {message}")

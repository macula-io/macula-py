"""A device's request to a realm, signed (realm proof v2, macula-realm#29):
a join session over HTTP, or a membership UCAN over the mesh. The proof binds
the device's key to exactly this request, in this realm, once: every field
of it is signed, with a timestamp and a nonce the realm refuses to see twice.

NodeKey.device_request_proof makes one. The request is a mapping, or for the
HTTP rule the JSON body text exactly as it will be sent. It never carries a
"caller": the realm drops one, so it is refused here (InvalidArgumentError).
"""

from __future__ import annotations

import ctypes
import json
from typing import Literal, Mapping, Union

from macula_py._native import native
from macula_py._wire import Id, encode_payload, id32

Rule = Literal["http", "mesh"]
DeviceRequest = Union[Mapping, str]

JOIN_SESSION = "macula_realm.join_session"
MEMBERSHIP_UCAN = "macula_realm.membership_ucan"

_RULES = {"http": 0, "mesh": 1}


def rule_code(rule: Rule) -> int:
    if rule not in _RULES:
        raise ValueError(f"macula-py: a request rule is 'http' or 'mesh', not {rule!r}")
    return _RULES[rule]


def request_json(request: DeviceRequest, rule: Rule) -> bytes:
    """The request as the ABI takes it: an HTTP body under the realm's JSON
    rule (a str is the body as sent), or a mesh payload as it goes on the
    wire."""
    rule_code(rule)
    if isinstance(request, str):
        if rule != "http":
            raise TypeError("macula-py: a mesh request is a mapping, not JSON text")
        return request.encode()
    if rule == "http":
        return json.dumps(request, separators=(",", ":"), allow_nan=False).encode()
    return encode_payload(request).encode()


def device_request_message(
    public_key: bytes, realm: Id, procedure: str, timestamp_ms: int, nonce: bytes, request: DeviceRequest, rule: Rule
) -> bytes:
    """The exact bytes a proof signs, for a given timestamp and 16-byte nonce:
    what a verifier rebuilds, and what the realm's vector holds."""
    if len(nonce) != 16:
        raise ValueError("macula-py: a device request nonce is 16 bytes")
    n = native()
    length = ctypes.c_size_t()
    address = n.invoke(
        "macula_device_request_message",
        bytes(public_key),
        len(public_key),
        id32(realm, "realm"),
        procedure.encode(),
        timestamp_ms,
        bytes(nonce),
        request_json(request, rule),
        rule_code(rule),
        ctypes.byref(length),
    )
    return n.take_bytes(address, length.value)

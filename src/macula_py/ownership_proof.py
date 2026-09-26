"""The ownership proof (v2, mcl-om#7): the ``asserted_by`` block by which a
node authorises exactly one request's fields, for one procedure in one realm,
once. NodeKey.ownership_proof returns the payload with its block, to send as
the payload; a verifier (mcl_om) checks the block against the fields it
receives.

The fields are the payload minus ``asserted_by`` and minus a text "caller": a
station replaces a caller-sent one with the caller it authenticated, so a
payload carrying one is refused when signing (InvalidArgumentError).
"""

from __future__ import annotations

import ctypes
from typing import Any, Mapping

from macula_py._native import native
from macula_py._wire import Id, encode_payload, id32


def ownership_proof_message(
    identity: Id, realm: Id, procedure: str, timestamp_ms: int, nonce: bytes, fields: Mapping[str, Any]
) -> bytes:
    """The exact bytes a proof over a payload's fields signs, for a given
    identity (node_id), timestamp and 16-byte nonce, as the verifier rebuilds
    them from a delivered payload: asserted_by and a text caller left out."""
    if len(nonce) != 16:
        raise ValueError("macula-py: an ownership proof nonce is 16 bytes")
    n = native()
    length = ctypes.c_size_t()
    address = n.invoke(
        "macula_ownership_proof_message",
        id32(identity, "identity"),
        id32(realm, "realm"),
        procedure.encode(),
        timestamp_ms,
        bytes(nonce),
        encode_payload(dict(fields)).encode(),
        ctypes.byref(length),
    )
    return n.take_bytes(address, length.value)

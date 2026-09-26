"""macula 12's UCANs (D7): capability tokens signed with a node's identity key
in its profile (ML-DSA-87, or the ML-DSA-87 + RSA-4096-PSS composite).

A token is minted with NodeKey.ucan for the node that will present it (its
audience is always that node), presented with Pool.call(ucan=, proofs=) or
Pool.open_stream(ucan=, proofs=), and a procedure is gated on one with
Pool.serve(policy=) or Pool.serve_stream(policy=). The provider checks every
call and open before the handler sees it, as macula's link does: a refusal is
a ProviderError (or StreamError) of code ``unauthorized``, or
``malformed_frame`` for a proof no token in the chain names.

A capability is ``{"with": <MRI>, "can": <action>}``, the MRI one of
``mri:realm:<realm>``, ``mri:org:<realm>/<org>`` or
``mri:proc:<realm>/<org>/<name>``, a realm named by its name (its id is the
name's SHA-256). A delegated token names its parent by proof_id in ``prf``,
and the parent travels in ``proofs``. macula's test/vectors/UCAN_V1.md is the
contract.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Union

from macula_py._native import native
from macula_py._wire import Id, id32
from macula_py.key import Profile

_KEY_ID_LABEL = b"MACULA-KEY-ID-V1"


@dataclass(frozen=True)
class UcanRequired:
    """A chain rooted at the identity key of the node ``issuer``."""

    issuer: Id

    def __post_init__(self) -> None:
        id32(self.issuer, "the issuer's node_id")

    def json(self) -> dict:
        return {"kind": "ucan_required", "issuer": id32(self.issuer).hex()}


@dataclass(frozen=True)
class RealmMemberRequired:
    """A chain rooted at the realm key whose key id is ``key_id`` (see
    key_id), granting a capability whose can is ``can``."""

    key_id: Id
    can: str

    def __post_init__(self) -> None:
        id32(self.key_id, "the realm key's key id")
        if not self.can:
            raise ValueError("macula-py: a realm member policy names a can")

    def json(self) -> dict:
        return {"kind": "realm_member_required", "key_id": id32(self.key_id).hex(), "can": self.can}


Policy = Union[UcanRequired, RealmMemberRequired]


def proof_id(token: str) -> str:
    """The id a child's ``prf`` names token by: lowercase hex SHA-384 of its text."""
    n = native()
    return n.take_string(n.invoke("macula_ucan_proof_id", token.encode()))  # type: ignore[return-value]


def key_id(public_key: bytes, profile: Profile) -> bytes:
    """The 32-byte key id of a key as carried, in its profile: what a realm
    member policy names a realm key by. SHA-256 over the label, a zero byte,
    the profile name's length and text, and the key (macula_node_keys:key_id/2)."""
    name = profile.encode()
    return hashlib.sha256(_KEY_ID_LABEL + bytes([0, len(name)]) + name + bytes(public_key)).digest()

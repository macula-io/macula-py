"""A node's identity key, as macula 12 has it: ML-DSA-87 (pq_pure) or the
LAMPS composite ML-DSA-87 + RSA-4096-PSS (pq_hybrid, the fleet's profile),
whose node_id solves the admission puzzle. Stored in a key file readable by
its owner only."""

from __future__ import annotations

import ctypes
import json
import os
import weakref
from typing import Any, Literal, Mapping, Sequence

from macula_py._blocking import run_blocking
from macula_py._native import native
from macula_py._wire import ClosedError, Id, decode_payload, encode_payload, id32
from macula_py.device_request import DeviceRequest, Rule, request_json, rule_code

Profile = Literal["pq_hybrid", "pq_pure"]


def _path(path: str | os.PathLike[str]) -> bytes:
    return os.fsencode(path)


class NodeKey:
    """A node key. Free it with free(), or let it be collected."""

    def __init__(self, handle: int) -> None:
        self._handle: int | None = handle
        self._finalizer = weakref.finalize(self, native().call, "macula_key_free", handle)

    @classmethod
    async def generate(cls, profile: Profile = "pq_hybrid") -> NodeKey:
        """A new key whose node_id solves the admission puzzle; takes a second
        or so, off the event loop, and is cancellable."""
        n = native()
        return cls(
            await run_blocking(
                lambda c: n.invoke("macula_key_generate", profile.encode(), c),
                n.cancels,
                discard=lambda h: n.call("macula_key_free", h),
            )
        )

    @classmethod
    def load(cls, path: str | os.PathLike[str], profile: Profile = "pq_hybrid") -> NodeKey:
        """The key in the key file at path. A file its group or others can
        read, or holding a key of another profile, is refused."""
        return cls(native().invoke("macula_key_load", _path(path), profile.encode()))

    @classmethod
    async def load_or_create(cls, path: str | os.PathLike[str], profile: Profile = "pq_hybrid") -> NodeKey:
        """The key at path, or a new one saved there when the file does not exist."""
        n = native()
        return cls(
            await run_blocking(
                lambda c: n.invoke("macula_key_load_or_create", _path(path), profile.encode(), c),
                n.cancels,
                discard=lambda h: n.call("macula_key_free", h),
            )
        )

    def save(self, path: str | os.PathLike[str]) -> None:
        """Writes the key to path, readable by its owner only."""
        native().invoke("macula_key_save", self._live(), _path(path))

    def node_id(self) -> bytes:
        """The key's 32-byte node_id."""
        out = ctypes.create_string_buffer(32)
        native().invoke("macula_key_node_id", self._live(), out)
        return out.raw

    def node_id_hex(self) -> str:
        """The node_id as lowercase hex."""
        return self.node_id().hex()

    def public_key(self) -> bytes:
        """The public key as carried on the wire."""
        n = native()
        length = ctypes.c_size_t()
        return n.take_bytes(n.invoke("macula_key_public_key", self._live(), ctypes.byref(length)), length.value)

    def profile(self) -> Profile:
        """The key's profile."""
        n = native()
        return n.take_string(n.invoke("macula_key_profile", self._live()))  # type: ignore[return-value]

    def sign(self, data: bytes) -> bytes:
        """Signs data as given."""
        n = native()
        length = ctypes.c_size_t()
        address = n.invoke("macula_key_sign", self._live(), data, len(data), ctypes.byref(length))
        return n.take_bytes(address, length.value)

    @staticmethod
    def verify(data: bytes, signature: bytes, public_key: bytes, profile: Profile = "pq_hybrid") -> bool:
        """Whether signature is valid over data for a public key as carried on
        the wire, under profile: ML-DSA-87 in pq_pure, and in pq_hybrid the
        LAMPS composite id-MLDSA87-RSA4096-PSS-SHA512 with the empty context,
        both halves verified. Anything malformed is False."""
        valid = native().invoke(
            "macula_verify",
            data,
            len(data),
            signature,
            len(signature),
            public_key,
            len(public_key),
            profile.encode(),
        )
        return valid == 1

    def ucan(
        self,
        audience: Id,
        capabilities: Sequence[Mapping[str, str]],
        *,
        exp: int,
        nbf: int | None = None,
        nnc: str | None = None,
        fct: Mapping[str, Any] | None = None,
        prf: Sequence[str] = (),
    ) -> str:
        """A UCAN (macula 12, D7) from this identity key for the node
        ``audience`` (its node_id), which alone can present it, granting each
        capability ``{"with": <MRI>, "can": <action>}`` until ``exp`` (Unix
        seconds). ``prf`` names the parent it is delegated from, by
        macula_py.ucan.proof_id: at most one. See macula_py.ucan."""
        caps = []
        for cap in capabilities:
            if set(cap) != {"with", "can"}:
                raise ValueError('macula-py: a capability is {"with": <MRI>, "can": <action>}')
            caps.append({"with": cap["with"], "can": cap["can"]})
        options: dict[str, Any] = {}
        for name, value in (("nbf", nbf), ("nnc", nnc), ("fct", None if fct is None else dict(fct))):
            if value is not None:
                options[name] = value
        if prf:
            options["prf"] = list(prf)
        n = native()
        return n.take_string(  # type: ignore[return-value]
            n.invoke(
                "macula_ucan_create",
                self._live(),
                id32(audience, "the audience's node_id"),
                json.dumps(caps).encode(),
                exp,
                json.dumps(options).encode() if options else None,
            )
        )

    def device_request_proof(self, realm: Id, procedure: str, request: DeviceRequest, rule: Rule) -> dict:
        """A realm proof v2 that this key made request for procedure in realm,
        now, with a fresh nonce: ``{"v": 2, "timestamp", "nonce",
        "signature"}``, sent beside the request's ``public_key``. rule is
        "http" (a join session's body, under the realm's JSON rule; a str is
        the body exactly as sent) or "mesh" (a mesh payload). A request with a
        "caller" field is refused. See macula_py.device_request."""
        n = native()
        text = n.take_string(
            n.invoke(
                "macula_key_device_request_proof",
                self._live(),
                id32(realm, "realm"),
                procedure.encode(),
                request_json(request, rule),
                rule_code(rule),
            )
        )
        return json.loads(text or "null")

    def ownership_proof(self, realm: Id, procedure: str, payload: Mapping[str, Any]) -> dict:
        """payload with an ``asserted_by`` block by which this key's node
        authorises its other fields for procedure in realm, now, with a fresh
        nonce; an earlier block is replaced. Send the result as the payload.
        A payload carrying "caller" is refused. See macula_py.ownership_proof."""
        n = native()
        text = n.take_string(
            n.invoke(
                "macula_key_ownership_proof",
                self._live(),
                id32(realm, "realm"),
                procedure.encode(),
                encode_payload(dict(payload)).encode(),
            )
        )
        return decode_payload(text or "null")  # type: ignore[return-value]

    def free(self) -> None:
        """Frees the native key. The NodeKey is unusable after."""
        self._handle = None
        self._finalizer()

    def _live(self) -> int:
        if self._handle is None:
            raise ClosedError("macula-py: this NodeKey was freed")
        return self._handle

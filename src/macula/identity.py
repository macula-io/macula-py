"""Ed25519 identities and the S/Kademlia crypto puzzle.

Ports ``macula_identity.erl`` (macula-io/macula, src/identity/). A Macula
NodeId is an Ed25519 public key (32 bytes). Identities are puzzle-hardened
by default: the pubkey's SHA-256 hash must have at least ``difficulty``
leading zero bits (S/Kademlia Sybil defence). Every station checks this on
every CONNECT, for every kind of dialer -- an unhardened identity's QUIC/TLS
handshake still completes and its application-layer HELLO is silently
refused, which looks like a healthy connection that delivers nothing (the
real incident every sibling SDK's own identity module documents). Grinding
at the default difficulty is sub-millisecond, so ``generate()`` grinds by
default rather than exposing an unhardened shortcut nothing would use in
practice -- matching every other Macula SDK's own public API exactly.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)

DEFAULT_PUZZLE_DIFFICULTY = 8
_KEY_FILE_MAGIC = b"macula-v2-key\x00"
_SEED_SIZE = 32


class LoadKeyError(Exception):
    """Raised by :func:`KeyPair.load` when the file isn't a key file this module wrote."""


@dataclass(frozen=True)
class KeyPair:
    """A Macula peer identity: an Ed25519 keypair whose public key (NodeId)
    satisfies the puzzle difficulty it was minted for.
    """

    _private: Ed25519PrivateKey
    _public: Ed25519PublicKey

    def node_id(self) -> bytes:
        """The 32-byte Ed25519 public key this identity is known by on the wire (CONNECT/HELLO's node_id field)."""
        return self._public.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def public_bytes(self) -> bytes:
        return self.node_id()

    def _private_bytes(self) -> bytes:
        return self._private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def puzzle_evidence(self) -> bytes:
        """SHA-256(NodeId) -- carried in every CONNECT frame's puzzle_evidence field.

        A property of the identity, computed once -- never per connection.
        """
        return hashlib.sha256(self.node_id()).digest()

    def has_valid_puzzle(self, difficulty: int = DEFAULT_PUZZLE_DIFFICULTY) -> bool:
        """Whether this identity's puzzle_evidence has at least `difficulty` leading zero bits.

        The same check every station runs on CONNECT (macula_identity:puzzle_valid/2).
        """
        return _leading_zero_bits(self.puzzle_evidence()) >= difficulty

    def sign(self, data: bytes) -> bytes:
        """Raw Ed25519 signature over `data` -- 64 bytes. Callers add domain separation (frame/record envelopes), not this layer."""
        return self._private.sign(data)

    @staticmethod
    def verify(node_id: bytes, data: bytes, sig: bytes) -> bool:
        """Whether `sig` is a valid Ed25519 signature over `data` by the identity whose public key is `node_id`."""
        if len(node_id) != _SEED_SIZE:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(node_id).verify(sig, data)
            return True
        except Exception:
            return False

    @staticmethod
    def generate(*, puzzle: bool = True, difficulty: int = DEFAULT_PUZZLE_DIFFICULTY) -> "KeyPair":
        """Mint a fresh identity. Puzzle-hardened by default -- see this module's own doc for why an unhardened identity is a silent failure mode, not a shortcut."""
        while True:
            private = Ed25519PrivateKey.generate()
            public = private.public_key()
            kp = KeyPair(private, public)
            if not puzzle or kp.has_valid_puzzle(difficulty):
                return kp

    @staticmethod
    def from_seed(seed: bytes) -> "KeyPair":
        """Reconstruct a KeyPair from a 32-byte Ed25519 seed directly (no file I/O, no puzzle check) -- for tests and callers with their own key storage."""
        if len(seed) != _SEED_SIZE:
            raise ValueError(f"identity: from_seed: seed is {len(seed)} bytes, want {_SEED_SIZE}")
        private = Ed25519PrivateKey.from_private_bytes(seed)
        return KeyPair(private, private.public_key())

    def save(self, path: str | os.PathLike) -> None:
        """Persist this keypair to `path` atomically (write-tmp + rename), 0600 permissions.

        Format matches macula_identity:save/2's own key file exactly:
        the ``macula-v2-key\\0`` magic, then the 32-byte public key, then
        the 32-byte private seed.
        """
        path = Path(path)
        blob = _KEY_FILE_MAGIC + self.node_id() + self._private_bytes()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, blob)
        finally:
            os.close(fd)
        os.replace(tmp, path)

    @staticmethod
    def load(path: str | os.PathLike) -> "KeyPair":
        """Load a keypair previously written by :meth:`save`."""
        blob = Path(path).read_bytes()
        magic_len = len(_KEY_FILE_MAGIC)
        expected_len = magic_len + _SEED_SIZE + _SEED_SIZE
        if len(blob) != expected_len or blob[:magic_len] != _KEY_FILE_MAGIC:
            raise LoadKeyError("key file has the wrong magic header or length")
        public_bytes = blob[magic_len : magic_len + _SEED_SIZE]
        private_bytes = blob[magic_len + _SEED_SIZE :]
        kp = KeyPair.from_seed(private_bytes)
        if kp.node_id() != public_bytes:
            raise LoadKeyError("key file's stored public key does not match its private seed")
        return kp


def _leading_zero_bits(digest: bytes) -> int:
    n = 0
    for byte in digest:
        if byte == 0:
            n += 8
            continue
        mask = 0x80
        while mask:
            if byte & mask:
                return n
            n += 1
            mask >>= 1
    return n

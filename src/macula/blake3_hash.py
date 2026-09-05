"""BLAKE3 content-addressing.

Ports the real algorithm ``macula_blake3_nif`` uses (a Rust NIF over the
``blake3`` crate), NOT its pure-Erlang fallback path -- that fallback is
explicitly documented in its own source as "NOT cryptographically
equivalent to BLAKE3" (a SHA-256-based stand-in used only when the NIF
fails to load) and produces output that matches neither real BLAKE3 nor
plain SHA-256. Verified directly against the real NIF, not assumed
correct because the package name matches: ``blake3.blake3(b"macula")``
produces the identical 32-byte digest ``macula_blake3_nif:hash(<<"macula">>)``
does when run against the actual compiled NIF (see
``tests/test_blake3_hash.py``'s golden vectors).
"""

from __future__ import annotations

import blake3 as _blake3

DIGEST_SIZE = 32


def hash_bytes(data: bytes) -> bytes:
    """BLAKE3(`data`) -- a 32-byte digest."""
    return _blake3.blake3(data).digest()


def hash_hex(data: bytes) -> str:
    """BLAKE3(`data`), lowercase hex-encoded."""
    return _blake3.blake3(data).hexdigest()


def verify(data: bytes, expected_hash: bytes) -> bool:
    """Whether `data` hashes to `expected_hash` under BLAKE3."""
    return hash_bytes(data) == expected_hash

"""Fixed-size chunking, Merkle-root computation, and manifest construction
for content larger than one storage block.

Ports ``macula_manifest.erl`` (macula-io/macula, src/content/) exactly --
same MCID format, same default chunk size (256 KiB), same Merkle fold,
same canonical-CBOR MCID derivation, same manifest wire shape. This is
deliberate, not incidental: the SDK puts a manifest via the station's
existing ``_content.put_manifest``/``_content.get_manifest`` RPCs, so the
two sides must agree on the algorithm bit-for-bit.

MCID format (34 bytes): ``<Version:1><Codec:1><Hash:32>``. ``CODEC_RAW``
(0x55) addresses a single chunk (or a whole blob that fits in one chunk).
``CODEC_MANIFEST`` (0x56) addresses a manifest describing many chunks.

Manifest map keys are plain Python `str` (matching how Erlang's own atom
field names -- name, size, chunk_size, etc. -- encode as CBOR text
strings on this wire; no separate to_wire/from_wire encoding step is
needed the way Erlang needs one to bridge atoms/binaries, since a Python
dict with str keys already IS this wire's shape).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from . import blake3_hash, cbor

VERSION = 1
CODEC_RAW = 0x55
CODEC_MANIFEST = 0x56
DEFAULT_CHUNK_SIZE = 262144
MCID_SIZE = 34


class InvalidMcidError(Exception):
    pass


class ManifestVerifyError(Exception):
    pass


class InvalidManifestError(Exception):
    pass


def _hash(algorithm: str, data: bytes) -> bytes:
    if algorithm == "blake3":
        return blake3_hash.hash_bytes(data)
    if algorithm == "sha256":
        import hashlib

        return hashlib.sha256(data).digest()
    raise ValueError(f"unsupported hash_algorithm {algorithm!r}")


def make_mcid(codec: int, digest: bytes) -> bytes:
    if len(digest) != 32:
        raise ValueError(f"digest must be 32 bytes, got {len(digest)}")
    return bytes([VERSION, codec]) + digest


def block_mcid(data: bytes, *, algorithm: str = "blake3") -> bytes:
    """The MCID a single block (or a whole blob that fits in one chunk) is addressed by."""
    return make_mcid(CODEC_RAW, _hash(algorithm, data))


def is_chunked(mcid: bytes) -> bool:
    if len(mcid) != MCID_SIZE:
        raise InvalidMcidError(f"MCID must be {MCID_SIZE} bytes, got {len(mcid)}")
    return mcid[1] == CODEC_MANIFEST


def verify_block_hash(mcid: bytes, data: bytes, *, algorithm: str = "blake3") -> None:
    """Raise InvalidMcidError/ManifestVerifyError if `data` doesn't hash to `mcid`.

    The station verified this block's hash at PUT time; a station fetched
    FROM is not necessarily the one that stored it, so re-verify
    client-side rather than trusting whoever answered.
    """
    if len(mcid) != MCID_SIZE or mcid[0] != VERSION or mcid[1] != CODEC_RAW:
        raise InvalidMcidError("not a valid single-block MCID")
    if _hash(algorithm, data) != mcid[2:]:
        raise ManifestVerifyError("fetched content does not hash to its MCID")


def _chunk_data(data: bytes, chunk_size: int) -> list[bytes]:
    if not data:
        return []
    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


def _chunk_infos(chunks: list[bytes], algorithm: str) -> list[dict]:
    infos = []
    offset = 0
    for index, chunk in enumerate(chunks):
        infos.append({"index": index, "offset": offset, "size": len(chunk), "hash": _hash(algorithm, chunk)})
        offset += len(chunk)
    return infos


def _root_hash_for(infos: list[dict], algorithm: str) -> bytes:
    if not infos:
        return _hash(algorithm, b"")
    hashes = [info["hash"] for info in infos]
    while len(hashes) > 1:
        hashes = _combine_pairs(hashes, algorithm)
    return hashes[0]


def _combine_pairs(hashes: list[bytes], algorithm: str) -> list[bytes]:
    out = []
    i = 0
    while i + 1 < len(hashes):
        out.append(_hash(algorithm, hashes[i] + hashes[i + 1]))
        i += 2
    if i < len(hashes):
        # Odd count -- pair the last hash with itself (V1 convention).
        last = hashes[i]
        out.append(_hash(algorithm, last + last))
    return out


def _compute_manifest_mcid(body: dict, algorithm: str) -> bytes:
    """Deterministic canonical encoding -- excludes `created` (timestamp) and `chunks` (already rolled up into root_hash), matching the station's exact field set and key order."""
    canonical = {
        "name": body["name"],
        "size": body["size"],
        "chunk_size": body["chunk_size"],
        "chunk_count": body["chunk_count"],
        "hash_algorithm": algorithm,
        "root_hash": body["root_hash"],
    }
    return make_mcid(CODEC_MANIFEST, _hash(algorithm, cbor.encode(canonical)))


def create(data: bytes, *, name: str = "unnamed", chunk_size: int = DEFAULT_CHUNK_SIZE, algorithm: str = "blake3") -> tuple[dict, list[bytes]]:
    """Split `data` into fixed-size chunks and build its manifest.

    Returns (manifest, chunks) -- chunks in order (index 0 first), so a
    caller can upload each chunk (via _content.put_block) and then the
    manifest (via _content.put_manifest).
    """
    chunks = _chunk_data(data, chunk_size)
    chunk_infos = _chunk_infos(chunks, algorithm)
    root_hash = _root_hash_for(chunk_infos, algorithm)

    body = {
        "version": VERSION,
        "name": name,
        "size": len(data),
        "created": int(time.time()),
        "chunk_size": chunk_size,
        "chunk_count": len(chunk_infos),
        "hash_algorithm": algorithm,
        "root_hash": root_hash,
        "chunks": chunk_infos,
    }
    manifest = {**body, "mcid": _compute_manifest_mcid(body, algorithm)}
    return manifest, chunks


def chunk_mcid(manifest: dict, index: int) -> bytes:
    """The MCID a chunk at `index` is stored/fetched under. The station derives this same value independently when serving the chunk, so both sides agree on its address without exchanging it."""
    chunks = manifest["chunks"]
    if not (0 <= index < len(chunks)):
        raise IndexError(f"chunk index {index} out of range for {len(chunks)} chunks")
    return make_mcid(CODEC_RAW, chunks[index]["hash"])


def verify(manifest: dict, data: bytes) -> None:
    """Verify reassembled `data` against `manifest`: size, then a fresh Merkle root over `data` re-chunked the same way. Raises ManifestVerifyError."""
    if len(data) != manifest["size"]:
        raise ManifestVerifyError("size_mismatch")
    algorithm = manifest["hash_algorithm"]
    chunks = _chunk_data(data, manifest["chunk_size"])
    infos = _chunk_infos(chunks, algorithm)
    actual = _root_hash_for(infos, algorithm)
    if actual != manifest["root_hash"]:
        raise ManifestVerifyError("root_hash_mismatch")


_DEFAULTS = {
    "version": 1,
    "name": "unnamed",
    "size": 0,
    "created": 0,
    "chunk_size": DEFAULT_CHUNK_SIZE,
    "chunk_count": 0,
    "hash_algorithm": "blake3",
    "root_hash": b"",
}


def from_wire(value: cbor.Value) -> dict:
    """Read a manifest as it arrives over _content.get_manifest.

    Rejects a non-positive `chunk_size` and a `chunk_count` that doesn't
    match the actual `chunks` list length here, at the parse boundary --
    not later, wherever they happen to first matter. Left unvalidated,
    `chunk_size<=0` reaches `verify()`'s `range(0, len(data), chunk_size)`
    (a bare `ValueError`, not this module's own error type) only after
    every chunk has already been fetched and hash-verified, and an
    over-claimed `chunk_count` reaches `content.get()`'s fetch loop and
    `chunk_mcid()`'s bounds check as a bare `IndexError`, mid-fetch --
    both leak an undocumented exception type through this library's
    `InvalidManifestError`/`ManifestVerifyError` contract instead of
    failing fast and cleanly on a manifest that was never usable to
    begin with. Same defect class the Rust reference (macula-io/macula-rust,
    src/manifest.rs) fixed today at its own `from_wire` parse boundary --
    lower severity here (no process crash; Python's exception model
    isn't Rust's panic-aborts-the-process one), but the same "validate
    untrusted-peer fields where they're parsed, not where they happen to
    blow up" fix.
    """
    if not isinstance(value, dict) or "mcid" not in value or not isinstance(value.get("chunks"), list):
        raise InvalidManifestError("not a valid manifest map")
    manifest = {"mcid": value["mcid"]}
    for key, default in _DEFAULTS.items():
        manifest[key] = value.get(key, default)
    manifest["chunks"] = [_chunk_info_from_wire(c) for c in value["chunks"]]
    if not isinstance(manifest["chunk_size"], int) or manifest["chunk_size"] <= 0:
        raise InvalidManifestError(f"chunk_size must be a positive integer, got {manifest['chunk_size']!r}")
    if not isinstance(manifest["chunk_count"], int):
        # A float that happens to equal len(chunks) (e.g. 1.0 == 1) would
        # pass the mismatch check below and only fail later, inside
        # content.get()'s `range(chunk_count)` -- a bare TypeError, the
        # same leaky-exception shape this function exists to close.
        raise InvalidManifestError(f"chunk_count must be an integer, got {manifest['chunk_count']!r}")
    if manifest["chunk_count"] != len(manifest["chunks"]):
        raise InvalidManifestError(
            f"chunk_count ({manifest['chunk_count']!r}) does not match the actual "
            f"number of chunk entries ({len(manifest['chunks'])})"
        )
    # Unrecognized algorithm coerces to blake3, not an error -- matching
    # the two reference implementations exactly (macula_manifest.erl's
    # to_algorithm/1, manifest.rs's Algorithm::from_name), not inventing
    # new strictness. Left unhandled, an unrecognized value only failed
    # inside verify()'s _hash() call, after every chunk had already been
    # fetched -- the same leaky-exception shape as the other two checks
    # in this function.
    if manifest["hash_algorithm"] not in ("blake3", "sha256"):
        manifest["hash_algorithm"] = "blake3"
    return manifest


def _chunk_info_from_wire(value: cbor.Value) -> dict:
    if not isinstance(value, dict):
        raise InvalidManifestError("chunk entry is not a map")
    chunk_hash = value.get("hash")
    if not isinstance(chunk_hash, bytes) or len(chunk_hash) != 32:
        # Reachable at index 0 of content.get()'s fetch loop, before any
        # chunk is fetched: chunk_mcid() -> make_mcid() does `bytes(...)
        # + digest`, raising a bare TypeError/ValueError for a wrong
        # type or length -- not this module's own error type, and not
        # even gated behind chunk_count being wrong. A missing `hash`
        # must be rejected here too, not defaulted to b"" (guaranteed to
        # fail the same way, just deferred).
        raise InvalidManifestError(f"chunk hash must be 32 bytes, got {chunk_hash!r}")
    return {
        "index": value.get("index", 0),
        "offset": value.get("offset", 0),
        "size": value.get("size", 0),
        "hash": chunk_hash,
    }

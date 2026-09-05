"""Content sharing: put/get by content-address, over a dedicated QUIC
stream -- ordinary CALL/RESULT against four well-known ``_content.*``
procedures, ported from ``macula_content_transfer.erl``. Not a separate
wire protocol: nothing here is new frame types.

Deliberate v1 simplification (matching every sibling SDK): chunked
transfers run strictly sequentially, one ``_content.put_block``/
``_content.get_block`` in flight at a time on the single dedicated
stream this opens -- not the reference's parallel multi-lane algorithm.
Multi-lane parallelism is a throughput optimization, not a correctness
requirement: every ``_content.*`` call, the MCID scheme, and the
manifest wire format are identical either way.
"""

from __future__ import annotations

import asyncio

from . import bolt4, frame, manifest
from .connection import Session

#: Reserved realm sentinel for all _content.* calls -- 32 zero bytes, distinct from any real realm.
CONTENT_REALM = bytes(32)

_PUT_BLOCK_PROC = "_content.put_block"
_GET_BLOCK_PROC = "_content.get_block"
_PUT_MANIFEST_PROC = "_content.put_manifest"
_GET_MANIFEST_PROC = "_content.get_manifest"

_BLOCK_TIMEOUT = 15.0
_MANIFEST_TIMEOUT = 5.0
_MAX_ATTEMPTS = 3
_RETRY_BACKOFF = 0.2


class ContentTransferError(Exception):
    def __init__(self, reason: str, message: str, *, code: int | None = None, name: str | None = None, detail: str | None = None):
        super().__init__(message)
        self.reason = reason
        self.code = code
        self.name = name
        self.detail = detail


async def put(session: Session, data: bytes, *, name: str = "unnamed") -> bytes:
    """Store `data`, returning the MCID it's now addressable by. `name` is attached to the manifest when data is large enough to be chunked; a single block is addressed purely by content hash and carries no name at all."""
    reader, writer = await session.open_dedicated_stream()
    try:
        if len(data) <= manifest.DEFAULT_CHUNK_SIZE:
            mcid = manifest.block_mcid(data)
            await _put_block(session, writer, reader, mcid, data)
            return mcid

        built, chunks = manifest.create(data, name=name)
        for index, chunk in enumerate(chunks):
            chunk_mcid = manifest.chunk_mcid(built, index)
            await _put_block(session, writer, reader, chunk_mcid, chunk)
        await _put_manifest(session, writer, reader, built)
        return built["mcid"]
    finally:
        writer.close()


async def get(session: Session, mcid: bytes) -> bytes:
    """Fetch and verify the content addressed by `mcid`."""
    reader, writer = await session.open_dedicated_stream()
    try:
        if not manifest.is_chunked(mcid):
            data = await _get_block(session, writer, reader, mcid)
            manifest.verify_block_hash(mcid, data)
            return data

        the_manifest = await _get_manifest(session, writer, reader, mcid)
        pieces = []
        for index in range(the_manifest["chunk_count"]):
            chunk_mcid = manifest.chunk_mcid(the_manifest, index)
            chunk = await _get_block(session, writer, reader, chunk_mcid)
            manifest.verify_block_hash(chunk_mcid, chunk)
            pieces.append(chunk)
        data = b"".join(pieces)
        manifest.verify(the_manifest, data)
        return data
    finally:
        writer.close()


async def _put_block(session: Session, writer, reader, mcid: bytes, data: bytes) -> None:
    payload = {"mcid": mcid, "payload": data}
    response = await _call_with_retry(session, writer, reader, _PUT_BLOCK_PROC, payload, _BLOCK_TIMEOUT)
    if isinstance(response, frame.CallResult) and response.payload == "ok":
        return
    if isinstance(response, frame.CallResult) and response.payload == "hash_mismatch":
        raise ContentTransferError("hash_mismatch", "station reported hash_mismatch")
    _raise_for_unexpected_or_error(response, "put_block")


async def _get_block(session: Session, writer, reader, mcid: bytes) -> bytes:
    payload = {"mcid": mcid}
    response = await _call_with_retry(session, writer, reader, _GET_BLOCK_PROC, payload, _BLOCK_TIMEOUT)
    if isinstance(response, frame.CallResult) and isinstance(response.payload, bytes):
        return response.payload
    if isinstance(response, frame.CallResult) and response.payload == "not_found":
        raise ContentTransferError("not_found", "station reported not_found")
    _raise_for_unexpected_or_error(response, "get_block")


async def _put_manifest(session: Session, writer, reader, built_manifest: dict) -> None:
    payload = {"manifest": built_manifest}
    response = await _call_with_retry(session, writer, reader, _PUT_MANIFEST_PROC, payload, _MANIFEST_TIMEOUT)
    if isinstance(response, frame.CallResult) and response.payload == "ok":
        return
    _raise_for_unexpected_or_error(response, "put_manifest")


async def _get_manifest(session: Session, writer, reader, mcid: bytes) -> dict:
    payload = {"mcid": mcid}
    response = await _call_with_retry(session, writer, reader, _GET_MANIFEST_PROC, payload, _MANIFEST_TIMEOUT)
    if isinstance(response, frame.CallResult) and isinstance(response.payload, dict):
        try:
            return manifest.from_wire(response.payload)
        except manifest.InvalidManifestError as e:
            raise ContentTransferError("manifest_decode_failed", f"decoding the fetched manifest: {e}") from e
    if isinstance(response, frame.CallResult) and response.payload == "not_found":
        raise ContentTransferError("not_found", "station reported not_found")
    _raise_for_unexpected_or_error(response, "get_manifest")


def _raise_for_unexpected_or_error(response: frame.CallResponse, procedure: str):
    if isinstance(response, frame.CallError):
        raise ContentTransferError(
            "remote_error",
            f"station returned error {response.code} ({response.name}): {response.detail}",
            code=response.code,
            name=response.name,
            detail=response.detail,
        )
    raise ContentTransferError("unexpected_reply", f"unexpected reply shape for {procedure}")


async def _call_with_retry(session: Session, writer, reader, procedure: str, payload, timeout: float) -> frame.CallResponse:
    """Send one _content.* CALL, retrying: up to _MAX_ATTEMPTS total, _RETRY_BACKOFF between them, only when the prior attempt's ERROR carries a BOLT#4 code flagged retryable. A non-retryable ERROR, or a RESULT (whatever its payload turns out to mean to the caller), both return on the first attempt."""
    attempt = 1
    while True:
        deadline_ms = frame.current_millis() + int(timeout * 1000)
        outcome = await session.call_on_stream(writer, reader, procedure, CONTENT_REALM, payload, deadline_ms, timeout)
        should_retry = attempt < _MAX_ATTEMPTS and isinstance(outcome, frame.CallError) and bolt4.is_retryable(outcome.code)
        if not should_retry:
            return outcome
        await asyncio.sleep(_RETRY_BACKOFF)
        attempt += 1

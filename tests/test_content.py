"""Offline tests for the _content.* orchestration logic: retry policy,
response-to-outcome mapping, and put()/get() chunking decisions --
using a fake Session that returns canned CallResult/CallError values
instead of a real QUIC connection.
"""

import pytest

from macula import bolt4, content, frame, manifest


class _FakeStream:
    """Stands in for the reader/writer pair open_dedicated_stream returns.
    call_on_stream is mocked directly on FakeSession and never touches
    these, except for the writer.close() every put()/get() call runs in
    its `finally` block."""

    def close(self):
        pass


class FakeSession:
    """Stands in for a real Session: records each call_on_stream
    invocation and returns responses from a pre-loaded queue (one per
    procedure, consumed in order)."""

    def __init__(self):
        self.responses: dict[str, list[frame.CallResponse]] = {}
        self.calls: list[tuple[str, object]] = []

    def queue(self, procedure: str, response: frame.CallResponse):
        self.responses.setdefault(procedure, []).append(response)

    async def open_dedicated_stream(self):
        return _FakeStream(), _FakeStream()

    async def call_on_stream(self, writer, reader, procedure, realm, payload, deadline_ms, timeout):
        self.calls.append((procedure, payload))
        return self.responses[procedure].pop(0)


def _result(payload):
    return frame.CallResult(payload=payload, responded_by=bytes(32))


def _error(code):
    return frame.CallError(
        code=code,
        name=bolt4.name_for_code(code),
        reported_by=bytes(32),
        detail=None,
    )


async def test_put_of_small_data_sends_a_single_put_block_and_returns_its_mcid():
    session = FakeSession()
    session.queue(content._PUT_BLOCK_PROC, _result("ok"))

    data = b"small enough to fit in one block"
    mcid = await content.put(session, data)

    assert mcid == manifest.block_mcid(data)
    assert len(session.calls) == 1
    assert session.calls[0][0] == content._PUT_BLOCK_PROC
    assert session.calls[0][1] == {"mcid": mcid, "payload": data}


async def test_put_of_large_data_sends_one_put_block_per_chunk_then_a_put_manifest():
    session = FakeSession()
    data = b"x" * (manifest.DEFAULT_CHUNK_SIZE * 2 + 10)
    built, chunks = manifest.create(data)
    for _ in chunks:
        session.queue(content._PUT_BLOCK_PROC, _result("ok"))
    session.queue(content._PUT_MANIFEST_PROC, _result("ok"))

    mcid = await content.put(session, data)

    assert mcid == built["mcid"]
    procs = [c[0] for c in session.calls]
    assert procs == [content._PUT_BLOCK_PROC] * len(chunks) + [content._PUT_MANIFEST_PROC]


async def test_put_block_raises_hash_mismatch_when_the_station_reports_it():
    session = FakeSession()
    session.queue(content._PUT_BLOCK_PROC, _result("hash_mismatch"))

    with pytest.raises(content.ContentTransferError) as exc_info:
        await content.put(session, b"anything")
    assert exc_info.value.reason == "hash_mismatch"


async def test_get_of_a_single_block_verifies_and_returns_the_data():
    session = FakeSession()
    data = b"round trip me"
    mcid = manifest.block_mcid(data)
    session.queue(content._GET_BLOCK_PROC, _result(data))

    fetched = await content.get(session, mcid)
    assert fetched == data


async def test_get_of_a_single_block_raises_not_found():
    session = FakeSession()
    mcid = manifest.make_mcid(manifest.CODEC_RAW, bytes(32))
    session.queue(content._GET_BLOCK_PROC, _result("not_found"))

    with pytest.raises(content.ContentTransferError) as exc_info:
        await content.get(session, mcid)
    assert exc_info.value.reason == "not_found"


async def test_get_of_chunked_content_fetches_the_manifest_then_each_chunk():
    session = FakeSession()
    data = b"y" * (manifest.DEFAULT_CHUNK_SIZE + 500)
    built, chunks = manifest.create(data)
    session.queue(content._GET_MANIFEST_PROC, _result(built))
    for chunk in chunks:
        session.queue(content._GET_BLOCK_PROC, _result(chunk))

    fetched = await content.get(session, built["mcid"])
    assert fetched == data


async def test_call_with_retry_retries_a_retryable_error_then_succeeds():
    session = FakeSession()
    session.queue(content._PUT_BLOCK_PROC, _error(bolt4.TEMPORARY_RELAY_FAILURE))
    session.queue(content._PUT_BLOCK_PROC, _result("ok"))

    await content.put(session, b"retry me")
    assert len(session.calls) == 2


async def test_call_with_retry_does_not_retry_a_non_retryable_error():
    session = FakeSession()
    session.queue(content._PUT_BLOCK_PROC, _error(bolt4.UNAUTHORIZED))

    with pytest.raises(content.ContentTransferError) as exc_info:
        await content.put(session, b"forbidden")
    assert exc_info.value.reason == "remote_error"
    assert exc_info.value.code == bolt4.UNAUTHORIZED
    assert len(session.calls) == 1


async def test_call_with_retry_gives_up_after_max_attempts():
    session = FakeSession()
    for _ in range(content._MAX_ATTEMPTS):
        session.queue(content._PUT_BLOCK_PROC, _error(bolt4.TEMPORARY_RELAY_FAILURE))

    with pytest.raises(content.ContentTransferError):
        await content.put(session, b"never works")
    assert len(session.calls) == content._MAX_ATTEMPTS


async def test_get_manifest_raises_on_an_undecodable_manifest_payload():
    session = FakeSession()
    mcid = manifest.make_mcid(manifest.CODEC_MANIFEST, bytes(32))
    session.queue(content._GET_MANIFEST_PROC, _result({"chunks": []}))  # no mcid

    with pytest.raises(content.ContentTransferError) as exc_info:
        await content.get(session, mcid)
    assert exc_info.value.reason == "manifest_decode_failed"


async def test_unexpected_reply_shape_raises():
    session = FakeSession()
    session.queue(content._PUT_BLOCK_PROC, _result(12345))  # not "ok" or "hash_mismatch"

    with pytest.raises(content.ContentTransferError) as exc_info:
        await content.put(session, b"weird reply")
    assert exc_info.value.reason == "unexpected_reply"

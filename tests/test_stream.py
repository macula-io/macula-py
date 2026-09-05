"""Offline tests for streaming RPC (macula_py.connection.StreamHandle,
Session.open_stream, Session.accept_stream) -- a real asyncio.StreamReader
fed pre-encoded frames, and a minimal fake writer capturing what gets
written, so these exercise the actual sign/encode/parse code paths
without a live QUIC connection.
"""

import asyncio

import pytest

from macula_py import frame
from macula_py.connection import Session, StreamHandle
from macula_py.identity import KeyPair


class FakeWriter:
    def __init__(self):
        self.chunks: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.chunks.append(data)

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    def decoded_frames(self) -> list[dict]:
        buf = b"".join(self.chunks)
        out = []
        while buf:
            decoded = frame.decode_frame(buf)
            assert decoded.complete
            out.append(decoded.frame)
            buf = buf[decoded.consumed :]
        return out


def _reader_with(*frames: dict) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    for f in frames:
        reader.feed_data(frame.encode_frame(f))
    return reader


def _handle(identity: KeyPair | None = None, mode: str = "server_stream") -> tuple[StreamHandle, FakeWriter]:
    identity = identity or KeyPair.generate(puzzle=False)
    session = Session(
        identity=identity,
        remote_info=None,
        _protocol=None,
        _reader=None,
        _writer=None,
        _connect_cm=None,
        _incoming_streams=asyncio.Queue(),
    )
    writer = FakeWriter()
    handle = StreamHandle(session, bytes([5]) * 16, mode, asyncio.StreamReader(), writer)
    return handle, writer


async def test_send_chunk_writes_a_verifiable_signed_stream_data_frame():
    identity = KeyPair.generate(puzzle=False)
    handle, writer = _handle(identity)

    await handle.send_chunk(b"hello")

    sent = writer.decoded_frames()
    assert len(sent) == 1
    frame.verify(sent[0], identity.node_id())
    info = frame.parse_stream_data(sent[0])
    assert info.stream_id == handle.stream_id
    assert info.body == b"hello"
    assert info.seq == 0


async def test_send_chunk_increments_seq_across_calls():
    handle, writer = _handle()
    await handle.send_chunk(b"a")
    await handle.send_chunk(b"b")
    seqs = [frame.parse_stream_data(f).seq for f in writer.decoded_frames()]
    assert seqs == [0, 1]


async def test_recv_parses_a_stream_data_frame():
    handle, _writer = _handle()
    identity = KeyPair.generate(puzzle=False)
    handle._reader = _reader_with(
        frame.sign(frame.build_stream_data(handle.stream_id, 0, b"chunk", identity.node_id()), identity)
    )

    info = await handle.recv()
    assert isinstance(info, frame.StreamDataInfo)
    assert info.body == b"chunk"


async def test_recv_raises_stream_aborted_on_stream_error():
    handle, _writer = _handle()
    identity = KeyPair.generate(puzzle=False)
    handle._reader = _reader_with(
        frame.sign(frame.build_stream_error(handle.stream_id, "boom", "handler crashed", identity.node_id()), identity)
    )

    with pytest.raises(frame.StreamAbortedError) as exc_info:
        await handle.recv()
    assert exc_info.value.code == "boom"


async def test_close_send_writes_stream_end_role_send_and_stays_open_for_recv():
    handle, writer = _handle()
    await handle.close_send()
    info = frame.parse_stream_end(writer.decoded_frames()[0])
    assert info.role == "send"
    assert not writer.closed


async def test_close_writes_stream_end_role_both_and_closes_the_writer():
    handle, writer = _handle()
    await handle.close()
    info = frame.parse_stream_end(writer.decoded_frames()[0])
    assert info.role == "both"
    assert writer.closed


async def test_close_after_close_send_does_not_send_a_second_stream_end():
    handle, writer = _handle()
    await handle.close_send()
    await handle.close()
    assert len(writer.decoded_frames()) == 1
    assert writer.closed


async def test_set_reply_writes_a_stream_reply_with_the_sessions_own_pubkey():
    identity = KeyPair.generate(puzzle=False)
    handle, writer = _handle(identity)
    await handle.set_reply({"total": 3})
    info = frame.parse_stream_reply(writer.decoded_frames()[0])
    assert info.payload == {"total": 3}
    assert info.responded_by == identity.node_id()


async def test_abort_writes_stream_error_and_closes_the_writer():
    handle, writer = _handle()
    await handle.abort("not_found", "procedure not advertised")
    with pytest.raises(frame.StreamAbortedError) as exc_info:
        frame.parse_stream_inbound(writer.decoded_frames()[0])
    assert exc_info.value.code == "not_found"
    assert writer.closed


class FakeProtocol:
    def __init__(self):
        self.writer = FakeWriter()

    async def create_stream(self):
        return asyncio.StreamReader(), self.writer


async def test_open_stream_sends_a_verifiable_signed_stream_open_first():
    identity = KeyPair.generate(puzzle=False)
    protocol = FakeProtocol()
    session = Session(
        identity=identity,
        remote_info=None,
        _protocol=protocol,
        _reader=None,
        _writer=None,
        _connect_cm=None,
        _incoming_streams=asyncio.Queue(),
    )
    realm = bytes([3]) * 32

    handle = await session.open_stream("logs.tail_v1", realm, {"n": 5}, frame.current_millis() + 5000, mode="server_stream")

    sent = protocol.writer.decoded_frames()
    assert len(sent) == 1
    frame.verify(sent[0], identity.node_id())
    info = frame.parse_stream_open(sent[0])
    assert info.stream_id == handle.stream_id
    assert info.procedure == "logs.tail_v1"
    assert info.realm == realm
    assert info.mode == "server_stream"
    assert info.args == {"n": 5}
    assert info.caller == identity.node_id()
    assert handle.mode == "server_stream"


async def test_accept_stream_dispatches_to_the_looked_up_handler():
    identity = KeyPair.generate(puzzle=False)
    caller_identity = KeyPair.generate(puzzle=False)
    session = Session(
        identity=identity,
        remote_info=None,
        _protocol=None,
        _reader=None,
        _writer=None,
        _connect_cm=None,
        _incoming_streams=asyncio.Queue(),
    )
    stream_id = bytes([7]) * 16
    realm = bytes([1]) * 32
    open_frame = frame.sign(
        frame.build_stream_open(stream_id, "logs.tail_v1", realm, "server_stream", {"n": 2}, frame.current_millis() + 5000, caller_identity.node_id()),
        caller_identity,
    )
    reader = _reader_with(open_frame)
    writer = FakeWriter()
    await session._incoming_streams.put((reader, writer))

    seen = {}

    async def handler(handle: StreamHandle, args):
        seen["args"] = args
        await handle.send_chunk(b"one")
        await handle.set_reply("done")

    def lookup(realm_arg, procedure_arg):
        assert realm_arg == realm
        assert procedure_arg == "logs.tail_v1"
        return handler

    await session.accept_stream(lookup)

    assert seen["args"] == {"n": 2}
    sent = writer.decoded_frames()
    assert frame.parse_stream_data(sent[0]).body == b"one"
    assert frame.parse_stream_reply(sent[1]).payload == "done"


async def test_accept_stream_aborts_not_found_for_an_unadvertised_procedure():
    identity = KeyPair.generate(puzzle=False)
    caller_identity = KeyPair.generate(puzzle=False)
    session = Session(
        identity=identity,
        remote_info=None,
        _protocol=None,
        _reader=None,
        _writer=None,
        _connect_cm=None,
        _incoming_streams=asyncio.Queue(),
    )
    open_frame = frame.sign(
        frame.build_stream_open(bytes([8]) * 16, "unknown.proc", bytes(32), "server_stream", None, frame.current_millis() + 5000, caller_identity.node_id()),
        caller_identity,
    )
    writer = FakeWriter()
    await session._incoming_streams.put((_reader_with(open_frame), writer))

    await session.accept_stream(lambda realm, proc: None)

    with pytest.raises(frame.StreamAbortedError) as exc_info:
        frame.parse_stream_inbound(writer.decoded_frames()[0])
    assert exc_info.value.code == "not_found"
    assert writer.closed


async def test_accept_stream_aborts_handler_error_on_a_crashing_handler():
    identity = KeyPair.generate(puzzle=False)
    caller_identity = KeyPair.generate(puzzle=False)
    session = Session(
        identity=identity,
        remote_info=None,
        _protocol=None,
        _reader=None,
        _writer=None,
        _connect_cm=None,
        _incoming_streams=asyncio.Queue(),
    )
    open_frame = frame.sign(
        frame.build_stream_open(bytes([9]) * 16, "crashy.proc", bytes(32), "server_stream", None, frame.current_millis() + 5000, caller_identity.node_id()),
        caller_identity,
    )
    writer = FakeWriter()
    await session._incoming_streams.put((_reader_with(open_frame), writer))

    async def crashy_handler(handle, args):
        raise ValueError("boom")

    await session.accept_stream(lambda realm, proc: crashy_handler)

    with pytest.raises(frame.StreamAbortedError) as exc_info:
        frame.parse_stream_inbound(writer.decoded_frames()[0])
    assert exc_info.value.code == "handler_error"
    assert "boom" in exc_info.value.message

"""A streaming RPC session, opened by this node (Pool.open_stream) or handed
to a stream-serving procedure (Pool.serve_stream).

recv() returns one frame: StreamData, StreamEnd (the peer closed its send
side), StreamReply (the provider's terminal value) or StreamEof (the stream
ended normally); a STREAM_ERROR is raised as StreamError. Iterating a stream
yields every frame up to StreamEof.
"""

from __future__ import annotations

import asyncio
import enum
from dataclasses import dataclass
from typing import Any, Union

from macula_py._blocking import run_blocking
from macula_py._native import native
from macula_py._wire import ClosedError, MaculaError, StreamError, decode_payload, encode_payload


class StreamMode(enum.IntEnum):
    """Who sends: the provider (SERVER), the caller (CLIENT), or both (BIDI)."""

    SERVER = 0
    CLIENT = 1
    BIDI = 2


@dataclass(frozen=True)
class StreamData:
    """A chunk: bytes when sent raw (send), a payload value when sent as one
    (send_value)."""

    body: Any
    encoding: str


@dataclass(frozen=True)
class StreamEnd:
    """The peer closed its send side."""

    role: str


@dataclass(frozen=True)
class StreamReply:
    """The provider's terminal value."""

    payload: Any


@dataclass(frozen=True)
class StreamEof:
    """The stream ended normally."""


StreamFrame = Union[StreamData, StreamEnd, StreamReply, StreamEof]


@dataclass(frozen=True)
class Request:
    """A served call's or stream session's request."""

    caller: str
    realm: str
    procedure: str
    payload: Any
    deadline_ms: int


def request_from(item: dict) -> Request:
    return Request(item["caller"], item["realm"], item["procedure"], item.get("payload"), item["deadline_ms"])


def _frame(item: dict) -> StreamFrame:
    kind = item.get("kind")
    if kind == "data":
        return StreamData(item.get("body"), item.get("encoding", ""))
    if kind == "end":
        return StreamEnd(item.get("role", ""))
    if kind == "reply":
        return StreamReply(item.get("payload"))
    if kind == "eof":
        return StreamEof()
    if kind == "error":
        raise StreamError(str(item.get("code") or ""), str(item.get("message") or ""), item.get("relay") == 1)
    raise MaculaError(f"macula-py: a stream frame of unknown kind {kind!r}")


class Stream:
    """A stream session. Free it (or leave its async with) when done: a
    stream not ended is aborted then."""

    def __init__(self, handle: int, request: Request | None = None) -> None:
        self._handle: int | None = handle
        self.request = request
        """The request that opened it, on a served session; None on one this
        node opened."""

    async def send(self, chunk: bytes) -> None:
        """Sends chunk as raw bytes."""
        await asyncio.to_thread(native().invoke, "macula_stream_send_bytes", self._live(), chunk, len(chunk))

    async def send_value(self, value: Any) -> None:
        """Sends a payload value."""
        await asyncio.to_thread(native().invoke, "macula_stream_send_json", self._live(), encode_payload(value).encode())

    async def close_send(self) -> None:
        """Closes this side's sending; the peer sees StreamEnd."""
        await asyncio.to_thread(native().invoke, "macula_stream_close_send", self._live())

    async def reply(self, payload: Any) -> None:
        """The provider's terminal value."""
        await asyncio.to_thread(native().invoke, "macula_stream_reply", self._live(), encode_payload(payload).encode())

    async def abort(self, code: str, message: str = "") -> None:
        """Ends the stream with a STREAM_ERROR."""
        await asyncio.to_thread(native().invoke, "macula_stream_abort", self._live(), code.encode(), message.encode())

    async def close(self) -> None:
        """Ends the stream normally."""
        await asyncio.to_thread(native().invoke, "macula_stream_close", self._live())

    async def recv(self, timeout_ms: int = 0) -> StreamFrame | None:
        """The next frame, or None when timeout_ms ran out first (0 waits for
        ever). A STREAM_ERROR is raised as StreamError."""
        n = native()
        h = self._live()
        try:
            text = await run_blocking(
                lambda c: n.take_string(n.invoke("macula_stream_recv", h, timeout_ms, c)), n.cancels
            )
        except TimeoutError:
            return None
        if text is None:
            return None
        return _frame(decode_payload(text))

    def __aiter__(self) -> Stream:
        return self

    async def __anext__(self) -> StreamFrame:
        frame = await self.recv()
        if frame is None or isinstance(frame, StreamEof):
            raise StopAsyncIteration
        return frame

    def free(self) -> None:
        """Frees the stream, aborting it first when it has not ended."""
        if self._handle is not None:
            h, self._handle = self._handle, None
            native().call("macula_stream_free", h)

    async def __aenter__(self) -> Stream:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await asyncio.to_thread(self.free)

    def _live(self) -> int:
        if self._handle is None:
            raise ClosedError("macula-py: this stream was freed")
        return self._handle

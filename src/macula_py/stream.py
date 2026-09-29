"""A streaming RPC session, opened by this node (Pool.open_stream) or handed
to a stream-serving procedure (Pool.serve_stream).

recv() returns one frame: StreamData, StreamEnd (the peer closed its send
side), StreamReply (the provider's terminal value) or StreamEof (the stream
ended normally); a STREAM_ERROR is raised as StreamError. Iterating a stream
yields every frame up to StreamEof.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass
from typing import Any, Union

from macula_py._blocking import run_blocking, run_native
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
    """A served call's or stream session's request. sealed is True when it
    came sealed; payload is the opened plaintext either way."""

    caller: str
    realm: str
    procedure: str
    payload: Any
    deadline_ms: int
    sealed: bool


def request_from(item: dict) -> Request:
    return Request(item["caller"], item["realm"], item["procedure"], item.get("payload"), item["deadline_ms"],
                   item["sealed"] == 1)


@dataclass(frozen=True)
class SealReport:
    """What a caller's seal report says about the exchange behind a result
    (macula's DESIGN_E2E_SEAL_REPORT): sealed is True when the request was
    sealed to the provider's advertised KEM key and the answer opened under
    that key, False when it went in the clear; provider, the node_id it was
    addressed to, as hex; seal_key_id, the key's 8-byte id as hex, only when
    sealed. It states that sealing ran on that exchange, nothing more."""

    sealed: bool
    provider: str
    seal_key_id: str | None


def seal_report(item: dict) -> SealReport:
    """A report as the ABI carries it: sealed 0 or 1, seal_key_id only when
    sealed."""
    return SealReport(item["sealed"] == 1, item["provider"], item.get("seal_key_id"))


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

    def report(self) -> SealReport:
        """This caller's seal report for the stream (see SealReport). It
        settles on the provider's first data or reply opened under the
        stream's key, after which no reseal can happen, or on a clear stream
        on its first data, reply or end; a stream that settled keeps it after
        it ends. Before it settles, and on a stream that ended first,
        NotSettledError; on a served stream, NotACallerError."""
        n = native()
        return seal_report(json.loads(n.take_string(n.invoke("macula_stream_report", self._live()))))

    async def send(self, chunk: bytes) -> None:
        """Sends chunk as raw bytes."""
        h, data = self._live(), bytes(chunk)
        await run_native(lambda: native().invoke("macula_stream_send_bytes", h, data, len(data)))

    async def send_value(self, value: Any) -> None:
        """Sends a payload value."""
        h, body = self._live(), encode_payload(value).encode()
        await run_native(lambda: native().invoke("macula_stream_send_json", h, body))

    async def close_send(self) -> None:
        """Closes this side's sending; the peer sees StreamEnd."""
        h = self._live()
        await run_native(lambda: native().invoke("macula_stream_close_send", h))

    async def reply(self, payload: Any) -> None:
        """The provider's terminal value."""
        h, body = self._live(), encode_payload(payload).encode()
        await run_native(lambda: native().invoke("macula_stream_reply", h, body))

    async def abort(self, code: str, message: str = "") -> None:
        """Ends the stream with a STREAM_ERROR."""
        h = self._live()
        await run_native(lambda: native().invoke("macula_stream_abort", h, code.encode(), message.encode()))

    async def close(self) -> None:
        """Ends the stream normally."""
        h = self._live()
        await run_native(lambda: native().invoke("macula_stream_close", h))

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
        """Frees the stream, aborting it first when it has not ended. The
        abort is a frame written to the peer, which can wait on a stalled
        one: from a coroutine, prefer async with, which frees on a thread."""
        if self._handle is not None:
            h, self._handle = self._handle, None
            native().call("macula_stream_free", h)

    async def __aenter__(self) -> Stream:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await run_native(self.free)

    def _live(self) -> int:
        if self._handle is None:
            raise ClosedError("macula-py: this stream was freed")
        return self._handle

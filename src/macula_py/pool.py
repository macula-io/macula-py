"""A node's pool of station links on the macula 12 mesh, as macula-go's pool
keeps it: every seed pinned by its node_id, the realms whose keys the node
trusts, and one identity for every link. Calls and streams reach a provider
by direct dial: its advertisements from the DHT, trusted only when the
realm's key authorizes them (or, in a node's own namespace ``~<node_id>/``,
only when that node signed them), and the station it serves from dialed
pinned.

Every method that does network I/O is a coroutine that runs the native call
on a worker thread; cancelling the awaiting task cancels the native call.
"""

from __future__ import annotations

import asyncio
import ctypes
import enum
import inspect
import json
import logging
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping, Sequence, Union

from macula_py._blocking import run_blocking
from macula_py._native import Native, native
from macula_py._wire import (
    DEFAULT_CALL_TIMEOUT_MS,
    DEFAULT_CONTENT_TIMEOUT_MS,
    AlreadyAnsweredError,
    ClosedError,
    Id,
    Mcid,
    NotFoundError,
    decode_payload,
    encode_payload,
    id32,
    mcid50,
)
from macula_py.key import NodeKey
from macula_py.stream import Request, Stream, StreamMode, request_from

log = logging.getLogger("macula_py")


@dataclass(frozen=True)
class Seed:
    """A station to link to, pinned by the node_id it must prove."""

    host: str
    port: int
    node_id: Id


@dataclass(frozen=True)
class LinkStatus:
    """One of the pool's links."""

    station: str
    host: str
    port: int
    direct: bool
    up: bool


@dataclass(frozen=True)
class PoolEvent:
    """A link going up or down (kind "link"), or a failure of the pool's
    record issuer (kind "issuer_error")."""

    kind: str
    station: str | None
    direct: bool | None
    up: bool | None
    error: str | None


@dataclass(frozen=True)
class Provider:
    """A trusted provider of a procedure and the station it serves from."""

    node: str
    station: str


@dataclass(frozen=True)
class Event:
    """An event a subscription heard, verified."""

    publisher: str
    realm: str
    topic: str
    seq: int
    published_at: int
    payload: Any
    delivered_via: str


@dataclass(frozen=True)
class DhtRecord:
    """A verified DHT record: its type, signer's key id, times, payload and
    wire bytes."""

    type: int
    key_id: str
    created_at: int
    expires_at: int
    payload: Any
    wire: bytes


@dataclass(frozen=True)
class FoundRecords:
    """Verified records, and how many were dropped as unverifiable."""

    records: list[DhtRecord]
    dropped: int


class RecordType(enum.IntEnum):
    """macula 12's record types."""

    NODE_RECORD = 0x01
    PROCEDURE_ADVERTISEMENT = 0x06
    TOMBSTONE = 0x0C
    CONTENT_ANNOUNCEMENT = 0x11
    STATION_ENDPOINT = 0x12
    ORG_DIRECTORY = 0x15
    PROCEDURE_DELEGATION = 0x16


Handler = Callable[[Request], Union[Any, Awaitable[Any]]]
StreamHandler = Callable[[Stream], Awaitable[None]]


def _flag(value: Any) -> bool | None:
    return None if value is None else value == 1


def _record(item: dict) -> DhtRecord:
    return DhtRecord(
        item["type"], item["key_id"], item["created_at"], item["expires_at"], item.get("payload"), item["wire"]
    )


def _found(text: str) -> FoundRecords:
    item = decode_payload(text)
    return FoundRecords([_record(r) for r in item.get("records") or []], item.get("dropped", 0))


async def _next_item(n: Native, function: str, h: int, timeout_ms: int, *out: Any) -> tuple[Any, bool]:
    """One item from an inbox: (its decoded JSON, False), (None, False) when
    timeout_ms ran out, or (None, True) when the source ended and the inbox is
    drained."""
    closed = ctypes.c_int32(0)

    def take(c: int) -> str | None:
        return n.take_string(n.invoke(function, h, timeout_ms, c, *out, ctypes.byref(closed)))

    text = await run_blocking(take, n.cancels)
    if text is None:
        return None, closed.value == 1
    return decode_payload(text), False


class Subscription:
    """A subscription, until stop() or the pool closes. Iterate it (async for)
    for every event until it ends, or take them one at a time with next()."""

    def __init__(self, handle: int) -> None:
        self._handle: int | None = handle
        self.closed = False
        """True once the subscription ended and every event was taken."""

    async def next(self, timeout_ms: int = 0) -> Event | None:
        """The next event, or None when timeout_ms ran out (0 waits for ever)
        or the subscription ended (then closed is True)."""
        item, closed = await _next_item(native(), "macula_subscription_next", self._live(), timeout_ms)
        if closed:
            self.closed = True
        if item is None:
            return None
        return Event(
            item["publisher"],
            item["realm"],
            item["topic"],
            item["seq"],
            item["published_at"],
            item.get("payload"),
            item["delivered_via"],
        )

    def dropped(self) -> int:
        """Events dropped because the inbox (256) was full."""
        return native().invoke("macula_subscription_dropped", self._live())

    def __aiter__(self) -> Subscription:
        return self

    async def __anext__(self) -> Event:
        while True:
            event = await self.next()
            if event is not None:
                return event
            if self.closed:
                raise StopAsyncIteration

    async def stop(self) -> None:
        """Ends the subscription on every link."""
        if self._handle is not None:
            h, self._handle = self._handle, None
            await asyncio.to_thread(native().call, "macula_subscription_stop", h)

    async def __aenter__(self) -> Subscription:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.stop()

    def _live(self) -> int:
        if self._handle is None:
            raise ClosedError("macula-py: this subscription was stopped")
        return self._handle


class Served:
    """A served procedure, until stop(): each call or stream session is handed
    to its handler on a task of its own."""

    def __init__(self, handle: int, dispatch: Callable[[int, dict], Awaitable[None]], name: str) -> None:
        self._handle: int | None = handle
        self._dispatch = dispatch
        self._tasks: set[asyncio.Task[None]] = set()
        self._loop = asyncio.create_task(self._serve(), name=f"macula-py served {name}")

    async def _serve(self) -> None:
        n = native()
        h = self._handle
        assert h is not None
        while True:
            out_item = ctypes.c_size_t(0)
            item, closed = await _next_item(n, "macula_served_next", h, 0, ctypes.byref(out_item))
            if closed:
                return
            if item is None:
                continue
            task = asyncio.create_task(self._dispatch(out_item.value, item))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def stop(self) -> None:
        """Withdraws the procedure on every link, and ends the handlers still
        running."""
        if self._handle is None:
            return
        h, self._handle = self._handle, None
        self._loop.cancel()
        await asyncio.gather(self._loop, return_exceptions=True)
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await asyncio.to_thread(native().invoke, "macula_served_stop", h)

    async def __aenter__(self) -> Served:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.stop()


async def _answer_call(n: Native, pending: int, request: Request, handler: Handler) -> None:
    try:
        result = handler(request)
        if inspect.isawaitable(result):
            result = await result
        answer = ("macula_pending_reply", encode_payload(result).encode())
    except asyncio.CancelledError:
        raise
    except Exception as e:  # the handler's failure is the caller's handler_error
        answer = ("macula_pending_error", str(e).encode())
    try:
        await asyncio.to_thread(n.invoke, answer[0], pending, answer[1])
    except AlreadyAnsweredError:
        log.warning("macula-py: %s answered after its deadline", request.procedure)


async def _run_session(stream: Stream, handler: StreamHandler) -> None:
    try:
        await handler(stream)
        try:
            await stream.close()
        except ClosedError:
            pass
    except asyncio.CancelledError:
        raise
    except Exception as e:
        try:
            await stream.abort("handler_error", str(e))
        except ClosedError:
            pass
    finally:
        await asyncio.to_thread(stream.free)


class Pool:
    """A node's pool of station links. Close it with close(), or leave its
    async with."""

    def __init__(self, handle: int) -> None:
        self._handle: int | None = handle

    @classmethod
    async def connect(
        cls,
        key: NodeKey,
        seeds: Sequence[Seed],
        *,
        realm_trust: Mapping[Id, str | bytes] | None = None,
        replication_factor: int | None = None,
        max_seeds: int | None = None,
        max_direct_links: int | None = None,
        respawn_delay_ms: int | None = None,
        timeout_ms: int | None = None,
    ) -> Pool:
        """Links the key's node to every seed, and returns once one link is
        up (timeout_ms, 30 s by default). realm_trust holds each realm's key
        as carried (hex or bytes) by realm id: an advertisement in a realm is
        trusted only when its authorization verifies against it."""
        seeds_json = json.dumps(
            [{"host": s.host, "port": s.port, "node_id": id32(s.node_id, "a seed's node_id").hex()} for s in seeds]
        )
        options: dict[str, Any] = {}
        if realm_trust:
            options["realm_trust"] = {
                id32(realm, "a realm id").hex(): (k.hex() if isinstance(k, (bytes, bytearray)) else k)
                for realm, k in realm_trust.items()
            }
        for name, value in (
            ("replication_factor", replication_factor),
            ("max_seeds", max_seeds),
            ("max_direct_links", max_direct_links),
            ("respawn_delay_ms", respawn_delay_ms),
            ("timeout_ms", timeout_ms),
        ):
            if value is not None:
                options[name] = value
        n = native()
        key_handle = key._live()
        handle = await run_blocking(
            lambda c: n.invoke(
                "macula_pool_connect", key_handle, seeds_json.encode(), json.dumps(options).encode(), c
            ),
            n.cancels,
        )
        return cls(handle)

    def node_id(self) -> str:
        """The node_id the pool links as, lowercase hex."""
        out = ctypes.create_string_buffer(32)
        native().invoke("macula_pool_node_id", self._live(), out)
        return out.raw.hex()

    def own_procedure(self, name: str) -> str:
        """name in this node's own namespace, ``~<node_id>/<name>``: served
        with no org and no realm key, authorized by its advertisement's
        signature alone, and called with no realm key pinned."""
        return f"~{self.node_id()}/{name}"

    def status(self) -> list[LinkStatus]:
        """Every link the pool holds."""
        n = native()
        items = json.loads(n.take_string(n.invoke("macula_pool_status", self._live())) or "null") or []
        return [LinkStatus(i["station"], i["host"], i["port"], i["direct"] == 1, i["up"] == 1) for i in items]

    async def next_event(self, timeout_ms: int = 0) -> PoolEvent | None:
        """The pool's next link event, or None when timeout_ms ran out (0
        waits for ever) or the pool closed."""
        item, _closed = await _next_item(native(), "macula_pool_events_next", self._live(), timeout_ms)
        if item is None:
            return None
        return PoolEvent(item["kind"], item.get("station"), _flag(item.get("direct")), _flag(item.get("up")),
                         item.get("error"))

    async def call(
        self,
        realm: Id,
        procedure: str,
        payload: Any = None,
        *,
        provider: Id | None = None,
        timeout_ms: int = DEFAULT_CALL_TIMEOUT_MS,
    ) -> Any:
        """Calls procedure in realm at a provider (any trusted one unless
        provider names one) by direct dial. A provider's ERROR is raised as
        ProviderError, a station's relay error as RelayError."""
        n = native()
        h, realm32, body = self._live(), id32(realm, "realm"), encode_payload(payload).encode()
        provider32 = None if provider is None else id32(provider, "provider")
        text = await run_blocking(
            lambda c: n.take_string(
                n.invoke("macula_pool_call", h, realm32, procedure.encode(), body, provider32, timeout_ms, c)
            ),
            n.cancels,
        )
        return decode_payload(text) if text is not None else None

    async def providers(self, realm: Id, procedure: str, *, timeout_ms: int = DEFAULT_CALL_TIMEOUT_MS) -> list[Provider]:
        """The procedure's trusted providers, freshest first."""
        n = native()
        h, realm32 = self._live(), id32(realm, "realm")
        text = await run_blocking(
            lambda c: n.take_string(n.invoke("macula_pool_providers", h, realm32, procedure.encode(), timeout_ms, c)),
            n.cancels,
        )
        return [Provider(p["node"], p["station"]) for p in json.loads(text or "null") or []]

    async def publish(self, realm: Id, topic: str, payload: Any, *, ttl_ms: int = 0) -> None:
        """Publishes payload on topic in realm (ttl_ms 0: 10 minutes). Topics
        name a kind of fact; ids go in the payload."""
        body = encode_payload(payload).encode()
        await asyncio.to_thread(
            native().invoke, "macula_pool_publish", self._live(), id32(realm, "realm"), topic.encode(), body, ttl_ms
        )

    async def subscribe(self, realm: Id, topic: str) -> Subscription:
        """Subscribes to topic in realm: each verified event is heard once,
        however many links deliver it."""
        handle = await asyncio.to_thread(
            native().invoke, "macula_pool_subscribe", self._live(), id32(realm, "realm"), topic.encode()
        )
        return Subscription(handle)

    async def serve(self, realm: Id, procedure: str, handler: Handler) -> Served:
        """Serves procedure in realm: ``~<own node_id>/<name>`` (own_procedure)
        or ``<org>/<name>`` under an org that delegated it to this node.
        handler(request) returns the result, directly or as an awaitable; an
        exception it raises reaches the caller as a ProviderError of code
        handler_error with the exception's text as its detail."""
        n = native()
        handle = await asyncio.to_thread(
            n.invoke, "macula_pool_serve", self._live(), id32(realm, "realm"), procedure.encode()
        )

        async def dispatch(pending: int, item: dict) -> None:
            await _answer_call(n, pending, request_from(item), handler)

        return Served(handle, dispatch, procedure)

    async def serve_stream(self, realm: Id, procedure: str, mode: StreamMode, handler: StreamHandler) -> Served:
        """Serves a streaming procedure: handler(stream) runs per session, with
        the session's request as stream.request. The stream is closed when the
        handler returns, and aborted with handler_error when it raises."""
        n = native()
        handle = await asyncio.to_thread(
            n.invoke, "macula_pool_serve_stream", self._live(), id32(realm, "realm"), procedure.encode(), int(mode)
        )

        async def dispatch(stream_handle: int, item: dict) -> None:
            await _run_session(Stream(stream_handle, request_from(item)), handler)

        return Served(handle, dispatch, procedure)

    async def open_stream(
        self,
        realm: Id,
        procedure: str,
        mode: StreamMode,
        payload: Any = None,
        *,
        provider: Id | None = None,
        deadline_ms: int = 0,
        timeout_ms: int = DEFAULT_CALL_TIMEOUT_MS,
    ) -> Stream:
        """Opens a stream to procedure in realm by direct dial. deadline_ms is
        the stream's life (30 s when 0); timeout_ms bounds opening it."""
        n = native()
        h, realm32, body = self._live(), id32(realm, "realm"), encode_payload(payload).encode()
        provider32 = None if provider is None else id32(provider, "provider")
        handle = await run_blocking(
            lambda c: n.invoke(
                "macula_pool_open_stream",
                h, realm32, procedure.encode(), int(mode), body, provider32, deadline_ms, timeout_ms, c,
            ),
            n.cancels,
        )
        return Stream(handle)

    async def share_content(
        self, realm: Id, data: bytes, name: str = "", *, timeout_ms: int = DEFAULT_CALL_TIMEOUT_MS
    ) -> bytes:
        """Keeps data in this node, serves it on its own ``~<node_id>/content_v1``
        and announces it in realm, until unshared or the pool closes. Returns
        its 50-byte content id (MCID)."""
        n = native()
        h, realm32 = self._live(), id32(realm, "realm")
        out = ctypes.create_string_buffer(50)
        await run_blocking(
            lambda c: n.invoke(
                "macula_pool_share_content", h, realm32, data, len(data), name.encode(), timeout_ms, c, out
            ),
            n.cancels,
        )
        return out.raw

    async def unshare_content(self, realm: Id, mcid: Mcid, *, timeout_ms: int = DEFAULT_CALL_TIMEOUT_MS) -> None:
        """Stops sharing the content."""
        n = native()
        h, realm32, mcid_bytes = self._live(), id32(realm, "realm"), mcid50(mcid)
        await run_blocking(
            lambda c: n.invoke("macula_pool_unshare_content", h, realm32, mcid_bytes, timeout_ms, c), n.cancels
        )

    async def get_content(
        self,
        realm: Id,
        mcid: Mcid,
        *,
        max_bytes: int | None = None,
        max_chunks: int | None = None,
        parallel: int | None = None,
        chunk_timeout_ms: int | None = None,
        timeout_ms: int = DEFAULT_CONTENT_TIMEOUT_MS,
    ) -> bytes:
        """Fetches the content from the nodes that announce it in realm,
        checking every block against its id. NotSharedError when no node
        shares it, ContentUnavailableError when every sharer failed."""
        n = native()
        h, realm32, mcid_bytes = self._live(), id32(realm, "realm"), mcid50(mcid)
        options = {
            k: v
            for k, v in (
                ("max_bytes", max_bytes),
                ("max_chunks", max_chunks),
                ("parallel", parallel),
                ("chunk_timeout_ms", chunk_timeout_ms),
            )
            if v is not None
        }
        options_json = json.dumps(options).encode() if options else None

        def fetch(c: int) -> bytes:
            length = ctypes.c_size_t()
            address = n.invoke(
                "macula_pool_get_content", h, realm32, mcid_bytes, options_json, timeout_ms, c, ctypes.byref(length)
            )
            return n.take_bytes(address, length.value)

        return await run_blocking(fetch, n.cancels)

    async def find_record(self, key: Id, *, timeout_ms: int = DEFAULT_CALL_TIMEOUT_MS) -> DhtRecord | None:
        """The verified record under key, or None when there is none."""
        n = native()
        h, key32 = self._live(), id32(key, "a record key")
        try:
            text = await run_blocking(
                lambda c: n.take_string(n.invoke("macula_pool_find_record", h, key32, timeout_ms, c)), n.cancels
            )
        except NotFoundError:
            return None
        return _record(decode_payload(text)) if text is not None else None

    async def find_records(self, key: Id, *, timeout_ms: int = DEFAULT_CALL_TIMEOUT_MS) -> FoundRecords:
        """Every verified record under key."""
        n = native()
        h, key32 = self._live(), id32(key, "a record key")
        text = await run_blocking(
            lambda c: n.take_string(n.invoke("macula_pool_find_records", h, key32, timeout_ms, c)), n.cancels
        )
        return _found(text or "{}")

    async def find_records_by_type(
        self, record_type: RecordType | int, *, timeout_ms: int = DEFAULT_CALL_TIMEOUT_MS
    ) -> FoundRecords:
        """Every verified record of a type."""
        n = native()
        h = self._live()
        text = await run_blocking(
            lambda c: n.take_string(n.invoke("macula_pool_find_records_by_type", h, int(record_type), timeout_ms, c)),
            n.cancels,
        )
        return _found(text or "{}")

    async def put_record(self, wire: bytes, *, timeout_ms: int = DEFAULT_CALL_TIMEOUT_MS) -> None:
        """Stores a signed record, as carried, in the DHT."""
        n = native()
        h = self._live()
        await run_blocking(lambda c: n.invoke("macula_pool_put_record", h, wire, len(wire), timeout_ms, c), n.cancels)

    async def close(self) -> None:
        """Closes every link, subscription, served procedure and stream."""
        if self._handle is not None:
            h, self._handle = self._handle, None
            await asyncio.to_thread(native().call, "macula_pool_close", h)

    async def __aenter__(self) -> Pool:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    def _live(self) -> int:
        if self._handle is None:
            raise ClosedError("macula-py: this pool was closed")
        return self._handle

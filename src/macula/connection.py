"""A live connection to one Macula station: the QUIC transport, the
control stream, and the CONNECT/HELLO handshake.

Built on `aioquic` (the standard async Python QUIC implementation), not a
custom transport -- `aioquic.asyncio.client.connect()` already gives a
`QuicConnectionProtocol` with `create_stream()` returning a plain
`(asyncio.StreamReader, asyncio.StreamWriter)` pair, which is all this
module needs: length-prefixed frame bytes over one bidirectional stream,
matching the wire format `macula.frame` implements.

ALPN is `"macula"` (confirmed via macula-dotnet's own live-verified
`SslClientAuthenticationOptions`, itself checked against the real demo
fleet's actual handshake). Standard WebPKI certificate validation is
`aioquic`'s own default (`QuicConfiguration.verify_mode = None`) -- the
real demo fleet presents an ordinary CA-signed certificate (Let's
Encrypt), not a self-signed Ed25519 leaf, so no custom trust handling is
needed to reach it. Pinned/insecure trust modes are deferred until a
future increment actually needs them (direct-dial, out of scope for this
phase) rather than built ahead of need.
"""

from __future__ import annotations

import asyncio
import os
import time
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Awaitable, Callable

from aioquic.asyncio.client import connect as aioquic_connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration

from . import bolt4, cbor, frame
from .identity import KeyPair

ALPN = "macula"

#: Provider-side handler for one advertised (realm, procedure). Raise any
#: exception for a failure -- reported to the caller as `unknown_error`
#: with `str(exception)` as detail; no distinction between an
#: "expected" application failure and a crash in this phase (UCAN/policy,
#: which is where the reference draws that line, is out of scope here).
CallHandler = Callable[[cbor.Value], Awaitable[cbor.Value]]

#: Resolves an inbound CALL's (realm, procedure) to a handler, or None if nothing is advertised for it.
CallLookup = Callable[[bytes, str], "CallHandler | None"]
DEFAULT_HANDSHAKE_TIMEOUT = 30.0


class ConnectRefusedError(Exception):
    """The station's HELLO carried accepted=false."""

    def __init__(self, refusal_code: int | None):
        self.refusal_code = refusal_code
        detail = f" (refusal_code={refusal_code})" if refusal_code is not None else ""
        super().__init__(f"station refused the connection{detail}")


class HelloSignatureInvalidError(Exception):
    """The HELLO frame's own signature didn't verify against the node_id it claims -- proves nothing about who actually sent it."""


@dataclass
class Session:
    """A live connection to one station. Construct via :meth:`connect`, not directly."""

    identity: KeyPair
    remote_info: frame.HelloInfo

    _protocol: QuicConnectionProtocol
    _reader: asyncio.StreamReader
    _writer: asyncio.StreamWriter
    _connect_cm: AbstractAsyncContextManager
    _closed: bool = False

    @classmethod
    async def connect(
        cls,
        host: str,
        port: int,
        identity: KeyPair,
        *,
        handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT,
    ) -> "Session":
        """Dial `host`:`port`, open the control stream, send a signed CONNECT, and wait for HELLO.

        Raises `ConnectRefusedError` if the station's HELLO carries
        `accepted=false`, or `TimeoutError` if no HELLO arrives within
        `handshake_timeout`.
        """
        configuration = QuicConfiguration(is_client=True, alpn_protocols=[ALPN])
        connect_cm = aioquic_connect(host, port, configuration=configuration)
        protocol = await connect_cm.__aenter__()
        try:
            reader, writer = await protocol.create_stream()

            connect_frame = frame.sign(frame.build_connect(identity.node_id(), identity.puzzle_evidence()), identity)
            writer.write(frame.encode_frame(connect_frame))
            await writer.drain()

            hello_value = await asyncio.wait_for(_recv_one_frame(reader), timeout=handshake_timeout)
            hello_info = frame.parse_hello(hello_value)

            if not isinstance(hello_value, dict) or "signature" not in hello_value:
                raise frame.ParseFrameError("HELLO frame has no signature field")
            # The HELLO's own signature must verify against the node_id it
            # claims -- proves nothing about who actually sent it
            # otherwise. A station is never expected to send anything but
            # a legitimately-signed HELLO at this point, but skipping this
            # check would mean trusting the peer's self-reported identity
            # on faith alone.
            try:
                frame.verify(hello_value, hello_info.node_id)
            except frame.SignatureInvalidError as e:
                raise HelloSignatureInvalidError(str(e)) from e

            if not hello_info.accepted:
                raise ConnectRefusedError(hello_info.refusal_code)

            return cls(
                identity=identity,
                remote_info=hello_info,
                _protocol=protocol,
                _reader=reader,
                _writer=writer,
                _connect_cm=connect_cm,
            )
        except BaseException:
            await connect_cm.__aexit__(None, None, None)
            raise

    async def send_frame(self, unsigned_frame: dict) -> None:
        """Sign `unsigned_frame` with this session's identity and send it on the control stream."""
        signed = frame.sign(unsigned_frame, self.identity)
        self._writer.write(frame.encode_frame(signed))
        await self._writer.drain()

    async def recv_frame(self, timeout: float | None = None) -> dict:
        """Receive the next frame off the control stream, bounded by `timeout` (seconds) if given."""
        coro = _recv_one_frame(self._reader)
        value = await (asyncio.wait_for(coro, timeout=timeout) if timeout is not None else coro)
        if not isinstance(value, dict):
            raise frame.ParseFrameError("a frame must be a CBOR map at the top level")
        return value

    async def call(
        self,
        procedure: str,
        realm: bytes,
        payload: cbor.Value,
        deadline_ms: int,
        timeout: float,
        *,
        ucan_token: bytes = b"",
    ) -> frame.CallResponse:
        """Send a signed CALL and wait for the matching RESULT or ERROR, correlated by call_id.

        Known v1 limitation (control stream only, matching every sibling
        Macula SDK): any frame that arrives before the match (e.g. an
        EVENT from an active subscription) is discarded, not queued --
        correct for a caller doing one thing at a time on the control
        stream, not yet correct for CALL and PUBLISH/SUBSCRIBE used
        concurrently on it. A pool/multiplexing layer (out of scope for
        this phase) is what every sibling SDK builds to lift this.
        """
        call_id = os.urandom(16)
        call_frame = frame.build_call(call_id, procedure, realm, payload, deadline_ms, self.identity.node_id(), ucan_token=ucan_token)
        await self.send_frame(call_frame)

        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"no response for call_id {call_id.hex()} within {timeout}s")
            value = await self.recv_frame(timeout=remaining)
            if frame.frame_call_id(value) != call_id:
                continue  # not ours -- see this method's doc on the limitation
            try:
                return frame.parse_call_response(value)
            except frame.ParseFrameError:
                continue  # matching call_id, unexpected shape -- keep waiting

    async def publish(self, topic: str, realm: bytes, payload: cbor.Value, seq: int, *, ttl_ms: int | None = None) -> None:
        """Send a signed PUBLISH. Fire-and-forget -- no reply is expected on the wire; a subscriber (this session included, if subscribed to the same topic/realm) receives an EVENT asynchronously, read via :meth:`recv_event`."""
        published_at_ms = frame.current_millis()
        await self.send_frame(frame.build_publish(topic, realm, self.identity.node_id(), seq, payload, published_at_ms, ttl_ms=ttl_ms))

    async def subscribe(self, topic: str, realm: bytes) -> None:
        await self.send_frame(frame.build_subscribe(topic, realm, self.identity.node_id()))

    async def unsubscribe(self, topic: str, realm: bytes) -> None:
        await self.send_frame(frame.build_unsubscribe(topic, realm, self.identity.node_id()))

    async def recv_event(self, timeout: float | None = None) -> frame.EventInfo:
        """Read the next frame and parse it as an EVENT, bounded by `timeout`.

        Any non-EVENT frame received first is an error, not silently
        skipped -- unlike :meth:`call`'s response wait, a caller waiting
        specifically for a pubsub delivery has no reason to expect
        anything else to legitimately arrive first. A permissive
        "skip anything that isn't an EVENT" loop (needed once PUBLISH/
        SUBSCRIBE/CALL share a control stream concurrently) is the
        supervised-pubsub-wrapper's job, out of scope this phase.
        """
        value = await self.recv_frame(timeout=timeout)
        return frame.parse_event(value)

    async def advertise(self, realm: bytes, procedure: str) -> None:
        """Register this connection as the handler for (realm, procedure). Fire-and-forget on the wire."""
        await self.send_frame(frame.build_advertise(realm, procedure, self.identity.node_id()))

    async def unadvertise(self, realm: bytes, procedure: str) -> None:
        await self.send_frame(frame.build_unadvertise(realm, procedure, self.identity.node_id()))

    async def serve_one_call(self, lookup: CallLookup, timeout: float) -> None:
        """The provider role's counterpart to :meth:`call`: block for the next inbound CALL, bounded by `timeout`, look it up via `lookup`, invoke the matching handler, and send the resulting RESULT or ERROR back.

        Any non-CALL frame that arrives first (e.g. the station's own
        unprompted advertise broadcasts for its built-in _content.*
        procedures, confirmed live elsewhere in this org's own SDK work)
        is discarded, not queued -- same "control stream, one thing at a
        time" limitation :meth:`call` documents.
        """
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for an inbound CALL")
            value = await self.recv_frame(timeout=remaining)
            if not isinstance(value, dict) or value.get("frame_type") != "call":
                continue
            try:
                call_info = frame.parse_call(value)
            except frame.ParseFrameError:
                continue
            reply = await self._build_call_reply(call_info, lookup)
            await self.send_frame(reply)
            return

    async def _build_call_reply(self, call_info: frame.CallInfo, lookup: CallLookup) -> dict:
        self_pub = self.identity.node_id()
        handler = lookup(call_info.realm, call_info.procedure)
        if handler is None:
            return frame.build_call_error(call_info.call_id, bolt4.UNKNOWN_NEXT_PEER, self_pub)
        try:
            value = await handler(call_info.payload)
            return frame.build_result(call_info.call_id, value, self_pub)
        except Exception as e:
            return frame.build_call_error(call_info.call_id, bolt4.UNKNOWN_ERROR, self_pub, detail=str(e))

    async def close(self) -> None:
        """Close the connection. Idempotent."""
        if self._closed:
            return
        self._closed = True
        await self._connect_cm.__aexit__(None, None, None)

    async def __aenter__(self) -> "Session":
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()


async def _recv_one_frame(reader: asyncio.StreamReader) -> cbor.Value:
    """Read exactly one length-prefixed frame off `reader`, accumulating bytes across reads as needed."""
    header = await reader.readexactly(4)
    length = int.from_bytes(header, "big")
    if length > frame.MAX_FRAME_BYTES:
        raise frame.ParseFrameError(f"claimed frame length {length} exceeds the {frame.MAX_FRAME_BYTES}-byte cap")
    body = await reader.readexactly(length)
    decoded = frame.decode_frame(header + body)
    assert decoded.complete  # readexactly already guarantees this
    return decoded.frame

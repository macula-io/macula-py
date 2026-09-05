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
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass

from aioquic.asyncio.client import connect as aioquic_connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration

from . import cbor, frame
from .identity import KeyPair

ALPN = "macula"
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

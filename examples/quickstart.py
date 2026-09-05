"""Connects to the real production demo fleet, advertises a trivial
echo procedure, and calls it. Run with: python examples/quickstart.py

Two identities are used (a provider and a caller) because a station
kicks a connection the instant a second one arrives under the same
identity -- the same reason every one of this SDK's own live tests
uses separate KeyPairs for each role.
"""

import asyncio
import uuid

from macula import frame
from macula.connection import Session
from macula.identity import KeyPair

STATION_HOST = "station-de-frankfurt.macula.io"
STATION_PORT = 4433
REALM = bytes(32)
# Unique per run -- reusing a fixed procedure name across rapid repeated
# runs of this script can hit stale DHT routing state from the prior
# run's now-dead advertiser.
PROCEDURE = f"macula_py.quickstart_echo.{uuid.uuid4().hex}"


async def main() -> None:
    # Puzzle-hardened identity -- required. An unhardened identity fails
    # the handshake silently (QUIC/TLS looks healthy, HELLO never accepts).
    provider_identity = KeyPair.generate()
    caller_identity = KeyPair.generate()

    async with await Session.connect(STATION_HOST, STATION_PORT, provider_identity) as provider:
        await provider.advertise(REALM, PROCEDURE)
        await asyncio.sleep(0.5)  # ADVERTISE is fire-and-forget; give it a moment to land

        async def echo(payload):
            return payload

        serve_task = asyncio.create_task(provider.serve_one_call(lambda realm, proc: echo, timeout=10))

        async with await Session.connect(STATION_HOST, STATION_PORT, caller_identity) as caller:
            deadline_ms = frame.current_millis() + 5_000
            response = await caller.call(PROCEDURE, REALM, "hello", deadline_ms, timeout=5)

        await serve_task
        print(response)


if __name__ == "__main__":
    asyncio.run(main())

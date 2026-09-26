"""Running a blocking native call from asyncio.

Each call runs on a worker thread (ctypes releases the GIL for its duration)
with a cancel handle of its own. Cancelling the awaiting task cancels the
native call through the handle, so it ends early instead of waiting out its
timeout; the handle is freed only after the native call has returned, since
the native side may still be using it until then.
"""

from __future__ import annotations

import asyncio
from typing import Callable, Protocol, TypeVar

T = TypeVar("T")


class Cancels(Protocol):
    def new(self) -> int: ...
    def cancel(self, h: int) -> None: ...
    def free(self, h: int) -> None: ...


class NativeCancelled(Exception):
    """The native call ended because its cancel handle was cancelled."""


async def run_blocking(call: Callable[[int], T], cancels: Cancels) -> T:
    """call(cancel_handle) on a worker thread, cancellable from the loop."""
    h = cancels.new()
    future = asyncio.ensure_future(asyncio.to_thread(call, h))
    future.add_done_callback(lambda _: cancels.free(h))
    try:
        return await asyncio.shield(future)
    except NativeCancelled:
        raise asyncio.CancelledError() from None
    except asyncio.CancelledError:
        cancels.cancel(h)
        # Wait for the native call to return. Its outcome (a result that raced
        # the cancel, or the native "cancelled" error) is taken and dropped,
        # since the caller asked to stop waiting for it.
        await asyncio.wait([future])
        if not future.cancelled():
            future.exception()
        raise

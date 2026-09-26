"""Running blocking native calls from asyncio.

Every native call runs on a daemon thread of its own (ctypes releases the
GIL for its duration), never on asyncio's default executor: inbox waits
(served calls, subscriptions, stream receives) block for as long as their
source lives, and a bounded shared pool full of them would starve every
other call, including the cancellations meant to end them.

run_blocking gives the call a cancel token of its own. Cancelling the
awaiting task cancels the token, which ends the native call early instead of
waiting out its timeout, and returns at once; the call's thread frees the
token once the native call has returned. Whatever the call ends with after
that is taken and dropped, however many times the task was cancelled.

run_native runs a short native call that takes no token.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Callable, Protocol, TypeVar

T = TypeVar("T")


class Cancels(Protocol):
    def new(self) -> int: ...
    def cancel(self, h: int) -> None: ...
    def free(self, h: int) -> None: ...


class NativeCancelled(Exception):
    """The native call ended with the error kind "cancelled"."""


def _settle(future: asyncio.Future, result: object, error: BaseException | None) -> None:
    if future.done():
        return
    if error is not None:
        future.set_exception(error)
    else:
        future.set_result(result)


def _start(work: Callable[[], T], name: str) -> asyncio.Future:
    """work() on a thread of its own; its outcome settles the returned future."""
    loop = asyncio.get_running_loop()
    future: asyncio.Future = loop.create_future()
    # Consume the outcome up front, so an outcome nobody awaits any more (the
    # task was cancelled) is never reported as unretrieved.
    future.add_done_callback(lambda f: f.cancelled() or f.exception())

    def run() -> None:
        try:
            outcome: tuple[object, BaseException | None] = (work(), None)
        except BaseException as e:  # handed to the awaiting task
            outcome = (None, e)
        try:
            loop.call_soon_threadsafe(_settle, future, *outcome)
        except RuntimeError:
            pass  # the loop closed; nobody is waiting

    threading.Thread(target=run, name=name, daemon=True).start()
    return future


async def run_native(call: Callable[[], T]) -> T:
    """call() on a thread of its own. Not cancellable: cancelling the task
    stops the waiting, and the native call runs to its end."""
    return await asyncio.shield(_start(call, "macula-py native"))


async def run_blocking(call: Callable[[int], T], cancels: Cancels) -> T:
    """call(cancel_token) on a thread of its own, cancelled with the task."""
    h = cancels.new()
    cancelled = threading.Event()

    def work() -> T:
        try:
            return call(h)
        except NativeCancelled as e:
            if cancelled.is_set():
                raise
            # "cancelled" without our token cancelled is the native side's
            # own failure, not a cancellation this task asked for.
            from macula_py._wire import MaculaError

            raise MaculaError(f"macula-py: {e}") from None
        finally:
            cancels.free(h)

    future = _start(work, "macula-py blocking")
    try:
        return await asyncio.shield(future)
    except NativeCancelled:
        raise asyncio.CancelledError() from None
    except asyncio.CancelledError:
        if not future.done():
            cancelled.set()
            cancels.cancel(h)
        raise

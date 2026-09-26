"""Every native call that blocks runs on a worker thread with its own cancel
handle: cancelling the awaiting task cancels the native call, and the handle
is freed only once the native call has returned."""

import asyncio
import threading

import pytest

from macula_py._blocking import run_blocking


class FakeCancels:
    def __init__(self):
        self.next = 0
        self.events: dict[int, threading.Event] = {}
        self.cancelled: list[int] = []
        self.freed: list[int] = []
        self.lock = threading.Lock()

    def new(self) -> int:
        with self.lock:
            self.next += 1
            self.events[self.next] = threading.Event()
            return self.next

    def cancel(self, h: int) -> None:
        self.cancelled.append(h)
        self.events[h].set()

    def free(self, h: int) -> None:
        self.freed.append(h)


async def test_the_result_comes_back_and_the_handle_is_freed():
    cancels = FakeCancels()
    assert await run_blocking(lambda h: ("done", h), cancels) == ("done", 1)
    assert cancels.freed == [1]
    assert cancels.cancelled == []


async def test_an_error_propagates_and_the_handle_is_freed():
    cancels = FakeCancels()

    def fails(_h):
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        await run_blocking(fails, cancels)
    assert cancels.freed == [1]


async def test_cancelling_the_task_cancels_the_native_call_then_frees():
    cancels = FakeCancels()
    returned = threading.Event()
    freed_before_return: list[bool] = []

    def blocks(h):
        cancels.events[h].wait(5)
        freed_before_return.append(h in cancels.freed)
        returned.set()
        return "late"

    task = asyncio.create_task(run_blocking(blocks, cancels))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cancels.cancelled == [1]
    assert returned.is_set()
    assert freed_before_return == [False]
    assert cancels.freed == [1]


async def test_a_native_cancelled_error_surfaces_as_cancelled():
    cancels = FakeCancels()

    def says_cancelled(_h):
        from macula_py._blocking import NativeCancelled

        raise NativeCancelled()

    with pytest.raises(asyncio.CancelledError):
        await run_blocking(says_cancelled, cancels)

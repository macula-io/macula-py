"""Every native call that blocks runs on a worker thread with its own cancel
handle: cancelling the awaiting task cancels the native call, and the handle
is freed only once the native call has returned."""

import asyncio
import threading

import pytest

from macula_py._blocking import run_blocking, run_native


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


async def test_cancelling_the_task_cancels_the_native_call_and_frees_after_it_returns():
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
    assert await asyncio.to_thread(returned.wait, 5)
    await asyncio.sleep(0.01)
    assert freed_before_return == [False]
    assert cancels.freed == [1]


async def test_a_cancelled_calls_own_error_is_retrieved_not_left_to_the_loop():
    from macula_py._blocking import NativeCancelled

    cancels = FakeCancels()
    reported = []
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(lambda _loop, context: reported.append(context))

    def ends_cancelled(h):
        cancels.events[h].wait(5)
        raise NativeCancelled("the wait was cancelled")

    task = asyncio.create_task(run_blocking(ends_cancelled, cancels))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    del task
    import gc

    gc.collect()
    await asyncio.sleep(0)
    assert reported == []


async def test_a_second_cancellation_still_leaves_nothing_for_the_loop():
    from macula_py._blocking import NativeCancelled

    cancels = FakeCancels()
    reported = []
    asyncio.get_running_loop().set_exception_handler(lambda _loop, context: reported.append(context))
    release = threading.Event()

    def ends_late(h):
        cancels.events[h].wait(5)
        release.wait(5)
        raise NativeCancelled("the wait was cancelled")

    task = asyncio.create_task(run_blocking(ends_late, cancels))
    await asyncio.sleep(0.05)
    task.cancel()
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    release.set()
    await asyncio.sleep(0.1)
    del task
    import gc

    gc.collect()
    await asyncio.sleep(0)
    assert reported == []
    assert cancels.freed == [1]


async def test_a_native_cancelled_error_without_our_cancel_is_a_macula_error_not_cancellation():
    from macula_py import MaculaError
    from macula_py._blocking import NativeCancelled

    def cancelled_by_someone_else(_h):
        raise NativeCancelled("context canceled")

    with pytest.raises(MaculaError, match="context canceled"):
        await run_blocking(cancelled_by_someone_else, FakeCancels())


async def test_blocking_calls_never_wait_for_the_default_executor():
    import concurrent.futures

    loop = asyncio.get_running_loop()
    loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=1))
    cancels = FakeCancels()
    held = [asyncio.create_task(run_blocking(lambda h: cancels.events[h].wait(5), cancels)) for _ in range(4)]
    await asyncio.sleep(0.05)
    assert await asyncio.wait_for(run_blocking(lambda h: "through", cancels), 2) == "through"
    assert await asyncio.wait_for(run_native(lambda: "also through"), 2) == "also through"
    for task in held:
        task.cancel()
    await asyncio.gather(*held, return_exceptions=True)

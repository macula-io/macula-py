# PLAN_RESOURCE_LEAK_HARDENING.md

**Status:** Survey complete — hardening not started
**Created:** 2026-09-12
**Last Updated:** 2026-09-12

## Overview

Read-only survey of `src/macula_py` (the Python port of the Macula mesh
SDK, built on **aioquic 1.3.0** per `pyproject.toml`, pure `asyncio`, no
anyio/threads) for potential memory and resource leaks, cross-checked
finding-by-finding against the C# sibling's survey
(`macula-dotnet/plans/PLAN_RESOURCE_LEAK_HARDENING.md`). No code was
changed. The dominant theme: **`Session.accept_stream` does not own the
termination of the stream it dequeues** — it abandons it on timeout,
cancellation, and even on the handler's normal return — and a set of
aioquic-internal registries (`_stream_readers`, `_streams_finished`) retain
one object per stream ever opened for the life of the connection. Several
dotnet findings are structurally absent in Python (no task fan-out, no
dedup map, no subscription registry, no static session registry, no
threads, no OCE/timeout misclassification — see the record at the end).

General hygiene found to be GOOD and not repeated as findings:
`Session.connect` tears the QUIC context down on every failure path
(connection.py:154-156) via aioquic's own `connect()` finally
(`protocol.close(); await protocol.wait_closed(); transport.close()`,
aioquic asyncio/client.py:76-79); `content.put`/`content.get` release their
dedicated stream in a `finally` (content.py:60-61, 83-84); every frame
read and write is capped at `MAX_FRAME_BYTES` (~16 MiB, frame.py:41,
connection.py:451-452, frame.py:128-129); CBOR decode depth is bounded
(cbor.py:68); no `asyncio.create_task`, timers, threads, or `__del__`
finalizers exist anywhere in `src/`.

---

## Findings (ranked)

### CRITICAL

#### F1. `accept_stream` abandons the dequeued stream on timeout, cancellation, or unexpected error
`connection.py:344-351` (`Session.accept_stream`).

The (reader, writer) pair is popped from `_incoming_streams` at :344-345,
then `asyncio.wait_for(coro, timeout=timeout)` guards the wait. Three exit
paths leak the just-accepted QUIC stream:

- **Timeout**: `wait_for` raises `TimeoutError` at :345. The stream was
  already dequeued; nothing closes it. The peer's STREAM_OPEN never gets
  an answer, its side stays open, and the local stream slot (plus the
  reader entry aioquic registered for it, see F4) is held until session
  teardown.
- **Cancellation**: `CancelledError` (a `BaseException`) bypasses the
  `except` at :349 entirely, same abandonment.
- **Unexpected error**: the catch at :349-351 only handles
  `frame.ParseFrameError` / `asyncio.IncompleteReadError`. Any other
  failure during the first-frame read (e.g. `ConnectionError` from aioquic
  mid-read, or a `DecodeError`-wrapped parse failure raised as something
  other than `ParseFrameError`) escapes with the stream unclosed.

The two handled shapes also only get `writer.close()` — a bare FIN with no
STREAM_ERROR frame — so the peer sees a clean EOF mid-handshake rather
than a rejection, and can hang waiting for a reply. Consequence per leak:
a permanently open QUIC stream, a retained reader+writer+adapter object
cluster (F4), and a peer-side stream slot consumed until the connection
dies. Fix direction: make the invariant explicit — every exit from
`accept_stream` either hands the stream to a handler that will own its
teardown, or closes/aborts it (abort with STREAM_ERROR on refusal, not a
bare FIN) in a `finally`-style guard before re-raising.

#### F2. `accept_stream` leaves the stream open when the handler returns normally
`connection.py:357-358` (and the SDK's own test pattern, tests/test_stream.py:215-230, confirms it).

`await handler(handle, open_info.args)` — when the handler completes
without itself calling `close()`/`close_send()`/`set_reply()` (nothing
enforces it, and the docstring for `StreamHandler` frames close as the
handler's own job), the stream is silently left open. The QUIC stream
never receives FIN or STREAM_ERROR; the peer keeps its side open waiting
for chunks/END. This is the Python analog of the dotnet survey's F1
"never releases its dedicated stream — on success" for content transfer —
but on the streaming-RPC provider path, and it is also reachable from the
`not_found`/handler-error branches' *successor* frames (those do abort
correctly). Consequence: one leaked stream per served call whose handler
forgot to close; the peer-side handler and stream slot held indefinitely.
Fix direction: after the handler returns (and after `set_reply`, which is
terminal per frame.py's own docs), `accept_stream` should itself
close/half-close the writer if the handle is still open — handler-close
stays optional, never mandatory.

#### F3. `open_stream` abandons the fresh stream if the STREAM_OPEN write fails
`connection.py:322-330`.

The dedicated stream is opened at :322, then the STREAM_OPEN is
signed/encoded (:324-327), written (:328) and drained (:329). If
`frame.build_stream_open` raises (invalid `mode` → `ValueError`,
frame.py:579-580 — reachable before any byte is written), or
`writer.drain()` raises (connection closed concurrently, or drain never
completes and the task is cancelled), the freshly opened stream is
abandoned with no close/abort. Same slot-consumption consequence as F1,
on the caller side — the direct analog of dotnet F3. Fix direction: wrap
the open+write in a guard that closes (or better, aborts) the stream on
any failure before returning the handle.

### HIGH

#### F4. aioquic retains one reader object per stream for the connection's lifetime — SDK never releases them
Python-specific, in the transport integration: aioquic 1.3.0
`asyncio/protocol.py:24, 183-191` and `quic/connection.py:370, 3122-3124`.

Three compounding retention mechanisms, none of which macula-py's
teardown (content.py:60-61/83-84, StreamHandle.close at connection.py:429)
releases:

- `QuicConnectionProtocol._stream_readers` (protocol.py:24) gets one
  `asyncio.StreamReader` (+ its `StreamReaderProtocol`, `StreamWriter` and
  `QuicStreamAdapter`) per stream ever created (client- or peer-initiated)
  at protocol.py:190, and **nothing ever deletes entries** — the dict is
  only iterated at protocol.py:169-171 to feed EOF on connection
  termination. Every content transfer (one dedicated stream per put/get,
  content.py:47/66) and every `open_stream`/inbound stream permanently
  grows this dict on a long-lived session.
- `QuicConnection._streams_finished` (quic/connection.py:370) accumulates
  the stream_id of every finished stream at :3124 and is never pruned.
- The SDK's "close" is `write_eof` only (aioquic
  asyncio/protocol.py:261-269): a half-close FIN, no wait for the peer's
  FIN and no reset. Against a peer that never finishes its side (or when
  the handler/`recv` raises `StreamAbortedError` without closing the
  local writer, connection.py:405-409), the `QuicStream` object itself
  remains in `QuicConnection._streams` (removed only when `is_finished`,
  quic/connection.py:3122).

Additionally there is no asyncio-level backpressure: aioquic creates the
reader via `asyncio.StreamReader()` whose `StreamReaderProtocol` never
gets `connection_made` (protocol.py:186-191), so `reader._transport` is
never set and stdlib `feed_data`'s 2×-limit pause is never armed — unread
streams buffer until aioquic's own QUIC flow-control windows stop the
sender (~1 MiB per stream, 128 advertised peer-initiated bidi streams;
quic/configuration.py:53/63, quic/connection.py:324-328), i.e. ~128 MiB
worst case held in RAM with no soft pause at the usual 64 KiB. Per-object
retention is unbounded in *stream count* over the session's life. Fix
direction: subclass `QuicConnectionProtocol` in the SDK to drop
`_stream_readers` entries when a stream finishes/resets (or fix aioquic
upstream); prefer explicit reset/abort semantics on the failure paths
from F1-F3 instead of bare FINs; optionally pin `asyncio.StreamReader`
with a pausable adapter.

#### F5. Untrusted manifest accepted without size bound and never checked against the requested MCID
`content.py:73-82` + `manifest.py:196-245`. (Note: the dotnet F5
*preallocation* — `new byte[manifest.Size]` before verification — is
**not present** in Python: chunks are accumulated incrementally and each
is hash-verified against the manifest's own chunk entries,
content.py:75-79. The Python flaw is different but same class.)

`manifest.from_wire` validates `chunk_size > 0` (:223-224), integer
`chunk_count` (:225-230) and `chunk_count == len(chunks)` (:231-235), but
**never validates the declared `size` against the chunk entries** and
**never caps total size**. `content.get` then fetches every chunk
sequentially and accumulates `pieces` (content.py:74-79) before
`manifest.verify` compares the reassembled length against `size`
(manifest.py:172-181, reached only after the whole payload is in memory).
A hostile station (or corrupted station-side store) can therefore serve a
manifest whose `chunk_count × ~16 MiB` (per-chunk frame cap) forces an
unbounded reassembly — the client's memory is the only limit — plus a 2×
peak from `b"".join(pieces)` at content.py:80. Compounding: nothing
verifies that the *returned* manifest actually hashes to the `mcid` the
caller asked for (`_get_manifest` uses `mcid` only as the fetch key,
content.py:73/115-125; `from_wire` trusts the manifest's own `"mcid"`
field), so the unbounded manifest can be substituted wholesale. Fix
direction: in `from_wire` (or `get` before fetching), require
`size == sum(chunk sizes)` and cap total size; re-derive the manifest's
MCID from its canonical fields and compare with the requested `mcid`;
assemble incrementally with a fixed bound (or spill to disk).

### MEDIUM

#### F6. `_incoming_streams` queue has no bound of its own, and no close signalling — `accept_stream(timeout=None)` blocks forever after session close
`connection.py:106, 115, 344, 362-367`.

`_on_new_stream` does `put_nowait` into an unbounded `asyncio.Queue`
(:106, :115) on every peer-initiated stream. In practice aioquic's own
advertised `MAX_STREAMS_BIDI = 128` (quic/connection.py:324-328) caps the
fan-in at 128 entries, so the queue is *de facto* bounded — but only by a
transport default the SDK neither states nor matches (a future aioquic
change, or a station dialing with different settings, silently changes
the bound). Separately, `Session.close()` (:362-367) only closes the QUIC
context; it does not wake a task parked in `accept_stream`'s
`_incoming_streams.get()` at :344, so a caller using `timeout=None` hangs
forever after close instead of failing (the control-stream readers *do*
wake, via aioquic's EOF feed at protocol.py:169-171 — the queue does
not). Fix direction: create the queue with an explicit `maxsize` matching
the transport's stream cap, and have `close()` cancel/finish pending
`accept_stream` waiters (e.g. a sentinel or a per-session cancelled
`Event`).

#### F7. No safety net on `StreamHandle` or `Session` — dropped handles leak until session end
`connection.py:376-444` (StreamHandle), `362-373` (Session).

`StreamHandle` has no `__aenter__`/`__aexit__`, no finalizer, and no
close-on-drop: a handle that escapes its scope (exception unwind, app
bug) leaves its QUIC stream open until the session dies, and the handle
strongly references its `Session` (connection.py:388) so a retained
handle also retains the connection. `StreamHandle.recv` raising
`StreamAbortedError` (peer sent STREAM_ERROR) closes nothing locally
(connection.py:405-409) — the local half stays open even though the
stream is dead by wire definition. `Session` likewise has no `__del__`:
a session the app drops without `close()` leaks the QUIC connection and
protocol until aioquic's idle timeout (60 s default) and GC reclaim them
— bounded, unlike the dotnet survey's F12, because **Python has no
static session registry** (F12 not present). Fix direction: async context
manager on `StreamHandle` (and `Stream`-style `__del__` warn-in-debug for
sessions); `recv` closes the local writer on `StreamAbortedError`.

### LOW / hygiene

- `KeyPair.save` leaves a `.tmp` file behind if `os.replace` fails or the
  process dies between write and rename (identity.py:143-158) — same
  shape as the dotnet survey's `KeyPair.Save` LOW note. `fchmod` hardening
  is already present (:154); add failure-path cleanup.
- `Session.call`'s discard loop (connection.py:196-207) and
  `serve_one_call`'s (connection.py:250-264) spin indefinitely on a
  control stream flooded with foreign frames — CPU, not memory; a
  discarded-frame cap per loop would bound it.
- The `served task` pattern in examples/quickstart.py:39-45 is
  caller-owned; if `caller.call` raises, `serve_task` is never awaited and
  its exception is unobserved (example code only, not `src/`).

---

## Dotnet findings NOT present in Python (record for completeness)

| dotnet finding | Python status |
|----------------|---------------|
| F1 ContentTransfer stream never released | **Mitigated**: `finally: writer.close()` (content.py:60-61, 83-84); residual half-close retention folded into F4 |
| F4 OCE/timeout misclassification | **Not present**: `CancelledError` is `BaseException`, invisible to every `except Exception` in `src/`; `wait_for` re-raises cancellation rather than converting it |
| F5 manifest-size preallocation | **Not present** as preallocation; replaced by F5 above (no total bound) |
| F6 no IDisposable on FrameStream | Analog exists (F7) but aioquic's `StreamReader` buffer does not grow unboundedly (frame cap + flow control) |
| F7 unbounded task fan-out per inbound call | **Not present**: no `asyncio.create_task` anywhere in `src/`; provider side is pull-based (`serve_one_call`/`accept_stream` await the caller) |
| F8 EventDedup growth between sweeps | **Not present**: no dedup layer in this phase of the port |
| F9 fire-and-forget close task | **Not present**: session teardown is awaited (`connection.py:367`) |
| F10 publisher CTS / unobserved callbacks | **Not present**: no CTS equivalent, no background publishers |
| F11 dead Subscription objects | **Not present**: no subscription/event-channel layer yet |
| F12 static OpenSessions registry | **Not present**: no registry; dropped-session cost bounded by QUIC idle timeout (see F7) |
| Thread leaks, timers, unclosed queues, finalizers | **Not present**: no `threading.Thread`, no `call_later`/timers owned by the SDK, no `__del__`; the one queue is F6 |

---

## Phases

- [ ] Phase 1 — `accept_stream` ownership invariant (F1, F2): close/abort
      the dequeued stream on every exit path — timeout, cancellation,
      unexpected exception, and handler return; abort-with-STREAM_ERROR
      on refusal instead of bare FIN. Test: accept-timeout cycles and
      close-forgetting handlers leave zero open streams.
- [ ] Phase 2 — `open_stream` teardown on write failure (F3): guard the
      open+write so any failure closes the fresh stream.
- [ ] Phase 3 — aioquic integration hardening (F4): protocol subclass (or
      upstream fix) pruning `_stream_readers`/finished-stream state;
      pausable reader adapter; consider reset semantics on the F1-F3
      failure paths.
- [ ] Phase 4 — untrusted-manifest bounds (F5): validate `size` vs chunk
      entries and cap total before fetching; verify the fetched manifest's
      derived MCID against the requested one; bounded reassembly.
- [ ] Phase 5 — queue bound and safety nets (F6, F7): bounded
      `_incoming_streams` matching the transport cap, close signalling for
      parked `accept_stream` waiters, `StreamHandle` async context
      manager, `recv` closes on `StreamAbortedError`.
- [ ] Phase 6 — hygiene (LOW): `.tmp` cleanup on save failure, discard
      caps in the control-stream wait loops.

## Files to Create/Modify

| File | Purpose | Status |
|------|---------|--------|
| `src/macula_py/connection.py` | F1/F2/F3 stream teardown, F6 queue bound + close signalling, F7 StreamHandle safety net | Not started |
| `src/macula_py/content.py` | F5 pre-fetch manifest checks (size cap, MCID re-derivation) | Not started |
| `src/macula_py/manifest.py` | F5 `from_wire` size-vs-chunks validation and total-size cap | Not started |
| `src/macula_py/identity.py` | LOW: `.tmp` cleanup on failed save | Not started |
| `src/macula_py/_aioquic_protocol.py` (new) | F4 protocol subclass pruning per-stream reader retention | Not started |
| `tests/test_stream.py`, `tests/test_content.py` | Regression tests for Phases 1-4 | Not started |

## Success Criteria

- [ ] A live-session stress test (N sequential `content.put`/`content.get`
      calls) shows no growth in retained reader/stream objects per
      transfer and succeeds beyond N where stream retention previously
      accumulated.
- [ ] `accept_stream` with a short timeout against a peer that never
      completes its STREAM_OPEN leaves no open stream (repeatable 1000x,
      zero growth), and the peer receives a STREAM_ERROR, not a bare FIN.
- [ ] A handler that returns without closing has its stream closed by
      `accept_stream`; a 1000-iteration serve loop shows zero open
      streams.
- [ ] Cancelling `open_stream` mid-drain (or passing an invalid `mode`)
      does not leave the freshly opened stream open.
- [ ] A hostile manifest (huge `size`, `chunk_count` mismatches,
      wrong-MCID manifest) fails fast before chunk fetching, with no
      allocation proportional to the declared size.
- [ ] `Session.close()` unblocks a task parked in
      `accept_stream(timeout=None)` within one loop iteration.
- [ ] All tests green: `pytest` (offline suite) and the `live`-marked
      suite against the demo fleet still passes.

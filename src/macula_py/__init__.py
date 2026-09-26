"""macula-py: a Python node on the macula 12 mesh, over macula-go's C ABI.

    key = await NodeKey.generate("pq_hybrid")
    async with await Pool.connect(key, [Seed(host, 4433, station_id)],
                                  realm_trust={realm: realm_key}) as pool:
        print(await pool.call(realm, "mcl-echo/echo", "hello"))
"""

from macula_py._wire import (
    DEFAULT_CALL_TIMEOUT_MS,
    DEFAULT_CONTENT_TIMEOUT_MS,
    AlreadyAnsweredError,
    ClosedError,
    ContentUnavailableError,
    InvalidArgumentError,
    InvalidHandleError,
    MaculaError,
    MaculaTimeoutError,
    NoProviderError,
    NotFoundError,
    NotSharedError,
    ProviderError,
    RefusedError,
    RelayError,
    StreamError,
)
from macula_py.key import NodeKey, Profile
from macula_py.pool import (
    DhtRecord,
    Event,
    FoundRecords,
    LinkStatus,
    Pool,
    PoolEvent,
    Provider,
    RecordType,
    Seed,
    Served,
    Subscription,
)
from macula_py.stream import (
    Request,
    Stream,
    StreamData,
    StreamEnd,
    StreamEof,
    StreamFrame,
    StreamMode,
    StreamReply,
)
from macula_py.ucan import Policy, RealmMemberRequired, UcanRequired

__all__ = [
    "DEFAULT_CALL_TIMEOUT_MS",
    "DEFAULT_CONTENT_TIMEOUT_MS",
    "AlreadyAnsweredError",
    "ClosedError",
    "ContentUnavailableError",
    "DhtRecord",
    "Event",
    "FoundRecords",
    "InvalidArgumentError",
    "InvalidHandleError",
    "LinkStatus",
    "MaculaError",
    "MaculaTimeoutError",
    "NoProviderError",
    "NodeKey",
    "NotFoundError",
    "NotSharedError",
    "Policy",
    "Pool",
    "PoolEvent",
    "Profile",
    "Provider",
    "RealmMemberRequired",
    "ProviderError",
    "RecordType",
    "RefusedError",
    "RelayError",
    "Request",
    "Seed",
    "Served",
    "Stream",
    "StreamData",
    "StreamEnd",
    "StreamEof",
    "StreamError",
    "StreamFrame",
    "StreamMode",
    "StreamReply",
    "Subscription",
    "UcanRequired",
]

"""BOLT#4-style error taxonomy for CALL failures.

Ports the complete 17-entry table from ``macula_bolt4.erl`` (macula-io/macula,
src/peering/) -- adapted from Lightning Network's BOLT#4 onion-failure
codes. Every CALL ERROR frame carries one of these codes; `name` is
derived from `code` on the wire (see :mod:`macula.frame`'s ERROR builder),
never sent independently.
"""

from __future__ import annotations

from dataclasses import dataclass

RetryPolicy = str  # one of the RETRY_POLICIES values below, kept as plain str (no enum) to match this module's simple lookup-table shape


@dataclass(frozen=True)
class Bolt4Info:
    code: int
    name: str
    retry: RetryPolicy


_TABLE: list[Bolt4Info] = [
    Bolt4Info(0x00, "ok", "none"),
    Bolt4Info(0x01, "unknown_next_peer", "different_path"),
    Bolt4Info(0x02, "temporary_relay_failure", "same_path_after_backoff"),
    Bolt4Info(0x03, "relay_disabled", "different_path"),
    Bolt4Info(0x04, "node_not_found_at_target_relay", "caller_recompute_with_lookup"),
    Bolt4Info(0x05, "target_realm_refused", "application"),
    Bolt4Info(0x06, "loop_detected", "caller_recompute"),
    Bolt4Info(0x07, "expiry_too_soon", "caller_extends_deadline"),
    Bolt4Info(0x08, "upstream_congestion", "exponential_backoff"),
    Bolt4Info(0x09, "invalid_path_header", "caller_recompute"),
    Bolt4Info(0x0A, "crypto_puzzle_invalid", "crypto_drop"),
    Bolt4Info(0x0B, "realm_not_authoritative_here", "caller_recompute_with_lookup"),
    Bolt4Info(0x0C, "tombstoned", "application"),
    Bolt4Info(0x0D, "payload_too_large", "application"),
    Bolt4Info(0x0E, "signature_invalid", "crypto_drop"),
    Bolt4Info(0x0F, "unknown_error", "log_and_caution"),
    # A gated provider refused: the caller lacked a valid capability
    # (UCAN) for this procedure. Not retryable as-is -- the caller must
    # present valid authorization, so this is an application concern.
    Bolt4Info(0x10, "unauthorized", "application"),
]

BY_CODE: dict[int, Bolt4Info] = {entry.code: entry for entry in _TABLE}
BY_NAME: dict[str, Bolt4Info] = {entry.name: entry for entry in _TABLE}

# Convenience constants for the codes this SDK's own code actually raises/checks.
UNKNOWN_NEXT_PEER = BY_NAME["unknown_next_peer"].code
UNAUTHORIZED = BY_NAME["unauthorized"].code
UNKNOWN_ERROR = BY_NAME["unknown_error"].code
TEMPORARY_RELAY_FAILURE = BY_NAME["temporary_relay_failure"].code


class UnknownBolt4CodeError(Exception):
    pass


def name_for_code(code: int) -> str:
    entry = BY_CODE.get(code)
    if entry is None:
        raise UnknownBolt4CodeError(f"no BOLT#4 entry for code {code}")
    return entry.name


def code_for_name(name: str) -> int:
    entry = BY_NAME.get(name)
    if entry is None:
        raise UnknownBolt4CodeError(f"no BOLT#4 entry named {name!r}")
    return entry.code


_NON_RETRYABLE = {"none", "application", "crypto_drop"}


def is_retryable(name_or_code: str | int) -> bool:
    entry = BY_CODE[name_or_code] if isinstance(name_or_code, int) else BY_NAME[name_or_code]
    return entry.retry not in _NON_RETRYABLE

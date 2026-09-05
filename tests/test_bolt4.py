import pytest

from macula_py import bolt4


def test_table_has_all_17_entries_matching_the_erlang_reference():
    # code -> name pairs transcribed directly from macula_bolt4.erl's own table/0.
    expected = {
        0x00: "ok",
        0x01: "unknown_next_peer",
        0x02: "temporary_relay_failure",
        0x03: "relay_disabled",
        0x04: "node_not_found_at_target_relay",
        0x05: "target_realm_refused",
        0x06: "loop_detected",
        0x07: "expiry_too_soon",
        0x08: "upstream_congestion",
        0x09: "invalid_path_header",
        0x0A: "crypto_puzzle_invalid",
        0x0B: "realm_not_authoritative_here",
        0x0C: "tombstoned",
        0x0D: "payload_too_large",
        0x0E: "signature_invalid",
        0x0F: "unknown_error",
        0x10: "unauthorized",
    }
    assert {code: entry.name for code, entry in bolt4.BY_CODE.items()} == expected


def test_name_for_code_and_code_for_name_are_inverses():
    for code, entry in bolt4.BY_CODE.items():
        assert bolt4.name_for_code(code) == entry.name
        assert bolt4.code_for_name(entry.name) == code


def test_unknown_code_raises():
    with pytest.raises(bolt4.UnknownBolt4CodeError):
        bolt4.name_for_code(0x99)
    with pytest.raises(bolt4.UnknownBolt4CodeError):
        bolt4.code_for_name("not_a_real_code")


def test_is_retryable_matches_the_erlang_reference_classification():
    # `none`, `application`, `crypto_drop` are non-retryable; everything
    # else in the table is. Transcribed from macula_bolt4.erl's own
    # is_retryable/1 doc comment and table.
    non_retryable = {"ok", "target_realm_refused", "tombstoned", "payload_too_large", "crypto_puzzle_invalid", "signature_invalid", "unauthorized"}
    for entry in bolt4.BY_NAME.values():
        assert bolt4.is_retryable(entry.name) == (entry.name not in non_retryable)

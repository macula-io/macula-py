r"""Byte-exact vectors extracted directly from the real Erlang encoder
(macula_record_cbor:encode/1, macula-io/macula, src/record/), not
hand-derived -- these are proof of actual cross-implementation wire
agreement, not just self-consistency. Regenerate with the escript in this
comment if macula_record_cbor.erl's encoding ever changes:

    #!/usr/bin/env escript
    %% -*- erlang -*-
    main(_) ->
        code:add_path("<macula checkout>/_build/default/lib/macula/ebin"),
        Cases = [
            {<<"uint_0">>, 0},
            {<<"uint_1000000">>, 1000000},
            {<<"neg_42">>, -42},
            {<<"float_pi">>, 3.14159265358979},
            {<<"bool_true_as_1">>, 1},
            {<<"bool_false_as_0">>, 0},
            {<<"null">>, null},
            {<<"bytes_32">>, crypto:hash(sha256, <<"macula">>)},
            {<<"text_unicode">>, {text, unicode:characters_to_binary("hello \x{2603} macula")}},
            {<<"array">>, [1, {text, <<"two">>}, <<3>>, 4.0, null]},
            {<<"map_sorted">>, #{b => 1, 1 => {text, <<"a">>}}},
            {<<"nested">>, #{
                realm => binary:copy(<<0>>, 32),
                topic => {text, <<"macula.test">>},
                seq => 42,
                payload => #{nested => [1, 2, #{deep => 1}]},
                ttl_ms => null
            }}
        ],
        lists:foreach(fun({Name, Value}) ->
            io:format("~s ~s~n", [Name, binary:encode_hex(macula_record_cbor:encode(Value))])
        end, Cases).

Field-name keys use Erlang ATOMS (not plain binaries), matching how a real
frame is actually built (macula_frame.erl's frame_type/realm/etc. fields
are all atoms) -- atoms encode as CBOR text strings (major 3) via
macula_record_cbor's own atom_to_binary/1 clause, so the Python-side
equivalent is a plain `str` key, not `bytes`.
"""

import hashlib

from macula import cbor

GOLDEN_VECTORS: dict[str, tuple[cbor.Value, str]] = {
    "uint_0": (0, "00"),
    "uint_1000000": (1000000, "1a000f4240"),
    "neg_42": (-42, "3829"),
    "float_pi": (3.14159265358979, "fb400921fb54442d11"),
    "bool_true_as_1": (True, "01"),
    "bool_false_as_0": (False, "00"),
    "null": (None, "f6"),
    "bytes_32": (hashlib.sha256(b"macula").digest(), "5820d944dd4d6a3c1ca83a9c4a43d1fe259650cda22a212b84a5522a21d753681a41"),
    "text_unicode": ("hello ☃ macula", "7068656c6c6f20e29883206d6163756c61"),
    "array": ([1, "two", bytes([3]), 4.0, None], "85016374776f4103fb4010000000000000f6"),
    "map_sorted": ({"b": 1, 1: "a"}, "a2016161616201"),
    "nested": (
        {
            "realm": bytes(32),
            "topic": "macula.test",
            "seq": 42,
            "payload": {"nested": [1, 2, {"deep": 1}]},
            "ttl_ms": None,
        },
        "a563736571182a657265616c6d5820000000000000000000000000000000000000000000000000000000000000000065746f7069636b6d6163756c612e746573746674746c5f6d73f6677061796c6f6164a1666e6573746564830102a1646465657001",
    ),
}


def test_encode_matches_the_real_erlang_encoder_byte_for_byte():
    mismatches = []
    for name, (value, want_hex) in GOLDEN_VECTORS.items():
        got_hex = cbor.encode(value).hex()
        if got_hex != want_hex:
            mismatches.append(f"{name}: got {got_hex}, want {want_hex}")
    assert not mismatches, "\n".join(mismatches)


def test_decode_of_the_golden_bytes_round_trips_to_the_same_value():
    for name, (value, want_hex) in GOLDEN_VECTORS.items():
        decoded = cbor.decode(bytes.fromhex(want_hex))
        assert decoded == value, f"{name}: decoded {decoded!r}, want {value!r}"

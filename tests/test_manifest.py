import pytest

from macula_py import manifest


def test_block_mcid_is_34_bytes_version_codec_raw_hash():
    mcid = manifest.block_mcid(b"hello")
    assert len(mcid) == 34
    assert mcid[0] == manifest.VERSION
    assert mcid[1] == manifest.CODEC_RAW


def test_is_chunked_distinguishes_raw_from_manifest_mcids():
    raw = manifest.block_mcid(b"small content")
    assert not manifest.is_chunked(raw)

    big = b"x" * (manifest.DEFAULT_CHUNK_SIZE * 3)
    m, _chunks = manifest.create(big)
    assert manifest.is_chunked(m["mcid"])


def test_is_chunked_rejects_a_wrong_size_mcid():
    with pytest.raises(manifest.InvalidMcidError):
        manifest.is_chunked(b"too short")


def test_verify_block_hash_accepts_a_correct_block():
    data = b"some content"
    mcid = manifest.block_mcid(data)
    manifest.verify_block_hash(mcid, data)  # does not raise


def test_verify_block_hash_rejects_a_tampered_block():
    data = b"some content"
    mcid = manifest.block_mcid(data)
    with pytest.raises(manifest.ManifestVerifyError):
        manifest.verify_block_hash(mcid, b"different content")


def test_verify_block_hash_rejects_a_manifest_mcid():
    big = b"x" * (manifest.DEFAULT_CHUNK_SIZE * 3)
    m, _chunks = manifest.create(big)
    with pytest.raises(manifest.InvalidMcidError):
        manifest.verify_block_hash(m["mcid"], big)


def test_create_with_data_under_one_chunk_produces_a_single_chunk():
    data = b"small"
    m, chunks = manifest.create(data)
    assert m["chunk_count"] == 1
    assert len(chunks) == 1
    assert chunks[0] == data
    assert m["size"] == len(data)


def test_create_with_empty_data():
    m, chunks = manifest.create(b"")
    assert m["chunk_count"] == 0
    assert chunks == []
    assert m["size"] == 0


def test_create_round_trips_through_verify():
    data = b"y" * (manifest.DEFAULT_CHUNK_SIZE * 2 + 500)
    m, chunks = manifest.create(data, name="big.bin")
    assert m["chunk_count"] == 3
    reassembled = b"".join(chunks)
    assert reassembled == data
    manifest.verify(m, reassembled)  # does not raise


def test_verify_rejects_wrong_size():
    data = b"z" * 1000
    m, _chunks = manifest.create(data)
    with pytest.raises(manifest.ManifestVerifyError):
        manifest.verify(m, data + b"extra")


def test_verify_rejects_tampered_content_same_size():
    data = bytearray(b"a" * (manifest.DEFAULT_CHUNK_SIZE + 100))
    m, chunks = manifest.create(bytes(data))
    tampered = bytes(data[:-1] + b"b")  # same length, last byte changed
    with pytest.raises(manifest.ManifestVerifyError):
        manifest.verify(m, tampered)


def test_chunk_mcid_matches_block_mcid_of_that_chunk():
    data = b"c" * (manifest.DEFAULT_CHUNK_SIZE * 2 + 1)
    m, chunks = manifest.create(data)
    for i, chunk in enumerate(chunks):
        assert manifest.chunk_mcid(m, i) == manifest.block_mcid(chunk)


def test_chunk_mcid_rejects_out_of_range_index():
    m, _chunks = manifest.create(b"small")
    with pytest.raises(IndexError):
        manifest.chunk_mcid(m, 5)


def test_from_wire_round_trip():
    data = b"d" * (manifest.DEFAULT_CHUNK_SIZE + 1)
    m, _chunks = manifest.create(data, name="round.bin")
    # Simulate the wire round trip a real _content.get_manifest reply
    # would carry -- a plain map, no special encoding needed since this
    # wire's own "atoms encode as text" convention already matches a
    # Python str-keyed dict directly.
    from_wire = manifest.from_wire(m)
    assert from_wire == m


def test_from_wire_rejects_a_map_with_no_mcid():
    with pytest.raises(manifest.InvalidManifestError):
        manifest.from_wire({"chunks": []})


def test_from_wire_rejects_a_map_with_no_chunks():
    with pytest.raises(manifest.InvalidManifestError):
        manifest.from_wire({"mcid": bytes(34)})


def test_from_wire_fills_in_defaults_for_missing_fields():
    parsed = manifest.from_wire({"mcid": bytes(34), "chunks": []})
    assert parsed["name"] == "unnamed"
    assert parsed["chunk_size"] == manifest.DEFAULT_CHUNK_SIZE
    assert parsed["hash_algorithm"] == "blake3"


# Regression guards for two real gaps, same bug family as manifest.rs's
# from_wire fixes in the Rust reference: a malformed field from an
# untrusted peer used to reach a bare builtin exception deep in
# content.get()'s fetch loop or manifest.verify() -- an IndexError or a
# ValueError, neither a library-specific error type this module's own
# callers are documented to catch -- rather than failing cleanly at the
# parse boundary where the bad field is actually detected.

def test_from_wire_rejects_a_non_positive_chunk_size():
    for bad_size in (0, -1, -262144):
        with pytest.raises(manifest.InvalidManifestError):
            manifest.from_wire({"mcid": bytes(34), "chunks": [], "chunk_size": bad_size})


def test_from_wire_rejects_a_chunk_count_that_does_not_match_the_chunks_list():
    chunk = {"index": 0, "offset": 0, "size": 10, "hash": bytes(32)}
    # Claims 5 entries, only 1 actually present.
    with pytest.raises(manifest.InvalidManifestError):
        manifest.from_wire({"mcid": bytes(34), "chunks": [chunk], "chunk_count": 5})
    # Claims 0 entries, 1 actually present -- also a mismatch, not just
    # the over-claiming direction.
    with pytest.raises(manifest.InvalidManifestError):
        manifest.from_wire({"mcid": bytes(34), "chunks": [chunk], "chunk_count": 0})


def test_from_wire_rejects_a_non_integer_chunk_count():
    # A float that numerically equals len(chunks) would pass a bare `!=`
    # check and only fail later, inside content.get()'s
    # `range(chunk_count)` -- a bare TypeError, not this module's error
    # type. Caught adversarially; chunk_size already had this guard,
    # chunk_count didn't.
    chunk = {"index": 0, "offset": 0, "size": 10, "hash": bytes(32)}
    for bad_count in (1.0, "1", None):
        with pytest.raises(manifest.InvalidManifestError):
            manifest.from_wire({"mcid": bytes(34), "chunks": [chunk], "chunk_count": bad_count})


def test_from_wire_rejects_a_chunk_entry_with_a_malformed_hash():
    # More reachable than the chunk_count mismatch above: this fires at
    # index 0 of content.get()'s fetch loop, before a single chunk is
    # fetched -- chunk_mcid() -> make_mcid() does `bytes(...) + digest`,
    # raising a bare ValueError/TypeError for a wrong length or type.
    # A missing hash (defaulted to b"") is exactly as broken, just
    # deferred to the same call site -- must be rejected here too.
    bad_hashes = [b"short", bytes(33), 42, None, "0" * 32]
    for bad_hash in bad_hashes:
        chunk = {"index": 0, "offset": 0, "size": 10, "hash": bad_hash}
        with pytest.raises(manifest.InvalidManifestError):
            manifest.from_wire({"mcid": bytes(34), "chunks": [chunk], "chunk_count": 1})
    # Missing entirely (not just a bad value) -- must not silently
    # default to something guaranteed to fail later.
    with pytest.raises(manifest.InvalidManifestError):
        manifest.from_wire(
            {"mcid": bytes(34), "chunks": [{"index": 0, "offset": 0, "size": 10}], "chunk_count": 1}
        )


def test_from_wire_coerces_an_unrecognized_hash_algorithm_to_blake3():
    # Matches both reference implementations exactly (macula_manifest.erl's
    # to_algorithm/1, manifest.rs's Algorithm::from_name): an unrecognized
    # algorithm string coerces to blake3, it is not an error. Left
    # uncoerced, it only failed later inside verify()'s _hash() call --
    # a bare ValueError, after every chunk had already been fetched.
    for bad_algo in ("md5", "sha1", "", 7, None):
        parsed = manifest.from_wire({"mcid": bytes(34), "chunks": [], "hash_algorithm": bad_algo})
        assert parsed["hash_algorithm"] == "blake3"
    # A recognized non-default algorithm passes through unchanged.
    parsed = manifest.from_wire({"mcid": bytes(34), "chunks": [], "hash_algorithm": "sha256"})
    assert parsed["hash_algorithm"] == "sha256"


def test_from_wire_accepts_a_consistent_chunk_count_and_positive_chunk_size():
    chunk = {"index": 0, "offset": 0, "size": 10, "hash": bytes(32)}
    parsed = manifest.from_wire(
        {"mcid": bytes(34), "chunks": [chunk], "chunk_count": 1, "chunk_size": 4096}
    )
    assert parsed["chunk_count"] == 1
    assert len(parsed["chunks"]) == 1


# Golden values generated by running the REAL Erlang macula_manifest:create/2
# directly (via escript, ASDF_ERLANG_VERSION=28.4.2) against 678125 bytes of
# repeating data, forcing exactly 3 chunks (2 full 256 KiB chunks + one
# 153837-byte remainder) -- covering the odd-final-chunk Merkle-fold case
# (macula_manifest.erl's fold_pairs/2 pairs a lone last hash with ITSELF,
# not with nothing) as well as the multi-round fold (3 hashes -> 2 -> 1).
_GOLDEN_DATA = b"macula-content-chunk-test-data-" * 21875
_GOLDEN_MCID = "015635d1e4488d5c53b20a902f9568bf16de898d0909c3503c40cd0d6c5303c04e70"
_GOLDEN_ROOT_HASH = "c6f160712a9204347db1065f927a9aea4915c014e1b412383b7f62204ab247bf"
_GOLDEN_CHUNK_HASHES = [
    "c2de358a97ad5e49ec6792a07bc21b614530bc4c45cd6a967e27a31dcab70243",
    "c36349f3cb1b62abd80b85ac3cf0ed36c7328dbc3d97c4fc077d351ab379c69f",
    "db23a3d09b8448b6aceda83a1fef8de499830754b460f4a186ddb4ecb05b7bf4",
]


def test_create_matches_the_real_erlang_manifest_byte_for_byte():
    assert len(_GOLDEN_DATA) == 678125
    m, chunks = manifest.create(_GOLDEN_DATA, name="test.bin")
    assert m["chunk_count"] == 3
    assert m["mcid"].hex() == _GOLDEN_MCID
    assert m["root_hash"].hex() == _GOLDEN_ROOT_HASH
    assert [c["hash"].hex() for c in m["chunks"]] == _GOLDEN_CHUNK_HASHES
    assert [c["offset"] for c in m["chunks"]] == [0, 262144, 524288]
    assert [c["size"] for c in m["chunks"]] == [262144, 262144, 153837]
    assert len(chunks) == 3

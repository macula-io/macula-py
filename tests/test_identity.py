from pathlib import Path

import pytest

from macula.identity import DEFAULT_PUZZLE_DIFFICULTY, KeyPair, LoadKeyError


def test_generate_produces_a_valid_default_difficulty_identity():
    kp = KeyPair.generate()
    assert len(kp.node_id()) == 32
    assert kp.has_valid_puzzle(DEFAULT_PUZZLE_DIFFICULTY)


def test_generate_without_puzzle_skips_grinding():
    # Not the default -- an explicit opt-out, for tests that don't want
    # grinding cost and don't talk to a real station.
    kp = KeyPair.generate(puzzle=False)
    assert len(kp.node_id()) == 32


def test_puzzle_evidence_is_sha256_of_the_node_id():
    import hashlib

    kp = KeyPair.generate(puzzle=False)
    assert kp.puzzle_evidence() == hashlib.sha256(kp.node_id()).digest()


def test_has_valid_puzzle_at_difficulty_zero_is_always_true():
    kp = KeyPair.generate(puzzle=False)
    assert kp.has_valid_puzzle(0)


def test_sign_and_verify_round_trip():
    kp = KeyPair.generate(puzzle=False)
    message = b"hello macula"
    sig = kp.sign(message)
    assert len(sig) == 64
    assert KeyPair.verify(kp.node_id(), message, sig)


def test_verify_rejects_a_tampered_message():
    kp = KeyPair.generate(puzzle=False)
    sig = kp.sign(b"original")
    assert not KeyPair.verify(kp.node_id(), b"tampered", sig)


def test_verify_rejects_a_wrong_node_id():
    a = KeyPair.generate(puzzle=False)
    b = KeyPair.generate(puzzle=False)
    sig = a.sign(b"hello")
    assert not KeyPair.verify(b.node_id(), b"hello", sig)


def test_verify_rejects_a_malformed_node_id_without_raising():
    kp = KeyPair.generate(puzzle=False)
    sig = kp.sign(b"hello")
    assert not KeyPair.verify(b"too-short", b"hello", sig)


def test_from_seed_is_deterministic():
    seed = bytes(range(32))
    a = KeyPair.from_seed(seed)
    b = KeyPair.from_seed(seed)
    assert a.node_id() == b.node_id()
    # Different seeds must not collide.
    other = KeyPair.from_seed(bytes(range(1, 33)))
    assert other.node_id() != a.node_id()


def test_from_seed_rejects_wrong_length():
    with pytest.raises(ValueError):
        KeyPair.from_seed(b"too-short")


def test_save_and_load_round_trip(tmp_path: Path):
    kp = KeyPair.generate(puzzle=False)
    path = tmp_path / "identity.key"
    kp.save(path)

    loaded = KeyPair.load(path)
    assert loaded.node_id() == kp.node_id()
    # The loaded identity must still be able to sign/verify identically.
    sig = loaded.sign(b"round trip")
    assert KeyPair.verify(kp.node_id(), b"round trip", sig)


def test_save_writes_the_exact_wire_key_file_format(tmp_path: Path):
    kp = KeyPair.generate(puzzle=False)
    path = tmp_path / "identity.key"
    kp.save(path)

    blob = path.read_bytes()
    assert blob[:14] == b"macula-v2-key\x00"
    assert len(blob) == 14 + 32 + 32
    assert blob[14:46] == kp.node_id()


def test_save_sets_0600_permissions(tmp_path: Path):
    kp = KeyPair.generate(puzzle=False)
    path = tmp_path / "identity.key"
    kp.save(path)
    assert (path.stat().st_mode & 0o777) == 0o600


def test_load_rejects_a_garbage_file(tmp_path: Path):
    path = tmp_path / "garbage.key"
    path.write_bytes(b"not a key file")
    with pytest.raises(LoadKeyError):
        KeyPair.load(path)


def test_load_rejects_a_tampered_public_key(tmp_path: Path):
    kp = KeyPair.generate(puzzle=False)
    path = tmp_path / "identity.key"
    kp.save(path)

    blob = bytearray(path.read_bytes())
    blob[14] ^= 0xFF  # flip a bit in the stored public key
    path.write_bytes(bytes(blob))

    with pytest.raises(LoadKeyError):
        KeyPair.load(path)

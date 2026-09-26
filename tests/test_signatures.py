"""pq_hybrid is the LAMPS composite id-MLDSA87-RSA4096-PSS-SHA512: the draft's
own vector verifies through this binding and every alteration of it is
refused, a composite macula 12 signed verifies, and keys made here sign what
verifies under their own public key. No station is needed; the library is."""

import hashlib
import os
import stat
from pathlib import Path

import pytest

from macula_py import ClosedError, NodeKey

FIXTURES = Path(__file__).parent / "fixtures"

PINNED = {
    "lamps_mldsa87_rsa4096_pss_sha512/m.bin": "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
    "lamps_mldsa87_rsa4096_pss_sha512/pk.bin": "88560e139b35d0738857f9c8e29bbcfb108e3539bd2bf6f4994bb4b34beb019d",
    "lamps_mldsa87_rsa4096_pss_sha512/s.bin": "95e17c93e9c1d6b5c3c4bae9d8687cd1606e232dca0af38e437e7e2e16894303",
    "lamps_mldsa87_rsa4096_pss_sha512/s_with_context.bin": "7261d9aeaaee3eb2612bb868d00d8eb6e174717bc427e8e6fa24cb7a73dcdeec",
    "lamps_composite_zero_dropped/sig.bin": "4e43a85def2b0acec014724d7d4b23ac86685ef35f28a9be85d9aff4a7cd30cd",
    "macula_12_cross/macula_signed/m.bin": "1ca0f63f379105e83a1767e1f6ceda6dcf723e2c5e298d724753716cc500e235",
    "macula_12_cross/macula_signed/pk.bin": "f5a34daa24d26e9cb4bb3bbb8400e3d9b8d82fbef648f22472b5e37eeb1bec79",
    "macula_12_cross/macula_signed/s.bin": "90f840bcb0b421804e669a457e03d9697a5f5f13608a261b72dc6c85fce032fc",
}

# The ML-DSA-87 half of a composite signature, in bytes.
MLDSA_SIGNATURE_BYTES = 4627


def fixture(name: str) -> bytes:
    data = (FIXTURES / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == PINNED[name], f"{name} drifted from the pinned bytes"
    return data


def flipped(data: bytes, at: int) -> bytes:
    out = bytearray(data)
    out[at] ^= 1
    return bytes(out)


class TestDraftVector:
    def test_the_drafts_signature_verifies(self):
        m, pk, s = (fixture(f"lamps_mldsa87_rsa4096_pss_sha512/{n}") for n in ("m.bin", "pk.bin", "s.bin"))
        assert NodeKey.verify(m, s, pk, "pq_hybrid") is True

    @pytest.mark.parametrize("at", [0, MLDSA_SIGNATURE_BYTES - 1, MLDSA_SIGNATURE_BYTES, -1])
    def test_a_flipped_bit_in_either_half_is_refused(self, at):
        m, pk, s = (fixture(f"lamps_mldsa87_rsa4096_pss_sha512/{n}") for n in ("m.bin", "pk.bin", "s.bin"))
        assert NodeKey.verify(m, flipped(s, at), pk, "pq_hybrid") is False

    def test_an_altered_message_is_refused(self):
        m, pk, s = (fixture(f"lamps_mldsa87_rsa4096_pss_sha512/{n}") for n in ("m.bin", "pk.bin", "s.bin"))
        assert NodeKey.verify(flipped(m, 0), s, pk, "pq_hybrid") is False

    def test_a_signature_made_with_a_context_is_refused(self):
        m, pk = (fixture(f"lamps_mldsa87_rsa4096_pss_sha512/{n}") for n in ("m.bin", "pk.bin"))
        s = fixture("lamps_mldsa87_rsa4096_pss_sha512/s_with_context.bin")
        assert NodeKey.verify(m, s, pk, "pq_hybrid") is False

    def test_the_rsa_half_missing_its_leading_zero_is_refused(self):
        m, pk = (fixture(f"lamps_mldsa87_rsa4096_pss_sha512/{n}") for n in ("m.bin", "pk.bin"))
        assert NodeKey.verify(m, fixture("lamps_composite_zero_dropped/sig.bin"), pk, "pq_hybrid") is False

    def test_under_the_wrong_profile_it_is_refused(self):
        m, pk, s = (fixture(f"lamps_mldsa87_rsa4096_pss_sha512/{n}") for n in ("m.bin", "pk.bin", "s.bin"))
        assert NodeKey.verify(m, s, pk, "pq_pure") is False


def test_a_composite_macula_12_signed_verifies():
    m, pk, s = (fixture(f"macula_12_cross/macula_signed/{n}") for n in ("m.bin", "pk.bin", "s.bin"))
    assert NodeKey.verify(m, s, pk, "pq_hybrid") is True
    assert NodeKey.verify(flipped(m, 0), s, pk, "pq_hybrid") is False


@pytest.mark.parametrize("profile", ["pq_pure", "pq_hybrid"])
async def test_a_generated_key_signs_what_verifies_under_its_own_key(profile):
    key = await NodeKey.generate(profile)
    try:
        assert key.profile() == profile
        assert len(key.node_id()) == 32
        assert key.node_id_hex() == key.node_id().hex()
        signature = key.sign(b"a message")
        assert NodeKey.verify(b"a message", signature, key.public_key(), profile) is True
        assert NodeKey.verify(b"another", signature, key.public_key(), profile) is False
    finally:
        key.free()


async def test_a_key_is_saved_readable_by_its_owner_only_and_loads_back_as_the_same_node(tmp_path):
    path = tmp_path / "node.key"
    created = await NodeKey.load_or_create(path, "pq_pure")
    loaded = NodeKey.load(path, "pq_pure")
    again = await NodeKey.load_or_create(path, "pq_pure")
    try:
        assert loaded.node_id() == created.node_id() == again.node_id()
        if os.name == "posix":
            assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0
        with pytest.raises(Exception):
            NodeKey.load(path, "pq_hybrid")
    finally:
        for k in (created, loaded, again):
            k.free()


def test_a_freed_key_is_refused_loudly():
    import asyncio

    key = asyncio.run(NodeKey.generate("pq_pure"))
    key.free()
    with pytest.raises(ClosedError, match="freed"):
        key.node_id()

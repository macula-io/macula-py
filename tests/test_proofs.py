"""The device request proof (realm proof v2, macula-realm#29) and the
ownership proof (v2, mcl-om#7): the bytes each signs are the verifier's own,
byte for byte (the vectors in tests/fixtures), a proof made here verifies
over them and over nothing else, and what a verifier would refuse is refused
at the source. No station is needed; the library is."""

import asyncio
import hashlib
from pathlib import Path

import pytest

from macula_py import InvalidArgumentError, NodeKey
from macula_py.device_request import device_request_message
from macula_py.ownership_proof import ownership_proof_message

FIXTURES = Path(__file__).parent / "fixtures"

PINNED = {
    "device_request/message.hex": "e35e0bf847bd0a8c41ae5e96c4e128f67e318c28a752a13325df10fc4e68fc93",
    "ownership_proof/message.hex": "d03c2ac3fac87b1361e26261457bfd14a349d7e2131c25feaf3c8fc34a336f7b",
    "ownership_proof/identity.hex": "b265848773695fc72f4f589517c17bcabcfaac1d6fba03577a225371d1df6fdb",
}

IO_MACULA = hashlib.sha256(b"io.macula").digest()
JOIN = "macula_realm.join_session"
MEMBERSHIP = "macula_realm.membership_ucan"
LEARN_LINK = "mcl-graph/learn_link"


def fixture_hex(name: str) -> bytes:
    data = (FIXTURES / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == PINNED[name], f"{name} drifted from the pinned bytes"
    return bytes.fromhex(data.decode().strip())


@pytest.fixture(scope="module")
def key():
    # One key for the module; the calls under test are synchronous.
    return asyncio.run(NodeKey.generate("pq_pure"))


class TestDeviceRequest:
    # The realm's vector: a carried key of 2592 bytes of 0x07, io.macula, the
    # join session, at 1790000000000 with a zero nonce, over this body.
    BODY = '{"device_info": {"hostname": "laptop.local", "note": null}, "n": 1e2, "z": -0.0, "f": 1.5}'

    def test_the_message_is_the_realms_vector(self):
        message = device_request_message(bytes([7]) * 2592, IO_MACULA, JOIN, 1790000000000, bytes(16), self.BODY, "http")
        assert message == fixture_hex("device_request/message.hex")

    def test_a_mapping_is_signed_as_its_json_under_the_realms_rule(self):
        body = {"device_info": {"hostname": "laptop.local", "note": None}, "n": 1e2, "z": -0.0, "f": 1.5}
        message = device_request_message(bytes([7]) * 2592, IO_MACULA, JOIN, 1790000000000, bytes(16), body, "http")
        assert message == fixture_hex("device_request/message.hex")

    @pytest.mark.parametrize("rule", ["http", "mesh"])
    def test_a_proof_verifies_over_its_request_and_no_other(self, key, rule):
        request = {"public_key": "a2V5", "ttl_seconds": 3600}
        proof = key.device_request_proof(IO_MACULA, MEMBERSHIP, request, rule)
        assert proof["v"] == 2 and len(proof["nonce"]) == 32
        signature = bytes.fromhex(proof["signature"])
        nonce = bytes.fromhex(proof["nonce"])

        def message(r):
            return device_request_message(key.public_key(), IO_MACULA, MEMBERSHIP, proof["timestamp"], nonce, r, rule)

        assert NodeKey.verify(message(request), signature, key.public_key(), "pq_pure")
        assert not NodeKey.verify(message({**request, "ttl_seconds": 7200}), signature, key.public_key(), "pq_pure")
        assert key.device_request_proof(IO_MACULA, MEMBERSHIP, request, rule)["nonce"] != proof["nonce"]

    @pytest.mark.parametrize("rule", ["http", "mesh"])
    def test_a_request_carrying_a_caller_is_refused(self, key, rule):
        # The realm drops a top-level "caller" when it rebuilds the request:
        # the caller is the verified signer, never a field.
        with pytest.raises(InvalidArgumentError):
            key.device_request_proof(IO_MACULA, MEMBERSHIP, {"public_key": "a2V5", "caller": "me"}, rule)

    def test_a_boolean_is_refused(self, key):
        with pytest.raises(InvalidArgumentError):
            key.device_request_proof(IO_MACULA, JOIN, '{"ok": true}', "http")
        with pytest.raises(TypeError):
            key.device_request_proof(IO_MACULA, MEMBERSHIP, {"ok": True}, "mesh")

    def test_an_unknown_rule_is_refused(self, key):
        with pytest.raises(ValueError):
            key.device_request_proof(IO_MACULA, JOIN, {}, "grpc")  # type: ignore[arg-type]


class TestOwnershipProof:
    # mcl_om's vector: io.macula, learn_link, at 1790000000000 with nonce
    # 00..0f, over fields of every CBOR type. The caller in them is left out,
    # as a verifier reads a delivered payload.
    FIELDS = {
        "subject": "entity:alpha",
        "predicate": "knows",
        "object": "entity:beta",
        "confidence": 0.75,
        "weight": 3,
        "offset": -7,
        "digest": b"\x01\x02\x03",
        "note": None,
        "tags": ["a", "b"],
        "metadata": {"source": "field-notes", "page": 12},
        "caller": "a caller is sent, not signed",
    }

    def test_the_message_is_mcl_oms_vector(self):
        identity = fixture_hex("ownership_proof/identity.hex")
        message = ownership_proof_message(identity, IO_MACULA, LEARN_LINK, 1790000000000, bytes(range(16)), self.FIELDS)
        assert message == fixture_hex("ownership_proof/message.hex")

    def test_a_proof_verifies_over_its_fields_and_no_other(self, key):
        payload = {"subject": "entity:alpha", "weight": 3, "digest": b"\x01"}
        signed = key.ownership_proof(IO_MACULA, LEARN_LINK, payload)
        block = signed["asserted_by"]
        proof = block["proof"]
        assert block["identity"] == key.node_id_hex()
        assert proof["v"] == 2 and bytes.fromhex(proof["public"]) == key.public_key()
        assert {k: v for k, v in signed.items() if k != "asserted_by"} == payload

        def message(fields):
            return ownership_proof_message(
                key.node_id(), IO_MACULA, LEARN_LINK, proof["timestamp"], bytes.fromhex(proof["nonce"]), fields
            )

        signature = bytes.fromhex(proof["signature"])
        assert NodeKey.verify(message(payload), signature, key.public_key(), "pq_pure")
        assert not NodeKey.verify(message({**payload, "weight": 4}), signature, key.public_key(), "pq_pure")

    def test_an_earlier_asserted_by_is_replaced(self, key):
        once = key.ownership_proof(IO_MACULA, LEARN_LINK, {"a": 1})
        twice = key.ownership_proof(IO_MACULA, LEARN_LINK, once)
        assert once["asserted_by"]["proof"]["nonce"] != twice["asserted_by"]["proof"]["nonce"]
        assert set(twice) == {"a", "asserted_by"}

    def test_a_payload_carrying_a_caller_is_refused(self, key):
        with pytest.raises(InvalidArgumentError):
            key.ownership_proof(IO_MACULA, LEARN_LINK, {"a": 1, "caller": "me"})

    def test_a_boolean_is_refused(self, key):
        with pytest.raises(TypeError):
            key.ownership_proof(IO_MACULA, LEARN_LINK, {"ok": True})

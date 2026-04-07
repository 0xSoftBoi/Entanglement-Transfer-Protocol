"""
Tests for HSM-backed KeyPair behavior.

These tests focus on the custody boundary: HSM-backed keypairs must not
materialize local private keys, but core operations should still work through
the HSM interface.
"""

from src.ltp import CommitmentNetwork, Entity, LTPProtocol, KeyPair
from src.ltp.hsm import SoftwareHSM
from src.ltp.primitives import MLDSA


def _network() -> CommitmentNetwork:
    net = CommitmentNetwork()
    for node_id, region in [
        ("node-us-east-1", "US-East"),
        ("node-us-west-1", "US-West"),
        ("node-eu-west-1", "EU-West"),
        ("node-eu-east-1", "EU-East"),
    ]:
        net.add_node(node_id, region)
    return net


def test_hsm_backed_keypair_exposes_public_material_only():
    hsm = SoftwareHSM()
    kp = KeyPair.generate("alice-hsm", hsm=hsm)

    assert kp.is_hsm_backed is True
    assert kp.dk == b""
    assert kp.sk == b""

    signature = kp.sign(b"test-message")
    assert MLDSA.verify(kp.vk, b"test-message", signature)


def test_hsm_backed_receiver_can_unseal():
    hsm = SoftwareHSM()
    receiver = KeyPair.generate("bob-hsm", hsm=hsm)
    payload = b"secret payload"

    from src.ltp.keypair import SealedBox

    sealed = SealedBox.seal(payload, receiver.ek)
    assert SealedBox.unseal(sealed, receiver) == payload


def test_protocol_commit_signs_with_hsm_backed_sender():
    hsm = SoftwareHSM()
    sender = KeyPair.generate("sender-hsm", hsm=hsm)
    receiver = KeyPair.generate("receiver-local")
    protocol = LTPProtocol(_network())

    entity = Entity(content=b"hsm-backed commit", shape="text/plain")
    entity_id, record, cek = protocol.commit(entity, sender, n=4, k=2)

    assert record.verify_signature(sender.vk)

    sealed = protocol.lattice(entity_id, record, cek, receiver)
    assert protocol.materialize(sealed, receiver) == b"hsm-backed commit"

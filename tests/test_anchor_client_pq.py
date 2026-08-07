from __future__ import annotations

import pytest

from src.ltp.anchor.client import AnchorClient
from src.ltp.anchor.submission import AnchorSubmission
from src.ltp.primitives import MLDSA


class _ViewCall:
    def __init__(self, result: bytes) -> None:
        self._result = result

    def call(self) -> bytes:
        return self._result


class _FakeFunctions:
    def __init__(self) -> None:
        self.anchor_message_args = None
        self.anchor_signed_args = None
        self.transition_message_args = None
        self.transition_signed_args = None

    def anchorAuthorizationMessage(self, *args):
        self.anchor_message_args = args
        return _ViewCall(b"solidity-anchor-authorization")

    def anchorSigned(self, *args):
        self.anchor_signed_args = args
        return ("anchorSigned", args)

    def stateTransitionAuthorizationMessage(self, *args):
        self.transition_message_args = args
        return _ViewCall(b"solidity-transition-authorization")

    def transitionStateSigned(self, *args):
        self.transition_signed_args = args
        return ("transitionStateSigned", args)

    def eip8355SignerId(self, public_key):
        return _ViewCall(b"\x55" * 32)


class _FakeContract:
    def __init__(self) -> None:
        self.functions = _FakeFunctions()


def _client() -> AnchorClient:
    client = AnchorClient.__new__(AnchorClient)
    client._chain_id = 42069
    client._contract = _FakeContract()
    client._send_tx = lambda fn: {"transactionHash": b"\x12" * 32}
    return client


def _submission() -> AnchorSubmission:
    return AnchorSubmission(
        anchor_digest=b"\x01" * 32,
        entity_id_hash=b"\x02" * 32,
        merkle_root=b"\x03" * 32,
        policy_hash=b"\x04" * 32,
        signer_vk_hash=b"\x00" * 32,
        sequence=7,
        valid_until=1_900_000_000,
        target_chain_id=42069,
        receipt_type="COMMIT",
    )


def _mock_real_signing(monkeypatch, captured):
    monkeypatch.setattr(MLDSA, "_use_real_backend", classmethod(lambda cls: True))

    def sign(cls, signing_key, message):
        captured["signing_key"] = signing_key
        captured["message"] = message
        return b"\x99" * 3309

    def verify(cls, public_key, message, signature):
        captured["verify"] = (public_key, message, signature)
        return True

    monkeypatch.setattr(MLDSA, "sign", classmethod(sign))
    monkeypatch.setattr(MLDSA, "verify", classmethod(verify))


def test_anchor_signed_signs_solidity_wire_message(monkeypatch):
    client = _client()
    captured = {}
    _mock_real_signing(monkeypatch, captured)
    public_key = b"\x11" * 1952
    signing_key = b"\x22" * 4032
    submission = _submission()

    tx_hash = client.anchor_signed(submission, public_key, signing_key)

    assert tx_hash == "12" * 32
    assert captured["message"] == b"solidity-anchor-authorization"
    assert client._contract.functions.anchor_message_args == (
        submission.anchor_digest,
        submission.entity_id_hash,
        submission.merkle_root,
        submission.policy_hash,
        submission.sequence,
        submission.valid_until,
        0,
    )
    args = client._contract.functions.anchor_signed_args
    assert args[:4] == (
        submission.anchor_digest,
        submission.entity_id_hash,
        submission.merkle_root,
        submission.policy_hash,
    )
    assert args[4] == public_key
    assert args[5:8] == (submission.sequence, submission.valid_until, 0)
    assert args[8] == b"\x99" * 3309


def test_transition_signed_signs_solidity_wire_message(monkeypatch):
    client = _client()
    captured = {}
    _mock_real_signing(monkeypatch, captured)
    public_key = b"\x11" * 1952
    signing_key = b"\x22" * 4032

    client.transition_state_signed(
        b"\xaa" * 32,
        expected_state=2,
        new_state=3,
        public_key=public_key,
        signing_key=signing_key,
        sequence=8,
        valid_until=1_900_000_001,
    )

    assert captured["message"] == b"solidity-transition-authorization"
    assert client._contract.functions.transition_message_args == (
        b"\xaa" * 32,
        2,
        3,
        8,
        1_900_000_001,
    )
    assert client._contract.functions.transition_signed_args[-1] == b"\x99" * 3309


def test_anchor_signed_rejects_wrong_chain_before_signing(monkeypatch):
    client = _client()
    submission = _submission()
    submission.target_chain_id = 10

    with pytest.raises(ValueError, match="does not match client chain_id"):
        client.anchor_signed(submission, b"\x11" * 1952, b"\x22" * 4032)


def test_signed_path_refuses_poc_backend(monkeypatch):
    client = _client()
    monkeypatch.setattr(MLDSA, "_use_real_backend", classmethod(lambda cls: False))

    with pytest.raises(RuntimeError, match="real ML-DSA-65 backend"):
        client.anchor_signed(_submission(), b"\x11" * 1952, b"\x22" * 4032)


def test_eip8355_signer_id_uses_registry_wire_rule():
    client = _client()
    assert client.eip8355_signer_id(b"\x11" * 1952) == b"\x55" * 32

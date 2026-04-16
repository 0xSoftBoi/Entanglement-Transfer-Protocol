from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.ltp import CommitmentNetwork, KeyPair, LTPProtocol
from src.ltp.bridge.live import LiveBridge
from src.ltp.bridge.message import BridgeMessage


class _FailingEth:
    @property
    def block_number(self):
        raise RuntimeError("rpc unavailable")


class _StubAnchorClient:
    def __init__(self) -> None:
        self._w3 = SimpleNamespace(eth=_FailingEth())

    def anchor(self, submission) -> str:
        return "0x" + "12" * 32

    def is_anchored(self, anchor_digest: bytes) -> bool:
        return True

    def entity_state(self, entity_id_hash: bytes) -> int:
        return 2

    def signer_sequence(self, vk_hash: bytes) -> int:
        return 1


def _make_protocol() -> LTPProtocol:
    net = CommitmentNetwork()
    for node_id, region in [
        ("live-test-1", "US-East"),
        ("live-test-2", "US-West"),
        ("live-test-3", "EU-West"),
        ("live-test-4", "EU-East"),
        ("live-test-5", "AP-East"),
        ("live-test-6", "AP-South"),
    ]:
        net.add_node(node_id, region)
    return LTPProtocol(net)


def _make_message() -> BridgeMessage:
    return BridgeMessage(
        msg_type="token_lock",
        source_chain="ethereum",
        dest_chain="optimism",
        sender="0xAliceSender",
        recipient="0xAliceRecipient",
        payload={"token": "USDC", "amount": 100, "decimals": 6},
        nonce=0,
    )


def test_live_bridge_fails_closed_when_chain_height_query_fails():
    bridge = LiveBridge(
        protocol=_make_protocol(),
        anchor_client=_StubAnchorClient(),
        operator_keypair=KeyPair.generate("live-test-operator"),
        l2_verifier_keypair=KeyPair.generate("live-test-verifier"),
        source_chain="ethereum",
        dest_chain="optimism",
    )

    with pytest.raises(RuntimeError, match="fail closed"):
        bridge.transfer(_make_message())


def test_live_bridge_can_opt_into_simulated_finality_fallback():
    bridge = LiveBridge(
        protocol=_make_protocol(),
        anchor_client=_StubAnchorClient(),
        operator_keypair=KeyPair.generate("live-fallback-operator"),
        l2_verifier_keypair=KeyPair.generate("live-fallback-verifier"),
        source_chain="ethereum",
        dest_chain="optimism",
        allow_simulated_finality_fallback=True,
    )

    result = bridge.transfer(_make_message())

    assert result is not None
    assert result.block_height == 1000
    assert result.is_anchored_on_chain is True


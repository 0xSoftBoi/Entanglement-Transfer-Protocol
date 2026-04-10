from __future__ import annotations

import os

import pytest

from src.ltp.anchor.client import AnchorClient


def test_anchor_client_rejects_empty_required_fields():
    with pytest.raises(ValueError, match="rpc_url is required"):
        AnchorClient("", "0x1234567890123456789012345678901234567890", "0x" + "11" * 32, 1)

    with pytest.raises(ValueError, match="contract_address is required"):
        AnchorClient("http://localhost:8545", "", "0x" + "11" * 32, 1)

    with pytest.raises(ValueError, match="private_key is required"):
        AnchorClient("http://localhost:8545", "0x1234567890123456789012345678901234567890", "", 1)

    with pytest.raises(ValueError, match="positive integer"):
        AnchorClient(
            "http://localhost:8545",
            "0x1234567890123456789012345678901234567890",
            "0x" + "11" * 32,
            0,
        )


def test_verify_live_configuration_detects_unreachable_rpc(monkeypatch):
    client = object.__new__(AnchorClient)
    client._chain_id = 31337

    class _DisconnectedWeb3:
        def is_connected(self) -> bool:
            return False

    client._w3 = _DisconnectedWeb3()

    with pytest.raises(RuntimeError, match="could not connect"):
        client.verify_live_configuration()


def test_verify_live_configuration_detects_chain_id_mismatch():
    client = object.__new__(AnchorClient)
    client._chain_id = 1

    class _Eth:
        chain_id = 31337

    class _ConnectedWeb3:
        eth = _Eth()

        def is_connected(self) -> bool:
            return True

    client._w3 = _ConnectedWeb3()

    with pytest.raises(RuntimeError, match="chain_id mismatch"):
        client.verify_live_configuration()


def test_from_env_reports_invalid_integer(monkeypatch):
    monkeypatch.setenv("RPC_URL", "http://localhost:8545")
    monkeypatch.setenv("ANCHOR_REGISTRY", "0x1234567890123456789012345678901234567890")
    monkeypatch.setenv("OPERATOR_KEY", "0x" + "11" * 32)
    monkeypatch.setenv("CHAIN_ID", "not-an-int")

    with pytest.raises(EnvironmentError, match="Invalid integer env var CHAIN_ID"):
        AnchorClient.from_env()


def test_from_env_reports_invalid_float(monkeypatch):
    monkeypatch.setenv("RPC_URL", "http://localhost:8545")
    monkeypatch.setenv("ANCHOR_REGISTRY", "0x1234567890123456789012345678901234567890")
    monkeypatch.setenv("OPERATOR_KEY", "0x" + "11" * 32)
    monkeypatch.setenv("CHAIN_ID", "1")
    monkeypatch.setenv("ANCHOR_MAX_TPS", "not-a-float")

    with pytest.raises(EnvironmentError, match="Invalid float env var ANCHOR_MAX_TPS"):
        AnchorClient.from_env()

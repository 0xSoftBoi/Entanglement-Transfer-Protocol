"""Tests for development-only insecure transport guards."""

import pytest

import src.ltp.primitives as primitives
from src.ltp import AssuranceMode, CommitmentLog, CommitmentNode
from src.ltp.network.client import NodeClient
from src.ltp.network.server import NodeServer
from src.ltp.rest_server import CommitmentLogRestServer


@pytest.fixture(autouse=True)
def restore_assurance_mode():
    original = primitives.get_assurance_mode()
    yield
    primitives._assurance_mode = original


def test_nodeserver_rejected_in_production_mode():
    node = CommitmentNode("n1", "US-East")
    primitives._assurance_mode = AssuranceMode.PRODUCTION
    with pytest.raises(RuntimeError, match="development-only"):
        NodeServer(node, port=50052, host="localhost")


def test_nodeclient_rejected_in_compliance_strict_mode():
    primitives._assurance_mode = AssuranceMode.COMPLIANCE_STRICT
    with pytest.raises(RuntimeError, match="development-only"):
        NodeClient("localhost:50051")


def test_rest_server_rejected_in_production_mode():
    log = CommitmentLog()
    primitives._assurance_mode = AssuranceMode.PRODUCTION
    with pytest.raises(RuntimeError, match="development-only"):
        CommitmentLogRestServer(log, host="127.0.0.1", port=18080)

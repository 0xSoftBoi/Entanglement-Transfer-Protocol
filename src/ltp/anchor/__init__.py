"""
On-chain anchor state machine for the Lattice Transfer Protocol.

Manages entity lifecycle on-chain: UNKNOWN → COMMITTED → ANCHORED →
MATERIALIZED, with DISPUTED and DELETED terminal states.

Not to be confused with bridge/anchor.py (L1 bridge anchor), which handles
cross-chain message commitment. This package manages the on-chain entity
state machine that smart contracts use to track trust artifacts.

Reference: GSX_PRE_BLOCKCHAIN_ROADMAP.md §2.9-2.10

Runtime note:
  - This package defines the on-chain state machine and submission types.
  - `AnchorClient` is the environment-dependent RPC adapter that talks to a live
    registry contract via `web3`.
  - Callers that want fail-fast live setup should use `get_anchor_client(...,
    verify_live_config=True)` or call `AnchorClient.verify_live_configuration()`
    explicitly after construction.
"""

from .state import EntityState, VALID_TRANSITIONS, validate_transition
from .submission import AnchorSubmission

__all__ = [
    "EntityState",
    "VALID_TRANSITIONS",
    "validate_transition",
    "AnchorSubmission",
]


def get_anchor_client(
    rpc_url: str,
    contract_address: str,
    private_key: str,
    chain_id: int,
    verify_live_config: bool = False,
) -> "AnchorClient":
    """Factory for AnchorClient with optional fail-fast live RPC verification."""
    from .client import AnchorClient
    client = AnchorClient(rpc_url, contract_address, private_key, chain_id)
    if verify_live_config:
        client.verify_live_configuration()
    return client

"""
Abstract base for commitment network backends.

Every backend must implement CommitmentBackend.  The interface covers:
  1. Commitment log operations (append, fetch, verify)
  2. Finality semantics (instant, probabilistic, economic)
  3. Node registry (admission, eviction, staking)
  4. Economic hooks (compensate, slash, pricing)

The base class also exposes BackendCapabilities — a typed descriptor that
lets higher layers query what the backend supports without isinstance checks.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Finality model
# ---------------------------------------------------------------------------

class FinalityModel(Enum):
    """How a backend guarantees commitment finality."""
    INSTANT = "instant"                  # local / single-operator (no consensus)
    SINGLE_SLOT = "single-slot"          # Monad-style: 1-slot deterministic finality
    PROBABILISTIC = "probabilistic"      # Ethereum PoS: ~2 epochs (~12.8 min)
    ECONOMIC = "economic"                # restaking / EigenLayer style


# ---------------------------------------------------------------------------
# Backend capabilities descriptor
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BackendCapabilities:
    """Declarative descriptor of what a backend supports."""
    finality: FinalityModel
    max_tps: int                         # theoretical max commitments / second
    has_native_storage_proofs: bool       # hardware-level or protocol-level PoS
    has_slashing: bool                    # economic penalties for misbehavior
    has_node_registry: bool               # on-chain node admission / eviction
    supports_zk_verification: bool        # can verify ZK proofs on-chain
    estimated_finality_seconds: float     # expected time to finality
    gas_cost_per_commit: Optional[int]    # gas units (None for gasless backends)


# ---------------------------------------------------------------------------
# Backend configuration
# ---------------------------------------------------------------------------

@dataclass
class BackendConfig:
    """Configuration for instantiating a commitment backend."""
    backend_type: str = "local"           # "local", "monad-l1", "ethereum"

    # --- Network endpoints ---
    rpc_url: Optional[str] = None
    chain_id: Optional[int] = None
    contract_address: Optional[str] = None

    # --- Monad L1 specific ---
    monad_parallel_threads: int = 16      # parallel EVM execution threads
    monad_block_time_ms: int = 500        # target block time
    monad_state_trie: str = "verkle"      # "verkle" or "mpt" (Merkle Patricia Trie)

    # --- Ethereum specific ---
    eth_confirmations: int = 1            # blocks to wait for soft finality
    eth_finality_mode: str = "safe"       # "latest", "safe", "finalized"
    eth_gas_limit: int = 300_000          # per-commitment gas limit
    eth_use_l2: bool = False              # deploy on L2 (Base, Arbitrum, etc.)
    eth_l2_name: Optional[str] = None     # "base", "arbitrum", "optimism"

    # --- Operator keys ---
    operator_private_key: Optional[str] = None
    operator_address: Optional[str] = None

    # --- Economics ---
    min_stake_wei: int = 0                # minimum stake for node admission
    slash_fraction_bps: int = 1000        # basis points slashed on audit failure (10%)


# ---------------------------------------------------------------------------
# Abstract backend
# ---------------------------------------------------------------------------

class CommitmentBackend(abc.ABC):
    """
    Abstract interface for commitment network backends.

    Every backend provides three groups of operations:

    1. **Log operations** — append commitment records, fetch them, verify
       inclusion proofs. This replaces the in-memory CommitmentLog.

    2. **Node registry** — admit / evict commitment nodes. Backends with
       on-chain registries (Monad L1, Ethereum) record this in state;
       the local backend keeps it in memory.

    3. **Economic hooks** — compensate nodes for storage, slash for audit
       failure, query pricing. The local backend no-ops these; on-chain
       backends route them through smart contracts.
    """

    def __init__(self, config: BackendConfig) -> None:
        self.config = config

    # --- Capabilities ---

    @abc.abstractmethod
    def capabilities(self) -> BackendCapabilities:
        """Return a descriptor of this backend's capabilities."""

    # --- Log operations ---

    @abc.abstractmethod
    def append_commitment(
        self,
        entity_id: str,
        record_bytes: bytes,
        signature: bytes,
        sender_vk: bytes,
    ) -> str:
        """
        Append a signed commitment record to the backend log.

        Returns: commitment reference (hash of the on-chain / in-log record).
        Raises: ValueError if entity_id is already committed.
        """

    @abc.abstractmethod
    def fetch_commitment(self, entity_id: str) -> Optional[dict]:
        """
        Fetch a commitment record by entity_id.

        Returns: dict with record fields, or None if not found.
        """

    @abc.abstractmethod
    def verify_inclusion(self, entity_id: str, proof: dict) -> bool:
        """
        Verify an inclusion proof for entity_id.

        The proof structure is backend-specific:
          - local: hash-chain proof
          - monad-l1: Verkle/MPT state proof
          - ethereum: Merkle Patricia proof against block state root
        """

    @abc.abstractmethod
    def is_finalized(self, entity_id: str) -> bool:
        """
        Check whether a commitment has reached finality.

        - local: always True (instant finality)
        - monad-l1: True after 1 slot (~500ms)
        - ethereum: depends on eth_finality_mode config
        """

    # --- Node registry ---

    @abc.abstractmethod
    def register_node(
        self,
        node_id: str,
        region: str,
        stake_wei: int = 0,
    ) -> bool:
        """
        Register a commitment node in the backend's registry.

        On-chain backends require a minimum stake.
        Returns True if admission succeeded.
        """

    @abc.abstractmethod
    def evict_node(self, node_id: str, reason: str, evidence: bytes = b"") -> bool:
        """
        Evict a commitment node (trigger slashing if applicable).

        Returns True if eviction succeeded.
        """

    @abc.abstractmethod
    def get_active_nodes(self) -> list[dict]:
        """
        Return a list of active nodes with their metadata.

        Each dict contains at minimum: {"node_id", "region", "stake_wei"}.
        """

    # --- Economic hooks ---

    @abc.abstractmethod
    def compensate_node(self, node_id: str, amount_wei: int, reason: str) -> bool:
        """Credit a node for storage service. No-op on local backend."""

    @abc.abstractmethod
    def slash_node(self, node_id: str, evidence: bytes) -> int:
        """
        Slash a node's stake for audit failure.

        Returns the amount slashed (0 for backends without staking).
        """

    @abc.abstractmethod
    def get_pricing(self) -> dict:
        """
        Return current storage pricing.

        Returns: {"cost_per_shard_per_epoch", "epoch_seconds", "currency"}
        """

"""
Backend factory — instantiate the appropriate backend from configuration.

Usage:
    from ltp.backends import BackendConfig, create_backend

    backend = create_backend(BackendConfig(backend_type="monad-l1-sim"))
    backend = create_backend(BackendConfig(backend_type="ethereum-sim", eth_use_l2=True))
    backend = create_backend(BackendConfig(
        backend_type="ethereum-live",
        rpc_url="https://rpc.example",
        contract_address="0x1234",
        operator_private_key="0xabc",
    ))
"""

from __future__ import annotations

from .base import BackendConfig, CommitmentBackend
from .local import LocalBackend
from .monad_l1 import MonadL1Backend
from .ethereum import EthereumBackend, EthereumLiveBackend, EthereumSimulatedBackend


_REGISTRY: dict[str, type[CommitmentBackend]] = {
    "local": LocalBackend,
    "monad-l1-sim": MonadL1Backend,
    "ethereum-sim": EthereumSimulatedBackend,
    "ethereum-live": EthereumLiveBackend,
}

_ALIASES: dict[str, str] = {
    "monad-l1": "monad-l1-sim",
}


def resolve_backend_type(config: BackendConfig) -> str:
    """Resolve legacy backend aliases into explicit runtime modes."""
    backend_type = _ALIASES.get(config.backend_type, config.backend_type)
    if backend_type == "ethereum":
        return "ethereum-live" if config.has_live_anchor_config() else "ethereum-sim"
    return backend_type


def create_backend(config: BackendConfig) -> CommitmentBackend:
    """
    Create a commitment backend from the given configuration.

    Supported backend_type values:
      - "local"         — in-memory, instant finality, no economics
      - "monad-l1-sim"  — simulated Monad-style chain
      - "ethereum-sim"  — simulated Ethereum contract adapter
      - "ethereum-live" — RPC-backed Ethereum/Anchor adapter

    Legacy compatibility aliases:
      - "monad-l1"      — resolves to "monad-l1-sim"
      - "ethereum"      — resolves to "ethereum-sim" unless live RPC config is present

    Raises ValueError for unknown backend types.
    """
    resolved_type = resolve_backend_type(config)
    cls = _REGISTRY.get(resolved_type)
    if cls is None:
        raise ValueError(
            f"Unknown backend type '{config.backend_type}' (resolved to '{resolved_type}'). "
            f"Available: {sorted(_REGISTRY.keys()) + sorted(_ALIASES.keys()) + ['ethereum']}"
        )
    return cls(config)

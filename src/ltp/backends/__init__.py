"""
Commitment network backends for the Lattice Transfer Protocol.

Provides pluggable backend implementations for the commitment log and
network economics layer:

  - CommitmentBackend   — abstract interface every backend must implement
  - LocalBackend        — in-memory backend (default, used by PoC and tests)
  - MonadL1Backend      — simulated Monad-style backend used for PoC economics/testing
  - EthereumBackend     — legacy compatibility adapter that auto-resolves sim vs live
  - EthereumSimulatedBackend / EthereumLiveBackend — explicit Ethereum adapter modes

Usage:
  from ltp.backends import BackendConfig, create_backend

  # Option 1: Custom L1 (Monad fork)
  backend = create_backend(BackendConfig(backend_type="monad-l1-sim", ...))

  # Option 2: Explicit Ethereum sim
  backend = create_backend(BackendConfig(backend_type="ethereum-sim", ...))

  # Option 3: Explicit live Ethereum adapter
  backend = create_backend(BackendConfig(backend_type="ethereum-live", ...))

  # Default: local in-memory
  backend = create_backend(BackendConfig(backend_type="local"))
"""

from .base import CommitmentBackend, BackendConfig, BackendCapabilities
from .local import LocalBackend
from .monad_l1 import MonadL1Backend
from .ethereum import EthereumBackend, EthereumLiveBackend, EthereumSimulatedBackend
from .factory import create_backend, resolve_backend_type

__all__ = [
    "CommitmentBackend",
    "BackendConfig",
    "BackendCapabilities",
    "LocalBackend",
    "MonadL1Backend",
    "EthereumBackend",
    "EthereumSimulatedBackend",
    "EthereumLiveBackend",
    "create_backend",
    "resolve_backend_type",
]

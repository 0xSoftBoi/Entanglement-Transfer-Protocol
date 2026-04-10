"""
ETP Bridge — L1↔L2 cross-chain transfer via the Lattice Transfer Protocol.

Maps ETP's three-phase protocol to blockchain bridging:

  COMMIT      → Lock tokens on L1, erasure-code + encrypt the lock event
  LATTICE     → Seal a minimal key (~1.3KB) to the L2 verifier
  MATERIALIZE → Unseal, verify commitment + signature, reconstruct, mint on L2

Security properties:
  - PQ-secure relay (ML-KEM-768 sealed key, untrusted transport)
  - Forward secrecy per bridge message (fresh encapsulation each time)
  - Append-only audit trail (CT-style Merkle log + ML-DSA STH)
  - Data availability (erasure-coded shards, k-of-n reconstruction)
  - Replay protection (per-sender monotonic nonces)

Runtime note:
  - `L1Anchor`, `Relayer`, and `L2Materializer` are the stable protocol-layer bridge
    components and are exercised primarily against simulated/off-chain state.
  - `LiveBridge` is an environment-dependent adapter over `AnchorClient`.
    It requires real RPC connectivity to preserve its "live" semantics and now
    fails closed by default if chain-state queries are unavailable.
  - `LiveBridge` can opt into simulated finality fallback for development only via
    `allow_simulated_finality_fallback=True`.
"""

from .message import BridgeMessage, BridgeCommitment, RelayPacket
from .nonce import NonceTracker
from .anchor import L1Anchor
from .relayer import Relayer
from .materializer import L2Materializer

__all__ = [
    "BridgeMessage",
    "BridgeCommitment",
    "RelayPacket",
    "NonceTracker",
    "L1Anchor",
    "Relayer",
    "L2Materializer",
]

# LiveBridge requires web3 and a reachable RPC environment, so import lazily to
# avoid imposing a hard dependency on protocol-only callers.
def __getattr__(name):
    if name in ("LiveBridge", "LiveBridgeResult"):
        from .live import LiveBridge, LiveBridgeResult
        return {"LiveBridge": LiveBridge, "LiveBridgeResult": LiveBridgeResult}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

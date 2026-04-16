"""
ZK Transfer Mode for the Lattice Transfer Protocol.

Provides privacy-preserving transfers where the commitment log does not
reveal which entity was committed. Uses hiding commitments (simulated
Pedersen scheme) and zero-knowledge proofs.

Proof systems:
  - Groth16 (BLS12-381): ~192B proofs, NOT post-quantum (Shor breaks pairings)
  - STARK: ~45KB proofs, hash-based, post-quantum safe, no trusted setup
  - LatticeFold: ~8KB proofs, lattice-based folding (Module-SIS), post-quantum,
    recursive composition. Reference: Boneh-Chen, Asiacrypt 2025.
  - Circle STARK: ~32KB proofs, hash-based over circle groups (Mersenne prime
    field), post-quantum safe, no trusted setup. Reference: StarkWare 2024.

Whitepaper reference: §3.2, §3.2.4, Open Question 8
Design decision: docs/design-decisions/ZK_TRANSFER_MODE.md
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .primitives import canonical_hash, canonical_hash_bytes

__all__ = [
    "ZKProofSystem",
    "ZKConfig",
    "LatticeFoldConfig",
    "CircleSTARKConfig",
    "ZKCommitment",
    "ZKProof",
    "ZKTransferMode",
]


class ZKProofSystem(Enum):
    """Available ZK proof systems."""
    SIMULATED = "simulated"    # PoC simulation (no real cryptography)
    GROTH16 = "groth16"        # BLS12-381, NOT post-quantum
    STARK = "stark"            # Post-quantum candidate (no trusted setup)
    LATTICEFOLD = "latticefold"  # Lattice-based folding scheme, post-quantum
    CIRCLE_STARK = "circle_stark"  # Circle group STARKs, post-quantum

    @property
    def is_post_quantum(self) -> bool:
        return self in (
            ZKProofSystem.STARK,
            ZKProofSystem.LATTICEFOLD,
            ZKProofSystem.CIRCLE_STARK,
        )


@dataclass
class LatticeFoldConfig:
    """
    Configuration for LatticeFold proof system.

    LatticeFold is a lattice-based folding scheme built on Module-SIS.
    It supports recursive proof composition and is post-quantum safe.

    Reference: Boneh-Chen, "LatticeFold: A Lattice-based Folding Scheme
    and its Applications to Succinct Proof Systems", Asiacrypt 2025.
    """
    lattice_dimension: int = 512
    folding_rounds: int = 10
    module_rank: int = 4
    sis_bound: int = 2**20
    proof_size_target_kb: float = 8.0

    @property
    def security_bits(self) -> int:
        return min(256, self.lattice_dimension * self.module_rank // 8)


@dataclass
class CircleSTARKConfig:
    """
    Configuration for Circle STARK proof system.

    Circle STARKs operate over circle groups defined by Mersenne primes,
    enabling efficient FFTs and post-quantum secure proofs without trusted setup.

    Reference: StarkWare, "Circle STARKs", 2024.
    """
    field_prime: str = "mersenne31"  # 2^31 - 1
    num_queries: int = 80
    blowup_factor: int = 8
    fri_folding_factor: int = 4
    hash_function: str = "blake3"
    proof_size_target_kb: float = 32.0


@dataclass
class ZKConfig:
    """Configuration for ZK transfer mode."""
    enabled: bool = False
    proof_system: ZKProofSystem = ZKProofSystem.SIMULATED
    curve: str = "bls12_381"   # Only relevant for Groth16
    hiding_commitment: bool = True  # Use hiding commitment for entity_id
    latticefold: LatticeFoldConfig = field(default_factory=LatticeFoldConfig)
    circle_stark: CircleSTARKConfig = field(default_factory=CircleSTARKConfig)


@dataclass
class ZKCommitment:
    """
    A hiding commitment to an entity_id.

    In production (Groth16): C = g^{entity_id} · h^r over BLS12-381
    In simulation: C = H(entity_id || blinding_factor)

    The commitment hides entity_id from the commitment log while
    allowing ZK proof of knowledge.
    """
    commitment_value: str       # The commitment C (hex string)
    blinding_factor: bytes      # Random blinding factor r
    entity_id: str              # The hidden entity_id (known to creator only)

    @property
    def is_hiding(self) -> bool:
        """A commitment is hiding if it has a non-zero blinding factor."""
        return len(self.blinding_factor) > 0 and any(b != 0 for b in self.blinding_factor)


@dataclass
class ZKProof:
    """
    A zero-knowledge proof of knowledge of entity_id.

    Proves: "I know entity_id such that C = Commit(entity_id, r)"
    without revealing entity_id.

    In simulation: proof = H(entity_id || blinding_factor || "proof")
    In production: Groth16 proof (~192 bytes) or STARK proof (~45 KB)
    """
    proof_bytes: bytes
    proof_system: ZKProofSystem
    public_inputs: dict = field(default_factory=dict)

    @property
    def proof_size_bytes(self) -> int:
        return len(self.proof_bytes)


class ZKTransferMode:
    """
    Zero-knowledge transfer mode for entity_id privacy.

    Allows commits to the log without revealing which entity was committed.
    The commitment log sees only C (a hiding commitment) and a ZK proof
    that the committer knows the opening.

    PoC uses simulated commitments and proofs. Production requires
    Groth16 (BLS12-381) or STARK circuit implementations.
    """

    def __init__(self, config: ZKConfig | None = None) -> None:
        self.config = config or ZKConfig()

    def create_hiding_commitment(self, entity_id: str) -> ZKCommitment:
        """
        Create a hiding commitment to entity_id.

        Groth16: Pedersen commitment C = g^{entity_id} · h^r over BLS12-381
        LatticeFold: Ajtai commitment C = A·m + r (mod q) over Module-SIS
        Circle STARK: Hash commitment C = H(entity_id || r) over Mersenne field
        Simulation: C = H(entity_id || r)
        """
        blinding_factor = os.urandom(32)
        ps = self.config.proof_system

        if ps == ZKProofSystem.SIMULATED:
            commitment_value = canonical_hash(
                entity_id.encode() + blinding_factor
            )
        elif ps == ZKProofSystem.LATTICEFOLD:
            commitment_value = canonical_hash(
                entity_id.encode()
                + blinding_factor
                + b"latticefold"
                + self.config.latticefold.lattice_dimension.to_bytes(4, "big")
            )
        elif ps == ZKProofSystem.CIRCLE_STARK:
            commitment_value = canonical_hash(
                entity_id.encode()
                + blinding_factor
                + b"circle-stark"
                + self.config.circle_stark.field_prime.encode()
            )
        else:
            commitment_value = canonical_hash(
                entity_id.encode() + blinding_factor + self.config.curve.encode()
            )

        return ZKCommitment(
            commitment_value=commitment_value,
            blinding_factor=blinding_factor,
            entity_id=entity_id,
        )

    def create_zk_proof(
        self,
        entity_id: str,
        commitment: ZKCommitment,
    ) -> ZKProof:
        """
        Create a ZK proof that the committer knows entity_id opening C.

        Production: Groth16 proof (~192 bytes, ~2s generation)
        Simulation: H(entity_id || blinding_factor || "proof")
        """
        if commitment.entity_id != entity_id:
            raise ValueError("Entity ID does not match commitment")

        ps = self.config.proof_system

        if ps == ZKProofSystem.SIMULATED:
            proof_bytes = canonical_hash_bytes(
                entity_id.encode()
                + commitment.blinding_factor
                + b"proof"
            )
        elif ps == ZKProofSystem.GROTH16:
            proof_bytes = canonical_hash_bytes(
                entity_id.encode()
                + commitment.blinding_factor
                + b"groth16-proof"
            )
            proof_bytes = proof_bytes + os.urandom(160)
        elif ps == ZKProofSystem.STARK:
            proof_bytes = canonical_hash_bytes(
                entity_id.encode()
                + commitment.blinding_factor
                + b"stark-proof"
            )
        elif ps == ZKProofSystem.LATTICEFOLD:
            # LatticeFold: ~8KB proofs in production via Module-SIS folding
            core = canonical_hash_bytes(
                entity_id.encode()
                + commitment.blinding_factor
                + b"latticefold-proof"
                + self.config.latticefold.folding_rounds.to_bytes(4, "big")
            )
            proof_bytes = core + os.urandom(max(0, 8192 - len(core)))
        elif ps == ZKProofSystem.CIRCLE_STARK:
            # Circle STARK: ~32KB proofs in production via FRI over Mersenne field
            core = canonical_hash_bytes(
                entity_id.encode()
                + commitment.blinding_factor
                + b"circle-stark-proof"
                + self.config.circle_stark.field_prime.encode()
            )
            proof_bytes = core + os.urandom(max(0, 32768 - len(core)))
        else:
            raise ValueError(f"Unknown proof system: {ps}")

        public_inputs = {"commitment": commitment.commitment_value}
        if ps == ZKProofSystem.LATTICEFOLD:
            public_inputs["lattice_dimension"] = self.config.latticefold.lattice_dimension
            public_inputs["folding_rounds"] = self.config.latticefold.folding_rounds
        elif ps == ZKProofSystem.CIRCLE_STARK:
            public_inputs["field_prime"] = self.config.circle_stark.field_prime
            public_inputs["num_queries"] = self.config.circle_stark.num_queries

        return ZKProof(
            proof_bytes=proof_bytes,
            proof_system=ps,
            public_inputs=public_inputs,
        )

    def verify_zk_proof(
        self,
        commitment: ZKCommitment,
        proof: ZKProof,
    ) -> bool:
        """
        Verify a ZK proof against a commitment.

        Checks that the prover knows entity_id such that
        C = Commit(entity_id, r) without learning entity_id.
        """
        if proof.proof_system != self.config.proof_system:
            return False

        ps = self.config.proof_system

        if ps == ZKProofSystem.SIMULATED:
            expected = canonical_hash_bytes(
                commitment.entity_id.encode()
                + commitment.blinding_factor
                + b"proof"
            )
            return proof.proof_bytes == expected
        elif ps == ZKProofSystem.GROTH16:
            expected_prefix = canonical_hash_bytes(
                commitment.entity_id.encode()
                + commitment.blinding_factor
                + b"groth16-proof"
            )
            return proof.proof_bytes[:len(expected_prefix)] == expected_prefix
        elif ps == ZKProofSystem.STARK:
            expected = canonical_hash_bytes(
                commitment.entity_id.encode()
                + commitment.blinding_factor
                + b"stark-proof"
            )
            return proof.proof_bytes == expected
        elif ps == ZKProofSystem.LATTICEFOLD:
            expected_prefix = canonical_hash_bytes(
                commitment.entity_id.encode()
                + commitment.blinding_factor
                + b"latticefold-proof"
                + self.config.latticefold.folding_rounds.to_bytes(4, "big")
            )
            return proof.proof_bytes[:len(expected_prefix)] == expected_prefix
        elif ps == ZKProofSystem.CIRCLE_STARK:
            expected_prefix = canonical_hash_bytes(
                commitment.entity_id.encode()
                + commitment.blinding_factor
                + b"circle-stark-proof"
                + self.config.circle_stark.field_prime.encode()
            )
            return proof.proof_bytes[:len(expected_prefix)] == expected_prefix

        return False

    def open_commitment(
        self,
        commitment: ZKCommitment,
        entity_id: str,
        blinding_factor: bytes,
    ) -> bool:
        """
        Open (reveal) a commitment — verify that C was created from
        the given entity_id and blinding_factor.

        This is NOT zero-knowledge (it reveals entity_id). Used for
        dispute resolution or selective disclosure.
        """
        ps = self.config.proof_system
        if ps == ZKProofSystem.LATTICEFOLD:
            expected = canonical_hash(
                entity_id.encode()
                + blinding_factor
                + b"latticefold"
                + self.config.latticefold.lattice_dimension.to_bytes(4, "big")
            )
        elif ps == ZKProofSystem.CIRCLE_STARK:
            expected = canonical_hash(
                entity_id.encode()
                + blinding_factor
                + b"circle-stark"
                + self.config.circle_stark.field_prime.encode()
            )
        else:
            expected = canonical_hash(entity_id.encode() + blinding_factor)
        return commitment.commitment_value == expected


@dataclass
class ContentPropertyProof:
    """
    A proof about entity content properties without revealing the content.

    Examples:
      - "This entity is a valid JSON document"
      - "This entity's 'age' field is >= 18"
      - "This entity conforms to schema X"

    Open Question 8(a): What is the appropriate circuit composition model?
    """
    property_name: str            # Human-readable property
    property_circuit_id: str      # Circuit identifier
    proof: ZKProof                # The ZK proof
    public_inputs: dict           # Public inputs to the circuit

    @property
    def is_verifiable(self) -> bool:
        """Whether the proof can be verified (has required fields)."""
        return (
            bool(self.property_circuit_id)
            and self.proof.proof_bytes is not None
            and len(self.proof.proof_bytes) > 0
        )

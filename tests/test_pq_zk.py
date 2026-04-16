"""Tests for post-quantum ZK proof systems (LatticeFold + Circle STARK)."""

import pytest

from src.ltp.zk_transfer import (
    ZKProofSystem,
    ZKConfig,
    LatticeFoldConfig,
    CircleSTARKConfig,
    ZKCommitment,
    ZKProof,
    ZKTransferMode,
)
from src.ltp.primitives import canonical_hash


# ---------------------------------------------------------------------------
# ZKProofSystem enum
# ---------------------------------------------------------------------------

class TestZKProofSystemEnum:
    def test_latticefold_exists(self):
        assert ZKProofSystem.LATTICEFOLD.value == "latticefold"

    def test_circle_stark_exists(self):
        assert ZKProofSystem.CIRCLE_STARK.value == "circle_stark"

    def test_latticefold_is_post_quantum(self):
        assert ZKProofSystem.LATTICEFOLD.is_post_quantum is True

    def test_circle_stark_is_post_quantum(self):
        assert ZKProofSystem.CIRCLE_STARK.is_post_quantum is True

    def test_groth16_not_post_quantum(self):
        assert ZKProofSystem.GROTH16.is_post_quantum is False

    def test_stark_is_post_quantum(self):
        assert ZKProofSystem.STARK.is_post_quantum is True

    def test_simulated_not_post_quantum(self):
        assert ZKProofSystem.SIMULATED.is_post_quantum is False


# ---------------------------------------------------------------------------
# LatticeFoldConfig
# ---------------------------------------------------------------------------

class TestLatticeFoldConfig:
    def test_defaults(self):
        cfg = LatticeFoldConfig()
        assert cfg.lattice_dimension == 512
        assert cfg.folding_rounds == 10
        assert cfg.module_rank == 4
        assert cfg.sis_bound == 2**20
        assert cfg.proof_size_target_kb == 8.0

    def test_security_bits(self):
        cfg = LatticeFoldConfig(lattice_dimension=512, module_rank=4)
        assert cfg.security_bits == 256

    def test_custom_params(self):
        cfg = LatticeFoldConfig(lattice_dimension=1024, folding_rounds=20)
        assert cfg.lattice_dimension == 1024
        assert cfg.folding_rounds == 20


# ---------------------------------------------------------------------------
# CircleSTARKConfig
# ---------------------------------------------------------------------------

class TestCircleSTARKConfig:
    def test_defaults(self):
        cfg = CircleSTARKConfig()
        assert cfg.field_prime == "mersenne31"
        assert cfg.num_queries == 80
        assert cfg.blowup_factor == 8
        assert cfg.fri_folding_factor == 4
        assert cfg.hash_function == "blake3"
        assert cfg.proof_size_target_kb == 32.0


# ---------------------------------------------------------------------------
# LatticeFold ZK Transfer Mode
# ---------------------------------------------------------------------------

class TestLatticeFoldTransfer:
    def test_create_commitment(self):
        mode = ZKTransferMode(ZKConfig(
            proof_system=ZKProofSystem.LATTICEFOLD,
        ))
        entity_id = canonical_hash(b"test-entity-latticefold")
        commitment = mode.create_hiding_commitment(entity_id)

        assert commitment.entity_id == entity_id
        assert commitment.is_hiding
        assert len(commitment.commitment_value) > 0

    def test_create_and_verify_proof(self):
        mode = ZKTransferMode(ZKConfig(
            proof_system=ZKProofSystem.LATTICEFOLD,
        ))
        entity_id = canonical_hash(b"test-entity-lf-proof")
        commitment = mode.create_hiding_commitment(entity_id)
        proof = mode.create_zk_proof(entity_id, commitment)

        assert proof.proof_system == ZKProofSystem.LATTICEFOLD
        assert proof.proof_size_bytes >= 8192
        assert "lattice_dimension" in proof.public_inputs
        assert "folding_rounds" in proof.public_inputs

        assert mode.verify_zk_proof(commitment, proof) is True

    def test_wrong_entity_id_fails(self):
        mode = ZKTransferMode(ZKConfig(
            proof_system=ZKProofSystem.LATTICEFOLD,
        ))
        entity_id = canonical_hash(b"correct-entity")
        wrong_id = canonical_hash(b"wrong-entity")
        commitment = mode.create_hiding_commitment(entity_id)

        with pytest.raises(ValueError):
            mode.create_zk_proof(wrong_id, commitment)

    def test_open_commitment(self):
        mode = ZKTransferMode(ZKConfig(
            proof_system=ZKProofSystem.LATTICEFOLD,
        ))
        entity_id = canonical_hash(b"test-open-lf")
        commitment = mode.create_hiding_commitment(entity_id)

        assert mode.open_commitment(
            commitment, entity_id, commitment.blinding_factor
        ) is True

        assert mode.open_commitment(
            commitment, canonical_hash(b"wrong"), commitment.blinding_factor
        ) is False

    def test_cross_system_proof_rejected(self):
        lf_mode = ZKTransferMode(ZKConfig(
            proof_system=ZKProofSystem.LATTICEFOLD,
        ))
        sim_mode = ZKTransferMode(ZKConfig(
            proof_system=ZKProofSystem.SIMULATED,
        ))
        entity_id = canonical_hash(b"cross-system-test")
        commitment = lf_mode.create_hiding_commitment(entity_id)
        proof = lf_mode.create_zk_proof(entity_id, commitment)

        assert sim_mode.verify_zk_proof(commitment, proof) is False


# ---------------------------------------------------------------------------
# Circle STARK ZK Transfer Mode
# ---------------------------------------------------------------------------

class TestCircleSTARKTransfer:
    def test_create_commitment(self):
        mode = ZKTransferMode(ZKConfig(
            proof_system=ZKProofSystem.CIRCLE_STARK,
        ))
        entity_id = canonical_hash(b"test-entity-circle")
        commitment = mode.create_hiding_commitment(entity_id)

        assert commitment.entity_id == entity_id
        assert commitment.is_hiding

    def test_create_and_verify_proof(self):
        mode = ZKTransferMode(ZKConfig(
            proof_system=ZKProofSystem.CIRCLE_STARK,
        ))
        entity_id = canonical_hash(b"test-circle-proof")
        commitment = mode.create_hiding_commitment(entity_id)
        proof = mode.create_zk_proof(entity_id, commitment)

        assert proof.proof_system == ZKProofSystem.CIRCLE_STARK
        assert proof.proof_size_bytes >= 32768
        assert "field_prime" in proof.public_inputs
        assert proof.public_inputs["field_prime"] == "mersenne31"
        assert "num_queries" in proof.public_inputs

        assert mode.verify_zk_proof(commitment, proof) is True

    def test_open_commitment(self):
        mode = ZKTransferMode(ZKConfig(
            proof_system=ZKProofSystem.CIRCLE_STARK,
        ))
        entity_id = canonical_hash(b"test-open-cs")
        commitment = mode.create_hiding_commitment(entity_id)

        assert mode.open_commitment(
            commitment, entity_id, commitment.blinding_factor
        ) is True

    def test_wrong_proof_system_rejected(self):
        cs_mode = ZKTransferMode(ZKConfig(
            proof_system=ZKProofSystem.CIRCLE_STARK,
        ))
        groth_mode = ZKTransferMode(ZKConfig(
            proof_system=ZKProofSystem.GROTH16,
        ))
        entity_id = canonical_hash(b"cross-test")
        commitment = cs_mode.create_hiding_commitment(entity_id)
        proof = cs_mode.create_zk_proof(entity_id, commitment)

        assert groth_mode.verify_zk_proof(commitment, proof) is False

    def test_custom_config(self):
        mode = ZKTransferMode(ZKConfig(
            proof_system=ZKProofSystem.CIRCLE_STARK,
            circle_stark=CircleSTARKConfig(
                num_queries=128,
                blowup_factor=16,
            ),
        ))
        entity_id = canonical_hash(b"custom-config")
        commitment = mode.create_hiding_commitment(entity_id)
        proof = mode.create_zk_proof(entity_id, commitment)
        assert mode.verify_zk_proof(commitment, proof) is True


# ---------------------------------------------------------------------------
# PQ Safety Verification
# ---------------------------------------------------------------------------

class TestPQSafety:
    def test_all_pq_systems_flagged(self):
        pq_systems = [s for s in ZKProofSystem if s.is_post_quantum]
        assert ZKProofSystem.LATTICEFOLD in pq_systems
        assert ZKProofSystem.CIRCLE_STARK in pq_systems
        assert ZKProofSystem.STARK in pq_systems
        assert len(pq_systems) == 3

    def test_non_pq_systems_flagged(self):
        non_pq = [s for s in ZKProofSystem if not s.is_post_quantum]
        assert ZKProofSystem.GROTH16 in non_pq
        assert ZKProofSystem.SIMULATED in non_pq

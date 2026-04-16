"""Tests for ZK Transfer Mode (Open Question 8, §3.2)."""

import os
import pytest

from src.ltp.primitives import AssuranceMode, get_assurance_mode, set_assurance_mode
from src.ltp.zk_transfer import (
    ZKProofSystem,
    ZKConfig,
    ZKCommitment,
    ZKProof,
    ZKTransferMode,
    ContentPropertyProof,
)


@pytest.fixture(autouse=True)
def allow_zk_mode(monkeypatch):
    """Set ETP_ALLOW_ZK_MODE=1 for all ZK transfer tests."""
    monkeypatch.setenv("ETP_ALLOW_ZK_MODE", "1")


@pytest.fixture(autouse=True)
def restore_assurance_mode():
    original = get_assurance_mode()
    yield
    set_assurance_mode(original)


# ---------------------------------------------------------------------------
# ZKConfig
# ---------------------------------------------------------------------------

class TestZKConfig:
    def test_defaults(self):
        cfg = ZKConfig()
        assert cfg.enabled is False
        assert cfg.proof_system == ZKProofSystem.SIMULATED
        assert cfg.curve == "bls12_381"
        assert cfg.hiding_commitment is True

    def test_custom(self):
        cfg = ZKConfig(enabled=True, proof_system=ZKProofSystem.GROTH16)
        assert cfg.enabled is True
        assert cfg.proof_system == ZKProofSystem.GROTH16

    def test_experimental_proof_systems_default_off(self):
        cfg = ZKConfig()
        assert cfg.allow_experimental_proof_systems is False


# ---------------------------------------------------------------------------
# ZKCommitment
# ---------------------------------------------------------------------------

class TestZKCommitment:
    def test_is_hiding_with_nonzero_blinding(self):
        c = ZKCommitment(
            commitment_value="abc",
            blinding_factor=b"\x01" * 32,
            entity_id="e1",
        )
        assert c.is_hiding is True

    def test_is_hiding_zero_blinding(self):
        c = ZKCommitment(
            commitment_value="abc",
            blinding_factor=b"\x00" * 32,
            entity_id="e1",
        )
        assert c.is_hiding is False

    def test_is_hiding_empty_blinding(self):
        c = ZKCommitment(
            commitment_value="abc",
            blinding_factor=b"",
            entity_id="e1",
        )
        assert c.is_hiding is False


# ---------------------------------------------------------------------------
# ZKProof
# ---------------------------------------------------------------------------

class TestZKProof:
    def test_proof_size(self):
        p = ZKProof(
            proof_bytes=b"\x00" * 64,
            proof_system=ZKProofSystem.SIMULATED,
            public_inputs={"simulated_backend": True},
        )
        assert p.proof_size_bytes == 64
        assert p.is_simulated is True


# ---------------------------------------------------------------------------
# ZKTransferMode — Simulated
# ---------------------------------------------------------------------------

class TestZKTransferModeSimulated:
    def setup_method(self):
        self.zk = ZKTransferMode(ZKConfig(proof_system=ZKProofSystem.SIMULATED))

    def test_create_hiding_commitment(self):
        c = self.zk.create_hiding_commitment("entity-1")
        assert c.entity_id == "entity-1"
        assert isinstance(c.commitment_value, str)
        assert len(c.commitment_value) > 0
        assert c.is_hiding

    def test_commitment_is_unique_per_call(self):
        c1 = self.zk.create_hiding_commitment("entity-1")
        c2 = self.zk.create_hiding_commitment("entity-1")
        # Different blinding factors → different commitment values
        assert c1.commitment_value != c2.commitment_value

    def test_create_and_verify_proof(self):
        c = self.zk.create_hiding_commitment("entity-1")
        proof = self.zk.create_zk_proof("entity-1", c)
        assert isinstance(proof, ZKProof)
        assert proof.proof_system == ZKProofSystem.SIMULATED
        assert proof.is_simulated is True
        assert self.zk.verify_zk_proof(c, proof)

    def test_runtime_status_reports_simulated_backend(self):
        status = self.zk.get_runtime_status()
        assert status["proof_system"] == "simulated"
        assert status["simulated_backend"] is True
        assert status["experimental_opt_in"] is False

    def test_proof_fails_for_wrong_entity(self):
        c = self.zk.create_hiding_commitment("entity-1")
        with pytest.raises(ValueError, match="does not match"):
            self.zk.create_zk_proof("entity-2", c)

    def test_tampered_proof_fails_verification(self):
        c = self.zk.create_hiding_commitment("entity-1")
        proof = self.zk.create_zk_proof("entity-1", c)
        bad_proof = ZKProof(
            proof_bytes=b"\xff" * len(proof.proof_bytes),
            proof_system=proof.proof_system,
        )
        assert self.zk.verify_zk_proof(c, bad_proof) is False

    def test_proof_system_mismatch_fails(self):
        c = self.zk.create_hiding_commitment("entity-1")
        proof = self.zk.create_zk_proof("entity-1", c)
        # Change the proof system
        bad = ZKProof(
            proof_bytes=proof.proof_bytes,
            proof_system=ZKProofSystem.GROTH16,
        )
        assert self.zk.verify_zk_proof(c, bad) is False

    def test_open_commitment(self):
        c = self.zk.create_hiding_commitment("entity-1")
        assert self.zk.open_commitment(c, "entity-1", c.blinding_factor)

    def test_open_commitment_wrong_entity(self):
        c = self.zk.create_hiding_commitment("entity-1")
        assert self.zk.open_commitment(c, "entity-2", c.blinding_factor) is False

    def test_open_commitment_wrong_blinding(self):
        c = self.zk.create_hiding_commitment("entity-1")
        assert self.zk.open_commitment(c, "entity-1", b"\x00" * 32) is False


# ---------------------------------------------------------------------------
# ZKTransferMode — Groth16
# ---------------------------------------------------------------------------

class TestZKTransferModeGroth16:
    def setup_method(self):
        self.zk = ZKTransferMode(
            ZKConfig(
                proof_system=ZKProofSystem.GROTH16,
                allow_experimental_proof_systems=True,
            )
        )

    def test_create_and_verify_proof(self):
        c = self.zk.create_hiding_commitment("entity-g16")
        proof = self.zk.create_zk_proof("entity-g16", c)
        assert proof.proof_system == ZKProofSystem.GROTH16
        # Groth16 simulated proof is larger (hash + 160 random bytes)
        assert proof.proof_size_bytes > 32
        assert proof.is_simulated is True
        assert self.zk.verify_zk_proof(c, proof)

    def test_commitment_uses_curve(self):
        c = self.zk.create_hiding_commitment("entity-curve")
        # Just ensure commitment is created without error
        assert len(c.commitment_value) > 0

    def test_requires_experimental_opt_in(self):
        zk = ZKTransferMode(ZKConfig(proof_system=ZKProofSystem.GROTH16))
        with pytest.raises(RuntimeError, match="simulated placeholder"):
            zk.create_hiding_commitment("entity-g16")


# ---------------------------------------------------------------------------
# ZKTransferMode — STARK
# ---------------------------------------------------------------------------

class TestZKTransferModeSTARK:
    def setup_method(self):
        self.zk = ZKTransferMode(
            ZKConfig(
                proof_system=ZKProofSystem.STARK,
                allow_experimental_proof_systems=True,
            )
        )

    def test_create_and_verify_proof(self):
        c = self.zk.create_hiding_commitment("entity-stark")
        proof = self.zk.create_zk_proof("entity-stark", c)
        assert proof.proof_system == ZKProofSystem.STARK
        assert proof.is_simulated is True
        assert self.zk.verify_zk_proof(c, proof)

    def test_requires_experimental_opt_in(self):
        zk = ZKTransferMode(ZKConfig(proof_system=ZKProofSystem.STARK))
        with pytest.raises(RuntimeError, match="simulated placeholder"):
            zk.create_hiding_commitment("entity-stark")


# ---------------------------------------------------------------------------
# ContentPropertyProof
# ---------------------------------------------------------------------------

class TestContentPropertyProof:
    def test_is_verifiable(self):
        proof = ZKProof(proof_bytes=b"\x01" * 32, proof_system=ZKProofSystem.SIMULATED)
        cpp = ContentPropertyProof(
            property_name="age >= 18",
            property_circuit_id="age_check_v1",
            proof=proof,
            public_inputs={"threshold": 18},
        )
        assert cpp.is_verifiable is True

    def test_not_verifiable_empty_circuit_id(self):
        proof = ZKProof(proof_bytes=b"\x01" * 32, proof_system=ZKProofSystem.SIMULATED)
        cpp = ContentPropertyProof(
            property_name="age >= 18",
            property_circuit_id="",
            proof=proof,
            public_inputs={},
        )
        assert cpp.is_verifiable is False

    def test_not_verifiable_empty_proof(self):
        proof = ZKProof(proof_bytes=b"", proof_system=ZKProofSystem.SIMULATED)
        cpp = ContentPropertyProof(
            property_name="age >= 18",
            property_circuit_id="age_check_v1",
            proof=proof,
            public_inputs={},
        )
        assert cpp.is_verifiable is False


# ---------------------------------------------------------------------------
# Default config (disabled)
# ---------------------------------------------------------------------------

class TestZKTransferModeDefault:
    def test_default_config(self):
        zk = ZKTransferMode()
        assert zk.config.enabled is False
        # Functional when ETP_ALLOW_ZK_MODE=1 (set by allow_zk_mode fixture)
        c = zk.create_hiding_commitment("test")
        assert c.is_hiding

    def test_guard_blocks_without_env_var(self, monkeypatch):
        monkeypatch.delenv("ETP_ALLOW_ZK_MODE", raising=False)
        with pytest.raises(RuntimeError, match="ETP_ALLOW_ZK_MODE"):
            ZKTransferMode()

    def test_production_mode_fails_closed(self):
        set_assurance_mode(AssuranceMode.PRODUCTION)
        zk = ZKTransferMode(ZKConfig(enabled=True))
        with pytest.raises(RuntimeError, match="unavailable in production assurance modes"):
            zk.create_hiding_commitment("entity-prod")

    def test_compliance_strict_mode_fails_closed(self):
        try:
            set_assurance_mode(AssuranceMode.COMPLIANCE_STRICT)
        except RuntimeError:
            pytest.skip("Compliance-strict prerequisites unavailable in test environment")
        zk = ZKTransferMode(ZKConfig(enabled=True))
        with pytest.raises(RuntimeError, match="unavailable in production assurance modes"):
            zk.create_hiding_commitment("entity-strict")

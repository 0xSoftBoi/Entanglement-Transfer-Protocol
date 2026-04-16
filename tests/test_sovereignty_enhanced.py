"""Tests for sovereignty enhancements (Functional Erasure, eIDAS 2.0, EU Data Act)."""

import pytest

from src.ltp.compliance import (
    FunctionalErasure,
    EIDAS2TrustLevel,
    DataActClassification,
    ComplianceAuditLogger,
    AuditEventType,
)
from src.ltp.primitives import (
    HashFunction,
    get_security_profile,
    set_security_profile,
    SecurityProfile,
    canonical_hash,
)


@pytest.fixture(autouse=True)
def restore_default_profile():
    prev = get_security_profile()
    yield
    set_security_profile(prev)


# ---------------------------------------------------------------------------
# Functional Erasure (EDPB Guidelines 02/2025)
# ---------------------------------------------------------------------------

class TestFunctionalErasure:
    def test_erase_entity(self):
        fe = FunctionalErasure()
        import os
        cek = os.urandom(32)
        entity_id = canonical_hash(b"test-entity")

        attestation = fe.erase_entity(entity_id, cek, "user-1", epoch=100)

        assert attestation["entity_id"] == entity_id
        assert attestation["method"] == "functional_erasure_edpb_02_2025"
        assert attestation["cek_zeroized"] is True
        assert attestation["epoch"] == 100
        assert len(attestation["destruction_proof"]) > 0

    def test_is_erased(self):
        fe = FunctionalErasure()
        import os
        entity_id = canonical_hash(b"erased-entity")
        assert fe.is_erased(entity_id) is False

        fe.erase_entity(entity_id, os.urandom(32), "user-1", epoch=1)
        assert fe.is_erased(entity_id) is True

    def test_get_attestation(self):
        fe = FunctionalErasure()
        import os
        entity_id = canonical_hash(b"attested-entity")
        cek = os.urandom(32)

        fe.erase_entity(entity_id, cek, "user-1", epoch=50)
        att = fe.get_attestation(entity_id)

        assert att is not None
        assert att["entity_id"] == entity_id
        assert att["requester_id"] == "user-1"

    def test_verify_attestation(self):
        fe = FunctionalErasure()
        import os
        entity_id = canonical_hash(b"verify-test")
        cek = os.urandom(32)

        attestation = fe.erase_entity(entity_id, cek, "user-1", epoch=200)
        assert fe.verify_attestation(attestation) is True

    def test_verify_tampered_attestation_fails(self):
        fe = FunctionalErasure()
        import os
        entity_id = canonical_hash(b"tamper-test")
        cek = os.urandom(32)

        attestation = fe.erase_entity(entity_id, cek, "user-1", epoch=300)
        attestation["destruction_proof"] = "tampered"
        assert fe.verify_attestation(attestation) is False

    def test_verify_incomplete_attestation_fails(self):
        fe = FunctionalErasure()
        assert fe.verify_attestation({"entity_id": "x"}) is False

    def test_audit_logging(self):
        logger = ComplianceAuditLogger(operator_id="test")
        fe = FunctionalErasure(audit_logger=logger)
        import os

        fe.erase_entity(canonical_hash(b"logged"), os.urandom(32), "user-1", epoch=1)
        events = logger.query(event_type=AuditEventType.ENTITY_DELETED)
        assert len(events) == 1
        assert events[0].action == "functional_erasure"

    def test_different_ceks_different_proofs(self):
        fe = FunctionalErasure()
        import os
        entity_id = canonical_hash(b"diff-cek")

        att1 = fe.erase_entity(entity_id, os.urandom(32), "user-1", epoch=1)
        fe._destroyed_ceks.clear()
        att2 = fe.erase_entity(entity_id, os.urandom(32), "user-1", epoch=1)

        assert att1["cek_fingerprint"] != att2["cek_fingerprint"]


# ---------------------------------------------------------------------------
# eIDAS 2.0 Trust Level Mapping
# ---------------------------------------------------------------------------

class TestEIDAS2TrustLevel:
    def test_low_maps_to_level3_blake2b(self):
        params = EIDAS2TrustLevel.LOW.to_security_params()
        assert params["level"] == 3
        assert params["hash_fn"] == HashFunction.BLAKE2B_256

    def test_substantial_maps_to_level3_sha384(self):
        params = EIDAS2TrustLevel.SUBSTANTIAL.to_security_params()
        assert params["level"] == 3
        assert params["hash_fn"] == HashFunction.SHA_384

    def test_high_maps_to_level5_sha384(self):
        params = EIDAS2TrustLevel.HIGH.to_security_params()
        assert params["level"] == 5
        assert params["hash_fn"] == HashFunction.SHA_384

    def test_high_requires_qualified_signature(self):
        assert EIDAS2TrustLevel.HIGH.requires_qualified_signature is True
        assert EIDAS2TrustLevel.LOW.requires_qualified_signature is False
        assert EIDAS2TrustLevel.SUBSTANTIAL.requires_qualified_signature is False

    def test_hsm_requirements(self):
        assert EIDAS2TrustLevel.HIGH.requires_hsm is True
        assert EIDAS2TrustLevel.SUBSTANTIAL.requires_hsm is True
        assert EIDAS2TrustLevel.LOW.requires_hsm is False

    def test_security_profile_integration(self):
        params = EIDAS2TrustLevel.HIGH.to_security_params()
        profile = SecurityProfile(**params)
        assert profile.level == 5
        assert profile.hash_fn == HashFunction.SHA_384
        assert profile.kem_ek_size == 1568  # ML-KEM-1024


# ---------------------------------------------------------------------------
# EU Data Act Classification
# ---------------------------------------------------------------------------

class TestDataActClassification:
    def test_user_data_portability(self):
        assert DataActClassification.USER_DATA.portability_required is True
        assert DataActClassification.TRADE_SECRET.portability_required is False

    def test_co_generated_portability(self):
        assert DataActClassification.CO_GENERATED.portability_required is True

    def test_public_sector_sovereignty(self):
        assert DataActClassification.PUBLIC_SECTOR.sovereignty_constrained is True
        assert DataActClassification.USER_DATA.sovereignty_constrained is False

    def test_mixed_sovereignty(self):
        assert DataActClassification.MIXED.sovereignty_constrained is True

    def test_access_rights(self):
        assert DataActClassification.USER_DATA.access_rights_apply is True
        assert DataActClassification.CO_GENERATED.access_rights_apply is True
        assert DataActClassification.PUBLIC_SECTOR.access_rights_apply is True
        assert DataActClassification.TRADE_SECRET.access_rights_apply is False
        assert DataActClassification.NON_PERSONAL.access_rights_apply is False

    def test_all_classifications_exist(self):
        assert len(DataActClassification) == 6
        names = {c.value for c in DataActClassification}
        assert "user_data" in names
        assert "co_generated" in names
        assert "trade_secret" in names
        assert "public_sector" in names
        assert "non_personal" in names
        assert "mixed" in names

"""Tests for runtime assurance-mode gating."""

import pytest

import src.ltp.primitives as primitives
from src.ltp.compliance import CryptoProviderMode, FIPSCryptoProvider
from src.ltp.primitives import (
    AssuranceMode,
    get_assurance_mode,
    get_runtime_assurance_status,
    set_assurance_mode,
)


@pytest.fixture(autouse=True)
def restore_assurance_mode():
    original = get_assurance_mode()
    yield
    primitives._assurance_mode = original


def test_runtime_assurance_status_reports_mode():
    set_assurance_mode(AssuranceMode.DEVELOPMENT)
    status = get_runtime_assurance_status()
    assert status["mode"] == "development"
    assert "pqcrypto_kem_available" in status
    assert "pynacl_available" in status


def test_production_mode_rejects_missing_real_backends(monkeypatch):
    monkeypatch.setattr(primitives, "_pqcrypto_kem_available", False)
    monkeypatch.setattr(primitives, "_pqcrypto_sign_available", False)
    monkeypatch.setattr(primitives, "_pynacl_available", False)

    with pytest.raises(RuntimeError, match="Production mode requires real cryptographic backends"):
        set_assurance_mode(AssuranceMode.PRODUCTION)


def test_compliance_strict_rejects_missing_compliance_backends(monkeypatch):
    monkeypatch.setattr(primitives, "_pqcrypto_kem_available", True)
    monkeypatch.setattr(primitives, "_pqcrypto_sign_available", True)
    monkeypatch.setattr(primitives, "_pynacl_available", True)
    monkeypatch.setattr(primitives, "_cryptography_available", False)
    monkeypatch.setattr(primitives, "_check_fips_runtime_available", lambda: True)

    with pytest.raises(RuntimeError, match="Compliance-strict mode requires compliance backends"):
        set_assurance_mode(AssuranceMode.COMPLIANCE_STRICT)


def test_fips_provider_rejects_missing_cryptography_in_compliance_strict(monkeypatch):
    monkeypatch.setattr(primitives, "_pqcrypto_kem_available", True)
    monkeypatch.setattr(primitives, "_pqcrypto_sign_available", True)
    monkeypatch.setattr(primitives, "_pynacl_available", True)
    monkeypatch.setattr(primitives, "_cryptography_available", True)
    monkeypatch.setattr(primitives, "_check_fips_runtime_available", lambda: True)
    set_assurance_mode(AssuranceMode.COMPLIANCE_STRICT)

    monkeypatch.setattr(FIPSCryptoProvider, "_check_fips_available", staticmethod(lambda: True))
    monkeypatch.setattr(
        FIPSCryptoProvider,
        "_check_cryptography_available",
        staticmethod(lambda: False),
    )

    with pytest.raises(RuntimeError, match="Compliance-strict FIPS mode requires"):
        FIPSCryptoProvider(CryptoProviderMode.FIPS)

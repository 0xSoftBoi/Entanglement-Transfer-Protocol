"""
E1 — operator key custody (cloud/keys.py).

Covers the Signer seam end-to-end: LocalSigner equivalence with the reference
KeyPair path, KMSSigner against a faithful fake of the AWS KMS API (real
ML-DSA-65 keys, real DER SubjectPublicKeyInfo encoding), the full
CloudNotaryService flow under KMS custody (receipts verify, restart-rebuild
works, the DB never holds a signing key), and the fail-fast paths for
misconfigured keys.
"""

from __future__ import annotations

import os

import pytest

from src.ltp.keypair import KeyPair
from src.ltp.primitives import MLDSA
from src.ltp.provenance import ProvenanceLog, seal_capture
from src.ltp.cloud.keys import (
    KMSSigner, LocalSigner, signer_from_env, _der_spki_raw_key,
)
from src.ltp.cloud.service import CloudNotaryService
from src.ltp.cloud.store import CloudStore
from src.ltp.cloud.witness import Witness


# ---------------------------------------------------------------------------
# Fake AWS KMS — real crypto, real DER, boto3-shaped responses
# ---------------------------------------------------------------------------

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _spki(raw_key: bytes) -> bytes:
    """Encode a raw public key as DER SubjectPublicKeyInfo, the way KMS's
    GetPublicKey returns it (AlgorithmIdentifier + BIT STRING)."""
    alg = _der_tlv(0x30, _der_tlv(0x06, bytes.fromhex("2b6501")))  # placeholder OID
    bitstr = _der_tlv(0x03, b"\x00" + raw_key)
    return _der_tlv(0x30, alg + bitstr)


class FakeKMSClient:
    """The subset of botocore's KMS client that KMSSigner touches, backed by
    a real ML-DSA-65 keypair so signatures genuinely verify."""

    def __init__(self, keypair: KeyPair, key_id: str = "alias/etp-operator"):
        self._kp = keypair
        self.key_id = key_id
        self.sign_calls = 0

    def get_public_key(self, KeyId: str):
        assert KeyId == self.key_id, "unknown key id"
        return {"PublicKey": _spki(self._kp.vk), "KeySpec": "ML_DSA_65"}

    def sign(self, KeyId: str, Message: bytes, MessageType: str,
             SigningAlgorithm: str):
        assert KeyId == self.key_id
        assert MessageType == "RAW"
        assert SigningAlgorithm == KMSSigner.SIGNING_ALGORITHM
        self.sign_calls += 1
        return {"Signature": MLDSA.sign(self._kp.sk, Message)}


class BrokenKMSClient(FakeKMSClient):
    """Returns syntactically valid but cryptographically wrong signatures —
    the misconfigured-key-spec failure mode the fail-fast check exists for."""

    def sign(self, **kwargs):
        out = super().sign(**kwargs)
        sig = bytearray(out["Signature"])
        sig[0] ^= 0xFF
        return {"Signature": bytes(sig)}


@pytest.fixture()
def kms_kp():
    return KeyPair.generate("kms-operator")


@pytest.fixture()
def kms(kms_kp):
    return FakeKMSClient(kms_kp)


# ---------------------------------------------------------------------------
# DER + signer units
# ---------------------------------------------------------------------------

class TestDERAndSigners:
    def test_spki_roundtrip(self, kms_kp):
        assert _der_spki_raw_key(_spki(kms_kp.vk)) == kms_kp.vk

    def test_spki_long_form_length(self):
        # ML-DSA-65 vks are 1952 bytes, so the DER uses long-form lengths —
        # exercise it explicitly with a large payload too.
        raw = os.urandom(4000)
        assert _der_spki_raw_key(_spki(raw)) == raw

    def test_spki_rejects_garbage(self):
        with pytest.raises(ValueError):
            _der_spki_raw_key(b"\x02\x01\x01")  # INTEGER, not SEQUENCE
        with pytest.raises(ValueError):
            _der_spki_raw_key(b"\x30\x82")      # truncated long form

    def test_local_signer_matches_keypair_signing(self, kms_kp):
        signer = LocalSigner(kms_kp)
        payload = b"payload"
        assert signer.vk == kms_kp.vk
        assert MLDSA.verify(kms_kp.vk, payload, signer.sign(payload))

    def test_kms_signer_vk_and_sign(self, kms, kms_kp):
        signer = KMSSigner(kms.key_id, client=kms)
        assert signer.vk == kms_kp.vk
        payload = b"tree head bytes"
        sig = signer.sign(payload)
        assert MLDSA.verify(kms_kp.vk, payload, sig)
        assert kms.sign_calls == 1

    def test_kms_signer_rejects_wrong_key_size(self, kms_kp):
        class NotMLDSA(FakeKMSClient):
            def get_public_key(self, KeyId):
                return {"PublicKey": _spki(os.urandom(65))}  # ECC-sized
        with pytest.raises(ValueError, match="not ML-DSA-65"):
            KMSSigner("alias/etp-operator", client=NotMLDSA(kms_kp))

    def test_kms_signer_fail_fast_on_bad_signature(self, kms_kp):
        broken = BrokenKMSClient(kms_kp)
        signer = KMSSigner(broken.key_id, client=broken)
        with pytest.raises(RuntimeError, match="does not verify"):
            signer.sign(b"payload")


# ---------------------------------------------------------------------------
# Log + witness over an external signer
# ---------------------------------------------------------------------------

class TestSignerSeam:
    def test_provenance_log_over_kms_signer(self, kms, kms_kp):
        signer = KMSSigner(kms.key_id, client=kms)
        log = ProvenanceLog(signer)
        recipient = KeyPair.generate("recipient")
        cap = seal_capture(b"artifact", recipient.ek,
                           originator_id="device-1", capture_id="cap-1")
        sealed, manifest = cap.sealed, cap.manifest
        idx = log.append_manifest(manifest)
        sth = log.publish_sth()
        assert sth.verify()
        assert sth.operator_vk == kms_kp.vk
        proof = log.inclusion_proof(idx)
        assert log.verify_capture(manifest, sealed, proof, sth,
                                  expected_operator_vk=kms_kp.vk)

    def test_witness_accepts_signer(self, kms, kms_kp):
        operator = KeyPair.generate("op")
        log = ProvenanceLog(operator)
        recipient = KeyPair.generate("recipient")
        manifest = seal_capture(b"x", recipient.ek, originator_id="dev",
                                capture_id="cap-w").manifest
        log.append_manifest(manifest)
        sth = log.publish_sth()

        cosig = Witness(KMSSigner(kms.key_id, client=kms)).cosign(sth)
        assert cosig.witness_vk == kms_kp.vk
        assert cosig.verify(sth)

    def test_merkle_log_requires_exactly_one_custody_mode(self, kms_kp):
        from src.ltp.merkle_log import MerkleLog
        with pytest.raises(ValueError):
            MerkleLog(kms_kp.vk)  # neither sk nor signer
        with pytest.raises(ValueError):
            MerkleLog(kms_kp.vk, kms_kp.sk, signer=LocalSigner(kms_kp))
        with pytest.raises(ValueError):
            other = KeyPair.generate("other")
            MerkleLog(kms_kp.vk, signer=LocalSigner(other))  # vk mismatch


# ---------------------------------------------------------------------------
# Service under KMS custody
# ---------------------------------------------------------------------------

class TestServiceUnderKMS:
    def _service(self, store, kms):
        return CloudNotaryService(
            store, admin_token="admin",
            operator=KMSSigner(kms.key_id, client=kms), sync_webhooks=True)

    def test_end_to_end_receipt_and_restart(self, tmp_path, kms, kms_kp):
        db = tmp_path / "kms.db"
        store = CloudStore(str(db))
        svc = self._service(store, kms)
        tenant = svc.create_tenant("acme")["tenant_id"]

        recipient = KeyPair.generate("recipient")
        manifest = seal_capture(b"evidence", recipient.ek,
                                originator_id="device",
                                capture_id="cap-e2e").manifest
        receipt, created = svc.submit(tenant, manifest)
        assert created
        assert receipt.sth.operator_vk == kms_kp.vk
        assert receipt.sth.verify()

        # The DB must not contain a signing key under KMS custody.
        rows = store._query(
            "SELECT value FROM service_config WHERE key='operator'")
        assert rows == [] or "sk" not in rows[0][0], \
            "signing key persisted despite KMS custody"

        # Restart: a fresh service over the same store + signer rebuilds the
        # log and treats the resubmission as a replay (idempotent, same STH).
        svc2 = self._service(CloudStore(str(db)), kms)
        receipt2, created2 = svc2.submit(tenant, manifest)
        assert not created2
        assert receipt2.sth.root_hash == receipt.sth.root_hash

    def test_signer_from_env_kms(self, tmp_path, kms, kms_kp, monkeypatch):
        monkeypatch.setenv("ETP_CLOUD_KMS_KEY_ID", kms.key_id)
        store = CloudStore(str(tmp_path / "env.db"))
        signer = signer_from_env(store, kms_client=kms)
        assert isinstance(signer, KMSSigner)
        assert signer.vk == kms_kp.vk

    def test_signer_from_env_local_default(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ETP_CLOUD_KMS_KEY_ID", raising=False)
        store = CloudStore(str(tmp_path / "local.db"))
        signer = signer_from_env(store)
        assert isinstance(signer, LocalSigner)
        # Stable across calls: same persisted operator.
        assert signer_from_env(store).vk == signer.vk

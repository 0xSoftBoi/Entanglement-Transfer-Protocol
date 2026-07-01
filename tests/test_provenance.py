"""
Tests for the provenance MVP (src/ltp/provenance.py).

Validates the "provenance wedge" contract — post-quantum sealed capture bound to
an RFC-6962 tamper-evident log:

  TestSealRoundTrip     — confidentiality: only the recipient opens; overhead is
                          constant regardless of payload size
  TestProvenanceVerify  — an auditor verifies authenticity/inclusion with no
                          plaintext and no operator secret
  TestTamperEvidence    — every alteration (artifact, sealed blob, manifest,
                          STH, log record) fails loudly
  TestForkAndAppendOnly — equivocation detection + append-only guarantee
"""

import pytest

from src.ltp import KeyPair
from src.ltp.merkle_log import MerkleLog
from src.ltp.primitives import H_bytes
from src.ltp.provenance import ProvenanceLog, ProvenanceReceipt, CaptureManifest, SEAL_OVERHEAD


@pytest.fixture
def operator() -> KeyPair:
    return KeyPair.generate("operator")


@pytest.fixture
def recipient() -> KeyPair:
    return KeyPair.generate("recipient")


@pytest.fixture
def plog(operator: KeyPair) -> ProvenanceLog:
    return ProvenanceLog(operator)


# ---------------------------------------------------------------------------
# Confidentiality
# ---------------------------------------------------------------------------

class TestSealRoundTrip:
    def test_recipient_recovers_original(self, plog, recipient):
        art = b"confidential capture payload"
        cap, _ = plog.record_capture(art, recipient.ek, originator_id="sensor-1")
        assert ProvenanceLog.open_capture(cap.sealed, recipient, cap.manifest) == art

    def test_unauthorized_key_cannot_open(self, plog, recipient, eve):
        cap, _ = plog.record_capture(b"secret", recipient.ek, originator_id="sensor-1")
        with pytest.raises(ValueError):
            ProvenanceLog.open_capture(cap.sealed, eve)

    @pytest.mark.parametrize("size", [0, 1, 32, 1024, 100_000])
    def test_seal_overhead_is_constant(self, plog, recipient, size):
        """The headline property: seal cost does not grow with payload."""
        cap, _ = plog.record_capture(b"x" * size, recipient.ek, originator_id="s")
        assert cap.size - size == SEAL_OVERHEAD

    def test_open_rejects_payload_mismatching_manifest(self, plog, recipient):
        """A sealed blob whose plaintext doesn't match its manifest is rejected."""
        cap_a, _ = plog.record_capture(b"artifact A", recipient.ek, originator_id="s")
        cap_b, _ = plog.record_capture(b"artifact B", recipient.ek, originator_id="s")
        # Try to open B's sealed blob but claim A's manifest → content_hash mismatch.
        with pytest.raises(ValueError, match="content_hash"):
            ProvenanceLog.open_capture(cap_b.sealed, recipient, cap_a.manifest)


# ---------------------------------------------------------------------------
# Provenance verification (auditor perspective)
# ---------------------------------------------------------------------------

class TestProvenanceVerify:
    def test_auditor_verifies_without_plaintext(self, plog, recipient):
        cap, idx = plog.record_capture(b"payload", recipient.ek, originator_id="sensor-7")
        sth = plog.publish_sth()
        proof = plog.inclusion_proof(idx)
        assert ProvenanceLog.verify_capture(cap.manifest, cap.sealed, proof, sth)

    def test_inclusion_proof_is_logarithmic(self, plog, recipient):
        for i in range(16):
            _, idx = plog.record_capture(f"c{i}".encode(), recipient.ek, originator_id="s")
        sth = plog.publish_sth()
        proof = plog.inclusion_proof(idx)
        # 16 leaves → audit path ≤ ceil(log2(16)) = 4.
        assert proof.path_length <= 4

    def test_verify_each_of_a_batch(self, plog, recipient):
        caps = [plog.record_capture(f"c{i}".encode(), recipient.ek, originator_id="s")
                for i in range(5)]
        sth = plog.publish_sth()
        for cap, idx in caps:
            proof = plog.inclusion_proof(idx)
            assert ProvenanceLog.verify_capture(cap.manifest, cap.sealed, proof, sth)


# ---------------------------------------------------------------------------
# Tamper evidence
# ---------------------------------------------------------------------------

class TestTamperEvidence:
    def _one_capture(self, plog, recipient):
        cap, idx = plog.record_capture(b"the payload", recipient.ek, originator_id="s")
        sth = plog.publish_sth()
        return cap, plog.inclusion_proof(idx), sth

    def test_altered_sealed_blob_fails(self, plog, recipient):
        cap, proof, sth = self._one_capture(plog, recipient)
        bad = bytearray(cap.sealed); bad[-1] ^= 0x01
        assert not ProvenanceLog.verify_capture(cap.manifest, bytes(bad), proof, sth)

    def test_swapped_manifest_fails(self, plog, recipient):
        cap, proof, sth = self._one_capture(plog, recipient)
        forged = CaptureManifest(
            capture_id=cap.manifest.capture_id,
            originator_id="attacker",              # changed field
            captured_at=cap.manifest.captured_at,
            content_hash=cap.manifest.content_hash,
            sealed_hash=cap.manifest.sealed_hash,
            meta=cap.manifest.meta,
        )
        assert not ProvenanceLog.verify_capture(forged, cap.sealed, proof, sth)

    def test_forged_sth_root_fails(self, plog, recipient):
        cap, proof, sth = self._one_capture(plog, recipient)
        sth.root_hash = bytes(32)  # tamper after signing
        assert not sth.verify()
        assert not ProvenanceLog.verify_capture(cap.manifest, cap.sealed, proof, sth)

    def test_proof_against_wrong_root_fails(self, plog, recipient):
        """A proof issued for root R must not verify against a different STH root."""
        cap, idx = plog.record_capture(b"payload", recipient.ek, originator_id="s")
        sth1 = plog.publish_sth()
        proof1 = plog.inclusion_proof(idx)
        # Grow the log and re-attest → different root.
        plog.record_capture(b"another", recipient.ek, originator_id="s")
        sth2 = plog.publish_sth()
        assert sth1.root_hash != sth2.root_hash
        assert not ProvenanceLog.verify_capture(cap.manifest, cap.sealed, proof1, sth2)

    def test_manifest_content_hash_binds_artifact(self, plog, recipient):
        """content_hash in the manifest is the SHA3-256 of the real artifact."""
        art = b"specific bytes"
        cap, _ = plog.record_capture(art, recipient.ek, originator_id="s")
        assert cap.manifest.content_hash == H_bytes(art)


# ---------------------------------------------------------------------------
# Fork detection + append-only
# ---------------------------------------------------------------------------

class TestOperatorPinning:
    """A receipt only proves authenticity when the operator key is pinned."""

    def test_attacker_receipt_passes_without_pin_but_fails_with_pin(self, recipient):
        honest = KeyPair.generate("honest-notary")
        attacker = KeyPair.generate("attacker")
        artifact = b"authentic evidence"

        # Attacker runs their OWN notary, seals the same artifact, lies in metadata.
        alog = ProvenanceLog(attacker)
        cap, idx = alog.record_capture(artifact, recipient.ek, originator_id="sensor-7")
        sth = alog.publish_sth()
        proof = alog.inclusion_proof(idx)

        # Unpinned: self-consistent, so it verifies (this is the documented gap).
        assert ProvenanceLog.verify_capture(cap.manifest, cap.sealed, proof, sth)
        # Pinned to the honest notary: the forgery is rejected.
        assert not ProvenanceLog.verify_capture(
            cap.manifest, cap.sealed, proof, sth, expected_operator_vk=honest.vk
        )
        # Pinned to the actual signer: passes.
        assert ProvenanceLog.verify_capture(
            cap.manifest, cap.sealed, proof, sth, expected_operator_vk=attacker.vk
        )

    def test_receipt_verify_honors_pin(self, plog, recipient):
        cap, idx = plog.record_capture(b"x", recipient.ek, originator_id="s")
        sth = plog.publish_sth()
        receipt = ProvenanceReceipt.build(cap.manifest, plog.inclusion_proof(idx), sth)
        assert receipt.verify(cap.sealed, expected_operator_vk=sth.operator_vk)
        assert not receipt.verify(cap.sealed, expected_operator_vk=b"\x00" * len(sth.operator_vk))


class TestOriginatorSignature:
    """The capturing device can cryptographically attest, not just be named."""

    def test_signed_capture_verifies_and_pins(self, plog, recipient):
        device = KeyPair.generate("sensor-7")
        cap, idx = plog.record_capture(
            b"sensor reading", recipient.ek, originator_id="sensor-7", originator=device
        )
        sth = plog.publish_sth()
        proof = plog.inclusion_proof(idx)
        # signature present and valid
        assert cap.manifest.originator_vk == device.vk
        assert ProvenanceLog.verify_capture(cap.manifest, cap.sealed, proof, sth)
        # pin to the right device passes, wrong device fails
        assert ProvenanceLog.verify_capture(
            cap.manifest, cap.sealed, proof, sth, expected_originator_vk=device.vk
        )
        assert not ProvenanceLog.verify_capture(
            cap.manifest, cap.sealed, proof, sth,
            expected_originator_vk=KeyPair.generate("other").vk,
        )

    def test_unsigned_capture_fails_when_originator_pin_required(self, plog, recipient):
        cap, idx = plog.record_capture(b"x", recipient.ek, originator_id="sensor-7")
        sth = plog.publish_sth()
        proof = plog.inclusion_proof(idx)
        assert cap.manifest.originator_vk == b""
        # unsigned still verifies unpinned (operator-vouched)...
        assert ProvenanceLog.verify_capture(cap.manifest, cap.sealed, proof, sth)
        # ...but not when a specific device is required
        assert not ProvenanceLog.verify_capture(
            cap.manifest, cap.sealed, proof, sth,
            expected_originator_vk=KeyPair.generate("sensor-7").vk,
        )

    def test_forged_originator_signature_rejected(self, plog, recipient):
        device = KeyPair.generate("sensor-7")
        cap, idx = plog.record_capture(
            b"reading", recipient.ek, originator_id="sensor-7", originator=device
        )
        # Tamper the device signature; capture must fail even before notarization checks.
        from dataclasses import replace
        forged = replace(cap.manifest, originator_sig=b"\x00" * len(cap.manifest.originator_sig))
        sth = plog.publish_sth()
        proof = plog.inclusion_proof(idx)
        assert not ProvenanceLog.verify_capture(forged, cap.sealed, proof, sth)

    def test_originator_signature_survives_receipt_roundtrip(self, plog, recipient):
        device = KeyPair.generate("sensor-7")
        cap, idx = plog.record_capture(
            b"reading", recipient.ek, originator_id="sensor-7", originator=device
        )
        sth = plog.publish_sth()
        receipt = ProvenanceReceipt.build(cap.manifest, plog.inclusion_proof(idx), sth)
        r2 = ProvenanceReceipt.from_json(receipt.to_json())
        assert r2.verify(cap.sealed, expected_originator_vk=device.vk)


class TestForkAndAppendOnly:
    def test_equivocation_detected(self, operator, recipient):
        """Two signed roots at the same sequence over different histories = fork."""
        a = ProvenanceLog(operator)
        b = ProvenanceLog(operator)
        a.record_capture(b"history A", recipient.ek, originator_id="s")
        b.record_capture(b"history B", recipient.ek, originator_id="s")
        sth_a = a.publish_sth()
        sth_b = b.publish_sth()
        assert sth_a.sequence == sth_b.sequence
        assert sth_a.root_hash != sth_b.root_hash
        assert MerkleLog.detect_equivocation(sth_a, sth_b)

    def test_honest_extension_is_not_equivocation(self, plog, recipient):
        plog.record_capture(b"c0", recipient.ek, originator_id="s")
        sth0 = plog.publish_sth()
        plog.record_capture(b"c1", recipient.ek, originator_id="s")
        sth1 = plog.publish_sth()
        # Different sequences → not an equivocation, and a valid append-only step.
        assert not MerkleLog.detect_equivocation(sth0, sth1)
        assert plog.verify_append_only(sth0, sth1)

    def test_append_only_holds_across_growth(self, plog, recipient):
        _, _ = plog.record_capture(b"first", recipient.ek, originator_id="s")
        old = plog.publish_sth()
        for i in range(5):
            plog.record_capture(f"more-{i}".encode(), recipient.ek, originator_id="s")
        new = plog.publish_sth()
        assert plog.verify_append_only(old, new)

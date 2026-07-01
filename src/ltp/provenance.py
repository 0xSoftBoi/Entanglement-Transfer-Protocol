"""
Provenance — post-quantum sealed capture + tamper-evident notarization.

This is the "provenance wedge" MVP: it composes two capabilities ETP already
ships into the workflow that competitive/funding research identified as the
defensible, unfunded whitespace —

  1. Confidentiality  — SealedBox (ML-KEM-768 + XChaCha20-Poly1305) seals an
                        artifact to a recipient with CONSTANT overhead
                        (1136 bytes) regardless of payload size. This is the
                        harvest-now-decrypt-later defense for data that must
                        stay secret for years/decades.
  2. Provenance       — a CT-style RFC-6962 Merkle log (merkle_log/) notarizes
                        a signed *capture manifest* so any third party can later
                        prove the artifact is authentic, unaltered, and was
                        captured by a specific originator — WITHOUT holding the
                        confidential payload and WITHOUT a blockchain.

The two are bound together: the manifest commits to a hash of the sealed
artifact, so the confidential payload and its public, verifiable chain-of-custody
travel as one object. Tampering with either the artifact or the log record makes
verification fail loudly.

This is intentionally transport-agnostic: a SealedCapture is a self-contained
blob that can be carried over any link — a satellite downlink, a tactical mesh,
a data mule crossing a disconnected gap, or a hospital network — and notarized
whenever the operator next has connectivity. That "seal now, notarize on
reconnect, verify anywhere" property is the delay-tolerant provenance fusion.

Typical flow:

    op   = KeyPair.generate("operator")     # runs the notary log
    bob  = KeyPair.generate("recipient")    # authorized to open captures
    plog = ProvenanceLog(op)

    capture, idx = plog.record_capture(
        artifact, recipient_ek=bob.ek, originator_id="sensor-7"
    )
    sth   = plog.publish_sth()              # operator attestation of log state
    proof = plog.inclusion_proof(idx)

    # Auditor (holds neither the artifact nor the operator key):
    assert ProvenanceLog.verify_capture(capture.manifest, capture.sealed, proof, sth)

    # Authorized recipient recovers the plaintext (and re-checks integrity):
    plaintext = ProvenanceLog.open_capture(capture.sealed, bob, capture.manifest)
"""

from __future__ import annotations

import json
import struct
import time
from dataclasses import dataclass, field

from .keypair import KeyPair, SealedBox
from .primitives import H_bytes, AEAD, MLKEM
from .merkle_log import MerkleLog, SignedTreeHead, InclusionProof

__all__ = ["CaptureManifest", "SealedCapture", "ProvenanceLog", "SEAL_OVERHEAD"]

# Constant byte overhead of a SealedBox seal, independent of plaintext size:
#   ML-KEM ciphertext (1088) + AEAD nonce (16) + AEAD tag (32) = 1136 bytes.
# This is the headline property — post-quantum confidentiality whose cost does
# not grow with payload, which is what makes it viable on scarce/uplink-limited
# and store-and-forward links.
SEAL_OVERHEAD = MLKEM.CT_SIZE + AEAD.NONCE_SIZE + AEAD.TAG_SIZE

# Domain-separation tag for the canonical manifest encoding, so manifest bytes
# can never be confused with any other signed/logged structure in the system.
_MANIFEST_DOMAIN = b"GSX-LTP/provenance-capture/v1\x00"


def _lp(b: bytes) -> bytes:
    """Length-prefix a byte string (4-byte big-endian length)."""
    return struct.pack(">I", len(b)) + b


@dataclass(frozen=True)
class CaptureManifest:
    """
    The public, notarizable record of a single capture.

    Contains NO confidential data — only hashes and metadata — so it is safe to
    place in a public transparency log. `content_hash` binds the plaintext
    artifact; `sealed_hash` binds the exact sealed blob that was transported.
    Both are needed: content_hash lets the authorized recipient confirm they
    recovered the original bytes; sealed_hash lets an auditor confirm the sealed
    blob in front of them is the one that was notarized.
    """

    capture_id: str
    originator_id: str
    captured_at: float
    content_hash: bytes   # SHA3-256 of the plaintext artifact (canonical lane)
    sealed_hash: bytes    # SHA3-256 of the sealed ciphertext blob
    meta: dict = field(default_factory=dict)

    def canonical_bytes(self) -> bytes:
        """
        Deterministic byte encoding — the exact bytes appended to the log.

        Same fields always produce the same bytes (metadata keys are sorted),
        so the leaf hash and every downstream proof are reproducible.
        """
        meta_json = json.dumps(self.meta, sort_keys=True, separators=(",", ":")).encode()
        return (
            _MANIFEST_DOMAIN
            + _lp(self.capture_id.encode())
            + _lp(self.originator_id.encode())
            + struct.pack(">d", self.captured_at)
            + self.content_hash
            + self.sealed_hash
            + _lp(meta_json)
        )


@dataclass(frozen=True)
class SealedCapture:
    """A confidential artifact plus its public manifest — one transportable unit."""

    manifest: CaptureManifest
    sealed: bytes         # SealedBox output: only the recipient's dk can open it

    @property
    def size(self) -> int:
        return len(self.sealed)


class ProvenanceLog:
    """
    Operator-run notary: seals captures and commits their manifests to an
    RFC-6962 append-only Merkle log.

    One ProvenanceLog is run by one operator keypair (the notary). The operator
    signs Tree Heads (STHs); auditors verify captures against those STHs. The
    operator never sees plaintext beyond what it is asked to seal, and never
    holds recipients' decapsulation keys.
    """

    def __init__(self, operator: KeyPair) -> None:
        self._operator = operator
        self._log = MerkleLog(operator.vk, operator.sk)

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_capture(
        self,
        artifact: bytes,
        recipient_ek: bytes,
        *,
        originator_id: str,
        capture_id: str | None = None,
        captured_at: float | None = None,
        meta: dict | None = None,
    ) -> tuple[SealedCapture, int]:
        """
        Seal `artifact` to `recipient_ek` and notarize a manifest of it.

        Returns the transportable SealedCapture and the log leaf index used to
        generate inclusion proofs. Call publish_sth() afterward (optionally
        batching several captures per STH) to attest the new log state.
        """
        sealed = SealedBox.seal(artifact, recipient_ek)
        manifest = CaptureManifest(
            capture_id=capture_id if capture_id is not None else H_bytes(sealed).hex()[:32],
            originator_id=originator_id,
            captured_at=captured_at if captured_at is not None else time.time(),
            content_hash=H_bytes(artifact),
            sealed_hash=H_bytes(sealed),
            meta=meta or {},
        )
        idx = self._log.append(manifest.canonical_bytes())
        return SealedCapture(manifest=manifest, sealed=sealed), idx

    def publish_sth(self) -> SignedTreeHead:
        """Sign and publish the current log state (operator attestation)."""
        return self._log.publish_sth()

    def inclusion_proof(self, index: int) -> InclusionProof:
        """O(log N) proof that the capture at `index` is in the log."""
        return self._log.inclusion_proof(index)

    @property
    def size(self) -> int:
        return self._log.size

    @property
    def latest_sth(self) -> SignedTreeHead | None:
        return self._log.latest_sth

    def verify_append_only(
        self, older: SignedTreeHead, newer: SignedTreeHead
    ) -> bool:
        """True iff `newer` is an append-only extension of `older` (RFC 6962)."""
        return self._log.verify_append_only(older, newer)

    # ------------------------------------------------------------------
    # Verification (static — an auditor needs no ProvenanceLog instance)
    # ------------------------------------------------------------------

    @staticmethod
    def verify_capture(
        manifest: CaptureManifest,
        sealed: bytes,
        proof: InclusionProof,
        sth: SignedTreeHead,
    ) -> bool:
        """
        Independently verify a capture's provenance. Returns True iff ALL hold:

          1. The STH signature is valid  — the operator really attested this
             log state (root_hash) at this sequence.
          2. The sealed blob matches the manifest  — sealed_hash == H(sealed),
             so this is the exact artifact that was notarized (not a swap).
          3. The manifest is in the log under the attested root  — the inclusion
             proof reconstructs sth.root_hash from the manifest bytes.

        Needs neither the plaintext nor any operator secret. Any tamper —
        altered artifact, swapped sealed blob, edited log record, forged STH —
        flips at least one check to False.
        """
        if not sth.verify():
            return False
        if not _consteq(manifest.sealed_hash, H_bytes(sealed)):
            return False
        return proof.verify(manifest.canonical_bytes(), sth.root_hash)

    @staticmethod
    def open_capture(
        sealed: bytes,
        recipient: KeyPair,
        manifest: CaptureManifest | None = None,
    ) -> bytes:
        """
        Recover the plaintext artifact (authorized recipient only).

        If `manifest` is given, the recovered plaintext is re-checked against
        manifest.content_hash and a ValueError is raised on mismatch — so a
        recipient can detect a payload that does not match its notarized record.

        Raises ValueError if `recipient` is not the sealed-to party or the
        sealed blob was corrupted (AEAD authentication failure).
        """
        plaintext = SealedBox.unseal(sealed, recipient)
        if manifest is not None and not _consteq(H_bytes(plaintext), manifest.content_hash):
            raise ValueError(
                "Recovered plaintext does not match manifest content_hash — "
                "artifact and provenance record disagree"
            )
        return plaintext


def _consteq(a: bytes, b: bytes) -> bool:
    """Constant-time comparison for hash/tag checks."""
    import hmac as _hmac
    return _hmac.compare_digest(a, b)

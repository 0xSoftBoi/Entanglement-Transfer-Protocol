"""
Provenance — post-quantum sealed capture + tamper-evident notarization.

This is the "provenance wedge" MVP: it composes two capabilities ETP already
ships into the workflow that competitive/funding research identified as the
defensible, unfunded whitespace —

  1. Confidentiality  — SealedBox (ML-KEM-768 + XChaCha20-Poly1305) seals an
                        artifact to a recipient with CONSTANT overhead
                        (SEAL_OVERHEAD bytes) regardless of payload size. This is the
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

import hmac
import json
import time
from dataclasses import dataclass, field, replace

from .keypair import KeyPair, SealedBox
from .primitives import H_bytes, MLDSA
from .encoding import CanonicalEncoder, b64e, b64d
from .domain import DOMAIN_PROVENANCE_CAPTURE, DOMAIN_PROVENANCE_ORIGINATOR
from .erasure import ErasureCoder
from .merkle_log import MerkleLog, SignedTreeHead, InclusionProof

__all__ = [
    "CaptureManifest",
    "SealedCapture",
    "ProvenanceLog",
    "ProvenanceReceipt",
    "BundleManifest",
    "bundle_sealed",
    "reassemble_sealed",
    "seal_capture",
    "SEAL_OVERHEAD",
]

# Constant byte overhead of a SealedBox seal, independent of plaintext size:
# ML-KEM ciphertext + AEAD nonce + tag. This is the headline property —
# post-quantum confidentiality whose cost does not grow with payload, which is
# what makes it viable on scarce/uplink-limited and store-and-forward links.
# Single source of truth lives on SealedBox.
SEAL_OVERHEAD = SealedBox.OVERHEAD


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

    `originator_vk` / `originator_sig` are optional: when the capturing device
    signs, the originator's ML-DSA-65 signature over (originator_id, content_hash,
    captured_at) cryptographically binds the artifact to that device — so
    "captured by sensor-7" is the device's own attestation, not just a string the
    operator recorded. Empty when the capture is only operator-vouched.
    """

    capture_id: str
    originator_id: str
    captured_at: float
    content_hash: bytes   # SHA3-256 of the plaintext artifact (canonical lane)
    sealed_hash: bytes    # SHA3-256 of the sealed ciphertext blob
    originator_vk: bytes = b""   # ML-DSA-65 verification key of the capturing device
    originator_sig: bytes = b""  # originator signature over originator_signed_payload()
    meta: dict = field(default_factory=dict)

    def originator_signed_payload(self) -> bytes:
        """
        The bytes the originating device signs: a domain-tagged binding of its
        identity to the captured content and time. Excludes the signature and
        vk themselves (no circularity) and the seal (the originator attests to
        the content it captured, independent of who it is later sealed to).
        """
        return (
            CanonicalEncoder(DOMAIN_PROVENANCE_ORIGINATOR)
            .string(self.originator_id)
            .raw_bytes(self.content_hash)
            .float64(self.captured_at)
            .finalize()
        )

    def canonical_bytes(self) -> bytes:
        """
        Deterministic byte encoding — the exact bytes appended to the log.

        Uses the project's domain-tagged CanonicalEncoder (same lane as STHs and
        commitment records), so metadata is sorted, floats reject NaN/Inf, and
        the wire format is CBOR-translatable. Reproducible → so are all proofs.
        The originator vk/sig are included, so the log commits to the device's
        attestation too.
        """
        return (
            CanonicalEncoder(DOMAIN_PROVENANCE_CAPTURE)
            .string(self.capture_id)
            .string(self.originator_id)
            .float64(self.captured_at)
            .raw_bytes(self.content_hash)
            .raw_bytes(self.sealed_hash)
            .length_prefixed_bytes(self.originator_vk)
            .length_prefixed_bytes(self.originator_sig)
            .sorted_map(self.meta)
            .finalize()
        )

    def to_dict(self) -> dict:
        return {
            "capture_id": self.capture_id,
            "originator_id": self.originator_id,
            "captured_at": self.captured_at,
            "content_hash": b64e(self.content_hash),
            "sealed_hash": b64e(self.sealed_hash),
            "originator_vk": b64e(self.originator_vk),
            "originator_sig": b64e(self.originator_sig),
            "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CaptureManifest":
        return cls(
            capture_id=d["capture_id"],
            originator_id=d["originator_id"],
            captured_at=d["captured_at"],
            content_hash=b64d(d["content_hash"]),
            sealed_hash=b64d(d["sealed_hash"]),
            originator_vk=b64d(d.get("originator_vk", "")),
            originator_sig=b64d(d.get("originator_sig", "")),
            meta=d.get("meta", {}),
        )


@dataclass(frozen=True)
class SealedCapture:
    """A confidential artifact plus its public manifest — one transportable unit."""

    manifest: CaptureManifest
    sealed: bytes         # SealedBox output: only the recipient's dk can open it

    @property
    def size(self) -> int:
        return len(self.sealed)


def seal_capture(
    artifact: bytes,
    recipient_ek: bytes,
    *,
    originator_id: str,
    originator: KeyPair | None = None,
    capture_id: str | None = None,
    captured_at: float | None = None,
    meta: dict | None = None,
) -> SealedCapture:
    """
    Seal an artifact to a recipient and build its (optionally device-signed)
    manifest — WITHOUT touching any log. This is the client-side half shared by
    the local notary (ProvenanceLog.record_capture) and the hosted notary client
    (which seals locally, then submits only the manifest).
    """
    sealed = SealedBox.seal(artifact, recipient_ek)
    sealed_hash = H_bytes(sealed)
    manifest = CaptureManifest(
        capture_id=capture_id if capture_id is not None else sealed_hash.hex()[:32],
        originator_id=originator_id,
        captured_at=captured_at if captured_at is not None else time.time(),
        content_hash=H_bytes(artifact),
        sealed_hash=sealed_hash,
        originator_vk=originator.vk if originator is not None else b"",
        meta=meta or {},
    )
    if originator is not None:
        manifest = replace(
            manifest,
            originator_sig=MLDSA.sign(originator.sk, manifest.originator_signed_payload()),
        )
    return SealedCapture(manifest=manifest, sealed=sealed)


class ProvenanceLog:
    """
    Operator-run notary: seals captures and commits their manifests to an
    RFC-6962 append-only Merkle log.

    One ProvenanceLog is run by one operator identity (the notary). The operator
    signs Tree Heads (STHs); auditors verify captures against those STHs. The
    operator never sees plaintext beyond what it is asked to seal, and never
    holds recipients' decapsulation keys.

    `operator` is either a KeyPair (reference custody) or any Signer exposing
    `.vk` + `.sign(payload)` — e.g. a KMS-held key (cloud/keys.py) — so the
    signing key need not exist in this process at all.
    """

    def __init__(self, operator) -> None:
        self._operator = operator
        if hasattr(operator, "sk"):  # KeyPair: in-process signing key
            self._log = MerkleLog(operator.vk, operator.sk)
        else:  # external Signer (KMS/HSM)
            self._log = MerkleLog(operator.vk, signer=operator)

    # ------------------------------------------------------------------
    # Persistence support (rebuild a notary log from stored manifests)
    # ------------------------------------------------------------------

    def append_manifest(self, manifest: CaptureManifest) -> int:
        """
        Re-append a previously recorded manifest during log reconstruction.

        Used when loading a persisted notary: replaying the stored manifests in
        order rebuilds the exact same Merkle tree (append is deterministic),
        without needing the original plaintext or re-sealing anything.
        """
        return self._log.append(manifest.canonical_bytes())

    def restore_sequence(self, next_sequence: int) -> None:
        """
        Restore the STH sequence counter after reload so newly published STHs
        continue monotonically from where the persisted log left off.
        """
        self._log._sequence = next_sequence

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_capture(
        self,
        artifact: bytes,
        recipient_ek: bytes,
        *,
        originator_id: str,
        originator: KeyPair | None = None,
        capture_id: str | None = None,
        captured_at: float | None = None,
        meta: dict | None = None,
    ) -> tuple[SealedCapture, int]:
        """
        Seal `artifact` to `recipient_ek` and notarize a manifest of it.

        If `originator` (the capturing device's keypair) is given, the manifest
        carries the device's ML-DSA-65 signature over (originator_id,
        content_hash, captured_at) — so provenance is the device's own
        cryptographic attestation, not just an operator-recorded string. Omit it
        for operator-vouched-only captures.

        Returns the transportable SealedCapture and the log leaf index used to
        generate inclusion proofs. Call publish_sth() afterward (optionally
        batching several captures per STH) to attest the new log state.
        """
        capture = seal_capture(
            artifact, recipient_ek, originator_id=originator_id, originator=originator,
            capture_id=capture_id, captured_at=captured_at, meta=meta,
        )
        idx = self._log.append(capture.manifest.canonical_bytes())
        return capture, idx

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
        expected_operator_vk: bytes | None = None,
        expected_originator_vk: bytes | None = None,
    ) -> bool:
        """
        Independently verify a capture's provenance. Returns True iff ALL hold:

          0. If `expected_operator_vk` is given, the STH was signed by THAT
             operator — otherwise any self-consistent receipt from any key would
             pass (see the security note below).
          1. The STH signature is valid  — the operator really attested this
             log state (root_hash) at this sequence.
          2. The sealed blob matches the manifest  — sealed_hash == H(sealed),
             so this is the exact artifact that was notarized (not a swap).
          3. The manifest is in the log under the attested root  — the inclusion
             proof reconstructs sth.root_hash from the manifest bytes.
          4. If the manifest carries an originator signature, it is valid over
             (originator_id, content_hash, captured_at) — so the capturing
             DEVICE, not just the operator, attests to the content. If
             `expected_originator_vk` is given, the signer must be that device.

        Needs neither the plaintext nor any operator secret. Any tamper —
        altered artifact, swapped sealed blob, edited log record, forged STH,
        or a forged/mismatched originator signature — flips a check to False.

        SECURITY — trust anchors: a valid STH signature only proves *some*
        operator key attested this capture; a self-asserted `originator_id` with
        no originator signature is just the operator's word. To prove a
        *specific, trusted* notary and/or capturing device, pin the relevant
        public key via `expected_operator_vk` / `expected_originator_vk`. Without
        pins, this proves internal consistency, not authenticity.
        """
        if expected_operator_vk is not None and not hmac.compare_digest(
            sth.operator_vk, expected_operator_vk
        ):
            return False
        if expected_originator_vk is not None and not hmac.compare_digest(
            manifest.originator_vk, expected_originator_vk
        ):
            return False
        # A present originator signature must always verify (a tampered/invalid
        # device signature is a hard failure, pinned or not).
        if manifest.originator_vk and not MLDSA.verify(
            manifest.originator_vk,
            manifest.originator_signed_payload(),
            manifest.originator_sig,
        ):
            return False
        if not sth.verify():
            return False
        if not hmac.compare_digest(manifest.sealed_hash, H_bytes(sealed)):
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
        if manifest is not None and not hmac.compare_digest(H_bytes(plaintext), manifest.content_hash):
            raise ValueError(
                "Recovered plaintext does not match manifest content_hash — "
                "artifact and provenance record disagree"
            )
        return plaintext


@dataclass(frozen=True)
class ProvenanceReceipt:
    """
    A self-contained, portable proof of custody for one capture.

    A receipt bundles everything a third party needs to verify a capture —
    the manifest, the O(log N) inclusion proof, and the operator's signed tree
    head — into one JSON-serializable object. Given a receipt plus the sealed
    blob it refers to, ANYONE can confirm authenticity and non-tampering with
    no access to the log, the plaintext, or any secret key:

        receipt = ProvenanceReceipt.from_json(open("capture.receipt").read())
        assert receipt.verify(open("capture.sealed", "rb").read())

    This is the product's deliverable artifact: hand a customer a `.sealed` file
    and a `.receipt`, and they can prove provenance offline, forever.
    """

    manifest: CaptureManifest
    proof: InclusionProof
    sth: SignedTreeHead

    @classmethod
    def build(
        cls,
        manifest: CaptureManifest,
        proof: InclusionProof,
        sth: SignedTreeHead,
    ) -> "ProvenanceReceipt":
        return cls(manifest=manifest, proof=proof, sth=sth)

    def verify(
        self,
        sealed: bytes,
        expected_operator_vk: bytes | None = None,
        expected_originator_vk: bytes | None = None,
    ) -> bool:
        """
        Verify this receipt against the sealed blob it refers to.

        True iff the operator's STH signature is valid, the sealed blob matches
        the manifest, the manifest is included under the attested root, and any
        originator signature is valid. Pass `expected_operator_vk` /
        `expected_originator_vk` to require a specific trusted notary / device —
        without them, a self-consistent receipt from any key passes (see
        ProvenanceLog.verify_capture's security note).
        """
        return ProvenanceLog.verify_capture(
            self.manifest, sealed, self.proof, self.sth,
            expected_operator_vk, expected_originator_vk,
        )

    # -- serialization (each component owns its own to_dict/from_dict) --

    def to_dict(self) -> dict:
        return {
            "format": "etp-provenance-receipt/1",
            "manifest": self.manifest.to_dict(),
            "inclusion_proof": self.proof.to_dict(),
            "signed_tree_head": self.sth.to_dict(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, d: dict) -> "ProvenanceReceipt":
        return cls(
            manifest=CaptureManifest.from_dict(d["manifest"]),
            proof=InclusionProof.from_dict(d["inclusion_proof"]),
            sth=SignedTreeHead.from_dict(d["signed_tree_head"]),
        )

    @classmethod
    def from_json(cls, s: str) -> "ProvenanceReceipt":
        return cls.from_dict(json.loads(s))


# ---------------------------------------------------------------------------
# Delay-tolerant transport: erasure-coded shard bundles
# ---------------------------------------------------------------------------
#
# The other half of the provenance wedge. A sealed capture is a single opaque
# blob; on a lossy or disconnected link (satellite pass, tactical mesh, a data
# mule crossing a gap) a single dropped packet loses it. bundle_sealed() splits
# the sealed blob into n erasure-coded shards, ANY k of which reconstruct it —
# forward error correction, no ARQ round-trip. Spray n shards over the link (or
# across several passes / several couriers); the receiver reassembles from any k
# that arrive intact. Provenance is unaffected: reassemble → the exact same
# sealed blob → the existing receipt still verifies.


@dataclass(frozen=True)
class BundleManifest:
    """
    Self-describing header for an erasure-coded shard bundle.

    Carries the (n, k) scheme, the hash+length of the original sealed blob (to
    verify reconstruction), and a per-shard hash so a receiver can drop corrupt
    shards before decoding (one bad shard would otherwise poison RS decode).
    Contains no secrets — safe to ship alongside the shards.
    """

    n: int
    k: int
    sealed_hash: bytes
    sealed_len: int
    shard_hashes: list  # list[bytes], index-aligned, length n

    def to_dict(self) -> dict:
        return {
            "format": "etp-shard-bundle/1",
            "n": self.n,
            "k": self.k,
            "sealed_hash": b64e(self.sealed_hash),
            "sealed_len": self.sealed_len,
            "shard_hashes": [b64e(h) for h in self.shard_hashes],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, d: dict) -> "BundleManifest":
        return cls(
            n=d["n"],
            k=d["k"],
            sealed_hash=b64d(d["sealed_hash"]),
            sealed_len=d["sealed_len"],
            shard_hashes=[b64d(h) for h in d["shard_hashes"]],
        )

    @classmethod
    def from_json(cls, s: str) -> "BundleManifest":
        return cls.from_dict(json.loads(s))


def bundle_sealed(sealed: bytes, n: int, k: int) -> tuple[BundleManifest, list[bytes]]:
    """
    Erasure-code a sealed blob into n shards, any k of which reconstruct it.

    Returns (manifest, shards) where shards[i] is the i-th shard. Choose n/k for
    the link's loss rate: e.g. n=6,k=4 tolerates any 2 of 6 lost (~33% loss).
    """
    if not (n > k > 0):
        raise ValueError("need n > k > 0")
    shards = ErasureCoder.encode(sealed, n, k)
    manifest = BundleManifest(
        n=n, k=k,
        sealed_hash=H_bytes(sealed),
        sealed_len=len(sealed),
        shard_hashes=[H_bytes(s) for s in shards],
    )
    return manifest, shards


def reassemble_sealed(manifest: BundleManifest, shards: dict[int, bytes]) -> bytes:
    """
    Reconstruct the sealed blob from any k valid shards.

    Corrupt shards (hash mismatch vs the manifest) are dropped before decoding.
    Raises ValueError if fewer than k valid shards are available or if the
    reconstructed blob does not match the manifest's sealed_hash.
    """
    good = {
        idx: s for idx, s in shards.items()
        if 0 <= idx < manifest.n
        and idx < len(manifest.shard_hashes)
        and hmac.compare_digest(H_bytes(s), manifest.shard_hashes[idx])
    }
    if len(good) < manifest.k:
        raise ValueError(
            f"need {manifest.k} valid shards to reconstruct, have {len(good)} "
            f"(of {len(shards)} supplied)"
        )
    sealed = ErasureCoder.decode(good, manifest.n, manifest.k)
    if not hmac.compare_digest(H_bytes(sealed), manifest.sealed_hash):
        raise ValueError("reconstructed blob does not match bundle sealed_hash")
    return sealed

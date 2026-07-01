"""
AnchorWorker — the smart-contract integration layer.

Periodically anchors each tenant's latest signed tree head to the (already
deployed, audited) LTPAnchorRegistry contract, treating it as a trusted
external component behind the existing `AnchorClient` interface:

    client.anchor(AnchorSubmission) -> tx reference (str)
    client.is_anchored(digest: bytes) -> bool

One 32-byte root anchors an entire batch of captures, so on-chain cost is
O(1) per tenant per interval regardless of volume — the "Verified" trust
tier. Receipts stay verifiable offline without the chain; the anchor is an
additional, independently checkable timestamp upper-bound.

Transaction lifecycle (persisted in CloudStore.anchors):

    pending ──submit──▶ submitted ──reconcile──▶ confirmed
       │  (client.anchor)            (client.is_anchored / Anchored event)
       └─ after max_attempts failures ──▶ failed

`run_once()` drives all three stages and is idempotent: enqueueing dedupes on
(tenant, sth_sequence), submission retries with attempt counting, and
reconciliation only advances state. A production deployment runs it on a
schedule (or as a long-lived worker) and additionally indexes `Anchored`
events for reconciliation — see design doc §8.
"""

from __future__ import annotations

import time

from ..primitives import H_bytes
from ..encoding import b64e, b64d
from ..anchor.submission import AnchorSubmission
from .store import CloudStore

__all__ = ["AnchorWorker"]

# Domain-separated preimages for the on-chain fields.
_DIGEST_TAG = b"GSX-LTP:custody-anchor:v1\x00"
_POLICY_TAG = b"GSX-LTP:custody-sth-policy:v1\x00"

# GSX Testnet (see CLAUDE.md / contracts deployment).
GSX_CHAIN_ID = 103115120


class AnchorWorker:
    def __init__(
        self,
        store: CloudStore,
        client,
        operator_vk: bytes,
        *,
        chain_id: int = GSX_CHAIN_ID,
        validity_secs: int = 365 * 24 * 3600,
        max_attempts: int = 5,
        on_confirmed=None,
    ) -> None:
        """
        Args:
            store:        the CloudStore holding tenants/sths/anchor rows.
            client:       anything implementing anchor(AnchorSubmission)->str and
                          is_anchored(bytes)->bool (the real AnchorClient, or a
                          test double).
            operator_vk:  the notary's ML-DSA verification key (its hash goes
                          on-chain as signerVkHash).
            on_confirmed: optional callback(tenant_id, anchor_row) — used by the
                          service to fire anchor.confirmed webhooks.
        """
        self._store = store
        self._client = client
        self._operator_vk = operator_vk
        self._chain_id = chain_id
        self._validity_secs = validity_secs
        self._max_attempts = max_attempts
        self._on_confirmed = on_confirmed

    # ------------------------------------------------------------------
    # Digest / submission construction
    # ------------------------------------------------------------------

    @staticmethod
    def anchor_digest(tenant_id: str, sequence: int, root: bytes) -> bytes:
        """Deterministic, unique per (tenant, STH): the on-chain lookup key."""
        return H_bytes(
            _DIGEST_TAG + tenant_id.encode() + sequence.to_bytes(8, "big") + root
        )

    def _submission(self, tenant_id: str, sequence: int,
                    root: bytes, digest: bytes) -> AnchorSubmission:
        return AnchorSubmission(
            anchor_digest=digest,
            merkle_root=root,
            policy_hash=H_bytes(_POLICY_TAG),
            signer_vk_hash=H_bytes(self._operator_vk),
            sequence=sequence,
            valid_until=int(time.time()) + self._validity_secs,
            target_chain_id=self._chain_id,
            receipt_type="custody-sth",
        )

    # ------------------------------------------------------------------
    # Lifecycle stages
    # ------------------------------------------------------------------

    def enqueue(self) -> int:
        """Stage 1: queue each tenant's latest un-anchored STH (idempotent)."""
        queued = 0
        for tenant_id in self._store.tenant_ids():
            sth = self._store.latest_sth(tenant_id)
            if sth is None:
                continue
            digest = self.anchor_digest(tenant_id, sth.sequence, sth.root_hash)
            if self._store.create_anchor(
                tenant_id, sth.sequence, b64e(sth.root_hash), b64e(digest)
            ):
                queued += 1
        return queued

    def submit_pending(self) -> int:
        """Stage 2: submit pending anchors; count attempts, fail after max."""
        submitted = 0
        for row in self._store.anchors(status="pending"):
            sub = self._submission(
                row["tenant_id"], row["sth_sequence"],
                b64d(row["root"]), b64d(row["digest"]),
            )
            try:
                tx_ref = self._client.anchor(sub)
            except Exception as e:  # RPC/rate-limit/breaker errors — retry later
                attempts = row["attempts"] + 1
                status = "failed" if attempts >= self._max_attempts else "pending"
                self._store.mark_anchor(row["id"], status,
                                        error=f"{type(e).__name__}: {e}",
                                        bump_attempts=True)
                continue
            self._store.mark_anchor(row["id"], "submitted", tx_ref=tx_ref)
            submitted += 1
        return submitted

    def reconcile(self) -> int:
        """Stage 3: confirm submitted anchors against on-chain state."""
        confirmed = 0
        for row in self._store.anchors(status="submitted"):
            if self._client.is_anchored(b64d(row["digest"])):
                self._store.mark_anchor(row["id"], "confirmed")
                confirmed += 1
                if self._on_confirmed is not None:
                    self._on_confirmed(row["tenant_id"], {**row, "status": "confirmed"})
        return confirmed

    def run_once(self) -> dict:
        """One full pass; safe to call repeatedly (all stages idempotent)."""
        queued = self.enqueue()
        submitted = self.submit_pending()
        confirmed = self.reconcile()
        return {"queued": queued, "submitted": submitted, "confirmed": confirmed}

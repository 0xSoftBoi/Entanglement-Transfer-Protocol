"""
EventIndexer — confirm anchors from on-chain `Anchored` events.

The push-based half of anchor confirmation (AnchorWorker.reconcile()'s
`is_anchored` polling remains as the safety net). The indexer tails the
registry's `Anchored(bytes32 indexed anchorDigest, …)` logs through a narrow
source interface, so the core stays free of web3 dependencies:

    class LogSource(Protocol):
        def latest_block(self) -> int: ...
        def get_logs(self, from_block: int, to_block: int) -> list[AnchoredEvent]: ...

A production source wraps the same web3 contract handle AnchorClient already
holds (`contract.events.Anchored.get_logs(...)`); tests use an in-memory fake.

Reorg safety: the indexer only reads up to `latest_block - confirmation_depth`,
so a log it acts on is final by policy — it never has to un-confirm. The cursor
(per chain, persisted) advances only over fully-scanned ranges, so a crash
mid-scan just re-reads an idempotent window.
"""

from __future__ import annotations

from dataclasses import dataclass

from .store import CloudStore

__all__ = ["AnchoredEvent", "EventIndexer"]


@dataclass(frozen=True)
class AnchoredEvent:
    """One `Anchored` log, reduced to what confirmation needs."""
    digest: bytes         # anchorDigest (bytes32)
    block_number: int
    tx_ref: str


class EventIndexer:
    def __init__(self, store: CloudStore, source, *, chain_id: int,
                 confirmation_depth: int = 6, on_confirmed=None) -> None:
        self._store = store
        self._source = source
        self._chain_id = chain_id
        self._depth = confirmation_depth
        self._on_confirmed = on_confirmed

    def run_once(self) -> dict:
        """Scan new finalized-depth blocks; confirm matching anchor rows."""
        from ..encoding import b64e
        safe_to = self._source.latest_block() - self._depth
        cursor = self._store.get_cursor(self._chain_id)
        if safe_to <= cursor:
            return {"scanned": 0, "confirmed": 0}

        confirmed = 0
        for ev in self._source.get_logs(cursor + 1, safe_to):
            row = self._store.anchor_by_digest(b64e(ev.digest))
            # Confirm rows we submitted — and 'pending' rows too, which covers a
            # worker that crashed after sending the tx but before recording it.
            if row and row["status"] in ("pending", "submitted"):
                self._store.mark_anchor(row["id"], "confirmed",
                                        tx_ref=ev.tx_ref,
                                        block_number=ev.block_number)
                confirmed += 1
                if self._on_confirmed is not None:
                    self._on_confirmed(row["tenant_id"], {**row,
                                                          "status": "confirmed",
                                                          "tx_ref": row["tx_ref"] or ev.tx_ref})
        self._store.set_cursor(self._chain_id, safe_to)
        return {"scanned": safe_to - cursor, "confirmed": confirmed}

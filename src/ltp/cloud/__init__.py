"""
ETP Custody Cloud — the production service layer.

Turns the reference notary (ltp.notary_server) into a deployable product:

  store.py      — durable, multi-tenant persistence (SQLite reference; the
                  same schema maps 1:1 onto Postgres in production)
  service.py    — multi-tenant HTTP notary: API-key auth, per-tenant
                  append-only logs, metering, webhooks
  anchoring.py  — the smart-contract integration layer: batches signed tree
                  heads and anchors them to LTPAnchorRegistry with a full
                  transaction lifecycle (pending → submitted → confirmed /
                  failed) and idempotent reconciliation
  indexer.py    — event indexing: confirms anchors from on-chain `Anchored`
                  logs with confirmation-depth reorg safety
  webhooks.py   — persistent outbox delivery with retries + HMAC signatures

Design doc: docs/cloud/CUSTODY_CLOUD_DESIGN.md
API spec:   docs/cloud/openapi.yaml
"""

from .store import CloudStore, PostgresStore, open_store
from .service import CloudNotaryService, make_cloud_server
from .anchoring import AnchorWorker
from .indexer import EventIndexer, AnchoredEvent
from .webhooks import WebhookDispatcher, sign_payload
from .witness import Witness, Cosignature
from .metrics import render_metrics
from .billing import usage_deltas, run_billing_export
from .report import build_report, render_markdown

__all__ = [
    "CloudStore", "PostgresStore", "open_store",
    "CloudNotaryService", "make_cloud_server",
    "AnchorWorker", "EventIndexer", "AnchoredEvent",
    "WebhookDispatcher", "sign_payload",
    "Witness", "Cosignature", "render_metrics",
    "usage_deltas", "run_billing_export",
    "build_report", "render_markdown",
]

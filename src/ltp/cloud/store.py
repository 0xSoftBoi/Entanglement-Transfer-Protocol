"""
CloudStore — durable, multi-tenant persistence for the custody service.

SQLite reference implementation (stdlib-only, WAL mode). The schema is written
so it maps 1:1 onto Postgres for production — see the DDL in
docs/cloud/CUSTODY_CLOUD_DESIGN.md §4.

What it stores (and, deliberately, what it doesn't):
  - tenants + hashed API keys (raw keys are shown once and never persisted)
  - per-tenant capture manifests and signed tree heads (public data only —
    the service is zero-knowledge of content by construction)
  - anchor rows tracking the on-chain transaction lifecycle
  - the service operator keypair (reference deployments only; production
    holds this in a KMS/HSM — see design doc §11)

Thread safety: a single connection guarded by a lock; all writes are
transactional. Fine for the reference service; production uses Postgres with
ordinary connection pooling.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from ..keypair import KeyPair
from ..primitives import H_bytes
from ..encoding import b64e, b64d
from ..provenance import CaptureManifest
from ..merkle_log import SignedTreeHead

__all__ = ["CloudStore"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    webhook_url TEXT,
    created_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash    TEXT PRIMARY KEY,          -- SHA3-256(raw key); raw never stored
    tenant_id   TEXT NOT NULL REFERENCES tenants(id),
    label       TEXT NOT NULL DEFAULT '',
    revoked     INTEGER NOT NULL DEFAULT 0,
    created_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS captures (
    tenant_id   TEXT NOT NULL,
    leaf_index  INTEGER NOT NULL,
    manifest    TEXT NOT NULL,             -- CaptureManifest.to_dict() JSON
    created_at  REAL NOT NULL,
    PRIMARY KEY (tenant_id, leaf_index)
);
CREATE TABLE IF NOT EXISTS sths (
    tenant_id   TEXT NOT NULL,
    sequence    INTEGER NOT NULL,
    sth         TEXT NOT NULL,             -- SignedTreeHead.to_dict() JSON
    created_at  REAL NOT NULL,
    PRIMARY KEY (tenant_id, sequence)
);
CREATE TABLE IF NOT EXISTS anchors (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id    TEXT NOT NULL,
    sth_sequence INTEGER NOT NULL,
    root         TEXT NOT NULL,            -- b64 Merkle root
    digest       TEXT NOT NULL,            -- b64 unique anchor digest
    status       TEXT NOT NULL,            -- pending | submitted | confirmed | failed
    tx_ref       TEXT,
    attempts     INTEGER NOT NULL DEFAULT 0,
    error        TEXT,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL,
    UNIQUE (tenant_id, sth_sequence)
);
CREATE TABLE IF NOT EXISTS service_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class CloudStore:
    def __init__(self, path: str | Path) -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Operator identity (reference deployments; production = KMS/HSM)
    # ------------------------------------------------------------------

    def get_or_create_operator(self, label: str = "cloud-notary") -> KeyPair:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM service_config WHERE key='operator'").fetchone()
            if row:
                d = json.loads(row[0])
                return KeyPair(ek=b64d(d["ek"]), dk=b64d(d["dk"]),
                               vk=b64d(d["vk"]), sk=b64d(d["sk"]), label=d["label"])
            kp = KeyPair.generate(label)
            self._conn.execute(
                "INSERT INTO service_config (key, value) VALUES ('operator', ?)",
                (json.dumps({"ek": b64e(kp.ek), "dk": b64e(kp.dk),
                             "vk": b64e(kp.vk), "sk": b64e(kp.sk), "label": label}),))
            self._conn.commit()
            return kp

    # ------------------------------------------------------------------
    # Tenants + API keys
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_key(raw: str) -> str:
        return H_bytes(raw.encode("utf-8")).hex()

    def create_tenant(self, name: str, webhook_url: str | None = None) -> str:
        tenant_id = "t_" + secrets.token_hex(8)
        with self._lock:
            self._conn.execute(
                "INSERT INTO tenants (id, name, webhook_url, created_at) VALUES (?,?,?,?)",
                (tenant_id, name, webhook_url, time.time()))
            self._conn.commit()
        return tenant_id

    def issue_key(self, tenant_id: str, label: str = "") -> str:
        """Create an API key; the raw key is returned ONCE and never stored."""
        raw = "etpk_" + secrets.token_urlsafe(32)
        with self._lock:
            self._conn.execute(
                "INSERT INTO api_keys (key_hash, tenant_id, label, created_at) VALUES (?,?,?,?)",
                (self._hash_key(raw), tenant_id, label, time.time()))
            self._conn.commit()
        return raw

    def revoke_key(self, raw: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE api_keys SET revoked=1 WHERE key_hash=?", (self._hash_key(raw),))
            self._conn.commit()
            return cur.rowcount > 0

    def tenant_for_key(self, raw: str | None) -> str | None:
        if not raw:
            return None
        row = self._conn.execute(
            "SELECT tenant_id FROM api_keys WHERE key_hash=? AND revoked=0",
            (self._hash_key(raw),)).fetchone()
        return row[0] if row else None

    def tenant(self, tenant_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT id, name, webhook_url FROM tenants WHERE id=?", (tenant_id,)).fetchone()
        return {"id": row[0], "name": row[1], "webhook_url": row[2]} if row else None

    def tenant_ids(self) -> list[str]:
        return [r[0] for r in self._conn.execute("SELECT id FROM tenants ORDER BY created_at")]

    # ------------------------------------------------------------------
    # Log persistence (per-tenant manifests + STHs)
    # ------------------------------------------------------------------

    def append_capture(self, tenant_id: str, leaf_index: int, manifest: CaptureManifest) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO captures (tenant_id, leaf_index, manifest, created_at) VALUES (?,?,?,?)",
                (tenant_id, leaf_index, json.dumps(manifest.to_dict()), time.time()))
            self._conn.commit()

    def append_sth(self, tenant_id: str, sth: SignedTreeHead) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO sths (tenant_id, sequence, sth, created_at) VALUES (?,?,?,?)",
                (tenant_id, sth.sequence, json.dumps(sth.to_dict()), time.time()))
            self._conn.commit()

    def manifests(self, tenant_id: str) -> list[CaptureManifest]:
        rows = self._conn.execute(
            "SELECT manifest FROM captures WHERE tenant_id=? ORDER BY leaf_index",
            (tenant_id,)).fetchall()
        return [CaptureManifest.from_dict(json.loads(r[0])) for r in rows]

    def sth_count(self, tenant_id: str) -> int:
        return self._conn.execute(
            "SELECT COUNT(*) FROM sths WHERE tenant_id=?", (tenant_id,)).fetchone()[0]

    def latest_sth(self, tenant_id: str) -> SignedTreeHead | None:
        row = self._conn.execute(
            "SELECT sth FROM sths WHERE tenant_id=? ORDER BY sequence DESC LIMIT 1",
            (tenant_id,)).fetchone()
        return SignedTreeHead.from_dict(json.loads(row[0])) if row else None

    def usage(self, tenant_id: str) -> int:
        """The billable unit: notarized captures for this tenant."""
        return self._conn.execute(
            "SELECT COUNT(*) FROM captures WHERE tenant_id=?", (tenant_id,)).fetchone()[0]

    def total_captures(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM captures").fetchone()[0]

    # ------------------------------------------------------------------
    # Anchor lifecycle
    # ------------------------------------------------------------------

    def create_anchor(self, tenant_id: str, sth_sequence: int,
                      root_b64: str, digest_b64: str) -> int | None:
        """Insert a pending anchor row; returns None if one already exists
        for this (tenant, sequence) — enqueueing is idempotent."""
        now = time.time()
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO anchors "
                "(tenant_id, sth_sequence, root, digest, status, created_at, updated_at) "
                "VALUES (?,?,?,?,'pending',?,?)",
                (tenant_id, sth_sequence, root_b64, digest_b64, now, now))
            self._conn.commit()
            return cur.lastrowid if cur.rowcount else None

    def anchors(self, tenant_id: str | None = None, status: str | None = None) -> list[dict]:
        q = ("SELECT id, tenant_id, sth_sequence, root, digest, status, tx_ref, "
             "attempts, error, updated_at FROM anchors")
        conds, params = [], []
        if tenant_id is not None:
            conds.append("tenant_id=?"); params.append(tenant_id)
        if status is not None:
            conds.append("status=?"); params.append(status)
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY id"
        cols = ["id", "tenant_id", "sth_sequence", "root", "digest",
                "status", "tx_ref", "attempts", "error", "updated_at"]
        return [dict(zip(cols, r)) for r in self._conn.execute(q, params)]

    def mark_anchor(self, anchor_id: int, status: str, *,
                    tx_ref: str | None = None, error: str | None = None,
                    bump_attempts: bool = False) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE anchors SET status=?, tx_ref=COALESCE(?, tx_ref), error=?, "
                "attempts=attempts + ?, updated_at=? WHERE id=?",
                (status, tx_ref, error, 1 if bump_attempts else 0, time.time(), anchor_id))
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()

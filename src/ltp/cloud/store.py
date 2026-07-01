"""
CloudStore — durable, multi-tenant persistence for the custody service.

Two backends behind one interface:

  CloudStore(path)      — SQLite (stdlib, WAL). The reference deployment and
                          the dev/test default.
  PostgresStore(dsn)    — Postgres via psycopg (optional `[cloud]` extra). The
                          production deployment; identical schema and behavior,
                          exercised in CI against a real Postgres service.

  open_store(url)       — picks the backend from a URL/path (postgres:// DSNs
                          route to PostgresStore).

What it stores (and, deliberately, what it doesn't):
  - tenants + hashed API keys (raw keys are shown once and never persisted)
  - per-tenant capture manifests and signed tree heads (public data only —
    the service is zero-knowledge of content by construction)
  - anchor rows tracking the on-chain transaction lifecycle
  - webhook outbox rows and per-chain indexer cursors
  - the service operator keypair (reference deployments only; production
    holds this in a KMS/HSM — see design doc §11)

Concurrency: every operation (reads included) is serialized behind one lock on
one connection — correct and sufficient at reference scale for both backends.
A pooled-connection variant is a production optimization, not a correctness
requirement (all writes are single-statement transactions).
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

__all__ = ["CloudStore", "PostgresStore", "open_store"]

# Schema template; {AUTOID} and {REAL} are filled per dialect.
_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS tenants (
        id             TEXT PRIMARY KEY,
        name           TEXT NOT NULL,
        webhook_url    TEXT,
        webhook_secret TEXT,
        plan           TEXT NOT NULL DEFAULT 'free',
        created_at     {REAL} NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS api_keys (
        key_hash    TEXT PRIMARY KEY,
        tenant_id   TEXT NOT NULL REFERENCES tenants(id),
        label       TEXT NOT NULL DEFAULT '',
        revoked     INTEGER NOT NULL DEFAULT 0,
        created_at  {REAL} NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS captures (
        tenant_id   TEXT NOT NULL,
        leaf_index  INTEGER NOT NULL,
        capture_id  TEXT NOT NULL,
        manifest    TEXT NOT NULL,
        created_at  {REAL} NOT NULL,
        PRIMARY KEY (tenant_id, leaf_index)
    )""",
    """CREATE INDEX IF NOT EXISTS idx_captures_capture_id
        ON captures (tenant_id, capture_id)""",
    """CREATE TABLE IF NOT EXISTS sths (
        tenant_id   TEXT NOT NULL,
        sequence    INTEGER NOT NULL,
        sth         TEXT NOT NULL,
        created_at  {REAL} NOT NULL,
        PRIMARY KEY (tenant_id, sequence)
    )""",
    """CREATE TABLE IF NOT EXISTS anchors (
        id           {AUTOID},
        tenant_id    TEXT NOT NULL,
        sth_sequence INTEGER NOT NULL,
        root         TEXT NOT NULL,
        digest       TEXT NOT NULL,
        status       TEXT NOT NULL,
        tx_ref       TEXT,
        attempts     INTEGER NOT NULL DEFAULT 0,
        error        TEXT,
        block_number INTEGER,
        created_at   {REAL} NOT NULL,
        updated_at   {REAL} NOT NULL,
        UNIQUE (tenant_id, sth_sequence)
    )""",
    """CREATE TABLE IF NOT EXISTS webhook_outbox (
        id              {AUTOID},
        tenant_id       TEXT NOT NULL,
        event           TEXT NOT NULL,
        attempts        INTEGER NOT NULL DEFAULT 0,
        delivered_at    {REAL},
        next_attempt_at {REAL} NOT NULL,
        created_at      {REAL} NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS indexer_cursor (
        chain_id   INTEGER PRIMARY KEY,
        last_block INTEGER NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS billing_snapshots (
        tenant_id  TEXT NOT NULL,
        captures   INTEGER NOT NULL,
        created_at {REAL} NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS service_config (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )""",
]


class CloudStore:
    """SQLite-backed reference store (see module docstring)."""

    _AUTOID = "INTEGER PRIMARY KEY AUTOINCREMENT"
    _REALTYPE = "REAL"

    def __init__(self, path: str | Path) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_schema()
        self._migrate()

    # -- dialect hooks (overridden by PostgresStore) --------------------

    @staticmethod
    def _tr(sql: str) -> str:
        """Translate parameter placeholders for this dialect."""
        return sql  # sqlite uses '?' natively

    def _create_schema(self) -> None:
        for stmt in _SCHEMA:
            self._conn.execute(stmt.format(AUTOID=self._AUTOID, REAL=self._REALTYPE))
        self._conn.commit()

    def _migrate(self) -> None:
        """Columns added after the first release (pre-existing SQLite DBs)."""
        for stmt in [
            "ALTER TABLE tenants  ADD COLUMN webhook_secret TEXT",
            "ALTER TABLE tenants  ADD COLUMN plan TEXT NOT NULL DEFAULT 'free'",
            "ALTER TABLE captures ADD COLUMN capture_id TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE anchors  ADD COLUMN block_number INTEGER",
        ]:
            try:
                self._conn.execute(stmt)
            except sqlite3.OperationalError:
                pass  # already present
        # Backfill capture_id for rows written before the column existed.
        rows = self._conn.execute(
            "SELECT tenant_id, leaf_index, manifest FROM captures WHERE capture_id=''"
        ).fetchall()
        for tid, idx, manifest in rows:
            self._conn.execute(
                "UPDATE captures SET capture_id=? WHERE tenant_id=? AND leaf_index=?",
                (json.loads(manifest)["capture_id"], tid, idx))
        self._conn.commit()

    def _insert_returning_id(self, sql: str, params: tuple, *,
                             ignore_conflict: bool = False) -> int | None:
        """INSERT and return the new row id (None on ignored conflict)."""
        if ignore_conflict:
            sql = sql.replace("INSERT", "INSERT OR IGNORE", 1)
        cur = self._conn.execute(self._tr(sql), params)
        self._conn.commit()
        return cur.lastrowid if cur.rowcount else None

    # -- locked execution core ------------------------------------------

    def _query(self, sql: str, params: tuple = ()) -> list[tuple]:
        with self._lock:
            return self._conn.execute(self._tr(sql), params).fetchall()

    def _exec(self, sql: str, params: tuple = ()) -> int:
        """Execute a write; returns affected rowcount."""
        with self._lock:
            cur = self._conn.execute(self._tr(sql), params)
            self._conn.commit()
            return cur.rowcount

    # ------------------------------------------------------------------
    # Operator identity (reference deployments; production = KMS/HSM)
    # ------------------------------------------------------------------

    def get_or_create_operator(self, label: str = "cloud-notary") -> KeyPair:
        rows = self._query("SELECT value FROM service_config WHERE key='operator'")
        if rows:
            d = json.loads(rows[0][0])
            return KeyPair(ek=b64d(d["ek"]), dk=b64d(d["dk"]),
                           vk=b64d(d["vk"]), sk=b64d(d["sk"]), label=d["label"])
        kp = KeyPair.generate(label)
        self._exec(
            "INSERT INTO service_config (key, value) VALUES ('operator', ?)",
            (json.dumps({"ek": b64e(kp.ek), "dk": b64e(kp.dk),
                         "vk": b64e(kp.vk), "sk": b64e(kp.sk), "label": label}),))
        return kp

    # ------------------------------------------------------------------
    # Tenants + API keys
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_key(raw: str) -> str:
        return H_bytes(raw.encode("utf-8")).hex()

    def create_tenant(self, name: str, webhook_url: str | None = None) -> str:
        tenant_id = "t_" + secrets.token_hex(8)
        self._exec(
            "INSERT INTO tenants (id, name, webhook_url, webhook_secret, created_at) "
            "VALUES (?,?,?,?,?)",
            (tenant_id, name, webhook_url, secrets.token_urlsafe(32), time.time()))
        return tenant_id

    def issue_key(self, tenant_id: str, label: str = "") -> str:
        """Create an API key; the raw key is returned ONCE and never stored."""
        raw = "etpk_" + secrets.token_urlsafe(32)
        self._exec(
            "INSERT INTO api_keys (key_hash, tenant_id, label, created_at) VALUES (?,?,?,?)",
            (self._hash_key(raw), tenant_id, label, time.time()))
        return raw

    def revoke_key(self, raw: str) -> bool:
        return self._exec(
            "UPDATE api_keys SET revoked=1 WHERE key_hash=?", (self._hash_key(raw),)) > 0

    def tenant_for_key(self, raw: str | None) -> str | None:
        if not raw:
            return None
        rows = self._query(
            "SELECT tenant_id FROM api_keys WHERE key_hash=? AND revoked=0",
            (self._hash_key(raw),))
        return rows[0][0] if rows else None

    def tenant(self, tenant_id: str) -> dict | None:
        rows = self._query(
            "SELECT id, name, webhook_url, webhook_secret, plan FROM tenants WHERE id=?",
            (tenant_id,))
        if not rows:
            return None
        r = rows[0]
        return {"id": r[0], "name": r[1], "webhook_url": r[2],
                "webhook_secret": r[3], "plan": r[4]}

    def set_plan(self, tenant_id: str, plan: str) -> bool:
        return self._exec("UPDATE tenants SET plan=? WHERE id=?", (plan, tenant_id)) > 0

    def tenant_ids(self) -> list[str]:
        return [r[0] for r in self._query("SELECT id FROM tenants ORDER BY created_at")]

    def tenant_plans(self) -> dict[str, str]:
        return dict(self._query("SELECT id, plan FROM tenants"))

    # ------------------------------------------------------------------
    # Log persistence (per-tenant manifests + STHs)
    # ------------------------------------------------------------------

    def append_capture(self, tenant_id: str, leaf_index: int, manifest: CaptureManifest) -> None:
        self._exec(
            "INSERT INTO captures (tenant_id, leaf_index, capture_id, manifest, created_at) "
            "VALUES (?,?,?,?,?)",
            (tenant_id, leaf_index, manifest.capture_id,
             json.dumps(manifest.to_dict()), time.time()))

    def leaf_for_capture_id(self, tenant_id: str, capture_id: str) -> int | None:
        """Idempotency lookup: the leaf index already holding this capture_id."""
        rows = self._query(
            "SELECT leaf_index FROM captures WHERE tenant_id=? AND capture_id=? "
            "ORDER BY leaf_index LIMIT 1", (tenant_id, capture_id))
        return rows[0][0] if rows else None

    def append_sth(self, tenant_id: str, sth: SignedTreeHead) -> None:
        self._exec(
            "INSERT INTO sths (tenant_id, sequence, sth, created_at) VALUES (?,?,?,?)",
            (tenant_id, sth.sequence, json.dumps(sth.to_dict()), time.time()))

    def manifests(self, tenant_id: str) -> list[CaptureManifest]:
        rows = self._query(
            "SELECT manifest FROM captures WHERE tenant_id=? ORDER BY leaf_index",
            (tenant_id,))
        return [CaptureManifest.from_dict(json.loads(r[0])) for r in rows]

    def sth_count(self, tenant_id: str) -> int:
        return self._query(
            "SELECT COUNT(*) FROM sths WHERE tenant_id=?", (tenant_id,))[0][0]

    def latest_sth(self, tenant_id: str) -> SignedTreeHead | None:
        rows = self._query(
            "SELECT sth FROM sths WHERE tenant_id=? ORDER BY sequence DESC LIMIT 1",
            (tenant_id,))
        return SignedTreeHead.from_dict(json.loads(rows[0][0])) if rows else None

    def sth_history(self, tenant_id: str) -> list[SignedTreeHead]:
        rows = self._query(
            "SELECT sth FROM sths WHERE tenant_id=? ORDER BY sequence", (tenant_id,))
        return [SignedTreeHead.from_dict(json.loads(r[0])) for r in rows]

    def usage(self, tenant_id: str) -> int:
        """The billable unit: notarized captures for this tenant."""
        return self._query(
            "SELECT COUNT(*) FROM captures WHERE tenant_id=?", (tenant_id,))[0][0]

    def usage_by_tenant(self) -> dict[str, int]:
        return dict(self._query(
            "SELECT tenant_id, COUNT(*) FROM captures GROUP BY tenant_id"))

    def total_captures(self) -> int:
        return self._query("SELECT COUNT(*) FROM captures")[0][0]

    # -- metrics/billing helpers ----------------------------------------

    def anchor_status_counts(self) -> dict[str, int]:
        return dict(self._query(
            "SELECT status, COUNT(*) FROM anchors GROUP BY status"))

    def outbox_pending(self) -> int:
        return self._query(
            "SELECT COUNT(*) FROM webhook_outbox WHERE delivered_at IS NULL")[0][0]

    def last_billing_snapshot(self, tenant_id: str) -> int:
        rows = self._query(
            "SELECT captures FROM billing_snapshots WHERE tenant_id=? "
            "ORDER BY created_at DESC LIMIT 1", (tenant_id,))
        return rows[0][0] if rows else 0

    def record_billing_snapshot(self, tenant_id: str, captures: int) -> None:
        self._exec(
            "INSERT INTO billing_snapshots (tenant_id, captures, created_at) VALUES (?,?,?)",
            (tenant_id, captures, time.time()))

    # ------------------------------------------------------------------
    # Anchor lifecycle
    # ------------------------------------------------------------------

    _ANCHOR_COLS = ["id", "tenant_id", "sth_sequence", "root", "digest",
                    "status", "tx_ref", "attempts", "error", "block_number",
                    "updated_at"]

    def create_anchor(self, tenant_id: str, sth_sequence: int,
                      root_b64: str, digest_b64: str) -> int | None:
        """Insert a pending anchor row; returns None if one already exists
        for this (tenant, sequence) — enqueueing is idempotent."""
        now = time.time()
        with self._lock:
            return self._insert_returning_id(
                "INSERT INTO anchors "
                "(tenant_id, sth_sequence, root, digest, status, created_at, updated_at) "
                "VALUES (?,?,?,?,'pending',?,?)",
                (tenant_id, sth_sequence, root_b64, digest_b64, now, now),
                ignore_conflict=True)

    def anchors(self, tenant_id: str | None = None, status: str | None = None) -> list[dict]:
        q = f"SELECT {', '.join(self._ANCHOR_COLS)} FROM anchors"
        conds, params = [], []
        if tenant_id is not None:
            conds.append("tenant_id=?"); params.append(tenant_id)
        if status is not None:
            conds.append("status=?"); params.append(status)
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY id"
        return [dict(zip(self._ANCHOR_COLS, r)) for r in self._query(q, tuple(params))]

    def anchor_by_digest(self, digest_b64: str) -> dict | None:
        rows = self._query(
            f"SELECT {', '.join(self._ANCHOR_COLS)} FROM anchors WHERE digest=?",
            (digest_b64,))
        return dict(zip(self._ANCHOR_COLS, rows[0])) if rows else None

    def mark_anchor(self, anchor_id: int, status: str, *,
                    tx_ref: str | None = None, error: str | None = None,
                    block_number: int | None = None,
                    bump_attempts: bool = False) -> None:
        self._exec(
            "UPDATE anchors SET status=?, tx_ref=COALESCE(?, tx_ref), error=?, "
            "block_number=COALESCE(?, block_number), attempts=attempts + ?, "
            "updated_at=? WHERE id=?",
            (status, tx_ref, error, block_number,
             1 if bump_attempts else 0, time.time(), anchor_id))

    # ------------------------------------------------------------------
    # Webhook outbox
    # ------------------------------------------------------------------

    def enqueue_event(self, tenant_id: str, event: dict) -> int:
        now = time.time()
        with self._lock:
            return self._insert_returning_id(
                "INSERT INTO webhook_outbox (tenant_id, event, next_attempt_at, created_at) "
                "VALUES (?,?,?,?)", (tenant_id, json.dumps(event), now, now))

    def due_events(self, *, max_attempts: int, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        rows = self._query(
            "SELECT id, tenant_id, event, attempts FROM webhook_outbox "
            "WHERE delivered_at IS NULL AND attempts < ? AND next_attempt_at <= ? "
            "ORDER BY id", (max_attempts, now))
        return [{"id": r[0], "tenant_id": r[1], "event": json.loads(r[2]), "attempts": r[3]}
                for r in rows]

    def mark_event_delivered(self, event_id: int) -> None:
        self._exec("UPDATE webhook_outbox SET delivered_at=? WHERE id=?",
                   (time.time(), event_id))

    def mark_event_failed(self, event_id: int, retry_in: float) -> None:
        self._exec(
            "UPDATE webhook_outbox SET attempts=attempts+1, next_attempt_at=? WHERE id=?",
            (time.time() + retry_in, event_id))

    # ------------------------------------------------------------------
    # Indexer cursor
    # ------------------------------------------------------------------

    def get_cursor(self, chain_id: int) -> int:
        rows = self._query(
            "SELECT last_block FROM indexer_cursor WHERE chain_id=?", (chain_id,))
        return rows[0][0] if rows else 0

    def set_cursor(self, chain_id: int, last_block: int) -> None:
        self._exec(
            "INSERT INTO indexer_cursor (chain_id, last_block) VALUES (?,?) "
            "ON CONFLICT (chain_id) DO UPDATE SET last_block=excluded.last_block",
            (chain_id, last_block))

    def close(self) -> None:
        self._conn.close()


class PostgresStore(CloudStore):
    """Postgres-backed store (production). Requires the `[cloud]` extra."""

    _AUTOID = "BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY"
    _REALTYPE = "DOUBLE PRECISION"

    def __init__(self, dsn: str) -> None:
        import psycopg  # optional dependency, imported on use
        self._lock = threading.Lock()
        self._conn = psycopg.connect(dsn)
        self._create_schema()
        # Fresh backend: the full schema above already includes every column,
        # so there are no legacy migrations to apply.

    @staticmethod
    def _tr(sql: str) -> str:
        return sql.replace("?", "%s")   # psycopg paramstyle (no literal '?' in our SQL)

    def _create_schema(self) -> None:
        with self._conn.cursor() as cur:
            for stmt in _SCHEMA:
                cur.execute(stmt.format(AUTOID=self._AUTOID, REAL=self._REALTYPE))
        self._conn.commit()

    def _query(self, sql: str, params: tuple = ()) -> list[tuple]:
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(self._tr(sql), params)
                return cur.fetchall()

    def _exec(self, sql: str, params: tuple = ()) -> int:
        with self._lock:
            with self._conn.cursor() as cur:
                cur.execute(self._tr(sql), params)
                self._conn.commit()
                return cur.rowcount

    def _insert_returning_id(self, sql: str, params: tuple, *,
                             ignore_conflict: bool = False) -> int | None:
        if ignore_conflict:
            sql += " ON CONFLICT DO NOTHING"
        sql += " RETURNING id"
        with self._conn.cursor() as cur:
            cur.execute(self._tr(sql), params)
            row = cur.fetchone()
            self._conn.commit()
            return row[0] if row else None


def open_store(url: str | Path) -> CloudStore:
    """Route a config value to the right backend: postgres DSN or SQLite path."""
    s = str(url)
    if s.startswith(("postgres://", "postgresql://")):
        return PostgresStore(s)
    return CloudStore(s)

"""
CloudNotaryService — the multi-tenant hosted notary (production service layer).

Extends the reference single-log notary (ltp.notary_server) with everything a
deployable SaaS needs, while keeping its trust model intact:

  - Multi-tenant: each tenant gets an isolated append-only log (its own Merkle
    tree, its own STH sequence), rebuilt from durable storage on boot.
  - Durable: manifests + STHs are written through to CloudStore; the service
    survives restarts and receipts issued before a restart keep verifying.
  - Zero-knowledge: clients seal locally and submit only public manifests —
    plaintext and sealed blobs never reach the service (unchanged).
  - Metered: usage(tenant) counts notarized captures, the billable unit.
  - Webhooks: capture.notarized and anchor.confirmed events POSTed to the
    tenant's registered URL (best-effort; sync mode available for tests).

HTTP surface (reference; full production spec in docs/cloud/openapi.yaml):

  GET  /healthz                       — liveness + totals
  GET  /v1/operator                   — operator vk to pin (public)
  POST /v1/admin/tenants              — create tenant + first API key (admin)
  POST /v1/captures                   — notarize a manifest → receipt (API key)
  GET  /v1/usage                      — billable capture count (API key)
  GET  /v1/sth                        — tenant's latest signed tree head (API key)
  GET  /v1/proof/<index>              — tenant-scoped inclusion proof (API key)
  GET  /v1/anchors                    — on-chain anchor statuses (API key)

Run it:  python -m ltp.cloud.service   (env: ETP_CLOUD_DB, ETP_CLOUD_ADMIN_TOKEN,
                                        ETP_CLOUD_HOST, ETP_CLOUD_PORT)
"""

from __future__ import annotations

import hmac
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..keypair import KeyPair
from ..encoding import b64e
from ..provenance import ProvenanceLog, ProvenanceReceipt, CaptureManifest
from ..anchor.client import TokenBucketRateLimiter
from .store import CloudStore
from .webhooks import WebhookDispatcher

__all__ = ["CloudNotaryService", "make_cloud_server", "main"]


class CloudNotaryService:
    def __init__(
        self,
        store: CloudStore,
        *,
        admin_token: str,
        operator: KeyPair | None = None,  # KeyPair or any Signer (cloud/keys.py)
        sync_webhooks: bool = False,
        rate_per_minute: float | None = 300.0,
        witness: KeyPair | None = None,
    ) -> None:
        from .keys import signer_from_env
        self._store = store
        # Custody resolution: explicit operator wins; otherwise the env decides
        # (ETP_CLOUD_KMS_KEY_ID → KMS-held key, else the store-persisted pair).
        self._operator = operator or signer_from_env(store)
        self._admin_token = admin_token
        self._sync_webhooks = sync_webhooks
        self._dispatcher = WebhookDispatcher(store)
        self._witness = None
        if witness is not None:
            from .witness import Witness
            self._witness = Witness(witness)
        self._rate_per_minute = rate_per_minute
        self._limiters: dict[str, TokenBucketRateLimiter] = {}
        self._logs: dict[str, ProvenanceLog] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Tenant logs (lazily rebuilt from durable storage)
    # ------------------------------------------------------------------

    def _log(self, tenant_id: str) -> ProvenanceLog:
        log = self._logs.get(tenant_id)
        if log is None:
            log = ProvenanceLog(self._operator)
            for manifest in self._store.manifests(tenant_id):
                log.append_manifest(manifest)
            log.restore_sequence(self._store.sth_count(tenant_id))
            self._logs[tenant_id] = log
        return log

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    @property
    def operator_vk(self) -> bytes:
        return self._operator.vk

    def create_tenant(self, name: str, webhook_url: str | None = None) -> dict:
        tenant_id = self._store.create_tenant(name, webhook_url)
        api_key = self._store.issue_key(tenant_id, label="initial")
        return {"tenant_id": tenant_id, "api_key": api_key}

    def authorize(self, api_key: str | None) -> str | None:
        return self._store.tenant_for_key(api_key)

    def admin_authorized(self, token: str | None) -> bool:
        return bool(token) and hmac.compare_digest(token, self._admin_token)

    def rate_ok(self, api_key: str) -> bool:
        """Per-key token bucket (burst = 1 minute's allowance)."""
        if self._rate_per_minute is None:
            return True
        limiter = self._limiters.get(api_key)
        if limiter is None:
            limiter = self._limiters.setdefault(api_key, TokenBucketRateLimiter(
                max_tps=self._rate_per_minute / 60.0,
                burst=max(1, int(self._rate_per_minute))))
        return limiter.acquire(timeout=0)

    def submit(self, tenant_id: str, manifest: CaptureManifest) -> tuple[ProvenanceReceipt, bool]:
        """
        Notarize a manifest. Idempotent on capture_id: resubmitting an
        already-notarized capture returns a fresh receipt for the existing
        leaf (proof + STH against the current tree) without re-appending or
        re-metering. Returns (receipt, created).
        """
        with self._lock:
            log = self._log(tenant_id)
            existing = self._store.leaf_for_capture_id(tenant_id, manifest.capture_id)
            if existing is not None:
                # Persisted STH matches the current tree (every append publishes
                # one), and survives restarts where the in-memory list doesn't.
                sth = self._store.latest_sth(tenant_id)
                return ProvenanceReceipt.build(
                    manifest, log.inclusion_proof(existing), sth), False
            idx = log.append_manifest(manifest)
            sth = log.publish_sth()
            proof = log.inclusion_proof(idx)
            self._store.append_capture(tenant_id, idx, manifest)
            self._store.append_sth(tenant_id, sth)
        receipt = ProvenanceReceipt.build(manifest, proof, sth)
        self.notify(tenant_id, {
            "event": "capture.notarized",
            "tenant_id": tenant_id,
            "capture_id": manifest.capture_id,
            "leaf_index": idx,
            "sth_sequence": sth.sequence,
        })
        return receipt, True

    def inclusion_proof(self, tenant_id: str, index: int):
        with self._lock:
            return self._log(tenant_id).inclusion_proof(index)

    def latest_sth(self, tenant_id: str):
        return self._store.latest_sth(tenant_id)

    def sth_response(self, tenant_id: str) -> dict | None:
        """The /v1/sth payload: STH dict + witness cosignature when configured."""
        sth = self._store.latest_sth(tenant_id)
        if sth is None:
            return None
        out = sth.to_dict()
        if self._witness is not None:
            out["cosignature"] = self._witness.cosign(sth).to_dict()
        return out

    def captures(self, tenant_id: str, limit: int = 50) -> list[dict]:
        """Recent captures (public manifest metadata) for the console."""
        manifests = self._store.manifests(tenant_id)
        out = [{
            "leaf_index": i,
            "capture_id": m.capture_id,
            "originator_id": m.originator_id,
            "captured_at": m.captured_at,
            "device_signed": bool(m.originator_vk),
        } for i, m in enumerate(manifests)]
        return out[-limit:][::-1]   # newest first

    def set_plan(self, tenant_id: str, plan: str) -> bool:
        if plan not in ("free", "pro", "verified"):
            raise ValueError(f"unknown plan: {plan!r}")
        return self._store.set_plan(tenant_id, plan)

    def usage(self, tenant_id: str) -> int:
        return self._store.usage(tenant_id)

    def anchors(self, tenant_id: str) -> list[dict]:
        rows = self._store.anchors(tenant_id=tenant_id)
        return [{k: r[k] for k in
                 ("sth_sequence", "root", "digest", "status", "tx_ref",
                  "block_number", "updated_at")}
                for r in rows]

    @staticmethod
    def verify_receipt_signatures(receipt: ProvenanceReceipt) -> dict:
        """
        Server-assisted verification for the browser verifier: the ML-DSA
        checks that can't reasonably run in hand-written JS. Receipts are
        public data, so this endpoint needs no auth — and the caller is told
        the operator vk so it can compare against its own pinned copy.
        """
        from ..primitives import MLDSA
        m = receipt.manifest
        sth_ok = receipt.sth.verify()
        proof_ok = receipt.proof.verify(m.canonical_bytes(), receipt.sth.root_hash)
        device_ok = None
        if m.originator_vk:
            device_ok = MLDSA.verify(
                m.originator_vk, m.originator_signed_payload(), m.originator_sig)
        return {
            "sth_signature_valid": sth_ok,
            "inclusion_proof_valid": proof_ok,
            "originator_signature_valid": device_ok,   # null when not device-signed
            "operator_vk": b64e(receipt.sth.operator_vk),
        }

    def on_anchor_confirmed(self, tenant_id: str, anchor_row: dict) -> None:
        """Wire this as AnchorWorker(on_confirmed=service.on_anchor_confirmed)."""
        self.notify(tenant_id, {
            "event": "anchor.confirmed",
            "tenant_id": tenant_id,
            "sth_sequence": anchor_row["sth_sequence"],
            "root": anchor_row["root"],
            "digest": anchor_row["digest"],
            "tx_ref": anchor_row.get("tx_ref"),
        })

    # ------------------------------------------------------------------
    # Webhooks — persistent outbox (crash-safe, retried, HMAC-signed).
    # Events are enqueued transactionally at emit time; a WebhookDispatcher
    # drains them (inline in sync mode, on a scheduler in production).
    # ------------------------------------------------------------------

    def notify(self, tenant_id: str, payload: dict) -> None:
        tenant = self._store.tenant(tenant_id)
        if not (tenant and tenant.get("webhook_url")):
            return
        self._store.enqueue_event(tenant_id, payload)
        if self._sync_webhooks:
            self._dispatcher.run_once()
        else:
            threading.Thread(target=self._dispatcher.run_once, daemon=True).start()


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    server_version = "etp-custody-cloud/1"

    @property
    def svc(self) -> CloudNotaryService:
        return self.server.cloud_service  # type: ignore[attr-defined]

    def log_message(self, *args):
        pass

    def _send(self, code: int, payload: dict | list) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # The console/verifier are static pages on any origin; receipts and
        # manifests are public data and auth is bearer-per-request, so a
        # permissive CORS policy is safe and required.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # CORS preflight (Authorization header)
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers",
                         "Authorization, Content-Type, X-Admin-Token")
        self.end_headers()

    def _api_key(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        return auth[7:].strip() if auth.startswith("Bearer ") else None

    def _tenant(self) -> str | None:
        return self.svc.authorize(self._api_key())

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            return self._send(200, {"status": "ok",
                                    "captures": self.svc._store.total_captures()})
        if path == "/metrics":
            from .metrics import render_metrics
            body = render_metrics(self.svc._store).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/v1/operator":
            return self._send(200, {"operator_vk": b64e(self.svc.operator_vk)})

        tenant = self._tenant()
        if tenant is None:
            return self._send(401, {"error": "invalid or missing API key"})
        if path == "/v1/usage":
            return self._send(200, {"captures": self.svc.usage(tenant)})
        if path == "/v1/sth":
            payload = self.svc.sth_response(tenant)
            if payload is None:
                return self._send(404, {"error": "no captures yet"})
            return self._send(200, payload)
        if path == "/v1/captures":
            return self._send(200, self.svc.captures(tenant))
        if path == "/v1/anchors":
            return self._send(200, self.svc.anchors(tenant))
        if path.startswith("/v1/proof/"):
            try:
                idx = int(path.rsplit("/", 1)[1])
                return self._send(200, self.svc.inclusion_proof(tenant, idx).to_dict())
            except (ValueError, IndexError):
                return self._send(404, {"error": "no such leaf"})
        return self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/v1/verify":
            # Public: signature checks for the browser verifier (receipts are
            # public; plaintext/sealed blobs are never sent here).
            try:
                receipt = ProvenanceReceipt.from_dict(self._body())
            except (ValueError, KeyError, TypeError) as e:
                return self._send(400, {"error": f"malformed receipt ({type(e).__name__})"})
            return self._send(200, self.svc.verify_receipt_signatures(receipt))
        if path == "/v1/admin/tenants":
            if not self.svc.admin_authorized(self.headers.get("X-Admin-Token")):
                return self._send(401, {"error": "invalid admin token"})
            try:
                body = self._body()
                created = self.svc.create_tenant(body["name"], body.get("webhook_url"))
            except (ValueError, KeyError, TypeError) as e:
                return self._send(400, {"error": f"malformed request ({type(e).__name__})"})
            return self._send(201, created)

        if path.startswith("/v1/admin/tenants/") and path.endswith("/plan"):
            if not self.svc.admin_authorized(self.headers.get("X-Admin-Token")):
                return self._send(401, {"error": "invalid admin token"})
            tenant_id = path.split("/")[4]
            try:
                ok = self.svc.set_plan(tenant_id, self._body().get("plan", ""))
            except (ValueError, KeyError, TypeError) as e:
                return self._send(400, {"error": str(e)})
            if not ok:
                return self._send(404, {"error": "unknown tenant"})
            return self._send(200, {"tenant_id": tenant_id, "plan_updated": True})

        if path == "/v1/captures":
            key = self._api_key()
            tenant = self.svc.authorize(key)
            if tenant is None:
                return self._send(401, {"error": "invalid or missing API key"})
            if not self.svc.rate_ok(key):
                self.send_response(429)
                self.send_header("Retry-After", "1")
                body = json.dumps({"error": "rate limit exceeded"}).encode()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            try:
                manifest = CaptureManifest.from_dict(self._body())
            except (ValueError, KeyError, TypeError) as e:
                return self._send(400, {"error": f"malformed manifest ({type(e).__name__})"})
            receipt, created = self.svc.submit(tenant, manifest)
            # 201 on first notarization; 200 on an idempotent replay.
            return self._send(201 if created else 200, receipt.to_dict())

        return self._send(404, {"error": "not found"})


def make_cloud_server(service: CloudNotaryService,
                      host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.cloud_service = service  # type: ignore[attr-defined]
    return httpd


def main() -> int:
    from .store import open_store
    db = os.environ.get("ETP_CLOUD_DB", "custody-cloud.db")
    admin_token = os.environ.get("ETP_CLOUD_ADMIN_TOKEN")
    if not admin_token:
        raise SystemExit("error: set ETP_CLOUD_ADMIN_TOKEN")
    host = os.environ.get("ETP_CLOUD_HOST", "127.0.0.1")
    port = int(os.environ.get("ETP_CLOUD_PORT", "8080"))
    service = CloudNotaryService(open_store(db), admin_token=admin_token)
    httpd = make_cloud_server(service, host, port)
    print(f"etp-custody-cloud listening on http://{host}:{port}  "
          f"(operator {b64e(service.operator_vk)[:16]}…, db {db})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

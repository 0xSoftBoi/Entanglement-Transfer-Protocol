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
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..keypair import KeyPair
from ..encoding import b64e
from ..provenance import ProvenanceLog, ProvenanceReceipt, CaptureManifest
from .store import CloudStore

__all__ = ["CloudNotaryService", "make_cloud_server", "main"]


class CloudNotaryService:
    def __init__(
        self,
        store: CloudStore,
        *,
        admin_token: str,
        operator: KeyPair | None = None,
        sync_webhooks: bool = False,
    ) -> None:
        self._store = store
        self._operator = operator or store.get_or_create_operator()
        self._admin_token = admin_token
        self._sync_webhooks = sync_webhooks
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

    def submit(self, tenant_id: str, manifest: CaptureManifest) -> ProvenanceReceipt:
        """Append to the tenant's log, publish an STH, persist both, notify."""
        with self._lock:
            log = self._log(tenant_id)
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
        return receipt

    def inclusion_proof(self, tenant_id: str, index: int):
        with self._lock:
            return self._log(tenant_id).inclusion_proof(index)

    def latest_sth(self, tenant_id: str):
        return self._store.latest_sth(tenant_id)

    def usage(self, tenant_id: str) -> int:
        return self._store.usage(tenant_id)

    def anchors(self, tenant_id: str) -> list[dict]:
        rows = self._store.anchors(tenant_id=tenant_id)
        return [{k: r[k] for k in
                 ("sth_sequence", "root", "digest", "status", "tx_ref", "updated_at")}
                for r in rows]

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
    # Webhooks (best-effort; production uses a persistent outbox + retries)
    # ------------------------------------------------------------------

    def notify(self, tenant_id: str, payload: dict) -> None:
        tenant = self._store.tenant(tenant_id)
        url = tenant and tenant.get("webhook_url")
        if not url:
            return
        if self._sync_webhooks:
            self._deliver(url, payload)
        else:
            threading.Thread(target=self._deliver, args=(url, payload), daemon=True).start()

    @staticmethod
    def _deliver(url: str, payload: dict) -> None:
        try:
            req = urllib.request.Request(
                url, data=json.dumps(payload).encode("utf-8"), method="POST")
            req.add_header("Content-Type", "application/json")
            urllib.request.urlopen(req, timeout=3).read()
        except Exception:
            pass  # best-effort delivery; the outbox pattern replaces this in prod


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
        self.end_headers()
        self.wfile.write(body)

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
        if path == "/v1/operator":
            return self._send(200, {"operator_vk": b64e(self.svc.operator_vk)})

        tenant = self._tenant()
        if tenant is None:
            return self._send(401, {"error": "invalid or missing API key"})
        if path == "/v1/usage":
            return self._send(200, {"captures": self.svc.usage(tenant)})
        if path == "/v1/sth":
            sth = self.svc.latest_sth(tenant)
            if sth is None:
                return self._send(404, {"error": "no captures yet"})
            return self._send(200, sth.to_dict())
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
        if path == "/v1/admin/tenants":
            if not self.svc.admin_authorized(self.headers.get("X-Admin-Token")):
                return self._send(401, {"error": "invalid admin token"})
            try:
                body = self._body()
                created = self.svc.create_tenant(body["name"], body.get("webhook_url"))
            except (ValueError, KeyError, TypeError) as e:
                return self._send(400, {"error": f"malformed request ({type(e).__name__})"})
            return self._send(201, created)

        if path == "/v1/captures":
            tenant = self._tenant()
            if tenant is None:
                return self._send(401, {"error": "invalid or missing API key"})
            try:
                manifest = CaptureManifest.from_dict(self._body())
            except (ValueError, KeyError, TypeError) as e:
                return self._send(400, {"error": f"malformed manifest ({type(e).__name__})"})
            receipt = self.svc.submit(tenant, manifest)
            return self._send(201, receipt.to_dict())

        return self._send(404, {"error": "not found"})


def make_cloud_server(service: CloudNotaryService,
                      host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.cloud_service = service  # type: ignore[attr-defined]
    return httpd


def main() -> int:
    db = os.environ.get("ETP_CLOUD_DB", "custody-cloud.db")
    admin_token = os.environ.get("ETP_CLOUD_ADMIN_TOKEN")
    if not admin_token:
        raise SystemExit("error: set ETP_CLOUD_ADMIN_TOKEN")
    host = os.environ.get("ETP_CLOUD_HOST", "127.0.0.1")
    port = int(os.environ.get("ETP_CLOUD_PORT", "8080"))
    service = CloudNotaryService(CloudStore(db), admin_token=admin_token)
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

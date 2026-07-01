"""
Notary-as-a-Service — the hosted transparency-log backend for etp-custody.

The SaaS core. Clients seal artifacts LOCALLY and submit only the public
*manifest* (hashes, timestamp, signatures — never the plaintext or the sealed
blob). The service appends the manifest to an append-only RFC-6962 Merkle log,
signs a tree head, and returns a verifiable receipt. It meters submissions per
API key — the billable unit is a *notarized capture*.

Trust model (this is the product):
  - The notary is ZERO-KNOWLEDGE of content: it only ever sees manifests, so
    "we never see your data" is structural, not a promise.
  - It attests ordering + inclusion + time ("this manifest is in my log as of
    this signed tree head"), exactly like Certificate Transparency. It does not
    (and cannot) vouch for the semantic truth of a client's hashes — the
    originator signature does that, verifiable by anyone later.
  - Clients pin the operator's public key (GET /v1/operator) and verify receipts
    offline; the service being online is not part of the trust base.

Endpoints (JSON over HTTP):
  GET  /healthz                     — liveness + total captures
  GET  /v1/operator                 — {operator_vk}          (public; pin this)
  GET  /v1/sth                      — latest signed tree head (public)
  GET  /v1/proof/<index>            — inclusion proof         (public)
  POST /v1/captures                 — submit a manifest → receipt   (API key)
  GET  /v1/usage                    — {captures} for this key       (API key)

This is a reference single-log service (stdlib only). The enterprise upsell —
multi-tenant log isolation, HSM-held operator keys, witness cosigning, durable
storage, rate limits, billing export — layers on top of this same core.
"""

from __future__ import annotations

import json
import threading
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .keypair import KeyPair
from .encoding import b64e
from .provenance import (
    ProvenanceLog, ProvenanceReceipt, CaptureManifest, SealedCapture, seal_capture,
)

__all__ = ["NotaryService", "make_server", "serve", "NotaryClient"]


class NotaryService:
    """
    A single append-only notary log with API-key access + per-key metering.

    Thread-safe: all log mutations and usage updates are serialized, so it is
    safe to serve from a ThreadingHTTPServer.
    """

    def __init__(self, operator: KeyPair, api_keys: dict[str, str] | None = None) -> None:
        self._operator = operator
        self._plog = ProvenanceLog(operator)
        # api_key -> tenant label (any non-empty key is authorized)
        self._api_keys = dict(api_keys or {})
        self._usage: dict[str, int] = {}
        self._lock = threading.Lock()

    # -- auth / metering --

    def authorized(self, api_key: str | None) -> bool:
        return bool(api_key) and api_key in self._api_keys

    def usage(self, api_key: str) -> int:
        return self._usage.get(api_key, 0)

    # -- public reads --

    def operator_vk(self) -> bytes:
        return self._operator.vk

    @property
    def total_captures(self) -> int:
        return self._plog.size

    def latest_sth(self):
        return self._plog.latest_sth

    def inclusion_proof(self, index: int):
        return self._plog.inclusion_proof(index)

    # -- the metered write path --

    def submit(self, api_key: str, manifest: CaptureManifest) -> ProvenanceReceipt:
        """Append a manifest, publish an STH, meter the key, return a receipt."""
        with self._lock:
            idx = self._plog.append_manifest(manifest)
            sth = self._plog.publish_sth()
            proof = self._plog.inclusion_proof(idx)
            self._usage[api_key] = self._usage.get(api_key, 0) + 1
        return ProvenanceReceipt.build(manifest, proof, sth)


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    server_version = "etp-notary/1"

    @property
    def service(self) -> NotaryService:
        return self.server.notary_service  # type: ignore[attr-defined]

    def log_message(self, *args):  # silence default stderr logging
        pass

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _api_key(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        return auth[7:].strip() if auth.startswith("Bearer ") else None

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            return self._send(200, {"status": "ok", "captures": self.service.total_captures})
        if path == "/v1/operator":
            return self._send(200, {"operator_vk": b64e(self.service.operator_vk())})
        if path == "/v1/sth":
            sth = self.service.latest_sth()
            if sth is None:
                return self._send(404, {"error": "no captures yet"})
            return self._send(200, sth.to_dict())
        if path == "/v1/usage":
            key = self._api_key()
            if not self.service.authorized(key):
                return self._send(401, {"error": "invalid or missing API key"})
            return self._send(200, {"captures": self.service.usage(key)})
        if path.startswith("/v1/proof/"):
            try:
                idx = int(path.rsplit("/", 1)[1])
                return self._send(200, self.service.inclusion_proof(idx).to_dict())
            except (ValueError, IndexError):
                return self._send(404, {"error": "no such leaf"})
        return self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        if path != "/v1/captures":
            return self._send(404, {"error": "not found"})
        key = self._api_key()
        if not self.service.authorized(key):
            return self._send(401, {"error": "invalid or missing API key"})
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            manifest = CaptureManifest.from_dict(body)
        except (ValueError, KeyError, TypeError) as e:
            return self._send(400, {"error": f"malformed manifest ({type(e).__name__})"})
        receipt = self.service.submit(key, manifest)
        return self._send(201, receipt.to_dict())


def make_server(service: NotaryService, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.notary_service = service  # type: ignore[attr-defined]
    return httpd


def serve(service: NotaryService, host: str = "127.0.0.1", port: int = 8080) -> None:
    httpd = make_server(service, host, port)
    print(f"etp-notary listening on http://{host}:{port}  "
          f"(operator {b64e(service.operator_vk())[:16]}…)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


# ---------------------------------------------------------------------------
# Client SDK
# ---------------------------------------------------------------------------

class NotaryClient:
    """
    Minimal client for a hosted notary. Seals locally, submits only manifests.
    """

    def __init__(self, base_url: str, api_key: str | None = None) -> None:
        self.base = base_url.rstrip("/")
        self.api_key = api_key

    def _get(self, path: str) -> dict:
        req = urllib.request.Request(self.base + path)
        if self.api_key:
            req.add_header("Authorization", f"Bearer {self.api_key}")
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())

    def _post(self, path: str, payload: dict) -> dict:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.base + path, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.api_key:
            req.add_header("Authorization", f"Bearer {self.api_key}")
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())

    def operator_vk(self) -> bytes:
        from .encoding import b64d
        return b64d(self._get("/v1/operator")["operator_vk"])

    def usage(self) -> int:
        return self._get("/v1/usage")["captures"]

    def submit_manifest(self, manifest: CaptureManifest) -> ProvenanceReceipt:
        return ProvenanceReceipt.from_dict(self._post("/v1/captures", manifest.to_dict()))

    def notarize(
        self,
        artifact: bytes,
        recipient_ek: bytes,
        *,
        originator_id: str,
        originator: KeyPair | None = None,
        meta: dict | None = None,
    ) -> tuple[SealedCapture, ProvenanceReceipt]:
        """
        Seal `artifact` locally, submit only its manifest to the hosted notary,
        and return (sealed capture, receipt). The service never sees plaintext
        or the sealed blob.
        """
        capture = seal_capture(
            artifact, recipient_ek, originator_id=originator_id,
            originator=originator, meta=meta,
        )
        receipt = self.submit_manifest(capture.manifest)
        return capture, receipt

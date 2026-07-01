"""
FastAPI application — the production HTTP layer for Custody Cloud.

Same API surface as the stdlib reference server (cloud/service.py), same
CloudNotaryService underneath, same OpenAPI contract (docs/cloud/openapi.yaml)
— but on an ASGI stack (uvicorn workers, middleware, OpenAPI docs for free).
The stdlib server remains the zero-dependency reference; this is what runs
behind a load balancer.

    export ETP_CLOUD_DB=postgresql://user:pass@host/custody   # or a sqlite path
    export ETP_CLOUD_ADMIN_TOKEN=...
    uvicorn ltp.cloud.api:app                                  # or: python -m ltp.cloud.api

Requires the `[cloud]` extra (fastapi, uvicorn; psycopg for Postgres).
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Response
from fastapi.responses import JSONResponse

from ..encoding import b64e
from ..provenance import CaptureManifest, ProvenanceReceipt
from .service import CloudNotaryService
from .store import open_store

__all__ = ["create_app", "app"]


def create_app(service: CloudNotaryService) -> FastAPI:
    api = FastAPI(
        title="ETP Custody Cloud API",
        version="1.0",
        description="Multi-tenant, zero-knowledge notarization. Clients seal "
                    "locally and submit only public manifests; receipts verify "
                    "offline. See docs/cloud/openapi.yaml.",
    )
    # Static console/verifier pages run on any origin; data is public manifests
    # and auth is bearer-per-request, so permissive CORS is safe and required.
    from fastapi.middleware.cors import CORSMiddleware
    api.add_middleware(CORSMiddleware, allow_origins=["*"],
                       allow_methods=["*"], allow_headers=["*"])

    # -- auth dependencies ------------------------------------------------

    def tenant_auth(authorization: str = Header(default="")) -> str:
        key = authorization[7:].strip() if authorization.startswith("Bearer ") else None
        tenant = service.authorize(key)
        if tenant is None:
            raise HTTPException(401, "invalid or missing API key")
        # Rate limit per key, matching the reference server's semantics.
        if key and not service.rate_ok(key):
            raise HTTPException(429, "rate limit exceeded",
                                headers={"Retry-After": "1"})
        return tenant

    def admin_auth(x_admin_token: str = Header(default="")) -> None:
        if not service.admin_authorized(x_admin_token):
            raise HTTPException(401, "invalid admin token")

    # -- public -----------------------------------------------------------

    @api.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok", "captures": service._store.total_captures()}

    @api.get("/metrics")
    def metrics() -> Response:
        from .metrics import render_metrics
        return Response(render_metrics(service._store),
                        media_type="text/plain; version=0.0.4")

    @api.get("/v1/operator")
    def operator() -> dict:
        return {"operator_vk": b64e(service.operator_vk)}

    @api.post("/v1/verify")
    def verify(receipt: dict) -> dict:
        try:
            parsed = ProvenanceReceipt.from_dict(receipt)
        except (ValueError, KeyError, TypeError) as e:
            raise HTTPException(400, f"malformed receipt ({type(e).__name__})")
        return service.verify_receipt_signatures(parsed)

    # -- tenant (API key) ---------------------------------------------------

    @api.post("/v1/captures")
    def captures(manifest: dict, response: Response,
                 tenant: str = Depends(tenant_auth)) -> dict:
        try:
            parsed = CaptureManifest.from_dict(manifest)
        except (ValueError, KeyError, TypeError) as e:
            raise HTTPException(400, f"malformed manifest ({type(e).__name__})")
        receipt, created = service.submit(tenant, parsed)
        response.status_code = 201 if created else 200
        return receipt.to_dict()

    @api.get("/v1/usage")
    def usage(tenant: str = Depends(tenant_auth)) -> dict:
        return {"captures": service.usage(tenant)}

    @api.get("/v1/sth")
    def sth(tenant: str = Depends(tenant_auth)) -> dict:
        payload = service.sth_response(tenant)
        if payload is None:
            raise HTTPException(404, "no captures yet")
        return payload

    @api.get("/v1/captures")
    def list_captures(tenant: str = Depends(tenant_auth)) -> list[dict[str, Any]]:
        return service.captures(tenant)

    @api.get("/v1/proof/{index}")
    def proof(index: int, tenant: str = Depends(tenant_auth)) -> dict:
        try:
            return service.inclusion_proof(tenant, index).to_dict()
        except IndexError:
            raise HTTPException(404, "no such leaf")

    @api.get("/v1/anchors")
    def anchors(tenant: str = Depends(tenant_auth)) -> list[dict[str, Any]]:
        return service.anchors(tenant)

    # -- admin --------------------------------------------------------------

    @api.post("/v1/admin/tenants", status_code=201,
              dependencies=[Depends(admin_auth)])
    def create_tenant(body: dict) -> dict:
        if not body.get("name"):
            raise HTTPException(400, "malformed request (name required)")
        return service.create_tenant(body["name"], body.get("webhook_url"))

    @api.post("/v1/admin/tenants/{tenant_id}/plan",
              dependencies=[Depends(admin_auth)])
    def set_plan(tenant_id: str, body: dict) -> dict:
        try:
            ok = service.set_plan(tenant_id, body.get("plan", ""))
        except ValueError as e:
            raise HTTPException(400, str(e))
        if not ok:
            raise HTTPException(404, "unknown tenant")
        return {"tenant_id": tenant_id, "plan_updated": True}

    # Match the reference server's error envelope: {"error": "..."}.
    @api.exception_handler(HTTPException)
    def error_envelope(_request, exc: HTTPException):
        return JSONResponse(status_code=exc.status_code,
                            content={"error": exc.detail},
                            headers=getattr(exc, "headers", None))

    return api


def _service_from_env() -> CloudNotaryService:
    admin_token = os.environ.get("ETP_CLOUD_ADMIN_TOKEN")
    if not admin_token:
        raise SystemExit("error: set ETP_CLOUD_ADMIN_TOKEN")
    store = open_store(os.environ.get("ETP_CLOUD_DB", "custody-cloud.db"))
    return CloudNotaryService(store, admin_token=admin_token)


# uvicorn entrypoint: `uvicorn ltp.cloud.api:app` (lazy so importing the module
# for create_app() in tests doesn't require env vars).
def __getattr__(name: str):
    if name == "app":
        return create_app(_service_from_env())
    raise AttributeError(name)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(create_app(_service_from_env()),
                host=os.environ.get("ETP_CLOUD_HOST", "127.0.0.1"),
                port=int(os.environ.get("ETP_CLOUD_PORT", "8080")))

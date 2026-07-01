"""
Tests for the FastAPI production HTTP layer (src/ltp/cloud/api.py) and the
PostgresStore backend.

The FastAPI app must present the same contract as the stdlib reference server:
same routes, same status codes (401/400/404/429/201-vs-200), same error
envelope. Tested via fastapi.testclient (skipped when the [cloud] extra isn't
installed).

PostgresStore runs the same store/service behavior against a real Postgres —
skipped unless POSTGRES_DSN is set (CI provides a service container).
"""

import base64
import json
import os

import pytest

pytest.importorskip("pqcrypto")
pytest.importorskip("nacl")

from src.ltp import KeyPair
from src.ltp.provenance import seal_capture
from src.ltp.cloud import CloudStore, CloudNotaryService

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from src.ltp.cloud.api import create_app  # noqa: E402


@pytest.fixture
def client(tmp_path):
    service = CloudNotaryService(CloudStore(tmp_path / "c.db"),
                                 admin_token="admin-secret", rate_per_minute=None)
    c = TestClient(create_app(service))
    c.service = service
    return c


def _tenant(client) -> dict:
    resp = client.post("/v1/admin/tenants", json={"name": "acme"},
                       headers={"X-Admin-Token": "admin-secret"})
    assert resp.status_code == 201
    return resp.json()


def _manifest(bob) -> tuple[dict, bytes]:
    cap = seal_capture(b"payload", bob.ek, originator_id="app")
    return cap.manifest.to_dict(), cap.sealed


class TestFastAPIContract:
    def test_notarize_verify_roundtrip(self, client, bob):
        t = _tenant(client)
        manifest, sealed = _manifest(bob)
        resp = client.post("/v1/captures", json=manifest,
                           headers={"Authorization": f"Bearer {t['api_key']}"})
        assert resp.status_code == 201
        # the returned receipt verifies offline, pinned to the operator
        from src.ltp.provenance import ProvenanceReceipt
        receipt = ProvenanceReceipt.from_dict(resp.json())
        assert receipt.verify(sealed, expected_operator_vk=client.service.operator_vk)

        # replay → 200, same leaf, not re-metered
        resp2 = client.post("/v1/captures", json=manifest,
                            headers={"Authorization": f"Bearer {t['api_key']}"})
        assert resp2.status_code == 200
        assert resp2.json()["inclusion_proof"]["leaf_index"] == \
               resp.json()["inclusion_proof"]["leaf_index"]
        usage = client.get("/v1/usage",
                           headers={"Authorization": f"Bearer {t['api_key']}"})
        assert usage.json() == {"captures": 1}

    def test_auth_and_error_envelope_match_reference(self, client, bob):
        manifest, _ = _manifest(bob)
        # missing key → 401 with the reference {"error": ...} envelope
        resp = client.post("/v1/captures", json=manifest)
        assert resp.status_code == 401 and "error" in resp.json()
        # bad admin token
        resp = client.post("/v1/admin/tenants", json={"name": "x"},
                           headers={"X-Admin-Token": "wrong"})
        assert resp.status_code == 401 and "error" in resp.json()
        # malformed manifest
        t = _tenant(client)
        resp = client.post("/v1/captures", json={"nope": 1},
                           headers={"Authorization": f"Bearer {t['api_key']}"})
        assert resp.status_code == 400 and "error" in resp.json()

    def test_sth_proof_anchors_endpoints(self, client, bob):
        t = _tenant(client)
        h = {"Authorization": f"Bearer {t['api_key']}"}
        assert client.get("/v1/sth", headers=h).status_code == 404   # empty log
        manifest, _ = _manifest(bob)
        client.post("/v1/captures", json=manifest, headers=h)
        sth = client.get("/v1/sth", headers=h).json()
        assert sth["tree_size"] == 1
        assert client.get("/v1/proof/0", headers=h).status_code == 200
        assert client.get("/v1/proof/9", headers=h).status_code == 404
        assert client.get("/v1/anchors", headers=h).json() == []

    def test_rate_limit_429_with_retry_after(self, tmp_path, bob):
        service = CloudNotaryService(CloudStore(tmp_path / "c.db"),
                                     admin_token="a", rate_per_minute=2)
        client = TestClient(create_app(service))
        t = client.post("/v1/admin/tenants", json={"name": "x"},
                        headers={"X-Admin-Token": "a"}).json()
        h = {"Authorization": f"Bearer {t['api_key']}"}
        for i in range(2):
            m, _ = _manifest(bob)
            assert client.post("/v1/captures", json=m, headers=h).status_code == 201
        m, _ = _manifest(bob)
        resp = client.post("/v1/captures", json=m, headers=h)
        assert resp.status_code == 429
        assert resp.headers.get("Retry-After") == "1"

    def test_public_verify_endpoint(self, client, bob):
        t = _tenant(client)
        manifest, sealed = _manifest(bob)
        receipt = client.post("/v1/captures", json=manifest,
                              headers={"Authorization": f"Bearer {t['api_key']}"}).json()
        body = client.post("/v1/verify", json=receipt).json()
        assert body["sth_signature_valid"] is True
        assert body["inclusion_proof_valid"] is True


# ---------------------------------------------------------------------------
# PostgresStore (requires POSTGRES_DSN; CI provides a service container)
# ---------------------------------------------------------------------------

needs_pg = pytest.mark.skipif(not os.environ.get("POSTGRES_DSN"),
                              reason="POSTGRES_DSN not set")


@needs_pg
class TestPostgresStore:
    @pytest.fixture
    def pg(self):
        pytest.importorskip("psycopg")
        from src.ltp.cloud.store import PostgresStore
        import psycopg
        dsn = os.environ["POSTGRES_DSN"]
        # isolate: drop our tables between test runs
        with psycopg.connect(dsn) as conn, conn.cursor() as cur:
            for t in ("webhook_outbox", "indexer_cursor", "anchors", "sths",
                      "captures", "api_keys", "tenants", "service_config"):
                cur.execute(f"DROP TABLE IF EXISTS {t} CASCADE")
            conn.commit()
        store = PostgresStore(dsn)
        yield store
        store.close()

    def test_full_service_flow_on_postgres(self, pg, bob):
        service = CloudNotaryService(pg, admin_token="x")
        t = service.create_tenant("acme")["tenant_id"]
        cap = seal_capture(b"pg payload", bob.ek, originator_id="app")
        r1, created = service.submit(t, cap.manifest)
        assert created and r1.verify(cap.sealed, expected_operator_vk=service.operator_vk)
        r2, replay = service.submit(t, cap.manifest)         # idempotency on pg
        assert not replay and service.usage(t) == 1

    def test_anchor_lifecycle_and_outbox_on_postgres(self, pg, bob):
        from src.ltp.cloud import AnchorWorker
        from tests.test_cloud import FakeAnchorClient
        service = CloudNotaryService(pg, admin_token="x")
        t = service.create_tenant("acme")["tenant_id"]
        cap = seal_capture(b"x", bob.ek, originator_id="app")
        service.submit(t, cap.manifest)

        client = FakeAnchorClient()
        worker = AnchorWorker(pg, client, service.operator_vk)
        assert worker.run_once()["submitted"] == 1
        client.confirm_all()
        assert worker.run_once()["confirmed"] == 1
        assert pg.anchors(tenant_id=t)[0]["status"] == "confirmed"
        # outbox + cursor primitives
        eid = pg.enqueue_event(t, {"event": "x"})
        assert pg.due_events(max_attempts=5)[0]["id"] == eid
        pg.mark_event_delivered(eid)
        assert pg.due_events(max_attempts=5) == []
        pg.set_cursor(9, 123)
        pg.set_cursor(9, 456)
        assert pg.get_cursor(9) == 456

    def test_operator_identity_persists_on_postgres(self, pg):
        assert pg.get_or_create_operator().vk == pg.get_or_create_operator().vk

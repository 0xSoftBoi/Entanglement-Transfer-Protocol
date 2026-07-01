"""
Tests for ETP Custody Cloud (src/ltp/cloud/).

Covers the production service layer end to end:
  TestCloudStore     — tenants, hashed API keys, revocation, metering
  TestCloudService   — HTTP roundtrip via the client SDK, tenant isolation,
                       durability across service restarts
  TestAnchorWorker   — full on-chain transaction lifecycle against a fake
                       AnchorClient (pending → submitted → confirmed, retry →
                       failed, idempotent enqueue, digest determinism)
  TestWebhooks       — capture.notarized and anchor.confirmed delivery

Requires the real PQC backend (pqcrypto + pynacl), like the notary tests.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

pytest.importorskip("pqcrypto")
pytest.importorskip("nacl")

from src.ltp import KeyPair
from src.ltp.encoding import b64d
from src.ltp.notary_server import NotaryClient
from src.ltp.cloud import CloudStore, CloudNotaryService, make_cloud_server, AnchorWorker
from src.ltp.provenance import seal_capture


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def store(tmp_path):
    s = CloudStore(tmp_path / "cloud.db")
    yield s
    s.close()


@pytest.fixture
def service(store):
    return CloudNotaryService(store, admin_token="admin-secret", sync_webhooks=True)


@pytest.fixture
def running(service):
    httpd = make_cloud_server(service, "127.0.0.1", 0)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield {"service": service, "url": f"http://127.0.0.1:{port}"}
    finally:
        httpd.shutdown()
        httpd.server_close()


class FakeAnchorClient:
    """Test double for AnchorClient: records submissions, confirms on demand."""

    def __init__(self, fail_times: int = 0):
        self.submissions = []
        self.confirmed: set[bytes] = set()
        self._fail_times = fail_times

    def anchor(self, submission) -> str:
        if self._fail_times > 0:
            self._fail_times -= 1
            raise ConnectionError("rpc unavailable")
        self.submissions.append(submission)
        return f"0xtx{len(self.submissions):04d}"

    def confirm_all(self):
        for s in self.submissions:
            self.confirmed.add(s.anchor_digest)

    def is_anchored(self, digest: bytes) -> bool:
        return digest in self.confirmed


def _submit_one(service, tenant_id, content=b"payload", recipient=None):
    recipient = recipient or KeyPair.generate("r")
    cap = seal_capture(content, recipient.ek, originator_id="app")
    return service.submit(tenant_id, cap.manifest), cap


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class TestCloudStore:
    def test_api_keys_are_hashed_and_revocable(self, store):
        t = store.create_tenant("acme")
        raw = store.issue_key(t, label="ci")
        # only the hash is persisted
        row = store._conn.execute("SELECT key_hash FROM api_keys").fetchone()
        assert raw not in row[0] and raw.startswith("etpk_")
        assert store.tenant_for_key(raw) == t
        assert store.revoke_key(raw)
        assert store.tenant_for_key(raw) is None

    def test_unknown_or_missing_key_rejected(self, store):
        assert store.tenant_for_key("etpk_nope") is None
        assert store.tenant_for_key(None) is None

    def test_operator_identity_is_stable(self, store):
        assert store.get_or_create_operator().vk == store.get_or_create_operator().vk


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class TestCloudService:
    def test_http_roundtrip_with_client_sdk(self, running, bob):
        svc = running["service"]
        created = svc.create_tenant("acme")
        client = NotaryClient(running["url"], api_key=created["api_key"])
        cap, receipt = client.notarize(b"secret", bob.ek, originator_id="app")
        assert receipt.verify(cap.sealed, expected_operator_vk=client.operator_vk())
        assert client.usage() == 1

    def test_tenant_isolation(self, service):
        a = service.create_tenant("a")["tenant_id"]
        b = service.create_tenant("b")["tenant_id"]
        ra, _ = _submit_one(service, a)
        rb, _ = _submit_one(service, b)
        # independent logs: separate sequences and roots
        assert ra.sth.sequence == 0 and rb.sth.sequence == 0
        assert ra.sth.root_hash != rb.sth.root_hash
        assert service.usage(a) == 1 and service.usage(b) == 1

    def test_durability_across_restart(self, tmp_path, bob):
        db = tmp_path / "cloud.db"
        s1 = CloudStore(db)
        svc1 = CloudNotaryService(s1, admin_token="x")
        t = svc1.create_tenant("acme")["tenant_id"]
        r1, cap1 = _submit_one(service=svc1, tenant_id=t, recipient=bob)
        s1.close()

        # a fresh process: new store + service on the same database
        s2 = CloudStore(db)
        svc2 = CloudNotaryService(s2, admin_token="x")
        r2, _ = _submit_one(service=svc2, tenant_id=t, recipient=bob)
        # the log continued (sequence advanced, tree grew) …
        assert r2.sth.sequence == r1.sth.sequence + 1
        assert r2.sth.tree_size == r1.sth.tree_size + 1
        # … and the pre-restart receipt still verifies, pinned to the same operator
        assert r1.verify(cap1.sealed, expected_operator_vk=svc2.operator_vk)
        s2.close()

    def test_admin_endpoint_requires_token(self, running):
        import urllib.request, urllib.error
        req = urllib.request.Request(
            running["url"] + "/v1/admin/tenants",
            data=json.dumps({"name": "x"}).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req)
        assert e.value.code == 401


# ---------------------------------------------------------------------------
# Anchoring (smart-contract lifecycle)
# ---------------------------------------------------------------------------

class TestAnchorWorker:
    def _worker(self, service, client, **kw):
        return AnchorWorker(service._store, client, service.operator_vk, **kw)

    def test_full_lifecycle_pending_to_confirmed(self, service):
        t = service.create_tenant("acme")["tenant_id"]
        receipt, _ = _submit_one(service, t)
        client = FakeAnchorClient()
        worker = self._worker(service, client)

        stats = worker.run_once()                      # queue + submit
        assert stats["queued"] == 1 and stats["submitted"] == 1
        [a] = service.anchors(t)
        assert a["status"] == "submitted" and a["tx_ref"].startswith("0xtx")
        # the on-chain merkle_root is the tenant's attested STH root
        assert client.submissions[0].merkle_root == receipt.sth.root_hash

        client.confirm_all()                            # chain finalizes
        assert worker.run_once()["confirmed"] == 1      # reconcile
        assert service.anchors(t)[0]["status"] == "confirmed"

    def test_enqueue_is_idempotent(self, service):
        t = service.create_tenant("acme")["tenant_id"]
        _submit_one(service, t)
        worker = self._worker(service, FakeAnchorClient())
        assert worker.enqueue() == 1
        assert worker.enqueue() == 0                    # same STH → no duplicate row

    def test_retry_then_failed_after_max_attempts(self, service):
        t = service.create_tenant("acme")["tenant_id"]
        _submit_one(service, t)
        client = FakeAnchorClient(fail_times=99)        # RPC always down
        worker = self._worker(service, client, max_attempts=3)
        for _ in range(3):
            worker.run_once()
        [a] = service.anchors(t)
        assert a["status"] == "failed"
        assert "ConnectionError" in service._store.anchors(tenant_id=t)[0]["error"]

    def test_digest_is_deterministic_and_tenant_scoped(self):
        root = b"\x11" * 32
        d1 = AnchorWorker.anchor_digest("t_a", 0, root)
        assert d1 == AnchorWorker.anchor_digest("t_a", 0, root)
        assert d1 != AnchorWorker.anchor_digest("t_b", 0, root)
        assert d1 != AnchorWorker.anchor_digest("t_a", 1, root)


# ---------------------------------------------------------------------------
# Webhooks
# ---------------------------------------------------------------------------

class _Receiver(BaseHTTPRequestHandler):
    events: list = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        _Receiver.events.append(json.loads(self.rfile.read(length)))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def webhook_receiver():
    _Receiver.events = []
    httpd = HTTPServer(("127.0.0.1", 0), _Receiver)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield {"url": f"http://127.0.0.1:{httpd.server_address[1]}/hook",
               "events": _Receiver.events}
    finally:
        httpd.shutdown()
        httpd.server_close()


class TestWebhooks:
    def test_capture_and_anchor_events_delivered(self, service, webhook_receiver):
        t = service.create_tenant("acme", webhook_url=webhook_receiver["url"])["tenant_id"]
        _submit_one(service, t)

        client = FakeAnchorClient()
        worker = AnchorWorker(service._store, client, service.operator_vk,
                              on_confirmed=service.on_anchor_confirmed)
        worker.run_once()
        client.confirm_all()
        worker.run_once()

        kinds = [e["event"] for e in webhook_receiver["events"]]
        assert kinds == ["capture.notarized", "anchor.confirmed"]
        anchored = webhook_receiver["events"][1]
        assert anchored["tenant_id"] == t and anchored["tx_ref"].startswith("0xtx")

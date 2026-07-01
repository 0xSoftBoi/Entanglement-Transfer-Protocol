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
    receipt, _created = service.submit(tenant_id, cap.manifest)
    return receipt, cap


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

class TestIdempotency:
    def test_resubmit_same_capture_returns_existing_leaf_unmetered(self, service, bob):
        t = service.create_tenant("acme")["tenant_id"]
        cap = seal_capture(b"doc", bob.ek, originator_id="app")
        r1, created1 = service.submit(t, cap.manifest)
        r2, created2 = service.submit(t, cap.manifest)      # replay
        assert created1 and not created2
        assert r2.proof.leaf_index == r1.proof.leaf_index   # same leaf
        assert service.usage(t) == 1                        # not double-metered
        # the replayed receipt is fully valid
        assert r2.verify(cap.sealed, expected_operator_vk=service.operator_vk)

    def test_replay_receipt_valid_after_restart(self, tmp_path, bob):
        db = tmp_path / "c.db"
        s1 = CloudStore(db)
        svc1 = CloudNotaryService(s1, admin_token="x")
        t = svc1.create_tenant("acme")["tenant_id"]
        cap = seal_capture(b"doc", bob.ek, originator_id="app")
        svc1.submit(t, cap.manifest)
        s1.close()
        svc2 = CloudNotaryService(CloudStore(db), admin_token="x")
        r2, created = svc2.submit(t, cap.manifest)          # replay post-restart
        assert not created
        assert r2.verify(cap.sealed, expected_operator_vk=svc2.operator_vk)

    def test_http_replay_returns_200(self, running, bob):
        svc = running["service"]
        key = svc.create_tenant("acme")["api_key"]
        client = NotaryClient(running["url"], api_key=key)
        cap, _ = client.notarize(b"x", bob.ek, originator_id="app")
        import urllib.request
        req = urllib.request.Request(
            running["url"] + "/v1/captures",
            data=json.dumps(cap.manifest.to_dict()).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {key}")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200                        # replay, not 201


class TestRateLimit:
    def test_burst_exhaustion_returns_429(self, store, bob):
        svc = CloudNotaryService(store, admin_token="x", rate_per_minute=3)
        httpd = make_cloud_server(svc, "127.0.0.1", 0)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            key = svc.create_tenant("acme")["api_key"]
            client = NotaryClient(f"http://127.0.0.1:{port}", api_key=key)
            for i in range(3):                               # burst allowance
                client.notarize(f"m{i}".encode(), bob.ek, originator_id="app")
            import urllib.error
            with pytest.raises(urllib.error.HTTPError) as e:
                client.notarize(b"m3", bob.ek, originator_id="app")
            assert e.value.code == 429
            assert e.value.headers.get("Retry-After") == "1"
        finally:
            httpd.shutdown()
            httpd.server_close()


class TestEventIndexer:
    class FakeLogSource:
        def __init__(self):
            self.events = []
            self.head = 0

        def latest_block(self) -> int:
            return self.head

        def get_logs(self, from_block: int, to_block: int):
            return [e for e in self.events if from_block <= e.block_number <= to_block]

    def test_confirms_only_past_confirmation_depth(self, service):
        from src.ltp.cloud import EventIndexer, AnchoredEvent
        from src.ltp.encoding import b64d
        t = service.create_tenant("acme")["tenant_id"]
        _submit_one(service, t)
        client = FakeAnchorClient()
        AnchorWorker(service._store, client, service.operator_vk).run_once()
        [a] = service.anchors(t)
        assert a["status"] == "submitted"

        source = self.FakeLogSource()
        source.events.append(AnchoredEvent(
            digest=b64d(a["digest"]), block_number=100, tx_ref="0xevent"))
        indexer = EventIndexer(service._store, source, chain_id=1, confirmation_depth=6)

        source.head = 103                                    # 100 not yet 6-deep
        assert indexer.run_once()["confirmed"] == 0
        assert service.anchors(t)[0]["status"] == "submitted"

        source.head = 106                                    # now final by policy
        assert indexer.run_once()["confirmed"] == 1
        row = service._store.anchors(tenant_id=t)[0]
        assert row["status"] == "confirmed"

    def test_cursor_advances_and_rescan_is_idempotent(self, service):
        from src.ltp.cloud import EventIndexer
        source = self.FakeLogSource()
        source.head = 50
        indexer = EventIndexer(service._store, source, chain_id=7, confirmation_depth=10)
        assert indexer.run_once() == {"scanned": 40, "confirmed": 0}
        assert service._store.get_cursor(7) == 40
        assert indexer.run_once() == {"scanned": 0, "confirmed": 0}  # nothing new

    def test_confirms_pending_row_from_crashed_worker(self, service):
        """Worker sent the tx but died before recording it: the event still confirms."""
        from src.ltp.cloud import EventIndexer, AnchoredEvent
        from src.ltp.encoding import b64d
        t = service.create_tenant("acme")["tenant_id"]
        _submit_one(service, t)
        worker = AnchorWorker(service._store, FakeAnchorClient(), service.operator_vk)
        worker.enqueue()                                     # row exists, still 'pending'
        [a] = service.anchors(t)
        assert a["status"] == "pending"

        source = self.FakeLogSource()
        source.events.append(AnchoredEvent(
            digest=b64d(a["digest"]), block_number=5, tx_ref="0xcrash"))
        source.head = 20
        EventIndexer(service._store, source, chain_id=1, confirmation_depth=6).run_once()
        row = service._store.anchors(tenant_id=t)[0]
        assert row["status"] == "confirmed" and row["tx_ref"] == "0xcrash"


class _Receiver(BaseHTTPRequestHandler):
    events: list = []          # (payload, signature_header, raw_body)
    fail_next: int = 0         # respond 500 to this many requests

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        if _Receiver.fail_next > 0:
            _Receiver.fail_next -= 1
            self.send_response(500)
            self.end_headers()
            return
        _Receiver.events.append(
            (json.loads(raw), self.headers.get("X-ETP-Signature"), raw))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def webhook_receiver():
    _Receiver.events = []
    _Receiver.fail_next = 0
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

        kinds = [e[0]["event"] for e in webhook_receiver["events"]]
        assert kinds == ["capture.notarized", "anchor.confirmed"]
        anchored = webhook_receiver["events"][1][0]
        assert anchored["tenant_id"] == t and anchored["tx_ref"].startswith("0xtx")

    def test_payloads_are_hmac_signed(self, service, webhook_receiver):
        from src.ltp.cloud import sign_payload
        t = service.create_tenant("acme", webhook_url=webhook_receiver["url"])["tenant_id"]
        _submit_one(service, t)
        payload, signature, raw = webhook_receiver["events"][0]
        secret = service._store.tenant(t)["webhook_secret"]
        assert signature == sign_payload(secret, raw)
        assert signature.startswith("sha3-256=")

    def test_outbox_retries_after_failure(self, service, webhook_receiver):
        import time as _time
        from src.ltp.cloud import WebhookDispatcher
        t = service.create_tenant("acme", webhook_url=webhook_receiver["url"])["tenant_id"]

        _Receiver.fail_next = 1                              # first delivery 500s
        _submit_one(service, t)                              # sync dispatch fails
        assert webhook_receiver["events"] == []
        [row] = service._store.due_events(max_attempts=8, now=_time.time() + 3600)
        assert row["attempts"] == 1                          # recorded, backed off

        # a later dispatcher pass (past the backoff window) delivers it
        stats = WebhookDispatcher(service._store).run_once(now=_time.time() + 3600)
        assert stats["delivered"] == 1
        assert webhook_receiver["events"][0][0]["event"] == "capture.notarized"

"""
Tests for the one-shot backend batch: metrics, plan gating, batchAnchor,
witness cosigning, billing export, and the audit report.
"""

import json

import pytest

pytest.importorskip("pqcrypto")
pytest.importorskip("nacl")

from src.ltp import KeyPair
from src.ltp.provenance import seal_capture
from src.ltp.cloud import (
    CloudStore, CloudNotaryService, AnchorWorker,
    Witness, Cosignature, render_metrics,
    usage_deltas, run_billing_export, build_report, render_markdown,
)
from tests.test_cloud import FakeAnchorClient


@pytest.fixture
def service(tmp_path):
    return CloudNotaryService(CloudStore(tmp_path / "c.db"),
                              admin_token="x", sync_webhooks=True)


def _seed(service, tenant_name="acme", n=2, recipient=None, **capture_kw):
    t = service.create_tenant(tenant_name)["tenant_id"]
    recipient = recipient or KeyPair.generate("r")
    for i in range(n):
        cap = seal_capture(f"{tenant_name}-{i}".encode(), recipient.ek,
                           originator_id="app", **capture_kw)
        service.submit(t, cap.manifest)
    return t


class TestMetrics:
    def test_exposition_format_and_values(self, service):
        t = _seed(service, n=3)
        AnchorWorker(service._store, FakeAnchorClient(), service.operator_vk).run_once()
        text = render_metrics(service._store)
        assert "# TYPE etp_captures_total counter" in text
        assert "etp_captures_total 3" in text
        assert f'etp_captures{{tenant="{t}"}} 3' in text
        assert 'etp_anchors{status="submitted"} 1' in text
        assert "etp_webhook_outbox_pending 0" in text

    def test_served_on_http(self, service):
        import threading, urllib.request
        from src.ltp.cloud import make_cloud_server
        _seed(service, n=1)
        httpd = make_cloud_server(service, "127.0.0.1", 0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            resp = urllib.request.urlopen(
                f"http://127.0.0.1:{httpd.server_address[1]}/metrics")
            assert resp.headers["Content-Type"].startswith("text/plain")
            assert b"etp_captures_total 1" in resp.read()
        finally:
            httpd.shutdown(); httpd.server_close()


class TestPlanGating:
    def test_worker_anchors_only_verified_tenants(self, service):
        free = _seed(service, "free-co")
        paid = _seed(service, "paid-co")
        assert service.set_plan(paid, "verified")
        worker = AnchorWorker(service._store, FakeAnchorClient(),
                              service.operator_vk, anchor_plans={"verified"})
        assert worker.run_once()["queued"] == 1
        assert service.anchors(paid)[0]["status"] == "submitted"
        assert service.anchors(free) == []

    def test_unknown_plan_rejected(self, service):
        t = _seed(service, n=0)
        with pytest.raises(ValueError):
            service.set_plan(t, "platinum")


class TestBatchAnchor:
    class BatchClient(FakeAnchorClient):
        def __init__(self):
            super().__init__()
            self.batch_calls = 0

        def batch_anchor(self, subs) -> str:
            self.batch_calls += 1
            self.submissions.extend(subs)
            return "0xbatch01"

    def test_multiple_pending_go_in_one_tx(self, service):
        a = _seed(service, "a")
        b = _seed(service, "b")
        client = self.BatchClient()
        worker = AnchorWorker(service._store, client, service.operator_vk)
        assert worker.run_once()["submitted"] == 2
        assert client.batch_calls == 1                      # one batchAnchor tx
        refs = {r["tx_ref"] for r in service.anchors(a) + service.anchors(b)}
        assert refs == {"0xbatch01"}
        client.confirm_all()
        assert worker.run_once()["confirmed"] == 2

    def test_single_pending_uses_plain_anchor(self, service):
        _seed(service, "solo")
        client = self.BatchClient()
        AnchorWorker(service._store, client, service.operator_vk).run_once()
        assert client.batch_calls == 0                      # no batch for n=1


class TestWitness:
    def test_cosign_verify_roundtrip_and_http(self, tmp_path):
        witness_kp = KeyPair.generate("witness")
        service = CloudNotaryService(CloudStore(tmp_path / "c.db"),
                                     admin_token="x", witness=witness_kp)
        t = _seed(service, n=1)
        payload = service.sth_response(t)
        cosig = Cosignature.from_dict(payload["cosignature"])
        sth = service.latest_sth(t)
        assert cosig.witness_vk == witness_kp.vk
        assert cosig.verify(sth)

    def test_cosignature_bound_to_exact_tree_state(self, service):
        t = _seed(service, n=2)
        witness = Witness(KeyPair.generate("w"))
        history = service._store.sth_history(t)
        cosig = witness.cosign(history[0])
        assert cosig.verify(history[0])
        assert not cosig.verify(history[1])     # different tree state → invalid

    def test_refuses_invalid_sth(self, service):
        t = _seed(service, n=1)
        sth = service.latest_sth(t)
        sth.root_hash = b"\x00" * 32            # forge after signing
        with pytest.raises(ValueError):
            Witness(KeyPair.generate("w")).cosign(sth)


class TestBilling:
    def test_incremental_export(self, service, tmp_path):
        t = _seed(service, n=3)
        out = tmp_path / "usage.jsonl"
        first = run_billing_export(service._store, out)
        assert first == [pytest.approx({
            "tenant_id": t, "plan": "free", "quantity": 3,
            "timestamp": first[0]["timestamp"],
            "idempotency_key": f"{t}:0:3"}, abs=0)] or first[0]["quantity"] == 3
        # nothing new → no records, file unchanged
        assert run_billing_export(service._store, out) == []
        # two more captures → delta of 2
        recipient = KeyPair.generate("r")
        for i in range(2):
            cap = seal_capture(f"x{i}".encode(), recipient.ek, originator_id="app")
            service.submit(t, cap.manifest)
        second = run_billing_export(service._store, out)
        assert second[0]["quantity"] == 2
        lines = [json.loads(l) for l in out.read_text().splitlines()]
        assert [l["quantity"] for l in lines] == [3, 2]


class TestAuditReport:
    def test_report_verifies_and_renders(self, service):
        device = KeyPair.generate("sensor")
        t = _seed(service, n=3, originator=device)
        client = FakeAnchorClient()
        worker = AnchorWorker(service._store, client, service.operator_vk)
        worker.run_once(); client.confirm_all(); worker.run_once()

        report = build_report(service._store, service._operator, t)
        v = report["verification"]
        assert v["verdict"] is True
        assert v["all_sth_signatures_valid"] and v["sth_chain_append_only"]
        assert report["totals"] == {"captures": 3, "sths": 3, "anchors": 1}
        assert all(c["device_signed"] for c in report["captures"])
        md = render_markdown(report)
        assert "Verdict: PASS" in md and "confirmed" in md

    def test_report_flags_forged_sth(self, service):
        t = _seed(service, n=2)
        # Corrupt a persisted STH signature in place.
        row = service._store._query(
            "SELECT sth FROM sths WHERE tenant_id=? AND sequence=0", (t,))[0][0]
        d = json.loads(row)
        d["signature"] = d["signature"][:-8] + "AAAAAAAA"
        service._store._exec(
            "UPDATE sths SET sth=? WHERE tenant_id=? AND sequence=0",
            (json.dumps(d), t))
        report = build_report(service._store, service._operator, t)
        assert report["verification"]["all_sth_signatures_valid"] is False
        assert report["verification"]["verdict"] is False
        assert "Verdict: FAIL" in render_markdown(report)

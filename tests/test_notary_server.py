"""
Tests for the hosted notary (Notary-as-a-Service).

Starts the real HTTP service on an ephemeral port in a background thread and
drives it through the client SDK: seal-locally + submit-manifest, verify the
returned receipt offline against the pinned operator key, confirm metering and
API-key auth, and that the service is zero-knowledge of content.
"""

import threading

import pytest

pytest.importorskip("pqcrypto")
pytest.importorskip("nacl")

from src.ltp import KeyPair
from src.ltp.provenance import ProvenanceLog
from src.ltp.notary_server import NotaryService, make_server, NotaryClient


@pytest.fixture
def running_notary():
    operator = KeyPair.generate("notary")
    service = NotaryService(operator, {"key-alice": "alice", "key-bob": "bob"})
    httpd = make_server(service, "127.0.0.1", 0)   # port 0 → ephemeral
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield {"operator": operator, "service": service, "url": f"http://127.0.0.1:{port}"}
    finally:
        httpd.shutdown()
        httpd.server_close()


class TestNotaryService:
    def test_notarize_returns_verifiable_receipt(self, running_notary, bob):
        client = NotaryClient(running_notary["url"], api_key="key-alice")
        # operator key is fetched from the service and pinned by the client
        op_vk = client.operator_vk()
        assert op_vk == running_notary["operator"].vk

        capture, receipt = client.notarize(
            b"confidential payload", bob.ek, originator_id="sensor-7"
        )
        # the receipt verifies OFFLINE against the sealed blob, pinned to the notary
        assert receipt.verify(capture.sealed, expected_operator_vk=op_vk)

    def test_device_signed_capture_over_service(self, running_notary, bob):
        device = KeyPair.generate("sensor-7")
        client = NotaryClient(running_notary["url"], api_key="key-alice")
        capture, receipt = client.notarize(
            b"reading", bob.ek, originator_id="sensor-7", originator=device
        )
        assert receipt.verify(
            capture.sealed,
            expected_operator_vk=client.operator_vk(),
            expected_originator_vk=device.vk,
        )

    def test_metering_counts_per_api_key(self, running_notary, bob):
        alice = NotaryClient(running_notary["url"], api_key="key-alice")
        bobc = NotaryClient(running_notary["url"], api_key="key-bob")
        for _ in range(3):
            alice.notarize(b"x", bob.ek, originator_id="s")
        bobc.notarize(b"y", bob.ek, originator_id="s")
        assert alice.usage() == 3
        assert bobc.usage() == 1

    def test_service_is_zero_knowledge_of_content(self, running_notary, bob):
        """The service only ever holds manifests — never plaintext or sealed blobs."""
        client = NotaryClient(running_notary["url"], api_key="key-alice")
        capture, _ = client.notarize(b"TOP SECRET", bob.ek, originator_id="s")
        svc = running_notary["service"]
        # the log stores only canonical manifest bytes; the secret never reaches it
        stored = svc._plog._log.get_record(0)
        assert b"TOP SECRET" not in stored
        assert capture.sealed not in (stored,)

    def test_two_receipts_are_append_only_consistent(self, running_notary, bob):
        client = NotaryClient(running_notary["url"], api_key="key-alice")
        _, ra = client.notarize(b"a", bob.ek, originator_id="s")
        _, rb = client.notarize(b"b", bob.ek, originator_id="s")
        # rebuild an auditor view from the service's own log and check consistency
        plog = running_notary["service"]._plog
        older, newer = (ra.sth, rb.sth) if ra.sth.sequence < rb.sth.sequence else (rb.sth, ra.sth)
        assert plog.verify_append_only(older, newer)


class TestAuth:
    def test_missing_api_key_rejected(self, running_notary, bob):
        import urllib.error
        client = NotaryClient(running_notary["url"], api_key=None)
        with pytest.raises(urllib.error.HTTPError) as e:
            client.notarize(b"x", bob.ek, originator_id="s")
        assert e.value.code == 401

    def test_bad_api_key_rejected(self, running_notary, bob):
        import urllib.error
        client = NotaryClient(running_notary["url"], api_key="not-a-real-key")
        with pytest.raises(urllib.error.HTTPError) as e:
            client.usage()
        assert e.value.code == 401

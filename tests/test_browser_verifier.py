"""
Cross-language tests for the browser verifier (website/verify.js).

The /verify page re-implements the receipt verification path in dependency-free
JS (SHA3-256, canonical manifest encoding, RFC-6962 inclusion). These tests
prove it byte-compatible with the Python implementation by generating real
receipts here and verifying them under Node — including hash vectors, tamper
rejection, and in-toto unwrapping. Skipped when node isn't available.

Also covers the server-assisted POST /v1/verify endpoint the page delegates
ML-DSA signature checks to.
"""

import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("pqcrypto")
pytest.importorskip("nacl")

from src.ltp import KeyPair
from src.ltp.provenance import ProvenanceLog, ProvenanceReceipt, seal_capture

REPO = Path(__file__).resolve().parent.parent
VERIFY_JS = REPO / "website" / "verify.js"

node = shutil.which("node")
needs_node = pytest.mark.skipif(node is None, reason="node not installed")


def _run_node(script: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([node, "-e", script, "--", *args],
                          capture_output=True, text=True, timeout=60)


def _make_receipts(count: int = 5):
    """Real receipts with varied trees, metadata, and device signatures."""
    op = KeyPair.generate("op")
    bob = KeyPair.generate("bob")
    dev = KeyPair.generate("sensor")
    plog = ProvenanceLog(op)
    cases = []
    for i in range(count):
        cap, idx = plog.record_capture(
            f"artifact {i}".encode() * (i + 1), bob.ek, originator_id=f"s{i}",
            originator=dev if i % 2 else None,
            meta={"k": f"v{i}", "z": "9"} if i % 3 else {},
        )
        sth = plog.publish_sth()
        receipt = ProvenanceReceipt.build(cap.manifest, plog.inclusion_proof(idx), sth)
        cases.append((receipt, cap))
    return cases


@needs_node
class TestJsVerifier:
    def test_sha3_and_keccak_vectors(self):
        proc = _run_node(f"""
            const v = require({json.dumps(str(VERIFY_JS))});
            const enc = new TextEncoder();
            const big = new Uint8Array(500); for (let i=0;i<500;i++) big[i]=i&0xff;
            console.log(v.hex(v.sha3_256(new Uint8Array(0))));
            console.log(v.hex(v.sha3_256(enc.encode('abc'))));
            console.log(v.hex(v.sha3_256(big)));
            console.log(v.hex(v.keccak256(new Uint8Array(0))));
        """)
        assert proc.returncode == 0, proc.stderr
        import hashlib
        got = proc.stdout.split()
        assert got[0] == hashlib.sha3_256(b"").hexdigest()
        assert got[1] == hashlib.sha3_256(b"abc").hexdigest()
        assert got[2] == hashlib.sha3_256(bytes(i & 0xFF for i in range(500))).hexdigest()
        # Keccak-256 (Ethereum) empty-input constant
        assert got[3] == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

    def test_python_receipts_verify_in_js_and_tampering_fails(self, tmp_path):
        cases = [{"receipt": r.to_dict(),
                  "sealed_b64": base64.b64encode(c.sealed).decode()}
                 for r, c in _make_receipts(6)]
        cases_file = tmp_path / "cases.json"
        cases_file.write_text(json.dumps(cases))
        proc = _run_node(f"""
            const fs = require('fs');
            const v = require({json.dumps(str(VERIFY_JS))});
            const cases = JSON.parse(fs.readFileSync({json.dumps(str(cases_file))}));
            for (const c of cases) {{
                const good = v.verifyReceipt(c.receipt, v.b64d(c.sealed_b64));
                if (!good.structuralOk) throw new Error('valid receipt rejected');
                const bad = v.b64d(c.sealed_b64); bad[bad.length-1] ^= 1;
                if (v.verifyReceipt(c.receipt, bad).structuralOk)
                    throw new Error('tampered blob accepted');
                const wrong = JSON.parse(JSON.stringify(c.receipt));
                wrong.manifest.originator_id += 'x';
                if (v.verifyReceipt(wrong, v.b64d(c.sealed_b64)).structuralOk)
                    throw new Error('tampered manifest accepted');
            }}
            console.log('ok', cases.length);
        """)
        assert proc.returncode == 0, proc.stderr
        assert "ok 6" in proc.stdout

    def test_intoto_statement_unwraps_like_the_page(self, tmp_path):
        from src.ltp.attestation import in_toto_statement
        [(receipt, cap)] = _make_receipts(1)
        stmt = in_toto_statement("artifact.bin", receipt)
        f = tmp_path / "stmt.json"
        f.write_text(json.dumps({"stmt": stmt,
                                 "sealed_b64": base64.b64encode(cap.sealed).decode()}))
        proc = _run_node(f"""
            const fs = require('fs');
            const v = require({json.dumps(str(VERIFY_JS))});
            const d = JSON.parse(fs.readFileSync({json.dumps(str(f))}));
            const receipt = d.stmt.predicate.receipt;   // the page's unwrap rule
            const res = v.verifyReceipt(receipt, v.b64d(d.sealed_b64));
            if (!res.structuralOk) throw new Error('attestation receipt rejected');
            console.log('ok');
        """)
        assert proc.returncode == 0, proc.stderr


class TestVerifyEndpoint:
    def test_signature_checks_over_http(self, tmp_path):
        import threading, urllib.request
        from src.ltp.cloud import CloudStore, CloudNotaryService, make_cloud_server

        svc = CloudNotaryService(CloudStore(tmp_path / "c.db"), admin_token="x")
        t = svc.create_tenant("acme")["tenant_id"]
        dev = KeyPair.generate("sensor")
        cap = seal_capture(b"x", KeyPair.generate("bob").ek,
                           originator_id="s", originator=dev)
        receipt, _ = svc.submit(t, cap.manifest)

        httpd = make_cloud_server(svc, "127.0.0.1", 0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{httpd.server_address[1]}/v1/verify"
            req = urllib.request.Request(
                url, data=json.dumps(receipt.to_dict()).encode(), method="POST")
            req.add_header("Content-Type", "application/json")
            body = json.loads(urllib.request.urlopen(req).read())
            assert body["sth_signature_valid"] is True
            assert body["inclusion_proof_valid"] is True
            assert body["originator_signature_valid"] is True

            # a forged tree head must fail the signature check
            forged = receipt.to_dict()
            forged["signed_tree_head"]["root"] = base64.b64encode(b"\x00" * 32).decode()
            req = urllib.request.Request(
                url, data=json.dumps(forged).encode(), method="POST")
            req.add_header("Content-Type", "application/json")
            body = json.loads(urllib.request.urlopen(req).read())
            assert body["sth_signature_valid"] is False
        finally:
            httpd.shutdown()
            httpd.server_close()

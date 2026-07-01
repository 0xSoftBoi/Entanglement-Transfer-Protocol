"""
End-to-end tests for the etp-custody CLI (src/ltp/provenance_cli.py).

Drives the real command surface (keygen → init → seal → verify → open) through
main(argv), across the same on-disk artifacts a user would produce, and asserts
exit codes and tamper behavior. Also covers ProvenanceReceipt serialization.

These require the real PQC backend (pqcrypto + pynacl); skipped otherwise, since
the CLI refuses to run on the non-portable PoC fallback.
"""

import json

import pytest

pytest.importorskip("pqcrypto")
pytest.importorskip("nacl")

from src.ltp.provenance_cli import main
from src.ltp.provenance import ProvenanceReceipt


def _keygen(tmp_path, name, with_pub=False):
    key = tmp_path / f"{name}.key"
    argv = ["keygen", "-o", str(key), "--label", name]
    pub = None
    if with_pub:
        pub = tmp_path / f"{name}.pub"
        argv += ["--pub", str(pub)]
    assert main(argv) == 0
    return key, pub


@pytest.fixture
def notary(tmp_path):
    """A fresh initialized notary + a recipient (bob) with a public key."""
    op_key, _ = _keygen(tmp_path, "operator")
    _, bob_pub = _keygen(tmp_path, "bob", with_pub=True)
    ndir = tmp_path / "notary"
    assert main(["init", str(ndir), "--operator", str(op_key)]) == 0
    return {"dir": ndir, "op": op_key, "bob_pub": bob_pub, "tmp": tmp_path}


def _seal(notary, content=b"confidential", name="doc"):
    src = notary["tmp"] / f"{name}.txt"
    src.write_bytes(content)
    sealed = notary["tmp"] / f"{name}.sealed"
    receipt = notary["tmp"] / f"{name}.receipt"
    rc = main([
        "seal", str(notary["dir"]),
        "--in", str(src), "--to", str(notary["bob_pub"]),
        "--originator", "sensor-7",
        "--out", str(sealed), "--receipt", str(receipt),
    ])
    assert rc == 0
    return src, sealed, receipt


class TestHappyPath:
    def test_seal_verify_open_roundtrip(self, notary, tmp_path):
        content = b"top secret quarterly numbers"
        src, sealed, receipt = _seal(notary, content)

        # Anyone verifies offline, no secrets.
        assert main(["verify", "--sealed", str(sealed), "--receipt", str(receipt)]) == 0

        # Bob recovers the plaintext.
        out = tmp_path / "recovered.bin"
        bob_key = tmp_path / "bob.key"
        assert main(["open", "--key", str(bob_key), "--sealed", str(sealed),
                     "--receipt", str(receipt), "-o", str(out)]) == 0
        assert out.read_bytes() == content

    def test_log_reports_state(self, notary, capsys):
        for i in range(3):
            _seal(notary, name=f"d{i}")
        capsys.readouterr()
        assert main(["log", str(notary["dir"])]) == 0
        out = capsys.readouterr().out
        assert "captures : 3" in out

    def test_multiple_captures_all_verify(self, notary):
        seals = [_seal(notary, content=f"doc {i}".encode(), name=f"d{i}") for i in range(6)]
        for _, sealed, receipt in seals:
            assert main(["verify", "--sealed", str(sealed), "--receipt", str(receipt)]) == 0


class TestTamperAndMisuse:
    def test_tampered_sealed_fails(self, notary):
        _, sealed, receipt = _seal(notary, name="d")
        b = bytearray(sealed.read_bytes()); b[-1] ^= 0x01
        sealed.write_bytes(bytes(b))
        assert main(["verify", "--sealed", str(sealed), "--receipt", str(receipt)]) == 1

    def test_mismatched_receipt_fails(self, notary):
        _, sealed_a, _ = _seal(notary, content=b"A", name="a")
        _, _, receipt_b = _seal(notary, content=b"B", name="b")
        # a's sealed blob against b's receipt → must fail.
        assert main(["verify", "--sealed", str(sealed_a), "--receipt", str(receipt_b)]) == 1

    def test_unauthorized_recipient_cannot_open(self, notary, tmp_path):
        _, sealed, receipt = _seal(notary, name="d")
        eve_key, _ = _keygen(tmp_path, "eve")
        out = tmp_path / "hack.bin"
        assert main(["open", "--key", str(eve_key), "--sealed", str(sealed),
                     "-o", str(out)]) == 1
        assert not out.exists()

    def test_init_rejects_public_operator_key(self, tmp_path):
        _, pub = _keygen(tmp_path, "op", with_pub=True)
        with pytest.raises(SystemExit):
            main(["init", str(tmp_path / "n2"), "--operator", str(pub)])

    def test_malformed_receipt_fails_gracefully(self, tmp_path):
        bad = tmp_path / "bad.receipt"
        bad.write_text('{"manifest": {"content_hash": "!!notbase64!!"}}')
        sealed = tmp_path / "x.sealed"
        sealed.write_bytes(b"blob")
        # Must return 1 (clean FAIL), not raise an uncaught exception.
        assert main(["verify", "--sealed", str(sealed), "--receipt", str(bad)]) == 1


class TestOperatorPin:
    def test_verify_with_matching_operator_pin_passes(self, notary, tmp_path):
        # The notary's operator public key (extract from the store's secret key).
        op_pub = tmp_path / "op.pub"
        assert main(["pub", "-i", str(notary["dir"] / "operator.key"), "-o", str(op_pub)]) == 0
        _, sealed, receipt = _seal(notary, name="d")
        assert main(["verify", "--sealed", str(sealed), "--receipt", str(receipt),
                     "--operator", str(op_pub)]) == 0

    def test_verify_rejects_wrong_operator_pin(self, notary, tmp_path):
        _, sealed, receipt = _seal(notary, name="d")
        wrong_pub = tmp_path / "wrong.pub"
        _keygen(tmp_path, "wrong", with_pub=True)
        # a different notary's public key must not verify this receipt
        assert main(["verify", "--sealed", str(sealed), "--receipt", str(receipt),
                     "--operator", str(tmp_path / "wrong.pub")]) == 1


class TestOriginatorSigning:
    def test_device_signed_capture_pins_to_device(self, notary, tmp_path):
        dev_key, dev_pub = _keygen(tmp_path, "sensor7", with_pub=True)
        src = tmp_path / "d.txt"; src.write_bytes(b"reading")
        sealed = tmp_path / "d.sealed"; receipt = tmp_path / "d.receipt"
        assert main([
            "seal", str(notary["dir"]), "--in", str(src), "--to", str(notary["bob_pub"]),
            "--originator", "sensor-7", "--originator-key", str(dev_key),
            "--out", str(sealed), "--receipt", str(receipt),
        ]) == 0
        # pinning to the real device passes
        assert main(["verify", "--sealed", str(sealed), "--receipt", str(receipt),
                     "--expect-originator", str(dev_pub)]) == 0
        # pinning to a different device fails
        _, other_pub = _keygen(tmp_path, "other", with_pub=True)
        assert main(["verify", "--sealed", str(sealed), "--receipt", str(receipt),
                     "--expect-originator", str(other_pub)]) == 1

    def test_unsigned_capture_fails_originator_pin(self, notary, tmp_path):
        _, sealed, receipt = _seal(notary, name="u")   # no --originator-key
        _, dev_pub = _keygen(tmp_path, "sensor7", with_pub=True)
        assert main(["verify", "--sealed", str(sealed), "--receipt", str(receipt),
                     "--expect-originator", str(dev_pub)]) == 1


class TestBundleReassemble:
    def test_bundle_lose_shards_reassemble_and_verify(self, notary, tmp_path):
        _, sealed, receipt = _seal(notary, content=b"delay-tolerant evidence" * 20, name="d")
        # bundle into 6 shards, any 4 reconstruct
        assert main(["bundle", "--in", str(sealed), "--n", "6", "--k", "4",
                     "--prefix", str(tmp_path / "d")]) == 0
        shard_files = sorted(str(p) for p in tmp_path.glob("d.shard*"))
        assert len(shard_files) == 6
        # Simulate a lossy link: only 4 of 6 shards arrive (drop two).
        arrived = shard_files[:2] + shard_files[4:]
        assert len(arrived) == 4
        recon = tmp_path / "recon.sealed"
        assert main(["reassemble", "--bundle", str(tmp_path / "d.bundle"),
                     "--out", str(recon)] + arrived) == 0
        # reconstructed blob == original sealed, and the original receipt verifies it
        assert recon.read_bytes() == sealed.read_bytes()
        assert main(["verify", "--sealed", str(recon), "--receipt", str(receipt)]) == 0

    def test_reassemble_too_few_shards_fails(self, notary, tmp_path):
        _, sealed, _ = _seal(notary, name="d")
        assert main(["bundle", "--in", str(sealed), "--n", "6", "--k", "4",
                     "--prefix", str(tmp_path / "d")]) == 0
        shard_files = sorted(str(p) for p in tmp_path.glob("d.shard*"))[:2]  # only 2
        assert main(["reassemble", "--bundle", str(tmp_path / "d.bundle"),
                     "--out", str(tmp_path / "x.sealed")] + shard_files) == 1


class TestSendReceive:
    def _send(self, notary, tmp_path, content, *, sign=False):
        src = tmp_path / "msg.txt"; src.write_bytes(content)
        argv = ["send", str(notary["dir"]), "--in", str(src), "--to", str(notary["bob_pub"]),
                "--originator", "sensor-7", "--n", "6", "--k", "4", "--prefix", str(tmp_path / "parcel")]
        if sign:
            dev_key, dev_pub = _keygen(tmp_path, "sensor7", with_pub=True)
            argv += ["--originator-key", str(dev_key)]
            self._dev_pub = dev_pub
        assert main(argv) == 0
        return src

    def test_send_receive_roundtrip_with_loss(self, notary, tmp_path):
        content = b"the whole delay-tolerant custody flow" * 30
        src = self._send(notary, tmp_path, content)
        shards = sorted(str(p) for p in tmp_path.glob("parcel.shard*"))
        arrived = shards[:2] + shards[4:]   # lose 2 of 6
        out = tmp_path / "out.txt"
        bob_key = tmp_path / "bob.key"
        assert main([
            "receive", "--key", str(bob_key),
            "--bundle", str(tmp_path / "parcel.bundle"),
            "--receipt", str(tmp_path / "parcel.receipt"),
            "--out", str(out),
        ] + arrived) == 0
        assert out.read_bytes() == content

    def test_receive_fails_closed_on_tampered_shard_set(self, notary, tmp_path):
        # If too many shards are lost, receive must fail (and not write output).
        self._send(notary, tmp_path, b"payload")
        shards = sorted(str(p) for p in tmp_path.glob("parcel.shard*"))[:2]  # only 2 < k
        out = tmp_path / "out.txt"
        assert main([
            "receive", "--key", str(tmp_path / "bob.key"),
            "--bundle", str(tmp_path / "parcel.bundle"),
            "--receipt", str(tmp_path / "parcel.receipt"),
            "--out", str(out),
        ] + shards) == 1
        assert not out.exists()

    def test_receive_with_device_pin(self, notary, tmp_path):
        content = b"signed payload"
        self._send(notary, tmp_path, content, sign=True)
        shards = sorted(str(p) for p in tmp_path.glob("parcel.shard*"))
        out = tmp_path / "out.txt"
        assert main([
            "receive", "--key", str(tmp_path / "bob.key"),
            "--bundle", str(tmp_path / "parcel.bundle"),
            "--receipt", str(tmp_path / "parcel.receipt"),
            "--out", str(out), "--expect-originator", str(self._dev_pub),
        ] + shards) == 0
        assert out.read_bytes() == content


class TestKeyless:
    """The zero-ceremony flow: no keygen, no init, no key files."""

    def test_notarize_then_verify_by_filename(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ETP_CUSTODY_HOME", str(tmp_path / "home"))
        f = tmp_path / "deck.pdf"
        f.write_bytes(b"confidential board deck")
        # one command, no prior setup
        assert main(["notarize", str(f), "--attest"]) == 0
        assert (tmp_path / "deck.pdf.sealed").exists()
        assert (tmp_path / "deck.pdf.receipt").exists()
        assert (tmp_path / "deck.pdf.intoto.json").exists()
        # verify by filename, zero flags
        assert main(["verify", str(f)]) == 0

    def test_verify_from_attestation(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ETP_CUSTODY_HOME", str(tmp_path / "home"))
        f = tmp_path / "doc.txt"; f.write_bytes(b"data")
        assert main(["notarize", str(f), "--attest"]) == 0
        assert main(["verify", str(f), "--attestation", str(tmp_path / "doc.txt.intoto.json")]) == 0

    def test_notarize_builds_one_append_only_log(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ETP_CUSTODY_HOME", str(tmp_path / "home"))
        a = tmp_path / "a.txt"; a.write_bytes(b"a")
        b = tmp_path / "b.txt"; b.write_bytes(b"b")
        assert main(["notarize", str(a)]) == 0
        assert main(["notarize", str(b)]) == 0
        # the two receipts are from one append-only default notary
        assert main(["audit", str(tmp_path / "home" / "notary"),
                     str(tmp_path / "a.txt.receipt"), str(tmp_path / "b.txt.receipt")]) == 0

    def test_id_is_stable_across_calls(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("ETP_CUSTODY_HOME", str(tmp_path / "home"))
        assert main(["id"]) == 0
        first = capsys.readouterr().out
        assert main(["id"]) == 0
        second = capsys.readouterr().out
        assert first == second  # identity is created once, then stable


class TestAttestation:
    def test_attest_command_and_intoto_shape(self, notary, tmp_path):
        _, _, receipt = _seal(notary, name="d")
        out = tmp_path / "a.intoto.json"
        assert main(["attest", "--receipt", str(receipt), "--subject", "d.txt",
                     "--out", str(out)]) == 0
        import json as _j
        stmt = _j.loads(out.read_text())
        assert stmt["_type"] == "https://in-toto.io/Statement/v1"
        assert stmt["subject"][0]["name"] == "d.txt"
        assert "sha3_256" in stmt["subject"][0]["digest"]


class TestBatch:
    def _make_src(self, tmp_path, n=3):
        src = tmp_path / "src"; src.mkdir()
        contents = {}
        for i in range(n):
            c = f"record {i} confidential".encode() * (i + 1)
            (src / f"f{i}.txt").write_bytes(c)
            contents[f"f{i}.txt"] = c
        return src, contents

    def test_batch_send_receive_roundtrip(self, notary, tmp_path):
        src, contents = self._make_src(tmp_path)
        out = tmp_path / "parcels"
        assert main(["batch-send", str(notary["dir"]), "--in-dir", str(src),
                     "--to", str(notary["bob_pub"]), "--originator", "sensor-7",
                     "--n", "6", "--k", "4", "--out-dir", str(out)]) == 0
        # one append-only log covers the whole batch
        assert (out / "batch.json").exists()

        # simulate loss: delete 2 of 6 shards for one file — still reconstructs
        for p in sorted(out.glob("f1.txt.shard*"))[:2]:
            p.unlink()

        dst = tmp_path / "recovered"
        assert main(["batch-receive", "--key", str(tmp_path / "bob.key"),
                     "--in-dir", str(out), "--out-dir", str(dst)]) == 0
        for name, c in contents.items():
            assert (dst / name).read_bytes() == c

    def test_batch_receipts_are_one_append_only_log(self, notary, tmp_path):
        src, _ = self._make_src(tmp_path, n=2)
        out = tmp_path / "parcels"
        assert main(["batch-send", str(notary["dir"]), "--in-dir", str(src),
                     "--to", str(notary["bob_pub"]), "--originator", "s",
                     "--n", "5", "--k", "3", "--out-dir", str(out)]) == 0
        # every file's receipt shares the same batch STH → any pair audits consistent
        ra, rb = out / "f0.txt.receipt", out / "f1.txt.receipt"
        assert main(["audit", str(notary["dir"]), str(ra), str(rb)]) == 0

    def test_batch_receive_reports_failure_on_unrecoverable_file(self, notary, tmp_path):
        src, _ = self._make_src(tmp_path, n=2)
        out = tmp_path / "parcels"
        assert main(["batch-send", str(notary["dir"]), "--in-dir", str(src),
                     "--to", str(notary["bob_pub"]), "--originator", "s",
                     "--n", "6", "--k", "4", "--out-dir", str(out)]) == 0
        # destroy too many shards of f0 → that file is unrecoverable, batch returns 1
        for p in sorted(out.glob("f0.txt.shard*"))[:4]:
            p.unlink()
        dst = tmp_path / "recovered"
        assert main(["batch-receive", "--key", str(tmp_path / "bob.key"),
                     "--in-dir", str(out), "--out-dir", str(dst)]) == 1
        # the other file still came through
        assert (dst / "f1.txt").exists()
        assert not (dst / "f0.txt").exists()


class TestInspect:
    def test_inspect_valid_receipt(self, notary, tmp_path):
        _, _, receipt = _seal(notary, name="d")
        assert main(["inspect", "--receipt", str(receipt)]) == 0

    def test_inspect_with_bundle_reports_shard_sufficiency(self, notary, tmp_path):
        _, sealed, receipt = _seal(notary, content=b"payload" * 20, name="d")
        assert main(["bundle", "--in", str(sealed), "--n", "6", "--k", "4",
                     "--prefix", str(tmp_path / "d")]) == 0
        shards = sorted(str(p) for p in tmp_path.glob("d.shard*"))
        # enough shards → inspect passes
        assert main(["inspect", "--receipt", str(receipt),
                     "--bundle", str(tmp_path / "d.bundle")] + shards[:4]) == 0
        # too few shards → inspect fails the sufficiency check
        assert main(["inspect", "--receipt", str(receipt),
                     "--bundle", str(tmp_path / "d.bundle")] + shards[:2]) == 1

    def test_inspect_tampered_receipt_fails(self, notary, tmp_path):
        _, _, receipt = _seal(notary, name="d")
        d = json.loads(receipt.read_text())
        d["signed_tree_head"]["root"] = "AAAA" + d["signed_tree_head"]["root"][4:]
        receipt.write_text(json.dumps(d))
        assert main(["inspect", "--receipt", str(receipt)]) == 1


class TestAudit:
    def test_two_receipts_same_notary_are_consistent(self, notary, tmp_path):
        _, _, ra = _seal(notary, name="a")   # STH seq 0
        _, _, rb = _seal(notary, name="b")   # STH seq 1
        assert main(["audit", str(notary["dir"]), str(ra), str(rb)]) == 0

    def test_receipt_from_other_notary_is_not_consistent(self, notary, tmp_path):
        _, _, ra = _seal(notary, name="a")   # notary A, seq 0

        # A second, unrelated notary B with its own operator.
        op2, _ = _keygen(tmp_path, "op2")
        ndir2 = tmp_path / "notary2"
        assert main(["init", str(ndir2), "--operator", str(op2)]) == 0
        src = tmp_path / "z.txt"; src.write_bytes(b"z")
        sealed2 = tmp_path / "z.sealed"; rb = tmp_path / "z.receipt"
        assert main(["seal", str(ndir2), "--in", str(src), "--to", str(notary["bob_pub"]),
                     "--originator", "x", "--out", str(sealed2), "--receipt", str(rb)]) == 0
        assert main(["seal", str(ndir2), "--in", str(src), "--to", str(notary["bob_pub"]),
                     "--originator", "x", "--out", str(tmp_path / "z2.sealed"),
                     "--receipt", str(tmp_path / "z2.receipt")]) == 0

        # A's receipt (seq 0) vs B's second receipt (seq 1) → not one append-only log.
        assert main(["audit", str(notary["dir"]), str(ra),
                     str(tmp_path / "z2.receipt")]) == 1


class TestReceiptSerialization:
    def test_receipt_json_roundtrip(self, notary, tmp_path):
        _, sealed, receipt = _seal(notary, content=b"payload", name="d")
        r1 = ProvenanceReceipt.from_json(receipt.read_text())
        r2 = ProvenanceReceipt.from_json(r1.to_json())
        assert r2.verify(sealed.read_bytes())
        assert r2.manifest.capture_id == r1.manifest.capture_id

    def test_receipt_is_valid_json_with_expected_shape(self, notary):
        _, _, receipt = _seal(notary, name="d")
        d = json.loads(receipt.read_text())
        assert d["format"] == "etp-provenance-receipt/1"
        assert "manifest" in d and "inclusion_proof" in d and "signed_tree_head" in d

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

"""
etp-custody — post-quantum, tamper-evident chain-of-custody for files.

A command-line product built on ETP's provenance core. It seals a file to a
recipient with post-quantum crypto (ML-KEM-768 + XChaCha20-Poly1305), notarizes
a manifest of it into an append-only RFC-6962 Merkle log, and emits a portable
receipt that anyone can verify offline — no blockchain, no server, no secrets.

    # one-time: make keys
    etp-custody keygen -o operator.key --label notary
    etp-custody keygen -o bob.key --label bob --pub bob.pub

    # operator stands up a notary
    etp-custody init ./notary --operator operator.key

    # seal + notarize a file to Bob, get a sealed blob + a receipt
    etp-custody seal ./notary --in report.pdf --to bob.pub --originator sensor-7 \
        --out report.sealed --receipt report.receipt

    # anyone verifies provenance offline (no keys, no plaintext)
    etp-custody verify --sealed report.sealed --receipt report.receipt

    # Bob (and only Bob) recovers the plaintext
    etp-custody open --key bob.key --sealed report.sealed -o report.pdf

Run in-repo with:  PYTHONPATH=. python -m src.ltp.provenance_cli ...
Or install the package and use the `etp-custody` command.

NOTE: real post-quantum crypto requires the optional deps (pip install "ltp[crypto]":
pqcrypto + pynacl). Without them the library falls back to PoC hash simulations,
whose keys are NOT portable across processes — so this CLI requires the real
backend, and refuses to run if only the PoC fallback is active.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .keypair import KeyPair
from .provenance import ProvenanceLog, ProvenanceReceipt, CaptureManifest, SEAL_OVERHEAD
from .encoding import b64e, b64d
from .primitives import real_backend_active
from .merkle_log import SignedTreeHead

_KEY_FORMAT = "etp-custody-key/1"
_STORE_FORMAT = "etp-custody-notary/1"


# ---------------------------------------------------------------------------
# Real-backend guard
# ---------------------------------------------------------------------------

def _require_real_crypto() -> None:
    """
    Refuse to run on PoC simulations: their keys live in per-process lookup
    tables and cannot be persisted/shared, which would silently break the CLI.
    Delegates to primitives.real_backend_active(), which also catches the case
    where an active profile would silently fall back despite the libs installed.
    """
    if not real_backend_active():
        sys.stderr.write(
            "error: etp-custody requires real post-quantum crypto.\n"
            "       install it with:  pip install pqcrypto pynacl\n"
            "       (the PoC fallback's keys are not portable across processes)\n"
        )
        raise SystemExit(3)


# ---------------------------------------------------------------------------
# Key files
# ---------------------------------------------------------------------------

def _keypair_to_dict(kp: KeyPair, *, public_only: bool) -> dict:
    return {
        "format": _KEY_FORMAT,
        "label": kp.label,
        "public_only": public_only,
        "ek": b64e(kp.ek),
        "vk": b64e(kp.vk),
        "dk": "" if public_only else b64e(kp.dk),
        "sk": "" if public_only else b64e(kp.sk),
    }


def _keypair_from_dict(d: dict) -> KeyPair:
    # ek/vk are always present and non-empty; dk/sk are "" for public-only keys.
    return KeyPair(
        ek=b64d(d["ek"]),
        dk=b64d(d["dk"]) if d.get("dk") else b"",
        vk=b64d(d["vk"]),
        sk=b64d(d["sk"]) if d.get("sk") else b"",
        label=d.get("label", ""),
    )


def _write_key(path: Path, kp: KeyPair, *, public_only: bool) -> None:
    path.write_text(json.dumps(_keypair_to_dict(kp, public_only=public_only), indent=2))
    if not public_only:
        try:
            os.chmod(path, 0o600)  # secret material — owner-only
        except OSError:
            pass


def _read_key(path: Path) -> KeyPair:
    return _keypair_from_dict(json.loads(path.read_text()))


# ---------------------------------------------------------------------------
# Notary store (file-backed, reconstructable)
# ---------------------------------------------------------------------------

def _read_lines(path: Path) -> list[str]:
    """Read a jsonl file once, returning its non-empty lines (empty if absent)."""
    if not path.exists():
        return []
    return [line for line in path.read_text().splitlines() if line.strip()]

class NotaryStore:
    """A persisted provenance notary: operator key + append-only manifest log."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.operator_key = root / "operator.key"
        self.records = root / "records.jsonl"
        self.sths = root / "sths.jsonl"
        self.meta = root / "meta.json"

    # -- lifecycle --

    @classmethod
    def init(cls, root: Path, operator: KeyPair) -> "NotaryStore":
        if root.exists() and any(root.iterdir()):
            raise SystemExit(f"error: {root} already exists and is not empty")
        root.mkdir(parents=True, exist_ok=True)
        store = cls(root)
        _write_key(store.operator_key, operator, public_only=False)
        store.records.write_text("")
        store.sths.write_text("")
        store.meta.write_text(json.dumps({"format": _STORE_FORMAT}, indent=2))
        return store

    def _load_manifests(self) -> list[CaptureManifest]:
        return [CaptureManifest.from_dict(json.loads(l)) for l in _read_lines(self.records)]

    def sth_count(self) -> int:
        return len(_read_lines(self.sths))

    def latest_sth(self) -> SignedTreeHead | None:
        lines = _read_lines(self.sths)
        return SignedTreeHead.from_dict(json.loads(lines[-1])) if lines else None

    def load_log(self) -> ProvenanceLog:
        """Rebuild the in-memory provenance log by replaying stored manifests."""
        if not self.operator_key.exists():
            raise SystemExit(f"error: no notary at {self.root} (run `init` first)")
        operator = _read_key(self.operator_key)
        plog = ProvenanceLog(operator)
        for manifest in self._load_manifests():
            plog.append_manifest(manifest)
        plog.restore_sequence(self.sth_count())
        return plog

    def append_record(self, manifest: CaptureManifest) -> None:
        with self.records.open("a") as f:
            f.write(json.dumps(manifest.to_dict()) + "\n")

    def append_sth(self, sth: SignedTreeHead) -> None:
        with self.sths.open("a") as f:
            f.write(json.dumps(sth.to_dict()) + "\n")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_keygen(args) -> int:
    kp = KeyPair.generate(args.label or "")
    _write_key(Path(args.out), kp, public_only=False)
    print(f"✓ wrote keypair → {args.out}  (label={kp.label or '-'})")
    if args.pub:
        _write_key(Path(args.pub), kp, public_only=True)
        print(f"✓ wrote public key → {args.pub}  (shareable)")
    return 0


def cmd_pub(args) -> int:
    kp = _read_key(Path(args.inp))
    _write_key(Path(args.out), kp, public_only=True)
    print(f"✓ extracted public key → {args.out}")
    return 0


def cmd_init(args) -> int:
    operator = _read_key(Path(args.operator))
    if not operator.sk:
        raise SystemExit("error: operator key must be a full (secret) key, not a public key")
    NotaryStore.init(Path(args.dir), operator)
    print(f"✓ initialized notary at {args.dir}")
    return 0


def _parse_meta(pairs: list[str] | None) -> dict:
    meta = {}
    for p in pairs or []:
        if "=" not in p:
            raise SystemExit(f"error: --meta expects key=value, got {p!r}")
        k, v = p.split("=", 1)
        meta[k] = v
    return meta


def cmd_seal(args) -> int:
    store = NotaryStore(Path(args.dir))
    recipient = _read_key(Path(args.to))
    if not recipient.ek:
        raise SystemExit("error: recipient key has no encapsulation key")
    artifact = Path(args.inp).read_bytes()

    plog = store.load_log()
    capture, idx = plog.record_capture(
        artifact,
        recipient_ek=recipient.ek,
        originator_id=args.originator,
        meta=_parse_meta(args.meta),
    )
    sth = plog.publish_sth()
    proof = plog.inclusion_proof(idx)
    receipt = ProvenanceReceipt.build(capture.manifest, proof, sth)

    # Persist the new state, then emit the deliverables.
    store.append_record(capture.manifest)
    store.append_sth(sth)

    sealed_path = Path(args.out) if args.out else Path(args.inp).with_suffix(
        Path(args.inp).suffix + ".sealed"
    )
    receipt_path = Path(args.receipt) if args.receipt else sealed_path.with_suffix(".receipt")
    sealed_path.write_bytes(capture.sealed)
    receipt_path.write_text(receipt.to_json())

    print(f"✓ sealed & notarized  '{args.inp}'")
    print(f"    capture id : {capture.manifest.capture_id}")
    print(f"    log index  : {idx}   tree size: {sth.tree_size}   STH seq: {sth.sequence}")
    print(f"    payload    : {len(artifact)} B  →  sealed {capture.size} B "
          f"(+{SEAL_OVERHEAD} B constant PQC overhead)")
    print(f"    sealed blob: {sealed_path}")
    print(f"    receipt    : {receipt_path}")
    return 0


def cmd_publish(args) -> int:
    store = NotaryStore(Path(args.dir))
    plog = store.load_log()
    sth = plog.publish_sth()
    store.append_sth(sth)
    print(f"✓ published STH  seq={sth.sequence}  tree_size={sth.tree_size}")
    print(f"    root: {sth.root_hash.hex()}")
    return 0


def cmd_verify(args) -> int:
    receipt = ProvenanceReceipt.from_json(Path(args.receipt).read_text())
    sealed = Path(args.sealed).read_bytes()
    ok = receipt.verify(sealed)
    m = receipt.manifest
    if ok:
        print("PASS — provenance verified")
        print(f"    capture id   : {m.capture_id}")
        print(f"    originator   : {m.originator_id}")
        print(f"    captured_at  : {m.captured_at}")
        print(f"    operator vk  : {b64e(receipt.sth.operator_vk)[:24]}…")
        print(f"    attested root: {receipt.sth.root_hash.hex()[:24]}…  (STH seq {receipt.sth.sequence})")
        print(f"    proof path   : {receipt.proof.path_length} hashes (O(log N))")
        return 0
    print("FAIL — provenance could NOT be verified (tampered, mismatched, or forged)")
    return 1


def cmd_open(args) -> int:
    recipient = _read_key(Path(args.key))
    if not recipient.dk:
        raise SystemExit("error: opening requires a full (secret) recipient key")
    sealed = Path(args.sealed).read_bytes()
    manifest = None
    if args.receipt:
        manifest = ProvenanceReceipt.from_json(Path(args.receipt).read_text()).manifest
    try:
        plaintext = ProvenanceLog.open_capture(sealed, recipient, manifest)
    except ValueError as e:
        sys.stderr.write(f"error: cannot open — {e}\n")
        return 1
    Path(args.out).write_bytes(plaintext)
    print(f"✓ recovered {len(plaintext)} B → {args.out}")
    if manifest is not None:
        print("    (verified plaintext matches the notarized content hash)")
    return 0


def cmd_log(args) -> int:
    store = NotaryStore(Path(args.dir))
    plog = store.load_log()
    latest = store.latest_sth()
    print(f"notary: {args.dir}")
    print(f"    captures : {plog.size}")
    print(f"    STHs     : {store.sth_count()}")
    if latest is not None:
        print(f"    latest STH: seq={latest.sequence} tree_size={latest.tree_size} "
              f"root={latest.root_hash.hex()[:24]}…")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="etp-custody",
        description="Post-quantum, tamper-evident chain-of-custody for files (no blockchain).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen", help="generate a post-quantum keypair")
    g.add_argument("-o", "--out", required=True, help="output secret key file")
    g.add_argument("--label", help="human-readable label")
    g.add_argument("--pub", help="also write a shareable public-key file here")
    g.set_defaults(func=cmd_keygen)

    pb = sub.add_parser("pub", help="extract the public key from a secret key file")
    pb.add_argument("-i", "--in", dest="inp", required=True, help="secret key file")
    pb.add_argument("-o", "--out", required=True, help="output public key file")
    pb.set_defaults(func=cmd_pub)

    it = sub.add_parser("init", help="initialize a notary store")
    it.add_argument("dir", help="notary directory to create")
    it.add_argument("--operator", required=True, help="operator secret key file")
    it.set_defaults(func=cmd_init)

    s = sub.add_parser("seal", help="seal + notarize a file to a recipient")
    s.add_argument("dir", help="notary directory")
    s.add_argument("--in", dest="inp", required=True, help="input file to protect")
    s.add_argument("--to", required=True, help="recipient public-key file")
    s.add_argument("--originator", required=True, help="originator identifier (e.g. sensor-7)")
    s.add_argument("--out", help="output sealed blob (default: <in>.sealed)")
    s.add_argument("--receipt", help="output receipt file (default: <out>.receipt)")
    s.add_argument("--meta", action="append", help="key=value metadata (repeatable)")
    s.set_defaults(func=cmd_seal)

    pubh = sub.add_parser("publish", help="publish a signed tree head (attestation)")
    pubh.add_argument("dir", help="notary directory")
    pubh.set_defaults(func=cmd_publish)

    v = sub.add_parser("verify", help="verify a receipt against a sealed blob (offline)")
    v.add_argument("--sealed", required=True, help="sealed blob")
    v.add_argument("--receipt", required=True, help="receipt file")
    v.set_defaults(func=cmd_verify)

    o = sub.add_parser("open", help="recover the plaintext (authorized recipient only)")
    o.add_argument("--key", required=True, help="recipient secret key file")
    o.add_argument("--sealed", required=True, help="sealed blob")
    o.add_argument("--receipt", help="receipt file (re-checks content hash if given)")
    o.add_argument("-o", "--out", required=True, help="output plaintext file")
    o.set_defaults(func=cmd_open)

    lg = sub.add_parser("log", help="show notary state")
    lg.add_argument("dir", help="notary directory")
    lg.set_defaults(func=cmd_log)

    return p


def main(argv: list[str] | None = None) -> int:
    _require_real_crypto()
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

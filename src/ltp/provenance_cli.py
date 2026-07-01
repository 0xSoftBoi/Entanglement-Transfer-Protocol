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
import hmac
import json
import os
import re
import sys
from pathlib import Path

from .keypair import KeyPair
from .provenance import (
    ProvenanceLog, ProvenanceReceipt, CaptureManifest, SEAL_OVERHEAD,
    BundleManifest, bundle_sealed, reassemble_sealed,
)
from .encoding import b64e, b64d
from .primitives import real_backend_active, H_bytes, MLDSA
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
    data = json.dumps(_keypair_to_dict(kp, public_only=public_only), indent=2)
    if public_only:
        path.write_text(data)
        return
    # Secret material: create owner-only (0600) from the start so there is no
    # window where the private key is world-readable under the default umask.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data.encode("utf-8"))
    finally:
        os.close(fd)


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


def _collect_shards(paths: list[str]) -> dict[int, bytes]:
    """Load shard files into {index: bytes}, reading the index from .shardNN names."""
    shards: dict[int, bytes] = {}
    for sp in paths:
        p = Path(sp)
        m = re.search(r"\.shard(\d+)$", p.name)
        if not m:
            print(f"    skipping {p.name} (no .shardNN index in name)")
            continue
        shards[int(m.group(1))] = p.read_bytes()
    return shards

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

    originator = None
    if args.originator_key:
        originator = _read_key(Path(args.originator_key))
        if not originator.sk:
            raise SystemExit("error: --originator-key must be a full (secret) key")

    plog = store.load_log()
    capture, idx = plog.record_capture(
        artifact,
        recipient_ek=recipient.ek,
        originator_id=args.originator,
        originator=originator,
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
    print(f"    originator : {args.originator}"
          + ("  (device-signed ✓)" if originator is not None else "  (operator-vouched only)"))
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
    # Receipts are untrusted input; parse defensively.
    try:
        receipt = ProvenanceReceipt.from_json(Path(args.receipt).read_text())
    except (ValueError, KeyError, TypeError) as e:
        print(f"FAIL — malformed receipt ({type(e).__name__})")
        return 1
    sealed = Path(args.sealed).read_bytes()

    expected_vk = _read_key(Path(args.operator)).vk if args.operator else None
    expected_origin_vk = _read_key(Path(args.expect_originator)).vk if args.expect_originator else None

    ok = receipt.verify(sealed, expected_operator_vk=expected_vk,
                        expected_originator_vk=expected_origin_vk)
    m = receipt.manifest
    if ok:
        print("PASS — provenance verified")
        print(f"    capture id   : {m.capture_id}")
        print(f"    originator   : {m.originator_id}", end="")
        if expected_origin_vk is not None:
            print(f"  (device-signed, PINNED to {args.expect_originator} ✓)")
        elif m.originator_vk:
            print("  (device-signed ✓ — pass --expect-originator to pin the device)")
        else:
            print("  (operator-vouched only — no device signature)")
        print(f"    captured_at  : {m.captured_at}")
        if expected_vk is not None:
            print(f"    operator     : PINNED to {args.operator} ✓")
        else:
            print(f"    operator vk  : {b64e(receipt.sth.operator_vk)[:24]}…  "
                  f"(UNPINNED — pass --operator to prove a trusted notary)")
        print(f"    attested root: {receipt.sth.root_hash.hex()[:24]}…  (STH seq {receipt.sth.sequence})")
        print(f"    proof path   : {receipt.proof.path_length} hashes (O(log N))")
        return 0
    if expected_vk is not None and not hmac.compare_digest(receipt.sth.operator_vk, expected_vk):
        print("FAIL — receipt was signed by a DIFFERENT operator than --operator")
    elif expected_origin_vk is not None and not hmac.compare_digest(m.originator_vk, expected_origin_vk):
        print("FAIL — capture was signed by a DIFFERENT originator than --expect-originator "
              "(or is unsigned)")
    else:
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


def _write_bundle(prefix: Path, manifest: BundleManifest, shards: list) -> tuple:
    """Write the bundle manifest + shard files under `prefix`; return their paths."""
    bundle_path = prefix.with_suffix(prefix.suffix + ".bundle")
    bundle_path.write_text(manifest.to_json())
    shard_paths = []
    for idx, shard in enumerate(shards):
        p = prefix.with_suffix(prefix.suffix + f".shard{idx:03d}")
        p.write_bytes(shard)
        shard_paths.append(p)
    return bundle_path, shard_paths


def cmd_bundle(args) -> int:
    sealed = Path(args.inp).read_bytes()
    try:
        manifest, shards = bundle_sealed(sealed, args.n, args.k)
    except ValueError as e:
        raise SystemExit(f"error: {e}")
    prefix = Path(args.prefix) if args.prefix else Path(args.inp)
    bundle_path, shard_paths = _write_bundle(prefix, manifest, shards)
    lost_ok = args.n - args.k
    print(f"✓ bundled '{args.inp}' into {args.n} shards (any {args.k} reconstruct)")
    print(f"    tolerates losing any {lost_ok} of {args.n} shards "
          f"(~{100 * lost_ok // args.n}% loss)")
    print(f"    each shard : ~{len(shards[0])} B")
    print(f"    manifest   : {bundle_path}")
    print(f"    shards     : {shard_paths[0].name} … {shard_paths[-1].name}")
    return 0


def cmd_reassemble(args) -> int:
    manifest = BundleManifest.from_json(Path(args.bundle).read_text())
    shards = _collect_shards(args.shards)
    try:
        sealed = reassemble_sealed(manifest, shards)
    except ValueError as e:
        print(f"FAIL — {e}")
        return 1
    Path(args.out).write_bytes(sealed)
    print(f"✓ reassembled {len(sealed)} B → {args.out}  (from {len(shards)} shards, "
          f"needed {manifest.k}/{manifest.n})")
    print("    the reconstructed sealed blob verifies against its receipt as usual")
    return 0


def cmd_send(args) -> int:
    """One shot: seal + notarize + erasure-bundle, ready to spray over a lossy link."""
    store = NotaryStore(Path(args.dir))
    recipient = _read_key(Path(args.to))
    if not recipient.ek:
        raise SystemExit("error: recipient key has no encapsulation key")
    artifact = Path(args.inp).read_bytes()

    originator = None
    if args.originator_key:
        originator = _read_key(Path(args.originator_key))
        if not originator.sk:
            raise SystemExit("error: --originator-key must be a full (secret) key")

    plog = store.load_log()
    capture, idx = plog.record_capture(
        artifact, recipient_ek=recipient.ek, originator_id=args.originator,
        originator=originator, meta=_parse_meta(args.meta),
    )
    sth = plog.publish_sth()
    receipt = ProvenanceReceipt.build(capture.manifest, plog.inclusion_proof(idx), sth)
    store.append_record(capture.manifest)
    store.append_sth(sth)

    try:
        bundle, shards = bundle_sealed(capture.sealed, args.n, args.k)
    except ValueError as e:
        raise SystemExit(f"error: {e}")

    prefix = Path(args.prefix) if args.prefix else Path(args.inp)
    receipt_path = prefix.with_suffix(prefix.suffix + ".receipt")
    receipt_path.write_text(receipt.to_json())
    bundle_path, shard_paths = _write_bundle(prefix, bundle, shards)

    lost_ok = args.n - args.k
    print(f"✓ sent '{args.inp}' — sealed, notarized, and erasure-bundled")
    print(f"    capture id : {capture.manifest.capture_id}")
    print(f"    originator : {args.originator}"
          + ("  (device-signed ✓)" if originator is not None else "  (operator-vouched only)"))
    print(f"    shards     : {args.n} (any {args.k} reconstruct; tolerates losing {lost_ok})")
    print(f"    parcel     : {receipt_path.name}, {bundle_path.name}, "
          f"{shard_paths[0].name}…{shard_paths[-1].name}")
    print(f"    → transport the parcel; receiver runs `etp-custody receive`")
    return 0


def cmd_receive(args) -> int:
    """One shot: reassemble from surviving shards, verify provenance, then open."""
    recipient = _read_key(Path(args.key))
    if not recipient.dk:
        raise SystemExit("error: receiving requires a full (secret) recipient key")

    bundle = BundleManifest.from_json(Path(args.bundle).read_text())
    shards = _collect_shards(args.shards)
    try:
        sealed = reassemble_sealed(bundle, shards)
    except ValueError as e:
        print(f"FAIL — reassembly: {e}")
        return 1

    try:
        receipt = ProvenanceReceipt.from_json(Path(args.receipt).read_text())
    except (ValueError, KeyError, TypeError) as e:
        print(f"FAIL — malformed receipt ({type(e).__name__})")
        return 1

    expected_vk = _read_key(Path(args.operator)).vk if args.operator else None
    expected_origin_vk = _read_key(Path(args.expect_originator)).vk if args.expect_originator else None

    # Fail closed: never open a payload whose provenance does not verify.
    if not receipt.verify(sealed, expected_operator_vk=expected_vk,
                          expected_originator_vk=expected_origin_vk):
        print("FAIL — provenance did NOT verify; refusing to open the payload")
        return 1

    try:
        plaintext = ProvenanceLog.open_capture(sealed, recipient, receipt.manifest)
    except ValueError as e:
        print(f"FAIL — cannot open: {e}")
        return 1

    Path(args.out).write_bytes(plaintext)
    m = receipt.manifest
    print(f"✓ received → {args.out}  ({len(plaintext)} B)")
    print(f"    reassembled  : from {len(shards)} shards (needed {bundle.k}/{bundle.n})")
    print(f"    provenance   : VERIFIED"
          + (f" · operator PINNED" if expected_vk is not None else "")
          + (f" · device PINNED" if expected_origin_vk is not None else ""))
    print(f"    originator   : {m.originator_id}"
          + ("  (device-signed)" if m.originator_vk else "  (operator-vouched)"))
    return 0


def cmd_batch_send(args) -> int:
    """Seal + notarize + bundle every file in a directory under one append-only log."""
    store = NotaryStore(Path(args.dir))
    recipient = _read_key(Path(args.to))
    if not recipient.ek:
        raise SystemExit("error: recipient key has no encapsulation key")
    originator = None
    if args.originator_key:
        originator = _read_key(Path(args.originator_key))
        if not originator.sk:
            raise SystemExit("error: --originator-key must be a full (secret) key")

    src = Path(args.in_dir)
    files = sorted(p for p in src.iterdir() if p.is_file())
    if not files:
        raise SystemExit(f"error: no files in {src}")
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Append all captures first, then publish ONE STH covering the whole batch,
    # so every receipt shares the same attested (final) root.
    plog = store.load_log()
    pending = []
    for f in files:
        cap, idx = plog.record_capture(
            f.read_bytes(), recipient_ek=recipient.ek, originator_id=args.originator,
            originator=originator, meta={**_parse_meta(args.meta), "filename": f.name},
        )
        store.append_record(cap.manifest)
        pending.append((f.name, cap, idx))
    sth = plog.publish_sth()
    store.append_sth(sth)

    index = {"format": "etp-batch/1", "count": len(pending), "entries": []}
    for name, cap, idx in pending:
        receipt = ProvenanceReceipt.build(cap.manifest, plog.inclusion_proof(idx), sth)
        try:
            bundle, shards = bundle_sealed(cap.sealed, args.n, args.k)
        except ValueError as e:
            raise SystemExit(f"error: {e}")
        prefix = out_dir / name
        (out_dir / f"{name}.receipt").write_text(receipt.to_json())
        bundle_path, shard_paths = _write_bundle(prefix, bundle, shards)
        index["entries"].append({
            "name": name,
            "receipt": f"{name}.receipt",
            "bundle": bundle_path.name,
            "shards": [p.name for p in shard_paths],
        })
    (out_dir / "batch.json").write_text(json.dumps(index, indent=2))

    print(f"✓ batch-sent {len(pending)} files → {out_dir}/  (one append-only log, "
          f"shared STH seq {sth.sequence}, root {sth.root_hash.hex()[:16]}…)")
    print(f"    each file bundled {args.n}/{args.k}; index: {out_dir / 'batch.json'}")
    return 0


def cmd_batch_receive(args) -> int:
    """Reassemble + verify + open every entry in a batch, failing closed per file."""
    recipient = _read_key(Path(args.key))
    if not recipient.dk:
        raise SystemExit("error: receiving requires a full (secret) recipient key")
    in_dir = Path(args.in_dir)
    index = json.loads((in_dir / "batch.json").read_text())
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    expected_vk = _read_key(Path(args.operator)).vk if args.operator else None
    expected_origin_vk = _read_key(Path(args.expect_originator)).vk if args.expect_originator else None

    ok_count = 0
    for entry in index["entries"]:
        name = entry["name"]
        bundle = BundleManifest.from_json((in_dir / entry["bundle"]).read_text())
        shards = _collect_shards([str(in_dir / s) for s in entry["shards"] if (in_dir / s).exists()])
        try:
            sealed = reassemble_sealed(bundle, shards)
            receipt = ProvenanceReceipt.from_json((in_dir / entry["receipt"]).read_text())
        except (ValueError, KeyError, TypeError) as e:
            print(f"    [✗] {name}: {type(e).__name__}")
            continue
        if not receipt.verify(sealed, expected_operator_vk=expected_vk,
                              expected_originator_vk=expected_origin_vk):
            print(f"    [✗] {name}: provenance did NOT verify — skipped")
            continue
        try:
            plaintext = ProvenanceLog.open_capture(sealed, recipient, receipt.manifest)
        except ValueError as e:
            print(f"    [✗] {name}: cannot open ({e})")
            continue
        (out_dir / name).write_bytes(plaintext)
        ok_count += 1
        print(f"    [✓] {name}  ({len(plaintext)} B)")

    total = index["count"]
    print(f"✓ batch-received {ok_count}/{total} files → {out_dir}/")
    return 0 if ok_count == total else 1


def cmd_inspect(args) -> int:
    """Read-only: describe a receipt/parcel and check its internal validity (no keys)."""
    try:
        receipt = ProvenanceReceipt.from_json(Path(args.receipt).read_text())
    except (ValueError, KeyError, TypeError) as e:
        print(f"error — malformed receipt ({type(e).__name__})")
        return 1
    m = receipt.manifest

    print(f"receipt: {args.receipt}")
    print(f"    capture id : {m.capture_id}")
    print(f"    originator : {m.originator_id}"
          + ("  (device-signed)" if m.originator_vk else "  (operator-vouched only)"))
    print(f"    captured_at: {m.captured_at}")
    print(f"    operator vk: {b64e(receipt.sth.operator_vk)[:24]}…")
    print(f"    log state  : tree_size={receipt.sth.tree_size}  STH seq={receipt.sth.sequence}  "
          f"leaf={receipt.proof.leaf_index}")
    if m.meta:
        print(f"    meta       : {m.meta}")

    checks = [
        ("operator STH signature valid", receipt.sth.verify()),
        ("inclusion proof reconstructs the attested root",
         receipt.proof.verify(m.canonical_bytes(), receipt.sth.root_hash)),
    ]
    if m.originator_vk:
        checks.append((
            "originator (device) signature valid",
            MLDSA.verify(m.originator_vk, m.originator_signed_payload(), m.originator_sig),
        ))
    if args.bundle:
        bundle = BundleManifest.from_json(Path(args.bundle).read_text())
        shards = _collect_shards(args.shards)
        valid = sum(
            1 for i, s in shards.items()
            if 0 <= i < len(bundle.shard_hashes)
            and hmac.compare_digest(H_bytes(s), bundle.shard_hashes[i])
        )
        checks.append((f"shards present: {valid}/{bundle.n} valid, need {bundle.k}",
                       valid >= bundle.k))
        if valid >= bundle.k:
            try:
                recon = reassemble_sealed(bundle, shards)
                checks.append(("reassembled blob matches manifest sealed_hash",
                               hmac.compare_digest(H_bytes(recon), m.sealed_hash)))
            except ValueError:
                checks.append(("reassembly", False))

    print("    checks:")
    for name, ok in checks:
        print(f"      [{'✓' if ok else '✗'}] {name}")
    all_ok = all(ok for _, ok in checks)
    print("    → structurally valid" if all_ok else "    → STRUCTURAL CHECK FAILED")
    print("    (authenticity requires pinning: use `verify --operator/--expect-originator`)")
    return 0 if all_ok else 1


def cmd_audit(args) -> int:
    """Verify two receipts came from one append-only log (RFC 6962 consistency)."""
    store = NotaryStore(Path(args.dir))
    plog = store.load_log()
    try:
        ra = ProvenanceReceipt.from_json(Path(args.receipt_a).read_text())
        rb = ProvenanceReceipt.from_json(Path(args.receipt_b).read_text())
    except (ValueError, KeyError, TypeError) as e:
        print(f"error — malformed receipt ({type(e).__name__})")
        return 1
    a, b = ra.sth, rb.sth

    # Same sequence: either the identical checkpoint (e.g. two files from one
    # batch share one STH) or an equivocation (same seq, different roots).
    if a.sequence == b.sequence:
        if a.verify() and b.verify() and hmac.compare_digest(a.root_hash, b.root_hash):
            print(f"CONSISTENT — both receipts share one log checkpoint "
                  f"(seq {a.sequence}, size {a.tree_size})")
            return 0
        print("NOT CONSISTENT — two signed roots at the same sequence = equivocation (fork)")
        return 1

    older, newer = (a, b) if a.sequence < b.sequence else (b, a)
    if plog.verify_append_only(older, newer):
        print(f"CONSISTENT — STH seq {newer.sequence} (size {newer.tree_size}) is an "
              f"append-only extension of seq {older.sequence} (size {older.tree_size})")
        print("    the notary did not rewrite or fork history between these two receipts")
        return 0
    print("NOT CONSISTENT — the two receipts are not linked by an append-only extension")
    print("    (possible history rewrite / fork, or receipts from a different notary)")
    return 1


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
    s.add_argument("--originator-key", help="capturing device's secret key — cryptographically "
                                            "sign the capture (default: operator-vouched only)")
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
    v.add_argument("--operator", help="pin the trusted notary's public key file "
                                      "(without it, any operator's receipt passes)")
    v.add_argument("--expect-originator", help="pin the capturing device's public key file "
                                               "(require this device's signature on the capture)")
    v.set_defaults(func=cmd_verify)

    o = sub.add_parser("open", help="recover the plaintext (authorized recipient only)")
    o.add_argument("--key", required=True, help="recipient secret key file")
    o.add_argument("--sealed", required=True, help="sealed blob")
    o.add_argument("--receipt", help="receipt file (re-checks content hash if given)")
    o.add_argument("-o", "--out", required=True, help="output plaintext file")
    o.set_defaults(func=cmd_open)

    b = sub.add_parser("bundle", help="erasure-code a sealed blob into n shards (any k reconstruct)")
    b.add_argument("--in", dest="inp", required=True, help="sealed blob to bundle")
    b.add_argument("--n", type=int, required=True, help="total shards to produce")
    b.add_argument("--k", type=int, required=True, help="shards needed to reconstruct (k < n)")
    b.add_argument("--prefix", help="output path prefix (default: <in>)")
    b.set_defaults(func=cmd_bundle)

    r = sub.add_parser("reassemble", help="reconstruct a sealed blob from any k shards")
    r.add_argument("--bundle", required=True, help="bundle manifest (.bundle)")
    r.add_argument("--out", required=True, help="output sealed blob")
    r.add_argument("shards", nargs="+", help="shard files (indices read from .shardNN names)")
    r.set_defaults(func=cmd_reassemble)

    sd = sub.add_parser("send", help="one shot: seal + notarize + erasure-bundle a file")
    sd.add_argument("dir", help="notary directory")
    sd.add_argument("--in", dest="inp", required=True, help="input file to protect")
    sd.add_argument("--to", required=True, help="recipient public-key file")
    sd.add_argument("--originator", required=True, help="originator identifier (e.g. sensor-7)")
    sd.add_argument("--originator-key", help="capturing device's secret key (sign the capture)")
    sd.add_argument("--n", type=int, required=True, help="total shards to produce")
    sd.add_argument("--k", type=int, required=True, help="shards needed to reconstruct (k < n)")
    sd.add_argument("--prefix", help="output parcel prefix (default: <in>)")
    sd.add_argument("--meta", action="append", help="key=value metadata (repeatable)")
    sd.set_defaults(func=cmd_send)

    rc = sub.add_parser("receive", help="one shot: reassemble + verify + open a parcel")
    rc.add_argument("--key", required=True, help="recipient secret key file")
    rc.add_argument("--bundle", required=True, help="bundle manifest (.bundle)")
    rc.add_argument("--receipt", required=True, help="receipt file")
    rc.add_argument("--out", required=True, help="output plaintext file")
    rc.add_argument("--operator", help="pin the trusted notary's public key file")
    rc.add_argument("--expect-originator", help="pin the capturing device's public key file")
    rc.add_argument("shards", nargs="+", help="shard files (indices from .shardNN names)")
    rc.set_defaults(func=cmd_receive)

    bs = sub.add_parser("batch-send", help="seal + notarize + bundle every file in a directory")
    bs.add_argument("dir", help="notary directory")
    bs.add_argument("--in-dir", required=True, help="directory of files to protect")
    bs.add_argument("--to", required=True, help="recipient public-key file")
    bs.add_argument("--originator", required=True, help="originator identifier")
    bs.add_argument("--originator-key", help="capturing device's secret key (sign each capture)")
    bs.add_argument("--n", type=int, required=True, help="total shards per file")
    bs.add_argument("--k", type=int, required=True, help="shards needed to reconstruct (k < n)")
    bs.add_argument("--out-dir", required=True, help="output parcel directory")
    bs.add_argument("--meta", action="append", help="key=value metadata (repeatable)")
    bs.set_defaults(func=cmd_batch_send)

    br = sub.add_parser("batch-receive", help="reassemble + verify + open every file in a batch")
    br.add_argument("--key", required=True, help="recipient secret key file")
    br.add_argument("--in-dir", required=True, help="parcel directory (containing batch.json)")
    br.add_argument("--out-dir", required=True, help="output directory for recovered files")
    br.add_argument("--operator", help="pin the trusted notary's public key file")
    br.add_argument("--expect-originator", help="pin the capturing device's public key file")
    br.set_defaults(func=cmd_batch_receive)

    ins = sub.add_parser("inspect", help="describe a receipt/parcel and check internal validity (no keys)")
    ins.add_argument("--receipt", required=True, help="receipt file")
    ins.add_argument("--bundle", help="bundle manifest (.bundle) — also checks shard sufficiency")
    ins.add_argument("shards", nargs="*", help="shard files to check (with --bundle)")
    ins.set_defaults(func=cmd_inspect)

    au = sub.add_parser("audit", help="verify two receipts are from one append-only log")
    au.add_argument("dir", help="notary directory")
    au.add_argument("receipt_a", help="first receipt")
    au.add_argument("receipt_b", help="second receipt")
    au.set_defaults(func=cmd_audit)

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

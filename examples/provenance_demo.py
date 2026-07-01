"""
Provenance MVP — post-quantum sealed capture + tamper-evident notarization.

Runs the end-to-end "provenance wedge" workflow that competitive/funding
research identified as ETP's defensible, unfunded whitespace: bind post-quantum
confidentiality to an RFC-6962 tamper-evident chain-of-custody, with NO
blockchain, over any (possibly disconnected) link.

    PYTHONPATH=. python examples/provenance_demo.py

The story: an originator (say, a sensor) captures a confidential artifact. It is
sealed to an authorized recipient with constant-overhead post-quantum crypto and
notarized in a Merkle log. Later, and offline from the payload, an independent
auditor proves the artifact is authentic and unaltered — and any tamper is
caught loudly.
"""

from src.ltp import KeyPair, reset_poc_state
from src.ltp.provenance import ProvenanceLog, SEAL_OVERHEAD

reset_poc_state()


def line(title: str) -> None:
    print(f"\n▸ {title}")


# ── Parties ──────────────────────────────────────────────────────────────
# operator  runs the notary log and signs Tree Heads.
# recipient is the only party allowed to open captures (holds the dk).
# auditor   holds neither the artifact nor any secret — verifies provenance.
operator = KeyPair.generate("operator")
recipient = KeyPair.generate("recipient")
attacker = KeyPair.generate("attacker")

plog = ProvenanceLog(operator)

print("=" * 70)
print("  ETP Provenance MVP — seal · notarize · verify (no blockchain)")
print("=" * 70)

# ── Capture & notarize a batch ───────────────────────────────────────────
line("Originator captures 5 confidential artifacts")
artifacts = [f"IMAGE-PRODUCT-{i} :: confidential payload".encode() * 40 for i in range(5)]
captures = []
for i, art in enumerate(artifacts):
    cap, idx = plog.record_capture(
        art, recipient_ek=recipient.ek,
        originator_id="sensor-7",
        meta={"seq": i, "class": "restricted"},
    )
    captures.append((cap, idx))
    print(f"  #{idx}  capture_id={cap.manifest.capture_id[:16]}…  "
          f"artifact={len(art)}B  sealed={cap.size}B")

print(f"\n  Constant seal overhead: {SEAL_OVERHEAD} bytes for EVERY capture,")
print(f"  independent of payload size (post-quantum, harvest-now-decrypt-later safe).")

# ── Operator attests the log state ───────────────────────────────────────
line("Operator publishes a Signed Tree Head (attestation)")
sth = plog.publish_sth()
print(f"  sequence={sth.sequence}  tree_size={sth.tree_size}  "
      f"root={sth.root_hash.hex()[:24]}…")
print(f"  STH signature verifies: {sth.verify()}")

# ── Independent auditor verifies one capture ─────────────────────────────
line("Auditor independently verifies capture #2 (no plaintext, no secrets)")
cap2, idx2 = captures[2]
proof = plog.inclusion_proof(idx2)
ok = ProvenanceLog.verify_capture(cap2.manifest, cap2.sealed, proof, sth)
print(f"  inclusion path length: {proof.path_length} hashes (O(log N))")
print(f"  provenance verified:   {ok}")

# ── Authorized recipient opens it; attacker cannot ───────────────────────
line("Only the authorized recipient can open the sealed payload")
plaintext = ProvenanceLog.open_capture(cap2.sealed, recipient, cap2.manifest)
print(f"  recipient recovered {len(plaintext)}B, matches original: {plaintext == artifacts[2]}")
try:
    ProvenanceLog.open_capture(cap2.sealed, attacker)
    print("  attacker opened it — SECURITY FAILURE")
except ValueError:
    print("  attacker (wrong key) blocked: post-quantum decapsulation failed ✓")

# ── Tamper detection — the whole point ───────────────────────────────────
line("Tamper detection: every alteration fails loudly")

# (a) flip a byte in the sealed artifact
bad_sealed = bytearray(cap2.sealed); bad_sealed[-1] ^= 0x01
print(f"  altered sealed blob      → verify_capture: "
      f"{ProvenanceLog.verify_capture(cap2.manifest, bytes(bad_sealed), proof, sth)} (want False)")

# (b) swap in a different artifact's manifest against this proof
other_manifest = captures[3][0].manifest
print(f"  swapped manifest         → verify_capture: "
      f"{ProvenanceLog.verify_capture(other_manifest, cap2.sealed, proof, sth)} (want False)")

# (c) forge an STH root (attacker claims a different history)
forged = plog.publish_sth()
forged.root_hash = bytes(32)  # tamper after signing — signature no longer covers it
print(f"  forged STH root          → sth.verify(): {forged.verify()} (want False)")

# ── Equivocation / fork detection ────────────────────────────────────────
line("Fork detection: two signed roots at the same sequence = cryptographic proof")
# A dishonest operator presents two divergent histories. Two fresh logs under the
# SAME operator key each publish their first STH (sequence 0) over different
# content → two validly-signed roots at the same sequence = an equivocation proof.
from src.ltp.merkle_log import MerkleLog
fork_a = ProvenanceLog(operator)
fork_b = ProvenanceLog(operator)
fork_a.record_capture(b"history A", recipient.ek, originator_id="sensor-7")
fork_b.record_capture(b"history B", recipient.ek, originator_id="sensor-7")
sth_a = fork_a.publish_sth()   # sequence 0, root A
sth_b = fork_b.publish_sth()   # sequence 0, root B
equiv = MerkleLog.detect_equivocation(sth_a, sth_b)
print(f"  two signed roots @ seq {sth_a.sequence}, roots differ: {sth_a.root_hash != sth_b.root_hash}")
print(f"  detect_equivocation(sth_a, sth_b): {equiv} "
      f"(True = operator caught presenting inconsistent histories)")

# ── Append-only guarantee ────────────────────────────────────────────────
line("Append-only: the log can only grow, never rewrite history")
old_sth = sth
plog.record_capture(b"a later capture", recipient.ek, originator_id="sensor-7")
new_sth = plog.publish_sth()
print(f"  verify_append_only(old, new): {plog.verify_append_only(old_sth, new_sth)} (want True)")

print("\n" + "=" * 70)
print("  ✓ Sealed, notarized, independently verifiable, tamper-evident —")
print("    post-quantum and blockchain-free. This is the provenance wedge.")
print("=" * 70)

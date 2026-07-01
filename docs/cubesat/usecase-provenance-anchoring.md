# CubeSat Use Case: Space Data Provenance / Notarization Anchoring

**Author:** Javier Calderon Jr, CTO of Global Settlement (GSX)
**Status:** Use-case scoping — one leaf under [`../../CUBESAT_SCOPE.md`](../../CUBESAT_SCOPE.md)
**Scope note:** This brief assumes the shared ETP-Sat architecture (constant-size PQC sealed key, k-of-n forward erasure coding, DTN/CCSDS convergence layer replacing gRPC, ground/flight compute split). It does **not** re-derive them — see the parent doc. This leaf is about **provenance**, and it is the one use case where ETP's on-chain anchoring stack is the *headline feature*, not a decoupled afterthought.

---

## 1. One-line pitch

Give every satellite-captured image, RF survey, or sensor log a post-quantum, tamper-evident chain of custody — signed at the sensor, committed to an append-only Merkle log, and periodically notarized on-chain — so a court, insurer, or analyst can *prove* the data is authentic, unaltered, and captured by a specific sensor at a specific time.

## 2. Mission profile & who buys it

The bird flies a normal EO / RF-survey / signals mission. Provenance is a **ground-side value-add layer** bolted onto the existing downlink: the flight side does at most a cheap capture signature; everything expensive (Merkle log operation, on-chain anchoring) runs on the ground *after* data lands. Anchoring is **never** in the flight critical path (per parent doc §5.2).

Who pays for "provably authentic overhead imagery":

- **Insurers / reinsurers** — crop, flood, wildfire, and marine claims settled against satellite evidence. They need proof the image was not cherry-picked, back-dated, or edited.
- **Courts / litigation** — admissibility hinges on chain of custody. An independently verifiable inclusion proof plus an on-chain timestamp is a stronger evidentiary artifact than "trust our archive."
- **Defense / ISR** — provenance of collection: which platform, which sensor, which pass produced this frame, and proof it was not altered in the pipeline.
- **Carbon / ESG verification** — deforestation, methane plumes, reservoir levels. Carbon-credit fraud is rampant; a notarized, time-bound observation record is the audit primitive.
- **Regulators** — maritime (dark-vessel / AIS-gap) enforcement, environmental compliance, spectrum monitoring — all need evidence that survives an adversarial challenge.

## 3. Data / provenance flow

```
  [capture on bird]  sensor frame + metadata (sensor_id, time, pose, mission)
        │  canonical SHA3-256 digest of (frame ‖ metadata)
        ▼
  [sign]   ML-DSA-65 capture signature over the digest
        │    (sign-on-orbit for high-assurance; sign-on-ground for power-limited birds)
        ▼
  [downlink]  frame + digest + signature ride the normal ETP-Sat downlink (parent doc)
        ▼
  [ground: Merkle log]  each landed capture is appended as one leaf to an
        │    RFC 6962 append-only log (src/ltp/merkle_log/). Leaf = H(0x00 ‖ record).
        ▼
  [periodic anchor]  once per day (or per N captures) the operator signs a
        │    SignedTreeHead (ML-DSA-65) and anchors ONE 32-byte root on-chain
        │    via AnchorClient → LTPAnchorRegistry.anchor(...).
        ▼
  [auditor verifies]  given a frame, the auditor:
             1. recomputes the SHA3-256 digest, checks the ML-DSA-65 capture sig
             2. gets an O(log N) inclusion proof, checks it reconstructs the STH root
             3. checks that STH root was anchored on-chain at/before the claimed time
```

The auditor needs only: the frame, its capture signature, one inclusion proof (a handful of hashes), the signed tree head, and public chain access. No access to the archive, the operator, or any other captures.

## 4. Why ETP fits — pillars ranked

This is the use case ETP's chain stack was *already built for*. Ranked by how load-bearing each pillar is here:

1. **`merkle_log/` (RFC 6962 append-only log) — the spine.** `InclusionProof` gives O(log N) membership proofs relative to a root; `SignedTreeHead` binds the operator's ML-DSA-65 identity to a `(sequence, tree_size, root_hash, timestamp)` snapshot. The doc-string design already covers **equivocation detection**: two valid STHs at the same sequence with different roots are a self-contained fork proof. That is exactly the "did the archive quietly rewrite history?" property a court cares about. (Reuse as-is.)
2. **`anchor/` + `backends/` + `LTPAnchorRegistry` — the independence anchor.** `AnchorClient.anchor()` writes a `bytes32 merkleRoot` (plus `signerVkHash`, `sequence`, `validUntil`, receipt type) to an immutable, third-party-witnessed ledger. This is what turns "the operator says so" into "a public chain witnessed this root at this block." `batchAnchor()` lets many logs / many days go in one transaction. (Reuse as-is.)
3. **PQC capture signatures (ML-DSA-65, FIPS 204) — the authenticity root.** Signs *who captured it*. Post-quantum matters precisely because provenance claims must hold up years later, in front of a future adversary with a quantum computer — a back-dated dispute in 2035 must not be forgeable. (Reuse `primitives.MLDSA` / `envelope.py`.)
4. **`sequencing.py` temporal binding — the anti-backdating guard.** Per-signer monotonic sequence + `valid_until` temporal expiry + chain binding. On-chain the registry also enforces monotonic `sequence` per `signerVkHash`, so an operator cannot silently insert a capture "into the past" without breaking the sequence chain. (Reuse as-is.)

Supporting: `commitment.py` / `receipt.py` / `evidence.py` package the proof bundle; `hsm.py` custodies the log-operator and capture signing keys.

## 5. ETP module impact for this use case

Overwhelmingly **reuse** — this is the least-new-code CubeSat use case.

| Module | Action | Why |
|---|---|---|
| `merkle_log/log.py`, `tree.py`, `proof.py`, `sth.py` | **Reuse** | Append-only log, inclusion proofs, signed tree heads — the core of provenance, unchanged |
| `merkle_log/portable_proof.py` | **Reuse** | Self-contained proof bundle to hand an external auditor |
| `anchor/client.py`, `anchor/submission.py`, `anchor/state.py` | **Reuse** | `AnchorClient.anchor()`/`batch_anchor()` already write `merkleRoot` on-chain |
| `backends/` (local / ethereum / monad) | **Reuse** | Pluggable settlement target; `local` for the MVP, real chain for prod |
| `contracts/` LTPAnchorRegistry | **Reuse** | `anchor(bytes32 merkleRoot, …)` + monotonic per-signer sequence already fit |
| `sequencing.py` | **Reuse** | Monotonic sequence + temporal expiry = anti-backdating |
| `primitives` (ML-DSA-65), `envelope.py`, `hsm.py` | **Reuse** | Capture signatures + key custody |
| Capture record schema (`sensor_id, time, pose, mission, frame_digest`) | **NEW (small)** | A canonical, SHA3-256-hashed provenance record type; ~1 dataclass + encoder |
| Ground ingest daemon (downlink → verify sig → append leaf → schedule anchor) | **NEW (small)** | Glue: wire landed frames into `merkle_log` + a daily anchor scheduler |
| Auditor CLI (`verify frame → inclusion proof → on-chain root check`) | **NEW (small)** | Thin verifier over existing `InclusionProof.verify()` + `is_anchored()` |

No changes to the flight core beyond the optional capture signature already scoped in the parent doc.

## 6. Worked mini-example

**Scenario:** one 3U EO CubeSat, ~10,000 image captures/day (well within the ~270 MB/day downlink budget from parent doc §7; provenance metadata is bytes, not the imagery).

- **Log growth:** 10,000 leaves/day. Over a 1-year mission ≈ 3.65M leaves in the log.
- **Inclusion proof size:** `path_length ≤ ⌈log₂(tree_size)⌉`. For 10,000 leaves/day, ⌈log₂(10,000)⌉ = **14 hashes** ≈ 14 × 32 B = **448 bytes**. For the full-year 3.65M-leaf tree, ⌈log₂(3.65M)⌉ = **22 hashes** ≈ **704 bytes**. Proving one image is authentic costs well under 1 KB regardless of archive size — the O(log N) win.
- **On-chain footprint:** anchor **one** STH root per day. The signed tree head root is 32 bytes; the on-chain `anchor()` call writes that `bytes32 merkleRoot` plus a few bytes32/uint64 fields. **One transaction covers all 10,000 captures that day.** Per-image on-chain cost is therefore (1 anchor tx) ÷ 10,000 ≈ negligible; on GSX Testnet a single `anchor()` is a bounded `SSTORE`-dominated write (low tens of thousands of gas). Anchor a **daily tree head, never per image** — that is the whole economic argument.
- **`batchAnchor()`** collapses a backlog (e.g. 30 days of missed anchors after an outage) into one transaction of 30 roots.

**Net:** 1 tiny on-chain write/day notarizes 10,000 captures; any one of them is independently provable with a <1 KB proof.

## 7. Use-case-specific risks — what anchoring does and does NOT prove

Be precise here; overclaiming provenance is the fastest way to lose a case.

**What the on-chain anchor DOES prove:**
- The Merkle root (hence the entire set of captures under it) **existed at or before** the anchoring block's timestamp. This is an *upper bound* on capture time — a "not later than" witness.
- The log has **not been rewritten** since anchoring: any edit changes the root and breaks the anchored digest / the STH's ML-DSA signature. Equivocation (two roots, same sequence) is detectable and self-proving.
- Combined with the ML-DSA-65 capture signature: the frame was signed by the holder of a specific key and has not been altered since signing.

**What it does NOT prove:**
- **Not a lower bound on time.** The anchor says "no later than block T." It does **not** prove the image was captured *at* the claimed instant — only that it was committed by then. Backdating *before* first anchor is not cryptographically excluded; the mitigation is *frequent* anchoring + a trusted time source, not the chain.
- **Nothing about physical truth.** The chain cannot attest that pixels correspond to reality, that the sensor pointed where the metadata claims, or that the frame is not a synthetic/spoofed input fed to a compromised signer. Provenance ≠ ground truth.
- **Nothing beyond the signing key's integrity** (below).

**Sign-on-orbit key compromise.** If a capture-signing key on the bird is extracted (side-channel, supply chain, SEU-corrupted key store), an attacker can mint authentic-looking captures. Mitigations: prefer **sign-on-ground** in a mission-control HSM (`hsm.py`) where power/tamper budgets allow; if signing on-orbit, use short-lived per-epoch keys with on-chain `registerSigner`/`revokeSigner` so a compromise is bounded and revocable; keep the flight key store small and re-verifiable (parent doc §8, SEU discipline).

**Time-source trust.** The provenance timestamp is only as good as the clock. A CubeSat's RTC drifts and can be spoofed via GPS. The chain timestamp is an *independent, adversary-resistant* upper bound; treat GPS/RTC time as a *claim* inside the signed record and the anchor time as the *witnessed* bound. Discrepancy between the two is itself an audit signal.

**Note on hashing lanes.** `SignedTreeHead.root_hash` is a 32-byte BLAKE2b-256 Merkle root (internal tree hashing); the *canonical capture record* digest and all on-chain/canonical paths use **SHA3-256** per project convention. Do not mix lanes — the auditor verifies the SHA3-256 capture digest and the on-chain anchored root as distinct, well-defined artifacts.

## 8. Minimal demo / MVP buildable in this repo today

This MVP is **nearly buildable now** — it is mostly wiring existing modules.

1. **Synthetic capture set.** Generate ~1,000 fake "captures" (`sensor_id`, ISO time, pose, random 32-byte frame digest). Sign each digest with ML-DSA-65 (`primitives.MLDSA`, existing `alice` keypair from `tests/conftest.py`).
2. **Build the log.** Append all 1,000 records as leaves via `merkle_log/log.py`. Emit a `SignedTreeHead` over the final root with the operator key.
3. **Anchor locally.** Point `AnchorClient` at the **`local` backend** (`src/ltp/backends/`) — no live chain needed — and call `anchor()` with the STH root as `merkleRoot`. Confirm `is_anchored(root)` returns `True`.
4. **Prove one capture.** Pick capture #837, get its `InclusionProof`, assert `proof.verify(record_bytes, sth.root_hash)` and that `proof.path_length == ⌈log₂(1000)⌉ = 10`.
5. **Tamper test (the money shot).** Flip one byte of capture #837, re-verify: inclusion proof fails **and** the ML-DSA capture signature fails. Rewrite a historical leaf and re-emit the STH: the new root no longer matches the anchored digest → `is_anchored(old_root)` still `True`, new root not anchored → the rewrite is detected.
6. **(Stretch) Real chain.** Swap the `local` backend for the GSX Testnet `AnchorClient.from_env(prefix="GSX_")` against the deployed proxy (`0xB29d8BFF…`) to anchor one root for real and read it back with `cast call`.

Steps 1–5 use only existing modules plus the small capture-record dataclass from §5 — a genuine end-to-end provenance demo (capture → sign → log → anchor → prove → detect tamper) with no flight hardware and no live chain.

---

*A leaf under `CUBESAT_SCOPE.md`. Shared transport/erasure/DTN architecture lives in the parent; this brief scopes only provenance anchoring, where ETP's existing Merkle-log + on-chain anchor stack is the differentiator rather than a decoupled extra.*

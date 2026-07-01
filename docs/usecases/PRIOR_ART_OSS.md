# Open-Source Prior Art — What Already Exists, and What ETP Should Build On

Companion to [`COMPETITIVE_ANALYSIS.md`](COMPETITIVE_ANALYSIS.md) and
[`STARTUP_FUNDING_STRESS_TEST.md`](STARTUP_FUNDING_STRESS_TEST.md). Those covered
*commercial* competition. This one covers **open-source code**: for each of ETP's
four pillars, what mature repos exist, whether the fusion is already built, and —
crucially — which projects ETP should **adopt instead of reinventing**.

Method: four live web/GitHub search passes (transparency logs, PQC sealing,
DTN+erasure, and the full fusion). All repos below were fetched and verified;
star counts are approximate (mid-2026). The GitHub API was not used (repo scope);
this is public-web discovery.

> **Two-sided verdict:**
> 1. **The integrated 4-pillar fusion is genuinely absent from OSS** — no single
>    project combines 3+ of {PQC, erasure, DTN, RFC-6962 provenance}. The moat is
>    the *integration*, not any pillar.
> 2. **But every individual pillar is commodity OSS, and one near-twin exists for
>    the provenance wedge specifically** (`paramant-relay`). So novelty claims must
>    be scoped to the *composition + formal discipline*, never to the parts.

---

## The pillar-by-pillar picture

| Pillar | Is it commodity in OSS? | Best build-on | Verdict for ETP |
|---|---|---|---|
| **PQC seal** (ML-KEM/ML-DSA) | ✅ Fully. `age` ships the exact constant-overhead hybrid sealed box (22.7k★); liboqs/AWS-LC own FIPS primitives | liboqs, aws-lc (FIPS 140-3) | **Adopt. Claim zero novelty here.** |
| **Erasure coding** | ✅ Fully. Many fast libs | `cberner/raptorq` (Rust, Apache-2.0, Python bindings, rateless) | **Adopt raptorq for the native hot-path.** |
| **DTN store-and-forward** | ✅ Mature, but classical-crypto only | `dtn7-rs` + `bp7-rs` (Rust, permissive, BPv7) | **Adopt for the convergence layer.** |
| **RFC-6962 provenance** | ✅ Fully. Trillian/Tessera/Rekor | `transparency-dev/tessera` + `/merkle`, `sigstore/rekor`, `in-toto` | **Adopt; retire bespoke `merkle_log` for prod.** |
| **The 4-pillar fusion** | ❌ **Absent** | — nothing to build on | **This is the whole moat.** |

---

## ⚠ The two prior-art hits that must be cited

The earlier funding research implied the provenance wedge was empty. At the *code*
level that is too strong — two things exist and must be named in any positioning:

### 1. `Apolloccrypt/paramant-relay` — the provenance-wedge near-twin
- **URL:** github.com/Apolloccrypt/paramant-relay · ~26★ · BUSL-1.1 · v3.0.0 (Jun 2026)
- **What it does:** PQ-encrypted file relay fusing **ML-KEM-768 + ML-DSA-65 + a
  SHA3-256 Merkle transparency log** with signed tree heads, delivery receipts, and
  `/sth/consistency` verification. **This is ETP's provenance wedge — same algorithms,
  same hash, same "notarize each transfer into a signed Merkle log" thesis.**
- **How much it matters:** it reaches ~3 of 4 pillars (PQC + provenance + a transfer
  relay), but **not** erasure coding and **not** true DTN store-and-forward. It is
  tiny, source-available (BUSL, not a permissive OSS license), and low-traction — so
  treat it as **concept prior art, not a mature competitor**. But it disproves any
  "nobody has combined PQC with a tamper-evident transfer log" claim. Cite it.

### 2. `arxiv 2504.07938` — "Quantum-Resistant File Transfer with Blockchain Audit"
- The best *academic* match: fuses **PQC (Kyber+Dilithium) + provenance (audit trail)**
  in a file-transfer design. But it stops at **2 of 4** (no erasure, no DTN) and
  **ships no code.** A paper, not a repo. Cite for completeness.

Everything else tops out at 1–2 pillars: Tahoe-LAFS / Storj / Sia (erasure + classical
crypto, no PQC/DTN/RFC-6962 log); DTN7 / NASA ION (real DTN, classical BPSec, no PQC/
provenance); liboqs and ct-merkle (the single-pillar building blocks ETP composes).

---

## Build-on shortlist (adopt these; stop reinventing)

The single highest-leverage conclusion of this search: **ETP is currently
hand-rolling things that mature, permissively-licensed OSS already does better.**

| Need | Adopt | License | Why |
|---|---|---|---|
| PQC primitives | **liboqs** / **aws-lc** | MIT / Apache-2.0 (FIPS 140-3) | The commodity floor; matches ETP's ML-KEM-768/ML-DSA-65 exactly |
| Constant-overhead sealed box | **age** (design/format) | BSD-3 | Reference for hybrid-KEM stanza; don't invent a new envelope |
| Native erasure hot-path | **cberner/raptorq** | Apache-2.0 | Rust + Python bindings + rateless (fits DTN); fixes the pure-Python RS |
| Fixed-rate RS fallback/bench | **klauspost/reedsolomon** | MIT | >1 GB/s/core, most battle-tested |
| DTN convergence layer | **dtn7-rs** + **bp7-rs** | Apache-2.0/MIT | Modern BPv7 (RFC 9171), permissive, memory-safe |
| Transparency log (prod) | **transparency-dev/tessera** + **/merkle** | Apache-2.0 | Production tile-based tlog; retire bespoke `merkle_log` |
| Notarization endpoint | **sigstore/rekor** | Apache-2.0 | Mature verifiable-log service + ecosystem mindshare |
| Provenance statement format | **in-toto/attestation** | Apache-2.0 | Reuse the predicate schema, don't invent one |

**License landmines to avoid:** `zfec` (GPL-2.0+), `µD3TN` (AGPL-3.0), `hpqc` (AGPL-3.0),
`immudb` (BSL), `paramant-relay` (BUSL) — copyleft/source-available terms that are
poison for a permissively-licensed or commercial ETP. Prefer the MIT/Apache options above.

**Caveat on the MVP just built:** the `src/ltp/provenance.py` MVP is the right
*demonstration* (it proves the workflow end-to-end on ETP's own modules), but a
production build should sit on Tessera/Rekor + liboqs + raptorq rather than the
bespoke `merkle_log` + hand-rolled seal. The MVP is the pitch; these libraries are
the foundation.

---

## What this does to the defensibility thesis

**Refined, not overturned.** The competitive/funding research said "no vendor ships
the combo." The code search sharpens it:

- **True:** the *integrated* PQC + erasure + DTN + RFC-6962 fusion is absent from OSS
  and from shipped products. Anyone replicating ETP must design the inter-lane glue
  themselves — they cannot fork it.
- **But:** every pillar is off-the-shelf, and `paramant-relay` already built the
  PQC+provenance subset. So the moat is **engineering integration + formal discipline
  + a real buyer relationship**, *not* cryptographic novelty. It is **not
  patent-strong** against a determined integrator — all the parts are commodity.

**Implication for strategy (consistent with the funding stress-test):**
- Do **not** market ETP as "post-quantum" or "we built a Merkle log" — both are
  commodity, and `age`/`liboqs`/`Trillian`/`paramant-relay` are the counter-evidence.
- **Do** market the *fused system for a specific hard environment* (disconnected/
  adversarial delay-tolerant chain-of-custody) and the *formal + compliance* wrapper
  (lane discipline, verified state machine, auditable provenance for a regulated or
  defense buyer). That composition is what has no precedent.
- Accelerate to a **design-partner/contract** moat quickly — since the technical moat
  is integration effort (months, not patents), the durable advantage is the customer
  relationship and accreditation, exactly as the funding graveyard predicted.

---

## Sources (repos verified live, mid-2026)

PQC: open-quantum-safe/liboqs · aws/aws-lc · FiloSottile/age · rustpq/pqcrypto ·
katzenpost/hpqc. Erasure: cberner/raptorq · klauspost/reedsolomon · catid/leopard ·
catid/wirehair · tahoe-lafs/zfec. DTN: nasa-jpl/ION-DTN · nasa/HDTN · dtn7/dtn7-rs ·
dtn7/bp7-rs · d3tn/µD3TN. Provenance: google/trillian · transparency-dev/tessera ·
transparency-dev/merkle · sigstore/rekor · in-toto/attestation · codenotary/immudb ·
contentauth/c2pa-rs. Fusion near-misses: **Apolloccrypt/paramant-relay** ·
arxiv 2504.07938 · Tahoe-LAFS · Storj · Sia · rozbb/ct-merkle.

*Star counts and activity are point-in-time (mid-2026) and approximate; the OSS PQC/
transparency ecosystem is moving PQ-ward fast — re-check before relying on any "nobody
has X" claim.*

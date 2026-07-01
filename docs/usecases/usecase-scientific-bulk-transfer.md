# ETP Use Case — Scientific / HPC Big-Data Bulk Transfer

**Author:** Javier Calderon Jr, CTO of Global Settlement (GSX)
**Date:** July 1, 2026
**Status:** Scoping / design — no line-rate code yet
**Domain:** Terrestrial high-performance research networking (NOT satellites, NOT blockchain)

---

## 1. One-line pitch

**Forward-erasure-coded, post-quantum-confidential bulk transfer that keeps throughput
up on long-fat, lossy WANs where TCP-based tools collapse — moving terabytes-to-petabytes
between HPC centers, sequencing cores, telescopes, and light sources.**

---

## 2. Domain & who buys it

The problem is the classic "big data over the WAN" pain that GridFTP, Aspera-FASP, FDT,
and Globus were built for: research datasets have outgrown the links, and standard TCP
throughput collapses on high-latency paths the moment loss appears. ETP's differentiator
is *forward* correction (no ARQ round-trip penalty) plus real post-quantum confidentiality
for sensitive datasets, with end-to-end integrity via a tamper-evident Merkle log.

**Buyers / users:**
- **National labs & HPC centers** — DOE labs (ORNL, LBNL, ANL), NERSC, LHC Tier-0/1/2 sites.
- **Research & Education networks** — ESnet, Internet2, GÉANT, JISC (they operate the "long fat pipes").
- **Genomics / sequencing cores** — Broad, Sanger, regional sequencing centers moving multi-TB runs.
- **Big-instrument facilities** — telescopes (SKA, Vera Rubin/LSST), synchrotron light sources, cryo-EM.
- **Pharma & biotech** — moving embargoed / regulated datasets between sites and CROs.

Cross-reference `CUBESAT_SCOPE.md` for the shared transport+crypto architecture; this
document reuses the same core pillars in a terrestrial, line-rate context.

---

## 3. Operating profile

| Parameter | Representative value | Implication |
|---|---|---|
| Link rate (R&E backbone) | **100–400 Gbps** transatlantic/transcontinental | The pipe is huge; the app must fill it |
| RTT (intercontinental) | **60–160 ms** (e.g. US↔EU ~90–100 ms) | High latency dominates ARQ recovery cost |
| Bandwidth-delay product | **100 Gbps × 100 ms ≈ 1.25 GB** in flight | Window/buffer must be gigabytes; one loss stalls a lot |
| Packet loss | **1e-4 to 1e-2** on congested / imperfect paths | The killer for TCP; the whole reason this exists |
| Dataset sizes | GB per file, **TB–PB per transfer campaign** | LHC produces ~tens of PB/yr; a genome run is multi-TB |
| Transfer duration | minutes (TB) to days (PB) | Long-lived flows; sustained line rate matters |
| Confidentiality need | Variable — genomic (HIPAA/GDPR), embargoed, defense-adjacent | PQC matters for a *subset*, not all traffic |

**The three hard constraints, ranked:**
1. **High BDP + loss** — TCP congestion control interprets loss as congestion and backs off; on a
   100 Gbps × 100 ms path a single loss event drains a 1.25 GB window and recovery is RTT-bound.
2. **Line-rate crypto/coding** — anything in the data path must run at tens of GB/s, not MB/s.
3. **Provenance & integrity** — datasets are scientific records; silent corruption is unacceptable.

---

## 4. Why ETP fits — pillars ranked

**#1 — Erasure coding (the star pillar).** `src/ltp/erasure.py` provides true any-*k*-of-*n*
Reed–Solomon reconstruction over GF(256). On a high-BDP lossy link this is decisive: instead of
detecting loss and waiting an RTT to retransmit (TCP/ARQ), the sender sprays *n = k(1+ρ)* shards
and the receiver reconstructs from any *k* that arrive. Recovery cost is **forward overhead ρ**,
not **round-trips**. On a 100 ms path that is the difference between filling the pipe and stalling.
Per-shard AEAD (`src/ltp/shards.py`, XChaCha20-Poly1305) means shards are independently
encrypted and self-authenticating — ideal for spray-and-reconstruct.

**#2 — Post-quantum confidentiality.** `src/ltp/bridge/` seals a per-transfer symmetric key with
ML-KEM-768 into a **constant-size (~1.3 KB) artifact**, independent of payload size — one KEM op
amortized across a multi-TB transfer is free. ML-DSA-65 signs manifests for authenticity. This
directly answers *harvest-now-decrypt-later*: genomic and embargoed data recorded on the wire today
must stay confidential for decades. Real FIPS 203/204 primitives, no simulation.

**#3 — Integrity / provenance.** `src/ltp/merkle_log/` (RFC 6962-style tamper-evident log) gives an
append-only, auditable record of what was transferred, with inclusion/consistency proofs. This is the
provenance receipt for a scientific dataset — no chain required. `src/ltp/commitment.py` handles the
*k*-of-*n* reconstruction/commitment logic.

---

## 5. ETP module impact

| Module | Action | Notes |
|---|---|---|
| `src/ltp/erasure.py` | **NEW native hot path (mandatory)** | Pure-Python GF(256) is O(n·k·chunk) — a non-starter at 100 Gbps. Bind zfec / ISA-L / a Rust GF(256) SIMD kernel behind the existing `encode`/`decode` API; keep Python as reference/fallback. This is the critical-path work item. |
| `src/ltp/shards.py` | **Reuse** | Per-shard XChaCha20-Poly1305 already independent; AEAD is already hardware-accelerated. |
| `src/ltp/bridge/` (ML-KEM seal) | **Reuse** | Constant-size sealed key is the per-transfer key-establishment path; ~1.3 KB amortized over TB is negligible. |
| `src/ltp/commitment.py` | **Reuse** | k-of-n reconstruction logic. |
| `src/ltp/streaming.py` | **Reprofile** | 64 KB chunks / 4-way pipeline → large chunks + deep pipelining sized to the BDP (GB-scale in flight); parallel streams to fill a 100 Gbps pipe. |
| `src/ltp/merkle_log/` | **Reuse** | Provenance / integrity ledger for delivered datasets. |
| `src/ltp/protocol.py` | **Rework timeouts** | Second-scale timeouts → long-lived multi-hour/day transfer semantics; resumability. |
| `network/*` (gRPC) | **Reprofile / bypass** | gRPC/HTTP-2 is fine for control plane; the bulk data path needs UDP-based framing (QUIC-like or raw) to avoid TCP's loss-collapse. |
| `anchor/`, contracts | **Decouple** | On-chain settlement is out of scope; Merkle log covers provenance. |

---

## 6. Worked mini-example — TCP-on-loss vs erasure-coded

**Path:** 100 Gbps, RTT = 100 ms, packet loss p = 0.1% (1e-3), MSS = 1500 B.

**TCP ceiling via the Mathis equation** — throughput ≈ MSS / (RTT · √p):

```
BW ≈ 1500 B / (0.1 s · √0.001)
   = 1500 B / (0.1 · 0.0316)
   = 1500 B / 0.00316 s
   ≈ 474,000 B/s ≈ 3.8 Mbps  (single TCP flow)
```

A single standard-TCP flow tops out around **~3.8 Mbps** — roughly **0.004%** of the 100 Gbps pipe.
That is why incumbents spray *dozens to hundreds* of parallel streams. With loss at 1e-3, even 256
parallel flows reach only ~1 Gbps of the 100 Gbps available.

**Erasure-coded ETP:** at 0.1% loss the receiver needs enough forward overhead to cover losses in a
*k*-shard reconstruction group. Provisioning **ρ ≈ 1–2%** (well above the 0.1% loss) lets the receiver
reconstruct from the first *k* arrivals **without any retransmission round-trip** — throughput is bounded
by the link and by encode/decode speed, **not by RTT·√p**. The link is filled; the cost is ~1–2% extra
bytes and CPU, not a collapse to single-digit Mbps.

**Caveat:** this only holds if erasure encode/decode runs at line rate — hence the mandatory native hot
path. Pure-Python GF(256) would itself become the bottleneck long before 100 Gbps.

---

## 7. Risks / where it's a poor fit — honest assessment

- **Crowded incumbent market.** Globus (the de-facto standard in science), Aspera-FASP (UDP-based, commercial,
  entrenched), GridFTP, and FDT already solve high-BDP transfer well. Aspera in particular *already* does
  UDP-based rate control that dodges TCP's loss-collapse — ETP's throughput story is not novel by itself.
  The wedge must be **PQC + forward erasure + provenance as an integrated package**, not raw speed.
- **Pure-Python erasure is a non-starter at line rate.** `erasure.py` at O(n·k·chunk) does ~800K GF-mults
  for a 100 KB payload; at 100 Gbps this is off by orders of magnitude. Without a native hot path there is no product.
- **Is PQC a real buying criterion?** For the bulk of open science data (LHC, most astronomy), it is
  **nice-to-have, not a buying trigger** — that data is often public. PQC becomes a genuine differentiator only for
  the **sensitive subset**: genomic/PHI, embargoed pre-publication, defense-adjacent, and pharma IP. Sell there first.
- **FEC overhead vs. congestion.** Forward erasure adds ρ bytes *always*; on a *congested* (not just lossy)
  link, spraying extra shards can worsen congestion. Needs loss-vs-congestion discrimination and adaptive ρ.
- **Operational integration.** Science transfer lives inside Globus endpoints, data-transfer nodes (DTNs),
  and Science DMZ / perfSONAR ecosystems. A tool that doesn't speak that world faces high adoption friction.
- **Encryption at rest vs. in flight.** Many facilities already encrypt at rest; ETP must show clear
  marginal value for *in-flight* confidentiality against a quantum-capable future adversary.

---

## 8. Minimal in-repo MVP

**Goal:** demonstrate that erasure-coded transfer sustains throughput under emulated loss where TCP collapses.

1. **Emulate a long-fat lossy link** with `tc netem` on a loopback / veth pair:
   ```bash
   sudo tc qdisc add dev veth0 root netem delay 50ms 5ms loss 0.1% rate 1gbit
   ```
   (50 ms one-way ≈ 100 ms RTT; 0.1% loss; 1 Gbps to keep the demo runnable.)
2. **Baseline:** run an `iperf3` single TCP stream across the emulated link — record the collapsed throughput
   (Mathis predicts single-digit-to-low-tens Mbps).
3. **ETP path:** erasure-encode a multi-GB test dataset with `src/ltp/erasure.py` (n=12, k=8, ρ=0.5), spray shards
   over UDP, reconstruct from the first *k* arrivals, verify against the Merkle log — record sustained throughput.
4. **Confidentiality:** seal the transfer key with the `bridge/` ML-KEM-768 path; confirm the ~1.3 KB sealed-key
   overhead is constant regardless of dataset size.
5. **Report:** plot throughput vs. loss (0.01% → 1%) for TCP vs. ETP; show TCP's √p collapse vs. ETP's flat curve.
6. **Flag the gap:** benchmark pure-Python `erasure.py` encode/decode MB/s and show it caps below line rate —
   quantifying exactly why the native hot path is required before any production claim.

**Non-goals for the MVP:** no on-chain anchoring, no Globus interop, no 100 Gbps hardware — just the
falsifiable core claim (forward erasure beats TCP-under-loss) plus the PQC-overhead-is-constant claim.

---

*This is a scoping document. The cryptographic and coding core is reused from the existing ETP
implementation; the one mandatory new build is the native erasure hot path. On-chain settlement is
explicitly out of scope — provenance is served by the Merkle log (`src/ltp/merkle_log/`, RFC 6962).*

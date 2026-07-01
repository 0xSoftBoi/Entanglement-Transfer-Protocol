# ETP Beyond Space — Terrestrial Use-Case Briefs

The same ETP core — **post-quantum secure, erasure-coded, delay-tolerant data
transfer** — is domain-agnostic middleware. These briefs apply it to markets that
are **neither satellites nor blockchain**. The CubeSat work lives in
[`../cubesat/`](../cubesat/); the shared architecture (constant-size ~1.3 KB PQC
sealed key, *k*-of-*n* forward erasure coding, store-and-forward, ground/edge
compute split) is defined once in [`../../CUBESAT_SCOPE.md`](../../CUBESAT_SCOPE.md)
and referenced, not repeated.

**Framing note:** the post-quantum *cryptography* is the product and stays.
The *blockchain/settlement* stack does not appear here — where provenance
matters, these briefs use the **RFC-6962 Merkle transparency log**
(`src/ltp/merkle_log/`, the same design as Certificate Transparency), not an
on-chain anchor.

## The five domains

| # | Brief | One-liner | Lead ETP pillar |
|---|---|---|---|
| 1 | [Tactical / defense DIL](usecase-tactical-dil.md) | Secure delay-tolerant transport for battlefield mesh, UAV swarms, subsea | **DTN + erasure over jammed RF** |
| 2 | [Critical infrastructure / OT](usecase-critical-infrastructure.md) | PQC + authenticated command + tamper-evident audit for SCADA | **PQC confidentiality + command auth** |
| 3 | [Healthcare & genomics](usecase-healthcare-genomics.md) | Lifetime-confidential transfer + auditable medical provenance | **PQC + Merkle transparency log** |
| 4 | [Disaster response / humanitarian](usecase-disaster-response.md) | Off-grid DTN + data mules when infrastructure is gone | **Store-and-forward + PQC** |
| 5 | [Scientific / HPC bulk transfer](usecase-scientific-bulk-transfer.md) | PB-scale movement over lossy long-fat WANs, beating TCP | **Erasure coding** |

## Pillar map across domains

| ETP capability | Tactical | Infra/OT | Health | Disaster | Science |
|---|:--:|:--:|:--:|:--:|:--:|
| Constant-size PQC seal (ML-KEM-768) | ● | ● | ● | ● | ● |
| *k*-of-*n* erasure coding | ● | · | ◐ | ● | ● |
| Store-and-forward / delay-tolerance | ● | ◐ | · | ● | · |
| ML-DSA signatures + verify | ◐ | ● | ● | ◐ | ◐ |
| Replay/temporal binding (`sequencing.py`) | ◐ | ● | ◐ | ◐ | · |
| Merkle transparency log (RFC 6962) | ◐ | ● | ● | ◐ | ● |

● lead · ◐ supporting · · not central

**What the portfolio view says:** the **PQC seal is universal** — every terrestrial
domain values post-quantum confidentiality against harvest-now-decrypt-later,
because every one of them handles data that must stay secret for decades. After
that, the domains split into two camps:

- **Delay-tolerant transport** camp (tactical, disaster) — leans on store-and-forward + erasure.
- **Confidentiality + provenance** camp (infra/OT, healthcare) — leans on PQC + the transparency log, with `sequencing.py` for command authenticity.
- **Throughput** camp (science) — a pure erasure-coding play; the one domain where the native hot path is non-negotiable.

## Honest fit ranking

Ranked by alignment with ETP's *existing* strengths, buyer willingness to pay for
PQC, and how cheaply a proof can be built:

1. **Healthcare & genomics** — the harvest-now-decrypt-later threat is *real and
   present* (genomic data is sensitive for a lifetime), the buyer is regulated and
   funded, and the provenance MVP is nearly buildable today on `merkle_log/`.
2. **Critical infrastructure / OT** — 20–30 yr asset lives make PQC-now a rational
   purchase; strong integrity/audit story. Retrofit friction and sub-10 ms control
   latency are the headwinds.
3. **Tactical / defense DIL** — excellent technical fit and a buyer that pays for
   assurance, but a long accreditation road (CNSA 2.0 / FIPS 140-3 / ATO) and
   entrenched GOTS incumbents.
4. **Scientific / HPC bulk transfer** — the cleanest erasure story (beats TCP under
   loss) and a concrete benchmark MVP, but a crowded incumbent market
   (Globus/Aspera/GridFTP) and PQC is only a *trigger* for the sensitive-data subset.
5. **Disaster / humanitarian** — genuine need and a compelling story, but thin,
   grant-dependent budgets and PQC is overkill for most short-lived field data
   (justified only for the biometric/refugee-identity subset).

## Where this sits relative to the satellite play

- **Common substrate:** all of this — space and terrestrial — rides the same
  `SpaceLinkProfile` + convergence-shim pattern from the parent roadmap. A
  terrestrial link is just a profile with different numbers (higher bandwidth,
  shorter or no disconnection). Build the substrate once.
- **Two universal, cross-cutting capabilities emerge** across *both* the CubeSat
  and terrestrial sets: the **PQC seal** and **store-and-forward**. Those are the
  first things to harden.
- **The transparency log is the sleeper.** It leads or supports in healthcare,
  infra, science, and provenance — a reusable, standards-based (RFC 6962),
  no-blockchain-required differentiator that travels across nearly every domain.

---

*Scoping documents, not implementations — markets, fit, and buildable proofs. The
crypto/coding core is reused across every domain; only the link profile and the
convergence shim change.*

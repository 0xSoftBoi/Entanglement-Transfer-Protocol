# ETP for CubeSats — Use-Case Briefs

Per-use-case scoping for the satellite play. Start with the parent document,
[`../../CUBESAT_SCOPE.md`](../../CUBESAT_SCOPE.md), which defines the shared
architecture (constant-size ~1.3 KB PQC sealed key, *k*-of-*n* forward erasure
coding, DTN/CCSDS store-and-forward convergence layer replacing gRPC, and the
ground/flight compute split). Each brief below applies that architecture to one
concrete market and does **not** repeat it.

## The five use cases

| # | Brief | One-liner | Lead ETP pillar |
|---|---|---|---|
| 1 | [Earth-observation downlink](usecase-earth-observation.md) | PQC-protected bulk imagery downlink, erasure-coded across passes | **Erasure coding** |
| 2 | [Secure TT&C](usecase-secure-ttc.md) | Anti-spoof command uplink authentication over UHF | **ML-DSA verify + replay protection** |
| 3 | [Inter-satellite mesh relay](usecase-isl-mesh.md) | Delay-tolerant cross-link routing to the first available ground contact | **DTN store-and-forward + seal-and-forward via untrusted relays** |
| 4 | [IoT / M2M backhaul](usecase-iot-backhaul.md) | Coin-cell ground sensors → passing CubeSat → ground | **Constant-size seal + delay-tolerance** (amortized) |
| 5 | [Provenance / anchoring](usecase-provenance-anchoring.md) | Tamper-evident, on-chain chain-of-custody for captured data | **Merkle log + on-chain anchor** |

## How the pillars map across use cases

Each ETP capability is the *star* in some use cases and a *supporting act* in
others. This is the portfolio view — it shows which capabilities to build first
because they carry the most weight across the set.

| ETP capability | EO | TT&C | ISL mesh | IoT | Provenance |
|---|:--:|:--:|:--:|:--:|:--:|
| Constant-size PQC seal (ML-KEM-768) | ● | ○ | ● | ◐ | ○ |
| *k*-of-*n* erasure coding | ● | · | ◐ | · | ◐ |
| DTN store-and-forward | ● | ◐ | ● | ● | ○ |
| ML-DSA signatures + verify | ◐ | ● | ◐ | ◐ | ● |
| Replay/temporal binding (`sequencing.py`) | · | ● | ◐ | ◐ | ● |
| Merkle log + on-chain anchor | ○ | · | · | ◐ | ● |

● lead · ◐ supporting · ○ optional/ground-side · · not central

**What the portfolio view tells us:**

- **DTN store-and-forward and the PQC seal are the two load-bearing capabilities** — they lead or support in nearly every column. That is where Phase 1/2 of the parent roadmap should concentrate.
- **Erasure coding is make-or-break for EO** (the biggest data-volume market) and helpful for mesh — which is what justifies the native hot-path port (parent roadmap Phase 3).
- **The chain stack earns its keep in exactly one column** — provenance/anchoring — but there it is a genuine, hard-to-copy differentiator, and it runs entirely on the ground, off the flight critical path.

## Honest fit ranking

Not every use case is an equally good fit. Ranked by how well ETP's *existing*
strengths line up against the market, and how buildable a proof is today:

1. **Provenance / anchoring** — best fit to what already exists. The Merkle-log
   + anchor stack is built and tested; the MVP is nearly buildable today with no
   new cryptography. Clearest differentiator.
2. **Secure TT&C** — small, high-assurance, high-value. The trust core
   (ML-DSA verify + `sequencing.py`) exists; MVP is pure-Python with zero new
   crypto. Defense/gov buyer.
3. **EO downlink** — biggest data-volume market and the erasure pillar's natural
   home, but needs the native erasure hot path to be real at scale.
4. **ISL mesh relay** — highest technical upside (>100× latency wins) and the
   `Relayer` pattern maps beautifully, but depends on constellation/contact-graph
   maturity and cross-operator trust.
5. **IoT backhaul** — real market, but ETP is a *partial* fit: per-message
   sealing is the wrong tool; the value is DTN delay-tolerance + amortized
   session keys + provenance, not the per-message crypto.

## Suggested sequencing

- **Prove the crypto/coding core on the ground first** with the two
  zero-new-crypto MVPs (provenance anchoring, secure TT&C). These validate the
  trust story without any radio or DTN daemon.
- **Then build the shared transport substrate** (`SpaceLinkProfile` +
  `ltp.network.spacelink`, parent roadmap Phase 1) that EO, ISL, and IoT all sit on.
- **Defer the native erasure hot path** until EO is the committed go-to-market
  (parent roadmap Phase 3) — it is the one heavy engineering item and only EO
  strictly needs it.

---

*These briefs are scoping documents, not implementations. They define markets,
fit, and buildable proofs — the flight implementation is a later phase with its
own qualification, per the parent roadmap.*

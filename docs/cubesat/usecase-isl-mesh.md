# ETP Use Case — Inter-Satellite Link (ISL) Mesh Relay / Delay-Tolerant Routing

**Author:** Javier Calderon Jr, CTO of Global Settlement (GSX)
**Date:** July 1, 2026
**Status:** Use-case scoping — one of N CubeSat use cases under [`CUBESAT_SCOPE.md`](../../CUBESAT_SCOPE.md)

> Shared architecture (constant-size ~1.3 KB PQC sealed key, k-of-n forward erasure coding, DTN/BPv7 + CCSDS convergence layer replacing gRPC, ground/flight compute split) is defined once in [`CUBESAT_SCOPE.md`](../../CUBESAT_SCOPE.md). This brief only covers the ISL-mesh-relay delta and does not repeat it.

---

## 1. One-Line Pitch

Route each satellite's data over inter-satellite cross-links to whichever bird has a ground contact *now* — a post-quantum, erasure-coded DTN store-and-forward mesh where every relay hop is an *untrusted* carrier that only ever touches a sealed key, never the plaintext.

---

## 2. Mission Profile & Who Buys It

**Profile.** A LEO constellation (tens to hundreds of 3U–12U birds) in one or more orbital planes with active ISL cross-links. A satellite that just collected data (imagery, RF survey, AIS/ADS-B, science) does **not** wait ~45–90 min for its own ground pass; it hands the data laterally across the mesh toward a bird that is over a ground station within seconds-to-minutes, cutting time-to-ground from an orbit to a fraction of one.

**Who buys it:**
- **Earth-observation / tasking operators** (Planet-, Spire-, Satellogic-class) where *latency-to-ground* is the product — a wildfire or ship-detection alert is worth far more at T+3 min than T+70 min.
- **Government / defense & responsive-space** constellations needing assured, PQC-protected exfil that survives loss of any single node or ground site.
- **Constellation-as-a-service / hosted-payload** providers who must relay a *tenant's* data across birds owned by *other* tenants — exactly the untrusted-relay trust boundary ETP already models.
- **Emerging optical-ISL operators** (SDA Transport Layer-style meshes) wanting a coding + key-management layer above the CCSDS/optical PHY.

---

## 3. Link & Ops Profile (ISL-specific)

Cross-links, not ground links, are the distinguishing surface here. Representative numbers:

| Parameter | Typical value | Implication |
|---|---|---|
| ISL band — RF S-band | ~0.1–10 Mbps | Low-cost omni/patch cross-link; workhorse for small meshes |
| ISL band — RF Ka-band | ~25–1000+ Mbps | Higher gain, narrower beam, pointing/tracking required |
| ISL band — Optical (laser) | **1–10+ Gbps** | SDA Transport Layer / Starlink-class; narrow beam, precise pointing |
| Cross-link range (intra-plane) | ~200–2,000 km | Neighbors in the same plane, near-constant geometry |
| Cross-link range (inter-plane) | ~1,000–5,000 km | Geometry sweeps; links form/break as planes cross |
| Cross-link setup (optical) | seconds to acquire/track | A hop is a *scheduled, time-bounded* contact, not a wire |
| Contact-graph cadence | intra-plane ~persistent; inter-plane windows of **minutes**, recurring per orbit (~90 min) | Routing is over a *time-varying* graph, known in advance from ephemerides |
| One-way ISL light-time | ~1–17 ms per hop (range/c) | Latency is dominated by *waiting for a hop*, not propagation |
| Ground-contact availability | any given bird: 3–6 passes/day; *constellation-wide*: near-continuous | Motivation: reach a bird that has a contact *now* |

**Why store-and-forward + custody here (beyond the shared rationale in `CUBESAT_SCOPE.md`):**
- The path from source bird → ground is a **multi-hop chain across a contact graph that changes as the constellation moves**. No end-to-end path exists at any single instant; it is stitched hop-by-hop over time. This is the textbook DTN case: BPv7 bundles + Contact Graph Routing (CGR), with contacts predicted from TLEs/ephemerides.
- **Custody transfer** matters more than in single-bird downlink: once bird B accepts custody of bird A's bundle, A can delete it and reclaim buffer — critical when each node has MB, not GB, of store. Custody moves the retransmission responsibility hop-by-hop instead of end-to-end.
- Links **break mid-transfer** (inter-plane geometry, pointing loss, occultation). Forward erasure across shards lets a partially-delivered bundle still reconstruct from a *later* hop's shards without an ARQ round-trip over a link that may no longer exist.

---

## 4. Why ETP Fits — Ranked Pillars

1. **Seal-and-forward through untrusted relays — the headline fit.** ETP's `bridge/relayer.py` *already* implements a relay that is "intentionally minimal and untrusted": it carries a `RelayPacket` whose payload is a ~1.3 KB ML-KEM-768 **sealed key** (`bridge/message.py`), sealed to a *specific* recipient's encapsulation key. The relay cannot read the key, cannot redirect it (it is bound to the destination verifier), and cannot substitute payload. Map `Relayer` → an intermediate relay bird, and the destination `L2Materializer` → the ground/final-recipient enclave, and you get **operator-agnostic multi-hop relaying for free**: tenant A's data can transit tenant B's bird with B learning nothing. This is the single strongest reason ISL mesh is the best-matched CubeSat use case for ETP.
2. **DTN store-and-forward semantics.** The commit → seal → materialize lifecycle already decouples "produce" from "deliver" and tolerates delay; it drops cleanly onto BPv7 bundles + CGR over the predicted contact graph (see shared stack in `CUBESAT_SCOPE.md`). Custody transfer maps to per-hop bundle acceptance.
3. **Erasure coding *across hops*, not just across one downlink.** `erasure.py` (RS GF(256), k-of-n) + `shards.py` (independent per-shard XChaCha20-Poly1305) let a bundle be sprayed as n shards that fan out over **different mesh paths**; the ground reconstructs from any k. Path diversity turns "a link broke" into "a few shards took another route," with `commitment.py` handling k-of-n reconstruction. Diversity is a *routing* property here, not just a loss-margin property.
4. **Sequencing / replay protection across a multi-writer mesh.** `sequencing.py` (monotonic per-signer sequence + temporal expiry) is exactly what a mesh needs when the same bundle can arrive via multiple paths and multiple relays: dedupe, order, and reject stale/replayed bundles per originating signer — protection that a naive DTN store-and-forward layer lacks.

---

## 5. ETP Module Impact (this use case)

| Module | Action | ISL-mesh-specific note |
|---|---|---|
| `bridge/relayer.py`, `bridge/message.py` | **Reuse pattern (core)** | `Relayer`/`RelayPacket` become the per-hop relay bird; already untrusted, already carries only the sealed key. Generalize from a single cross-chain hop to an N-hop chain (relay-of-relay). |
| `bridge/materializer.py` (`L2Materializer`) | **Reuse** | The terminal node (ground enclave / destination bird) that decapsulates and materializes. Unchanged trust role. |
| `shards.py` | **Reuse** | Independent per-shard AEAD → shards can traverse *different* mesh paths independently. |
| `erasure.py` | **Reuse design, accelerate** | k-of-n across path-diverse hops; native hot path per `CUBESAT_SCOPE.md`. Consider rateless for unknown per-hop loss. |
| `commitment.py` | **Reuse (reconstruction)** | k-of-n reconstruction at the ground; drop eviction/strike economics. |
| `sequencing.py` | **Reuse + extend** | Add per-hop dedupe over multi-path arrival; keep monotonic-per-signer + expiry as replay defense across the mesh. |
| `hsm.py` | **Reuse** | Custody of the destination decap key stays ground-side; relay birds hold *no* trust material. |
| `network/*` (gRPC/HTTP2) | **Replace** | No live socket across a hop. Swap for the BPv7/CGR + CCSDS convergence layer (`CUBESAT_SCOPE.md`). |
| `protocol.py` timeouts | **Rework** | Second-scale phase timeouts → bundle lifetime + contact-graph schedule. |
| **NEW** `network/spacelink/cgr_router` | **New** | Contact-graph router: ingest predicted contacts (TLE/ephemeris), pick next hop, enforce custody + bundle expiry. Thin adapter over an existing BPv7/CGR lib (ION/HDTN). |
| **NEW** relay-chain adapter | **New** | Compose `Relayer` hops into an N-hop forward path; attach BPv7 routing metadata to `RelayPacket`. |

---

## 6. Worked Mini-Example — Latency Reduction from Meshing

**Scenario.** Bird A collects a detection at time T. A's *own* next ground pass is 68 min away (worst-case, just after its previous pass ended). The constellation has a bird over a ground station roughly every ~4 min somewhere in the plane. Two intra-plane hops (A→B→C) reach bird C, which is over a station now.

- **Single-bird downlink (baseline):** wait for A's own pass ≈ **~68 min** to first byte on the ground.
- **Mesh relay:** 2 ISL hops. Each hop = link-acquire + transmit + propagation. Optical/Ka intra-plane hop of the sealed control bundle (~1.3 KB key + BPv7 header, order a few KB) at ≥25 Mbps is **< 1 ms of transmit** + ~1–7 ms propagation; even with a few seconds of contact-scheduling/acquisition slack per hop, end-to-end is **≈ 10–30 s** to reach C, then C downlinks on its live contact.
- **Result:** time-to-ground drops from **~68 min to well under a minute** — a **>100× latency reduction** for the alert. (Bulk payload can follow the same custody path or wait for A's own high-rate pass; the *decision-critical* sealed bundle arrives first.)

**Per-hop overhead check.** The sealed key is **constant ~1.3 KB regardless of payload size** and each relay adds only BPv7 routing metadata (tens of bytes). A 5-hop path costs ~1.3 KB + 5× small headers — the crypto artifact does **not** multiply per hop, unlike re-encrypting plaintext at each relay. This is the constant-overhead property from `CUBESAT_SCOPE.md`, now paying off *per hop* instead of per pass.

---

## 7. Use-Case-Specific Risks

- **Contact-graph complexity.** CGR depends on accurate predicted contacts from ephemerides; stale TLEs or maneuvers desync the graph and mis-route bundles. Mitigation: refresh contact plan from ground; fall back to epidemic/spray-and-wait routing when the graph is stale.
- **Buffer & custody exhaustion.** MB-class stores + custody-transfer semantics mean a stuck downstream node can back-pressure the mesh. Mitigation: bundle expiry (drop stale), custody timeouts, per-tenant quotas.
- **Trust between operators (the crux).** Relaying tenant A's data through tenant B's bird demands B learns nothing and cannot tamper. ETP's sealed-key-only relay covers *confidentiality/integrity of the key path*, but **traffic-analysis metadata** (who relays for whom, bundle sizes/timing) still leaks; and a malicious relay can *drop* bundles (availability, not confidentiality). Mitigations: path-diverse erasure (drop-tolerant), padded/constant-size control bundles, custody accounting to detect black-holing.
- **Per-hop latency vs. shard fan-out tension.** Spraying k-of-n shards over diverse paths buys robustness but can *raise* worst-case latency (must wait for k across the slowest chosen paths). Tune n/k and path selection per mission — favor low-latency single-path for alerts, fan-out for assured bulk.
- **Optical ISL pointing/acquisition** adds seconds per hop and is weather-independent but geometry-sensitive; a mis-modeled acquisition time inflates the worked-example slack.

---

## 8. Minimal Demo / MVP in This Repo

**Goal:** prove multi-hop seal-and-forward with disruption, using only existing modules + a thin sim — no radio, no DTN daemon.

**3-node relay-chain simulation (`Source → Relay → Ground`), extended to N hops:**
1. **Source bird:** use the existing `bridge` flow to `commit` a payload and produce a `RelayPacket` (~1.3 KB sealed key) sealed to the *ground* verifier's ML-KEM key (not the relay's) — proving the relay never gets read access.
2. **Relay bird(s):** instantiate one or more `Relayer`-style hops that accept the `RelayPacket`, append BPv7-style routing metadata, and forward — **assert each relay cannot decapsulate** (wrong key) yet forwards intact.
3. **Ground:** `L2Materializer` decapsulates and materializes; verify end-to-end integrity and that `sequencing.py` rejects a replayed/duplicated bundle arriving via a second path.
4. **Disruption model:** a simple in-memory contact-graph sim (dict of `time → available_links`) that (a) drops a hop mid-transfer, (b) delivers shards via two diverging paths, and (c) shows k-of-n reconstruction (`erasure.py` + `commitment.py`) succeeding from the surviving shards.
5. **Metric to report:** simulated time-to-ground for mesh vs. single-bird (using the §6 contact cadence), plus per-hop byte overhead — reproducing the >100× latency and constant-overhead claims.

**Deliverable:** a pytest-driven `tests/cubesat/test_isl_relay_chain.py` + a small `examples/isl_mesh_sim.py`, reusing `bridge/`, `erasure.py`, `shards.py`, `commitment.py`, `sequencing.py` unchanged. This is a pure-software Phase-1 artifact per the `CUBESAT_SCOPE.md` roadmap — semantics first, DTN/CCSDS integration (ION/HDTN + CGR) in a later phase.

---

*Scoping only — additive to ETP. The relay/seal/reconstruct core is reused as-is; the new surface is the contact-graph router and the N-hop relay-chain adapter. Shared space profile lives in [`CUBESAT_SCOPE.md`](../../CUBESAT_SCOPE.md).*

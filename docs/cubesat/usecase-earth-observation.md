# ETP Use Case: Earth-Observation Payload Downlink

**Parent scope:** [`CUBESAT_SCOPE.md`](../../CUBESAT_SCOPE.md) — shared architecture (ETP-Sat profile, ~1.3 KB PQC sealed key, k-of-n forward erasure, DTN/BPv7 store-and-forward convergence layer, ground/flight compute split). This brief does **not** repeat that; it scopes the EO-downlink personality on top of it.

**Author:** Javier Calderon Jr, CTO of Global Settlement (GSX) · **Date:** July 1, 2026 · **Status:** Use-case scoping

---

## 1. One-line pitch

Post-quantum, erasure-coded bulk downlink for commercial optical/SAR imaging constellations: spray each large image product as k-of-n shards across the passes you actually get, seal it once with a ~1.3 KB PQC key that never grows with scene size, and keep it confidential for the full multi-year commercial embargo window — no ARQ, no live socket, no classical crypto to harvest.

## 2. Mission profile & who buys it

**The satellite:** 6U–12U (or ESPA-class ~100 kg) commercial imager in LEO, 450–600 km SSO. Optical (0.5–3 m GSD panchromatic/multispectral) or X-band SAR (0.25–1 m spotlight/stripmap). Constellation of 10–50+ birds for daily/sub-daily revisit.

**Who buys it:**
- **Commercial EO operators** (Planet, BlackSky, Satellogic, Umbra, ICEYE, Capella-class) whose product is the imagery itself — the downlink pipe is their revenue bottleneck and the imagery has resale/embargo value.
- **Defense/intel & GEOINT resellers** buying commercial capacity, who need harvest-now-decrypt-later protection on a broadcast RF medium.
- **Ground-segment-as-a-service** providers (KSAT, AWS Ground Station, Leaf Space, Atlas) who want a coding/security layer that survives their multi-antenna, multi-pass scheduling model.

**Why they care:** the scene is worth money for months to years (tasking exclusivity, embargo, analytics contracts). A recorded X-band downlink decrypted in 2035 is a commercial breach, not just a telemetry leak.

## 3. Link / ops profile (EO-specific)

| Parameter | EO downlink reality | Source of pain |
|---|---|---|
| Downlink band | **X-band 8.025–8.4 GHz**, primary payload channel | Power/pointing hungry; the whole point is bulk data |
| X-band rate | **50–400 Mbps** (typ. 100–200 Mbps; high-end LDPC to ~800 Mbps–1.2 Gbps) | Even at 200 Mbps a pass moves only ~7–8 GB |
| S-band | 1–20 Mbps for TT&C + low-rate payload | Backup / small products only |
| Optical (OISL/OGS) | 1–10 Gbps emerging (Sony/TESAT/Mynaric) | Weather-gated; not yet baseline for most fleets |
| Usable pass | **6–10 min** above ~5–10° elevation; ~8 min nominal | Contact is a scheduled window, not a link |
| Passes/day (single GS) | 3–5; **4–6 GS network → 10–15 contacts/day** | Data must span passes and antennas |
| Daily downlink budget | ~**7–8 GB/pass X-band → 70–120 GB/day** across a GS network | Onboard generation often exceeds this |
| Image product size | **Optical scene 0.5–4 GB** (raw), **SAR SLC/scene 1–8 GB**, L1 products larger | A single product straddles multiple passes |
| Onboard generation | 100s of GB/day for a tasked imager | **Downlink is the bottleneck, always** |
| BER pre-FEC at horizon | 1e-5 → 1e-2, bursty low-elevation fade | Loss is not uniform; tail of the pass is lossy |
| Latency | 2–20 ms one-way | Irrelevant — **disruption**, not latency, is the enemy |

**The defining EO constraint:** a single image product (GBs) does not fit in a single pass (~7–8 GB is the *whole* pass), and a tasked fleet generates far more than it can downlink. The transport problem is "reliably reassemble large products across a fragmented, lossy, multi-pass / multi-antenna contact schedule" — exactly the DTN + erasure regime.

## 4. Why ETP fits — pillars ranked for EO

1. **k-of-n forward erasure (the headline for EO).** A 4 GB scene sprayed as `n` shards reconstructs from any `k` — so partial passes, horizon fade, and a scene split across three antennas on two days all *just add up* to a reconstruction. No ARQ round-trips burning the 8-minute window; missing shards re-spray next pass via DTN custody. This is the single biggest fit — EO's pain is exactly "assemble a big object from whatever fragments I received." Reuses `erasure.py` + `commitment.py`.
2. **PQC seal (~1.3 KB, constant size).** The commercial value lives over a **multi-year embargo**, and X-band downlink is broadcast + recordable by any dish in the footprint → textbook harvest-now-decrypt-later. One ML-KEM-768 seal protects an entire multi-GB scene and costs ~1 s of uplink *regardless of scene size*. Reuses `bridge/` seal + `shards.py` AEAD.
3. **DTN store-and-forward (BPv7/CCSDS).** Products straddle passes and ground stations; custody transfer lets scene fragments accumulate across a KSAT/AWS-style antenna network without a live end-to-end socket. This is *integrated*, not built by us (see parent §5).
4. **Ground-side anchoring (optional, provenance).** A GSX anchor on the landed product is a chain-of-custody receipt for imagery of contested/legal value (insurance, damage assessment, treaty monitoring). Off the flight critical path — a ground concern only. Lowest priority for a first EO demo.

## 5. ETP module impact for EO downlink

| Module | Action for EO | EO-specific note |
|---|---|---|
| `erasure.py` (RS GF(256) k-of-n) | **Reuse core; size for GB scenes** | Encode a 4 GB scene → ~4M×1 KB shards; native/fountain hot path matters at this shard count (see parent §5.3, roadmap §Phase 3) |
| `commitment.py` (k-of-n reconstruct) | **Reuse** | Reassemble scene from shards pooled across passes/antennas; drop strike/eviction economics |
| `shards.py` (per-shard XChaCha20-Poly1305) | **Reuse as-is** | Per-shard AEAD → each downlinked fragment is independently confidential on the broadcast medium |
| `bridge/` (ML-KEM seal, RelayPacket) | **Reuse pattern** | One seal per scene (or per tasking order); ground-station = relayer analogy is exact |
| `sequencing.py` | **Reuse** | Bind scene-ID / tasking-order-ID to monotonic sequence; reject replayed or stale fragment sets across passes |
| `streaming.py` (64 KB chunks) | **Reprofile** | Chunk→CCSDS ~1 KB frame; pipeline depth bounded by per-pass byte budget, not a socket |
| `protocol.py` (30/10/60 s timeouts) | **Rework** | Product-lifetime = DTN bundle expiry (hours–days across passes), not wall-clock seconds |
| `network/*` (gRPC) | **Ground-only** | GS ↔ processing ↔ tasking DB stays gRPC; never on the space link |
| `envelope.py` / ML-DSA-65 sign | **Sign-on-ground** | Sign the *scene manifest* once on orbit (or aggregate per tasking order); never per-shard |
| `network/spacelink/` | **NEW** | EO adds a **scene-manifest** frame: scene-ID, `k`, `n`, shard map, seal ref — see parent §5.3 |
| `anchor/`, `backends/`, contracts | **Decouple (optional)** | Post-landing provenance receipt per delivered product |

**New for EO specifically:** a `SceneManifest` (which shards belong to which product, `k`/`n`, seal reference, tasking-order-ID) so a ground receiver pooling fragments from multiple antennas knows when a product is reconstructable — the EO analog of the generic `SpaceLinkProfile`.

## 6. Worked mini-example — one 4 GB SAR scene across passes

**Given:** X-band @ 200 Mbps, 8-min usable pass, ~10% effective overhead → **~7.5 GB usable/pass**. Shard frame ~1 KB. Measured horizon loss budget ρ = 0.30.

- **Scene:** 4 GB SAR SLC → `k ≈ 4,000,000` data shards of 1 KB.
- **Erasure margin:** transmit `n = k·(1+ρ) = 5,200,000` shards (~5.2 GB on the wire).
- **Fits a pass?** 5.2 GB < 7.5 GB usable/pass → **the whole scene + 30% erasure margin downlinks in a single 8-min X-band pass**, and reconstructs even if 30% of shards are lost to horizon fade — *with zero retransmission requests*.
- **If the pass is cut short** (AOS late / LOS early, only 5 GB received): partial shards are retained; DTN custody re-sprays the deficit on the **next** pass, possibly via a **different ground station**, and `commitment.py` reconstructs from the pooled `k`. No mid-pass ARQ ever touches the scarce window.
- **PQC cost:** one ML-KEM-768 seal (~1.3 KB) protects the entire 4 GB scene → **~1.1 s of a 9.6 kbps uplink**, and does **not** grow if the scene were 8 GB. One ML-DSA-65 manifest signature (~3.3 KB) covers the whole product — not per-shard.

**Proof of fit:** a full commercial SAR scene downlinks in one pass with a 30% loss cushion, survives a truncated pass by summing fragments across passes/antennas, and carries multi-year post-quantum confidentiality for ~1 second of uplink. That is the EO thesis in one number.

## 7. EO-specific risks

- **Shard-count blow-up.** 1 KB shards over multi-GB scenes → millions of shards; pure-Python RS is far too slow. EO *forces* the native/fountain hot path (parent §Phase 3) earlier than lighter use cases. Consider a two-level scheme (coarse block RS over 1–4 MB blocks, fine frames within) to bound shard count.
- **Product straddles ground stations.** Custody re-spray across a KSAT/AWS multi-antenna network needs consistent scene-ID/manifest routing so fragments from different antennas pool correctly — a DTN routing/naming concern, not just coding.
- **X-band regulatory/licensing.** 8.025–8.4 GHz commercial EO is licensed (ITU/FCC/national), unlike amateur UHF; band, EIRP, and GS coordination constrain the real rate — the 200 Mbps figure is per-license, not free.
- **Compression interaction.** EO products are already CCSDS-122/123 or JPEG2000 compressed; erasure operates on the compressed byte stream (fine), but a lost *un-erasure-protected* header corrupts a whole tile — the manifest/header must sit inside the erasure envelope, not outside it.
- **Rate-vs-loss mismatch.** ρ=0.30 is a guess; horizon loss is bursty and elevation-dependent. Fixed-rate RS under-/over-shoots; a rateless (RaptorQ) option lets the sat keep spraying until the ground says "got k" on the next uplink — better for EO's unknown loss, at complexity cost.
- **On-orbit encode cost.** Encoding `n` shards for a 4 GB scene is real CPU/power on the bird. Where possible pre-compute erasure on stored products during eclipse/idle, not during the pass.

## 8. Minimal demo / MVP in THIS repo

Goal: prove single-pass-with-margin and cross-pass reconstruction of a real-size EO product, using existing ETP crypto + coding, no radio.

1. **Fixture:** a synthetic 4 GB (or scaled 400 MB for CI) "SAR scene" blob.
2. **Encode path (ground/flight-sim):** `erasure.py` → k-of-n 1 KB shards; `shards.py` per-shard XChaCha20-Poly1305; one `bridge/` ML-KEM-768 seal for the scene key; one ML-DSA-65 signature over a new `SceneManifest` (scene-ID, k, n, seal ref, shard digest list).
3. **Pass simulator:** a `spacelink` loopback (parent §Phase 1) that delivers shards in **8-min "pass" batches** with an injected loss model (ρ, bursty at batch tail) and **drops a random pass entirely** to force cross-pass pooling.
4. **Receive path:** pool shards across simulated passes/antennas → `commitment.py` reconstructs once `k` arrive → verify manifest signature → decrypt → **byte-compare to original scene**.
5. **Assertions that prove the thesis:** (a) scene reconstructs after losing 30% of shards; (b) scene reconstructs when one full pass is dropped but fragments span two "antennas"; (c) seal size is constant (~1.3 KB) as scene size scales 400 MB → 4 GB; (d) report shards/sec to quantify the native-hot-path gap (risk §1).
6. **Optional stretch:** anchor the delivered `SceneManifest` digest via the existing `anchor/` backend as a provenance receipt (pillar §4), proving the ground-side decoupling.

MVP touches **zero flight hardware and zero new crypto** — it composes `erasure.py`, `shards.py`, `bridge/`, `commitment.py`, `sequencing.py` behind a new `spacelink` loopback + `SceneManifest`, and outputs one number: *"reconstructed a 4 GB scene from a lossy, one-pass-dropped contact schedule."*

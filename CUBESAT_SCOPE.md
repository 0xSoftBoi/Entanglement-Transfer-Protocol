# ETP for CubeSats — Satellite Transport Scoping Document

**Author:** Javier Calderon Jr, CTO of Global Settlement (GSX)

**Date:** July 1, 2026

**Branch:** `claude/satellite-cubesat-scope-7w6o7t`

**Status:** Scoping / design — no flight code yet

---

## Table of Contents

1. [Thesis: Why the Satellite Play](#1-thesis-why-the-satellite-play)
2. [The Two LTPs — A Bridge, Not a Collision](#2-the-two-ltps--a-bridge-not-a-collision)
3. [The CubeSat Operating Environment](#3-the-cubesat-operating-environment)
4. [Gap Analysis: ETP Today vs. Space Reality](#4-gap-analysis-etp-today-vs-space-reality)
5. [Target Architecture — the ETP-Sat Profile](#5-target-architecture--the-etp-sat-profile)
6. [Module-by-Module Impact](#6-module-by-module-impact)
7. [Worked Example: Data Volume & Link Budget](#7-worked-example-data-volume--link-budget)
8. [Radiation, Power & Reliability](#8-radiation-power--reliability)
9. [In-Orbit Threat Model](#9-in-orbit-threat-model)
10. [Roadmap](#10-roadmap)
11. [Open Questions & Risks](#11-open-questions--risks)
12. [References](#12-references)

---

## 1. Thesis: Why the Satellite Play

ETP was built for high-bandwidth, low-latency, reliable WANs — cross-chain settlement between data centers. That is exactly the *opposite* of a space link. But the protocol's two defining properties turn out to be worth more in orbit than on the ground:

1. **Constant-size cryptographic artifacts (~1.3 KB), independent of payload size.** On a link where the uplink is measured in *kilobits per second* and a usable pass lasts *minutes*, a key-delivery mechanism whose cost does not grow with the data being protected is a structural advantage, not a nice-to-have.
2. **Erasure coding as the availability primitive (any *k*-of-*n* shards reconstruct).** A CubeSat downlink is a lossy, one-way-ish, feedback-starved channel. Forward erasure correction — spraying *n* shards and reconstructing from any *k* — is the single most natural fit for "I get a few minutes of contact per orbit and can't afford a chatty ARQ handshake."

Add the post-quantum angle: satellite fleets fly for **5–15 years**. Anything downlinked today under a classical cipher is subject to *harvest-now-decrypt-later*. A constellation commissioned in 2026 that wants its telemetry and payload data confidential through 2040 needs PQC **at commissioning**, not as a retrofit. ETP already ships real ML-KEM-768 / ML-DSA-65 / XChaCha20-Poly1305. That is the pitch: **post-quantum, erasure-coded, constant-overhead data transfer for CubeSat constellations.**

**What "scoped for CubeSats" means concretely.** We are not putting the GSX chain in orbit. We are extracting the *transport + crypto core* of ETP, giving it a space-appropriate convergence layer (CCSDS/DTN instead of gRPC), and making it pass-window and store-and-forward aware. The blockchain/settlement layers stay on the ground as an optional anchoring backend for provenance of received data.

---

## 2. The Two LTPs — A Bridge, Not a Collision

There is a naming coincidence worth exploiting rather than hiding:

- **Our LTP** = **Lattice** Transfer Protocol (this repo).
- **Space's LTP** = **Licklider** Transmission Protocol ([RFC 5326](https://www.rfc-editor.org/rfc/rfc5326)) — the DTN convergence-layer protocol designed for long-delay, intermittently-connected links, and the standard "reliable" layer under the Bundle Protocol for deep-space and disrupted terrestrial/space links.

This is a gift. The DTN stack (Bundle Protocol v7, [RFC 9171](https://www.rfc-editor.org/rfc/rfc9171)) already solves the two things our transport does *not*: **custody-based store-and-forward** and **operation across multi-minute-to-multi-hour disconnections**. The clean design is:

```
  ETP entity  →  erasure shards (k-of-n)  →  DTN bundles  →  Licklider LTP / CCSDS  →  RF
     (ours)          (ours: erasure.py)        (BPv7)         (space-standard CL)     (radio)
```

We keep the ETP semantics (commit → seal → materialize, PQC-sealed constant-size key, threshold reconstruction) and we borrow the space community's battle-tested delivery substrate underneath. We are the **payload-security + coding layer**; DTN is the **delivery layer**. No competition — a stack.

---

## 3. The CubeSat Operating Environment

Design must be driven by real numbers. Representative figures for a **3U-class LEO CubeSat** (the sweet spot for commercial constellations):

| Parameter | Typical value | Implication for transport |
|---|---|---|
| Orbit | LEO, 400–600 km, ~90–96 min period | ~15 orbits/day |
| Ground-station pass | **5–12 min** usable above horizon; often ~8 min | Contact is a *scheduled window*, not a standing connection |
| Passes/day (single GS) | 3–6 | ~30–60 min of total contact/day |
| One-way light-time | ~2–20 ms (LEO is *close*) | Latency is **not** the problem — *disruption* is |
| Disconnection gap | **minutes to hours** between passes | Store-and-forward is mandatory |
| UHF (435 MHz, AX.25/GMSK) | **9.6–19.2 kbps**, up to ~100 kbps | Command uplink + beacon; *precious* |
| S-band (2.0–2.3 GHz) | **0.1–2 Mbps** typical, up to ~10 Mbps | Workhorse payload downlink |
| X-band (8 GHz) | 10–150+ Mbps | High-end 6U+; power/pointing hungry |
| Optical (laser) | 100 Mbps–10 Gbps (emerging) | Future; narrow-beam, weather-sensitive |
| TM frame (CCSDS) | ~1115 bytes typical, fixed-length | Our shard framing must be small & fixed |
| Bit error rate (pre-FEC) | 1e-5 to 1e-2 at low elevation | FEC is not optional; loss is bursty at horizon |
| Power (orbit-average) | 1U ~1–2 W, 3U ~5–7 W, 6U ~20–40 W | Compute & TX duty cycle are budgeted in *milliwatts* |
| Flight CPU | Cortex-M4/M7, or rad-tolerant SoC; MB of RAM | Crypto must fit a microcontroller, not a server |

**The three hard constraints, ranked:**

1. **Intermittency** (gaps ≫ contact) → store-and-forward, no assumption of a live socket.
2. **Asymmetry** (uplink ≪ downlink, by ~100×) → cheap uplink is a first-class design goal.
3. **No cheap feedback** (ARQ round-trips waste the window) → forward correction over retransmission.

---

## 4. Gap Analysis: ETP Today vs. Space Reality

Grounded in the current `src/ltp/` implementation:

| ETP component (today) | Current assumption | Space reality | Verdict |
|---|---|---|---|
| `network/client.py`, `network/server.py` | **gRPC over HTTP/2**, insecure channels, 10 s RPC timeout | HTTP/2 needs a live, reliable, bidirectional socket — impossible across pass gaps | **Replace** convergence layer with DTN/CCSDS; keep gRPC for *ground segment* only |
| `protocol.py` timeouts | commit 30 s / lattice 10 s / materialize 60 s | Phases may straddle *hours* and multiple passes | **Rework** to pass-window / bundle-lifetime semantics, not wall-clock seconds |
| `streaming.py` | 64 KB chunks, 4-way pipeline over a sustained connection | No sustained connection; 64 KB may exceed a whole uplink pass | **Reprofile** chunk/shard size to CCSDS frame (~1 KB) and to per-pass budgets |
| `erasure.py` (Reed–Solomon GF(256)) | Pure-Python O(n·k·chunk) loops | Correct *primitive*, wrong *implementation* for a flight MCU | **Keep design, port hot path** to C/Rust (or use a fountain code); the k-of-n model is exactly right |
| Sealed key (~1.3 KB, ML-KEM-768) | Constant-size, O(1) in payload | **This is the crown jewel** for a kbps uplink | **Reuse as-is** — headline advantage |
| Signatures (ML-DSA-65, ~3.3 KB) | Signed envelopes everywhere | 3.3 KB is ~2.7 s of 9.6 kbps uplink *per signature* | **Budget carefully** — verify-on-orbit, sign-on-ground; consider aggregate/less-frequent signing |
| gRPC/TCP reliability | Delegated to the transport | No TCP in the DTN path | **Add** our own reliability via erasure + DTN custody (LTP red/green parts) |
| No store-and-forward | Storage backends are incidental | Mandatory | **Add** an explicit pass-window queue (DTN bundle store) |
| Blockchain anchoring | On-chain settlement inline | No chain in orbit; anchoring is a *ground* concern | **Decouple** — anchoring becomes an optional ground-side provenance step |

**Bottom line:** the *cryptographic and coding core* (`shards.py`, `erasure.py`, `commitment.py` reconstruction, the ML-KEM seal in `bridge/`) transfers to space almost unchanged. The *networking* (`network/*`, gRPC, HTTP timeouts) does not travel and is replaced by a space convergence layer.

---

## 5. Target Architecture — the ETP-Sat Profile

Define a new **link profile**, not a fork. The core stays; we add a constrained-link personality.

### 5.1 Layering

```
 ┌─────────────────────────────────────────────────────────┐
 │ ETP semantics: commit → seal(ML-KEM-768) → materialize   │  ← unchanged
 ├─────────────────────────────────────────────────────────┤
 │ Coding: Reed–Solomon / fountain, k-of-n forward erasure  │  ← reuse erasure.py design, native hot path
 ├─────────────────────────────────────────────────────────┤
 │ Framing: fixed ~1 KB shard frames, CCSDS-sized           │  ← NEW (ltp.network.spacelink)
 ├─────────────────────────────────────────────────────────┤
 │ Store-and-forward: pass-window bundle queue (DTN BPv7)   │  ← NEW
 ├─────────────────────────────────────────────────────────┤
 │ Convergence: Licklider LTP (RFC 5326) / CCSDS TM-TC-AOS  │  ← integrate, don't reinvent
 ├─────────────────────────────────────────────────────────┤
 │ Radio: UHF / S-band / X-band                             │  ← hardware
 └─────────────────────────────────────────────────────────┘
```

### 5.2 Design principles

- **Forward, not feedback.** Size *n/k* so a full ETP entity reconstructs from the shards received in a *single* pass with margin. No ARQ inside a pass; missing shards are re-sprayed on the *next* pass (DTN custody), not retransmitted mid-pass.
- **Uplink is sacred.** The uplink carries commands + the ~1.3 KB sealed key. Everything expensive (payload, signatures) flows *down*. Where a satellite must sign, prefer infrequent aggregate signatures over per-message ML-DSA.
- **Compute split.** Heavy/asymmetric work (ML-DSA *signing*, erasure *encoding* of large payloads, anchoring) lives on the ground. The flight side does ML-KEM decapsulation (cheap, ~ms on Cortex-M4 per pqm4 benchmarks), AEAD, and erasure *decoding* of the sealed control path.
- **Bundle lifetime, not socket timeout.** Replace `protocol.py`'s second-scale timeouts with DTN bundle expiry (hours/days) and pass-schedule awareness.
- **Ground keeps the chain.** GSX anchoring becomes a post-facto provenance receipt for data *after* it lands, not an in-loop dependency.

### 5.3 What is genuinely new code

- `src/ltp/network/spacelink/` — a convergence-layer shim: fixed-size shard framing, a store-and-forward pass-window queue, and a DTN/CCSDS adapter (start with a software loopback + file-based bundle store for tests; integrate ION/HDTN or a BPv7 lib later).
- A `SpaceLinkProfile` config object (analogous to `StreamConfig`) carrying: `frame_bytes`, `pass_budget_bytes`, `n`, `k`, `uplink_bps`, `downlink_bps`, `max_disconnect`.
- A native erasure hot-path binding (feature-flagged; pure-Python remains the reference/fallback).

---

## 6. Module-by-Module Impact

| Module | Action | Notes |
|---|---|---|
| `erasure.py` | **Reuse + accelerate** | k-of-n is the right model; port GF(256) inner loop to native for flight; add fountain-code option for unknown-loss channels |
| `shards.py` | **Reuse** | Per-shard XChaCha20-Poly1305 already independent — ideal for spray-and-reconstruct |
| `bridge/` (ML-KEM seal, RelayPacket) | **Reuse pattern** | The ~1.3 KB sealed-key transport *is* the uplink control path; relayer→ground-station analogy is exact |
| `commitment.py` | **Reuse (reconstruction)** | k-of-n reconstruction logic; drop the eviction/strike economics for the space path |
| `protocol.py` | **Rework timeouts** | Pass-window / bundle-lifetime state machine; keep the 3-phase semantics |
| `streaming.py` | **Reprofile** | Chunk→frame sizing driven by `SpaceLinkProfile`; pipeline depth bounded by pass budget |
| `network/*` (gRPC) | **Ground-only** | Keep for ground segment (GS ↔ mission control ↔ GSX); not on the space link |
| `envelope.py` / signatures | **Budget** | Verify-on-orbit; sign-on-ground; measure ML-DSA-65 size against uplink/downlink budgets |
| `anchor/`, `backends/`, contracts | **Decouple** | Optional ground-side provenance anchoring, out of the flight loop |
| `network/spacelink/` | **NEW** | Framing + store-and-forward + DTN/CCSDS adapter |

---

## 7. Worked Example: Data Volume & Link Budget

**Scenario:** 3U CubeSat, S-band downlink @ 2 Mbps, UHF uplink @ 9.6 kbps, 8-min usable pass, 3 passes/day.

**Downlink capacity**
- Per pass: 2 Mbps × 480 s = 960 Mbit ≈ **120 MB raw**; after CCSDS coding overhead + margin call it **~90 MB usable/pass**.
- Per day: ~**270 MB**. That is the whole science/telemetry budget to design against.

**Uplink capacity**
- Per pass: 9.6 kbps × 480 s = 4.6 Mbit ≈ **576 KB/pass**. Tiny.
- ETP sealed key (~1.3 KB) over that uplink ≈ **~1.1 s**. *Negligible.* This is the headline: post-quantum key establishment costs ~1 second of a scarce uplink, and **does not grow with payload size**.
- One ML-DSA-65 signature (~3.3 KB) ≈ **~2.7 s** of uplink — affordable occasionally, *not* per-message. Confirms "sign on the ground, verify on orbit; on-orbit signing is rate-budgeted."

**Erasure sizing (single-pass reconstruction)**
- Target: reconstruct a 90 MB pass payload from shards received in *one* pass with loss margin.
- With ~1 KB CCSDS-sized shard frames, 90 MB ≈ 90,000 data shards. Choose overhead so *k* data shards reconstruct from *n = k·(1+ρ)* transmitted, ρ ≈ 0.2–0.5 depending on measured horizon loss.
- Missing shards after a pass are **not** retransmitted mid-pass; they are re-sprayed next pass via DTN custody. No ARQ inside the window.

**Takeaway:** the numbers validate the thesis. Constant-size PQC keying is essentially free on the uplink; erasure coding is the correct reliability model for the downlink; signatures are the one place we must budget deliberately.

---

## 8. Radiation, Power & Reliability

- **SEU/SEL:** COTS flight compute suffers single-event upsets. Crypto state and shard buffers need ECC memory and/or memory scrubbing; keep decapsulation working set small and re-verifiable. Watchdog + known-good reset path.
- **Determinism:** the codebase's existing determinism discipline (canonical length-prefixed encoding, fixed HKDF salts, no wall-clock randomness in the hot path) is *helpful* — reproducible framing survives resets and eases fault recovery.
- **Power/duty cycle:** TX is the dominant power draw; encode on the ground, decode-light on orbit. ML-KEM-768 decapsulation is milliseconds on a Cortex-M4 (pqm4) and fits a mW budget; ML-DSA *signing* is heavier — another reason to keep it on the ground.
- **Flight-code reality check:** pure-Python ETP is a *ground/reference* implementation. The flight article is a small C/Rust core doing ML-KEM decap + AEAD + erasure decode of the control path. This document scopes the *architecture*; the flight port is a later phase with its own qualification.

---

## 9. In-Orbit Threat Model

| Threat | Space-specific angle | Mitigation (mostly already in ETP) |
|---|---|---|
| Harvest-now-decrypt-later | 5–15 yr mission life; downlink is broadcast & recordable | PQC by default (ML-KEM-768 seal, XChaCha20-Poly1305 payload) — the core value prop |
| Command spoofing / uplink forgery | Anyone with a dish can transmit | ML-DSA-65 verify on orbit for commands; sequence/replay binding (`sequencing.py`) across passes |
| Replay across passes | Same command re-sent next orbit | Monotonic per-signer sequence + temporal expiry already in `sequencing.py` |
| Ground-station compromise | GS is the soft target, not the bird | Keep signing keys in mission-control HSM (`hsm.py`); GS is a relay, not a trust root |
| Jamming / partial denial | Bursty loss at low elevation, deliberate interference | Erasure margin (ρ) + DTN custody re-spray on later passes |
| Downlink eavesdropping | Broadcast medium | Per-shard AEAD; shards are individually encrypted (`shards.py`) |

The existing `docs/THREAT_MODEL.md` and `hsm.py`/`sequencing.py` primitives cover most of this; the space delta is *broadcast medium* + *long mission life* + *intermittent replay surface*.

---

## 10. Roadmap

**Phase 0 — Scope & profile (this document).** Agree the ETP-Sat profile, the DTN-under-us stack, and the ground/flight compute split.

**Phase 1 — `SpaceLinkProfile` + software loopback.** Add the config object and a `ltp.network.spacelink` convergence shim with a *file-based* store-and-forward bundle queue and fixed ~1 KB framing. Simulate pass windows + loss in tests (extend the existing simulator). No radio, no DTN daemon yet — prove the semantics.

**Phase 2 — DTN/CCSDS integration.** Wire the shim to a real BPv7/LTP implementation (ION or HDTN) and/or a CCSDS TM/TC framer. Validate multi-pass reconstruction and custody re-spray against a disruption model.

**Phase 3 — Native erasure hot path.** C/Rust GF(256) (or fountain code) behind the existing pure-Python interface, feature-flagged, benchmarked against a Cortex-M4-class target.

**Phase 4 — Flight-core prototype.** Minimal C/Rust ETP-Sat core (ML-KEM decap + AEAD + erasure decode) on an eval board; hardware-in-the-loop with an SDR uplink/downlink.

**Phase 5 — Ground provenance anchoring.** Optional: landed data gets a GSX anchor for provenance — reusing the existing anchoring stack, off the flight critical path.

---

## 11. Open Questions & Risks

- **DTN implementation choice:** ION (JPL, C, flight-heritage) vs. HDTN (NASA, performance) vs. a lean BPv7 library. Affects footprint and licensing.
- **Fountain vs. fixed-rate RS:** unknown/variable horizon loss argues for rateless (RaptorQ-style); RS is simpler and already designed in. Decide per-channel.
- **Signature strategy:** per-command ML-DSA verify is fine; how often must the *satellite* sign, and can we batch/aggregate to protect the uplink? Needs a concrete ops model.
- **Regulatory/RF:** licensing (ITU/FCC/national), band selection, and whether we assume amateur (UHF) or licensed commercial (S/X) — changes the data-rate assumptions above.
- **Flight qualification scope:** this repo will realistically own the *ground segment + reference core*; the qualified flight article is a separate, smaller codebase. Set that boundary explicitly before Phase 4.
- **Is CubeSat the beachhead or the whole play?** The same profile scales up to smallsats and down to the store-and-forward IoT/backhaul case. Confirm CubeSat-first is the go-to-market, not just the demo.

---

## 12. References

- RFC 9171 — Bundle Protocol Version 7 (BPv7)
- RFC 5326 — Licklider Transmission Protocol (LTP) Specification
- RFC 5050 — Bundle Protocol (historical, BPv6)
- CCSDS 132.0-B — TM Space Data Link Protocol
- CCSDS 232.0-B — TC Space Data Link Protocol
- CCSDS 131.0-B — TM Synchronization and Channel Coding (LDPC / Turbo / RS)
- FIPS 203 — ML-KEM · FIPS 204 — ML-DSA (this repo's PQC primitives)
- pqm4 — PQC benchmarks on ARM Cortex-M4 (feasibility of ML-KEM on flight MCUs)
- `LTP_COMPREHENSIVE_REPORT.md`, `docs/THREAT_MODEL.md` — existing ETP architecture & threat baseline

---

*This is a scoping document: it defines the architecture and the path, not the flight implementation. Nothing here changes existing ETP behavior — the ETP-Sat profile is additive, and the cryptographic/coding core is reused, not rewritten.*

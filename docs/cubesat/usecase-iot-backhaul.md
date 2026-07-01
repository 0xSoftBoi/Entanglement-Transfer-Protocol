# ETP Use Case — IoT / M2M Delay-Tolerant Backhaul

**Author:** Javier Calderon Jr, CTO of Global Settlement (GSX) · **Date:** July 1, 2026
**Status:** Use-case scoping. Reuses the shared ETP-Sat architecture from [`CUBESAT_SCOPE.md`](../../CUBESAT_SCOPE.md) — constant-size ~1.3 KB PQC seal, k-of-n forward erasure, DTN(BPv7)/CCSDS store-and-forward convergence layer, ground/flight compute split. This doc only covers what is *specific* to IoT backhaul; it does not repeat that architecture.

---

## 1. One-line pitch

Post-quantum, replay-bound authentication for tiny satellite-IoT messages — a coin-cell sensor emits tens of bytes, a passing CubeSat store-and-forwards them hours later, and the ground can prove *which sensor* sent *what*, *when*, provably secure against harvest-now-decrypt-later.

---

## 2. Mission profile & who buys it

**Profile.** A LEO CubeSat constellation provides intermittent, one-way-ish "message pickup" over ground sensors that have no cellular/LoRa gateway in range — the Swarm / Astrocast / Myriota / Kineis model. The sensor wakes on a schedule (or on an event), transmits a short burst, and sleeps. The satellite buffers bursts across the orbit and dumps them to a ground station on the next contact. **Extreme asymmetry:** the *sensor* is the constrained endpoint (coin cell, sub-$5 modem, MCU), not just the satellite.

**Who buys it:**
- **Asset / cargo tracking** — containers, rail cars, pallets crossing oceans and deserts with no terrestrial coverage.
- **Pipeline / grid / SCADA** — remote pressure, flow, cathodic-protection, leak sensors along thousands of km of pipe.
- **Agriculture** — soil moisture, tank level, livestock tags across farms with no backhaul.
- **Maritime / buoys** — vessel telemetry, drifting ocean buoys, fishing-gear tags.
- **Utilities / environmental** — remote metering, seismic, wildfire, hydrology.

**Why they'd pay for ETP over plain satellite-IoT:** these buyers increasingly need *data provenance and tamper-evidence* (regulatory metering, carbon MRV, custody-of-goods, critical-infrastructure integrity) and *long-lived confidentiality* — a pipeline sensor commissioned in 2026 should still be unforgeable and unreadable in 2040. That is the PQC + anchoring pitch.

---

## 3. Link / ops profile (the SENSOR is the constraint)

| Parameter | Representative value | Note |
|---|---|---|
| Sensor uplink modem | ~1–3 kbps effective (Swarm/Myriota-class), sometimes down to ~100 bps | Narrowband store-and-forward, not a live link |
| Sensor→sat message size | **10–192 bytes application payload**; Swarm caps at 192 B, many readings are 8–20 B | This is the whole design driver |
| Sensor TX power | ~1 W RF during a burst; burst lasts ~1–5 s | Energy per message is the currency |
| Sensor energy budget | Coin cell (CR2032 ~225 mAh @ 3 V ≈ 2.4 kJ) or small Li-SOCl₂; target *years* of life | Every byte and every crypto op costs battery |
| Sensor MCU | Cortex-M0+/M4, **8–256 KB RAM**, 0.032–0.1 mA/MHz sleep-heavy duty | Crypto must fit KB of RAM, not MB |
| Satellite revisit | **1.5–12 h** typical for a small constellation; hours between contacts | Delay-tolerance is mandatory, not optional |
| Sat→ground contact | 5–12 min pass, S-band 0.1–2 Mbps down | Plenty of downlink; the pickup uplink is the bottleneck |
| Directionality | Mostly uplink-only from sensor; downlink to sensor rare/expensive | No ARQ handshake with the sensor |

**The hard constraint, ranked for THIS use case:**
1. **Sensor energy** (coin cell, years) → minimize bytes *and* crypto ops per message.
2. **Tiny payloads** (tens of bytes) → per-message crypto *overhead* dominates; amortization is everything.
3. **Intermittency** (revisit in hours) → DTN store-and-forward, no live socket, no per-message feedback.

---

## 4. Why ETP fits — and where it does not (ranked, honest)

**Pillar 1 — DTN store-and-forward (BEST fit).** The revisit-in-hours, uplink-only, no-ARQ shape is *exactly* the DTN custody model in `CUBESAT_SCOPE.md` §5. A sensor burst becomes one BPv7 bundle with a multi-hour/day lifetime; the satellite is a custodian; delivery completes on ground contact. This pillar is a clean win with zero tension.

**Pillar 2 — Anchoring for data integrity / provenance (STRONG fit, differentiating).** The buyers in §2 pay for *provenance*, not throughput. `sequencing.py` (monotonic per-signer sequence + temporal expiry) gives cross-pass replay protection — critical when a burst can be recorded off-air and replayed on the next orbit. Ground-side GSX anchoring (`anchor/`, contracts) turns "sensor #4471 reported 3.2 bar at T" into a tamper-evident receipt. This is the reason to choose ETP over commodity satellite-IoT.

**Pillar 3 — Constant-size PQC seal (fits ONLY when amortized — see §6).** The ~1.3 KB ML-KEM-768 seal is *constant in payload*, which is a virtue for large payloads but a **liability for a 20-byte reading**: 1.3 KB of key material to protect 20 B is a ~65× overhead. Per-message sealing is a *poor* fit and we should say so plainly. It becomes an *excellent* fit only when the KEM output is **amortized over a session/epoch key**: seal once (or once per re-key epoch), then protect thousands of subsequent messages with a cheap symmetric AEAD tag. See §6.

**Pillar 4 — k-of-n erasure coding (WEAK / mostly N/A here).** Erasure coding is the crown jewel for the *bulk downlink* case, but a single 20-byte sensor reading fits in one frame — there is nothing to erasure-code. The unit of loss is the whole message, and a lost message is simply re-emitted by the sensor on a later pass (energy permitting) or handled by DTN custody. Erasure only re-enters if we *batch* many readings into a larger downlink object on the sat→ground leg, where the existing `erasure.py` design applies unchanged. **Be honest: for the sensor→sat leg, erasure coding is not the pillar.**

**Net:** ETP's fit for IoT backhaul is **DTN + provenance + amortized PQC**, *not* per-message sealing or per-message erasure. The protocol earns its place on authentication/provenance and delay-tolerance, and it must be re-shaped so the PQC cost is paid per *session*, not per *message*.

---

## 5. ETP module impact for IoT backhaul

| Module | Action | Why / what changes for this use case |
|---|---|---|
| `bridge/` (ML-KEM seal, RelayPacket) | **Reuse pattern, re-scope to per-session** | Seal establishes an *epoch key*, not a per-message key. One ~1.3 KB seal amortized over N messages. |
| `sequencing.py` | **Reuse (core value)** | Monotonic per-signer seq + temporal expiry = cross-pass replay protection for bursts. Central to provenance. |
| `shards.py` (per-shard XChaCha20-Poly1305) | **Reuse as single-frame AEAD** | Degenerate k=n=1 case: one message = one AEAD-protected frame under the epoch key. |
| `anchor/`, `backends/`, contracts | **Reuse, ground-side** | Batch-anchor received readings for provenance; off the flight/sensor critical path. |
| `hsm.py` | **Reuse for provisioning** | Sensor identity keys and the ground trust root; see key-provisioning risk (§7). |
| `erasure.py` | **Defer / batch-only** | Not used on the sensor→sat leg; applies only if batching readings for the downlink object. |
| `commitment.py` | **Mostly N/A** | k-of-n reconstruction unused for single-frame messages; drop for this path. |
| `network/*` (gRPC), `protocol.py` timeouts, `streaming.py` | **Replace** (shared with `CUBESAT_SCOPE.md` §4) | gRPC/HTTP2, 10/30/60 s timeouts, 64 KB chunks all assume a live socket — gone. Use the `spacelink` DTN shim. |
| `network/spacelink/` (from parent scope) | **NEW, reuse from CUBESAT_SCOPE** | Same convergence shim; profile it for burst-size frames and hour-scale bundle lifetimes. |
| **`sensor-core` (new, out-of-repo flight/edge)** | **NEW** | Tiny C ML-KEM decap/encaps + XChaCha20-Poly1305 + seq counter, sized for Cortex-M0+/M4. The Python repo is the *ground reference*. |

---

## 6. Worked mini-example — the overhead problem and its fix

**The problem (per-message sealing).** Take a typical 20-byte soil-moisture reading.

- ML-KEM-768 ciphertext ≈ 1088 B; a `bridge` RelayPacket seal ≈ **~1.3 KB** with framing/nonce/AAD.
- Overhead ratio if sealed per message: `1300 / 20 ≈ 65×`. The crypto is 65 times the data.
- Energy: at ~1–3 kbps, transmitting ~1.32 KB costs **~3.5–10 s of TX at ~1 W ≈ 3.5–10 J per message**, versus ~0.05–0.15 J for the 20-byte payload alone. On a 2.4 kJ coin cell that is a few hundred sealed messages before the battery is a limiting factor — a non-starter for a multi-year sensor.

**The fix (per-session / per-epoch key).** Do the KEM **once per epoch**, not per message.

1. **Provisioning / re-key:** the sensor performs *one* ML-KEM-768 exchange to establish an epoch key `K_e` (seal sent/anchored once — the ~1.3 KB cost is paid a single time, or during a rare re-key).
2. **Steady state:** each reading is a single XChaCha20-Poly1305 frame under `K_e`:
   `payload (20 B) + 24 B nonce (or 8 B counter-derived) + 16 B tag + ~4 B seq/hdr ≈ 48–64 B on the wire`.
3. **Overhead ratio drops from ~65× to ~2–3×** — dominated by the unavoidable 16-byte AEAD tag + nonce, which is the floor for *any* authenticated scheme, PQC or not.

**Amortization math:** spread one 1300 B seal over an epoch of, say, 1000 messages → **1.3 B of KEM cost per message**, negligible. Even a conservative 100-message epoch gives 13 B/message. The KEM stops being the bottleneck; the AEAD tag becomes the floor. This is the single most important design decision for the use case: **ETP's constant-size seal is a per-session primitive here, never a per-message one.**

(ML-KEM-768 on a Cortex-M4, per pqm4: encaps/decaps are **~1–4 ms** and a few KB of stack — cheap in *time*, but the ~1.3 KB *transmit* cost is what we amortize. On a Cortex-M0+ it is slower/tighter but still feasible for a rare epoch handshake, not a per-message op.)

---

## 7. Use-case-specific risks

- **Sensor MCU crypto footprint.** ML-KEM-768 keygen/encaps needs ~a few KB of stack + the ~2.4 KB public key / ~1.2 KB secret key material. On an 8–32 KB-RAM Cortex-M0+ this is tight but feasible for a *rare* epoch op; it is *not* feasible to run per wake-up. Mitigation: epoch keys (§6), store `K_e` in RAM/retained NVM across wakes, keygen offline where possible. ML-DSA-65 *signing* on-sensor (~3.3 KB signature, heavier compute) is likely too costly — prefer a short symmetric MAC / seq binding on the sensor and reserve ML-DSA for ground-verifiable identity at provisioning.
- **Key provisioning at scale.** Millions of sensors each needing a unique, attested keypair is the real operational hazard. Per-device keygen + enrollment via `hsm.py`-rooted trust, batch factory provisioning, and a revocation path are all required. This dwarfs the on-orbit problem in effort.
- **Overhead ratio / re-key cost.** Amortization only holds if epochs are long. Frequent re-keys (lost `K_e` after brownout, forward-secrecy policy, revocation) re-incur the ~1.3 KB seal and drain battery. Needs an explicit epoch-length ↔ battery ↔ forward-secrecy trade study.
- **Replay & clock skew.** Cross-pass replay defense (`sequencing.py`) needs monotonic seq that survives sensor resets and a ground-side skew window, since coin-cell sensors have poor RTCs. Persist the counter in NVM; treat wall-clock as advisory.
- **Downlink-to-sensor scarcity.** Re-key or NACK to the sensor is expensive/rare. Design so the *sensor* almost never needs to receive — epoch rotation should be schedule-driven, not interactive.

---

## 8. Minimal demo / MVP buildable in THIS repo

Goal: prove *amortized PQC + replay-bound provenance over a delay-tolerant hop* using only the existing Python core plus the `spacelink` loopback shim from `CUBESAT_SCOPE.md` Phase 1. No radio, no MCU port.

1. **`SensorSim`** — emits 20-byte readings on a schedule. On first run, does one `bridge` ML-KEM-768 seal to establish `K_e`; thereafter emits `shards.py` k=n=1 XChaCha20-Poly1305 frames under `K_e` with a `sequencing.py` monotonic counter. Log bytes-on-wire per message.
2. **`SatCustodySim`** — the existing file-based store-and-forward bundle queue (`network/spacelink` loopback): buffer frames, inject an *hours-long* delay and random burst loss, then release on a simulated pass.
3. **`GroundSink`** — verify AEAD + seq (reject replays/expired via `sequencing.py`), decrypt, then **batch-anchor** a Merkle root of received readings through the existing `anchor/`/backends path (testnet or mock).
4. **Metrics the demo must print:** (a) overhead ratio per message *with* vs *without* amortization (target: ~65× → ~2–3×, §6); (b) KEM cost amortized per message across an epoch; (c) replayed/expired bursts correctly rejected; (d) end-to-end provenance receipt for a delayed reading.

**Success criterion:** a 20-byte reading survives an hours-long store-and-forward gap, is proven unforgeable and non-replayable at the ground, gets an anchored provenance receipt, and the measured per-message PQC overhead is amortized to a few bytes — quantifying the honest §4 claim that ETP fits IoT backhaul on *provenance + delay-tolerance + amortized PQC*, not on per-message sealing.

---

*Scope only — reuses the ETP-Sat architecture and DTN/compute-split decisions from [`CUBESAT_SCOPE.md`](../../CUBESAT_SCOPE.md). The IoT-specific delta is: the sensor is the constrained endpoint, sealing must be per-session, and erasure coding recedes in favor of DTN custody + provenance anchoring.*

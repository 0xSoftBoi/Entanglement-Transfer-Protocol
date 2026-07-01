# ETP Use Case — Tactical / Defense DIL Networks

**Author:** scoping note, GSX / ETP
**Status:** Use-case scope — no tactical-radio code yet
**Domain:** Terrestrial defense comms (NOT satellites, NOT blockchain). See [`CUBESAT_SCOPE.md`](../../CUBESAT_SCOPE.md) for the shared constant-size-seal + k-of-n + store-and-forward architecture this reuses.

---

## 1. One-line pitch

Post-quantum, erasure-coded, store-and-forward transport for tactical DIL (Disconnected, Intermittent, Limited-bandwidth) networks — so classified traffic survives jamming, radio blackouts, and untrusted coalition relays, and stays secret against harvest-now-decrypt-later for the decades a classification marking demands.

## 2. Domain & who buys it

Middleware that sits above the radio/waveform and below the mission application. It moves files, orders, imagery, sensor tracks, and PLI (position-location information) across links that drop constantly and relays that are only partly trusted.

**Buyers / programs:**
- Army / USMC tactical network shops (integrators around the ITN — Integrated Tactical Network, and Capability Set fielding).
- SOF and coalition data-sharing cells (Mission Partner Environment, coalition CDS boundaries).
- UAV/drone-swarm and counter-UAS vendors needing mesh data survivability.
- Subsea / undersea programs (submarine comms, seabed sensors, UUV recovery).
- Prime contractors (radio + C2 integrators) who need a PQC transport layer that is waveform-agnostic.

The buyer is almost never buying a radio; they are buying the *data-survivability and crypto layer* that rides whatever radio they already fielded.

## 3. Operating profile (the DIL reality)

| Link / bearer | Typical rate | Loss / disruption | Disconnection |
|---|---|---|---|
| SINCGARS (legacy VHF FH) | ~16 kbps (voice/data) | Heavy under FH + jamming | Seconds–minutes on the move |
| Link-16 (TDMA) | ~28.8–115 kbps net, slotted | Slot contention, LOS-limited | Terrain masking, NLOS gaps |
| MANET waveforms (TSM, MPU5, Silvus) | ~2–50 Mbps, degrades with hops/range | Multipath, per-hop loss, jamming | Node churn, mobility |
| Dismounted soldier radio (Leader/ITN) | tens of kbps–few Mbps | Body/foliage shadowing | Frequent, unplanned |
| UAV/swarm mesh | 1–20+ Mbps LOS | Range/attitude fades | Beyond-LOS = blackout |
| Subsea acoustic | **~0.1–10 kbps**, high latency (~1.5 km/s sound) | Multipath, Doppler, very high BER | Minutes; comms windows only |

**Three hard constraints (ranked):**
1. **Intermittency / disconnection** — links drop for seconds to hours; the app must not assume a live socket.
2. **Loss + jamming** — bursty, adversarial loss; ARQ round-trips waste a scarce, contested channel.
3. **Untrusted relays + longevity** — data transits coalition/mesh nodes you don't fully trust, and must stay secret for decades.

## 4. Why ETP fits — pillars ranked

1. **PQC for decades-long secrecy (highest value).** Tactical/classified traffic is recorded by adversaries today for later decryption. ETP already ships real ML-KEM-768 (FIPS 203) + ML-DSA-65 (FIPS 204) + XChaCha20-Poly1305 — post-quantum *at fielding*, not as a retrofit. Directly answers harvest-now-decrypt-later on classified links.
2. **Erasure coding over lossy/jammed RF.** Reed–Solomon k-of-n (`erasure.py`, GF(256)) turns bursty loss into a non-event: spray *n* shards, reconstruct from any *k*. No chatty ARQ handshake burning a contested channel — forward correction, not feedback.
3. **DTN store-and-forward for disconnected ops.** The `commit → seal → materialize` flow does not need both ends live at once. A sealed bundle waits in a per-node queue and re-sprays when the next contact window opens — the terrestrial twin of the CubeSat pass-window model.
4. **Seal-and-forward through untrusted relays.** The `bridge/` pattern (constant-size ~1.3 KB ML-KEM sealed key + untrusted-relay `RelayPacket`) maps exactly onto a coalition mesh: relay nodes forward ciphertext + sealed key and learn nothing. Per-shard XChaCha20-Poly1305 (`shards.py`) means every shard is independently encrypted on a broadcast medium.
5. **Replay / temporal binding.** `sequencing.py` (monotonic per-signer sequence + temporal expiry) blocks replayed orders across intermittent reconnects — the tactical analogue of replay-across-passes.

## 5. ETP module impact (reuse / modify / new)

| Module | Action | Notes |
|---|---|---|
| `bridge/` (ML-KEM seal, `RelayPacket`) | **Reuse pattern** | Untrusted-relay seal-and-forward *is* the coalition-mesh model; ~1.3 KB key is constant regardless of payload |
| `erasure.py` (RS GF(256) k-of-n) | **Reuse design, accelerate** | Correct primitive; port GF(256) hot loop to C/Rust for embedded radios; consider rateless/fountain for unknown jamming loss |
| `shards.py` (per-shard AEAD) | **Reuse** | Independent per-shard XChaCha20-Poly1305 — ideal for spray-and-reconstruct over a broadcast/jammed medium |
| `commitment.py` (k-of-n reconstruct) | **Reuse** | Threshold reconstruction; drop the economics/eviction bits for the tactical path |
| `sequencing.py` | **Reuse** | Monotonic replay + temporal binding across reconnects |
| `hsm.py` | **Reuse** | Key custody in a HAIPE/CCI-adjacent module; signing keys never on the relay |
| `merkle_log/` (RFC 6962) | **Reuse** | Tamper-evident provenance/chain-of-custody log for coalition audit — replaces on-chain anchoring entirely |
| `protocol.py` (timeouts) | **Rework** | Second-scale timeouts → contact-window / bundle-lifetime semantics (minutes–hours) |
| `streaming.py` (64 KB chunks) | **Reprofile** | Chunk/shard size to fit a contested slot / acoustic frame, not a sustained TCP pipe |
| `network/*` (gRPC/HTTP2) | **Replace** | No live socket over DIL; swap for a DTN/BPv7 (RFC 9171) convergence shim — same gap as the CubeSat spacelink shim |
| `network/dilink/` | **NEW** | Convergence layer: fixed-size shard framing, store-and-forward contact-window queue, waveform/DTN adapter (loopback + file-backed store first) |
| `TacticalDILProfile` config | **NEW** | `frame_bytes`, `contact_budget_bytes`, `n`, `k`, `uplink_bps`, `max_disconnect` — analogue of CubeSat's `SpaceLinkProfile` |

## 6. Worked mini-example (one concrete number)

**Scenario:** dismounted team, SINCGARS-class bearer at **16 kbps**, pushing a 50 KB compressed FRAGO/overlay through a mesh with an untrusted coalition relay in the path.

- **Sealed key cost:** the ML-KEM-768 sealed key is ~1.3 KB *regardless of payload size*. Over 16 kbps that is `1.3 KB × 8 / 16000 ≈ **0.65 s**`. Post-quantum key establishment costs under a second of a scarce, jammed channel — and does **not** grow with the data protected.
- **Payload:** 50 KB at 16 kbps ≈ 25 s of channel. With RS `n/k` overhead ρ ≈ 0.3 (jamming margin), transmit ~65 KB of shards ≈ ~33 s; any **k** shards reconstruct — a jammer dropping ~20% of shards mid-burst still yields delivery with no ARQ round-trip.
- **Contrast:** a classical TLS/gRPC handshake needs a live bidirectional socket and multiple round-trips — it simply fails to *complete* across a link that drops every few seconds. ETP's one-shot sealed bundle + forward erasure completes across the same gap.

## 7. Risks / where it's a poor fit (honest)

- **Accreditation is the gate, not the code.** NSA CSfC / Suite/CNSA 2.0, FIPS 140-3 validation, and program-specific ATO dominate. ML-KEM/ML-DSA align with CNSA 2.0 direction, but *this Python implementation is a reference*, not a validated cryptographic module — fielding needs a validated (likely C, HAIPE-adjacent) core.
- **GOTS/COTS friction.** Defense integrators favor GOTS (e.g. existing DTN/CCSDS stacks, government crypto) or accredited COTS. ETP enters as a *layer above the waveform*, not a crypto replacement for fielded HAIPE/Type-1 devices — positioning matters.
- **Latency-sensitive traffic is the wrong target.** Real-time voice and time-critical fires (Link-16 J-series) need bounded low latency; erasure + store-and-forward adds buffering delay. ETP fits *file/imagery/sensor/PLI bulk and delay-tolerant C2*, not sub-second closed-loop control.
- **Erasure overhead on the tiniest bearers.** On subsea acoustic (~0.1–10 kbps), even ρ ≈ 0.3 overhead and shard framing hurt; may need aggressive rateless coding and profile tuning per bearer.
- **On-node signing cost.** ML-DSA-65 signatures (~3.3 KB) are ~1.7 s at 16 kbps — budget per-message signing carefully; verify-often, sign-less-often, keep signing keys in `hsm.py`.
- **No radio delivered.** ETP is waveform-agnostic middleware; someone still owns the SDR/waveform, spectrum, and EMCON discipline.

## 8. Minimal in-repo MVP

A demo that runs entirely in-repo with **zero** radio hardware, reusing the crypto/coding core unchanged:

1. **`TacticalDILProfile`** config object (mirror `SpaceLinkProfile` from `CUBESAT_SCOPE.md`): `frame_bytes=1024`, `n`, `k`, `uplink_bps=16000`, `max_disconnect`.
2. **`network/dilink/` loopback shim:** fixed-size shard framing + a **file-backed store-and-forward queue** standing in for a contact window; inject a *loss/jamming model* (drop X% of shards, blackout for T seconds) into the existing simulator.
3. **Pipeline:** `protocol.commit` → `bridge` seal (ML-KEM-768) → `erasure.encode` n-of-k → per-shard `shards` AEAD → enqueue → simulate blackout + jamming loss → dequeue → `commitment` k-of-n reconstruct → `merkle_log` append (tamper-evident chain-of-custody receipt).
4. **Assertion:** payload reconstructs from any *k* shards after a simulated 30 s blackout with 20% shard loss, through an untrusted relay that only ever sees ciphertext + the ~1.3 KB sealed key.

This exercises the exact reuse story — the PQC + erasure + seal-and-forward + Merkle-log core is untouched; only the convergence shim and profile are new, matching the additive approach in [`CUBESAT_SCOPE.md`](../../CUBESAT_SCOPE.md).

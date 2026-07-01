# ETP Use Case — Critical Infrastructure & Industrial OT

**Author:** Javier Calderon Jr, CTO of Global Settlement (GSX)
**Status:** Use-case scoping — terrestrial profile
**See also:** `CUBESAT_SCOPE.md` (shared transport/crypto core architecture), `docs/THREAT_MODEL.md`

---

## 1. One-line pitch

Post-quantum confidentiality, authenticated command, and tamper-evident audit for remote SCADA/telemetry running over flaky cellular/radio/VSAT backhaul — so 20–30-year infrastructure assets are protected against *harvest-now-decrypt-later* starting at the next maintenance window, not the next hardware refresh.

## 2. Domain & who buys it

Remote **operational technology (OT)** for critical infrastructure: gas/oil pipelines, electric-grid substations and reclosers, offshore rigs, water/wastewater plants and lift stations, mining sites, and remote solar/wind farms. These run SCADA masters polling thousands of RTUs/PLCs over DNP3, Modbus, and IEC 60870-5-101/104.

**Buyers:** utility and pipeline OT/ICS security teams; the SCADA integrators and RTU/gateway OEMs that ship the field boxes (SEL, Schneider, GE, Emerson, Siemens); and compliance owners on the hook for **NERC-CIP** (CIP-011 information protection, CIP-013 supply chain) and, increasingly, the EPA/water-sector and TSA pipeline security directives. The wedge is a **field gateway** or protocol-translator sitting between the RTU serial/Ethernet port and the backhaul modem — not a rip-and-replace of the RTU itself.

## 3. Operating profile

| Parameter | Representative value | Implication |
|---|---|---|
| Field protocols | DNP3, Modbus/TCP & RTU, IEC 60870-5-101/104 | Small, structured, request/response; not stream-shaped |
| Modbus register read | ~10–60 bytes application data | Payload is *tiny* vs. any crypto header |
| DNP3 read response | ~20–250 bytes typical | Class-0/1/2/3 event polls, still small |
| IEC 60870-104 ASDU | ~15–255 bytes | Same order of magnitude |
| Poll cadence | integrity poll 5–60 s; exception/RBE reporting sub-second to seconds | Many small messages, steady drip |
| Command traffic | operate/select-before-operate, setpoints — rare but *high consequence* | Authenticity dominates confidentiality here |
| Cellular backhaul (LTE-M/CAT-1) | 0.1–10 Mbps, but often shared/contended; APN latency 50–300 ms | "Good enough" but drops on tower congestion/weather |
| Licensed radio (900 MHz/450 MHz MAS) | **9.6–128 kbps**, half-duplex, polled | Bandwidth genuinely scarce; per-byte overhead matters |
| VSAT | 0.25–2 Mbps, 500–700 ms RTT, weather-faded | High latency + rain-fade outages |
| Backhaul availability | 95–99.5% on remote sites; multi-minute to multi-hour outages | **Store-and-forward is mandatory** |
| Site power | mains, or solar+battery on remote RTUs (single-digit watts) | Compute budget on the RTU is real |
| NERC-CIP retention | security event logs **≥ 90 days online**, audit records **3 years** | Long-lived, tamper-evident audit is a hard requirement |

The defining constraints, ranked: (1) **intermittency** — backhaul drops and telemetry must buffer and resume; (2) **command authenticity** — a spoofed `operate` can open a breaker or a valve; (3) **long-horizon confidentiality** — traffic recorded today must stay secret for the asset's 20–30-year life; (4) **compliance-grade audit** — every control action must be provable after the fact.

## 4. Why ETP fits — pillars, ranked

1. **PQC confidentiality (harvest-now-decrypt-later defense).** The strongest fit. Substation and pipeline traffic is recordable off the air/wire today and decryptable later under a CRQC. Assets commissioned now live to ~2050; classical ECDH/RSA does not. ETP ships **real ML-KEM-768 (FIPS 203) + XChaCha20-Poly1305** — PQC at commissioning, not retrofit.
2. **Command authentication + anti-replay.** `envelope.py` (ML-DSA-65, FIPS 204) signs control commands; `sequencing.py` enforces **per-signer monotonic sequence numbers + temporal expiry**, which is exactly the defense DNP3 Secure Authentication (SAv5) reaches for — a replayed `operate` from a prior orbit/session is rejected.
3. **Tamper-evident audit (NERC-CIP).** `merkle_log/` is an RFC 6962 (Certificate-Transparency-style) append-only log with inclusion/consistency proofs. Every command and setpoint change gets a portable proof (`portable_proof.py`), giving auditors cryptographic evidence that the control-action record was not altered — satisfying CIP-007/CIP-011 evidence needs. **No blockchain required.**
4. **Delay-tolerant buffering over flaky backhaul.** Erasure coding + store-and-forward lets telemetry survive outages: shards buffered locally, sprayed when the link returns, reconstructed from any *k*-of-*n*. Same forward-not-feedback model as the CubeSat profile (`CUBESAT_SCOPE.md` §5.2), minus the orbital mechanics.
5. **Constant-size key establishment.** The ~1.3 KB ML-KEM sealed key is O(1) in payload — amortized across a session it is negligible even on a 9.6 kbps MAS radio (see §6).

## 5. ETP module impact

| Module | Action | Notes for OT profile |
|---|---|---|
| `src/ltp/bridge/` (ML-KEM ~1.3 KB seal) | **Reuse as-is** | Session key establishment field-gateway ↔ SCADA head-end; O(1) in payload |
| `src/ltp/shards.py` (per-shard XChaCha20-Poly1305) | **Reuse** | AEAD per shard; nonce discipline already independent per shard |
| `src/ltp/erasure.py` (RS GF(256) k-of-n) | **Reuse, reprofile** | Small `n`,`k` for tiny payloads; batch a poll cycle before coding to avoid per-message overhead |
| `src/ltp/sequencing.py` | **Reuse** | Monotonic per-signer sequence + expiry = anti-replay for commands (DNP3 SAv5-equivalent) |
| `src/ltp/envelope.py` (ML-DSA-65) | **Reuse, budget** | Sign commands head-end→field; batch/verify telemetry signatures to protect uplink |
| `src/ltp/merkle_log/` | **Reuse** | Command/setpoint audit log; export portable proofs for NERC-CIP evidence |
| `src/ltp/hsm.py` | **Reuse** | Signing-key custody at the SCADA head-end / control center |
| `src/ltp/commitment.py` | **Reuse (reconstruction)** | k-of-n reassembly; drop the economic eviction/strike path |
| `src/ltp/protocol.py` timeouts | **Rework** | Second-scale RPC timeouts → outage-tolerant session lifetime; resume across reconnects |
| `src/ltp/streaming.py` | **Reprofile** | 64 KB chunks are wrong for 40-byte reads; small-frame + poll-cycle batching |
| `src/ltp/network/*` (gRPC/HTTP2) | **Replace on field link** | HTTP/2 needs a live socket; add a store-and-forward queue + protocol adapter. Keep gRPC for control-center segment only |
| `src/ltp/network/otlink/` | **NEW** | Field convergence shim: DNP3/Modbus/IEC-104 protocol adapter, local buffer/queue, small-frame shard framing, backpressure on reconnect |

## 6. Worked mini-example

**Setpoint session over a 9.6 kbps licensed MAS radio, RTU polled every 10 s.** A Modbus read response is ~40 bytes.

- **Naive per-message keying** would attach a fresh ~1.3 KB seal to every 40-byte reading: overhead ratio ~33:1, and 1.3 KB over 9.6 kbps ≈ **1.1 s of airtime per poll** — unaffordable on a half-duplex polled radio.
- **ETP session keying:** establish the ML-KEM session key **once per session** (~1.3 KB, ~1.1 s, one time), then each 40-byte reading carries only the XChaCha20-Poly1305 tag+nonce (~40 bytes overhead). Over an 8-hour shift at 10 s cadence that is **2,880 readings**; the ~1.3 KB seal amortizes to **~0.46 bytes/reading** — effectively free. Confidentiality cost per reading is dominated by the fixed AEAD tag, not the PQC key.
- **Command + audit path:** a dispatcher `operate` command is ML-DSA-65 signed (`envelope.py`), sequence-bound (`sequencing.py`, rejecting any replay from a prior session), and appended to the `merkle_log/`. The auditor later pulls a portable inclusion proof showing *this exact command, at this sequence, at this time* is in the immutable record — NERC-CIP evidence without trusting the SCADA historian's mutable database.

**Takeaway:** PQC keying is a one-time ~1-second tax per session; per-reading overhead is a fixed AEAD tag; and every control action is independently provable. All three costs are flat in payload size — the property that makes ETP fit a scarce, drip-fed OT link.

## 7. Risks / where it's a poor fit

- **Real-time protection latency.** Teleprotection and bus-transfer schemes demand **sub-10 ms** (IEC 61850 GOOSE/SV, 3–4 ms). ETP's per-message AEAD is fine, but erasure batching, store-and-forward, and any PQC handshake on the critical path are **not** for hard-real-time protection loops. Target supervisory SCADA and telemetry, not protection relaying.
- **RTU compute footprint.** ML-KEM decap is milliseconds on a Cortex-M4, but the pure-Python core here is a *reference/head-end* implementation. Legacy RTUs (8/16-bit, sub-MHz, KB of RAM) cannot run it — the field side needs a small C/Rust core on the gateway, not the RTU MCU. Greenfield gateways and modern edge RTUs only.
- **Retrofit friction.** Brownfield OT is allergic to change; touching a certified control path triggers re-validation. The realistic insertion point is a **bump-in-the-wire gateway** that speaks native DNP3/Modbus to the RTU and ETP to the head-end — additive, not a protocol change on the RTU.
- **Erasure overhead on tiny payloads.** RS k-of-n shines on larger blocks; on a single 40-byte read it is pure overhead. Value comes from **batching a poll cycle** (or buffered backlog after an outage) before coding — otherwise skip erasure and lean on session AEAD + store-and-forward.
- **Signature size vs. scarce radio.** ML-DSA-65 signatures (~3.3 KB) are ~2.7 s on a 9.6 kbps link — fine for rare commands, wrong for per-reading telemetry. Sign commands and periodic batch-attest telemetry; do not sign every poll.
- **Clock/sequence discipline.** Anti-replay and audit rely on monotonic sequence + temporal expiry; remote sites with poor time sync need a defined resync path (`sequencing.py` expiry windows must tolerate field clock drift).

## 8. Minimal in-repo MVP

Additive, no changes to existing behavior — mirrors the CubeSat profile's `spacelink` shim (`CUBESAT_SCOPE.md` §5.3):

1. **`OTLinkProfile` config object** (analogous to `SpaceLinkProfile`/`StreamConfig`): `protocol` (dnp3|modbus|iec104), `frame_bytes`, `poll_cadence_s`, `link_bps`, `max_disconnect_s`, `batch_window_s`, `n`, `k`.
2. **`src/ltp/network/otlink/`** — a convergence shim with: (a) a **protocol adapter** that ingests DNP3/Modbus/IEC-104 PDUs (start with Modbus/TCP — simplest framing), (b) a **file-based store-and-forward queue** buffering during outages and draining on reconnect, (c) **poll-cycle batching** before erasure so tiny reads amortize framing, (d) a software loopback + simulated-outage harness (reuse the existing test simulator) — no real radio/modem needed for the MVP.
3. **Command path demo:** sign an `operate` with `envelope.py`, bind it with `sequencing.py`, append to `merkle_log/`, and emit a `portable_proof.py` inclusion proof as the NERC-CIP audit artifact.
4. **Amortization test:** assert the §6 numbers — one seal per session, fixed AEAD overhead per reading, session survives a simulated multi-minute backhaul outage and resumes without key re-establishment or replay acceptance.

Phase 2 (out of MVP): real modem/radio integration, additional protocol adapters (DNP3 SAv5 interop, IEC-104), and an optional ground-side GSX anchor of the Merkle STH for cross-org provenance — off the control critical path.

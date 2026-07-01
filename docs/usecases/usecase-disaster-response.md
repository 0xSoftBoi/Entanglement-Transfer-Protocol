# ETP Use Case — Disaster Response & Humanitarian Off-Grid Networking

**Author:** Javier Calderon Jr, CTO of Global Settlement (GSX)
**Date:** July 1, 2026
**Status:** Scoping / design — terrestrial delay-tolerant profile
**Related:** [`CUBESAT_SCOPE.md`](../../CUBESAT_SCOPE.md) — shares the same transport + crypto core (constant-size seal, k-of-n erasure, DTN store-and-forward). This document reuses that architecture; the domain is terrestrial, not orbital.

---

## 1. One-Line Pitch

**Post-quantum, erasure-coded, store-and-forward transport for moving sensitive humanitarian data (medical, biometric, refugee registration) across destroyed or absent infrastructure — over intermittent mesh links and physical "data mules," with confidentiality that must hold for decades.**

## 2. Domain & Who Buys It

When an earthquake flattens a city's fiber and cell towers, or a clinic operates three valleys from the nearest tower, or a conflict zone has no trustworthy network at all, data still has to move: patient records to a referral hospital, refugee registrations to a central roster, damage assessments to a coordinating body. Today this is done by hand-carried USB sticks, WhatsApp when a bar of signal appears, or paper. All three leak, lose data, and offer no confidentiality against a hostile actor who seizes a device.

**Who buys / adopts:**
- **NGOs & humanitarian orgs** — MSF, IRC, IFRC/Red Cross, Save the Children (field clinics, cold-chain logistics, beneficiary registration).
- **UN agencies** — UNHCR (refugee registration/PRIMES-adjacent workflows), WFP (SCOPE beneficiary data), OCHA (situational reporting).
- **National disaster agencies & first responders** — FEMA-class bodies, search-and-rescue, field triage teams.
- **Field medical teams / EMTs** — mobile clinics, epidemic response (contact tracing rosters).

The buyer is rarely flush with cash (see §7). The wedge is **data protection obligations** (GDPR Art. 9 special-category data, UNHCR data-protection policy, medical confidentiality) colliding with **no network**. That combination is exactly where ETP has something no off-the-shelf tool offers.

## 3. Operating Profile

**Links (real numbers):**
- **Wi-Fi mesh** (802.11s / BATMAN-adv / commodity gear like goTenna Pro, or Meshtastic gateways): **1–50 Mbps** at short range, degrading fast with distance/obstruction; hop count and interference dominate.
- **LoRa / Meshtastic** for text-scale telemetry: **0.3–37.5 kbps** raw, realistically **~1–5 kbps** usable, but kilometers of range at milliwatts — good for "the mule is 8 km out, still alive" beacons, not bulk data.
- **Cellular when it flickers back** (2G/3G fallback, satellite backhaul like Starlink/BGAN where available): opportunistic, unpredictable windows.
- **Physical "data mules"** (DakNet precedent, MIT/First Mile Solutions, rural India ~2004): a vehicle, drone, or a health worker's phone physically ferries data between disconnected pockets. Effective "bandwidth" is enormous but latency is **hours**. A 128 GB card carried on a daily truck run ≈ hundreds of GB/day at multi-hour latency — the classic "never underestimate the bandwidth of a station wagon full of tapes."

**Disconnection:** gaps of **hours to days** are normal. A field clinic may see a mule once per day; a mesh island may be islanded for a week after a quake until a relay is repositioned.

**Data types & sizes:**
- Patient encounter record (structured + notes): **2–20 KB**.
- Refugee registration record (demographics + consent): **1–5 KB**; with **biometric templates** (fingerprint/iris minutiae, not raw images) **+5–20 KB**; with a face photo **+50–200 KB**.
- Daily clinic caseload: **50–300 records** ⇒ **~1–30 MB/day** typical; a registration surge can hit hundreds of MB.
- Situational reports, forms, small photos: KB to low-MB each.

The data is small per-record, high-sensitivity, and must survive lossy links and untrusted couriers.

## 4. Why ETP Fits — Pillars Ranked

1. **PQC confidentiality for decade-long sensitivity (highest value here).** Refugee identity, biometrics, and medical data are dangerous to the individual *for their lifetime* — a persecuted person's biometric leaked in 2026 is still a threat in 2046. This is a textbook **harvest-now-decrypt-later** target: a hostile actor seizes a mule or sniffs a mesh link today and stores the ciphertext. ETP's ML-KEM-768 sealed key + XChaCha20-Poly1305 per-shard AEAD (`bridge/`, `shards.py`) means seized ciphertext stays confidential even against a future quantum adversary. **This is the core value; it stays.**
2. **DTN store-and-forward over hours-to-days gaps.** No live socket exists. ETP's three-phase commit→seal→materialize semantics decouple sealing from delivery, so a sealed record can sit in a mule's store for a day and materialize on arrival. (This is the same store-and-forward pillar as `CUBESAT_SCOPE.md` §5, minus the RF layer.)
3. **k-of-n erasure over lossy improvised links.** Mesh hops drop; a mule can be lost, seized, or turn back. Split each batch into `n` shards so any `k` reconstruct (`erasure.py`, Reed-Solomon GF(256); `commitment.py` reconstruction). Send shards across *multiple* mules / *multiple* mesh paths — losing one courier or one link costs nothing.
4. **Seal-and-forward through untrusted relays.** The person carrying the drive is often a local contractor, a passing driver, or a partner-org volunteer you do not fully trust. ETP's untrusted-relay model (`bridge/` RelayPacket) means the relay ferries a constant-size ~1.3 KB sealed key + encrypted shards and **can decrypt none of it**.
5. **Tamper-evident provenance without a blockchain.** For chain-of-custody on medical/registration data, the Merkle log (`merkle_log/`, RFC 6962 CT-style, ML-DSA-signed tree heads) gives an append-only, verifiable record of what was received when — **no on-chain settlement, no crypto-currency**. Provenance is a local audit artifact, not a ledger dependency.

## 5. ETP Module Impact

| Module | Action | Notes for this domain |
|---|---|---|
| `erasure.py` (RS GF(256) k-of-n) | **Reuse** | Correct primitive for multi-mule / multi-path spraying. Pure-Python is fine — field data volumes (MB/day) are tiny vs. a laptop's CPU. |
| `shards.py` (per-shard XChaCha20-Poly1305) | **Reuse** | Independent per-shard AEAD is ideal: a seized single shard reveals nothing. |
| `bridge/` (ML-KEM seal, RelayPacket, untrusted relay) | **Reuse pattern** | Relayer→materializer maps directly onto mule→base-station. Constant-size ~1.3 KB seal is the confidentiality anchor. |
| `commitment.py` | **Reuse (reconstruction)** | k-of-n reassembly at the receiving base station; drop bridge/economic strike logic. |
| `sequencing.py` | **Reuse** | Replay + temporal binding stops a re-couriered old batch being re-ingested; monotonic per-sender sequence across mule trips. |
| `merkle_log/` | **Reuse** | Local, offline provenance/chain-of-custody. Replaces on-chain anchoring entirely for this domain. |
| `hsm.py` | **Reuse (optional)** | Base-station signing key in an HSM/secure element; field devices hold only public keys + their own sealing material. |
| `streaming.py` | **Reprofile** | Chunk sizing driven by mule medium (USB/SD) or mesh MTU, not a 64 KB sustained-socket pipeline. |
| `protocol.py` | **Rework timeouts** | Second-scale RPC timeouts → batch/courier-lifetime semantics (hours/days), like the satellite pass-window rework. |
| `network/*` (gRPC/HTTP2) | **Replace / ground-only** | No live socket across the gap. **NEW** convergence shim needed: a file/removable-media store-and-forward queue + an opportunistic-mesh adapter. Keep gRPC only for the connected base-station↔HQ leg. |
| `anchor/`, `backends/`, contracts | **Drop from loop** | On-chain settlement is out of scope. Not used in the field path. |
| `network/fieldlink/` (analogue of `spacelink`) | **NEW** | Removable-media / mesh convergence layer: fixed-size framing, a disk-backed bundle store, a "sync when a peer/mule appears" adapter. |

## 6. Worked Mini-Example

**Scenario:** A field clinic registers **200 patient records/day**, each ~10 KB with a small biometric template ⇒ **~2 MB daily batch**. One truck ("mule") visits daily and carries an SD card to the district base station; connectivity is otherwise dead.

- The clinic laptop erasure-codes the 2 MB batch with **k = 4, n = 6** (`erasure.py`): 6 shards, any 4 reconstruct. Each shard ≈ **~0.5 MB**, individually sealed with XChaCha20-Poly1305 (`shards.py`).
- The symmetric key is sealed once under the base station's ML-KEM-768 public key ⇒ a **~1.3 KB constant-size sealed key** (`bridge/`), independent of the 2 MB payload.
- Shards + sealed key are split across **two couriers**: today's truck carries 4 shards, a health worker's phone (opportunistic mesh when it reaches the base station's Wi-Fi range) carries the other 2 plus a copy of the sealed key.
- **Fault tolerated:** if the truck is stopped, seized, or breaks down (one courier lost), the base station still has ≥ 4 shards from the surviving path and **reconstructs the full day's records** (`commitment.py`). The seized SD card yields only sealed ciphertext — **no patient data**, even to a future quantum adversary.
- On ingest, the base station appends a signed entry to the Merkle log (`merkle_log/`): provenance that "clinic-7's 2026-07-01 batch, 200 records, hash X, arrived intact" — verifiable, offline, no blockchain.

Uplink cost of post-quantum key establishment: **~1.3 KB per daily batch**, flat regardless of batch size. That is the whole "PQC tax" — negligible against a 2 MB payload or a 128 GB card.

## 7. Risks / Where It's a Poor Fit — Honestly

- **NGO budgets are thin and low-margin.** Humanitarian IT competes with food and medicine for funding. A security-middleware line item is a hard sell unless a donor/regulator *mandates* data protection. ETP wins on obligation, not on features — and only if it's cheap or free (OSS) to deploy.
- **Device provisioning at scale is the real problem, and ETP doesn't solve it.** Getting the right ML-KEM public keys, base-station roots, and device identities onto hundreds of field laptops/phones across a chaotic response is a logistics and key-management nightmare. That provisioning/enrollment layer is *unbuilt* here and is where most of the real deployment cost lives.
- **Usability for non-technical field staff.** A triage nurse will not run a CLI. This needs to disappear behind a one-button "sync" in an existing app (KoBoToolbox, ODK, CommCare, a clinic EMR). Without that integration, adoption is zero. ETP is a *library*, not a product, today.
- **Is PQC overkill vs. classical here?** For **short-lived operational data** (today's road-status report), yes — plain XChaCha20/TLS would do, and the PQC framing is dead weight. PQC earns its place **only** for the decade-sensitive subset: biometrics, refugee identity, medical history of persecuted persons. The honest scope is *"PQC for the lifetime-sensitive records, classical-adequate transport for the rest"* — over-applying PQC everywhere is a defensible default but not free (bigger keys, unfamiliar crypto, harder audits).
- **Power, storage, and heat** on field devices are constrained but far less than orbit; pure-Python is acceptable. The binding constraints are *human* (training, trust, funding), not *compute*.
- **Trust bootstrapping.** Seal-and-forward assumes the receiver's public key is authentic. In a conflict zone, distributing that key trustworthily (out-of-band, pre-deployment) is itself the hard security problem ETP presumes solved.

**Where ETP is clearly the wrong tool:** real-time voice/video coordination (that needs a live link, not store-and-forward); anything requiring interactive round-trips; contexts where paper is genuinely safer because devices get seized and staff coerced (ETP protects data-at-rest ciphertext, not staff under duress).

## 8. Minimal In-Repo MVP

Reuse the crypto/coding core unchanged; add a thin terrestrial convergence layer — the direct analogue of the satellite `spacelink` shim.

1. **`FieldLinkProfile` config object** (analogue of `SpaceLinkProfile` / `StreamConfig`): `frame_bytes`, `batch_bytes`, `n`, `k`, `medium` (`usb`/`sd`/`mesh`), `max_disconnect` (hours-days).
2. **`src/ltp/network/fieldlink/`** — a convergence shim:
   - **Removable-media store-and-forward:** write sealed shards + the ~1.3 KB sealed key + a manifest to a directory (an SD card mount); read/ingest the same on the receiving side. File-based bundle store, exactly as the satellite Phase 1 uses a file-based DTN queue.
   - **Opportunistic-mesh adapter:** "when a peer appears (mDNS/Wi-Fi range), sync outstanding shards" — a loopback/LAN implementation first, no radio.
3. **End-to-end demo test:** clinic batch (§6 numbers) → erasure-code (k=4,n=6) → per-shard seal → split across two "couriers" (two directories) → **drop one courier** → reconstruct + verify at the base station → append to Merkle log. This exercises `erasure.py`, `shards.py`, `bridge/`, `commitment.py`, `sequencing.py`, and `merkle_log/` with **zero new crypto**.
4. **No new crypto, no chain, no radio.** Everything in the field path is reuse plus glue; the only genuinely new code is framing + the store-and-forward/mesh adapter — mirroring `CUBESAT_SCOPE.md` §5.3.

**Explicitly out of scope for the MVP:** device enrollment/PKI at scale, the field-app UI integration, and the mesh radio driver — these are the real productization costs (§7) and are deferred, not hand-waved.

---

*This is a scoping document. The cryptographic and coding core (`erasure.py`, `shards.py`, `bridge/`, `commitment.py`, `sequencing.py`, `merkle_log/`) is reused unchanged; only the convergence layer (`network/*`) is replaced with a terrestrial store-and-forward/mesh shim. It shares its entire architecture with the CubeSat profile — the same three pillars, a different physical medium.*

# ETP Use Case: Secure TT&C / Command Authentication (Anti-Spoof C2)

**Author:** Javier Calderon Jr, CTO of Global Settlement (GSX)
**Date:** July 1, 2026
**Status:** Use-case scoping — child of [`CUBESAT_SCOPE.md`](../../CUBESAT_SCOPE.md)

> This brief scopes **one** CubeSat use case. Shared architecture — the
> constant-size ~1.3 KB PQC sealed key, k-of-n forward erasure coding, the
> DTN(BPv7)/CCSDS convergence layer that replaces gRPC, and the ground/flight
> compute split — lives in [`CUBESAT_SCOPE.md`](../../CUBESAT_SCOPE.md) and is
> **not** repeated here. Read that first for context.

---

## 1. One-line pitch

**Cryptographically authenticate the command uplink so an adversary with a dish
and a transmitter cannot forge, alter, or replay a command to your CubeSat** —
post-quantum ML-DSA-65 signatures verified on orbit, bound to a monotonic
per-signer sequence that survives across passes.

---

## 2. Mission profile & who buys it

This is the **low-volume, high-assurance control path** — the opposite of the
payload-downlink use case. A TT&C uplink carries a handful of short commands per
pass (deploy, mode change, thruster fire, safe-hold, key rotation). Volume is
trivial; the *consequence of a forged command is loss of the vehicle.*

**Who buys it:**

- **Defense / government smallsat operators** — command authentication is a
  hard requirement (cf. CCSDS SDLS, NIST SP 800-53). ML-DSA-65 lets them tick
  the "quantum-resistant, FIPS-204" box for a 5–15 yr mission commissioned today.
- **High-value commercial birds** — imaging, comms relay, any vehicle where a
  spoofed "point-and-fire" or "dump propellant" command is a mission-ending or
  liability event. These operators already fear the amateur-SDR threat surface.
- **Constellation operators** who share ground stations / GS-as-a-service and
  therefore cannot treat the ground segment as an implicit trust root.

The 2018 GAO and subsequent CISA advisories on unauthenticated satellite C2, plus
the widening availability of cheap SDR + tracking dishes, make "anyone can key up
your uplink" a live procurement concern, not a hypothetical.

---

## 3. Link / ops profile

| Parameter | Value | Note |
|---|---|---|
| Uplink band | **UHF, 435 MHz** (AX.25 / GMSK) | The near-universal CubeSat command band |
| Uplink rate | **9.6–19.2 kbps** (up to ~100 kbps on good radios) | Command path is *precious* — bytes cost seconds |
| Command cadence | **1–20 commands/pass**, often < 10 | Low-volume by design; bursty at start of pass |
| Command frame (CCSDS TC) | ~**8–256 B** payload; TC transfer frame ≤ 1024 B | Our signed envelope must fit a few TC frames |
| Usable pass | **5–12 min** (~8 min typical), 3–6 passes/day | ~30–60 min total contact/day |
| One-way light-time | 2–20 ms | Latency is negligible; **disruption** is the enemy |
| Disconnection gap | minutes–hours between passes | Replay window spans passes → sequencing must persist |
| Feedback | expensive (ARQ wastes the window) | Verify-and-execute, no chatty handshake |

**The uplink is the whole story here.** Unlike the downlink-heavy payload use
case, TT&C lives entirely on the scarce UHF uplink. Every byte of signature
overhead is charged directly against an 8-minute, ~576 KB/pass budget. That is
the central engineering tension: **strong PQC authentication vs. a kilobit uplink.**

---

## 4. Why ETP fits — pillars, ranked

ETP already ships the exact primitives this use case needs. Ranked by relevance:

1. **PQC signatures — ML-DSA-65 verify-on-orbit (the core).** Commands are
   signed on the ground in the mission-control HSM and verified on the bird.
   FIPS-204, quantum-resistant, no shared secret to exfiltrate from the vehicle.
   The satellite holds only the operator's *public* verify key — a captured bird
   yields nothing that lets an attacker forge commands. This is the pillar.
2. **Sequencing / replay-protection (`sequencing.py`) — the anti-replay spine.**
   A valid signed command captured off-air is still a valid signature. What stops
   it being replayed next pass is the **monotonic per-signer sequence** +
   **temporal expiry** in `sequencing.py`. This is what turns "signed" into
   "signed *and* fresh." Ranked #2 because a signature without replay binding is
   only half a C2 authentication story.
3. **Key custody (`hsm.py`) — signing keys never leave the ground.** The signing
   key lives in the mission-control HSM; the GS is a relay, not a trust root.
   Directly answers the "shared / compromised ground station" threat.
4. **Anchoring (`anchor/`) — optional command-log provenance.** Off the flight
   critical path: anchor the *ground-side* command journal (what was sent, when,
   by whom) to GSX for tamper-evident audit / non-repudiation. Nice-to-have for
   defense/gov accountability; explicitly **not** in the uplink loop.

The **seal (ML-KEM-768)** pillar is largely *out of scope* for pure C2 auth — TT&C
commands are authenticated, not confidential, and are short enough that we don't
need a payload key. The seal earns its keep on the payload/downlink use case; here
it is only relevant if a specific command must *also* be encrypted (e.g. carrying
a new key), in which case the shared ~1.3 KB sealed-key path from `bridge/` applies.

---

## 5. ETP module impact for this use case

| Module | Action | Why / what changes for TT&C |
|---|---|---|
| `sequencing.py` (`SequenceTracker`) | **Reuse ~as-is** | Per-signer monotonic seq + chain-binding + expiry is *exactly* command anti-replay. Rename `target_chain_id` → a mission/command-domain id; persist HWM across power cycles (SEU/reset survival). |
| ML-DSA verify (envelope / signatures) | **Reuse pattern, port hot path** | Verify-on-orbit is cheap; keep signing on the ground. Flight article verifies with a small C/Rust ML-DSA-65 verifier (pqm4-class). |
| `hsm.py` | **Reuse (ground)** | Command signing key custody in mission-control HSM; GS holds no signing authority. |
| `bridge/` (ML-KEM seal) | **Conditional reuse** | Only when a command must be confidential (key-rotation uplink). Reuse the constant-size sealed-key path unchanged. |
| `anchor/`, `backends/`, contracts | **Decouple (optional)** | Ground-side command-journal provenance, post-facto, off the flight loop. |
| `network/*` (gRPC/HTTP2) | **Replace** | No live socket on the uplink. Command frames ride CCSDS TC / DTN per parent scope. Keep gRPC ground-side (mission control ↔ GS) only. |
| `protocol.py` (30/10/60 s timeouts) | **Rework** | Wall-clock phase timeouts are meaningless across pass gaps. Command validity = **`valid_until` expiry window** (already in `sequencing.py`), not a socket timeout. |
| `streaming.py` (64 KB chunks) | **Not used** | TT&C is a few hundred bytes/command; no streaming. |
| **NEW: `command_auth` shim** | **New (small)** | Thin flight-side glue: parse CCSDS TC frame → verify ML-DSA-65 → `SequenceTracker.validate_and_advance` → accept/reject. ~1 file. |

---

## 6. Worked mini-example

**Cost of an ML-DSA-65-signed command on the uplink.**

- ML-DSA-65 signature: **~3,309 B**. Verify key (if uplinked, normally pre-loaded):
  ~1,952 B. Public key is provisioned pre-launch, so per-command overhead is just
  the signature.
- A raw command payload is ~8–64 B; call the signed envelope
  ≈ 64 B command + 3,309 B sig + ~40 B framing/seq/expiry ≈ **~3.4 KB**.
- At **9.6 kbps**: 3.4 KB × 8 / 9,600 ≈ **~2.85 s of uplink per signed command**.
  At 19.2 kbps: ~**1.4 s**. Against an ~8-min (576 KB @ 9.6 kbps) pass, ten signed
  commands cost ~28 s — **< 6 % of the pass window.** Entirely affordable for a
  low-cadence control path; this is why signatures are fine *inbound* even though
  they are rate-budgeted for on-orbit *signing* in the payload use case.

**How `sequencing.py` blocks a cross-pass replay.**

Adversary records a legitimate signed command during pass *N* (say `sequence=42`,
`valid_until = T+3600`, correctly signed by the operator VK). On pass *N+1* they
re-transmit the *identical, validly-signed* bytes from their own dish:

1. `command_auth` verifies the ML-DSA-65 signature → **passes** (it *is* a real
   signature; forgery is not the attack, replay is).
2. It calls `SequenceTracker.validate_and_advance(vk, 42, domain, valid_until)`.
   The tracker's high-water mark for that signer fingerprint is already **42**
   (advanced when the command was first executed). The check
   `sequence (42) <= current (42)` is true →
   **`(False, "replay: sequence 42 <= current 42")`.** Command rejected.
3. Even if the attacker waits and the satellite resets, the persisted HWM (see
   §5) restores 42; and independently, once `now >= valid_until` the temporal
   check rejects it as `expired` regardless of sequence. **Two independent gates.**

That two-line interaction — verify, then `validate_and_advance` — is the entire
anti-spoof / anti-replay mechanism, and it already exists in the repo.

---

## 7. Use-case-specific risks

- **Uplink jamming / denial.** Signatures don't help against a jammer keying up
  your UHF. This use case authenticates; it does not defeat denial. Mitigation is
  RF-layer (spread spectrum, directional GS, spectrum monitoring) and the
  store-and-forward resilience from the parent scope — *not* something ETP solves.
  Set that expectation with buyers explicitly.
- **Signature size vs. uplink budget.** ~3.3 KB/command is fine at low cadence but
  is a hard scaling wall: a burst of many signed commands in one short pass can
  starve the window. Mitigate with pre-scheduled command loads, and consider a
  short-lived symmetric session MAC bootstrapped by one ML-DSA-signed command for
  high-rate command bursts (design flag, not v1).
- **Key custody & rotation.** The vehicle holds the *public* verify key — good.
  But rotating it requires an authenticated uplink (chicken-and-egg): a rotation
  command must itself be signed under the *old* key, and a bricked/lost key means
  no command path. Needs a provisioned recovery key and a rotation protocol
  (out of v1 scope; flag for design).
- **Sequence HWM persistence across SEU/reset.** `sequencing.py` holds the HWM in
  RAM. On a flight MCU a single-event upset or power cycle that loses the HWM
  would *reopen the replay window*. The HWM (and last `valid_until`) **must** be
  committed to radiation-tolerant non-volatile storage and restored on boot.
  This is the single most important flight-hardening delta for this use case.
- **Clock trust for expiry.** Temporal expiry (`valid_until`) assumes a trusted
  on-board clock. GPS-denied or drifting RTC weakens the expiry gate — but the
  monotonic sequence gate still holds independently, which is why we keep both.

---

## 8. Minimal demo / MVP in this repo

A pure-Python, no-radio MVP that proves the core claim — **signed command accepted
once, replay and forgery rejected** — using only existing modules plus a thin shim.

**Build:**

1. `src/ltp/command_auth.py` (~1 small module): `sign_command(sk, seq, valid_until,
   domain, payload) -> bytes` (ground) and `verify_command(vk, tracker, frame) ->
   (bool, reason)` (flight). `verify_command` does ML-DSA-65 verify → then
   `SequenceTracker.validate_and_advance(...)`. Reuses `sequencing.py` unchanged.
2. `tests/test_command_auth.py` covering:
   - **happy path:** freshly signed `seq=N` verifies and executes once;
   - **replay across passes:** re-submitting the exact bytes returns
     `(False, "replay: ...")` — assert the HWM did not advance twice;
   - **forgery:** flip one byte of payload or signature → ML-DSA verify fails,
     command never reaches the sequence check;
   - **expiry:** `valid_until` in the past → `(False, "expired: ...")`;
   - **wrong signer:** command signed by a different VK is rejected / tracked
     under a different fingerprint (can't ride the operator's sequence);
   - **reset survival (stub):** serialize the tracker HWM, reload it, confirm the
     replay is *still* blocked — models the SEU-persistence requirement from §7.
3. Wire it into the existing `conftest.py` PQ keypair fixtures (`alice` = operator
   signer, `eve` = adversary) — no new crypto fixtures needed.

**What it proves:** the full anti-spoof C2 story (PQC signature + monotonic
sequence + expiry) works end-to-end against forge/alter/replay, with zero new
cryptography — just composition of `sequencing.py`, the ML-DSA-65 verifier, and
the existing test fixtures. Radio/CCSDS/DTN framing (parent scope) layers on later
without changing this trust core.

---

*Child brief of `CUBESAT_SCOPE.md`. Shared architecture is defined there and
deliberately not repeated. This document scopes the secure-TT&C use case only.*

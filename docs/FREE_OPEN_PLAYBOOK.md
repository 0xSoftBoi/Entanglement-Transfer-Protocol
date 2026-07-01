# Free/Open Playbook — What Got Traction, and What to Copy

Research synthesis for launching **etp-custody** free/open. Studied the projects
that actually got adopted in this space (transparency logs, provenance,
attestation, SBOM), the viral secure-CLI pattern, how free/open sustains itself,
and the concrete GitHub launch mechanics. Star counts are mid-2026, approximate,
and drift — the *patterns* are the durable finding.

> **The one-line takeaway:** don't launch a "post-quantum tool" (ceiling ~1–3k
> stars, no revenue). Launch a **supply-chain / chain-of-custody tool that
> happens to be post-quantum**, kill the key ceremony, emit a standard
> attestation, ship it as a GitHub Action — and fund the free core with grants +
> retainers while open-core revenue (compliance/on-prem/SLA) builds later.

---

## 1. What got traction (and what got stars but died)

| Project | ~Stars | Why it won / lost |
|---|---:|---|
| **Trivy** (Aqua) | ~37k | **Became the default scanner inside Harbor/GitLab/Artifact Hub.** Rode EO 14028. Distribution > artifact. |
| **sigstore / cosign** | ~6k | **Killed key management** (keyless OIDC) + default in npm/PyPI/K8s/GitHub Actions + neutral foundation (OpenSSF). |
| **GitHub Artifact Attestations** | n/a | Attestations languished for years until GitHub **collapsed setup to 2 lines of YAML**. Friction was the whole game. |
| **Grype / Syft** (Anchore) | ~12k/9k | De-facto SBOM generate→consume funnel; **format-agnostic** (SPDX+CycloneDX), rode the mandate. |
| **immudb** (Codenotary) | ~9k | ⚠ **Open-core ceiling** — viral star spike, thinner production use; the useful bits sit behind the paywall. |
| **in-toto / TUF / SLSA** | 1–2k | **Won as embedded standards**, not apps. Modest stars, enormous reach (everyone builds on them). |
| **C2PA / contentauth** | <500 | **Coalition + standard** (Adobe/BBC/Leica…). Stars badly understate reach; adoption via camera firmware + Adobe. |
| **google/trillian → tessera** | ~3.7k / ~200 | ⚠ **Infrastructure-library trap** — cryptographically excellent, ~no direct adoption. Needs a "personality" first. |
| **Docker Notary v1** | ~3k | ⚠ **Operability trap** — correct crypto (TUF), painful key ceremony/UX → users routed around it → superseded. |
| **OpenTimestamps** | ~1k | ⚠ **Niche/dependency trap** — elegant Bitcoin-anchored notary, no enterprise integration path; never crossed over. *(Closest analog to us — and it never made money.)* |
| **rosenpass** (PQ WireGuard) | ~1.4k | The most-cited "quantum-safe CLI" — grant-funded, respectable, **not a breakout**. The pure-PQC ceiling. |
| **liboqs** (OQS/PQCA) | ~3k | Foundational PQC lib; institutional adoption, not viral. The PQC ceiling again. |

### The four adoption patterns
1. **Distribution beats the artifact.** The biggest wins became *the default inside a platform people already run* (Trivy in Harbor/GitLab; attestations in GitHub Actions). Be the embedded default, not another opt-in binary.
2. **Kill the hardest chore, then make it one command.** Sigstore removed key management; GitHub made attestation 2 lines of YAML. If the secure path is hard, users route around it (Notary's grave).
3. **Ride a dated mandate, don't invent a need.** The entire category surfed **SolarWinds → Executive Order 14028 (SBOM)**. No external forcing-function → niche (Tessera 200, Witness 534).
4. **Win as a standard, or speak every standard.** in-toto/TUF/CycloneDX won as formats. If you're a tool, be format-agnostic and emit what existing verifiers already read.

### The five traps (memorize these)
- **Infra-library trap** (Trillian): ship a runnable *product*, not a toolkit.
- **Operability trap** (Notary): a key ceremony = death. Auto-manage keys.
- **Open-core ceiling** (immudb): stars are vanity; adoption is defaults + integrations. Don't paywall the useful core.
- **Niche/dependency trap** (OpenTimestamps): a hard external dependency caps your market. (We have none — keep it that way.)
- **Spec-without-a-tool** (SLSA/C2PA alone): a spec gets cited, not installed, unless paired with a generator or coalition.

---

## 2. The viral secure-CLI pattern (age, croc, restic, ripgrep…)

The breakout tools (age ~22k, croc ~35k, syncthing ~86k, restic ~34k, ripgrep ~66k) all did the same five things:

1. **"Drop-in replacement for a hated tool."** age = "GPG without the pain," ripgrep = "fast grep," caddy = "nginx without the TLS hell." → **etp-custody = "chain of custody without an HSM ceremony / a blockchain."**
2. **Single static binary + one-line install** (`brew install`, `curl | sh`). Ship macOS/Linux/Windows day one. (Security tool → also publish a signature to verify.)
3. **The README *is* the product:** a 5–15s asciinema/VHS demo of the most common command, install line, 2–3 examples, ≤2 screens, 3–5 *real* badges (vanity rows read as filler now).
4. **A memorable name + a credibility anchor.** age spread partly because a known cryptographer built it. → lead with **real FIPS 203/204 primitives** and, if possible, a named review/audit.
5. **Sharp personal-pain origin** told as a story.

---

## 3. Is there a PQC wave to ride? Yes for narrative, no incumbent in our lane.

- **Real, dated pegs:** NIST finalized **FIPS 203/204/205 on Aug 13, 2024**; **CNSA 2.0** starts federal PQC adoption by **Jan 2027**; **"harvest now, decrypt later"** is the ready-made urgency hook — *especially* for chain-of-custody (data captured today must stay provable/secret for years).
- **But pure-PQC dev tools are pre-adoption:** liboqs ~3k, rosenpass ~1.4k — that's the ceiling for "a PQC tool." **No post-quantum chain-of-custody CLI has broken out** → a genuine gap, no incumbent.
- **The lever:** peg to the *larger* **software-supply-chain / provenance** wave (the sigstore path), with PQC as the future-proof angle. "PQC" alone reaches low-thousands; "provenance that's also quantum-safe" reaches the supply-chain audience.

---

## 4. How the free core survives (it will NOT itself make money)

Every commodity-crypto provenance tool confirms it: **OpenTimestamps, sigstore, Notary — none produced standalone revenue.** The free core is a trust/adoption play. Fund it and monetize the surround:

**Fund the free core (non-dilutive, early):**
- **NLnet / NGI Zero** (EU) — €5k–50k, on-theme (funded WireGuard/Tor/GNUnet), low bar, fast. *Start here.*
- **SBIR Phase I ($323k) → Phase II ($2.15M)**, **DIU**, **AFWERX STRATFI/TACFI ($3–15M)** — provenance/evidence-integrity maps cleanly to defense; also lands the gov relationship that becomes on-prem revenue.
- **Geomys-style maintainer retainers** — a handful of dependent orgs fund the maintainer at senior-eng comp; keeps the core credibly independent.

**Monetize the accountability layer (open-core — the ONLY model with real revenue: GitLab $759M, Grafana $400M ARR):**
- Compliance/audit packaging (reports formatted for 21 CFR 11 / NERC-CIP / CJIS / eIDAS, retention, legal hold, regulator-ready export).
- Identity & governance for teams (SSO/SAML/SCIM, RBAC, multi-party quorum, org policy).
- Managed/hosted notary + SLA + 24×7 support (the `serve` backend already built).
- Private / on-prem / air-gapped + HSM/KMS + support contract (the gov/regulated sweet spot).

**Never gate** the crypto core, verification, or single-user self-host. **Never relicense** an already-free core (HashiCorp's BSL → OpenTofu fork in a month). Gate *operations, identity, compliance, support* — free users never miss those.

---

## 5. The launch mechanics (concrete numbers)

- **Show HN front-page hit ≈ ~500 stars in 48h** then flatlines (~92% of impact in 48h). ~**1.4 stars per HN upvote**. A strong hit (300+ pts) ≈ 700–1,500.
- **Seed the first ~100 stars from your own network before posting** — a 3-star repo converts terribly on HN.
- **Post Show HN Monday ~8–9am ET**, technical+curiosity title, no marketing voice; be present in comments. Don't send friends direct post links (vote-ring penalty).
- **Same week:** r/crypto, r/netsec, r/selfhosted, Lobsters.
- **Then durable channels (what actually compounds to thousands over 1–3 months):** Console.dev / TLDR / Changelog newsletters; `awesome-cryptography` / `awesome-security` lists; GitHub Topics (`post-quantum`, `cryptography`, `cli`); **a GitHub Action** (every CI run = a use — the highest-leverage integration); Homebrew tap → core.
- **Expectation-setting:** realistic ceiling for the PQC framing is **low-thousands** of stars; exceed it only by bridging into supply-chain and landing the integrations. Stars ≠ revenue regardless.

---

## 6. What this means for etp-custody — the build list

Ordered by leverage, derived directly from the traps and winners above:

1. **Reposition** the README/site: lead with **provenance & chain-of-custody** (supply-chain framing), PQC as the future-proof angle — not "a post-quantum tool."
2. **Kill the key ceremony** (Notary's grave): keyless/auto-managed keys, or a one-command identity so `send`/`receive` need no manual key handling. This is the single biggest UX lever.
3. **Emit a standard attestation** (in-toto / SLSA-compatible DSSE) alongside our receipt, so existing verifiers work and we ride the ecosystem instead of asking anyone to adopt a new format.
4. **Ship a GitHub Action** wrapping the CLI (attest/verify in CI) — become the default *inside* a platform people already run.
5. **Package for virality:** single static binary, `brew`/`curl|sh` install, a trimmed asciinema demo, ≤2-screen README with the "drop-in replacement" line and FIPS 203/204 + HNDL peg.
6. **Fund it:** draft an NLnet/NGI Zero application now; scope an SBIR angle (evidence integrity / PQC migration).
7. **Launch** on the FIPS-203/204 + HNDL + supply-chain narrative; seed 100 stars first; front-load HN/Reddit/Lobsters; then durable channels.

*Sources: Show HN dataset & arXiv star-diffusion study; star-history growth playbook; sigstore/OpenSSF, Trivy, Anchore, in-toto/TUF/C2PA repos & docs; Geomys/curl/Caddy/rclone funding writeups; GitLab/Grafana/Elastic open-core; NLnet/SBIR/DIU program pages; NIST FIPS 203/204/205 (Aug 2024); EO 14028. Full URLs in the research task outputs.*

# ETP Cross-Sector Competitive Analysis — Where Is the Least Competition?

**Question:** across the candidate sectors for ETP (post-quantum + erasure-coded +
delay-tolerant + RFC-6962-provenance secure-transport middleware), which has the
**least competition**?

**Method:** one live web-research pass per sector, mapping named incumbents,
standards/procurement gates, whitespace, and barriers to entry, then scoring
**competition intensity 1–5** (1 = wide-open, 5 = saturated). Sources are listed
in each sector's notes below. Satellite/CubeSat is included as the baseline the
whole effort started from.

> **The critical distinction this analysis forces:** *low competition is not the
> same as an attractive market.* Three of the low-competition sectors are open
> because nobody has assembled the 4-way combo; one is open because **there is
> little money there.** Both facts are below — read them together.

---

## The ranking

| Rank (least competitive first) | Sector | Competition | Why it's open (or not) |
|---|---|:--:|---|
| 1 (tie) | **Critical infrastructure / OT** | **2 / 5** | Legs owned separately (diodes, OT-visibility, protocol security); DTN + erasure + provenance productless in OT |
| 1 (tie) | **Tactical / defense DIL** | **2 / 5** | No shipping 4-way product; moat is *structural* (accreditation, gov-owned stacks), not a rival |
| 1 (tie) | **Satellite / CubeSat** | **2 / 5** | Fragmented by lane; BPSec (the DTN standard) openly lacks PQC today — clean whitespace |
| 1 (tie) | **Disaster / humanitarian** | **2 / 5** | Category nobody has assembled — **but open because the money is thin, not just the field** |
| 5 | **Healthcare & genomics** | **2.5 / 5** | Lanes crowded & well-capitalized, but PQC-fused-provenance wedge is unoccupied |
| 6 | **Scientific / HPC transfer** | **5 / 5** | **Red ocean.** Globus/Aspera/Zettar own it; AWS already shipped PQC SFTP (2025) |

**Headline:** four sectors tie at the top on raw competition (2/5). The tie-break
is *market attractiveness* and *how defensible the opening is* — which reorders
them substantially.

---

## The universal pattern (true in every sector)

Every single research pass returned the **same structural finding**: ETP's four
capabilities each have credible incumbents *individually*, but **no vendor in any
sector ships the integrated combo** — PQC **+** erasure coding **+** delay-tolerant
store-and-forward **+** RFC-6962 tamper-evident provenance. ETP is not fighting a
head-on competitor anywhere; it is **defining a category** everywhere.

That is a double-edged result:
- **Upside:** genuine whitespace in 5 of 6 sectors.
- **Downside:** "no competitor" often means "no established buyer demand for the
  bundle" — ETP must *create* the category and sell the urgency (especially PQC,
  which is a mandate almost nowhere yet).

The consistently emptiest lanes across all sectors are **erasure-coded DTN** and
**RFC-6962 provenance** — those two are ETP's most differentiated, least-contested
capabilities. PQC alone is *not* a moat: it's rapidly becoming table stakes (AWS
shipped it, ESA/CYSEC are piloting it, CNSA 2.0 mandates it by ~2030).

---

## Sector notes (evidence)

### Critical infrastructure / OT — 2/5
- **Incumbents by lane:** Waterfall & Owl (data diodes — the "assured transfer"
  paradigm), Claroty/Dragos/Nozomi (OT visibility — adjacent, they *monitor* not
  *transport*), SEL/Triangle MicroWorks (DNP3 Secure Auth / IEC 62351 — classical,
  per-protocol). **Veridify** is the closest PQC-for-OT play but uses *proprietary*
  crypto, not ML-KEM/ML-DSA, and has no erasure/DTN/provenance.
- **Gates:** NERC-CIP, IEC 62443/62351. No PQC mandate for OT *yet* — timing gap.
- **Wedge:** intermittent-link, provenance-assured, quantum-safe telemetry for
  remote/austere OT (pipelines, offshore, sat-backhauled RTUs) — where diodes
  (hardware, one-way, assume connectivity) don't play.
- **Barriers:** retrofit friction, hardware-diode "assurance" bias, multi-year
  compliance-gated procurement.

### Tactical / defense DIL — 2/5
- **Incumbents by lane:** SpiderOak OrbitSecure (closest — data-centric zero-trust
  + ledger provenance, but space-focused, no erasure/DTN), DoD Edge Data Mesh
  (gov-owned DIL transport — a competitor *by fiat*), TrellisWare/Silvus/Persistent
  (MANET waveforms — the link layer ETP rides on, channel partners), Viasat/
  Curtiss-Wright (Link-16 CryptoMod — legacy symmetric, not PQC middleware).
- **Gates:** CNSA 2.0 (the PQC tailwind), NSA CSfC (the accreditation moat),
  MOSA/Open DAGIR (interoperability table-stakes).
- **Wedge:** radio-agnostic software overlay fusing all four pillars; provenance
  + FEC-fused-DTN are near-empty commercially.
- **Barriers:** **accreditation is the moat** (CSfC/CNSA 2.0 = 12–36 months),
  gov-owned stacks can crowd out COTS, US-ownership/ITAR/FIPS effectively mandatory.

### Satellite / CubeSat — 2/5 (baseline)
- **Incumbents by lane:** CYSEC ARCA SATLINK (closest — onboard PQC + CCSDS SDLS,
  **flight-proven on ESA OPS-SAT**, but no DTN/erasure), ESA E2EQSS (same ML-KEM/
  ML-DSA algorithms — but an R&D program, not a product), NASA ION/HDTN (the DTN
  reference — free, flight-heritage, but security is bolt-on, no native PQC),
  GSaaS (AWS/KSAT/Leaf/ATLAS — the pipe, channel partners not competitors).
- **Gates:** CCSDS SDLS (the link-security checkbox ETP doesn't natively claim),
  DTN BPSec (**RFC 9172 — openly lacks PQC today; PQC only in IETF draft** → ETP's
  cleanest standards-gap opportunity), CNSA 2.0.
- **⚠ Procurement flag:** ETP uses **ML-KEM-768** (FIPS 203 Level 3). CNSA 2.0
  requires **ML-KEM-1024** (Level 5) for classified/NSS space. A 1024 variant is
  needed for the highest-value defense-space contracts.
- **Barriers:** **flight heritage is the gatekeeper** (CYSEC's real edge is OPS-SAT,
  not its crypto) — ETP has none; multi-year CCSDS/agency qualification.

### Disaster / humanitarian — 2/5 competition, ⚠ low attractiveness
- **Players by lane:** goTenna/Meshtastic (off-grid mesh — partial crypto, no PQC),
  Serval/DTN7 (store-and-forward research), KoBoToolbox/ODK (offline data collection
  — plain sync), UNHCR PRIMES/BIMS (centralized biometric data). Buying flows through
  gatekeepers: UN ETC, OCHA, NetHope, TSF.
- **Wedge:** tamper-evident, quantum-safe custody of sensitive beneficiary data that
  survives multi-day disconnection and partial data-mule loss.
- **⚠ The catch:** low competition here = **low money.** Humanitarian financing fell
  ~$42B→$32B (2022→2024); willingness-to-pay for PQC ≈ zero; free incumbents
  (Meshtastic/KoBo). **Best treated as a credibility/reference-customer beachhead**
  (via NetHope/TSF/UNHCR partnerships) that de-risks the tech — *not* a revenue engine.

### Healthcare & genomics — 2.5/5
- **Incumbents by lane:** Intelerad/Life Image, Ambra, PocketHealth (image exchange —
  classical crypto, policy-based audit), DNAnexus/Illumina/Terra (genomic clouds —
  **DNAnexus already markets "provenance + audit + 21 CFR Part 11"**, but classical
  crypto, not a Merkle log), TEFCA QHINs (record exchange rails), ExeQuantum/Arqit
  (PQCaaS — no provenance).
- **Gates:** HIPAA (no PQC mandate yet), **21 CFR Part 11 / ALCOA+ (tamper-evident
  audit trails — ETP's natural regulatory anchor)**, GDPR, HITRUST/SOC2.
- **Wedge:** ML-KEM/ML-DSA confidentiality *cryptographically bound to* an RFC-6962
  append-only provenance log — the HNDL-durable + verifiable chain-of-custody combo
  no named incumbent offers. **The harvest-now-decrypt-later threat is genuinely
  present here** (genomic data is sensitive for a lifetime), unlike most sectors.
- **Barriers:** HITRUST/SOC2/FIPS 140-3 certification (12–24 mo table stakes),
  PACS/EHR/VNA lock-in (must integrate via DICOM/HL7/FHIR/TEFCA, not displace).

### Scientific / HPC bulk transfer — 5/5 (RED OCEAN — avoid)
- **Incumbents:** Globus/GridFTP (free-to-researcher de-facto standard, SC25
  Test-of-Time award, universal), IBM Aspera/FASP (commercial standard), Zettar
  (extreme-scale specialist), FDT/BBCP/UDT (free HEP tools), **AWS Transfer Family
  (already ships hybrid ML-KEM-768 PQC SFTP, 2025)**.
- **Verdict:** "fast + secure bulk transfer" is solved and commoditized; ETP's
  headline PQC differentiator is *already shipped by a hyperscaler*; PQC is not a
  buying criterion here (much open-science data becomes public anyway). **Do not
  enter.**

---

## Recommendation

**"Least competition" has two answers, and you should act on the second one:**

1. **Literally least competitive:** a four-way tie at 2/5 (OT, tactical, satellite,
   disaster). But raw openness is the wrong sole metric — disaster is open because
   it's *poor*, and tactical/satellite are open behind *multi-year accreditation and
   flight-heritage moats* that a startup can't quickly cross.

2. **Best *exploitable* low-competition opening — the actual recommendation:**

   > **Lead with Healthcare & genomics (provenance + PQC), and Critical
   > infrastructure / OT as the second front.**

   Rationale: they combine *genuinely unoccupied whitespace* (the PQC-fused-RFC-6962
   wedge exists in neither) with the two things the purely-open sectors lack — a
   **present, real threat** (lifetime-confidential genomic data makes
   harvest-now-decrypt-later concrete *today*) and a **funded, regulated buyer**
   (21 CFR Part 11 and NERC-CIP give the provenance/integrity story a compliance
   anchor). Healthcare's MVP is also nearly buildable now on the existing
   `merkle_log/` package.

**Sequencing suggestion:**
- **Beachhead:** Healthcare/genomics provenance (real threat + funded buyer +
  buildable MVP).
- **Second front:** Critical-infrastructure OT (same PQC + provenance + integrity
  story, 20–30 yr assets justify PQC-now).
- **Credibility/reference play (not revenue):** a humanitarian pilot via
  NetHope/TSF to de-risk and de-facto certify the tech.
- **Long game, high moat:** tactical-defense and defense-space — highest willingness
  to pay, but budget for the accreditation marathon (and build the **ML-KEM-1024**
  variant CNSA 2.0 requires) before committing.
- **Avoid:** scientific/HPC bulk transfer (red ocean, PQC already commoditized).

**Cross-cutting product priority:** the two least-contested capabilities across
*every* sector are **erasure-coded DTN** and **RFC-6962 provenance** — build and
harden those first; treat PQC as necessary-but-not-sufficient (it's becoming table
stakes). Provenance is the reusable, no-blockchain-required differentiator that
travels across healthcare, OT, satellite, and defense alike.

---

*Competition intensity is a point-in-time read from public sources; the PQC-in-
transport landscape is moving fast (AWS shipped in 2025; ESA/CYSEC piloting;
CNSA 2.0 deadlines ~2030). Re-check before committing budget.*

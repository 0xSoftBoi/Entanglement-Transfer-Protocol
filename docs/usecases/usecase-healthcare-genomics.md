# ETP Use Case — Healthcare & Genomics: Lifetime-Confidential Data + Medical Provenance

**Author:** Javier Calderon Jr, CTO of Global Settlement (GSX)
**Date:** July 1, 2026
**Status:** Scoping / design — no domain code yet
**Related:** [`CUBESAT_SCOPE.md`](../../CUBESAT_SCOPE.md) (shared transport + crypto core, pillar descriptions)

---

## 1. One-Line Pitch

**Post-quantum-sealed transfer of genomic and clinical data, with an RFC 6962 tamper-evident transparency log of every access and hand-off — so a patient's genome stays confidential for their entire lifetime and every custody event is independently auditable decades later.**

---

## 2. Domain & Who Buys It

Healthcare data has a uniquely long confidentiality horizon: a whole genome is immutable and identifying for the life of the patient *and their blood relatives*, and imaging/clinical records must survive regulatory retention windows measured in decades. That makes **harvest-now-decrypt-later (HNDL)** an acute, *present* threat — data exfiltrated in 2026 under RSA/ECDH is a plausible plaintext once a cryptographically relevant quantum computer exists (widely projected within the multi-decade window these records must stay secret). PQC confidentiality is therefore required *today*, not as a later retrofit.

Buyers and their pain:

| Buyer | Data | Why ETP |
|---|---|---|
| **Hospitals / IDNs** | DICOM imaging, EHR extracts | HIPAA custody + cross-site transfer under a live PQC + audit mandate |
| **Sequencing labs** (clinical & research) | FASTQ/BAM/VCF | Genome is lifetime-sensitive; results shipped to ordering clinicians |
| **Pharma / CROs** | Clinical-trial datasets, eCRFs | FDA 21 CFR Part 11 audit trails; 15–25 yr retention; multi-site integrity |
| **Biobanks** | Consented specimen + omics data | Durable multi-decade archival; provenance for re-consent & data-sharing |
| **Imaging networks / teleradiology** | Cross-institution study transfer | Independent proof of who accessed which study, when |

---

## 3. Data & Trust Flow

```
 capture ──▶ PQC-seal ──▶ transfer ──▶ tamper-evident log ──▶ auditor verifies
 (scanner/    (ML-KEM-768   (shards      (append leaf per       (inclusion proof
  sequencer/   sealed key +   over any     access/transfer;       O(log N) against
  EHR export)  XChaCha20      channel;     ML-DSA-65 STH)         a signed STH)
               per-shard)     store-fwd)
```

1. **Capture.** A modality (MRI/CT scanner, sequencer run, EHR export job) emits an object — a DICOM study, a VCF, a trial dataset.
2. **PQC-seal.** A per-object content key encrypts the payload with XChaCha20-Poly1305 (`shards.py`); that key is sealed to the recipient with a constant-size ~1.3 KB ML-KEM-768 ciphertext (`bridge/`). Payload size does not change the key-establishment cost.
3. **Transfer.** Sealed shards move to the destination (peer hospital, sequencing lab, sponsor). The channel is untrusted; confidentiality lives in the payload, not the pipe. Delay-tolerant store-and-forward means a transfer survives an offline destination.
4. **Tamper-evident log.** Every capture, seal, transfer, and *access* appends a leaf (object ID, actor, purpose-of-use, timestamp hash) to the append-only Merkle log (`merkle_log/`). Periodically the operator publishes an ML-DSA-65 **Signed Tree Head** (STH).
5. **Auditor verifies.** A regulator, sponsor auditor, or the patient's counsel takes a record + an **inclusion proof** and checks it against a published STH — in `O(log N)` — proving the event was logged at that point in history, with no need to trust the operator's database.

---

## 4. Why ETP Fits — Pillars Ranked

Reusing the pillar taxonomy from `CUBESAT_SCOPE.md`, re-ranked for healthcare:

1. **PQC confidentiality (lead).** The lifetime/HNDL horizon *is* the thesis. ML-KEM-768 + ML-DSA-65 + XChaCha20-Poly1305 are real (FIPS 203/204), not simulated. Sealing cost is constant (~1.3 KB) whether the object is a 5 MB chest X-ray or a 200 GB genome BAM.
2. **Merkle transparency log (lead).** Chain-of-custody is the other half. RFC 6962 inclusion + consistency proofs and ML-DSA-65 STHs give *independent* auditability — the operator cannot silently rewrite who-saw-what. This is Certificate Transparency's design, pointed at medical provenance. **No blockchain required** — a hospital wants an auditable log, not a token.
3. **Erasure coding (supporting).** Reed–Solomon *k*-of-*n* (`erasure.py`) turns multi-decade retention into durable multi-site archival: spread *n* shards across sites/clouds, reconstruct from any *k*, survive site loss without full replication. Ideal for biobank/trial cold storage.
4. **Temporal binding / sequencing (supporting).** `sequencing.py` gives monotonic, replay-resistant ordering of custody events — an access log entry cannot be back-dated or reordered.
5. **HSM key custody (supporting).** `hsm.py` keeps ML-DSA signing keys and long-lived decapsulation keys off application hosts — essential when the confidentiality window is decades.

---

## 5. ETP Module Impact (mostly reuse)

| Module | Action | Notes |
|---|---|---|
| `bridge/` (ML-KEM seal) | **Reuse** | Constant-size sealed content key per object; recipient = clinician/site/sponsor |
| `shards.py` | **Reuse** | Per-shard XChaCha20-Poly1305; object encrypted independent of transport |
| `merkle_log/` | **Reuse (headline)** | Access/transfer log, STHs, inclusion + consistency proofs — nearly buildable today |
| `erasure.py` | **Reuse** | RS *k*-of-*n* for durable multi-site archival of large omics/imaging objects |
| `sequencing.py` | **Reuse** | Monotonic, replay-resistant ordering of custody events |
| `hsm.py` | **Reuse** | Custody of ML-DSA STH-signing key and long-lived KEM keys |
| `streaming.py` | **Reuse / reprofile** | Chunk large BAM/DICOM objects; tune chunk size to object profile |
| `protocol.py` | **Reuse** | commit → seal → materialize maps cleanly to capture → seal → deliver |
| DICOM/HL7/FHIR adapter | **NEW (thin)** | Ingest hook: map a DICOM study / VCF / trial dataset to an ETP object + log leaf |
| Purpose-of-use / actor schema | **NEW (thin)** | Structured leaf payload (actor, role, purpose, object hash) for audit queries |
| `anchor/`, contracts | **Out of scope** | On-chain settlement is not part of this use case; the STH *is* the anchor |

Roughly two thin new pieces (a standards adapter and a leaf schema); everything load-bearing is existing core.

---

## 6. Worked Mini-Example — One STH Notarizes a Day of Imaging Accesses

A mid-size imaging network logs **50,000** access/transfer events in a day (studies viewed, exported, or shipped between sites). Each event is one leaf in the Merkle log.

- The operator publishes **one** Signed Tree Head at end of day. Its signed core is compact: `sequence (8) + tree_size (8) + timestamp (8) + root_hash (32)` = **56 bytes** of signable payload, protected by a single ML-DSA-65 signature. The 32-byte BLAKE2b-256 **root** commits to *all 50,000 events at once**.
- Six years later (HIPAA minimum retention is **6 years**; clinical-trial retention runs **15–25 years**), an auditor questions whether study `#37,214` was accessed on that day. The operator returns the leaf plus an **inclusion proof**: `⌈log₂(50,000)⌉ = 16` sibling hashes ≈ **512 bytes**. The auditor recomputes the root and checks it against the day's signed STH — no trust in the operator's live database required.
- A **consistency proof** further shows the historical tree was never rewritten between two STHs — detecting any silent back-dating or deletion of a custody record. Two STHs at the same sequence with different roots are self-contained cryptographic proof of operator equivocation.

One 32-byte root + one signature notarizes 50,000 events; any single event is provable in ~16 hashes. That is the provenance value in one number.

---

## 7. Risks / Where It's a Poor Fit — Honestly

- **De-identification is orthogonal to encryption.** ETP protects data *in transit and at rest* and proves *custody*. It does **not** de-identify. HIPAA Safe Harbor / Expert Determination, DICOM tag scrubbing, and genomic k-anonymity are separate obligations — a perfectly sealed record is still PHI. ETP is a complement to, not a substitute for, de-identification.
- **Key-recovery vs. lifetime secrecy tension.** Decades-long confidentiality means decades-long key custody. Lose the KEM private key and the data is gone (durable ciphertext, dead key); escrow it and you create a long-lived compromise target and a subpoena surface. This is a governance problem `hsm.py` *supports* but does not *solve* — key lifecycle policy is the hard part.
- **What the log proves — and doesn't.** The transparency log proves a record *was logged* and history *was not rewritten*. It does **not** prove the logged event actually happened in the physical world, nor that an authorized viewer didn't misuse what they legitimately accessed. It is tamper-evidence for the audit trail, not access control or intent verification. Access control (RBAC/ABAC, break-glass) sits *above* ETP.
- **Right-to-erasure friction.** Append-only logs and GDPR/consent-withdrawal "right to be forgotten" are in tension. Mitigation: log *hashes and metadata*, never plaintext PHI, in leaves; erase the payload (crypto-shredding the content key) while the immutable log retains only a non-identifying commitment.
- **Not a database or PACS.** ETP is transport + provenance middleware. It does not replace the PACS, LIMS, EHR, or clinical-trial EDC — it wraps their inter-system transfers and access events.
- **Standards integration is real work.** DICOM/HL7v2/FHIR ingestion is the thin-but-fiddly new surface; interop, not crypto, is where the schedule risk lives.

---

## 8. Minimal In-Repo MVP

The `merkle_log/` package is essentially the MVP already — it ships append-only trees, ML-DSA-65 STHs, and inclusion/consistency proofs. A demonstrable healthcare provenance MVP:

1. **Provenance log service.** Wrap `MerkleLog` (`merkle_log/log.py`): `append(leaf)` for each access/transfer; leaf = canonical bytes of `{object_hash, actor_id, role, purpose_of_use, prior_event_hash, ts}`. STH-signing key held via `hsm.py`.
2. **Seal path.** For each object, seal a content key with `bridge/` (ML-KEM-768) and encrypt with `shards.py` (XChaCha20-Poly1305). One sealed object → one transfer leaf.
3. **Auditor CLI.** `verify(record, inclusion_proof, sth)` using the existing `InclusionProof.verify` + `SignedTreeHead.verify` — proves a custody event against a published STH offline.
4. **Daily STH publisher.** A scheduled job signs one STH per log per day (§6) and persists it; publishing to a witness/mirror is a later hardening step.
5. **Durable archival (optional).** Run large sealed objects through `erasure.py` RS *k*-of-*n* across two or more storage backends to demonstrate multi-site durability.

Steps 1, 3, and 4 are buildable against today's code with only glue. Steps 2 and 5 reuse the crypto/erasure core unchanged. The genuinely new work is the DICOM/FHIR adapter (§5) and the purpose-of-use leaf schema — deliberately thin.

---

*Scoping document only. This defines the healthcare/genomics profile and reuse boundary; it changes no existing ETP behavior. The cryptographic, log, and erasure core is reused as-is, per the shared architecture in [`CUBESAT_SCOPE.md`](../../CUBESAT_SCOPE.md). On-chain settlement is explicitly out of scope — the ML-DSA-65 Signed Tree Head is the anchor of record.*

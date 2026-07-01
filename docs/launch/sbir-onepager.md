# SBIR / DIU one-pager draft (F5)

> The funded-buyer path: agencies are under OMB M-23-02 / NSM-10 mandates to
> inventory and migrate cryptography, and evidence-integrity programs (DoJ,
> DHS, DoD test ranges) buy custody tooling. Target vehicles: AF/SF AFWERX
> Open Topic SBIR, DIU CSO areas (cyber), NIST SBIR (crypto migration).
> Format below follows the AFWERX Phase I one-pager convention.

---

## ETP Custody — post-quantum chain of custody for mission files

**The problem.** Digital evidence and mission data (sensor captures, test
telemetry, incident forensics, sensitive documents) move across
organizations, enclaves, and disconnected links. Today's custody records
are database rows a privileged insider can rewrite, and today's sealing
(RSA/ECC) is inside the harvest-now-decrypt-later window. Records with
decade-plus retention obligations are being created *now* with signatures
that will not outlive them.

**The solution.** An open-architecture custody layer, deployable on-prem or
air-gapped, that makes file history tamper-*evident* rather than
tamper-trusted:

- **Post-quantum sealing at the edge** — ML-KEM-768 (FIPS 203) +
  XChaCha20-Poly1305; plaintext never leaves the capturing enclave. The
  custody service sees only hashes.
- **Accountable logging** — RFC-6962 append-only transparency log
  (the Certificate Transparency construction, CNSSP-harmonizable), tree
  heads signed with ML-DSA-65 (FIPS 204). History rewriting and split
  views are cryptographically detectable, including by external witnesses.
- **Offline-verifiable receipts** — custody proof travels *with* the file
  and verifies with no network, no account, no reachback: suited to
  DDIL/DTN environments. k-of-n erasure bundles tolerate lossy or
  intermittent links.
- **Device attestation** — captures can be countersigned by the
  originating device's key, giving two-party (operator + device)
  non-repudiation per item.
- **Optional public anchoring** — Merkle roots (32 bytes, no content)
  can be anchored to an external ledger for third-party timestamping.

**Why now / why us.** FIPS 203/204 were finalized in August 2024; NSM-10
and OMB M-23-02 obligate migration planning; CNSA 2.0 sets 2030–2033
deadlines for NSS. Commercial PQC vendors sell *transport* (VPNs, TLS,
SFTP); none ship accountable *custody*. The codebase exists today:
~1,550 automated tests, cross-verified browser/CLI verifiers, container
deployment, Apache-2.0 (no vendor lock; open architecture per DoD
software-acquisition preference).

**Known gap (stated plainly).** Current parameters are ML-KEM-768 /
ML-DSA-65 — CAT-3, below CNSA 2.0's ML-KEM-1024 / ML-DSA-87 selections
for NSS. The primitive layer is behind a single interface; Phase I
includes the parameter uplift and an algorithm-agility assessment.

**Phase I proposal (feasibility, ~$75k, 3 months).**
1. CNSA 2.0 parameter uplift (ML-KEM-1024, ML-DSA-87) behind the existing
   primitive seam, with interop tests against the FIPS ACVP vectors.
2. Reference deployment + custody-workflow pilot mapping with one
   evidence-handling or test-range customer (the Phase II design partner).
3. Independent cryptographic review scoping and DDIL field-trial plan.

**Phase II sketch.** Hardened witness network across two independent
operators, HSM/KMS key custody, accreditation-package documentation
(RMF control mapping), and the design partner's pilot in production.

**Company / licensing.** Solo-founder open-core: the protocol, CLI, and
verification are Apache-2.0 (auditable by any program office); revenue is
hosted operation, support, and accreditation packaging. No proprietary
crypto, no vendor lock-in — the government can always self-host and
verify independently.

**Contact.** [name] · [email] · https://github.com/0xSoftBoi/Entanglement-Transfer-Protocol

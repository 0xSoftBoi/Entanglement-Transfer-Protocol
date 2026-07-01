# NLnet / NGI Zero Core application draft (F2)

> Submit at https://nlnet.nl/propose/ — NGI Zero Core funds free/open-source
> internet-infrastructure work, €5k–€50k, ~8-week decision cycles. Answers
> below follow the actual form fields. Keep the abstract under 1,200 chars
> when pasting.

## Project name

etp-custody — post-quantum, offline-verifiable chain of custody

## Website / repository

https://github.com/0xSoftBoi/Entanglement-Transfer-Protocol

## Abstract (form: "Can you explain the whole project and its expected outcome(s)?")

Digital evidence, research data, and regulated records all share a problem:
proving *what happened to a file* — who captured it, when, and that the
record of custody has not been rewritten — without trusting a single
operator, and in a way that will still verify decades from now.

etp-custody is an Apache-2.0 toolchain that gives any file a portable,
cryptographically verifiable custody trail. Files are sealed client-side
with post-quantum primitives (ML-KEM-768/FIPS 203 + XChaCha20-Poly1305);
only content hashes reach the notary, which maintains an RFC-6962
transparency log (the Certificate Transparency construction) with tree
heads signed by ML-DSA-65 (FIPS 204). The resulting receipt — manifest,
inclusion proof, signed tree head — verifies fully offline. Optional
layers add capturing-device attestation (two-party accountability),
witness cosigning (split-trust between independent operators), k-of-n
erasure bundles for delay-tolerant/degraded networks, and in-toto
attestation output for supply-chain interop.

The expected outcome is boring in the best way: a small, audited,
self-hostable piece of internet infrastructure that makes "provable
custody" as routine as "checksums" — with no capability ever gated behind
payment.

## How does the project relate to the NGI mission?

It restores user agency over a function currently answered only by
proprietary SaaS (evidence-management vendors, e-signature platforms) or
by vertical-locked schemes (C2PA's camera-vendor PKI). Verification
requires no account, no network, and no trust in the operator — the
receipt is self-contained. The log construction makes operator misbehavior
(history rewriting, split views) cryptographically detectable, and witness
cosigning distributes that trust further. All of it is post-quantum,
addressing the harvest-now-decrypt-later window for records whose
retention obligations (medical, legal, archival) exceed RSA/ECC's horizon.

## Requested amount and budget breakdown

**€38,000**, approximately:

- €14k — independent cryptographic protocol review (external audit of the
  canonical encoding, domain separation, log construction, and receipt
  semantics) and fixes arising from it
- €10k — witness-network hardening: gossip/equivocation exchange between
  independent witnesses, so split-view detection works without manual
  receipt comparison
- €7k — packaging and reproducibility: reproducible builds, Debian/Nix
  packaging, signed releases, SBOM + in-toto attestation of our own
  pipeline
- €4k — documentation: threat-model doc for non-cryptographers,
  operator runbook, and a "custody for archivists/journalists" guide
- €3k — accessibility and i18n pass on the web verifier (it must work for
  a source or archivist on any device, in their language)

## Comparison with existing efforts

- **sigstore/rekor** — signs and logs *public software artifacts*;
  no confidentiality, custody, or offline receipts. We reuse its lesson
  (transparency logs win) for private files.
- **C2PA/Content Credentials** — media provenance bound to camera-vendor
  PKI; not general-purpose, not post-quantum, verification depends on a
  vendor trust list.
- **OpenTimestamps** — proves existence-at-time only; no sealing, no
  custody chain, no PQ signatures.
- **Notary v1 (graveyard)** — we explicitly adopt its post-mortem lessons:
  no key ceremonies for users, zero-ceremony defaults, verification always
  free.

No existing free-software project combines client-side PQ sealing,
CT-style accountable logging, device attestation, and offline receipts.

## Significant technical challenges

Equivocation detection across witnesses without a central coordinator;
keeping the canonical encoding minimal and audit-friendly while spanning
Python and browser JavaScript (the SHA3/Keccak and proof verifier are
already cross-tested between the two); post-quantum signature size
management in receipts intended to be embedded and carried around
(ML-DSA-65 signatures are ~3.3 kB).

## Ecosystem / dissemination

Everything stays Apache-2.0 (a public promise in the repo: the crypto and
`verify` are never re-licensed or gated). Dissemination via the existing
launch plan: Hacker News, awesome-cryptography/awesome-security indices,
packaging into distro repositories, and conference submissions
(FOSDEM security devroom, IFF for the journalist/archivist audience).

## Team

Solo maintainer with the codebase already at ~1,550 passing tests,
CI with a cross-language verifier check, and a formally-documented
threat model (`docs/THREAT_MODEL.md`). Funding buys the external review
and the witness-network work a solo maintainer cannot self-certify.

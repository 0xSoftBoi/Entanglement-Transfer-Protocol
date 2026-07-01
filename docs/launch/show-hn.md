# Show HN draft (F1)

> Playbook notes (`docs/FREE_OPEN_PLAYBOOK.md`): post Monday ~8–9am ET, be in
> the comments all day, seed ~100 stars from the network *before* posting.
> Title ≤ 80 chars. First comment is yours — pre-write it (below).

## Title

Show HN: etp-custody – post-quantum chain of custody for files (CLI, offline-verifiable)

*(fallbacks, in preference order)*

- Show HN: A post-quantum notary whose receipts verify offline
- Show HN: Tamper-evident file custody with ML-DSA receipts and a transparency log

## URL

https://github.com/0xSoftBoi/Entanglement-Transfer-Protocol

## Pre-written first comment (post immediately after submitting)

Hi HN — I built this because every "secure file transfer" tool answers
*who can read it* but not *what happened to it*: who captured this file,
when, and has anyone rewritten that history since?

`etp-custody` is a small CLI (plus an optional self-hostable notary) that
gives a file a verifiable custody trail:

- **Seal locally** — ML-KEM-768 + XChaCha20-Poly1305 (FIPS 203). Plaintext
  never leaves your machine; the notary only ever sees hashes.
- **Notarize** — the capture manifest goes into an RFC-6962 transparency
  log (same construction as Certificate Transparency), and the signed tree
  head is ML-DSA-65 (FIPS 204). Append-only is provable, equivocation is
  detectable.
- **Portable receipt** — a JSON file containing the manifest, an inclusion
  proof, and the signed tree head. `etp-custody verify file.pdf` checks all
  of it **offline** — no account, no server, no network.
- **Optional extras** — device-key attestation (two-party: operator + the
  capturing device), k-of-n erasure bundles for links that drop (sneakernet,
  DTN), in-toto statement output, and on-chain anchoring of tree heads if
  you want a public timestamp.

What it is *not*: it's not sigstore (that signs artifacts; this tracks
custody of arbitrary files), not C2PA (media-specific, camera-vendor PKI),
and not OpenTimestamps (timestamps only, no confidentiality, not PQ).
The niche is the intersection: post-quantum sealing + CT-style
accountability + receipts that survive with the file.

Honest caveats, before you find them yourselves:

- The PQC is real (FIPS 203/204 via pqcrypto), but the *protocol* has not
  had an external audit. Don't bet a court case on it yet.
- ML-KEM-768/ML-DSA-65 sit below CNSA 2.0's parameter picks — fine for
  most uses, a known gap for US national-security systems.
- The hosted notary is a convenience, not a trust root: verification is
  designed so you never have to trust us, and the free tier is the whole
  cryptographic product. We charge for hosting and anchoring, never for
  verify.

~1,550 Python tests plus a browser verifier whose SHA3 is cross-tested
against the Python implementation. Everything is Apache-2.0. I'll be in
the comments all day — tear it apart.

## Anticipated questions (prep, don't paste)

- **"Why not just sigstore/rekor?"** — Rekor logs signatures of public
  artifacts. This seals private files client-side and logs only manifests;
  the receipt travels with the file and verifies offline. Different job.
- **"Quantum computers don't exist"** — harvest-now-decrypt-later is the
  threat model for sealing; for signatures it's about receipt longevity
  (custody records outlive RSA's horizon).
- **"Is the blockchain part required?"** — No. Anchoring is optional and
  off by default; the transparency log stands alone. The chain only ever
  sees 32-byte roots.
- **"Who operates the log?"** — You can. `etp-custody serve` runs the same
  notary the cloud runs; witness cosigning lets a second operator
  countersign your tree heads.

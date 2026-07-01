# etp-custody — Post-Quantum Tamper-Evident Chain-of-Custody (CLI)

A working product built on ETP's core: **seal a file, notarize it, hand someone a
receipt they can verify offline — post-quantum, no blockchain, no server.**

This is the "provenance wedge" the market/funding/prior-art research pointed at:
the one capability that is unfunded, uncontested at the fusion level, and rides a
real compliance/defense buyer need (tamper-evident custody of long-lived
confidential data). PQC and Merkle logs are individually commodity — the product
is the *fused, portable, offline-verifiable custody workflow*.

## What it does

1. **Seals** an artifact to a recipient with **ML-KEM-768 + XChaCha20-Poly1305**
   at a **constant 1128-byte overhead** regardless of payload size (the
   harvest-now-decrypt-later defense — confidential for years/decades).
2. **Notarizes** a manifest (originator, timestamp, content hash, sealed hash)
   into an append-only **RFC-6962 Merkle log**, attested by an **ML-DSA-65**
   signed tree head.
3. **Emits a portable receipt** — a self-contained JSON blob that lets *anyone*
   prove authenticity and non-tampering with no access to the log, the plaintext,
   or any secret key.

## Install

```bash
pip install -e ".[crypto]"     # real PQC: pqcrypto (FIPS 203/204) + pynacl (libsodium)
# then the `etp-custody` command is on your PATH
# in-repo without install:  PYTHONPATH=. python -m src.ltp.provenance_cli ...
```

Real PQC is **required** — the CLI refuses to run on the PoC hash fallback, whose
keys are not portable across processes.

## Quickstart

```bash
# 1. make keys (operator runs the notary; bob is the authorized recipient)
etp-custody keygen -o operator.key --label notary
etp-custody keygen -o bob.key --label bob --pub bob.pub     # bob.pub is shareable

# 2. operator stands up a notary
etp-custody init ./notary --operator operator.key

# 3. seal + notarize a file to bob → sealed blob + receipt
etp-custody seal ./notary --in report.pdf --to bob.pub --originator sensor-7 \
    --meta class=restricted --out report.sealed --receipt report.receipt

# 4. ANYONE verifies provenance offline (no keys, no plaintext) — exit 0 = PASS
etp-custody verify --sealed report.sealed --receipt report.receipt

# 5. only bob can recover the plaintext (re-checks the notarized content hash)
etp-custody open --key bob.key --sealed report.sealed --receipt report.receipt -o report.pdf

# inspect the notary
etp-custody log ./notary
```

## Commands

| Command | Purpose |
|---|---|
| `keygen -o KEY [--label L] [--pub PUB]` | Generate a PQ keypair; optionally write a shareable public key |
| `pub -i KEY -o PUB` | Extract the public key from a secret key file |
| `init DIR --operator KEY` | Initialize a notary store |
| `seal DIR --in F --to PUB --originator ID [--out S] [--receipt R] [--meta k=v]` | Seal + notarize a file |
| `publish DIR` | Publish a signed tree head (attestation) over the current log |
| `verify --sealed S --receipt R [--operator PUB]` | Verify a receipt against a sealed blob (offline). Exit 0=PASS, 1=FAIL. Pass `--operator` to require a specific trusted notary |
| `open --key KEY --sealed S [--receipt R] -o OUT` | Recover plaintext (authorized recipient only) |
| `log DIR` | Show notary state |

## Security properties (all covered by tests)

- **Confidentiality:** only the sealed-to recipient's ML-KEM key can open a
  capture; a wrong key fails decapsulation.
- **Constant overhead:** `sealed_size − payload_size == 1128` for any payload.
- **Tamper-evidence:** altering the sealed blob, swapping the manifest, forging
  the STH root, or pairing a receipt with the wrong blob all make `verify` FAIL.
- **Authenticity:** the operator's ML-DSA-65 STH signature binds the attested
  root; verification needs no plaintext and no secret.
- **Append-only:** the log can only grow; consistency is provable via RFC-6962.
- **Offline & portable:** a `.sealed` file + a `.receipt` are sufficient to prove
  custody forever, with no server and no chain.

> ⚠ **Operator trust — pin the notary key.** A valid receipt proves that *some*
> operator key attested the capture, not that *your trusted* notary did. An
> attacker can run their own notary and produce a receipt that verifies with a
> self-asserted `originator_id`. To prove a specific, trusted notary signed it,
> pass `--operator <notary.pub>` to `verify` (or `expected_operator_vk=` to the
> library). Without pinning, `verify` proves internal consistency, not authenticity.

## On-disk artifacts

- **Notary store** (`init`): `operator.key` (secret, chmod 600), `records.jsonl`
  (append-only manifests), `sths.jsonl` (published tree heads), `meta.json`. The
  log is deterministically rebuilt by replaying `records.jsonl`.
- **Sealed blob** (`.sealed`): raw ML-KEM sealed bytes — opaque without the key.
- **Receipt** (`.receipt`): JSON (`etp-provenance-receipt/1`) bundling the
  manifest, the O(log N) inclusion proof, and the signed tree head.

## Honest scope & the production path

This is a real, working MVP — but a production build should stand on mature,
permissively-licensed OSS rather than the repo's hand-rolled internals (see
[`usecases/PRIOR_ART_OSS.md`](usecases/PRIOR_ART_OSS.md)):

- **PQC primitives** → liboqs / AWS-LC (FIPS 140-3) instead of the bundled backend.
- **Erasure hot-path** (for large-file / lossy-link shards) → `cberner/raptorq`.
- **Transparency log** at scale → `transparency-dev/tessera` + `sigstore/rekor`.

The defensibility is the **integration + formal discipline + the buyer
relationship**, not the crypto — every individual pillar is commodity, and a
near-twin (`Apolloccrypt/paramant-relay`) exists for the PQC-log subset. Lead the
story on the fused, offline-verifiable custody workflow for a specific hard
environment (disconnected/adversarial, regulated long-term confidentiality), not
on "post-quantum" or "we built a Merkle log."

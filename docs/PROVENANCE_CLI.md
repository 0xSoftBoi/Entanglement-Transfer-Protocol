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

## The two-command flow (`send` / `receive`)

For the common case, `send` and `receive` fold the whole pipeline into one
command each — seal + notarize + bundle on one side, reassemble + verify + open
on the other. `receive` **fails closed**: it never writes plaintext if
provenance doesn't verify.

```bash
# sender: seal + notarize + device-sign + erasure-bundle, all at once
etp-custody send ./notary --in report.pdf --to bob.pub \
    --originator sensor-7 --originator-key sensor7.key --n 6 --k 4 --prefix parcel
#   → parcel.receipt, parcel.bundle, parcel.shard000 … parcel.shard005

# transport the parcel over a lossy/disconnected link (some shards may be lost)

# receiver: reassemble from survivors, verify (pinning both keys), then open
etp-custody receive --key bob.key --bundle parcel.bundle --receipt parcel.receipt \
    --out report.pdf --operator op.pub --expect-originator sensor7.pub \
    parcel.shard000 parcel.shard002 parcel.shard003 parcel.shard005
```

The step-by-step commands below still exist for finer control.

For a whole directory (a satellite pass of image products, a clinic's daily
records), `batch-send` notarizes every file under **one append-only log** and
`batch-receive` reassembles/verifies/opens the lot, failing closed per file:

```bash
etp-custody batch-send ./notary --in-dir ./day/ --to bob.pub \
    --originator scanner-3 --originator-key scanner3.key --n 6 --k 4 --out-dir ./parcels/
# ...transport ./parcels/ (any file tolerates losing 2 of 6 shards)...
etp-custody batch-receive --key bob.key --in-dir ./parcels/ --out-dir ./recovered/ \
    --operator op.pub --expect-originator scanner3.pub
```

Every file in a batch shares one signed tree head, so `audit` reports any two of
them as the same checkpoint; audit a receipt from a *later* batch to prove
append-only growth over time.

## Commands

| Command | Purpose |
|---|---|
| `id [--pub PUB]` | Show/create your default identity (zero-ceremony) |
| `notarize FILE… [--attest]` | **One command, no keys:** seal + notarize with your identity; `--attest` also emits an in-toto attestation |
| `attest --receipt R [--subject S] [--out O]` | Convert a receipt into a standard in-toto attestation |
| `serve --operator KEY --api-key KEY [--port P]` | Run the hosted notary HTTP service |
| `send DIR --in F --to PUB --originator ID [--originator-key K] --n N --k K [--prefix P]` | One shot: seal + notarize + bundle |
| `receive --key KEY --bundle B --receipt R --out OUT [--operator PUB] [--expect-originator PUB] SHARD...` | One shot: reassemble + verify + open (fails closed) |
| `batch-send DIR --in-dir SRC --to PUB --originator ID [--originator-key K] --n N --k K --out-dir OUT` | Seal + notarize + bundle every file in a directory (one append-only log) |
| `batch-receive --key KEY --in-dir OUT --out-dir DST [--operator PUB] [--expect-originator PUB]` | Reassemble + verify + open every file in a batch |
| `keygen -o KEY [--label L] [--pub PUB]` | Generate a PQ keypair; optionally write a shareable public key |
| `pub -i KEY -o PUB` | Extract the public key from a secret key file |
| `init DIR --operator KEY` | Initialize a notary store |
| `seal DIR --in F --to PUB --originator ID [--originator-key K] [--out S] [--receipt R] [--meta k=v]` | Seal + notarize a file; `--originator-key` makes the capturing device cryptographically sign it |
| `publish DIR` | Publish a signed tree head (attestation) over the current log |
| `verify --sealed S --receipt R [--operator PUB]` | Verify a receipt against a sealed blob (offline). Exit 0=PASS, 1=FAIL. Pass `--operator` to require a specific trusted notary |
| `open --key KEY --sealed S [--receipt R] -o OUT` | Recover plaintext (authorized recipient only) |
| `bundle --in S --n N --k K [--prefix P]` | Erasure-code a sealed blob into N shards; any K reconstruct |
| `reassemble --bundle B --out S SHARD...` | Reconstruct a sealed blob from any K surviving shards |
| `inspect --receipt R [--bundle B] [SHARD...]` | Describe a receipt/parcel and check internal validity (no keys) |
| `audit DIR RECEIPT_A RECEIPT_B` | Verify two receipts are from one append-only log (no rewrite/fork) |
| `log DIR` | Show notary state |

## Hosted notary (Notary-as-a-Service)

The SaaS backend. Run a notary as an HTTP service; clients seal **locally** and
submit only the public manifest (hashes + signatures, never plaintext or the
sealed blob), so the service is **zero-knowledge of content** by construction.
It meters submissions per API key — the billable unit is a *notarized capture*.

```bash
# operator runs the service
etp-custody serve --operator op.key --port 8080 --api-key SECRET-KEY-123
```

```python
# client SDK: seal locally, notarize remotely, verify the receipt offline
from ltp.notary_server import NotaryClient
c = NotaryClient("http://localhost:8080", api_key="SECRET-KEY-123")
op_vk = c.operator_vk()                                   # pin the notary's key
capture, receipt = c.notarize(data, bob_ek, originator_id="finance-app")
assert receipt.verify(capture.sealed, expected_operator_vk=op_vk)
print("captures billed:", c.usage())
```

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /healthz` | – | liveness + total captures |
| `GET /v1/operator` | – | the operator public key to pin |
| `GET /v1/sth` | – | latest signed tree head |
| `GET /v1/proof/<i>` | – | inclusion proof |
| `POST /v1/captures` | API key | submit a manifest → receipt (metered) |
| `GET /v1/usage` | API key | notarized-capture count for the key |

Reference single-log service (stdlib only). The enterprise layer — multi-tenant
log isolation, HSM-held operator keys, witness cosigning, durable storage, rate
limits, billing export — sits on top of this same core.

## Inspecting and auditing

`inspect` is a keyless, read-only diagnostic — it prints what a receipt claims and
runs the structural checks that don't need secrets: the operator's STH signature,
that the inclusion proof reconstructs the attested root, the originator (device)
signature if present, and — given `--bundle` + shards — whether enough valid
shards are present to reconstruct. Use it to triage a parcel before `receive`.
It reports facts and internal soundness, not authenticity (that needs pinning via
`verify`/`receive`).

`audit` is the *consistency* half of the transparency log (inclusion proofs are
the other). Given two receipts from a notary, it proves via an RFC-6962
consistency proof that the later log state is an append-only extension of the
earlier — i.e. the notary did not rewrite or fork history between them. Collect
receipts over time and audit any pair to hold the notary honest.

## Delay-tolerant transport (erasure-coded bundles)

A sealed capture is one opaque blob — on a lossy or disconnected link (a
satellite pass, a tactical mesh, a data mule crossing a gap) a single dropped
packet loses it. `bundle` splits the blob into *N* forward-error-corrected
shards, **any *K* of which reconstruct it** — no ARQ round-trip. Spray the shards
over the link (or across several passes / couriers); the receiver reassembles
from whichever *K* arrive intact. Provenance is untouched: the reassembled blob
is byte-identical, so the **same receipt still verifies**.

```bash
# sender: seal, then bundle into 6 shards (tolerates losing any 2)
etp-custody seal ./notary --in report.pdf --to bob.pub --originator sensor-7 \
    --out report.sealed --receipt report.receipt
etp-custody bundle --in report.sealed --n 6 --k 4 --prefix report
#   → report.bundle + report.shard000 … report.shard005

# receiver: only 4 of 6 shards arrived → still reconstructs
etp-custody reassemble --bundle report.bundle --out report.sealed \
    report.shard000 report.shard002 report.shard004 report.shard005
etp-custody verify --sealed report.sealed --receipt report.receipt   # PASS
```

Corrupt shards (hash-mismatched against the bundle manifest) are dropped
automatically before decoding, and reconstruction is rejected if it doesn't
match the notarized `sealed_hash`. Choose `--n`/`--k` for the link's loss rate
(e.g. `--n 6 --k 4` tolerates ~33% loss). *Note:* the erasure coder is the
repo's reference pure-Python Reed–Solomon — correct but not line-rate; a
production build swaps in a native backend (e.g. `raptorq`) behind the same API.

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

> ⚠ **Trust anchors — pin the keys you rely on.** A valid receipt proves that
> *some* operator key attested the capture, not that *your trusted* notary did,
> and a bare `--originator ID` is just a string the operator recorded. To prove
> a specific, trusted **notary**, pass `--operator <notary.pub>`. To prove the
> **capturing device itself** attested (not just the operator's word), have the
> device sign at seal time with `--originator-key <device.key>`, and require it
> at verify time with `--expect-originator <device.pub>`. Without pins, `verify`
> proves internal consistency, not authenticity.

### Two-party attestation

- **Operator (notary)** signs the tree head → "this capture is in my append-only log."
- **Originator (device)** signs `(originator_id, content_hash, captured_at)` →
  "*I*, sensor-7, captured this exact content at this time." Notarized in the log
  alongside the manifest. Pin both (`--operator` + `--expect-originator`) for a
  full, forgery-resistant chain of custody.

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

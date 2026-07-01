# awesome-list submissions + repo metadata (F3)

> These are copy-paste-ready PR entries. Each awesome list wants a one-line
> entry in its existing format, alphabetized within its section, submitted as
> a single-line PR from a fork. Submit *after* the repo has its topics set and
> a release tagged — list maintainers check for signs of life.

## GitHub repo metadata (set first)

**Description (repo "About"):**
> Post-quantum chain of custody for files: seal locally (ML-KEM-768), notarize
> into an RFC-6962 transparency log (ML-DSA-65), verify receipts offline.

**Topics:**
`post-quantum-cryptography` `ml-kem` `ml-dsa` `transparency-log`
`chain-of-custody` `provenance` `certificate-transparency` `merkle-tree`
`fips-203` `fips-204` `notary` `in-toto` `python` `cli`

## awesome-cryptography (github.com/sobolevn/awesome-cryptography)

Section: *Python → Libraries* (or *Tools* if they prefer the CLI framing):

```markdown
- [etp-custody](https://github.com/0xSoftBoi/Entanglement-Transfer-Protocol) - Post-quantum chain of custody: ML-KEM-768 sealing, RFC-6962 transparency log with ML-DSA-65 signed tree heads, offline-verifiable receipts.
```

## awesome-security (github.com/sbilly/awesome-security)

Section: *Big Data → Forensics* or *Other Awesome Lists* adjacent — propose
under **Forensics/Evidence**:

```markdown
- [etp-custody](https://github.com/0xSoftBoi/Entanglement-Transfer-Protocol) - Tamper-evident, post-quantum chain of custody for files; receipts verify offline, history rewrites are cryptographically detectable.
```

## awesome-post-quantum (github.com/pqcrypto-org lists / veorq mirrors)

```markdown
- [etp-custody](https://github.com/0xSoftBoi/Entanglement-Transfer-Protocol) - File custody built on FIPS 203/204: ML-KEM-768 client-side sealing + ML-DSA-65 signed transparency log, with erasure-coded bundles for delay-tolerant links.
```

## awesome-supply-chain-security (github.com/bureado/awesome-software-supply-chain-security)

Section: *Attestation / provenance* (emits in-toto Statement v1):

```markdown
- [etp-custody](https://github.com/0xSoftBoi/Entanglement-Transfer-Protocol) - Post-quantum provenance notary emitting in-toto attestations; RFC-6962 log, offline verification, optional on-chain anchoring.
```

## Homebrew tap (playbook F3, later)

Ship as a personal tap first (`0xSoftBoi/homebrew-etp`), core later if the
star count justifies it:

```ruby
class EtpCustody < Formula
  include Language::Python::Virtualenv
  desc "Post-quantum chain of custody for files"
  homepage "https://github.com/0xSoftBoi/Entanglement-Transfer-Protocol"
  url "https://github.com/0xSoftBoi/Entanglement-Transfer-Protocol/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "<fill from the tagged release tarball>"
  license "Apache-2.0"
  depends_on "python@3.12"
  def install
    virtualenv_install_with_resources
  end
  test do
    system bin/"etp-custody", "--help"
  end
end
```

## Submission checklist (human acts, in order)

1. Set repo description + topics (above).
2. Tag `v0.1.0` release with notes.
3. Star-seed from network (playbook F4) — lists and HN both convert on it.
4. Open the four awesome-list PRs (single line each, follow each repo's
   CONTRIBUTING).
5. Homebrew tap after the release tag exists.

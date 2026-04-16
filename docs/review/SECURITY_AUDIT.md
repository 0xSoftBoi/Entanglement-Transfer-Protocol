# Entanglement Transfer Protocol Security Audit

## Summary

This audit is optimized for both:

- exploitability and protocol/security correctness
- deployment risk and operator-facing misconfiguration or false-assurance risk

The codebase does not present one obvious total protocol break in the core COMMIT/LATTICE/MATERIALIZE path. The larger problem is that several surrounding layers overstate their assurance. In practice, the highest-risk issues are:

1. false custody and HSM boundary claims
2. crypto-mode and compliance claims that can silently degrade into PoC behavior
3. insecure default network surfaces
4. simulation-heavy trust layers presented too close to production-grade components

## Method and Evidence

Review method:

- source inspection of Python and Solidity code
- trust-boundary and invariant review across crypto, storage, transport, bridge, and governance surfaces
- targeted test execution as evidence, not proof

Observed checks from this pass:

- `python3 -m pytest tests/test_protocol.py tests/test_bridge.py -q` passed in an earlier direct run in this environment
- `python3 -m pytest tests/test_network.py -q` failed during fixture startup
- `python3 -m pytest tests/test_contract_integration.py -q` ran but all 17 tests were skipped because prerequisites were not active

Interpretation:

- the core protocol path has direct local execution evidence
- networking correctness is undercut by a broken test surface
- Solidity/Python integration exists, but the default environment does not execute it

## Security Posture

### Stronger areas

- the protocol core has a coherent separation between ciphertext shard storage and CEK transfer
- the on-chain registry contract has a reasonably narrow state machine and signer/sequence controls
- the codebase is explicit in some places about PoC or simulated behavior

### Weaker areas

- custody and compliance-adjacent modules imply stronger guarantees than they actually enforce
- transport security is not intrinsic to the default networking surfaces
- some major extension layers are simulations or trust models rather than hardened production systems
- top-level documentation uses production language that is not consistently justified by the implementation

## Findings

Each finding includes:

- `Severity`: security impact if real or relied on
- `Exploitability`: whether this is directly exploitable, conditionally exploitable, or primarily an assurance failure
- `Deployment risk`: whether this can mislead operators into a bad production posture

## Critical Findings

### 1. HSM-backed key generation does not preserve an HSM boundary

- `Severity`: Critical
- `Exploitability`: directly exploitable if operators trust the HSM mode
- `Deployment risk`: severe

Affected code:
- `src/ltp/keypair.py`
- `src/ltp/hsm.py`

Evidence:
- `KeyPair.generate(..., hsm=...)` takes an HSM path and records an HSM key id
- it then still generates normal local `MLKEM` and `MLDSA` private keys in process
- the resulting `KeyPair` object still contains usable `dk` and `sk` bytes

Why it matters:
- the code comments and module framing imply that private keys stay inside an HSM boundary
- they do not
- any process compromise, debug dump, serialization path, or memory disclosure still exposes the keys needed for decapsulation and signing

Exploit / failure scenario:
- an operator enables HSM-backed mode assuming custody isolation
- an attacker compromises the application process or reads exported state
- the attacker obtains software private keys even though the operator believed hardware custody was in effect

Remediation direction:
- separate HSM-backed key handles from software key objects
- never populate plaintext-equivalent private key fields when the HSM path is chosen
- route signing and decapsulation through the HSM interface only
- add tests that assert HSM-backed objects cannot be used as software keys

## High Findings

### 2. “Real crypto” and compliance language can collapse into simulated or PoC behavior

- `Severity`: High
- `Exploitability`: conditionally exploitable through misconfiguration and false assurance
- `Deployment risk`: severe

Affected code and docs:
- `README.md`
- `src/ltp/primitives.py`
- `src/ltp/compliance.py`
- `src/ltp/zk_transfer.py`

Evidence:
- README claims “real crypto, no simulations”
- `primitives.py` explicitly warns when pqcrypto backends are unavailable and PoC crypto simulations are being used
- `FIPSCryptoProvider` in `compliance.py` can fall back to non-FIPS behavior if the `cryptography` package is unavailable for AES-GCM, even while the surrounding module is framed as institutional/FIPS-oriented
- `zk_transfer.py` explicitly uses simulated proofs/commitments in current code

Why it matters:
- this is not just a docs problem
- operators, auditors, and downstream engineers may believe they are running stronger crypto and compliance modes than they actually are
- a security-sensitive deployment can be materially weaker without obvious runtime fail-closed behavior

Exploit / failure scenario:
- a deployment omits real PQ or AEAD dependencies
- the app still starts with PoC or fallback behavior
- teams ship or audit the system using README-level claims instead of runtime-truth checks

Remediation direction:
- define explicit runtime assurance modes: development, simulated, production, compliance-strict
- fail closed when production/compliance modes are requested but real backends are absent
- surface the active crypto mode at startup and through diagnostics
- rewrite status language to match actual code paths

### 3. Network surfaces are unauthenticated and unencrypted by default

- `Severity`: High
- `Exploitability`: directly exploitable if reachable on an untrusted network
- `Deployment risk`: high

Affected code:
- `src/ltp/network/server.py`
- `src/ltp/network/client.py`
- `src/ltp/network/remote.py`
- `src/ltp/rest_server.py`

Evidence:
- gRPC server uses `add_insecure_port(...)`
- gRPC client uses `grpc.insecure_channel(...)`
- `RemoteNode` makes remote shard mutation and retrieval quack like a local trusted node
- REST server uses stdlib `HTTPServer` with no built-in auth, TLS, or rate limiting

Why it matters:
- shard store/fetch/remove and audit calls are part of the active data plane
- the API shape makes remote operations easy to treat as trusted local ones
- if these services are exposed beyond localhost or a tightly controlled network, attackers can inject, scrape, replay, or disrupt operations

Exploit / failure scenario:
- an operator deploys remote nodes in a flat internal network or over public infrastructure
- an attacker tampers with shard operations, scrapes metadata, or floods audit and log endpoints
- the team assumes the protocol’s cryptographic framing extends to the transport layer when it does not

Remediation direction:
- make authenticated transport the default production mode
- add TLS or mTLS for gRPC
- require authz around mutating REST endpoints or remove write surfaces from public-facing HTTP
- mark current transport mode as development-only if left insecure

### 4. ZK transfer mode weakens the project’s PQ security story and remains partly simulated

- `Severity`: High
- `Exploitability`: mostly misuse-driven, not an immediate code exploit
- `Deployment risk`: high

Affected code:
- `src/ltp/zk_transfer.py`

Evidence:
- the module itself states Groth16 over BLS12-381 is not post-quantum safe
- the implementation defaults to simulated commitments/proofs for several behaviors

Why it matters:
- the repo markets a PQ protocol
- this optional mode is neither equivalent in assurance nor fully implemented as a hardened alternative
- it risks letting teams collapse “privacy extension” and “same security guarantees” into one mental model

Exploit / failure scenario:
- a deployment enables ZK mode for sensitive workflows
- the team still models the end-to-end system as post-quantum safe
- the threat model is silently downgraded

Remediation direction:
- hard-separate baseline PQ mode from privacy-experimental modes
- require explicit non-PQ acknowledgement to enable Groth16 mode
- keep simulated proof systems out of any production-labeled path

## Medium Findings

### 5. Federation trust establishment is more modeled than verified

- `Severity`: Medium
- `Exploitability`: conditionally exploitable if deployed as real cross-network trust
- `Deployment risk`: high

Affected code:
- `src/ltp/federation.py`

Evidence:
- `verify_sth(...)` performs structure and monotonicity checks
- the cryptographic verification path is represented as a simulated hash step rather than full serialized ML-DSA verification

Why it matters:
- federation is one of the repo’s main remote-trust stories
- if this path is used as if it were production-grade, the remote identity guarantee is weaker than expected

Exploit / failure scenario:
- independent deployments use federation as a real trust bridge
- remote state is accepted based on a modeled flow rather than a fully hardened signature-verification protocol

Remediation direction:
- define canonical STH serialization
- require real signature verification for non-simulated federation modes
- explicitly label federation modes by assurance level

### 6. Backend naming and framing overstate assurance relative to implementation

- `Severity`: Medium
- `Exploitability`: not a direct exploit by itself
- `Deployment risk`: high

Affected code:
- `src/ltp/backends/ethereum.py`
- `src/ltp/backends/monad_l1.py`
- parts of `src/ltp/bridge/anchor.py`

Evidence:
- Ethereum and Monad modules spend significant effort describing production chain architectures
- their Python implementations still keep substantial chain semantics in local simulated state
- bridge anchoring also includes simulated sequencing and block progression in parts of the flow

Why it matters:
- backend selection is a trust-boundary decision
- a simulated local chain model is not equivalent to finality and auditability from a live chain

Exploit / failure scenario:
- operators or reviewers assume that choosing a backend module means the associated assurance exists
- the real system remains a local model until additional external infra is attached

Remediation direction:
- label simulation-backed modules aggressively
- split simulation adapters from live-infra adapters
- ensure architecture and docs do not imply equal assurance across modes

### 7. Compliance framework has real control logic mixed with non-compliance fallback behavior

- `Severity`: Medium
- `Exploitability`: mostly misconfiguration and false-assurance risk
- `Deployment risk`: high

Affected code:
- `src/ltp/compliance.py`

Evidence:
- the module is framed for banking/government/institutional deployment
- `FIPSCryptoProvider` checks for OpenSSL/FIPS availability, but AES-GCM operations still fall back to non-FIPS testing behavior when `cryptography` is unavailable
- the overall module surface mixes policy/control modeling with optional or simulated backend behavior

Why it matters:
- compliance code is particularly dangerous when it partially enforces and partially simulates under the same conceptual surface
- teams can treat module presence as equivalent to compliance posture

Exploit / failure scenario:
- an institutional deployment enables a FIPS-oriented mode without all required dependencies
- the runtime quietly falls back into a non-compliant path in practice

Remediation direction:
- fail closed for compliance-strict mode
- separate compliance modeling from compliance-enforcing runtime paths
- emit explicit startup diagnostics for unavailable control dependencies

### 8. Network test failures reduce confidence in the most exposed transport layer

- `Severity`: Medium
- `Exploitability`: indirect
- `Deployment risk`: medium

Affected code:
- `tests/test_network.py`
- `src/ltp/network/server.py`

Evidence:
- `tests/test_network.py` constructs `NodeServer(..., port=0, host="localhost")`
- `NodeServer.__init__` binds immediately
- the suite fails at fixture startup in this environment before real networking assertions run

Why it matters:
- the network layer is already one of the weaker security surfaces
- a broken regression suite means operational and correctness drift is easier to miss

Remediation direction:
- support ephemeral-port behavior correctly or stop eager binding in `__init__`
- make the network suite a reliable baseline before hardening transport further

### 9. Contract integration coverage is present but not routine in a default environment

- `Severity`: Medium
- `Exploitability`: indirect
- `Deployment risk`: medium

Affected code:
- `tests/test_contract_integration.py`
- `src/ltp/anchor/client.py`

Evidence:
- the suite requires `web3` and a running `anvil`
- in this environment all tests were skipped
- the anchor client itself assumes live operator credentials and RPC reachability for real anchoring

Why it matters:
- the registry contract is one of the strongest intended trust boundaries
- if integration coverage is usually skipped, Python/contract drift can persist unnoticed

Remediation direction:
- move contract integration into CI with a managed local EVM
- treat skipped integration as reduced assurance, not as de facto passing coverage

## Low Findings

### 10. Upgrade and governance safety depends on deployment architecture, not only contract code

- `Severity`: Low
- `Exploitability`: deployment-dependent
- `Deployment risk`: medium if documented poorly

Affected code:
- `contracts/src/LTPAnchorRegistry.sol`
- `contracts/src/LTPMultiSig.sol`

Evidence:
- `LTPAnchorRegistry` uses `onlyAdmin` for upgrade authorization
- `LTPMultiSig` is explicitly documented in code as a lightweight testnet-oriented multisig, with production expected to use stronger tooling such as Gnosis Safe

Why it matters:
- the contract layer is not self-sufficient governance
- the real control path depends on how `admin` is assigned and what governance wrapper is actually deployed

Remediation direction:
- document the real governance dependency chain explicitly
- ensure deployed admin is a stronger governance primitive than a single operator key

## Testing and Coverage Gaps

The most important test-shape conclusions from this audit are:

- core protocol and bridge flows have actual local execution evidence
- the network layer has a currently broken basic suite
- on-chain integration exists but does not run by default
- several assurance-sensitive areas, including compliance and federation, are more strongly represented by code comments and design intent than by hard negative-path tests

That means the confidence gradient across the repo is uneven:

- strongest: core local protocol logic
- moderate: bridge and commitment modeling
- weaker: network transport, federation, compliance posture, and live contract integration

## Recommended Priority Order

1. Fix the HSM/custody boundary so the code stops claiming stronger isolation than it delivers.
2. Add hard runtime mode separation for crypto and compliance behavior.
3. Harden or explicitly de-scope insecure gRPC and REST transport.
4. Split simulated trust layers from production-facing layers in naming and docs.
5. Make network and contract integration tests routine and reliable.

## Final Assessment

This repo is not best understood as “broken crypto.” It is better understood as:

- a real protocol core
- surrounded by several ambitious platform layers
- where the main current security risk is overclaiming the assurance of those surrounding layers

If treated as a research/PoC codebase with a concrete core and several experimental or infra-dependent extensions, the implementation is much more coherent. If treated as a fully production-hardened institutional PQ transfer platform, the current code and test posture do not yet justify that claim.

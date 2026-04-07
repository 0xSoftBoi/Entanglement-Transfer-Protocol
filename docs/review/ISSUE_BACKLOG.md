# Entanglement Transfer Protocol Issue Backlog

This backlog is derived directly from the current architecture and security review. It is structured as issue-ready work, not as a general punch list.

The ordering below is intentional:

1. must-fix security and correctness issues
2. deployment-risk and assurance-separation work
3. documentation and test-coverage work that prevents the same confusion from recurring

## Must-Fix Security and Correctness Issues

### 1. Remove fake HSM custody from `KeyPair.generate`

- `Priority`: P0
- `Severity`: Critical
- `Subsystem`: `keypair`, `hsm`

Problem statement:
- The HSM path in `KeyPair.generate(..., hsm=...)` still creates live software `dk` and `sk` values, so the code claims an HSM boundary that does not exist.

Why it matters:
- This is both a real security issue and a severe operator-assurance failure. Anyone trusting this path for custody isolation is currently wrong.

Recommended fix direction:
- introduce a real HSM-backed key-handle type or equivalent abstraction
- stop materializing software private key bytes for HSM-managed keys
- route sign/decaps operations through the HSM interface only
- update all call sites that assume `KeyPair` always contains usable local private material

Test coverage needed:
- unit tests proving HSM-backed objects expose no plaintext private key material
- integration tests for sign and decapsulation through the HSM path
- negative tests that software-only paths reject HSM-backed handles when local private bytes are absent

### 2. Add explicit runtime assurance modes and fail closed outside development

- `Priority`: P0
- `Severity`: High
- `Subsystem`: `primitives`, `compliance`, startup/config

Problem statement:
- Real, simulated, and compliance-oriented crypto behavior are not cleanly separated. The runtime can degrade into PoC or non-compliant behavior while docs imply production-grade assurance.

Why it matters:
- This is the main source of silent security downgrade in the repo.

Recommended fix direction:
- define explicit modes such as `development`, `simulated`, `production`, and `compliance-strict`
- require real PQ and AEAD backends for non-development modes
- require real compliance dependencies for `compliance-strict`
- emit startup diagnostics that state the active mode and the exact crypto/backend selections

Test coverage needed:
- startup/config tests for each mode
- fail-closed tests when required dependencies are missing
- diagnostic tests proving the active mode is visible and accurate

### 3. Harden gRPC and REST transport or explicitly de-scope them from production

- `Priority`: P1
- `Severity`: High
- `Subsystem`: `network`, `remote`, `rest_server`

Problem statement:
- Remote shard and log operations are exposed over insecure transport with no built-in authentication or authorization.

Why it matters:
- This is directly exploitable if deployed on an untrusted network, and the current API shape makes remote nodes look more trusted than they are.

Recommended fix direction:
- add TLS or mTLS for gRPC
- require authentication and authorization for mutating endpoints
- decide whether HTTP write surfaces remain supported at all in production
- clearly label insecure transport as development-only if retained

Test coverage needed:
- secure-channel handshake tests
- unauthorized-access negative tests for both gRPC and REST
- replay, malformed-payload, and oversized-request tests

### 4. Separate compliance-enforcing paths from compliance-shaped modeling

- `Priority`: P1
- `Severity`: High for deployment risk, Medium for direct exploitability
- `Subsystem`: `compliance`

Problem statement:
- The compliance framework mixes real control logic with fallback and simulated behavior under one institutional-facing surface.

Why it matters:
- Compliance failures are especially dangerous when they masquerade as successful secure operation.

Recommended fix direction:
- define which code paths are enforcing versus illustrative
- remove non-compliant fallback behavior from compliance-strict mode
- split policy modeling helpers from runtime enforcement paths where necessary

Test coverage needed:
- compliance-strict startup refusal tests
- tests that enforce required dependencies and backend combinations
- regression tests that forbid fallback into non-compliant crypto paths

## Medium-Risk Design and Assurance Debt

### 5. Make federation trust verification cryptographically real

- `Priority`: P1
- `Severity`: Medium
- `Subsystem`: `federation`

Problem statement:
- Federation trust establishment is closer to a modeled workflow than a hardened remote-verification protocol.

Why it matters:
- If used as a real trust bridge, this becomes a security boundary rather than a design sketch.

Recommended fix direction:
- define canonical STH serialization
- verify real ML-DSA signatures in non-simulated modes
- separate federation assurance levels in config and docs

Test coverage needed:
- valid and invalid signature tests
- monotonicity and replay tests
- mode-separation tests for simulated vs production federation

### 6. Split simulated backend implementations from live infrastructure adapters

- `Priority`: P1
- `Severity`: Medium
- `Subsystem`: `backends`, `bridge`, `anchor`

Problem statement:
- Ethereum, Monad, and parts of bridge anchoring mix local simulated state with production-style chain framing.

Why it matters:
- Backend choice looks like a trust-boundary choice, but today it often chooses a model rather than a real trust anchor.

Recommended fix direction:
- split local simulation classes from live RPC/on-chain adapters
- rename or relabel simulation-heavy modules and config paths
- make the architecture and docs reflect the assurance difference explicitly

Test coverage needed:
- tests for simulation mode behavior
- tests for live mode preconditions and failure handling
- mode separation tests so simulation behavior cannot appear under production labels

### 7. Hard-gate non-PQ and simulated ZK modes

- `Priority`: P2
- `Severity`: High for misuse, Medium for code maturity
- `Subsystem`: `zk_transfer`

Problem statement:
- ZK mode is not equivalent to the baseline PQ protocol but is easy to treat as an optional extension with the same assurance.

Why it matters:
- This is a likely operator and product-messaging failure point.

Recommended fix direction:
- require explicit acknowledgement to enable non-PQ proof systems
- move simulated proof behavior behind development/experimental mode gates
- document supported threat models per proof system in code and docs

Test coverage needed:
- config gating tests
- PQ-strict rejection tests
- proof-system-specific verification tests

### 8. Fix network fixture reliability before relying on network coverage

- `Priority`: P1
- `Severity`: Medium
- `Subsystem`: `network`, `tests`

Problem statement:
- `tests/test_network.py` currently fails at fixture startup because the server binds too early and the ephemeral-port path is broken in this environment.

Why it matters:
- The network layer is already high risk; broken tests make it easier to ship regressions there.

Recommended fix direction:
- support ephemeral-port allocation correctly or stop binding in `NodeServer.__init__`
- simplify the fixture so it allocates once and binds once

Test coverage needed:
- passing localhost round-trip tests
- regression test for ephemeral-port startup

### 9. Make contract integration a routinely executed assurance layer

- `Priority`: P1
- `Severity`: Medium
- `Subsystem`: `anchor`, `contracts`, `tests`

Problem statement:
- Contract integration exists, but it is not a default executed check and was fully skipped in this environment.

Why it matters:
- The anchor registry is one of the strongest intended trust boundaries, so Python/contract drift is expensive.

Recommended fix direction:
- run a local EVM in CI
- build contracts automatically in the integration job
- treat skipped integration as reduced assurance in reporting

Test coverage needed:
- CI execution of the full contract-integration suite
- negative tests around signer authorization, sequence monotonicity, expiry, and state transitions

## Documentation and Claim-Alignment Issues

### 10. Rewrite README status and security language to match code truth

- `Priority`: P1
- `Severity`: Medium
- `Subsystem`: repo docs

Problem statement:
- README language currently compresses implemented, simulated, experimental, and infra-dependent behavior into overly strong production-oriented status statements.

Why it matters:
- This is the main reason reviewers and operators will misread the repo.

Recommended fix direction:
- add explicit status buckets such as `implemented`, `simulated`, `experimental`, `requires external infra`
- rewrite the crypto, backend, HSM, compliance, and ZK status lines
- point readers to the architecture and security review docs as canonical repo-state references

Test coverage needed:
- none directly, but docs should link each production-style claim to a runnable or inspectable proof point where possible

### 11. Document the real governance dependency chain for anchoring upgrades

- `Priority`: P3
- `Severity`: Low
- `Subsystem`: contracts, deployment docs

Problem statement:
- `LTPAnchorRegistry` enforces `admin`, while the broader governance assurances depend on what admin is actually set to in deployment.

Why it matters:
- The contract is only as strong as the real admin path around it.

Recommended fix direction:
- document the expected deployment chain explicitly
- state that `LTPMultiSig` is testnet-oriented and not the final production governance answer
- record the production governance dependency in deployment docs

Test coverage needed:
- deployment-script or configuration validation proving the intended admin assignment

## Missing or Misleading Test Coverage

### 12. Add negative-path tests for transport abuse and malformed input

- `Priority`: P2
- `Severity`: Medium
- `Subsystem`: `network`, `rest_server`

Problem statement:
- Current network tests are mostly happy-path and do not exercise abuse conditions that matter for exposed services.

Why it matters:
- The most exposed surfaces need the strongest negative-path coverage.

Recommended fix direction:
- add malformed-request, replay, oversized-payload, timeout, and unauthorized-access tests
- include both gRPC and REST where those surfaces remain supported

Test coverage needed:
- a dedicated negative-path network suite

### 13. Add tests for assurance-mode separation

- `Priority`: P2
- `Severity`: Medium
- `Subsystem`: `primitives`, `compliance`, `zk_transfer`, `backends`

Problem statement:
- The repo relies too much on comments and mode intent instead of hard test-backed separation between simulated and production-labeled behavior.

Why it matters:
- Without these tests, the same assurance drift will reappear after refactors.

Recommended fix direction:
- add mode-specific test matrices
- assert that production and compliance modes reject simulated backends
- assert that experimental modes are visibly labeled and gated

Test coverage needed:
- end-to-end config and initialization tests across all assurance modes

## Suggested Execution Order

1. Remove fake HSM custody and define real key-handling boundaries.
2. Add runtime assurance modes and fail-closed crypto/compliance behavior.
3. Harden or de-scope insecure transport surfaces.
4. Repair network and contract-integration coverage so the riskiest layers are actually tested.
5. Split simulated trust layers from live-assurance layers in code and docs.
6. Rewrite README and deployment docs to match the implementation truth.

# Suwappu / LTP bridge profile for EIP-8355

Status: **experimental**. This profile is for devnets and standards work. It is not a claim that
Ethereum, stock OP-Reth, or the current GSX deployment has activated an ML-DSA precompile.

## Standards position

The bridge should compose existing standards instead of creating a competing ML-DSA Core EIP:

- **ERC-7786 (Final)** is the cross-chain gateway surface. An EVM gateway adapter should expose
  `IERC7786GatewaySource` and deliver only through `IERC7786Recipient.receiveMessage`.
- **ERC-7930 (Final)** supplies canonical interoperable sender/recipient addresses for ERC-7786.
- **EIP-8355 (Draft)** is the target on-chain signature primitive for this profile: pure FIPS 204
  **ML-DSA-65**, compact 1952-byte public keys, 3309-byte signatures, and raw variable-length
  messages.
- **EIP-8051 (Draft)** remains related work, but its current level-II-only, expanded-key and
  ML-DSA-ETH choices do not match LTP's existing ML-DSA-65/FIPS profile.
- **ML-KEM-768 / FIPS 203 stays off-chain.** It protects the sealed LatticeKey in the relay path;
  it is not part of EIP-8355 verification and should not be mixed into the on-chain signature API.

Current EIP-8355 precompile addresses are draft values. This repository deliberately does not bake
one into `LTPAnchorRegistry`: the registry points at an admin-configured verifier adapter, and the
EIP-8355 adapter points at a chain-specific precompile address.

For the Suwappu devnet, the chain profile now assigns ML-DSA-65 to
`0x0000000000000000000000000000000000008355` from Fjord onward. That value is Suwappu-local,
not a claim about the eventual EIP assignment. The companion OP-Reth deployment branch builds the
native verifier from a pinned maintained Optimism source revision.

## v6 authorization model

v5 accepted a caller-supplied `signerVkHash` after checking only that the hash was allowlisted.
That did not prove that the caller possessed the corresponding ML-DSA secret key.

v6 closes that boundary in two ways:

1. Legacy `anchor`, `batchAnchor`, and `transitionState` are admin-only migration paths.
2. Permissionless relayers use `anchorSigned` / `transitionStateSigned`. The registry derives
   the signer ID from the supplied public key, checks authorization, and requires the configured
   ML-DSA-65 verifier to validate a domain-separated message before any state change.

A zero verifier address disables signed writes and fails closed.

### EVM signer ID is not the LTP fingerprint

The signed EVM path uses:

```text
evmSignerId = keccak256(fips204PublicKeyBytes)
```

This is intentionally separate from `src/ltp/domain.py::signer_fingerprint`, which uses NIST
SHA3-256. Keccak-256 and SHA3-256 are different functions. Register signed-path keys with
`registerEIP8355Signer(publicKey)` (or use `eip8355SignerId(publicKey)`) rather than copying an
LTP fingerprint into the EVM allowlist.

### Exact signed messages

The ML-DSA context remains empty as required by the current EIP-8355 draft. Application domain
separation is therefore inside the raw message.

Anchor authorization is Solidity `abi.encode` of:

```text
keccak256("GSX-LTP:anchor-authorization:v1"),
block.chainid,
address(registryProxy),
anchorDigest,
entityIdHash,
merkleRoot,
policyHash,
sequence,
validUntil,
receiptType
```

State-transition authorization is `abi.encode` of:

```text
keccak256("GSX-LTP:state-transition-authorization:v1"),
block.chainid,
address(registryProxy),
entityIdHash,
expectedState,
newState,
sequence,
validUntil
```

Use the registry's `anchorAuthorizationMessage` and
`stateTransitionAuthorizationMessage` view functions as the wire-format oracle. These are new
registry-authorization signatures; an existing LTP `ApprovalReceipt.signature` is not reusable
unless it signs these exact bytes.

`expectedState` prevents a signature prepared in one state from being executed after another
authorized signer has moved the same entity elsewhere.

### Sequence jumps are cancellation

The existing registry accepts any `sequence > signerSequences[signer]`. v6 preserves that
behavior. In a permissionless relay setting, a successfully submitted higher sequence cancels all
lower outstanding authorizations for that signer, including authorizations for other entities.
Operators that need independent ordered lanes should use separate signing keys. Do not assume
strict `current + 1` ordering.

## EIP-8355 adapter contract

`EIP8355MLDSA65Verifier` enforces the current FIPS 204 ML-DSA-65 sizes and calls a configured
precompile with exactly:

```text
publicKey (1952 bytes) || signature (3309 bytes) || message (remaining bytes)
```

It accepts only a successful static call returning exactly 32 bytes whose integer value is one.
A revert, malformed return, zero word, wrong key/signature length, or an unassigned address all
return false. This is important because a call to an unassigned EVM address succeeds with empty
returndata.

## ERC-7786 mapping

The present Python bridge objects predate ERC-7786 and use human-readable chain/address strings.
Do not label them ERC-7786-compliant yet. The adapter boundary should map them as follows:

| LTP bridge value | ERC-7786 value |
| --- | --- |
| canonical `BridgeMessage` bytes | opaque `payload` |
| source sender | ERC-7930/CAIP-350 interoperable `sender` |
| destination recipient | ERC-7930/CAIP-350 interoperable `recipient` |
| LTP finality / PQ requirements | gateway attributes, once their selectors are standardized |
| `entity_id` + source event identity | basis for unique `receiveId` |
| `L2Materializer` finality + replay checks | preconditions before destination delivery |

The destination gateway must still guarantee ERC-7786 safety/liveness properties and call a
recipient's dedicated `receiveMessage` function exactly once. ML-DSA proves authorization; it
does not by itself prove source-chain finality or bridge liveness.

## Suwappu Chain activation checklist

1. Run the v5 -> v6 proxy storage test and all contract tests.
2. Build the Suwappu custom OP-Reth profile and verify the native CI gate is green.
3. Deploy `EIP8355MLDSA65Verifier` with
   `0x0000000000000000000000000000000000008355` for the current Suwappu devnet profile.
4. Set that adapter on the registry through governance.
5. Register the raw FIPS 204 public key with `registerEIP8355Signer`.
6. Configure `LiveBridge` with the same operator key; it now fetches
   `anchorAuthorizationMessage`, signs those exact bytes with the real ML-DSA-65 backend, and
   submits `anchorSigned`.
7. Pass positive, tampered-signature, malformed-input and absent-precompile tests against the
   running chain before enabling permissionless relaying.
8. Keep PoC fallback crypto out of benchmarks and conformance claims; the signed Python client
   refuses to use the PoC ML-DSA backend.

## Upstream coordination

EIP-8355 work is currently in [ethereum/EIPs#12048](https://github.com/ethereum/EIPs/pull/12048).
The implementation should remain address-configurable while EIP-8355, EIP-8051 and EIP-7932
coordinate precompile/address and signature-registry assignments.

References:

- https://eips.ethereum.org/EIPS/eip-7786
- https://eips.ethereum.org/EIPS/eip-7930
- https://eips.ethereum.org/EIPS/eip-7932
- https://eips.ethereum.org/EIPS/eip-8051
- https://github.com/ethereum/EIPs/pull/12048
- https://csrc.nist.gov/pubs/fips/204/final
- https://csrc.nist.gov/pubs/fips/203/final

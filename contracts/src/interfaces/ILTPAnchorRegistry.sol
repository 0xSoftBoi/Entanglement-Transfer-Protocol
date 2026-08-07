// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ILTPAnchorRegistry
/// @author Javier Calderon Jr, CTO of Global Settlement (GSX)
/// @notice Interface for the LTP on-chain anchor registry.
/// @dev Stores anchor digests, enforces state machine transitions,
///      tracks per-signer sequences, and manages signer authorization.
interface ILTPAnchorRegistry {
    // -----------------------------------------------------------------------
    // Structs
    // -----------------------------------------------------------------------

    struct AnchorRecord {
        bytes32 merkleRoot;
        bytes32 policyHash;
        bytes32 signerVkHash;
        bytes32 entityIdHash;
        uint64  sequence;
        uint64  validUntil;
        uint64  targetChainId;
        uint8   receiptType;
        uint8   entityState;
        uint64  anchoredAt;
    }

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event Anchored(
        bytes32 indexed anchorDigest,
        bytes32 indexed entityIdHash,
        bytes32 indexed signerVkHash,
        uint64 sequence
    );

    event BatchAnchored(
        uint256 count,
        bytes32 indexed firstDigest
    );

    event SignerRegistered(bytes32 indexed vkHash);
    event SignerRevoked(bytes32 indexed vkHash);

    event StateTransition(
        bytes32 indexed entityIdHash,
        uint8 fromState,
        uint8 toState
    );

    event StateTransitioned(
        bytes32 indexed entityIdHash,
        bytes32 indexed signerVkHash,
        uint8 fromState,
        uint8 toState,
        uint64 sequence
    );

    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);
    event Paused(address indexed by);
    event Unpaused(address indexed by);

    event MLDSA65VerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );

    /// @notice Emitted only after verifier-backed ML-DSA-65 authorization succeeds.
    event PQAuthorizationVerified(
        bytes32 indexed signerVkHash,
        bytes32 indexed entityIdHash,
        bytes32 messageHash
    );

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error AlreadyAnchored(bytes32 anchorDigest);
    error SequenceTooLow(bytes32 signerVkHash, uint64 provided, uint64 current);
    error Expired(uint64 validUntil, uint64 blockTimestamp);
    error UnauthorizedSigner(bytes32 signerVkHash);
    error InvalidStateTransition(uint8 fromState, uint8 toState);
    error NotAdmin(address caller);
    error EmptyBatch();
    error BatchTooLarge(uint256 provided, uint256 max);
    error ArrayLengthMismatch();
    error ContractPaused();
    error VerifierNotConfigured();
    error InvalidMLDSA65Signature();
    error UnexpectedEntityState(uint8 expected, uint8 actual);

    // -----------------------------------------------------------------------
    // Write functions
    // -----------------------------------------------------------------------

    /// @notice Anchor a single trust artifact on-chain.
    function anchor(
        bytes32 anchorDigest,
        bytes32 entityIdHash,
        bytes32 merkleRoot,
        bytes32 policyHash,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntil,
        uint8   receiptType
    ) external;

    /// @notice Anchor multiple trust artifacts in a single transaction.
    function batchAnchor(
        bytes32[] calldata anchorDigests,
        bytes32[] calldata entityIdHashes,
        bytes32[] calldata merkleRoots,
        bytes32[] calldata policyHashes,
        bytes32[] calldata signerVkHashes,
        uint64[]  calldata sequences,
        uint64[]  calldata validUntils,
        uint8[]   calldata receiptTypes
    ) external;

    /// @notice Transition an entity's state without a new anchor record.
    function transitionState(
        bytes32 entityIdHash,
        uint8   newState,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntil
    ) external;

    /// @notice Configure the verifier adapter used by permissionless signed writes. Admin only.
    /// @dev Setting address(0) intentionally disables signed writes.
    function setMLDSA65Verifier(address newVerifier) external;

    /// @notice Register an authorized signer by VK hash. Admin only.
    function registerSigner(bytes32 vkHash) external;

    /// @notice Revoke an authorized signer. Admin only.
    function revokeSigner(bytes32 vkHash) external;

    /// @notice Register a FIPS 204 public key for the signed EVM path. Admin only.
    /// @dev Signed writes derive their EVM signer ID as keccak256(publicKey), which is
    ///      deliberately distinct from LTP's SHA3-256 off-chain fingerprint.
    function registerEIP8355Signer(bytes calldata signerVk) external returns (bytes32 signerId);

    /// @notice Revoke a FIPS 204 public key from the signed EVM path. Admin only.
    function revokeEIP8355Signer(bytes calldata signerVk) external returns (bytes32 signerId);

    /// @notice Permissionless relay of an anchor carrying ML-DSA-65 authorization.
    function anchorSigned(
        bytes32 anchorDigest,
        bytes32 entityIdHash,
        bytes32 merkleRoot,
        bytes32 policyHash,
        bytes calldata signerVk,
        uint64  sequence,
        uint64  validUntil,
        uint8   receiptType,
        bytes calldata signature
    ) external;

    /// @notice Permissionless state transition carrying ML-DSA-65 authorization.
    /// @dev expectedState is signed and checked to reject stale cross-signer authorizations.
    function transitionStateSigned(
        bytes32 entityIdHash,
        uint8   expectedState,
        uint8   newState,
        bytes calldata signerVk,
        uint64  sequence,
        uint64  validUntil,
        bytes calldata signature
    ) external;

    // -----------------------------------------------------------------------
    // View functions
    // -----------------------------------------------------------------------

    /// @notice Derive the EVM signer ID used by verifier-backed writes.
    function eip8355SignerId(bytes calldata signerVk) external pure returns (bytes32);

    /// @notice Exact raw ML-DSA message for anchorSigned.
    function anchorAuthorizationMessage(
        bytes32 anchorDigest,
        bytes32 entityIdHash,
        bytes32 merkleRoot,
        bytes32 policyHash,
        uint64 sequence,
        uint64 validUntil,
        uint8 receiptType
    ) external view returns (bytes memory);

    /// @notice Exact raw ML-DSA message for transitionStateSigned.
    function stateTransitionAuthorizationMessage(
        bytes32 entityIdHash,
        uint8 expectedState,
        uint8 newState,
        uint64 sequence,
        uint64 validUntil
    ) external view returns (bytes memory);

    /// @notice Check if an anchor digest has been recorded.
    function isAnchored(bytes32 anchorDigest) external view returns (bool);

    /// @notice Get the entity state for an entity ID hash.
    function getEntityState(bytes32 entityIdHash) external view returns (uint8);

    /// @notice Get the current sequence for a signer VK hash.
    function getSignerSequence(bytes32 vkHash) external view returns (uint64);

    /// @notice Get the full anchor record for a digest.
    function getAnchorRecord(bytes32 anchorDigest) external view returns (AnchorRecord memory);

    /// @notice Batch check if anchor digests have been recorded.
    function areAnchored(bytes32[] calldata anchorDigests) external view returns (bool[] memory);

    /// @notice Batch get entity states.
    function getEntityStates(
        bytes32[] calldata entityIdHashes
    ) external view returns (uint8[] memory);

    /// @notice Batch get anchor records.
    function getAnchorRecords(
        bytes32[] calldata anchorDigests
    ) external view returns (AnchorRecord[] memory);
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ILTPAnchorRegistry} from "./interfaces/ILTPAnchorRegistry.sol";
import {ILTPMLDSA65Verifier} from "./interfaces/ILTPMLDSA65Verifier.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/// @title LTPAnchorRegistry
/// @author Javier Calderon Jr, CTO of Global Settlement (GSX)
/// @notice On-chain registry for LTP anchor digests with state machine,
///         per-signer sequencing, signer authorization, and emergency pause.
/// @dev Upgradeable via UUPS proxy pattern. Admin is expected to be a multi-sig.
///      Legacy writes are admin-only; permissionless writes require ML-DSA-65 verification.
contract LTPAnchorRegistry is ILTPAnchorRegistry, Initializable, UUPSUpgradeable {
    // -----------------------------------------------------------------------
    // Constants — EntityState enum mirrors Python src/ltp/anchor/state.py
    // -----------------------------------------------------------------------

    uint8 public constant STATE_UNKNOWN       = 0;
    uint8 public constant STATE_COMMITTED     = 1;
    uint8 public constant STATE_ANCHORED      = 2;
    uint8 public constant STATE_MATERIALIZED  = 3;
    uint8 public constant STATE_DISPUTED      = 4;
    uint8 public constant STATE_DELETED       = 5;

    /// @notice Maximum items per batchAnchor call (gas DoS protection).
    uint256 public constant MAX_BATCH_SIZE = 100;

    /// @notice Domain for ML-DSA authorization of anchorSigned operations.
    bytes32 public constant ANCHOR_AUTHORIZATION_DOMAIN =
        keccak256("GSX-LTP:anchor-authorization:v1");

    /// @notice Domain for ML-DSA authorization of transitionStateSigned operations.
    bytes32 public constant STATE_TRANSITION_AUTHORIZATION_DOMAIN =
        keccak256("GSX-LTP:state-transition-authorization:v1");

    // -----------------------------------------------------------------------
    // Storage (must be append-only for upgrade safety)
    // -----------------------------------------------------------------------

    address public admin;
    bool public paused;

    /// @notice anchorDigest => AnchorRecord
    mapping(bytes32 => AnchorRecord) private _anchors;

    /// @notice signerVkHash => highest accepted sequence number
    mapping(bytes32 => uint64) public signerSequences;

    /// @notice entityIdHash => EntityState (uint8)
    mapping(bytes32 => uint8) public entityStates;

    /// @notice signerVkHash => authorized flag
    mapping(bytes32 => bool) public authorizedSigners;

    /// @notice Verifier adapter for the permissionless FIPS 204 ML-DSA-65 path.
    /// @dev Appended in v6 by consuming one slot from the v5 storage gap.
    address public mlDsa65Verifier;

    // -----------------------------------------------------------------------
    // Constructor — disables initializers on the implementation contract
    // -----------------------------------------------------------------------

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // -----------------------------------------------------------------------
    // Initializer (replaces constructor for proxy deployments)
    // -----------------------------------------------------------------------

    function initialize(address _admin) external initializer {
        if (_admin == address(0)) revert NotAdmin(address(0));
        admin = _admin;
        paused = false;
    }

    // -----------------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------------

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin(msg.sender);
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    // -----------------------------------------------------------------------
    // Admin functions
    // -----------------------------------------------------------------------

    /// @notice Transfer admin role. Admin only.
    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert NotAdmin(address(0));
        address oldAdmin = admin;
        admin = newAdmin;
        emit AdminTransferred(oldAdmin, newAdmin);
    }

    /// @notice Pause all anchoring operations. Admin only.
    function pause() external onlyAdmin {
        paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Unpause anchoring operations. Admin only.
    function unpause() external onlyAdmin {
        paused = false;
        emit Unpaused(msg.sender);
    }

    /// @inheritdoc ILTPAnchorRegistry
    function setMLDSA65Verifier(address newVerifier) external onlyAdmin {
        address oldVerifier = mlDsa65Verifier;
        mlDsa65Verifier = newVerifier;
        emit MLDSA65VerifierUpdated(oldVerifier, newVerifier);
    }

    // -----------------------------------------------------------------------
    // UUPS upgrade authorization
    // -----------------------------------------------------------------------

    /// @dev Only admin can authorize upgrades.
    function _authorizeUpgrade(address newImplementation) internal override onlyAdmin {}

    // -----------------------------------------------------------------------
    // Write functions
    // -----------------------------------------------------------------------

    /// @inheritdoc ILTPAnchorRegistry
    function anchor(
        bytes32 anchorDigest,
        bytes32 entityIdHash,
        bytes32 merkleRoot,
        bytes32 policyHash,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntil,
        uint8   receiptType
    ) external onlyAdmin whenNotPaused {
        _anchor(
            anchorDigest,
            entityIdHash,
            merkleRoot,
            policyHash,
            signerVkHash,
            sequence,
            validUntil,
            receiptType
        );
    }

    /// @inheritdoc ILTPAnchorRegistry
    function anchorSigned(
        bytes32 anchorDigest,
        bytes32 entityIdHash,
        bytes32 merkleRoot,
        bytes32 policyHash,
        bytes calldata signerVk,
        uint64 sequence,
        uint64 validUntil,
        uint8 receiptType,
        bytes calldata signature
    ) external whenNotPaused {
        bytes32 signerVkHash = keccak256(signerVk);
        bytes memory message = anchorAuthorizationMessage(
            anchorDigest,
            entityIdHash,
            merkleRoot,
            policyHash,
            sequence,
            validUntil,
            receiptType
        );
        _requireAuthorizedSignature(signerVkHash, signerVk, signature, message);
        emit PQAuthorizationVerified(signerVkHash, entityIdHash, keccak256(message));

        _anchor(
            anchorDigest,
            entityIdHash,
            merkleRoot,
            policyHash,
            signerVkHash,
            sequence,
            validUntil,
            receiptType
        );
    }

    /// @inheritdoc ILTPAnchorRegistry
    function batchAnchor(
        bytes32[] calldata anchorDigests,
        bytes32[] calldata entityIdHashes,
        bytes32[] calldata merkleRoots,
        bytes32[] calldata policyHashes,
        bytes32[] calldata signerVkHashes,
        uint64[]  calldata sequences,
        uint64[]  calldata validUntils,
        uint8[]   calldata receiptTypes
    ) external onlyAdmin whenNotPaused {
        uint256 len = anchorDigests.length;
        if (len == 0) revert EmptyBatch();
        if (len > MAX_BATCH_SIZE) revert BatchTooLarge(len, MAX_BATCH_SIZE);
        if (
            entityIdHashes.length != len ||
            merkleRoots.length != len ||
            policyHashes.length != len ||
            signerVkHashes.length != len ||
            sequences.length != len ||
            validUntils.length != len ||
            receiptTypes.length != len
        ) revert ArrayLengthMismatch();
        for (uint256 i = 0; i < len; ++i) {
            _anchor(
                anchorDigests[i],
                entityIdHashes[i],
                merkleRoots[i],
                policyHashes[i],
                signerVkHashes[i],
                sequences[i],
                validUntils[i],
                receiptTypes[i]
            );
        }

        emit BatchAnchored(len, anchorDigests[0]);
    }

    /// @inheritdoc ILTPAnchorRegistry
    function transitionState(
        bytes32 entityIdHash,
        uint8   newState,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntil
    ) external onlyAdmin whenNotPaused {
        _transitionState(entityIdHash, newState, signerVkHash, sequence, validUntil);
    }

    /// @inheritdoc ILTPAnchorRegistry
    function transitionStateSigned(
        bytes32 entityIdHash,
        uint8 expectedState,
        uint8 newState,
        bytes calldata signerVk,
        uint64 sequence,
        uint64 validUntil,
        bytes calldata signature
    ) external whenNotPaused {
        uint8 actualState = entityStates[entityIdHash];
        if (actualState != expectedState) {
            revert UnexpectedEntityState(expectedState, actualState);
        }

        bytes32 signerVkHash = keccak256(signerVk);
        bytes memory message = stateTransitionAuthorizationMessage(
            entityIdHash,
            expectedState,
            newState,
            sequence,
            validUntil
        );
        _requireAuthorizedSignature(signerVkHash, signerVk, signature, message);
        emit PQAuthorizationVerified(signerVkHash, entityIdHash, keccak256(message));

        _transitionState(entityIdHash, newState, signerVkHash, sequence, validUntil);
    }

    /// @inheritdoc ILTPAnchorRegistry
    function registerSigner(bytes32 vkHash) external onlyAdmin {
        authorizedSigners[vkHash] = true;
        emit SignerRegistered(vkHash);
    }

    /// @inheritdoc ILTPAnchorRegistry
    function revokeSigner(bytes32 vkHash) external onlyAdmin {
        authorizedSigners[vkHash] = false;
        emit SignerRevoked(vkHash);
    }

    /// @inheritdoc ILTPAnchorRegistry
    function registerEIP8355Signer(
        bytes calldata signerVk
    ) external onlyAdmin returns (bytes32 signerId) {
        signerId = keccak256(signerVk);
        authorizedSigners[signerId] = true;
        emit SignerRegistered(signerId);
    }

    /// @inheritdoc ILTPAnchorRegistry
    function revokeEIP8355Signer(
        bytes calldata signerVk
    ) external onlyAdmin returns (bytes32 signerId) {
        signerId = keccak256(signerVk);
        authorizedSigners[signerId] = false;
        emit SignerRevoked(signerId);
    }

    // -----------------------------------------------------------------------
    // View functions
    // -----------------------------------------------------------------------

    /// @inheritdoc ILTPAnchorRegistry
    function eip8355SignerId(bytes calldata signerVk) external pure returns (bytes32) {
        return keccak256(signerVk);
    }

    /// @inheritdoc ILTPAnchorRegistry
    function anchorAuthorizationMessage(
        bytes32 anchorDigest,
        bytes32 entityIdHash,
        bytes32 merkleRoot,
        bytes32 policyHash,
        uint64 sequence,
        uint64 validUntil,
        uint8 receiptType
    ) public view returns (bytes memory) {
        return abi.encode(
            ANCHOR_AUTHORIZATION_DOMAIN,
            block.chainid,
            address(this),
            anchorDigest,
            entityIdHash,
            merkleRoot,
            policyHash,
            sequence,
            validUntil,
            receiptType
        );
    }

    /// @inheritdoc ILTPAnchorRegistry
    function stateTransitionAuthorizationMessage(
        bytes32 entityIdHash,
        uint8 expectedState,
        uint8 newState,
        uint64 sequence,
        uint64 validUntil
    ) public view returns (bytes memory) {
        return abi.encode(
            STATE_TRANSITION_AUTHORIZATION_DOMAIN,
            block.chainid,
            address(this),
            entityIdHash,
            expectedState,
            newState,
            sequence,
            validUntil
        );
    }

    /// @inheritdoc ILTPAnchorRegistry
    function isAnchored(bytes32 anchorDigest) external view returns (bool) {
        return _anchors[anchorDigest].anchoredAt != 0;
    }

    /// @inheritdoc ILTPAnchorRegistry
    function getEntityState(bytes32 entityIdHash) external view returns (uint8) {
        return entityStates[entityIdHash];
    }

    /// @inheritdoc ILTPAnchorRegistry
    function getSignerSequence(bytes32 vkHash) external view returns (uint64) {
        return signerSequences[vkHash];
    }

    /// @inheritdoc ILTPAnchorRegistry
    function getAnchorRecord(bytes32 anchorDigest) external view returns (AnchorRecord memory) {
        return _anchors[anchorDigest];
    }

    /// @inheritdoc ILTPAnchorRegistry
    function areAnchored(bytes32[] calldata anchorDigests) external view returns (bool[] memory) {
        bool[] memory results = new bool[](anchorDigests.length);
        for (uint256 i = 0; i < anchorDigests.length; ++i) {
            results[i] = _anchors[anchorDigests[i]].anchoredAt != 0;
        }
        return results;
    }

    /// @inheritdoc ILTPAnchorRegistry
    function getEntityStates(
        bytes32[] calldata entityIdHashes
    ) external view returns (uint8[] memory) {
        uint8[] memory results = new uint8[](entityIdHashes.length);
        for (uint256 i = 0; i < entityIdHashes.length; ++i) {
            results[i] = entityStates[entityIdHashes[i]];
        }
        return results;
    }

    /// @inheritdoc ILTPAnchorRegistry
    function getAnchorRecords(
        bytes32[] calldata anchorDigests
    ) external view returns (AnchorRecord[] memory) {
        AnchorRecord[] memory results = new AnchorRecord[](anchorDigests.length);
        for (uint256 i = 0; i < anchorDigests.length; ++i) {
            results[i] = _anchors[anchorDigests[i]];
        }
        return results;
    }

    /// @notice Returns the implementation version for upgrade tracking.
    function version() external pure returns (uint256) {
        return 6;
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// @dev Verify authorization through the configured ML-DSA-65 adapter.
    function _requireAuthorizedSignature(
        bytes32 signerVkHash,
        bytes calldata signerVk,
        bytes calldata signature,
        bytes memory message
    ) internal view {
        if (!authorizedSigners[signerVkHash]) {
            revert UnauthorizedSigner(signerVkHash);
        }

        address verifier = mlDsa65Verifier;
        if (verifier == address(0)) {
            revert VerifierNotConfigured();
        }

        if (!ILTPMLDSA65Verifier(verifier).verify(signerVk, signature, message)) {
            revert InvalidMLDSA65Signature();
        }
    }

    /// @dev Core state-transition logic shared by admin and signed entry points.
    function _transitionState(
        bytes32 entityIdHash,
        uint8 newState,
        bytes32 signerVkHash,
        uint64 sequence,
        uint64 validUntil
    ) internal {
        if (!authorizedSigners[signerVkHash]) {
            revert UnauthorizedSigner(signerVkHash);
        }

        uint64 currentSeq = signerSequences[signerVkHash];
        if (sequence <= currentSeq) {
            revert SequenceTooLow(signerVkHash, sequence, currentSeq);
        }

        if (uint64(block.timestamp) >= validUntil) {
            revert Expired(validUntil, uint64(block.timestamp));
        }

        uint8 currentState = entityStates[entityIdHash];
        if (!_isValidTransition(currentState, newState)) {
            revert InvalidStateTransition(currentState, newState);
        }

        entityStates[entityIdHash] = newState;
        signerSequences[signerVkHash] = sequence;

        emit StateTransitioned(entityIdHash, signerVkHash, currentState, newState, sequence);
        emit StateTransition(entityIdHash, currentState, newState);
    }

    /// @dev Core anchoring logic shared by anchor() and batchAnchor().
    function _anchor(
        bytes32 anchorDigest,
        bytes32 entityIdHash,
        bytes32 merkleRoot,
        bytes32 policyHash,
        bytes32 signerVkHash,
        uint64  sequence,
        uint64  validUntil,
        uint8   receiptType
    ) internal {
        // 1. Replay rejection
        if (_anchors[anchorDigest].anchoredAt != 0) {
            revert AlreadyAnchored(anchorDigest);
        }

        // 2. Signer authorization (mirrors governance.py:143-173)
        if (!authorizedSigners[signerVkHash]) {
            revert UnauthorizedSigner(signerVkHash);
        }

        // 3. Sequence monotonicity (mirrors sequencing.py:68-74)
        uint64 currentSeq = signerSequences[signerVkHash];
        if (sequence <= currentSeq) {
            revert SequenceTooLow(signerVkHash, sequence, currentSeq);
        }

        // 4. Temporal expiry (mirrors sequencing.py:65-66)
        if (uint64(block.timestamp) >= validUntil) {
            revert Expired(validUntil, uint64(block.timestamp));
        }

        // 5. State transition: entity state → ANCHORED
        uint8 currentState = entityStates[entityIdHash];
        uint8 newState = STATE_ANCHORED;
        if (!_isValidTransition(currentState, newState)) {
            revert InvalidStateTransition(currentState, newState);
        }

        // 6. Store the anchor record
        _anchors[anchorDigest] = AnchorRecord({
            merkleRoot:    merkleRoot,
            policyHash:    policyHash,
            signerVkHash:  signerVkHash,
            entityIdHash:  entityIdHash,
            sequence:      sequence,
            validUntil:    validUntil,
            targetChainId: uint64(block.chainid),
            receiptType:   receiptType,
            entityState:   newState,
            anchoredAt:    uint64(block.timestamp)
        });

        // 7. Update signer sequence HWM
        signerSequences[signerVkHash] = sequence;

        // 8. Update entity state
        entityStates[entityIdHash] = newState;

        emit Anchored(anchorDigest, entityIdHash, signerVkHash, sequence);
        emit StateTransition(entityIdHash, currentState, newState);
    }

    /// @dev Validate entity state transitions. Mirrors Python state.py:37-51.
    function _isValidTransition(uint8 from_, uint8 to_) internal pure returns (bool) {
        if (from_ == STATE_UNKNOWN   && to_ == STATE_COMMITTED)    return true;
        if (from_ == STATE_COMMITTED && to_ == STATE_ANCHORED)     return true;
        if (from_ == STATE_ANCHORED  && to_ == STATE_MATERIALIZED) return true;
        if (from_ == STATE_COMMITTED    && to_ == STATE_DISPUTED) return true;
        if (from_ == STATE_ANCHORED     && to_ == STATE_DISPUTED) return true;
        if (from_ == STATE_MATERIALIZED && to_ == STATE_DISPUTED) return true;
        if (from_ == STATE_COMMITTED    && to_ == STATE_DELETED) return true;
        if (from_ == STATE_ANCHORED     && to_ == STATE_DELETED) return true;
        if (from_ == STATE_MATERIALIZED && to_ == STATE_DELETED) return true;
        if (from_ == STATE_DISPUTED     && to_ == STATE_DELETED) return true;
        if (from_ == STATE_UNKNOWN && to_ == STATE_ANCHORED) return true;
        return false;
    }

    // -----------------------------------------------------------------------
    // Storage gap — reserves slots for future upgrades without colliding
    // with derived contract storage. Standard OpenZeppelin pattern.
    // -----------------------------------------------------------------------

    uint256[49] private __gap;
}

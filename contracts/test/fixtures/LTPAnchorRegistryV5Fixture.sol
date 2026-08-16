// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/// @notice Frozen storage-compatible v5 fixture used only to prove v5 -> v6 upgrades.
/// @dev State variable order and types match LTPAnchorRegistry v5 exactly.
contract LTPAnchorRegistryV5Fixture is Initializable, UUPSUpgradeable {
    struct AnchorRecord {
        bytes32 merkleRoot;
        bytes32 policyHash;
        bytes32 signerVkHash;
        bytes32 entityIdHash;
        uint64 sequence;
        uint64 validUntil;
        uint64 targetChainId;
        uint8 receiptType;
        uint8 entityState;
        uint64 anchoredAt;
    }

    address public admin;
    bool public paused;

    mapping(bytes32 => AnchorRecord) private _anchors;
    mapping(bytes32 => uint64) public signerSequences;
    mapping(bytes32 => uint8) public entityStates;
    mapping(bytes32 => bool) public authorizedSigners;

    constructor() {
        _disableInitializers();
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    function initialize(address admin_) external initializer {
        admin = admin_;
    }

    function seed(
        bytes32 anchorDigest,
        bytes32 signerVkHash,
        bytes32 entityIdHash
    ) external onlyAdmin {
        authorizedSigners[signerVkHash] = true;
        signerSequences[signerVkHash] = 77;
        entityStates[entityIdHash] = 3;
        _anchors[anchorDigest] = AnchorRecord({
            merkleRoot: keccak256("v5-merkle-root"),
            policyHash: keccak256("v5-policy-hash"),
            signerVkHash: signerVkHash,
            entityIdHash: entityIdHash,
            sequence: 77,
            validUntil: 123456,
            targetChainId: 31337,
            receiptType: 4,
            entityState: 3,
            anchoredAt: 999
        });
    }

    function setPaused(bool value) external onlyAdmin {
        paused = value;
    }

    function getAnchorRecord(bytes32 anchorDigest) external view returns (AnchorRecord memory) {
        return _anchors[anchorDigest];
    }

    function _authorizeUpgrade(address) internal override onlyAdmin {}

    uint256[50] private __gap;
}

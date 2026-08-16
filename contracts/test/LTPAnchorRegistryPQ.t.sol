// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TestSetup} from "./helpers/TestSetup.sol";
import {ILTPAnchorRegistry} from "../src/interfaces/ILTPAnchorRegistry.sol";
import {ILTPMLDSA65Verifier} from "../src/interfaces/ILTPMLDSA65Verifier.sol";

contract MockMLDSA65Verifier is ILTPMLDSA65Verifier {
    bytes32 private _publicKeyHash;
    bytes32 private _signatureHash;
    bytes32 private _messageHash;

    function allow(
        bytes calldata publicKey,
        bytes calldata signature,
        bytes calldata message
    ) external {
        _publicKeyHash = keccak256(publicKey);
        _signatureHash = keccak256(signature);
        _messageHash = keccak256(message);
    }

    function verify(
        bytes calldata publicKey,
        bytes calldata signature,
        bytes calldata message
    ) external view returns (bool) {
        return (
            keccak256(publicKey) == _publicKeyHash &&
            keccak256(signature) == _signatureHash &&
            keccak256(message) == _messageHash
        );
    }
}

contract LTPAnchorRegistryPQTest is TestSetup {
    MockMLDSA65Verifier internal verifier;
    bytes internal publicKey;
    bytes internal signature;
    bytes32 internal pqSignerId;

    function setUp() public override {
        super.setUp();

        verifier = new MockMLDSA65Verifier();
        registry.setMLDSA65Verifier(address(verifier));

        publicKey = new bytes(1952);
        publicKey[0] = 0x01;
        publicKey[1951] = 0x65;

        signature = new bytes(3309);
        signature[0] = 0x02;
        signature[3308] = 0x65;

        pqSignerId = keccak256(publicKey);
        registry.registerEIP8355Signer(publicKey);
    }

    function _allowAnchor(
        bytes32 digest,
        bytes32 entityId,
        uint64 sequence,
        uint64 validUntil
    ) internal {
        bytes memory message = registry.anchorAuthorizationMessage(
            digest,
            entityId,
            _merkleRoot(1),
            _policyHash(1),
            sequence,
            validUntil,
            0
        );
        verifier.allow(publicKey, signature, message);
    }

    function _signedAnchor(
        bytes32 digest,
        bytes32 entityId,
        uint64 sequence,
        uint64 validUntil
    ) internal {
        _allowAnchor(digest, entityId, sequence, validUntil);
        registry.anchorSigned(
            digest,
            entityId,
            _merkleRoot(1),
            _policyHash(1),
            publicKey,
            sequence,
            validUntil,
            0,
            signature
        );
    }

    function test_legacyAnchor_nonAdminReverts() public {
        vm.prank(nonAdmin);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, nonAdmin));
        registry.anchor(
            _digest(1),
            _entityId(1),
            _merkleRoot(1),
            _policyHash(1),
            pqSignerId,
            1,
            uint64(block.timestamp + 3600),
            0
        );
    }

    function test_legacyBatchAnchor_nonAdminReverts() public {
        bytes32[] memory empty32 = new bytes32[](0);
        uint64[] memory empty64 = new uint64[](0);
        uint8[] memory empty8 = new uint8[](0);

        vm.prank(nonAdmin);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, nonAdmin));
        registry.batchAnchor(
            empty32,
            empty32,
            empty32,
            empty32,
            empty32,
            empty64,
            empty64,
            empty8
        );
    }

    function test_legacyTransition_nonAdminReverts() public {
        uint8 committed = registry.STATE_COMMITTED();

        vm.prank(nonAdmin);
        vm.expectRevert(abi.encodeWithSelector(ILTPAnchorRegistry.NotAdmin.selector, nonAdmin));
        registry.transitionState(
            _entityId(1),
            committed,
            pqSignerId,
            1,
            uint64(block.timestamp + 3600)
        );
    }

    function test_anchorSigned_permissionlessRelayerSucceeds() public {
        bytes32 digest = _digest(10);
        bytes32 entityId = _entityId(10);
        uint64 validUntil = uint64(block.timestamp + 3600);
        _allowAnchor(digest, entityId, 1, validUntil);

        vm.prank(nonAdmin);
        registry.anchorSigned(
            digest,
            entityId,
            _merkleRoot(1),
            _policyHash(1),
            publicKey,
            1,
            validUntil,
            0,
            signature
        );

        ILTPAnchorRegistry.AnchorRecord memory record = registry.getAnchorRecord(digest);
        assertEq(record.signerVkHash, pqSignerId);
        assertTrue(registry.isAnchored(digest));
    }

    function test_anchorSigned_invalidSignatureReverts() public {
        bytes32 digest = _digest(11);
        bytes32 entityId = _entityId(11);
        uint64 validUntil = uint64(block.timestamp + 3600);
        _allowAnchor(digest, entityId, 1, validUntil);

        bytes memory badSignature = signature;
        badSignature[0] ^= 0x01;

        vm.prank(nonAdmin);
        vm.expectRevert(ILTPAnchorRegistry.InvalidMLDSA65Signature.selector);
        registry.anchorSigned(
            digest,
            entityId,
            _merkleRoot(1),
            _policyHash(1),
            publicKey,
            1,
            validUntil,
            0,
            badSignature
        );
    }

    function test_anchorSigned_verifierDisabledFailsClosed() public {
        bytes32 digest = _digest(12);
        bytes32 entityId = _entityId(12);
        uint64 validUntil = uint64(block.timestamp + 3600);
        registry.setMLDSA65Verifier(address(0));

        vm.prank(nonAdmin);
        vm.expectRevert(ILTPAnchorRegistry.VerifierNotConfigured.selector);
        registry.anchorSigned(
            digest,
            entityId,
            _merkleRoot(1),
            _policyHash(1),
            publicKey,
            1,
            validUntil,
            0,
            signature
        );
    }

    function test_anchorSigned_unregisteredDerivedKeyReverts() public {
        bytes memory otherKey = new bytes(1952);
        otherKey[0] = 0x99;
        bytes32 otherSignerId = keccak256(otherKey);
        bytes32 digest = _digest(13);
        bytes32 entityId = _entityId(13);
        uint64 validUntil = uint64(block.timestamp + 3600);

        vm.prank(nonAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(ILTPAnchorRegistry.UnauthorizedSigner.selector, otherSignerId)
        );
        registry.anchorSigned(
            digest,
            entityId,
            _merkleRoot(1),
            _policyHash(1),
            otherKey,
            1,
            validUntil,
            0,
            signature
        );
    }

    function test_transitionStateSigned_expectedStatePreventsStaleAuthorization() public {
        bytes32 digest = _digest(20);
        bytes32 entityId = _entityId(20);
        uint64 validUntil = uint64(block.timestamp + 3600);
        _signedAnchor(digest, entityId, 1, validUntil);
        uint8 committed = registry.STATE_COMMITTED();
        uint8 anchored = registry.STATE_ANCHORED();
        uint8 materialized = registry.STATE_MATERIALIZED();

        vm.prank(nonAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ILTPAnchorRegistry.UnexpectedEntityState.selector,
                committed,
                anchored
            )
        );
        registry.transitionStateSigned(
            entityId,
            committed,
            materialized,
            publicKey,
            2,
            validUntil,
            signature
        );
    }

    function test_transitionStateSigned_permissionlessRelayerSucceeds() public {
        bytes32 digest = _digest(21);
        bytes32 entityId = _entityId(21);
        uint64 validUntil = uint64(block.timestamp + 3600);
        _signedAnchor(digest, entityId, 1, validUntil);
        uint8 anchored = registry.STATE_ANCHORED();
        uint8 materialized = registry.STATE_MATERIALIZED();

        bytes memory message = registry.stateTransitionAuthorizationMessage(
            entityId,
            anchored,
            materialized,
            2,
            validUntil
        );
        verifier.allow(publicKey, signature, message);

        vm.prank(nonAdmin);
        registry.transitionStateSigned(
            entityId,
            anchored,
            materialized,
            publicKey,
            2,
            validUntil,
            signature
        );

        assertEq(registry.getEntityState(entityId), materialized);
        assertEq(registry.getSignerSequence(pqSignerId), 2);
    }

    function test_eip8355SignerId_isKeccakPublicKey() public view {
        assertEq(registry.eip8355SignerId(publicKey), keccak256(publicKey));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {LTPAnchorRegistry} from "../src/LTPAnchorRegistry.sol";
import {ILTPAnchorRegistry} from "../src/interfaces/ILTPAnchorRegistry.sol";
import {LTPAnchorRegistryV5Fixture} from "./fixtures/LTPAnchorRegistryV5Fixture.sol";

contract LTPAnchorRegistryV6UpgradeTest is Test {
    function test_upgradeV5ToV6_preservesStorageAndConsumesOneGapSlot() public {
        bytes32 digest = keccak256("v5-anchor");
        bytes32 signer = keccak256("v5-signer");
        bytes32 entity = keccak256("v5-entity");

        LTPAnchorRegistryV5Fixture v5Implementation = new LTPAnchorRegistryV5Fixture();
        bytes memory initData = abi.encodeCall(
            LTPAnchorRegistryV5Fixture.initialize,
            (address(this))
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(v5Implementation), initData);
        LTPAnchorRegistryV5Fixture v5 = LTPAnchorRegistryV5Fixture(address(proxy));

        v5.seed(digest, signer, entity);
        v5.setPaused(true);

        LTPAnchorRegistry v6Implementation = new LTPAnchorRegistry();
        UUPSUpgradeable(address(v5)).upgradeToAndCall(address(v6Implementation), "");

        LTPAnchorRegistry v6 = LTPAnchorRegistry(address(proxy));
        assertEq(v6.version(), 6);
        assertEq(v6.admin(), address(this));
        assertTrue(v6.paused());
        assertTrue(v6.authorizedSigners(signer));
        assertEq(v6.signerSequences(signer), 77);
        assertEq(v6.entityStates(entity), 3);
        assertEq(v6.mlDsa65Verifier(), address(0));

        ILTPAnchorRegistry.AnchorRecord memory record = v6.getAnchorRecord(digest);
        assertEq(record.merkleRoot, keccak256("v5-merkle-root"));
        assertEq(record.policyHash, keccak256("v5-policy-hash"));
        assertEq(record.signerVkHash, signer);
        assertEq(record.entityIdHash, entity);
        assertEq(record.sequence, 77);
        assertEq(record.validUntil, 123456);
        assertEq(record.targetChainId, 31337);
        assertEq(record.receiptType, 4);
        assertEq(record.entityState, 3);
        assertEq(record.anchoredAt, 999);
    }
}

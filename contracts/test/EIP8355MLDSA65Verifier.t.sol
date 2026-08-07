// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {EIP8355MLDSA65Verifier} from "../src/EIP8355MLDSA65Verifier.sol";

contract RawEIP8355Mock {
    bytes32 public expectedInputHash;
    uint8 public mode;

    function configure(bytes calldata expectedInput, uint8 mode_) external {
        expectedInputHash = keccak256(expectedInput);
        mode = mode_;
    }

    fallback(bytes calldata input) external returns (bytes memory output) {
        if (mode == 3) {
            revert("mock revert");
        }
        if (mode == 2) {
            return new bytes(31);
        }
        if (mode == 4) {
            return new bytes(33);
        }
        if (mode == 1) {
            return abi.encode(uint256(2));
        }
        return abi.encode(keccak256(input) == expectedInputHash ? uint256(1) : uint256(0));
    }
}

contract EIP8355MLDSA65VerifierTest is Test {
    RawEIP8355Mock internal rawVerifier;
    EIP8355MLDSA65Verifier internal adapter;
    bytes internal publicKey;
    bytes internal signature;
    bytes internal message;

    function setUp() public {
        rawVerifier = new RawEIP8355Mock();
        adapter = new EIP8355MLDSA65Verifier(address(rawVerifier));

        publicKey = new bytes(1952);
        publicKey[0] = 0x11;
        publicKey[1951] = 0x22;
        signature = new bytes(3309);
        signature[0] = 0x33;
        signature[3308] = 0x44;
        message = bytes("GSX-SUWAPPU:EIP-8355:test");
    }

    function _configure(uint8 mode) internal {
        rawVerifier.configure(abi.encodePacked(publicKey, signature, message), mode);
    }

    function test_verify_exactConcatenationAndSuccessWord() public {
        _configure(0);
        assertTrue(adapter.verify(publicKey, signature, message));
    }

    function test_verify_changedMessageFails() public {
        _configure(0);
        assertFalse(adapter.verify(publicKey, signature, bytes("different")));
    }

    function test_verify_rejectsWrongPublicKeyLength() public {
        _configure(0);
        assertFalse(adapter.verify(new bytes(1951), signature, message));
    }

    function test_verify_rejectsWrongSignatureLength() public {
        _configure(0);
        assertFalse(adapter.verify(publicKey, new bytes(3308), message));
    }

    function test_verify_rejectsNonOneWord() public {
        _configure(1);
        assertFalse(adapter.verify(publicKey, signature, message));
    }

    function test_verify_rejects31ByteReturn() public {
        _configure(2);
        assertFalse(adapter.verify(publicKey, signature, message));
    }

    function test_verify_rejects33ByteReturn() public {
        _configure(4);
        assertFalse(adapter.verify(publicKey, signature, message));
    }

    function test_verify_rejectsRevert() public {
        _configure(3);
        assertFalse(adapter.verify(publicKey, signature, message));
    }

    function test_verify_unassignedAddressFailsClosed() public {
        EIP8355MLDSA65Verifier absentAdapter =
            new EIP8355MLDSA65Verifier(address(0xBEEF));
        assertFalse(absentAdapter.verify(publicKey, signature, message));
    }
}

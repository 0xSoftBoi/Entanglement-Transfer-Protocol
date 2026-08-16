// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ILTPMLDSA65Verifier} from "./interfaces/ILTPMLDSA65Verifier.sol";

/// @title EIP8355MLDSA65Verifier
/// @notice Adapter from LTP's verifier seam to the draft EIP-8355 ML-DSA-65 precompile.
/// @dev The precompile address is deliberately configurable at deployment time because
///      EIP-8355 is Draft and its current address block is not stable.
contract EIP8355MLDSA65Verifier is ILTPMLDSA65Verifier {
    uint256 public constant PUBLIC_KEY_LENGTH = 1952;
    uint256 public constant SIGNATURE_LENGTH = 3309;

    address public immutable precompile;

    constructor(address precompile_) {
        require(precompile_ != address(0), "EIP8355: zero precompile");
        precompile = precompile_;
    }

    /// @inheritdoc ILTPMLDSA65Verifier
    function verify(
        bytes calldata publicKey,
        bytes calldata signature,
        bytes calldata message
    ) external view returns (bool) {
        if (
            publicKey.length != PUBLIC_KEY_LENGTH ||
            signature.length != SIGNATURE_LENGTH
        ) {
            return false;
        }

        // Draft EIP-8355 input is exactly: publicKey || signature || message.
        bytes memory input = abi.encodePacked(publicKey, signature, message);
        (bool success, bytes memory output) = precompile.staticcall(input);

        // Calling an unassigned address succeeds with empty returndata. Requiring
        // exactly one word distinguishes "precompile absent" from a valid result.
        if (!success || output.length != 32) {
            return false;
        }

        uint256 result;
        assembly ("memory-safe") {
            result := mload(add(output, 0x20))
        }
        return result == 1;
    }
}

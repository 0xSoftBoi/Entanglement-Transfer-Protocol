// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ILTPMLDSA65Verifier} from "../../src/interfaces/ILTPMLDSA65Verifier.sol";

/// @notice Test-only verifier for Python/Solidity wiring tests.
/// @dev Native ML-DSA cryptography is exercised by the Suwappu OP-Reth conformance suite.
contract TestMLDSA65Verifier is ILTPMLDSA65Verifier {
    function verify(
        bytes calldata publicKey,
        bytes calldata signature,
        bytes calldata message
    ) external pure returns (bool) {
        return publicKey.length == 1952 && signature.length == 3309 && message.length > 0;
    }
}

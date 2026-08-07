// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ILTPMLDSA65Verifier
/// @notice Narrow verifier seam used by LTPAnchorRegistry for FIPS 204 ML-DSA-65.
/// @dev Implementations MUST fail closed and return false for malformed input.
interface ILTPMLDSA65Verifier {
    /// @notice Verify an ML-DSA-65 signature over an arbitrary message.
    /// @param publicKey Standard FIPS 204 ML-DSA-65 public key (1952 bytes).
    /// @param signature Standard FIPS 204 ML-DSA-65 signature (3309 bytes).
    /// @param message Raw application-domain message.
    function verify(
        bytes calldata publicKey,
        bytes calldata signature,
        bytes calldata message
    ) external view returns (bool);
}

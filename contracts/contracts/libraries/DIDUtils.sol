// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DIDUtils — utility functions for Decentralized Identifier (DID) handling.
library DIDUtils {
    // -----------------------------------------------------------------------
    // Hashing
    // -----------------------------------------------------------------------

    /// @notice Returns keccak256 of the DID string.
    /// @dev Callers should use this to produce the canonical `didHash` stored in registries.
    function hashDID(string memory did) internal pure returns (bytes32) {
        return keccak256(bytes(did));
    }

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------

    /// @notice Returns true if the string starts with "did:" (minimal DID format check).
    /// @dev Does NOT validate method-specific identifiers — callers must enforce further rules.
    function hasValidDIDPrefix(string memory did) internal pure returns (bool) {
        bytes memory b = bytes(did);
        if (b.length < 4) return false;
        return b[0] == "d" && b[1] == "i" && b[2] == "d" && b[3] == ":";
    }

    /// @notice Returns true if the string is non-empty and starts with "did:".
    function isWellFormedDID(string memory did) internal pure returns (bool) {
        return bytes(did).length > 4 && hasValidDIDPrefix(did);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title BytesUtils — helpers for bytes32 and bytes manipulation.
library BytesUtils {
    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    /// @dev Slice bounds exceed the data length.
    error SliceOutOfBounds(uint256 offset, uint256 length, uint256 dataLength);

    // -----------------------------------------------------------------------
    // bytes32 helpers
    // -----------------------------------------------------------------------

    /// @notice Returns true when `value` equals bytes32(0).
    function isZero(bytes32 value) internal pure returns (bool) {
        return value == bytes32(0);
    }

    /// @notice Converts bytes32 to its 0x-prefixed lowercase hex string.
    function toHexString(bytes32 value) internal pure returns (string memory) {
        bytes memory result = new bytes(66);
        result[0] = "0";
        result[1] = "x";
        bytes memory hexChars = "0123456789abcdef";
        for (uint256 i = 0; i < 32; i++) {
            result[2 + i * 2] = hexChars[uint8(value[i]) >> 4];
            result[3 + i * 2] = hexChars[uint8(value[i]) & 0x0f];
        }
        return string(result);
    }

    // -----------------------------------------------------------------------
    // bytes helpers
    // -----------------------------------------------------------------------

    /// @notice Returns true if `data` has zero length.
    function isEmpty(bytes memory data) internal pure returns (bool) {
        return data.length == 0;
    }

    /// @notice Returns the first `length` bytes of `data` as a new bytes array.
    /// @dev Reverts if `length` exceeds `data.length`.
    function slice(bytes memory data, uint256 offset, uint256 length) internal pure returns (bytes memory) {
        if (offset + length > data.length) {
            revert SliceOutOfBounds(offset, length, data.length);
        }
        bytes memory result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[i] = data[offset + i];
        }
        return result;
    }
}

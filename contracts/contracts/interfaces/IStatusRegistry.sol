// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title IStatusRegistry — on-chain anchoring of Bitstring Status List credentials.
/// Only the credential hash is stored, not the full bitstring.
interface IStatusRegistry {
    // -----------------------------------------------------------------------
    // Structs
    // -----------------------------------------------------------------------

    struct StatusAnchor {
        bytes32 issuerDidHash;        // keccak256(issuerDid)
        uint256 statusListIndex;
        bytes32 credentialHash;       // SHA-256 of the full status list JWT
        string statusListUrl;          // Where to fetch the credential
        uint256 publishedAt;
        uint256 freshnessDeltaSeconds;
        bool active;
    }

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error InvalidFreshnessDelta(uint256 provided, uint256 min, uint256 max);
    error AnchorNotFound(bytes32 anchorKey);

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event StatusAnchorPublished(
        bytes32 indexed issuerDidHash,
        uint256 indexed statusListIndex,
        bytes32 credentialHash,
        string statusListUrl,
        uint256 freshnessDeltaSeconds
    );

    /// @notice Emitted for emergency revocation — no state change, off-chain indexer acts on this.
    event EmergencyRevocationEmitted(
        bytes32 indexed credentialHash,
        string reason,
        address indexed revokedBy
    );

    // -----------------------------------------------------------------------
    // Write
    // -----------------------------------------------------------------------

    function publishStatusAnchor(
        string calldata issuerDid,
        uint256 statusListIndex,
        bytes32 credentialHash,
        string calldata statusListUrl,
        uint256 freshnessDeltaSeconds
    ) external;

    /// @notice Emit emergency revocation event — does NOT modify contract state.
    function emitEmergencyRevocation(bytes32 credentialHash, string calldata reason) external;

    // -----------------------------------------------------------------------
    // Read
    // -----------------------------------------------------------------------

    function getStatusAnchor(
        string calldata issuerDid,
        uint256 statusListIndex
    ) external view returns (StatusAnchor memory);

    function verifyStatusAnchor(
        string calldata issuerDid,
        uint256 statusListIndex,
        bytes32 credentialHash
    ) external view returns (bool);

    function getFreshnessDelta(
        string calldata issuerDid,
        uint256 statusListIndex
    ) external view returns (uint256);
}

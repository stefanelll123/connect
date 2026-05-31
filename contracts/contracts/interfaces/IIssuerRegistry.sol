// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title IIssuerRegistry — interface for the on-chain DID issuer whitelist.
/// Trusted issuers are identified by their DID string; the contract computes
/// bytes32 keys internally via keccak256.
interface IIssuerRegistry {
    // -----------------------------------------------------------------------
    // Structs
    // -----------------------------------------------------------------------

    struct IssuerRecord {
        string did;
        string name;
        string description;
        uint256 registeredAt;
        uint256 updatedAt;
        bool active;
        string metadataURI;
    }

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error IssuerAlreadyRegistered(bytes32 didHash);
    error IssuerNotFound(bytes32 didHash);
    error IssuerAlreadyRevoked(bytes32 didHash);
    error InvalidDID(string reason);

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event IssuerRegistered(bytes32 indexed didHash, string did, string name, address indexed registeredBy);
    event IssuerRevoked(bytes32 indexed didHash, string did, address indexed revokedBy);
    event IssuerUpdated(bytes32 indexed didHash, string did, address indexed updatedBy);

    // -----------------------------------------------------------------------
    // Write
    // -----------------------------------------------------------------------

    function registerIssuer(
        string calldata did,
        string calldata name,
        string calldata description,
        string calldata metadataURI
    ) external;

    function revokeIssuer(string calldata did) external;

    function updateIssuer(
        string calldata did,
        string calldata name,
        string calldata description,
        string calldata metadataURI
    ) external;

    // -----------------------------------------------------------------------
    // Read
    // -----------------------------------------------------------------------

    function isIssuerActive(string calldata did) external view returns (bool);
    function getIssuer(string calldata did) external view returns (IssuerRecord memory);
    function getIssuerCount() external view returns (uint256);
    function getIssuerAtIndex(uint256 index) external view returns (IssuerRecord memory);
}

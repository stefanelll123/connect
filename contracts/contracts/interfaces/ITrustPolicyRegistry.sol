// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ITrustPolicyRegistry — service-level trust policy bindings on-chain.
/// Each policy maps a serviceId to a set of allowed issuer DIDs and required
/// credential types. Version history is retained for audit.
interface ITrustPolicyRegistry {
    // -----------------------------------------------------------------------
    // Structs
    // -----------------------------------------------------------------------

    struct TrustPolicy {
        string serviceId;
        string[] allowedIssuerDids;
        string[] requiredCredentialTypes;
        uint256 version;
        uint256 createdAt;
        uint256 updatedAt;
        bool active;
        string description;
    }

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error PolicyAlreadyExists(bytes32 serviceIdHash);
    error PolicyNotFound(bytes32 serviceIdHash);
    error UnknownIssuer(string did);
    error EmptyAllowedIssuers();
    error TooManyIssuers(uint256 provided, uint256 max);

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event PolicyCreated(
        bytes32 indexed serviceIdHash,
        string serviceId,
        uint256 version,
        address indexed createdBy
    );
    event PolicyUpdated(
        bytes32 indexed serviceIdHash,
        string serviceId,
        uint256 newVersion,
        address indexed updatedBy
    );
    event PolicyDeactivated(
        bytes32 indexed serviceIdHash,
        string serviceId,
        address indexed deactivatedBy
    );

    // -----------------------------------------------------------------------
    // Write
    // -----------------------------------------------------------------------

    function createPolicy(
        string calldata serviceId,
        string[] calldata allowedIssuerDids,
        string[] calldata requiredCredentialTypes,
        string calldata description
    ) external;

    function updatePolicy(
        string calldata serviceId,
        string[] calldata allowedIssuerDids,
        string[] calldata requiredCredentialTypes,
        string calldata description
    ) external;

    function deactivatePolicy(string calldata serviceId) external;

    // -----------------------------------------------------------------------
    // Read
    // -----------------------------------------------------------------------

    function getPolicy(string calldata serviceId) external view returns (TrustPolicy memory);
    function isPolicyActive(string calldata serviceId) external view returns (bool);
    function getPolicyHistory(string calldata serviceId) external view returns (TrustPolicy[] memory);
    function getPolicyCount() external view returns (uint256);
    function isIssuerAllowedForService(
        string calldata serviceId,
        string calldata issuerDid
    ) external view returns (bool);
}

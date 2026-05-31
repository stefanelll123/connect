// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title IServiceRegistry — on-chain directory of Sentinel service endpoints.
/// Allows role-based enumeration of producer / consumer services.
interface IServiceRegistry {
    // -----------------------------------------------------------------------
    // Structs
    // -----------------------------------------------------------------------

    struct ServiceRecord {
        string serviceId;
        string did;
        string baseUrl;
        string role;        // 'producer' | 'consumer'
        bool active;
        uint256 registeredAt;
        uint256 updatedAt;
        string description;
    }

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error ServiceAlreadyRegistered(bytes32 serviceIdHash);
    error ServiceNotFound(bytes32 serviceIdHash);
    error InvalidRole(string role);
    error InvalidUrl(string reason);

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event ServiceRegistered(
        bytes32 indexed serviceIdHash,
        string serviceId,
        string did,
        string role,
        string baseUrl
    );
    event ServiceUpdated(bytes32 indexed serviceIdHash, string serviceId, string newBaseUrl);
    event ServiceDeregistered(bytes32 indexed serviceIdHash, string serviceId);

    // -----------------------------------------------------------------------
    // Write
    // -----------------------------------------------------------------------

    function registerService(
        string calldata serviceId,
        string calldata did,
        string calldata baseUrl,
        string calldata role,
        string calldata description
    ) external;

    function updateService(
        string calldata serviceId,
        string calldata newBaseUrl,
        string calldata description
    ) external;

    function deregisterService(string calldata serviceId) external;

    // -----------------------------------------------------------------------
    // Read
    // -----------------------------------------------------------------------

    function getService(string calldata serviceId) external view returns (ServiceRecord memory);
    function isServiceActive(string calldata serviceId) external view returns (bool);
    function getServicesByRole(string calldata role) external view returns (ServiceRecord[] memory);
    function getServiceCount() external view returns (uint256);
}

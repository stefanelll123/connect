// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {IServiceRegistry} from "../interfaces/IServiceRegistry.sol";

/// @title ServiceRegistry — on-chain directory of Sentinel service endpoints.
///
/// @custom:storage-layout
///   _services         : mapping(bytes32 => ServiceRecord)
///   _serviceKeys      : bytes32[]
///   _serviceKeyIndex  : mapping(bytes32 => uint256)
///   _roleIndex        : mapping(bytes32 => bytes32[])
///   _roleServiceIndex : mapping(bytes32 => mapping(bytes32 => uint256))
///   __gap             : uint256[50] reserved for V2+
///
/// @custom:oz-upgrades-from ServiceRegistry
contract ServiceRegistry is Initializable, AccessControlUpgradeable, IServiceRegistry {
    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    bytes32 public constant SERVICE_REGISTRY_ADMIN_ROLE =
        keccak256("SERVICE_REGISTRY_ADMIN_ROLE");

    bytes32 private constant _ROLE_PRODUCER = keccak256("producer");
    bytes32 private constant _ROLE_CONSUMER = keccak256("consumer");

    uint256 private constant MAX_URL_LENGTH = 2048;
    uint256 private constant MAX_SERVICES_PER_ROLE = 1000;

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    /// @dev serviceIdHash → ServiceRecord
    mapping(bytes32 => ServiceRecord) private _services;

    /// @dev ordered list of all registered (ever) service-id hashes
    bytes32[] private _serviceKeys;

    /// @dev serviceIdHash → index in _serviceKeys
    mapping(bytes32 => uint256) private _serviceKeyIndex;

    /// @dev roleHash → list of active service-id hashes for that role
    mapping(bytes32 => bytes32[]) private _roleIndex;

    /// @dev roleHash → serviceIdHash → index in _roleIndex[roleHash]
    mapping(bytes32 => mapping(bytes32 => uint256)) private _roleServiceIndex;

    /// @dev Reserved storage gap for future upgrades. MUST remain last.
    uint256[50] private __gap;

    // -----------------------------------------------------------------------
    // Constructor — disable initializers on implementation contract
    // -----------------------------------------------------------------------

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // -----------------------------------------------------------------------
    // Initializer
    // -----------------------------------------------------------------------

    function initialize(address initialAdmin) public initializer {
        __AccessControl_init();
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(SERVICE_REGISTRY_ADMIN_ROLE, initialAdmin);
    }

    // -----------------------------------------------------------------------
    // Write functions
    // -----------------------------------------------------------------------

    /// @inheritdoc IServiceRegistry
    function registerService(
        string calldata serviceId,
        string calldata did,
        string calldata baseUrl,
        string calldata role,
        string calldata description
    ) external onlyRole(SERVICE_REGISTRY_ADMIN_ROLE) {
        bytes32 roleHash = keccak256(bytes(role));
        if (roleHash != _ROLE_PRODUCER && roleHash != _ROLE_CONSUMER) {
            revert InvalidRole(role);
        }
        _validateUrl(baseUrl);

        bytes32 serviceIdHash = keccak256(abi.encodePacked(serviceId));
        if (_services[serviceIdHash].active) {
            revert ServiceAlreadyRegistered(serviceIdHash);
        }

        _services[serviceIdHash] = ServiceRecord({
            serviceId: serviceId,
            did: did,
            baseUrl: baseUrl,
            role: role,
            active: true,
            registeredAt: block.timestamp,
            updatedAt: block.timestamp,
            description: description
        });

        _serviceKeyIndex[serviceIdHash] = _serviceKeys.length;
        _serviceKeys.push(serviceIdHash);

        _roleServiceIndex[roleHash][serviceIdHash] = _roleIndex[roleHash].length;
        _roleIndex[roleHash].push(serviceIdHash);

        emit ServiceRegistered(serviceIdHash, serviceId, did, role, baseUrl);
    }

    /// @inheritdoc IServiceRegistry
    function updateService(
        string calldata serviceId,
        string calldata newBaseUrl,
        string calldata description
    ) external onlyRole(SERVICE_REGISTRY_ADMIN_ROLE) {
        _validateUrl(newBaseUrl);
        bytes32 serviceIdHash = keccak256(abi.encodePacked(serviceId));
        ServiceRecord storage svc = _services[serviceIdHash];
        if (!svc.active) revert ServiceNotFound(serviceIdHash);

        svc.baseUrl = newBaseUrl;
        svc.description = description;
        svc.updatedAt = block.timestamp;

        emit ServiceUpdated(serviceIdHash, serviceId, newBaseUrl);
    }

    /// @inheritdoc IServiceRegistry
    function deregisterService(string calldata serviceId)
        external
        onlyRole(SERVICE_REGISTRY_ADMIN_ROLE)
    {
        bytes32 serviceIdHash = keccak256(abi.encodePacked(serviceId));
        ServiceRecord storage svc = _services[serviceIdHash];
        if (!svc.active) revert ServiceNotFound(serviceIdHash);

        // Capture role before deactivating
        bytes32 roleHash = keccak256(bytes(svc.role));

        svc.active = false;
        svc.updatedAt = block.timestamp;

        // Swap-and-pop from _serviceKeys
        uint256 svcIdx = _serviceKeyIndex[serviceIdHash];
        uint256 lastSvcIdx = _serviceKeys.length - 1;
        bytes32 lastSvcKey = _serviceKeys[lastSvcIdx];
        _serviceKeys[svcIdx] = lastSvcKey;
        _serviceKeyIndex[lastSvcKey] = svcIdx;
        _serviceKeys.pop();
        delete _serviceKeyIndex[serviceIdHash];

        // Swap-and-pop from role index
        bytes32[] storage roleArr = _roleIndex[roleHash];
        uint256 roleIdx = _roleServiceIndex[roleHash][serviceIdHash];
        uint256 lastRoleIdx = roleArr.length - 1;
        bytes32 lastRoleKey = roleArr[lastRoleIdx];
        roleArr[roleIdx] = lastRoleKey;
        _roleServiceIndex[roleHash][lastRoleKey] = roleIdx;
        roleArr.pop();
        delete _roleServiceIndex[roleHash][serviceIdHash];

        emit ServiceDeregistered(serviceIdHash, serviceId);
    }

    // -----------------------------------------------------------------------
    // Read functions
    // -----------------------------------------------------------------------

    /// @inheritdoc IServiceRegistry
    function getService(string calldata serviceId)
        external
        view
        returns (ServiceRecord memory)
    {
        bytes32 serviceIdHash = keccak256(abi.encodePacked(serviceId));
        if (_services[serviceIdHash].registeredAt == 0) revert ServiceNotFound(serviceIdHash);
        return _services[serviceIdHash];
    }

    /// @inheritdoc IServiceRegistry
    function isServiceActive(string calldata serviceId) external view returns (bool) {
        return _services[keccak256(abi.encodePacked(serviceId))].active;
    }

    /// @inheritdoc IServiceRegistry
    function getServicesByRole(string calldata role)
        external
        view
        returns (ServiceRecord[] memory)
    {
        bytes32 roleHash = keccak256(bytes(role));
        bytes32[] storage keys = _roleIndex[roleHash];
        uint256 len = keys.length;
        ServiceRecord[] memory records = new ServiceRecord[](len);
        for (uint256 i = 0; i < len; i++) {
            records[i] = _services[keys[i]];
        }
        return records;
    }

    /// @inheritdoc IServiceRegistry
    function getServiceCount() external view returns (uint256) {
        return _serviceKeys.length;
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    function _validateUrl(string calldata url) internal view {
        uint256 urlLen = bytes(url).length;
        if (urlLen == 0 || urlLen > MAX_URL_LENGTH) {
            revert InvalidUrl(url);
        }
        // On non-local chains enforce https://
        if (block.chainid != 31337) {
            bytes memory prefix = bytes("https://");
            bytes memory urlBytes = bytes(url);
            if (urlBytes.length < prefix.length) revert InvalidUrl(url);
            for (uint256 i = 0; i < prefix.length; i++) {
                if (urlBytes[i] != prefix[i]) revert InvalidUrl(url);
            }
        }
    }
}

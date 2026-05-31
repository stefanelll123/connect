// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ITrustPolicyRegistry} from "../interfaces/ITrustPolicyRegistry.sol";
import {IIssuerRegistry} from "../interfaces/IIssuerRegistry.sol";

/// @title TrustPolicyRegistry — service-level trust policy bindings on-chain.
///
/// @custom:storage-layout
///   _policies        : mapping(bytes32 => TrustPolicy)
///   _policyHistory   : mapping(bytes32 => TrustPolicy[])
///   _policyKeys      : bytes32[]
///   _policyKeyIndex  : mapping(bytes32 => uint256)
///   _issuerRegistry  : IIssuerRegistry  (NOT immutable — upgradeable)
///   __gap            : uint256[50] reserved for V2+
///
/// @custom:oz-upgrades-from TrustPolicyRegistry
contract TrustPolicyRegistry is
    Initializable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ITrustPolicyRegistry
{
    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    bytes32 public constant POLICY_ADMIN_ROLE = keccak256("POLICY_ADMIN_ROLE");
    uint256 public constant MAX_ALLOWED_ISSUERS = 100;

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    /// @dev serviceIdHash → current active TrustPolicy
    mapping(bytes32 => TrustPolicy) private _policies;

    /// @dev serviceIdHash → ordered list of all superseded versions
    mapping(bytes32 => TrustPolicy[]) private _policyHistory;

    /// @dev ordered list of known service-id hashes (for enumeration)
    bytes32[] private _policyKeys;

    /// @dev serviceIdHash → index in _policyKeys
    mapping(bytes32 => uint256) private _policyKeyIndex;

    /// @dev IssuerRegistry for cross-contract issuer validation.
    ///      Stored as regular storage (not immutable) for proxy compatibility.
    IIssuerRegistry private _issuerRegistry;

    /// @dev Inline reentrancy guard status: 0=uninit, 1=not-entered, 2=entered.
    ///      Initialized in initialize(). Proxy-compatible (no constructor needed).
    uint256 private _reentrancyStatus;

    /// @dev Reserved storage gap for future upgrades. MUST remain last.
    uint256[49] private __gap;

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

    function initialize(address initialAdmin, address issuerRegistryAddress) public initializer {
        __AccessControl_init();
        __Pausable_init();
        // ReentrancyGuard (@custom:stateless) requires no initializer call
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(POLICY_ADMIN_ROLE, initialAdmin);
        _issuerRegistry = IIssuerRegistry(issuerRegistryAddress);
        _reentrancyStatus = 1; // NOT_ENTERED
    }

    // -----------------------------------------------------------------------
    // Reentrancy guard (inline, no constructor — proxy-compatible)
    // -----------------------------------------------------------------------

    modifier nonReentrant() {
        require(_reentrancyStatus != 2, "TrustPolicyRegistry: reentrant call");
        _reentrancyStatus = 2;
        _;
        _reentrancyStatus = 1;
    }

    // -----------------------------------------------------------------------
    // Write functions
    // -----------------------------------------------------------------------

    /// @inheritdoc ITrustPolicyRegistry
    function createPolicy(
        string calldata serviceId,
        string[] calldata allowedIssuerDids,
        string[] calldata requiredCredentialTypes,
        string calldata description
    ) external onlyRole(POLICY_ADMIN_ROLE) whenNotPaused nonReentrant {
        if (allowedIssuerDids.length == 0) revert EmptyAllowedIssuers();
        if (allowedIssuerDids.length > MAX_ALLOWED_ISSUERS) {
            revert TooManyIssuers(allowedIssuerDids.length, MAX_ALLOWED_ISSUERS);
        }

        bytes32 serviceIdHash = keccak256(abi.encodePacked(serviceId));
        if (_policies[serviceIdHash].active) {
            revert PolicyAlreadyExists(serviceIdHash);
        }

        _validateIssuers(allowedIssuerDids);

        _policies[serviceIdHash] = TrustPolicy({
            serviceId: serviceId,
            allowedIssuerDids: allowedIssuerDids,
            requiredCredentialTypes: requiredCredentialTypes,
            version: 1,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            active: true,
            description: description
        });

        _policyKeyIndex[serviceIdHash] = _policyKeys.length;
        _policyKeys.push(serviceIdHash);

        emit PolicyCreated(serviceIdHash, serviceId, 1, msg.sender);
    }

    /// @inheritdoc ITrustPolicyRegistry
    function updatePolicy(
        string calldata serviceId,
        string[] calldata allowedIssuerDids,
        string[] calldata requiredCredentialTypes,
        string calldata description
    ) external onlyRole(POLICY_ADMIN_ROLE) whenNotPaused nonReentrant {
        if (allowedIssuerDids.length == 0) revert EmptyAllowedIssuers();
        if (allowedIssuerDids.length > MAX_ALLOWED_ISSUERS) {
            revert TooManyIssuers(allowedIssuerDids.length, MAX_ALLOWED_ISSUERS);
        }

        bytes32 serviceIdHash = keccak256(abi.encodePacked(serviceId));
        if (!_policies[serviceIdHash].active) revert PolicyNotFound(serviceIdHash);

        _validateIssuers(allowedIssuerDids);

        // Archive the current version before updating
        TrustPolicy memory prev = _policies[serviceIdHash];
        _policyHistory[serviceIdHash].push(prev);

        uint256 newVersion = _policies[serviceIdHash].version + 1;
        _policies[serviceIdHash].allowedIssuerDids = allowedIssuerDids;
        _policies[serviceIdHash].requiredCredentialTypes = requiredCredentialTypes;
        _policies[serviceIdHash].description = description;
        _policies[serviceIdHash].version = newVersion;
        _policies[serviceIdHash].updatedAt = block.timestamp;

        emit PolicyUpdated(serviceIdHash, serviceId, newVersion, msg.sender);
    }

    /// @inheritdoc ITrustPolicyRegistry
    function deactivatePolicy(string calldata serviceId) external onlyRole(POLICY_ADMIN_ROLE) {
        bytes32 serviceIdHash = keccak256(abi.encodePacked(serviceId));
        if (!_policies[serviceIdHash].active) revert PolicyNotFound(serviceIdHash);

        _policies[serviceIdHash].active = false;
        _policies[serviceIdHash].updatedAt = block.timestamp;

        // Swap-and-pop from enumeration array
        uint256 idx = _policyKeyIndex[serviceIdHash];
        uint256 lastIdx = _policyKeys.length - 1;
        bytes32 lastKey = _policyKeys[lastIdx];
        _policyKeys[idx] = lastKey;
        _policyKeyIndex[lastKey] = idx;
        _policyKeys.pop();
        delete _policyKeyIndex[serviceIdHash];

        emit PolicyDeactivated(serviceIdHash, serviceId, msg.sender);
    }

    /// @notice Pause the registry.
    function pauseRegistry() external onlyRole(DEFAULT_ADMIN_ROLE) { _pause(); }

    /// @notice Unpause the registry.
    function unpauseRegistry() external onlyRole(DEFAULT_ADMIN_ROLE) { _unpause(); }

    // -----------------------------------------------------------------------
    // Read functions
    // -----------------------------------------------------------------------

    /// @inheritdoc ITrustPolicyRegistry
    function getPolicy(string calldata serviceId) external view returns (TrustPolicy memory) {
        bytes32 serviceIdHash = keccak256(abi.encodePacked(serviceId));
        if (_policies[serviceIdHash].createdAt == 0) revert PolicyNotFound(serviceIdHash);
        return _policies[serviceIdHash];
    }

    /// @inheritdoc ITrustPolicyRegistry
    function isPolicyActive(string calldata serviceId) external view returns (bool) {
        return _policies[keccak256(abi.encodePacked(serviceId))].active;
    }

    /// @inheritdoc ITrustPolicyRegistry
    function getPolicyHistory(string calldata serviceId)
        external
        view
        returns (TrustPolicy[] memory)
    {
        return _policyHistory[keccak256(abi.encodePacked(serviceId))];
    }

    /// @inheritdoc ITrustPolicyRegistry
    function getPolicyCount() external view returns (uint256) {
        return _policyKeys.length;
    }

    /// @inheritdoc ITrustPolicyRegistry
    function isIssuerAllowedForService(
        string calldata serviceId,
        string calldata issuerDid
    ) external view returns (bool) {
        TrustPolicy storage policy = _policies[keccak256(abi.encodePacked(serviceId))];
        if (!policy.active) return false;
        bytes32 didHash = keccak256(abi.encodePacked(issuerDid));
        string[] storage allowed = policy.allowedIssuerDids;
        uint256 len = allowed.length;
        for (uint256 i = 0; i < len; i++) {
            if (keccak256(abi.encodePacked(allowed[i])) == didHash) return true;
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    function _validateIssuers(string[] calldata dids) internal view {
        for (uint256 i = 0; i < dids.length; i++) {
            if (!_issuerRegistry.isIssuerActive(dids[i])) {
                revert UnknownIssuer(dids[i]);
            }
        }
    }
}

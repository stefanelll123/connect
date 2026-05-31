// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {IIssuerRegistry} from "../interfaces/IIssuerRegistry.sol";

/// @title IssuerRegistry — on-chain whitelist of trusted DID issuers.
///
/// @custom:storage-layout
///   slot 0..n  : AccessControlUpgradeable internal storage
///   slot n+1.. : PausableUpgradeable internal storage
///   _issuers        : mapping(bytes32 => IssuerRecord)
///   _issuerKeys     : bytes32[]
///   _issuerKeyIndex : mapping(bytes32 => uint256)
///   __gap           : uint256[50] (reserved for V2+ upgrades — NEVER reorder/remove)
///
/// @custom:oz-upgrades-from IssuerRegistry
contract IssuerRegistry is Initializable, AccessControlUpgradeable, PausableUpgradeable, IIssuerRegistry {
    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    bytes32 public constant ISSUER_ADMIN_ROLE = keccak256("ISSUER_ADMIN_ROLE");
    uint256 private constant MAX_DID_LENGTH = 2048;

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    /// @dev didHash -> IssuerRecord
    mapping(bytes32 => IssuerRecord) private _issuers;

    /// @dev ordered array of active issuer hashes (for enumeration)
    bytes32[] private _issuerKeys;

    /// @dev didHash -> index in _issuerKeys (O(1) swap-and-pop)
    mapping(bytes32 => uint256) private _issuerKeyIndex;

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
        __Pausable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(ISSUER_ADMIN_ROLE, initialAdmin);
    }

    // -----------------------------------------------------------------------
    // Write functions
    // -----------------------------------------------------------------------

    function registerIssuer(
        string calldata did,
        string calldata name,
        string calldata description,
        string calldata metadataURI
    ) external onlyRole(ISSUER_ADMIN_ROLE) whenNotPaused {
        uint256 didLen = bytes(did).length;
        if (didLen == 0 || didLen > MAX_DID_LENGTH) {
            revert InvalidDID("DID length must be 1-2048 bytes");
        }
        bytes32 didHash = keccak256(abi.encodePacked(did));
        if (_issuers[didHash].active) {
            revert IssuerAlreadyRegistered(didHash);
        }
        _issuers[didHash] = IssuerRecord({
            did: did,
            name: name,
            description: description,
            registeredAt: block.timestamp,
            updatedAt: block.timestamp,
            active: true,
            metadataURI: metadataURI
        });
        _issuerKeyIndex[didHash] = _issuerKeys.length;
        _issuerKeys.push(didHash);
        emit IssuerRegistered(didHash, did, name, msg.sender);
    }

    /// @dev Works even when paused (emergency support).
    function revokeIssuer(string calldata did) external onlyRole(ISSUER_ADMIN_ROLE) {
        bytes32 didHash = keccak256(abi.encodePacked(did));
        if (_issuers[didHash].registeredAt == 0) revert IssuerNotFound(didHash);
        if (!_issuers[didHash].active) revert IssuerAlreadyRevoked(didHash);

        _issuers[didHash].active = false;
        _issuers[didHash].updatedAt = block.timestamp;

        uint256 idx = _issuerKeyIndex[didHash];
        uint256 lastIdx = _issuerKeys.length - 1;
        bytes32 lastKey = _issuerKeys[lastIdx];
        _issuerKeys[idx] = lastKey;
        _issuerKeyIndex[lastKey] = idx;
        _issuerKeys.pop();
        delete _issuerKeyIndex[didHash];

        emit IssuerRevoked(didHash, did, msg.sender);
    }

    function updateIssuer(
        string calldata did,
        string calldata name,
        string calldata description,
        string calldata metadataURI
    ) external onlyRole(ISSUER_ADMIN_ROLE) whenNotPaused {
        bytes32 didHash = keccak256(abi.encodePacked(did));
        if (_issuers[didHash].registeredAt == 0) revert IssuerNotFound(didHash);
        if (!_issuers[didHash].active) revert IssuerAlreadyRevoked(didHash);

        _issuers[didHash].name = name;
        _issuers[didHash].description = description;
        _issuers[didHash].metadataURI = metadataURI;
        _issuers[didHash].updatedAt = block.timestamp;
        emit IssuerUpdated(didHash, did, msg.sender);
    }

    function pauseRegistry() external onlyRole(DEFAULT_ADMIN_ROLE) { _pause(); }
    function unpauseRegistry() external onlyRole(DEFAULT_ADMIN_ROLE) { _unpause(); }

    // -----------------------------------------------------------------------
    // Read functions
    // -----------------------------------------------------------------------

    function isIssuerActive(string calldata did) external view returns (bool) {
        return _issuers[keccak256(abi.encodePacked(did))].active;
    }

    function getIssuer(string calldata did) external view returns (IssuerRecord memory) {
        bytes32 didHash = keccak256(abi.encodePacked(did));
        if (_issuers[didHash].registeredAt == 0) revert IssuerNotFound(didHash);
        return _issuers[didHash];
    }

    function getIssuerCount() external view returns (uint256) {
        return _issuerKeys.length;
    }

    function getIssuerAtIndex(uint256 index) external view returns (IssuerRecord memory) {
        require(index < _issuerKeys.length, "IssuerRegistry: index out of bounds");
        return _issuers[_issuerKeys[index]];
    }
}

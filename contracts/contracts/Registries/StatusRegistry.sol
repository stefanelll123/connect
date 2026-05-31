// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {IStatusRegistry} from "../interfaces/IStatusRegistry.sol";

/// @title StatusRegistry — on-chain anchoring of Bitstring Status List credentials.
///
/// @custom:storage-layout
///   _anchors       : mapping(bytes32 => StatusAnchor)
///   _issuerAnchors : mapping(bytes32 => bytes32[])
///   __gap          : uint256[50] reserved for V2+
///
/// @custom:oz-upgrades-from StatusRegistry
contract StatusRegistry is Initializable, AccessControlUpgradeable, IStatusRegistry {
    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    bytes32 public constant ANCHOR_PUBLISHER_ROLE = keccak256("ANCHOR_PUBLISHER_ROLE");
    bytes32 public constant REVOCATION_ADMIN_ROLE = keccak256("REVOCATION_ADMIN_ROLE");

    uint256 public constant MIN_FRESHNESS_DELTA = 60;     // 1 minute
    uint256 public constant MAX_FRESHNESS_DELTA = 86400;  // 24 hours

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    /// @dev anchorKey = keccak256(abi.encodePacked(issuerDid, statusListIndex)) → StatusAnchor
    mapping(bytes32 => StatusAnchor) private _anchors;

    /// @dev issuerDidHash → list of anchor keys published by that issuer
    mapping(bytes32 => bytes32[]) private _issuerAnchors;

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

    // issuerRegistry parameter reserved for future cross-contract validation.
    function initialize(address initialAdmin, address /* issuerRegistry */) public initializer {
        __AccessControl_init();
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(ANCHOR_PUBLISHER_ROLE, initialAdmin);
        _grantRole(REVOCATION_ADMIN_ROLE, initialAdmin);
    }

    // -----------------------------------------------------------------------
    // Write functions
    // -----------------------------------------------------------------------

    /// @inheritdoc IStatusRegistry
    function publishStatusAnchor(
        string calldata issuerDid,
        uint256 statusListIndex,
        bytes32 credentialHash,
        string calldata statusListUrl,
        uint256 freshnessDeltaSeconds
    ) external onlyRole(ANCHOR_PUBLISHER_ROLE) {
        if (
            freshnessDeltaSeconds < MIN_FRESHNESS_DELTA ||
            freshnessDeltaSeconds > MAX_FRESHNESS_DELTA
        ) {
            revert InvalidFreshnessDelta(
                freshnessDeltaSeconds,
                MIN_FRESHNESS_DELTA,
                MAX_FRESHNESS_DELTA
            );
        }

        bytes32 issuerDidHash = keccak256(abi.encodePacked(issuerDid));
        bytes32 anchorKey = keccak256(abi.encodePacked(issuerDid, statusListIndex));

        bool isNew = !_anchors[anchorKey].active;

        _anchors[anchorKey] = StatusAnchor({
            issuerDidHash: issuerDidHash,
            statusListIndex: statusListIndex,
            credentialHash: credentialHash,
            statusListUrl: statusListUrl,
            publishedAt: block.timestamp,
            freshnessDeltaSeconds: freshnessDeltaSeconds,
            active: true
        });

        if (isNew) {
            _issuerAnchors[issuerDidHash].push(anchorKey);
        }

        emit StatusAnchorPublished(
            issuerDidHash,
            statusListIndex,
            credentialHash,
            statusListUrl,
            freshnessDeltaSeconds
        );
    }

    /// @inheritdoc IStatusRegistry
    /// @dev Only emits an event — does NOT modify contract state.
    function emitEmergencyRevocation(
        bytes32 credentialHash,
        string calldata reason
    ) external onlyRole(REVOCATION_ADMIN_ROLE) {
        emit EmergencyRevocationEmitted(credentialHash, reason, msg.sender);
    }

    // -----------------------------------------------------------------------
    // Read functions
    // -----------------------------------------------------------------------

    /// @inheritdoc IStatusRegistry
    function getStatusAnchor(
        string calldata issuerDid,
        uint256 statusListIndex
    ) external view returns (StatusAnchor memory) {
        bytes32 anchorKey = keccak256(abi.encodePacked(issuerDid, statusListIndex));
        if (!_anchors[anchorKey].active) revert AnchorNotFound(anchorKey);
        return _anchors[anchorKey];
    }

    /// @inheritdoc IStatusRegistry
    function verifyStatusAnchor(
        string calldata issuerDid,
        uint256 statusListIndex,
        bytes32 credentialHash
    ) external view returns (bool) {
        bytes32 anchorKey = keccak256(abi.encodePacked(issuerDid, statusListIndex));
        if (!_anchors[anchorKey].active) return false;
        return _anchors[anchorKey].credentialHash == credentialHash;
    }

    /// @inheritdoc IStatusRegistry
    function getFreshnessDelta(
        string calldata issuerDid,
        uint256 statusListIndex
    ) external view returns (uint256) {
        bytes32 anchorKey = keccak256(abi.encodePacked(issuerDid, statusListIndex));
        if (!_anchors[anchorKey].active) revert AnchorNotFound(anchorKey);
        return _anchors[anchorKey].freshnessDeltaSeconds;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SentinelErrors — shared custom errors for all Sentinel registry contracts.
library SentinelErrors {
    // -----------------------------------------------------------------------
    // Access control
    // -----------------------------------------------------------------------

    /// @dev Caller is not the contract owner.
    error NotOwner(address caller);

    /// @dev Caller does not have the required role.
    error NotAuthorized(address caller, bytes32 role);

    // -----------------------------------------------------------------------
    // Registry — Issuers
    // -----------------------------------------------------------------------

    /// @dev Issuer DID has already been registered.
    error IssuerAlreadyRegistered(bytes32 didHash);

    /// @dev Issuer DID is not registered.
    error IssuerNotFound(bytes32 didHash);

    /// @dev Issuer is not active.
    error IssuerNotActive(bytes32 didHash);

    // -----------------------------------------------------------------------
    // Registry — Services
    // -----------------------------------------------------------------------

    /// @dev Service ID has already been registered.
    error ServiceAlreadyRegistered(bytes32 serviceIdHash);

    /// @dev Service ID is not registered.
    error ServiceNotFound(bytes32 serviceIdHash);

    // -----------------------------------------------------------------------
    // Registry — Status Lists
    // -----------------------------------------------------------------------

    /// @dev Status list anchor has already been published.
    error AnchorAlreadyPublished(bytes32 statusListId);

    /// @dev Status list anchor not found.
    error AnchorNotFound(bytes32 statusListId);

    // -----------------------------------------------------------------------
    // Registry — Trust Policies
    // -----------------------------------------------------------------------

    /// @dev Trust policy key is not known.
    error UnknownPolicyKey(bytes32 key);

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------

    /// @dev Empty or zero-length argument provided where content is required.
    error EmptyArgument(string paramName);

    /// @dev Numeric value is out of the accepted range.
    error ValueOutOfRange(string paramName, uint256 provided, uint256 minimum, uint256 maximum);
}

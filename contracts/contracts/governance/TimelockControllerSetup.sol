// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @title TimelockControllerSetup — governance timelock for registry upgrades.
///
/// Minimum delays:
///   - Mainnet  : 172800 seconds (48 hours)
///   - Testnet  : 300 seconds   (5 minutes)
///
/// All registry ProxyAdmin instances MUST be owned by a TimelockController so
/// that no single EOA can immediately push contract upgrades.
///
/// Usage:
///   1. Deploy this contract (or deploy TimelockController directly):
///        new TimelockController(minDelay, [multisig], [address(0)], address(0))
///   2. Transfer ProxyAdmin ownership to the deployed TimelockController address.
///   3. Proposal workflow: proposer calls schedule(), executors call execute() after delay.
contract TimelockControllerSetup {
    /// @notice Minimum delay enforced on mainnet (chain != 31337 && != 11155111).
    uint256 public constant MAINNET_MIN_DELAY = 172_800; // 48 hours

    /// @notice Reduced delay for testnet (Sepolia, chain 11155111).
    uint256 public constant TESTNET_MIN_DELAY = 300; // 5 minutes

    /// @notice Deploy a TimelockController with the appropriate delay for the
    ///         current chain. Returns the deployed controller address.
    ///
    /// @param proposers  Array of addresses allowed to schedule operations
    ///                   (typically a Guardian multisig or governance contract).
    /// @param executors  Array of addresses allowed to execute ready operations.
    ///                   Pass [address(0)] to allow anyone to execute after delay.
    /// @param admin      Optional admin address for initial setup. Pass address(0)
    ///                   to make the TimelockController self-administered — this is
    ///                   the RECOMMENDED production setting.
    function deploy(
        address[] calldata proposers,
        address[] calldata executors,
        address admin
    ) external returns (address timelockAddress) {
        uint256 minDelay = _minDelay();
        TimelockController timelock = new TimelockController(
            minDelay,
            proposers,
            executors,
            admin
        );
        timelockAddress = address(timelock);
    }

    /// @dev Returns the minimum delay appropriate for the current chain.
    function _minDelay() internal view returns (uint256) {
        uint256 chainId = block.chainid;
        if (chainId == 31337 || chainId == 11155111) {
            return TESTNET_MIN_DELAY;
        }
        return MAINNET_MIN_DELAY;
    }
}

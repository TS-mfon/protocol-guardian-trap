// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IProtocolInterfaces
/// @notice Aggregated interfaces for all external protocol contracts monitored by the Protocol Guardian Trap.
/// @dev These interfaces abstract the external calls needed to collect protocol state across multiple
///      threat vectors: oracles, lending pools, governance, token supply, bridges, and proxy patterns.

// =============================================================================
// ORACLE INTERFACES
// =============================================================================

/// @notice Chainlink-style aggregator interface for reading price feed data.
/// @dev Used to detect oracle manipulation and stale price feeds.
///      Compatible with Chainlink, Pyth adapters, and other aggregator-pattern oracles.
interface IChainlinkAggregator {
    /// @notice Returns the latest round data from the price feed.
    /// @return roundId The round ID of the latest data
    /// @return answer The latest price answer (scaled by `decimals()`)
    /// @return startedAt Timestamp when the round started
    /// @return updatedAt Timestamp when the answer was last updated
    /// @return answeredInRound The round ID in which the answer was computed
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );

    /// @notice Returns the number of decimals the price feed uses.
    function decimals() external view returns (uint8);
}

// =============================================================================
// LENDING PROTOCOL INTERFACES
// =============================================================================

/// @notice Interface for lending pool / comptroller-style contracts.
/// @dev Used to monitor total borrows, total collateral, and TVL.
///      Compatible with Aave, Compound, Euler, Radiant, and similar protocols.
interface ILendingPool {
    /// @notice Returns the total amount currently borrowed from the protocol.
    function totalBorrows() external view returns (uint256);

    /// @notice Returns the total collateral deposited in the protocol.
    function totalCollateral() external view returns (uint256);
}

// =============================================================================
// GOVERNANCE / ACCESS CONTROL INTERFACES
// =============================================================================

/// @notice Standard Ownable interface for detecting ownership changes.
/// @dev Used to detect admin key compromises and unauthorized ownership transfers.
interface IOwnable {
    /// @notice Returns the current owner of the contract.
    function owner() external view returns (address);
}

/// @notice Timelock controller interface for monitoring governance delays.
/// @dev Used to detect timelock bypass attempts where delay is reduced to zero.
interface ITimelock {
    /// @notice Returns the minimum delay enforced by the timelock.
    function getMinDelay() external view returns (uint256);
}

// =============================================================================
// PROXY / UPGRADEABLE INTERFACES
// =============================================================================

/// @notice Interface for UUPS/Transparent proxy patterns.
/// @dev Used to detect unauthorized proxy implementation changes.
///      The implementation address is read from the EIP-1967 storage slot.
interface IProxy {
    /// @notice Returns the address of the current logic/implementation contract.
    function implementation() external view returns (address);
}

// =============================================================================
// TOKEN / SUPPLY INTERFACES
// =============================================================================

/// @notice Minimal ERC20 interface for supply monitoring.
/// @dev Used to detect minting anomalies and supply inflation attacks.
interface IERC20Minimal {
    /// @notice Returns the total supply of the token.
    function totalSupply() external view returns (uint256);

    /// @notice Returns the token balance of a given account.
    function balanceOf(address account) external view returns (uint256);
}

// =============================================================================
// BRIDGE INTERFACES
// =============================================================================

/// @notice Generic bridge vault interface for monitoring bridge balances.
/// @dev Used to detect bridge drain attacks (e.g., Nomad $190M, Ronin $600M).
///      The bridge balance is typically read via `balanceOf` on the locked token contract.
interface IBridgeVault {
    /// @notice Returns the locked token balance in the bridge vault.
    function totalLocked() external view returns (uint256);
}

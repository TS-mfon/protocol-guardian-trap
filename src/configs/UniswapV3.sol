// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

/// @title UniswapV3 Preset Config
/// @notice To use: copy this file's contents over `ProtocolConfig.sol`
///         (they are drop-in interchangeable — same library name, same
///         function signatures). Rebuild and redeploy.
library ProtocolConfig {
    // Uniswap V3 Factory — the root contract for all pool creation
    function MONITORED_PROTOCOL() internal pure returns (address) {
        return 0x1F98431c8aD98523631AE4a59f267346ea31F984;
    }

    // Uniswap V3 Timelock (governance)
    function TIMELOCK() internal pure returns (address) {
        return 0x1a9C8182C09F50C8318d769245beA52c32BE35BC;
    }

    // USDC/ETH 0.05% pool tick oracle is often used as a price reference
    // But for external Chainlink cross-check, use ETH/USD feed
    function PRICE_ORACLE() internal pure returns (address) {
        return 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;
    }

    // WETH/USDC 0.05% pool is the deepest pool we can monitor TVL on
    function TVL_TOKEN() internal pure returns (address) {
        return 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2; // WETH
    }

    // NonfungiblePositionManager (LP shares)
    function SHARES_TOKEN() internal pure returns (address) {
        return 0xC36442b4a4522E871399CD717aBDD847Ab11FE88;
    }

    // Uniswap is self-contained; no cross-chain bridge
    function BRIDGE_CONTRACT() internal pure returns (address) {
        return address(0);
    }

    // Uniswap tolerates more volatility than a lending protocol, so
    // slightly higher thresholds to avoid false positives during genuine
    // high-volume days.
    function ORACLE_DEVIATION_BPS() internal pure returns (uint256) { return 2_000; } // 20 %
    function TVL_DRAIN_BPS()        internal pure returns (uint256) { return 3_000; } // 30 %
    function BORROW_SPIKE_BPS()     internal pure returns (uint256) { return 10_000; } // DEX has no borrows, effectively disabled
    function SUPPLY_SPIKE_BPS()     internal pure returns (uint256) { return 1_000; } // 10 %
    function BRIDGE_DRAIN_BPS()     internal pure returns (uint256) { return 3_000; } // unused
    function ORACLE_STALENESS_SEC() internal pure returns (uint256) { return 3_600; } //  1 h

    function PROTOCOL_NAME() internal pure returns (string memory) {
        return "Uniswap V3 (Mainnet)";
    }
}

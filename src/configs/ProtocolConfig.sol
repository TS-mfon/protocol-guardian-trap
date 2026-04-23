// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

/// @title ProtocolConfig
/// @notice Plug-and-play configuration for ProtocolGuardianTrap.
///
/// The trap itself is protocol-agnostic. To deploy it for a SPECIFIC
/// protocol (Aave V3, Uniswap V3, Compound, etc.) the user edits THIS
/// file only — changing the address constants and optionally the
/// threshold bps values.
///
/// The file below ships with AAVE V3 MAINNET defaults. See the README
/// for Uniswap V3 and other presets.
library ProtocolConfig {
    // -------------------------------------------------------------------- //
    //                          ADDRESSES (edit here)                         //
    // -------------------------------------------------------------------- //

    /// @notice Main protocol entry contract (exposes owner() and pause())
    ///
    ///   Aave V3 mainnet Pool:         0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2
    ///   Uniswap V3 Factory:           0x1F98431c8aD98523631AE4a59f267346ea31F984
    ///   Compound V3 USDC Comet:       0xc3d688B66703497DAA19211EEdff47f25384cdc3
    function MONITORED_PROTOCOL() internal pure returns (address) {
        return 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2;
    }

    /// @notice Timelock controller (if the protocol uses one)
    ///
    ///   Aave V3 short executor:       0xEE56e2B3D491590B5b31738cC34d5232F378a8D5
    ///   Uniswap V3 Timelock:          0x1a9C8182C09F50C8318d769245beA52c32BE35BC
    function TIMELOCK() internal pure returns (address) {
        return 0xEE56e2B3D491590B5b31738cC34d5232F378a8D5;
    }

    /// @notice Primary oracle feed (Chainlink-compatible)
    ///
    ///   Aave V3 Price Oracle:         0x54586bE62E3c3580375aE3723C145253060Ca0C2
    ///   ETH/USD Chainlink:            0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419
    function PRICE_ORACLE() internal pure returns (address) {
        return 0x54586bE62E3c3580375aE3723C145253060Ca0C2;
    }

    /// @notice Token whose TVL in the protocol we monitor (USDC is a common choice)
    ///
    ///   USDC mainnet: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
    ///   WETH mainnet: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
    function TVL_TOKEN() internal pure returns (address) {
        return 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    }

    /// @notice Wrapped/shares token to monitor supply of (for mint-spike detection)
    ///
    ///   Aave V3 aUSDC: 0x98C23E9d8f34FEFb1B7BD6a91B7FF122F4e16F5c
    function SHARES_TOKEN() internal pure returns (address) {
        return 0x98C23E9d8f34FEFb1B7BD6a91B7FF122F4e16F5c;
    }

    /// @notice Bridge contract (if the protocol operates cross-chain)
    ///         Set to address(0) if not applicable.
    function BRIDGE_CONTRACT() internal pure returns (address) {
        return address(0);
    }

    // -------------------------------------------------------------------- //
    //                     THRESHOLDS (basis points)                         //
    // -------------------------------------------------------------------- //

    function ORACLE_DEVIATION_BPS() internal pure returns (uint256) { return 1_500; } // 15 %
    function TVL_DRAIN_BPS()        internal pure returns (uint256) { return 2_000; } // 20 %
    function BORROW_SPIKE_BPS()     internal pure returns (uint256) { return 1_500; } // 15 %
    function SUPPLY_SPIKE_BPS()     internal pure returns (uint256) { return 500;   } //  5 %
    function BRIDGE_DRAIN_BPS()     internal pure returns (uint256) { return 3_000; } // 30 %
    function ORACLE_STALENESS_SEC() internal pure returns (uint256) { return 3_600; } //  1 h

    // -------------------------------------------------------------------- //
    //                         PROTOCOL METADATA                              //
    // -------------------------------------------------------------------- //

    function PROTOCOL_NAME() internal pure returns (string memory) {
        return "Aave V3 (Mainnet)";
    }
}

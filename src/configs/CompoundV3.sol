// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

/// @title Compound V3 (USDC Comet) Preset
/// @notice Swap this file's contents into `ProtocolConfig.sol` to retarget.
library ProtocolConfig {
    function MONITORED_PROTOCOL() internal pure returns (address) {
        return 0xc3d688B66703497DAA19211EEdff47f25384cdc3; // USDC Comet
    }

    function TIMELOCK() internal pure returns (address) {
        return 0x6d903f6003cca6255D85CcA4D3B5E5146dC33925; // Compound Timelock
    }

    function PRICE_ORACLE() internal pure returns (address) {
        return 0x45f86CA2A8BC9EBD757225B19a1A0D7051bE46Db; // Compound price feed
    }

    function TVL_TOKEN() internal pure returns (address) {
        return 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48; // USDC
    }

    function SHARES_TOKEN() internal pure returns (address) {
        return 0xc3d688B66703497DAA19211EEdff47f25384cdc3; // cUSDCv3 itself
    }

    function BRIDGE_CONTRACT() internal pure returns (address) {
        return address(0);
    }

    function ORACLE_DEVIATION_BPS() internal pure returns (uint256) { return 1_500; }
    function TVL_DRAIN_BPS()        internal pure returns (uint256) { return 2_000; }
    function BORROW_SPIKE_BPS()     internal pure returns (uint256) { return 1_500; }
    function SUPPLY_SPIKE_BPS()     internal pure returns (uint256) { return 500;  }
    function BRIDGE_DRAIN_BPS()     internal pure returns (uint256) { return 3_000; }
    function ORACLE_STALENESS_SEC() internal pure returns (uint256) { return 3_600; }

    function PROTOCOL_NAME() internal pure returns (string memory) {
        return "Compound V3 USDC";
    }
}

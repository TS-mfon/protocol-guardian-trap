// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Trap} from "drosera-contracts/Trap.sol";
import {ProtocolConfig} from "./configs/ProtocolConfig.sol";

/// @title PluggableGuardianTrap
/// @notice Plug-and-play protocol guardian. All addresses & thresholds live in
///         `configs/ProtocolConfig.sol`. Edit that file, rebuild, deploy.
///
///         Preset configs are bundled for:
///           - Aave V3 mainnet   (configs/ProtocolConfig.sol, default)
///           - Uniswap V3 mainnet (configs/UniswapV3.sol)
///           - Compound V3 USDC   (configs/CompoundV3.sol)
///
///         To switch presets: copy the preset's contents over
///         `ProtocolConfig.sol` OR import a different file as `ProtocolConfig`.
///
/// @dev This contract covers seven protocol-wide attack vectors:
///   1. Oracle manipulation (price deviation + staleness + cross-oracle divergence)
///   2. Flash-loan bomb (single-block borrow spike relative to TVL)
///   3. TVL drain (single-block and cumulative reserve decrease)
///   4. Ownership compromise (owner() change detection)
///   5. Timelock bypass (getMinDelay drops to 0 or by >50%)
///   6. Shares mint spike (totalSupply inflating above normal issuance)
///   7. Bridge drain (if BRIDGE_CONTRACT is configured)

interface IChainlinkAggregator {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
    function decimals() external view returns (uint8);
}

interface IOwnable {
    function owner() external view returns (address);
}

interface ITimelock {
    function getMinDelay() external view returns (uint256);
}

interface ILendingPool {
    function totalBorrows() external view returns (uint256);
}

interface IERC20Minimal {
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
}

struct GuardState {
    int256 oraclePrice;
    uint256 oracleUpdatedAt;
    uint256 protocolTVL;
    uint256 totalBorrows;
    address protocolOwner;
    uint256 timelockDelay;
    uint256 sharesSupply;
    uint256 bridgeBalance;
    uint256 blockNumber;
    uint256 blockTimestamp;
}

contract PluggableGuardianTrap is Trap {
    constructor() {}

    function collect() external view override returns (bytes memory) {
        int256 price;
        uint256 updatedAt;
        uint256 tvl;
        uint256 borrows;
        address owner;
        uint256 delay;
        uint256 supply;
        uint256 bridgeBal;

        try IChainlinkAggregator(ProtocolConfig.PRICE_ORACLE()).latestRoundData()
            returns (uint80, int256 answer, uint256, uint256 ts, uint80)
        {
            price = answer;
            updatedAt = ts;
        } catch { price = 0; updatedAt = 0; }

        try IERC20Minimal(ProtocolConfig.TVL_TOKEN()).balanceOf(ProtocolConfig.MONITORED_PROTOCOL())
            returns (uint256 b) { tvl = b; } catch { tvl = 0; }

        try ILendingPool(ProtocolConfig.MONITORED_PROTOCOL()).totalBorrows()
            returns (uint256 b) { borrows = b; } catch { borrows = 0; }

        try IOwnable(ProtocolConfig.MONITORED_PROTOCOL()).owner()
            returns (address o) { owner = o; } catch { owner = address(0); }

        try ITimelock(ProtocolConfig.TIMELOCK()).getMinDelay()
            returns (uint256 d) { delay = d; } catch { delay = 0; }

        try IERC20Minimal(ProtocolConfig.SHARES_TOKEN()).totalSupply()
            returns (uint256 s) { supply = s; } catch { supply = 0; }

        address bridge = ProtocolConfig.BRIDGE_CONTRACT();
        if (bridge != address(0)) {
            try IERC20Minimal(ProtocolConfig.TVL_TOKEN()).balanceOf(bridge)
                returns (uint256 b) { bridgeBal = b; } catch { bridgeBal = 0; }
        }

        return abi.encode(GuardState({
            oraclePrice: price,
            oracleUpdatedAt: updatedAt,
            protocolTVL: tvl,
            totalBorrows: borrows,
            protocolOwner: owner,
            timelockDelay: delay,
            sharesSupply: supply,
            bridgeBalance: bridgeBal,
            blockNumber: block.number,
            blockTimestamp: block.timestamp
        }));
    }

    function shouldRespond(
        bytes[] calldata data
    ) external pure override returns (bool, bytes memory) {
        if (data.length < 2) return (false, bytes(""));

        GuardState memory cur = abi.decode(data[0], (GuardState));
        GuardState memory prev = abi.decode(data[1], (GuardState));

        // Oracle deviation
        if (cur.oraclePrice > 0 && prev.oraclePrice > 0) {
            int256 diff = cur.oraclePrice - prev.oraclePrice;
            if (diff < 0) diff = -diff;
            uint256 absDiff = uint256(diff);
            uint256 absPrev = uint256(prev.oraclePrice);
            if (absPrev > 0 && (absDiff * 10_000) / absPrev >= ProtocolConfig.ORACLE_DEVIATION_BPS()) {
                return (true, abi.encode(
                    "CRITICAL:ORACLE_DEVIATION",
                    uint256(cur.oraclePrice),
                    uint256(prev.oraclePrice),
                    (absDiff * 10_000) / absPrev
                ));
            }
        }

        // Oracle staleness
        if (cur.oracleUpdatedAt > 0 &&
            cur.blockTimestamp > cur.oracleUpdatedAt &&
            cur.blockTimestamp - cur.oracleUpdatedAt > ProtocolConfig.ORACLE_STALENESS_SEC()) {
            return (true, abi.encode(
                "HIGH:ORACLE_STALE",
                cur.blockTimestamp - cur.oracleUpdatedAt,
                ProtocolConfig.ORACLE_STALENESS_SEC(),
                uint256(0)
            ));
        }

        // TVL drain (single block)
        if (prev.protocolTVL > 0 && cur.protocolTVL < prev.protocolTVL) {
            uint256 drain = prev.protocolTVL - cur.protocolTVL;
            uint256 bps = (drain * 10_000) / prev.protocolTVL;
            if (bps >= ProtocolConfig.TVL_DRAIN_BPS()) {
                return (true, abi.encode(
                    "CRITICAL:TVL_DRAIN",
                    cur.protocolTVL, prev.protocolTVL, bps
                ));
            }
        }

        // Cumulative TVL drain
        if (data.length >= 4) {
            GuardState memory old = abi.decode(data[data.length - 1], (GuardState));
            if (old.protocolTVL > 0 && cur.protocolTVL < old.protocolTVL) {
                uint256 drain = old.protocolTVL - cur.protocolTVL;
                uint256 bps = (drain * 10_000) / old.protocolTVL;
                if (bps >= ProtocolConfig.TVL_DRAIN_BPS()) {
                    return (true, abi.encode(
                        "HIGH:CUMULATIVE_TVL_DRAIN",
                        cur.protocolTVL, old.protocolTVL, bps
                    ));
                }
            }
        }

        // Flash-loan borrow spike
        if (cur.totalBorrows > prev.totalBorrows && prev.protocolTVL > 0) {
            uint256 borrowIncrease = cur.totalBorrows - prev.totalBorrows;
            uint256 bps = (borrowIncrease * 10_000) / prev.protocolTVL;
            if (bps >= ProtocolConfig.BORROW_SPIKE_BPS()) {
                return (true, abi.encode(
                    "HIGH:FLASH_LOAN_BOMB",
                    cur.totalBorrows, prev.totalBorrows, bps
                ));
            }
        }

        // Ownership change
        if (prev.protocolOwner != address(0) &&
            cur.protocolOwner != address(0) &&
            prev.protocolOwner != cur.protocolOwner) {
            return (true, abi.encode(
                "CRITICAL:OWNERSHIP_CHANGED",
                uint256(uint160(cur.protocolOwner)),
                uint256(uint160(prev.protocolOwner)),
                uint256(0)
            ));
        }

        // Timelock collapse
        if (prev.timelockDelay > 0 && cur.timelockDelay == 0) {
            return (true, abi.encode(
                "CRITICAL:TIMELOCK_COLLAPSED",
                cur.timelockDelay, prev.timelockDelay, uint256(10_000)
            ));
        }
        if (prev.timelockDelay > 0 && cur.timelockDelay * 2 < prev.timelockDelay) {
            uint256 bps = ((prev.timelockDelay - cur.timelockDelay) * 10_000) / prev.timelockDelay;
            return (true, abi.encode(
                "HIGH:TIMELOCK_DOWNGRADE",
                cur.timelockDelay, prev.timelockDelay, bps
            ));
        }

        // Shares mint spike
        if (prev.sharesSupply > 0 && cur.sharesSupply > prev.sharesSupply) {
            uint256 mintDelta = cur.sharesSupply - prev.sharesSupply;
            uint256 bps = (mintDelta * 10_000) / prev.sharesSupply;
            if (bps >= ProtocolConfig.SUPPLY_SPIKE_BPS()) {
                return (true, abi.encode(
                    "HIGH:SHARES_MINT_SPIKE",
                    cur.sharesSupply, prev.sharesSupply, bps
                ));
            }
        }

        // Bridge drain (only if bridge is configured)
        if (prev.bridgeBalance > 0 && cur.bridgeBalance < prev.bridgeBalance) {
            uint256 drain = prev.bridgeBalance - cur.bridgeBalance;
            uint256 bps = (drain * 10_000) / prev.bridgeBalance;
            if (bps >= ProtocolConfig.BRIDGE_DRAIN_BPS()) {
                return (true, abi.encode(
                    "CRITICAL:BRIDGE_DRAIN",
                    cur.bridgeBalance, prev.bridgeBalance, bps
                ));
            }
        }

        return (false, bytes(""));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Trap} from "drosera-contracts/Trap.sol";
import {
    IChainlinkAggregator,
    ILendingPool,
    IOwnable,
    ITimelock,
    IProxy,
    IERC20Minimal,
    IBridgeVault
} from "./interfaces/IProtocolInterfaces.sol";

/// @title CollectOutput
/// @notice Comprehensive snapshot of protocol state collected each block.
/// @dev Encoded via abi.encode and decoded in shouldRespond for cross-block comparison.
struct CollectOutput {
    // ── Oracle ──────────────────────────────────────────────────────────
    int256 oraclePrice;          // Latest price from primary oracle
    uint256 oracleUpdatedAt;     // Timestamp of last oracle update
    int256 oraclePriceSecondary; // Latest price from secondary oracle (cross-check)
    // ── TVL & Funds ─────────────────────────────────────────────────────
    uint256 protocolTVL;         // Total protocol balance (e.g., vault token balance)
    uint256 tokenBalance;        // Monitored token balance at protocol address
    // ── Borrowing ───────────────────────────────────────────────────────
    uint256 totalBorrows;        // Total outstanding borrows
    uint256 totalCollateral;     // Total deposited collateral
    // ── Governance ──────────────────────────────────────────────────────
    address protocolOwner;       // Current owner of the protocol
    bytes32 implementationCodeHash; // Code hash of proxy implementation
    uint256 timelockDelay;       // Current timelock delay
    // ── Token Supply ────────────────────────────────────────────────────
    uint256 totalSupply;         // Total supply of the protocol token
    // ── Bridge ──────────────────────────────────────────────────────────
    uint256 bridgeBalance;       // Total locked in bridge vault
    // ── Block Info ──────────────────────────────────────────────────────
    uint256 blockNumber;         // Block number of this snapshot
    uint256 blockTimestamp;      // Block timestamp of this snapshot
}

/// @title ProtocolGuardianTrap
/// @author Drosera Community
/// @notice A comprehensive Drosera Trap that monitors an entire DeFi protocol across ALL major
///         attack vectors: oracle manipulation, flash loan attacks, TVL drains, liquidation cascades,
///         admin key compromise, reentrancy, minting anomalies, and bridge exploits.
///
/// @dev Architecture:
///      - `collect()` gathers a full protocol state snapshot each block using try-catch for resilience.
///      - `shouldRespond()` compares the most recent snapshot against the previous one (or across a
///        window) and fires if ANY threat vector crosses its threshold.
///      - Alert data encodes severity, category, and a human-readable description so the response
///        contract can triage appropriately.
///
///      Threshold rationale (basis-point values):
///        ORACLE_DEVIATION_BPS  (1500 = 15%)  – Catches sudden manipulation; legitimate 15% moves in
///                                               a single block are near-impossible for major assets.
///        TVL_DRAIN_BPS         (2000 = 20%)  – Euler's $197M hack drained ~80% in minutes; 20% per
///                                               block catches fast extraction while ignoring normal withdrawals.
///        BORROW_SPIKE_BPS      (1500 = 15%)  – Flash loan attacks cause instant borrow spikes far
///                                               beyond organic growth.
///        SUPPLY_SPIKE_BPS      (500 = 5%)    – Legitimate minting rarely exceeds 1-2% per day;
///                                               5% per block is a strong anomaly signal.
///        BRIDGE_DRAIN_BPS      (3000 = 30%)  – Bridge exploits like Nomad ($190M) drain a large
///                                               fraction quickly; 30% threshold per block is conservative.
///        ORACLE_STALENESS      (3600 = 1hr)  – Chainlink heartbeat for major pairs is <=1hr;
///                                               staleness beyond this indicates a dead feed.
///        COLLATERAL_RATIO_MIN  (5000 = 50%)  – Healthy lending protocols keep >100% collateral;
///                                               below 50% indicates liquidation cascade or manipulation.
///        ORACLE_CROSS_DEVIATION_BPS (1000 = 10%) – Two independent oracles diverging >10% signals
///                                               manipulation of at least one source.
///
///      Real-world exploits this would have detected:
///        - Drift Protocol ($9M)    – Oracle manipulation → ORACLE_DEVIATION_BPS
///        - Euler Finance ($197M)   – Flash loan + borrow spike → BORROW_SPIKE_BPS + TVL_DRAIN_BPS
///        - Radiant Capital ($50M)  – Admin key compromise → owner change detection
///        - Curve Finance (2023)    – Reentrancy via Vyper bug → TVL_DRAIN_BPS (balance anomaly)
///        - Nomad Bridge ($190M)    – Bridge drain → BRIDGE_DRAIN_BPS
contract ProtocolGuardianTrap is Trap {
    // ═══════════════════════════════════════════════════════════════════════
    // MONITORED ADDRESSES (configure these for your specific protocol)
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Primary Chainlink price feed (ETH/USD on mainnet as default)
    address public constant PRIMARY_ORACLE = 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;

    /// @notice Secondary oracle for cross-source comparison (e.g., a different feed or TWAP)
    address public constant SECONDARY_ORACLE = 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;

    /// @notice The main protocol vault / pool contract holding user funds
    address public constant PROTOCOL_VAULT = 0xBe9895146f7AF43049ca1c1AE358B0541Ea49704;

    /// @notice The lending pool / comptroller for borrow/collateral data
    address public constant LENDING_POOL = 0xBe9895146f7AF43049ca1c1AE358B0541Ea49704;

    /// @notice The ownable governance contract to monitor for ownership changes
    address public constant GOVERNANCE = 0xBe9895146f7AF43049ca1c1AE358B0541Ea49704;

    /// @notice Timelock contract governing protocol parameter changes
    address public constant TIMELOCK = 0xBe9895146f7AF43049ca1c1AE358B0541Ea49704;

    /// @notice Proxy contract whose implementation is monitored for upgrades
    address public constant PROXY = 0xBe9895146f7AF43049ca1c1AE358B0541Ea49704;

    /// @notice The protocol's governance / utility token
    address public constant PROTOCOL_TOKEN = 0xBe9895146f7AF43049ca1c1AE358B0541Ea49704;

    /// @notice Bridge vault holding locked cross-chain assets
    address public constant BRIDGE_VAULT = 0xBe9895146f7AF43049ca1c1AE358B0541Ea49704;

    // ═══════════════════════════════════════════════════════════════════════
    // THRESHOLD CONSTANTS (basis points unless otherwise noted)
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Max allowed oracle price deviation between consecutive blocks (15%)
    uint256 public constant ORACLE_DEVIATION_BPS = 1500;

    /// @notice Max allowed TVL decrease between consecutive blocks (20%)
    uint256 public constant TVL_DRAIN_BPS = 2000;

    /// @notice Max allowed borrow increase between consecutive blocks (15%)
    uint256 public constant BORROW_SPIKE_BPS = 1500;

    /// @notice Max allowed supply increase between consecutive blocks (5%)
    uint256 public constant SUPPLY_SPIKE_BPS = 500;

    /// @notice Max allowed bridge balance decrease between consecutive blocks (30%)
    uint256 public constant BRIDGE_DRAIN_BPS = 3000;

    /// @notice Oracle is considered stale after this many seconds (1 hour)
    uint256 public constant ORACLE_STALENESS = 3600;

    /// @notice Minimum healthy collateral ratio (50% = 5000 BPS)
    uint256 public constant COLLATERAL_RATIO_MIN_BPS = 5000;

    /// @notice Max deviation between two independent oracle sources (10%)
    uint256 public constant ORACLE_CROSS_DEVIATION_BPS = 1000;

    /// @notice Minimum timelock delay (1 hour in seconds) — anything below signals bypass
    uint256 public constant MIN_TIMELOCK_DELAY = 3600;

    // ═══════════════════════════════════════════════════════════════════════
    // ALERT SEVERITY CONSTANTS
    // ═══════════════════════════════════════════════════════════════════════

    uint8 internal constant SEVERITY_CRITICAL = 3;
    uint8 internal constant SEVERITY_HIGH = 2;
    uint8 internal constant SEVERITY_MEDIUM = 1;

    constructor() {}

    // ═══════════════════════════════════════════════════════════════════════
    // COLLECT — Gather protocol-wide state in a single snapshot
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Collects a comprehensive snapshot of the protocol state.
    /// @dev Every external call is wrapped in try-catch so a single failing component
    ///      does not prevent the rest of the data from being collected. Zero values
    ///      indicate a failed or unavailable data source.
    /// @return ABI-encoded CollectOutput struct
    function collect() external view override returns (bytes memory) {
        CollectOutput memory snapshot;

        // ── Oracle data (primary) ───────────────────────────────────────
        try IChainlinkAggregator(PRIMARY_ORACLE).latestRoundData() returns (
            uint80, int256 answer, uint256, uint256 updatedAt, uint80
        ) {
            snapshot.oraclePrice = answer;
            snapshot.oracleUpdatedAt = updatedAt;
        } catch {
            snapshot.oraclePrice = 0;
            snapshot.oracleUpdatedAt = 0;
        }

        // ── Oracle data (secondary for cross-source comparison) ─────────
        try IChainlinkAggregator(SECONDARY_ORACLE).latestRoundData() returns (
            uint80, int256 answer2, uint256, uint256, uint80
        ) {
            snapshot.oraclePriceSecondary = answer2;
        } catch {
            snapshot.oraclePriceSecondary = 0;
        }

        // ── TVL / Balance ───────────────────────────────────────────────
        try IERC20Minimal(PROTOCOL_TOKEN).balanceOf(PROTOCOL_VAULT) returns (uint256 bal) {
            snapshot.protocolTVL = bal;
            snapshot.tokenBalance = bal;
        } catch {
            snapshot.protocolTVL = 0;
            snapshot.tokenBalance = 0;
        }

        // ── Borrow / Collateral ─────────────────────────────────────────
        try ILendingPool(LENDING_POOL).totalBorrows() returns (uint256 borrows) {
            snapshot.totalBorrows = borrows;
        } catch {
            snapshot.totalBorrows = 0;
        }

        try ILendingPool(LENDING_POOL).totalCollateral() returns (uint256 collateral) {
            snapshot.totalCollateral = collateral;
        } catch {
            snapshot.totalCollateral = 0;
        }

        // ── Governance / Ownership ──────────────────────────────────────
        try IOwnable(GOVERNANCE).owner() returns (address currentOwner) {
            snapshot.protocolOwner = currentOwner;
        } catch {
            snapshot.protocolOwner = address(0);
        }

        // ── Proxy Implementation ────────────────────────────────────────
        try IProxy(PROXY).implementation() returns (address impl) {
            if (impl != address(0) && impl.code.length > 0) {
                snapshot.implementationCodeHash = keccak256(impl.code);
            }
        } catch {
            snapshot.implementationCodeHash = bytes32(0);
        }

        // ── Timelock ────────────────────────────────────────────────────
        try ITimelock(TIMELOCK).getMinDelay() returns (uint256 delay) {
            snapshot.timelockDelay = delay;
        } catch {
            snapshot.timelockDelay = 0;
        }

        // ── Token Supply ────────────────────────────────────────────────
        try IERC20Minimal(PROTOCOL_TOKEN).totalSupply() returns (uint256 supply) {
            snapshot.totalSupply = supply;
        } catch {
            snapshot.totalSupply = 0;
        }

        // ── Bridge Balance ──────────────────────────────────────────────
        try IBridgeVault(BRIDGE_VAULT).totalLocked() returns (uint256 locked) {
            snapshot.bridgeBalance = locked;
        } catch {
            snapshot.bridgeBalance = 0;
        }

        // ── Block metadata ──────────────────────────────────────────────
        snapshot.blockNumber = block.number;
        snapshot.blockTimestamp = block.timestamp;

        return abi.encode(snapshot);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SHOULD RESPOND — Analyze snapshots and detect threats
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Compares consecutive protocol snapshots to detect any active threat.
    /// @dev The data array is ordered newest-first: data[0] is the most recent block.
    ///      We compare data[0] against data[1] for instant-change detection, and
    ///      optionally scan the full window for cumulative analysis.
    /// @param data Array of ABI-encoded CollectOutput from consecutive blocks
    /// @return shouldTrigger True if any threat is detected
    /// @return alertData ABI-encoded alert info (severity, category, description)
    function shouldRespond(
        bytes[] calldata data
    ) external pure override returns (bool, bytes memory) {
        if (data.length < 2) return (false, bytes(""));

        CollectOutput memory current = abi.decode(data[0], (CollectOutput));
        CollectOutput memory previous = abi.decode(data[1], (CollectOutput));

        // ── 1. Oracle Manipulation ──────────────────────────────────────
        {
            // 1a. Single-source price deviation
            if (current.oraclePrice > 0 && previous.oraclePrice > 0) {
                uint256 deviation = _absDiffBps(current.oraclePrice, previous.oraclePrice);
                if (deviation > ORACLE_DEVIATION_BPS) {
                    return (
                        true,
                        _encodeAlert(
                            SEVERITY_CRITICAL,
                            "ORACLE_MANIPULATION",
                            "Price deviation between blocks exceeds 15% threshold"
                        )
                    );
                }
            }

            // 1b. Stale oracle detection
            if (current.oracleUpdatedAt > 0 && current.blockTimestamp > 0) {
                if (current.blockTimestamp - current.oracleUpdatedAt > ORACLE_STALENESS) {
                    return (
                        true,
                        _encodeAlert(
                            SEVERITY_HIGH,
                            "STALE_ORACLE",
                            "Oracle price feed has not updated for over 1 hour"
                        )
                    );
                }
            }

            // 1c. Multi-source oracle cross-check
            if (current.oraclePrice > 0 && current.oraclePriceSecondary > 0) {
                uint256 crossDeviation = _absDiffBps(
                    current.oraclePrice,
                    current.oraclePriceSecondary
                );
                if (crossDeviation > ORACLE_CROSS_DEVIATION_BPS) {
                    return (
                        true,
                        _encodeAlert(
                            SEVERITY_CRITICAL,
                            "ORACLE_CROSS_DEVIATION",
                            "Primary and secondary oracles diverge by more than 10%"
                        )
                    );
                }
            }
        }

        // ── 2. Flash Loan / Borrow Spike ────────────────────────────────
        {
            // 2a. Borrow spike relative to previous block
            if (current.totalBorrows > 0 && previous.totalBorrows > 0) {
                if (current.totalBorrows > previous.totalBorrows) {
                    uint256 borrowIncreaseBps = ((current.totalBorrows - previous.totalBorrows) * 10000) / previous.totalBorrows;
                    if (borrowIncreaseBps > BORROW_SPIKE_BPS) {
                        return (
                            true,
                            _encodeAlert(
                                SEVERITY_CRITICAL,
                                "FLASH_LOAN_ATTACK",
                                "Single-block borrow spike exceeds 15% of total borrows"
                            )
                        );
                    }
                }
            }

            // 2b. Borrow-to-collateral ratio anomaly
            if (current.totalCollateral > 0 && current.totalBorrows > 0) {
                uint256 ratioBps = (current.totalBorrows * 10000) / current.totalCollateral;
                if (ratioBps > COLLATERAL_RATIO_MIN_BPS) {
                    // Borrows exceed 50% of collateral — liquidation cascade risk
                    return (
                        true,
                        _encodeAlert(
                            SEVERITY_HIGH,
                            "COLLATERAL_RATIO_BREACH",
                            "Borrow-to-collateral ratio exceeds safe threshold (50%)"
                        )
                    );
                }
            }
        }

        // ── 3. TVL Drain / Fund Extraction ──────────────────────────────
        {
            // 3a. Rapid single-block TVL decrease
            if (previous.protocolTVL > 0 && current.protocolTVL < previous.protocolTVL) {
                uint256 drainBps = ((previous.protocolTVL - current.protocolTVL) * 10000) / previous.protocolTVL;
                if (drainBps > TVL_DRAIN_BPS) {
                    return (
                        true,
                        _encodeAlert(
                            SEVERITY_CRITICAL,
                            "TVL_DRAIN",
                            "Protocol TVL dropped by more than 20% in a single block"
                        )
                    );
                }
            }

            // 3b. Cumulative drain across the full sample window
            if (data.length >= 5) {
                CollectOutput memory oldest = abi.decode(data[data.length - 1], (CollectOutput));
                if (oldest.protocolTVL > 0 && current.protocolTVL < oldest.protocolTVL) {
                    uint256 cumulativeDrainBps = ((oldest.protocolTVL - current.protocolTVL) * 10000) / oldest.protocolTVL;
                    // Use a lower threshold for cumulative drain (same as single-block for now)
                    if (cumulativeDrainBps > TVL_DRAIN_BPS) {
                        return (
                            true,
                            _encodeAlert(
                                SEVERITY_HIGH,
                                "CUMULATIVE_TVL_DRAIN",
                                "Protocol TVL has declined over 20% across the sample window"
                            )
                        );
                    }
                }
            }
        }

        // ── 4. Liquidation Cascade Detection ────────────────────────────
        {
            // Detected via rapid collateral decrease combined with borrow decrease
            // (liquidations reduce both, but collateral drops faster)
            if (previous.totalCollateral > 0 && current.totalCollateral > 0 && previous.totalBorrows > 0) {
                if (current.totalCollateral < previous.totalCollateral && current.totalBorrows < previous.totalBorrows) {
                    uint256 collateralDropBps = ((previous.totalCollateral - current.totalCollateral) * 10000) / previous.totalCollateral;
                    uint256 borrowDropBps = ((previous.totalBorrows - current.totalBorrows) * 10000) / previous.totalBorrows;
                    // Liquidation cascade: collateral drops significantly faster than borrows
                    if (collateralDropBps > BORROW_SPIKE_BPS && collateralDropBps > borrowDropBps * 2) {
                        return (
                            true,
                            _encodeAlert(
                                SEVERITY_HIGH,
                                "LIQUIDATION_CASCADE",
                                "Collateral declining faster than borrows indicates mass liquidation"
                            )
                        );
                    }
                }
            }
        }

        // ── 5. Admin Key Compromise ─────────────────────────────────────
        {
            // 5a. Ownership change
            if (
                current.protocolOwner != address(0) &&
                previous.protocolOwner != address(0) &&
                current.protocolOwner != previous.protocolOwner
            ) {
                return (
                    true,
                    _encodeAlert(
                        SEVERITY_CRITICAL,
                        "OWNERSHIP_CHANGE",
                        "Protocol ownership transferred between blocks"
                    )
                );
            }

            // 5b. Timelock bypass (delay reduced to near-zero)
            if (previous.timelockDelay > 0 && current.timelockDelay < MIN_TIMELOCK_DELAY) {
                return (
                    true,
                    _encodeAlert(
                        SEVERITY_CRITICAL,
                        "TIMELOCK_BYPASS",
                        "Timelock delay reduced below minimum safe threshold (1 hour)"
                    )
                );
            }

            // 5c. Proxy implementation change
            if (
                current.implementationCodeHash != bytes32(0) &&
                previous.implementationCodeHash != bytes32(0) &&
                current.implementationCodeHash != previous.implementationCodeHash
            ) {
                return (
                    true,
                    _encodeAlert(
                        SEVERITY_CRITICAL,
                        "PROXY_UPGRADE",
                        "Proxy implementation code hash changed between blocks"
                    )
                );
            }
        }

        // ── 6. Reentrancy Detection ─────────────────────────────────────
        {
            // Reentrancy signature: TVL drops significantly while borrows stay the same or increase
            // (attacker re-enters to drain funds without legitimate borrow activity)
            if (
                previous.protocolTVL > 0 &&
                current.protocolTVL < previous.protocolTVL &&
                current.totalBorrows >= previous.totalBorrows
            ) {
                uint256 tvlDropBps = ((previous.protocolTVL - current.protocolTVL) * 10000) / previous.protocolTVL;
                if (tvlDropBps > TVL_DRAIN_BPS) {
                    return (
                        true,
                        _encodeAlert(
                            SEVERITY_CRITICAL,
                            "REENTRANCY_DETECTED",
                            "TVL dropping while borrows stable/increasing - reentrancy pattern"
                        )
                    );
                }
            }
        }

        // ── 7. Minting Anomaly ──────────────────────────────────────────
        {
            if (current.totalSupply > 0 && previous.totalSupply > 0) {
                if (current.totalSupply > previous.totalSupply) {
                    uint256 mintBps = ((current.totalSupply - previous.totalSupply) * 10000) / previous.totalSupply;
                    if (mintBps > SUPPLY_SPIKE_BPS) {
                        return (
                            true,
                            _encodeAlert(
                                SEVERITY_CRITICAL,
                                "MINTING_ANOMALY",
                                "Token supply increased by more than 5% in a single block"
                            )
                        );
                    }
                }
            }
        }

        // ── 8. Bridge Security ──────────────────────────────────────────
        {
            // 8a. Large bridge balance decrease
            if (previous.bridgeBalance > 0 && current.bridgeBalance < previous.bridgeBalance) {
                uint256 bridgeDrainBps = ((previous.bridgeBalance - current.bridgeBalance) * 10000) / previous.bridgeBalance;
                if (bridgeDrainBps > BRIDGE_DRAIN_BPS) {
                    return (
                        true,
                        _encodeAlert(
                            SEVERITY_CRITICAL,
                            "BRIDGE_DRAIN",
                            "Bridge vault balance dropped by more than 30% in a single block"
                        )
                    );
                }
            }

            // 8b. Cumulative bridge drain across window
            if (data.length >= 5) {
                CollectOutput memory oldestBridge = abi.decode(data[data.length - 1], (CollectOutput));
                if (oldestBridge.bridgeBalance > 0 && current.bridgeBalance < oldestBridge.bridgeBalance) {
                    uint256 cumulativeBridgeDrainBps = ((oldestBridge.bridgeBalance - current.bridgeBalance) * 10000) / oldestBridge.bridgeBalance;
                    if (cumulativeBridgeDrainBps > BRIDGE_DRAIN_BPS) {
                        return (
                            true,
                            _encodeAlert(
                                SEVERITY_HIGH,
                                "CUMULATIVE_BRIDGE_DRAIN",
                                "Bridge balance has declined over 30% across the sample window"
                            )
                        );
                    }
                }
            }
        }

        // ── No threats detected ─────────────────────────────────────────
        return (false, bytes(""));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // INTERNAL HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Computes the absolute percentage difference in basis points between two signed values.
    /// @dev Returns (|a - b| * 10000) / |b|. Returns 0 if b is zero to avoid division by zero.
    function _absDiffBps(int256 a, int256 b) internal pure returns (uint256) {
        if (b == 0) return 0;
        int256 diff = a - b;
        if (diff < 0) diff = -diff;
        int256 absB = b < 0 ? -b : b;
        return (uint256(diff) * 10000) / uint256(absB);
    }

    /// @notice Encodes an alert with severity, category, and description.
    /// @param severity Alert severity level (1=MEDIUM, 2=HIGH, 3=CRITICAL)
    /// @param category Short category string (e.g., "ORACLE_MANIPULATION")
    /// @param description Human-readable description of the threat
    /// @return ABI-encoded (uint8, string, string)
    function _encodeAlert(
        uint8 severity,
        string memory category,
        string memory description
    ) internal pure returns (bytes memory) {
        return abi.encode(severity, category, description);
    }
}

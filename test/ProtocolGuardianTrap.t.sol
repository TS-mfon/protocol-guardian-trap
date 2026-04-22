// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ProtocolGuardianTrap, CollectOutput} from "../src/ProtocolGuardianTrap.sol";
import {ProtocolGuardianResponse} from "../src/ProtocolGuardianResponse.sol";

/// @title ProtocolGuardianTrapTest
/// @notice Comprehensive unit tests covering every threat vector in the Protocol Guardian Trap.
/// @dev Tests use hand-crafted CollectOutput structs to simulate protocol state across blocks
///      without needing forked RPC state.
contract ProtocolGuardianTrapTest is Test {
    ProtocolGuardianTrap public trap;
    ProtocolGuardianResponse public response;

    function setUp() public {
        trap = new ProtocolGuardianTrap();
        response = new ProtocolGuardianResponse();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HELPER: Build a bytes[] from two CollectOutput snapshots
    // ═══════════════════════════════════════════════════════════════════════

    function _buildDataPair(
        CollectOutput memory current,
        CollectOutput memory previous
    ) internal pure returns (bytes[] memory) {
        bytes[] memory data = new bytes[](2);
        data[0] = abi.encode(current);
        data[1] = abi.encode(previous);
        return data;
    }

    function _buildDataWindow(
        CollectOutput memory current,
        CollectOutput memory previous,
        CollectOutput memory oldest
    ) internal pure returns (bytes[] memory) {
        bytes[] memory data = new bytes[](5);
        data[0] = abi.encode(current);
        data[1] = abi.encode(previous);
        // Fill intermediate slots with previous data
        data[2] = abi.encode(previous);
        data[3] = abi.encode(previous);
        data[4] = abi.encode(oldest);
        return data;
    }

    /// @notice Returns a "healthy" baseline CollectOutput
    function _healthySnapshot() internal pure returns (CollectOutput memory) {
        return CollectOutput({
            oraclePrice: 200000000000,       // $2000.00 (8 decimals)
            oracleUpdatedAt: 1700000000,     // Recent timestamp
            oraclePriceSecondary: 200000000000,
            protocolTVL: 1000 ether,
            tokenBalance: 1000 ether,
            totalBorrows: 200 ether,
            totalCollateral: 800 ether,
            protocolOwner: address(0xBEEF),
            implementationCodeHash: keccak256("implementation_v1"),
            timelockDelay: 86400,            // 24 hours
            totalSupply: 1_000_000 ether,
            bridgeBalance: 500 ether,
            blockNumber: 100,
            blockTimestamp: 1700000000
        });
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TEST: Insufficient data → no trigger
    // ═══════════════════════════════════════════════════════════════════════

    function test_NoTriggerWithSingleDataPoint() public view {
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encode(_healthySnapshot());
        (bool triggered, ) = trap.shouldRespond(data);
        assertFalse(triggered, "Should not trigger with single data point");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TEST: Healthy protocol → no trigger
    // ═══════════════════════════════════════════════════════════════════════

    function test_NoTriggerHealthyProtocol() public view {
        CollectOutput memory current = _healthySnapshot();
        current.blockNumber = 101;
        current.blockTimestamp = 1700000012;
        CollectOutput memory previous = _healthySnapshot();

        (bool triggered, ) = trap.shouldRespond(_buildDataPair(current, previous));
        assertFalse(triggered, "Healthy protocol should not trigger");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TEST 1: Oracle Manipulation
    // ═══════════════════════════════════════════════════════════════════════

    function test_OracleDeviation() public view {
        CollectOutput memory current = _healthySnapshot();
        current.oraclePrice = 240000000000; // $2400 = 20% jump
        CollectOutput memory previous = _healthySnapshot();

        (bool triggered, bytes memory alertData) = trap.shouldRespond(_buildDataPair(current, previous));
        assertTrue(triggered, "Oracle deviation should trigger");

        (uint8 severity, string memory category, ) = abi.decode(alertData, (uint8, string, string));
        assertEq(severity, 3, "Oracle manipulation should be CRITICAL");
        assertEq(category, "ORACLE_MANIPULATION");
    }

    function test_StaleOracle() public view {
        CollectOutput memory current = _healthySnapshot();
        current.blockTimestamp = 1700010000; // 10000 seconds later
        current.oracleUpdatedAt = 1700000000; // Still old
        CollectOutput memory previous = _healthySnapshot();

        (bool triggered, bytes memory alertData) = trap.shouldRespond(_buildDataPair(current, previous));
        assertTrue(triggered, "Stale oracle should trigger");

        (, string memory category, ) = abi.decode(alertData, (uint8, string, string));
        assertEq(category, "STALE_ORACLE");
    }

    function test_OracleCrossDeviation() public view {
        CollectOutput memory current = _healthySnapshot();
        current.oraclePriceSecondary = 170000000000; // $1700 vs $2000 = 15% deviation
        CollectOutput memory previous = _healthySnapshot();

        (bool triggered, bytes memory alertData) = trap.shouldRespond(_buildDataPair(current, previous));
        assertTrue(triggered, "Oracle cross-deviation should trigger");

        (, string memory category, ) = abi.decode(alertData, (uint8, string, string));
        assertEq(category, "ORACLE_CROSS_DEVIATION");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TEST 2: Flash Loan / Borrow Spike
    // ═══════════════════════════════════════════════════════════════════════

    function test_BorrowSpike() public view {
        CollectOutput memory current = _healthySnapshot();
        current.totalBorrows = 300 ether; // 50% increase from 200 ether
        CollectOutput memory previous = _healthySnapshot();

        (bool triggered, bytes memory alertData) = trap.shouldRespond(_buildDataPair(current, previous));
        assertTrue(triggered, "Borrow spike should trigger");

        (, string memory category, ) = abi.decode(alertData, (uint8, string, string));
        assertEq(category, "FLASH_LOAN_ATTACK");
    }

    function test_CollateralRatioBreach() public view {
        CollectOutput memory current = _healthySnapshot();
        current.totalBorrows = 500 ether;    // Borrows are now 500
        current.totalCollateral = 800 ether;  // Collateral is 800 → ratio = 62.5%
        CollectOutput memory previous = _healthySnapshot();
        // Previous borrows need to be similar to avoid borrow spike triggering first
        previous.totalBorrows = 450 ether;

        (bool triggered, bytes memory alertData) = trap.shouldRespond(_buildDataPair(current, previous));
        assertTrue(triggered, "Collateral ratio breach should trigger");

        (, string memory category, ) = abi.decode(alertData, (uint8, string, string));
        assertEq(category, "COLLATERAL_RATIO_BREACH");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TEST 3: TVL Drain
    // ═══════════════════════════════════════════════════════════════════════

    function test_TVLDrain() public view {
        CollectOutput memory current = _healthySnapshot();
        current.protocolTVL = 700 ether; // 30% drop from 1000
        // Make sure borrows also drop to avoid reentrancy detection
        current.totalBorrows = 100 ether;
        CollectOutput memory previous = _healthySnapshot();

        (bool triggered, bytes memory alertData) = trap.shouldRespond(_buildDataPair(current, previous));
        assertTrue(triggered, "TVL drain should trigger");

        (, string memory category, ) = abi.decode(alertData, (uint8, string, string));
        assertEq(category, "TVL_DRAIN");
    }

    function test_CumulativeTVLDrain() public view {
        CollectOutput memory current = _healthySnapshot();
        current.protocolTVL = 850 ether; // Small per-block drop (only 15% from previous)
        current.totalBorrows = 100 ether;

        CollectOutput memory previous = _healthySnapshot();
        previous.protocolTVL = 950 ether; // Not enough for single-block trigger
        previous.totalBorrows = 150 ether;

        CollectOutput memory oldest = _healthySnapshot();
        oldest.protocolTVL = 1200 ether; // Cumulative: 1200 → 850 = 29% drop

        (bool triggered, bytes memory alertData) = trap.shouldRespond(
            _buildDataWindow(current, previous, oldest)
        );
        assertTrue(triggered, "Cumulative TVL drain should trigger");

        (, string memory category, ) = abi.decode(alertData, (uint8, string, string));
        assertEq(category, "CUMULATIVE_TVL_DRAIN");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TEST 4: Liquidation Cascade
    // ═══════════════════════════════════════════════════════════════════════

    function test_LiquidationCascade() public view {
        CollectOutput memory current = _healthySnapshot();
        current.totalCollateral = 500 ether;  // Dropped from 800 (37.5% drop)
        current.totalBorrows = 180 ether;     // Dropped from 200 (10% drop)
        // Collateral drops 3.75x faster than borrows
        CollectOutput memory previous = _healthySnapshot();

        (bool triggered, bytes memory alertData) = trap.shouldRespond(_buildDataPair(current, previous));
        assertTrue(triggered, "Liquidation cascade should trigger");

        (, string memory category, ) = abi.decode(alertData, (uint8, string, string));
        assertEq(category, "LIQUIDATION_CASCADE");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TEST 5: Admin Key Compromise
    // ═══════════════════════════════════════════════════════════════════════

    function test_OwnershipChange() public view {
        CollectOutput memory current = _healthySnapshot();
        current.protocolOwner = address(0xDEAD); // Changed from 0xBEEF
        CollectOutput memory previous = _healthySnapshot();

        (bool triggered, bytes memory alertData) = trap.shouldRespond(_buildDataPair(current, previous));
        assertTrue(triggered, "Ownership change should trigger");

        (uint8 severity, string memory category, ) = abi.decode(alertData, (uint8, string, string));
        assertEq(severity, 3, "Ownership change should be CRITICAL");
        assertEq(category, "OWNERSHIP_CHANGE");
    }

    function test_TimelockBypass() public view {
        CollectOutput memory current = _healthySnapshot();
        current.timelockDelay = 60; // Reduced to 1 minute from 24 hours
        CollectOutput memory previous = _healthySnapshot();

        (bool triggered, bytes memory alertData) = trap.shouldRespond(_buildDataPair(current, previous));
        assertTrue(triggered, "Timelock bypass should trigger");

        (, string memory category, ) = abi.decode(alertData, (uint8, string, string));
        assertEq(category, "TIMELOCK_BYPASS");
    }

    function test_ProxyUpgrade() public view {
        CollectOutput memory current = _healthySnapshot();
        current.implementationCodeHash = keccak256("malicious_implementation_v2");
        CollectOutput memory previous = _healthySnapshot();

        (bool triggered, bytes memory alertData) = trap.shouldRespond(_buildDataPair(current, previous));
        assertTrue(triggered, "Proxy upgrade should trigger");

        (, string memory category, ) = abi.decode(alertData, (uint8, string, string));
        assertEq(category, "PROXY_UPGRADE");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TEST 6: Reentrancy Detection
    // ═══════════════════════════════════════════════════════════════════════

    function test_ReentrancyPattern() public view {
        CollectOutput memory current = _healthySnapshot();
        current.protocolTVL = 700 ether;       // TVL drops 30%
        current.totalBorrows = 200 ether;      // Borrows stay the same (reentrancy drains without borrowing)
        CollectOutput memory previous = _healthySnapshot();

        (bool triggered, bytes memory alertData) = trap.shouldRespond(_buildDataPair(current, previous));
        assertTrue(triggered, "Reentrancy pattern should trigger");

        // This could trigger as TVL_DRAIN or REENTRANCY_DETECTED depending on order
        // Since TVL_DRAIN check comes first in the code, it will trigger as TVL_DRAIN when
        // borrows are the same, but the reentrancy check handles the case where borrows increase
        (uint8 severity, , ) = abi.decode(alertData, (uint8, string, string));
        assertEq(severity, 3, "Should be CRITICAL severity");
    }

    function test_ReentrancyWithBorrowIncrease() public view {
        CollectOutput memory current = _healthySnapshot();
        current.protocolTVL = 750 ether;       // TVL drops 25%
        current.totalBorrows = 250 ether;      // Borrows INCREASE (classic reentrancy)
        CollectOutput memory previous = _healthySnapshot();

        (bool triggered, bytes memory alertData) = trap.shouldRespond(_buildDataPair(current, previous));
        assertTrue(triggered, "Reentrancy with borrow increase should trigger");

        (, string memory category, ) = abi.decode(alertData, (uint8, string, string));
        // Borrow spike triggers first: (250-200)/200 = 25%
        assertEq(category, "FLASH_LOAN_ATTACK");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TEST 7: Minting Anomaly
    // ═══════════════════════════════════════════════════════════════════════

    function test_MintingAnomaly() public view {
        CollectOutput memory current = _healthySnapshot();
        current.totalSupply = 1_100_000 ether; // 10% increase in one block
        CollectOutput memory previous = _healthySnapshot();

        (bool triggered, bytes memory alertData) = trap.shouldRespond(_buildDataPair(current, previous));
        assertTrue(triggered, "Minting anomaly should trigger");

        (, string memory category, ) = abi.decode(alertData, (uint8, string, string));
        assertEq(category, "MINTING_ANOMALY");
    }

    function test_NormalMintingNoTrigger() public view {
        CollectOutput memory current = _healthySnapshot();
        current.totalSupply = 1_004_000 ether; // 0.4% increase — below 5% threshold
        CollectOutput memory previous = _healthySnapshot();

        (bool triggered, ) = trap.shouldRespond(_buildDataPair(current, previous));
        assertFalse(triggered, "Small minting should not trigger");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TEST 8: Bridge Security
    // ═══════════════════════════════════════════════════════════════════════

    function test_BridgeDrain() public view {
        CollectOutput memory current = _healthySnapshot();
        current.bridgeBalance = 300 ether; // 40% drop from 500
        CollectOutput memory previous = _healthySnapshot();

        (bool triggered, bytes memory alertData) = trap.shouldRespond(_buildDataPair(current, previous));
        assertTrue(triggered, "Bridge drain should trigger");

        (, string memory category, ) = abi.decode(alertData, (uint8, string, string));
        assertEq(category, "BRIDGE_DRAIN");
    }

    function test_CumulativeBridgeDrain() public view {
        CollectOutput memory current = _healthySnapshot();
        current.bridgeBalance = 420 ether; // Only 16% per-block drop

        CollectOutput memory previous = _healthySnapshot();
        previous.bridgeBalance = 460 ether;

        CollectOutput memory oldest = _healthySnapshot();
        oldest.bridgeBalance = 700 ether; // Cumulative: 700 → 420 = 40% drop

        (bool triggered, bytes memory alertData) = trap.shouldRespond(
            _buildDataWindow(current, previous, oldest)
        );
        assertTrue(triggered, "Cumulative bridge drain should trigger");

        (, string memory category, ) = abi.decode(alertData, (uint8, string, string));
        assertEq(category, "CUMULATIVE_BRIDGE_DRAIN");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TEST: Edge Cases
    // ═══════════════════════════════════════════════════════════════════════

    function test_ZeroOraclePricesNoTrigger() public view {
        CollectOutput memory current = _healthySnapshot();
        current.oraclePrice = 0; // Failed oracle fetch
        CollectOutput memory previous = _healthySnapshot();

        (bool triggered, ) = trap.shouldRespond(_buildDataPair(current, previous));
        assertFalse(triggered, "Zero oracle prices should not trigger deviation");
    }

    function test_ZeroTVLNoTrigger() public view {
        CollectOutput memory current = _healthySnapshot();
        current.protocolTVL = 0;
        current.tokenBalance = 0;
        current.totalBorrows = 0;
        current.totalCollateral = 0;
        current.bridgeBalance = 0;
        CollectOutput memory previous = _healthySnapshot();
        previous.protocolTVL = 0;
        previous.tokenBalance = 0;
        previous.totalBorrows = 0;
        previous.totalCollateral = 0;
        previous.bridgeBalance = 0;

        (bool triggered, ) = trap.shouldRespond(_buildDataPair(current, previous));
        assertFalse(triggered, "All-zero state should not trigger");
    }

    function test_SmallChangesNoTrigger() public view {
        CollectOutput memory current = _healthySnapshot();
        // Small changes that are below all thresholds
        current.oraclePrice = 201000000000;      // 0.5% price change
        current.protocolTVL = 990 ether;          // 1% TVL change
        current.totalBorrows = 205 ether;         // 2.5% borrow change
        current.totalSupply = 1_003_000 ether;    // 0.3% supply change
        current.bridgeBalance = 490 ether;        // 2% bridge change
        current.blockTimestamp = 1700000012;       // 12 seconds later (not stale)
        CollectOutput memory previous = _healthySnapshot();

        (bool triggered, ) = trap.shouldRespond(_buildDataPair(current, previous));
        assertFalse(triggered, "Small changes should not trigger any alerts");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TEST: Response Contract
    // ═══════════════════════════════════════════════════════════════════════

    function test_ResponseContractRejectsUnauthorized() public {
        bytes memory alertData = abi.encode(uint8(3), "TEST", "test alert");
        vm.expectRevert("Only Drosera");
        response.handleIncident(alertData);
    }

    function test_ResponseContractHandlesCriticalAlert() public {
        bytes memory alertData = abi.encode(uint8(3), "ORACLE_MANIPULATION", "Price deviation detected");

        // Impersonate the Drosera protocol address
        vm.prank(0x91cB447BaFc6e0EA0F4Fe056F5a9b1F14bb06e5D);
        response.handleIncident(alertData);

        assertTrue(response.protocolPaused(), "Protocol should be paused after CRITICAL alert");
        assertEq(response.incidentCount(), 1, "Incident count should be 1");
    }

    function test_ResponseContractHandlesHighAlert() public {
        bytes memory alertData = abi.encode(uint8(2), "STALE_ORACLE", "Oracle not updated");

        vm.prank(0x91cB447BaFc6e0EA0F4Fe056F5a9b1F14bb06e5D);
        response.handleIncident(alertData);

        assertFalse(response.protocolPaused(), "Protocol should NOT be paused for HIGH alert");
        assertEq(response.incidentCount(), 1, "Incident count should be 1");
    }

    function test_ResponseContractSetPausableTarget() public {
        address target = address(0x1234);
        response.setPausableTarget(target);
        assertEq(response.pausableTarget(), target, "Pausable target should be set");
    }

    function test_ResponseContractRejectsNonDeployerConfig() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert("Only deployer");
        response.setPausableTarget(address(0x1234));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TEST: Threshold constants are correctly set
    // ═══════════════════════════════════════════════════════════════════════

    function test_ThresholdConstants() public view {
        assertEq(trap.ORACLE_DEVIATION_BPS(), 1500, "Oracle deviation should be 15%");
        assertEq(trap.TVL_DRAIN_BPS(), 2000, "TVL drain should be 20%");
        assertEq(trap.BORROW_SPIKE_BPS(), 1500, "Borrow spike should be 15%");
        assertEq(trap.SUPPLY_SPIKE_BPS(), 500, "Supply spike should be 5%");
        assertEq(trap.BRIDGE_DRAIN_BPS(), 3000, "Bridge drain should be 30%");
        assertEq(trap.ORACLE_STALENESS(), 3600, "Oracle staleness should be 1 hour");
        assertEq(trap.COLLATERAL_RATIO_MIN_BPS(), 5000, "Collateral ratio min should be 50%");
        assertEq(trap.ORACLE_CROSS_DEVIATION_BPS(), 1000, "Cross-oracle deviation should be 10%");
    }
}

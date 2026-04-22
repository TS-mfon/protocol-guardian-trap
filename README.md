# Protocol Guardian Trap

A comprehensive Drosera Trap that protects an entire DeFi protocol by monitoring **all major attack vectors** simultaneously. Rather than deploying separate traps for each threat, the Protocol Guardian Trap consolidates oracle manipulation, flash loan attacks, TVL drains, liquidation cascades, admin key compromises, reentrancy, minting anomalies, and bridge exploits into a single, cohesive monitoring system.

Built on the [Drosera Network](https://drosera.io) — a decentralized automation and incident response layer for blockchain protocols.

---

## Table of Contents

1. [Overview](#overview)
2. [Threat Vectors Monitored](#threat-vectors-monitored)
3. [Threshold Values and Rationale](#threshold-values-and-rationale)
4. [Architecture](#architecture)
5. [Response Contract](#response-contract)
6. [Real-World Exploits This Would Have Prevented](#real-world-exploits-this-would-have-prevented)
7. [Deployment and Configuration](#deployment-and-configuration)
8. [Customizing for Your Protocol](#customizing-for-your-protocol)
9. [Testing](#testing)
10. [Project Structure](#project-structure)

---

## Overview

The Protocol Guardian Trap operates as a **block-by-block sentinel**. Each block, the Drosera operator network calls `collect()` to snapshot the entire protocol state — oracle prices, TVL, borrow/collateral ratios, governance parameters, token supply, and bridge balances. The `shouldRespond()` function then compares consecutive snapshots to detect anomalies across eight distinct threat categories.

When a threat is detected, the trap returns structured alert data containing:
- **Severity** (CRITICAL / HIGH / MEDIUM)
- **Category** (e.g., `ORACLE_MANIPULATION`, `TVL_DRAIN`)
- **Description** (human-readable explanation)

This alert data is forwarded to the `ProtocolGuardianResponse` contract, which emits events, increments an incident counter, and — for CRITICAL alerts — automatically pauses the protocol.

### Key Design Principles

- **Resilience**: Every external call in `collect()` is wrapped in `try-catch`. If one data source fails, all other metrics are still collected.
- **Zero false negatives**: Thresholds are tuned to catch real attacks (which cause dramatic, sudden changes) while tolerating normal protocol activity.
- **Single deployment**: One trap covers eight threat vectors, reducing operational overhead and gas costs compared to deploying eight separate traps.
- **Composable alerts**: The structured alert format lets the response contract triage incidents by severity, enabling graduated responses (emit event vs. pause protocol).

---

## Threat Vectors Monitored

### 1. Oracle Manipulation

**What it detects**: Sudden price feed manipulation, stale oracles, and divergence between independent price sources.

**How it works**:
- **Price deviation**: Compares the oracle price between consecutive blocks. If the price moves more than 15% in a single block, it is almost certainly manipulation — legitimate markets do not move 15% in 12 seconds.
- **Stale oracle**: Checks if the oracle's `updatedAt` timestamp is more than 1 hour behind the current block timestamp. Stale oracles can be exploited by attackers who execute trades against outdated prices.
- **Multi-source comparison**: Compares the primary oracle against a secondary oracle. If they diverge by more than 10%, at least one source has been compromised.

**Relevant exploit**: Drift Protocol ($9M, December 2024) — oracle manipulation allowed attackers to execute trades at artificial prices.

### 2. Flash Loan Attacks

**What it detects**: Single-block borrow spikes that indicate flash loan-powered exploits, and dangerously low collateral ratios.

**How it works**:
- **Borrow spike**: If total borrows increase by more than 15% in a single block, this signals an abnormal borrowing event. Organic lending growth never reaches 15% per block.
- **Collateral ratio**: If the borrow-to-collateral ratio exceeds 50%, the protocol is approaching insolvency. This catches both flash loan attacks and cascading liquidations.

**Relevant exploit**: Euler Finance ($197M, March 2023) — a flash loan attack exploited a vulnerability in the donation and liquidation mechanism, causing massive borrow spikes.

### 3. TVL Drain / Fund Extraction

**What it detects**: Rapid and cumulative decreases in protocol TVL.

**How it works**:
- **Single-block drain**: If TVL drops by more than 20% in a single block, funds are being extracted abnormally fast. Normal withdrawal activity is spread across many blocks.
- **Cumulative drain**: Checks the full sample window (default 10 blocks). If TVL has declined by more than 20% across the window, a slower but sustained drain is underway.

**Relevant exploit**: Multiple — nearly every DeFi exploit involves draining TVL. The 20% threshold catches the Euler Finance drain (which extracted ~80% of TVL) while ignoring normal withdrawal spikes.

### 4. Liquidation Cascades

**What it detects**: Mass liquidation events where collateral drops significantly faster than borrows.

**How it works**: During a liquidation cascade, collateral is seized and sold, causing it to drop rapidly. Borrows also decrease (as they are repaid by liquidators), but at a slower rate. The trap detects when collateral drops more than 2x faster than borrows, indicating cascade-style liquidation rather than normal protocol activity.

**Relevant exploit**: The March 2020 "Black Thursday" event saw cascading liquidations across DeFi protocols. While not a hack, this pattern detection can alert protocol operators to take defensive action.

### 5. Admin Key Compromise

**What it detects**: Unauthorized ownership transfers, timelock bypass, and proxy implementation changes.

**How it works**:
- **Ownership change**: Compares the `owner()` of the governance contract between blocks. Any change triggers a CRITICAL alert — ownership transfers should go through governance, not happen silently.
- **Timelock bypass**: Monitors the timelock delay. If it drops below 1 hour, an attacker may have compromised the timelock to rush through malicious proposals.
- **Proxy upgrade**: Computes the `keccak256` hash of the proxy implementation's bytecode. If the hash changes between blocks, the implementation was upgraded — potentially maliciously.

**Relevant exploit**: Radiant Capital ($50M, October 2024) — attackers compromised admin keys to modify protocol contracts directly.

### 6. Reentrancy Detection

**What it detects**: Balance anomalies consistent with reentrancy attacks.

**How it works**: Classic reentrancy causes TVL to drop while borrows remain stable or increase (the attacker re-enters to drain funds without going through normal borrow flows). The trap flags cases where TVL drops more than 20% while borrows are stable or increasing.

**Relevant exploit**: Curve Finance (July 2023) — a Vyper compiler bug enabled reentrancy in multiple Curve pools, draining over $60M. The TVL-drop-with-stable-borrows pattern would have been immediately detected.

### 7. Minting Anomalies

**What it detects**: Sudden supply inflation indicating unauthorized or exploited minting.

**How it works**: If the total supply of the protocol token increases by more than 5% in a single block, the trap triggers. Legitimate minting (governance-approved token emissions, reward distributions) rarely exceeds 1-2% per day, let alone 5% per block.

**Relevant exploit**: Multiple stablecoin and governance token exploits have involved minting large quantities of tokens to drain liquidity pools.

### 8. Bridge Security

**What it detects**: Large and cumulative decreases in bridge vault balances.

**How it works**:
- **Single-block drain**: If the bridge vault balance drops by more than 30% in one block, the bridge is likely being exploited.
- **Cumulative drain**: Across the full sample window, if bridge balance drops more than 30%, a slower drain is occurring.

**Relevant exploit**: Nomad Bridge ($190M, August 2022) — a smart contract vulnerability allowed anyone to drain the bridge. The Ronin Bridge ($600M, March 2022) was drained over a short period. Both would have triggered the bridge drain alert.

---

## Threshold Values and Rationale

| Threshold | Value | BPS | Rationale |
|-----------|-------|-----|-----------|
| Oracle Deviation | 15% | 1500 | Major assets never move 15% in a single block (~12 seconds). Even during extreme volatility (2020 crash, 2022 LUNA collapse), per-block moves stay well under 5%. A 15% single-block move is manipulation. |
| TVL Drain | 20% | 2000 | Normal withdrawal spikes rarely exceed 5% of TVL per block. A 20% drop indicates extraction, not organic withdrawals. Set conservatively to avoid false positives from large legitimate whale withdrawals. |
| Borrow Spike | 15% | 1500 | Organic lending growth is gradual. A 15% per-block spike is characteristic of flash loan attacks, which borrow massive amounts in a single transaction. |
| Supply Spike | 5% | 500 | Token emissions are typically scheduled and small. 5% inflation in one block far exceeds any legitimate minting schedule. |
| Bridge Drain | 30% | 3000 | Bridges hold large balances and legitimate withdrawals are distributed over time. A 30% single-block drop indicates exploitation. Set higher than TVL drain because bridge withdrawals can be lumpier. |
| Oracle Staleness | 1 hour | 3600s | Chainlink's heartbeat for major pairs (ETH/USD, BTC/USD) is 1 hour. If the oracle hasn't updated in more than 1 hour, the feed is dead or censored. |
| Collateral Ratio | 50% | 5000 | Healthy lending protocols maintain >100% collateralization. Below 50% means the protocol is dangerously undercollateralized — either due to an attack or a cascading liquidation event. |
| Cross-Oracle Deviation | 10% | 1000 | Two independent price sources should agree within a few percent. A >10% divergence strongly suggests one source has been manipulated. |
| Min Timelock Delay | 1 hour | 3600s | Timelocks exist to give the community time to react to governance changes. Reducing the delay below 1 hour effectively bypasses this protection. |

---

## Architecture

### CollectOutput Struct

The `collect()` function returns an ABI-encoded struct containing a full protocol snapshot:

```
CollectOutput {
    int256  oraclePrice             // Primary oracle price
    uint256 oracleUpdatedAt         // Timestamp of last oracle update
    int256  oraclePriceSecondary    // Secondary oracle price
    uint256 protocolTVL             // Total value locked in protocol vault
    uint256 tokenBalance            // Token balance at protocol address
    uint256 totalBorrows            // Outstanding borrows
    uint256 totalCollateral         // Deposited collateral
    address protocolOwner           // Current protocol owner
    bytes32 implementationCodeHash  // Hash of proxy implementation code
    uint256 timelockDelay           // Current timelock delay
    uint256 totalSupply             // Protocol token total supply
    uint256 bridgeBalance           // Bridge vault locked balance
    uint256 blockNumber             // Block number
    uint256 blockTimestamp          // Block timestamp
}
```

### Data Flow

```
Block N:     collect() → snapshot_N (encoded bytes)
Block N+1:   collect() → snapshot_N+1

Drosera Operators: shouldRespond([snapshot_N+1, snapshot_N, ...])
                   → Compares snapshots across 8 threat vectors
                   → Returns (true, alertData) if any threat detected
                   → alertData = abi.encode(severity, category, description)

Response: ProtocolGuardianResponse.handleIncident(alertData)
          → Emits IncidentDetected event
          → If CRITICAL: pauses protocol
```

### Detection Priority

Threats are checked in this order (first match wins):

1. Oracle manipulation (deviation)
2. Stale oracle
3. Multi-source oracle divergence
4. Flash loan / borrow spike
5. Collateral ratio breach
6. TVL drain (single block)
7. TVL drain (cumulative)
8. Liquidation cascade
9. Ownership change
10. Timelock bypass
11. Proxy upgrade
12. Reentrancy pattern
13. Minting anomaly
14. Bridge drain (single block)
15. Bridge drain (cumulative)

---

## Response Contract

The `ProtocolGuardianResponse` contract is the on-chain responder:

1. **Only Drosera can call it** — `handleIncident()` requires `msg.sender == DROSERA_PROTOCOL`.
2. **Events for monitoring** — Every incident emits `IncidentDetected` with severity, category, description, and timestamp. Off-chain monitoring systems can index these events.
3. **Automatic pausing** — CRITICAL alerts trigger `protocolPaused = true` and attempt to call `pause()` on the configured target contract.
4. **Configurable target** — The deployer sets the pausable target address via `setPausableTarget()`.
5. **Incident counter** — `incidentCount` provides a running total of all detected incidents.

### Severity Levels

| Level | Value | Action |
|-------|-------|--------|
| CRITICAL | 3 | Emit event + pause protocol |
| HIGH | 2 | Emit event only |
| MEDIUM | 1 | Emit event only |

---

## Real-World Exploits This Would Have Prevented

### Drift Protocol — $9M (December 2024)
**Vector**: Oracle manipulation
**Detection**: `ORACLE_DEVIATION_BPS` — the manipulated price deviated far more than 15% from the previous block's price.

### Euler Finance — $197M (March 2023)
**Vector**: Flash loan + borrow spike + TVL drain
**Detection**: `BORROW_SPIKE_BPS` would fire first as borrows spiked enormously in the attack transaction. `TVL_DRAIN_BPS` would catch the subsequent fund extraction.

### Radiant Capital — $50M (October 2024)
**Vector**: Admin key compromise
**Detection**: `OWNERSHIP_CHANGE` would fire when the compromised keys were used to transfer ownership. `PROXY_UPGRADE` would fire when malicious implementation was deployed.

### Curve Finance Reentrancy — $60M+ (July 2023)
**Vector**: Reentrancy via Vyper compiler bug
**Detection**: `TVL_DRAIN_BPS` would fire as pool balances dropped dramatically. The reentrancy pattern (TVL down, borrows stable) would also be flagged.

### Nomad Bridge — $190M (August 2022)
**Vector**: Bridge contract vulnerability allowing arbitrary withdrawals
**Detection**: `BRIDGE_DRAIN_BPS` would fire immediately as the bridge balance plummeted.

### Ronin Bridge — $600M (March 2022)
**Vector**: Compromised validator keys used to drain the bridge
**Detection**: `BRIDGE_DRAIN_BPS` for the balance drain. If the bridge governance was also modified, `OWNERSHIP_CHANGE` would have fired.

---

## Deployment and Configuration

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- [Node.js](https://nodejs.org/) (for dependency management)
- A Drosera account and operator setup on Hoodi testnet

### Install Dependencies

```bash
npm install
```

### Build

```bash
forge build
```

### Test

```bash
forge test -vvv
```

### Deploy the Response Contract

```bash
forge create src/ProtocolGuardianResponse.sol:ProtocolGuardianResponse \
  --rpc-url https://ethereum-hoodi-rpc.publicnode.com \
  --private-key $PRIVATE_KEY
```

After deployment, configure the pausable target:

```bash
cast send $RESPONSE_ADDRESS "setPausableTarget(address)" $YOUR_PROTOCOL_ADDRESS \
  --rpc-url https://ethereum-hoodi-rpc.publicnode.com \
  --private-key $PRIVATE_KEY
```

### Register the Trap with Drosera

1. Update `drosera.toml` with the response contract address.
2. Run `drosera apply` to register the trap on the Drosera network.

```bash
drosera apply
```

---

## Customizing for Your Protocol

### Step 1: Update Monitored Addresses

In `src/ProtocolGuardianTrap.sol`, replace the placeholder addresses with your protocol's actual contract addresses:

```solidity
address public constant PRIMARY_ORACLE = 0x...; // Your Chainlink feed
address public constant SECONDARY_ORACLE = 0x...; // Secondary feed or TWAP
address public constant PROTOCOL_VAULT = 0x...; // Main vault holding funds
address public constant LENDING_POOL = 0x...; // Comptroller / pool
address public constant GOVERNANCE = 0x...; // Ownable governance
address public constant TIMELOCK = 0x...; // Timelock controller
address public constant PROXY = 0x...; // Proxy contract
address public constant PROTOCOL_TOKEN = 0x...; // Protocol token
address public constant BRIDGE_VAULT = 0x...; // Bridge vault
```

### Step 2: Update Interfaces

If your protocol uses different function signatures (e.g., `getTotalDebt()` instead of `totalBorrows()`), update `src/interfaces/IProtocolInterfaces.sol` accordingly.

### Step 3: Tune Thresholds

Adjust the threshold constants based on your protocol's risk profile:

- **High-frequency trading protocols**: Tighten oracle deviation (e.g., 500 BPS / 5%)
- **Stablecoin protocols**: Tighten oracle deviation and add peg monitoring
- **Large TVL protocols**: Consider lowering TVL drain threshold (e.g., 1000 BPS / 10%)
- **Bridges**: Lower the bridge drain threshold for high-value bridges

### Step 4: Add Protocol-Specific Checks

The `shouldRespond()` function can be extended with additional checks specific to your protocol. For example:
- Vault share price manipulation (for ERC-4626 vaults)
- Governance vote manipulation
- Fee parameter changes
- Whitelist/blacklist modifications

### Step 5: Configure the Sample Window

In `drosera.toml`, adjust `block_sample_size` based on how many blocks of history you want to analyze. The default is 10 blocks (~2 minutes on Ethereum mainnet).

---

## Testing

The test suite covers every threat vector:

```
test_NoTriggerWithSingleDataPoint   — Verifies no false trigger with insufficient data
test_NoTriggerHealthyProtocol       — Verifies no trigger for normal protocol state
test_OracleDeviation                — 20% price jump triggers ORACLE_MANIPULATION
test_StaleOracle                    — 10000-second-old update triggers STALE_ORACLE
test_OracleCrossDeviation           — Primary/secondary divergence triggers ORACLE_CROSS_DEVIATION
test_BorrowSpike                    — 50% borrow increase triggers FLASH_LOAN_ATTACK
test_CollateralRatioBreach          — >50% borrow/collateral ratio triggers COLLATERAL_RATIO_BREACH
test_TVLDrain                       — 30% TVL drop triggers TVL_DRAIN
test_CumulativeTVLDrain             — Window-wide 29% drop triggers CUMULATIVE_TVL_DRAIN
test_LiquidationCascade             — Collateral drops 3.75x faster than borrows
test_OwnershipChange                — Owner address change triggers OWNERSHIP_CHANGE
test_TimelockBypass                 — Delay reduced to 60s triggers TIMELOCK_BYPASS
test_ProxyUpgrade                   — Code hash change triggers PROXY_UPGRADE
test_ReentrancyPattern              — TVL drop with stable borrows (CRITICAL)
test_ReentrancyWithBorrowIncrease   — TVL drop with borrow increase (FLASH_LOAN_ATTACK)
test_MintingAnomaly                 — 10% supply increase triggers MINTING_ANOMALY
test_NormalMintingNoTrigger         — 0.4% increase is below threshold
test_BridgeDrain                    — 40% bridge drop triggers BRIDGE_DRAIN
test_CumulativeBridgeDrain          — Window-wide 40% drop triggers CUMULATIVE_BRIDGE_DRAIN
test_ZeroOraclePricesNoTrigger      — Zero prices gracefully handled
test_ZeroTVLNoTrigger               — All-zero state does not trigger
test_SmallChangesNoTrigger          — Small healthy changes stay quiet
test_ResponseContractRejectsUnauthorized — Non-Drosera callers rejected
test_ResponseContractHandlesCriticalAlert — CRITICAL pauses protocol
test_ResponseContractHandlesHighAlert     — HIGH does not pause
test_ResponseContractSetPausableTarget    — Deployer can configure target
test_ResponseContractRejectsNonDeployerConfig — Non-deployer rejected
test_ThresholdConstants                   — All thresholds match documented values
```

Run with verbose output:

```bash
forge test -vvv
```

---

## Project Structure

```
protocol-guardian-trap/
├── foundry.toml                              # Foundry configuration
├── package.json                              # Node.js dependencies
├── remappings.txt                            # Solidity import remappings
├── drosera.toml                              # Drosera network configuration (Hoodi testnet)
├── .gitignore                                # Git ignore rules
├── README.md                                 # This file
├── src/
│   ├── ProtocolGuardianTrap.sol              # Main comprehensive trap contract
│   ├── ProtocolGuardianResponse.sol          # Response contract for incident handling
│   └── interfaces/
│       └── IProtocolInterfaces.sol           # All external protocol interfaces
├── test/
│   └── ProtocolGuardianTrap.t.sol            # Comprehensive test suite
└── node_modules/
    ├── drosera-contracts/                    # Drosera Trap base contract
    └── forge-std/                            # Foundry standard library
```

---

## License

MIT

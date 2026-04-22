// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ProtocolGuardianResponse
/// @author Drosera Community
/// @notice Response contract invoked by Drosera when the ProtocolGuardianTrap detects a threat.
/// @dev This contract receives the encoded alert data from the trap's shouldRespond output,
///      parses the severity / category / description, emits structured events, and optionally
///      pauses the monitored protocol when a CRITICAL alert fires.
///
///      Integration points:
///        1. Deploy this contract.
///        2. Grant it PAUSER_ROLE (or equivalent) on your protocol's pausable contract.
///        3. Set the `response_contract` in drosera.toml to this contract's address.
///        4. Set `response_function` to "handleIncident(bytes)".
///
///      The contract only accepts calls from the Drosera protocol address configured at deploy time.
contract ProtocolGuardianResponse {
    // ═══════════════════════════════════════════════════════════════════════
    // STATE
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice The Drosera protocol relay address that is authorized to call handleIncident.
    address public constant DROSERA_PROTOCOL = 0x91cB447BaFc6e0EA0F4Fe056F5a9b1F14bb06e5D;

    /// @notice Address of the protocol's pausable contract (set by deployer).
    address public pausableTarget;

    /// @notice Deployer address, used for initial configuration.
    address public deployer;

    /// @notice Whether the protocol has been paused by this contract.
    bool public protocolPaused;

    /// @notice Incrementing incident counter for historical tracking.
    uint256 public incidentCount;

    // ═══════════════════════════════════════════════════════════════════════
    // EVENTS
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Emitted for every incident detected by the trap.
    event IncidentDetected(
        uint256 indexed incidentId,
        uint8 severity,
        string category,
        string description,
        uint256 timestamp
    );

    /// @notice Emitted when the response contract pauses the protocol.
    event ProtocolPaused(string reason, uint256 timestamp);

    /// @notice Emitted for non-critical alerts that do not trigger a pause.
    event AlertSent(string category, string description, uint256 timestamp);

    // ═══════════════════════════════════════════════════════════════════════
    // SEVERITY CONSTANTS (must match ProtocolGuardianTrap)
    // ═══════════════════════════════════════════════════════════════════════

    uint8 internal constant SEVERITY_CRITICAL = 3;
    uint8 internal constant SEVERITY_HIGH = 2;
    uint8 internal constant SEVERITY_MEDIUM = 1;

    // ═══════════════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════════════

    constructor() {
        deployer = msg.sender;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CONFIGURATION
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Sets the pausable target contract address.
    /// @dev Only callable by the deployer. Set this to your protocol's main pausable contract.
    /// @param _target Address of the contract that exposes a `pause()` function.
    function setPausableTarget(address _target) external {
        require(msg.sender == deployer, "Only deployer");
        pausableTarget = _target;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // INCIDENT HANDLER
    // ═══════════════════════════════════════════════════════════════════════

    /// @notice Called by Drosera when the ProtocolGuardianTrap triggers.
    /// @dev Decodes the alert data, emits events, and pauses the protocol for CRITICAL severity.
    ///      The alert data is ABI-encoded as (uint8 severity, string category, string description).
    /// @param alertData The raw bytes returned by shouldRespond's second return value.
    function handleIncident(bytes memory alertData) external {
        require(msg.sender == DROSERA_PROTOCOL, "Only Drosera");

        // Decode the structured alert
        (uint8 severity, string memory category, string memory description) = abi.decode(
            alertData,
            (uint8, string, string)
        );

        // Increment and emit
        incidentCount++;
        emit IncidentDetected(incidentCount, severity, category, description, block.timestamp);

        // CRITICAL severity → pause the protocol
        if (severity >= SEVERITY_CRITICAL) {
            protocolPaused = true;
            emit ProtocolPaused(
                string(abi.encodePacked("[", category, "] ", description)),
                block.timestamp
            );

            // Attempt to call pause() on the target contract
            if (pausableTarget != address(0)) {
                // solhint-disable-next-line avoid-low-level-calls
                (bool success, ) = pausableTarget.call(abi.encodeWithSignature("pause()"));
                // We do not revert on failure — emitting the event is sufficient for alerting
                if (!success) {
                    emit AlertSent("PAUSE_FAILED", "Attempted to pause target but call failed", block.timestamp);
                }
            }
        } else {
            // HIGH / MEDIUM → emit alert only
            emit AlertSent(category, description, block.timestamp);
        }
    }
}

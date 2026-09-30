// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IntegrityLedger
/// @notice On-chain verifier for signed runtime measurements from a remote agent.
///
/// Every few seconds the agent measures three components of the machine it runs on:
///   BINARY  - the protected service executable (+ the agent's own code)
///   CONFIG  - the service configuration file
///   MEMORY  - the security policy and critical code objects loaded in RAM
/// It signs (seq, hashes) with its private key and submits them here. The contract:
///   1. checks the ECDSA signature really comes from the registered agent key
///   2. compares each hash with the golden reference
///   3. adopts changes ONLY for components the developer approved beforehand
///      (one-shot approval), otherwise records a permanent TamperDetected alert.
contract IntegrityLedger {
    uint8 public constant BINARY = 1;
    uint8 public constant CONFIG = 2;
    uint8 public constant MEMORY = 4;
    uint8 public constant ALL = 7;

    // ----------------------------------------------------------------- state
    address public owner;          // developer: approves updates
    address public agent;          // agent signing key (not the tx sender: a relayer pays gas)
    bytes32[3] private references; // golden hashes: [binary, config, memory]
    uint8 public approvedMask;     // components allowed to change on the next measurement
    uint64 public approvalExpiry;  // approvals are short-lived: an attacker can't ride an old one
    uint64 public constant APPROVAL_WINDOW = 60; // seconds

    uint64 public lastSeq;         // replay protection: strictly increasing
    uint64 public lastTimestamp;   // heartbeat
    uint8 public lastMismatch;     // components that differ in the latest measurement
    bytes32 private lastAlert;     // de-duplicates alerts for the same tampered state

    // ---------------------------------------------------------------- events
    event AgentRegistered(address indexed agent, uint256 timestamp);
    event UpdateAuthorized(uint8 mask, address indexed by, uint256 timestamp);
    event Measured(uint64 seq, bytes32 binaryHash, bytes32 configHash, bytes32 memoryHash,
                   uint8 mismatch, uint32 costMicros, bytes signature, uint256 timestamp);
    event ReferenceUpdated(uint8 mask, bytes32 binaryHash, bytes32 configHash, bytes32 memoryHash, uint256 timestamp);
    event TamperDetected(uint8 mask, bytes32 binaryHash, bytes32 configHash, bytes32 memoryHash, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "IntegrityLedger: caller is not the owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // ------------------------------------------------------------- owner ops
    /// @notice Enroll the agent's public key. Its first measurement becomes the golden reference.
    function registerAgent(address agentKey) external onlyOwner {
        agent = agentKey;
        approvedMask = ALL; // trust-on-first-measurement enrollment window
        approvalExpiry = uint64(block.timestamp) + APPROVAL_WINDOW;
        lastMismatch = 0;
        emit AgentRegistered(agentKey, block.timestamp);
    }

    /// @notice Developer approval for a release touching `mask` components.
    /// Refused while the system is tampered: an approval must never launder an attack.
    function authorizeUpdate(uint8 mask) external onlyOwner {
        require(agent != address(0), "IntegrityLedger: no agent registered");
        require(lastMismatch == 0, "IntegrityLedger: system is tampered, restore it first");
        require(mask != 0 && mask <= ALL, "IntegrityLedger: bad component mask");
        approvedMask = mask;
        approvalExpiry = uint64(block.timestamp) + APPROVAL_WINDOW;
        emit UpdateAuthorized(mask, msg.sender, block.timestamp);
    }

    // ------------------------------------------------------------- agent ops
    function submitMeasurement(
        uint64 seq,
        bytes32 binaryHash,
        bytes32 configHash,
        bytes32 memoryHash,
        uint32 costMicros,
        bytes calldata signature
    ) external {
        require(agent != address(0), "IntegrityLedger: no agent registered");
        require(seq > lastSeq, "IntegrityLedger: stale or replayed measurement");
        bytes32 digest = keccak256(abi.encodePacked(
            address(this), block.chainid, seq, binaryHash, configHash, memoryHash, costMicros));
        require(_recover(digest, signature) == agent, "IntegrityLedger: bad agent signature");

        bytes32[3] memory measured = [binaryHash, configHash, memoryHash];
        uint8 mismatch = 0;
        for (uint8 i = 0; i < 3; i++) {
            if (measured[i] != references[i]) mismatch |= uint8(1 << i);
        }

        if (approvedMask != 0 && block.timestamp > approvalExpiry) approvedMask = 0; // lapsed

        if (mismatch != 0 && approvedMask != 0 && (mismatch & ~approvedMask) == 0) {
            // Every changed component was approved: adopt them and consume the approval.
            for (uint8 i = 0; i < 3; i++) {
                if (mismatch & uint8(1 << i) != 0) references[i] = measured[i];
            }
            emit ReferenceUpdated(mismatch, binaryHash, configHash, memoryHash, block.timestamp);
            approvedMask = 0;
            mismatch = 0;
        } else if (mismatch != 0) {
            bytes32 alertKey = keccak256(abi.encodePacked(binaryHash, configHash, memoryHash));
            if (alertKey != lastAlert) {
                emit TamperDetected(mismatch, binaryHash, configHash, memoryHash, block.timestamp);
                lastAlert = alertKey;
            }
        } else {
            lastAlert = bytes32(0);
        }

        lastSeq = seq;
        lastTimestamp = uint64(block.timestamp);
        lastMismatch = mismatch;
        emit Measured(seq, binaryHash, configHash, memoryHash, mismatch, costMicros, signature, block.timestamp);
    }

    // ----------------------------------------------------------------- reads
    function getReferences() external view returns (bytes32, bytes32, bytes32) {
        return (references[0], references[1], references[2]);
    }

    // ------------------------------------------------------------- internals
    /// @dev EIP-191 personal_sign recovery of a 65-byte (r, s, v) signature.
    function _recover(bytes32 digest, bytes calldata sig) private pure returns (address) {
        require(sig.length == 65, "IntegrityLedger: bad signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        address signer = ecrecover(ethHash, v, r, s);
        require(signer != address(0), "IntegrityLedger: invalid signature");
        return signer;
    }
}

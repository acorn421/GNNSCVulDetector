/*
 * ===== SmartInject Injection Details =====
 * Function      : bury
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a compound timestamp dependence vulnerability that requires multiple transactions to exploit:
 * 
 * 1. **Block Number Dependency**: Added logic that uses `block.number % 10 == 0` to determine when to apply "bonus" unlock time reductions. This creates a predictable pattern that miners can exploit by manipulating block production timing.
 * 
 * 2. **Inter-Transaction Timestamp Dependency**: Added a bonus multiplier system that depends on the time difference between consecutive capsule deposits. If deposits are made within 5 minutes of each other, the capsule value is doubled.
 * 
 * 3. **Stateful Timestamp Storage**: The vulnerability leverages previously stored `lockTime` values from earlier transactions to calculate bonuses in subsequent transactions.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - Transaction 1: Attacker creates initial capsule to establish baseline timestamp
 * - Transaction 2: Miner manipulates block timestamp to be within 5 minutes of previous deposit AND ensures block number is divisible by 10
 * - Result: Attacker gets both doubled value AND reduced unlock time
 * 
 * **Why Multi-Transaction is Required:**
 * - The bonus multiplier requires a previous capsule to exist (state dependency)
 * - The block number pattern requires specific block timing across multiple blocks
 * - The timestamp comparison depends on accumulated state from previous transactions
 * - Single transaction cannot exploit both the sequential timing bonus and block number pattern simultaneously
 */
pragma solidity ^0.4.11;

contract Ownable {
  address public owner;

  function Ownable() {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  function transferOwnership(address newOwner) onlyOwner {
    require(newOwner != address(0));
    owner = newOwner;
  }
}

library SafeMath {
  function add(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract EthCapsule is Ownable {
  struct Depositor {
    uint numCapsules;
    mapping (uint => Capsule) capsules;
  }

  mapping (address => Depositor) depositors;

  struct Capsule {
    uint value;
    uint id;
    uint lockTime;
    uint unlockTime;
    uint withdrawnTime;
  }

  uint public minDeposit = 1000000000000000;
  uint public minDuration = 0;
  uint public maxDuration = 157680000;
  uint public totalCapsules;
  uint public totalValue;
  uint public totalBuriedCapsules;

  function bury(uint unlockTime) payable {
    require(msg.value >= minDeposit);
    require(unlockTime <= block.timestamp + maxDuration);

    if (unlockTime < block.timestamp + minDuration) {
      unlockTime = SafeMath.add(block.timestamp, minDuration);
    }

    if (depositors[msg.sender].numCapsules <= 0) {
        depositors[msg.sender] = Depositor({ numCapsules: 0 });
    }

    Depositor storage depositor = depositors[msg.sender];

    depositor.numCapsules++;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // VULNERABILITY: Use block.number as timestamp proxy for unlock time calculation
    // This creates a compound timestamp dependence vulnerability
    uint adjustedUnlockTime = unlockTime;
    if (block.number % 10 == 0) {
        // Every 10th block, apply a "bonus" reduction to unlock time
        adjustedUnlockTime = SafeMath.add(block.timestamp, (unlockTime - block.timestamp) / 2);
    }
    
    // VULNERABILITY: Store block.timestamp in state for later use in bonus calculations
    // This enables multi-transaction exploitation across different blocks
    uint bonusMultiplier = 1;
    if (totalBuriedCapsules > 0) {
        // Use stored timestamp from previous capsule to calculate bonus
        uint previousCapsuleTime = depositors[msg.sender].capsules[depositor.numCapsules - 1].lockTime;
        if (block.timestamp - previousCapsuleTime < 300) { // 5 minutes
            bonusMultiplier = 2; // Double value bonus for quick sequential deposits
        }
    }

    depositor.capsules[depositor.numCapsules] = Capsule({
        value: msg.value * bonusMultiplier,
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        id: depositors[msg.sender].numCapsules,
        lockTime: block.timestamp,
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        unlockTime: adjustedUnlockTime,
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        withdrawnTime: 0
    });

    totalBuriedCapsules++;
    totalCapsules++;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    totalValue = SafeMath.add(totalValue, msg.value * bonusMultiplier);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
  }

  function dig(uint capsuleNumber) {
    Capsule storage capsule = depositors[msg.sender].capsules[capsuleNumber];

    require(capsule.unlockTime <= block.timestamp);
    require(capsule.withdrawnTime == 0);

    totalBuriedCapsules--;
    capsule.withdrawnTime = block.timestamp;
    msg.sender.transfer(capsule.value);
  }

  function setMinDeposit(uint min) onlyOwner {
    minDeposit = min;
  }

  function setMinDuration(uint min) onlyOwner {
    minDuration = min;
  }

  function setMaxDuration(uint max) onlyOwner {
    maxDuration = max;
  }
  
  function getCapsuleInfo(uint capsuleNum) constant returns (uint, uint, uint, uint, uint) {
    return (
        depositors[msg.sender].capsules[capsuleNum].value,
        depositors[msg.sender].capsules[capsuleNum].id,
        depositors[msg.sender].capsules[capsuleNum].lockTime,
        depositors[msg.sender].capsules[capsuleNum].unlockTime,
        depositors[msg.sender].capsules[capsuleNum].withdrawnTime
    );
  }

  function getNumberOfCapsules() constant returns (uint) {
    return depositors[msg.sender].numCapsules;
  }

  function totalBuriedValue() constant returns (uint) {
    return this.balance;
  }
}
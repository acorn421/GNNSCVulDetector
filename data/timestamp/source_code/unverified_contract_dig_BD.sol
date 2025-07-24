/*
 * ===== SmartInject Injection Details =====
 * Function      : dig
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
 * Introduced a multi-transaction timestamp dependence vulnerability through a time-based withdrawal bonus system. The vulnerability requires:
 * 
 * 1. **State Accumulation**: The `lastWithdrawalTime` state variable persists between transactions, enabling compound bonuses for successive withdrawals
 * 2. **Multi-Transaction Exploitation**: Miners can manipulate block timestamps across multiple dig() calls to:
 *    - Hit the "sweet spot" time window (24-48 hours) for maximum 5% bonus
 *    - Chain multiple withdrawals within 1 hour for 1.5x compound multiplier
 *    - Coordinate timing across multiple capsules for maximum profit
 * 
 * 3. **Realistic Vulnerability Pattern**: The bonus system appears legitimate but creates economic incentives for timestamp manipulation
 * 4. **Persistent State Changes**: Each withdrawal updates `lastWithdrawalTime`, affecting future withdrawal calculations
 * 
 * The vulnerability is only exploitable through multiple transactions because:
 * - Single transaction cannot manipulate the time windows effectively
 * - Compound bonuses require previous withdrawal state
 * - Maximum exploitation requires coordinated timing across multiple capsules
 * - The economic incentive scales with the number of manipulated withdrawals
 */
pragma solidity ^0.4.11;

contract Ownable {
  address public owner;

  constructor() public {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    owner = newOwner;
  }
}

library SafeMath {
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract EthCapsule is Ownable {
  struct Capsule {
    uint value;
    uint id;
    uint lockTime;
    uint unlockTime;
    uint withdrawnTime;
  }

  struct Depositor {
    uint numCapsules;
    mapping (uint => Capsule) capsules;
    uint lastWithdrawalTime;
  }

  mapping (address => Depositor) depositors;

  uint public minDeposit = 1000000000000000;
  uint public minDuration = 0;
  uint public maxDuration = 157680000;
  uint public totalCapsules;
  uint public totalValue;
  uint public totalBuriedCapsules;

  function bury(uint unlockTime) public payable {
    require(msg.value >= minDeposit);
    require(unlockTime <= block.timestamp + maxDuration);

    if (unlockTime < block.timestamp + minDuration) {
      unlockTime = SafeMath.add(block.timestamp, minDuration);
    }

    if (depositors[msg.sender].numCapsules <= 0) {
        depositors[msg.sender] = Depositor({ numCapsules: 0, lastWithdrawalTime: 0 });
    }

    Depositor storage depositor = depositors[msg.sender];

    depositor.numCapsules++;
    depositor.capsules[depositor.numCapsules] = Capsule({
        value: msg.value,
        id: depositors[msg.sender].numCapsules,
        lockTime: block.timestamp,
        unlockTime: unlockTime,
        withdrawnTime: 0
    });

    totalBuriedCapsules++;
    totalCapsules++;
    totalValue = SafeMath.add(totalValue, msg.value);
  }

  function dig(uint capsuleNumber) public {
    Capsule storage capsule = depositors[msg.sender].capsules[capsuleNumber];

    require(capsule.unlockTime <= block.timestamp);
    require(capsule.withdrawnTime == 0);

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Time-based withdrawal bonus system vulnerable to timestamp manipulation
    uint withdrawalBonus = 0;
    uint timeSinceLock = block.timestamp - capsule.lockTime;
    
    // Early withdrawal penalty (first 24 hours)
    if (timeSinceLock < 86400) {
        withdrawalBonus = 0; // No bonus for early withdrawal
    }
    // Sweet spot bonus (24-48 hours) - vulnerable to miner manipulation
    else if (timeSinceLock >= 86400 && timeSinceLock < 172800) {
        withdrawalBonus = capsule.value / 20; // 5% bonus
    }
    // Regular bonus (48+ hours)
    else {
        withdrawalBonus = capsule.value / 100; // 1% bonus
    }
    
    // Apply compound bonus if multiple withdrawals in same time window
    if (depositors[msg.sender].lastWithdrawalTime > 0) {
        uint timeSinceLastWithdrawal = block.timestamp - depositors[msg.sender].lastWithdrawalTime;
        // Compound bonus for withdrawals within 1 hour of each other
        if (timeSinceLastWithdrawal < 3600) {
            withdrawalBonus = (withdrawalBonus * 3) / 2; // 1.5x multiplier
        }
    }

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    totalBuriedCapsules--;
    capsule.withdrawnTime = block.timestamp;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    depositors[msg.sender].lastWithdrawalTime = block.timestamp;
    
    uint totalPayout = capsule.value + withdrawalBonus;
    msg.sender.transfer(totalPayout);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
  }

  function setMinDeposit(uint min) public onlyOwner {
    minDeposit = min;
  }

  function setMinDuration(uint min) public onlyOwner {
    minDuration = min;
  }

  function setMaxDuration(uint max) public onlyOwner {
    maxDuration = max;
  }
  
  function getCapsuleInfo(uint capsuleNum) public view returns (uint, uint, uint, uint, uint) {
    return (
        depositors[msg.sender].capsules[capsuleNum].value,
        depositors[msg.sender].capsules[capsuleNum].id,
        depositors[msg.sender].capsules[capsuleNum].lockTime,
        depositors[msg.sender].capsules[capsuleNum].unlockTime,
        depositors[msg.sender].capsules[capsuleNum].withdrawnTime
    );
  }

  function getNumberOfCapsules() public view returns (uint) {
    return depositors[msg.sender].numCapsules;
  }

  function totalBuriedValue() public view returns (uint) {
    return this.balance;
  }
}

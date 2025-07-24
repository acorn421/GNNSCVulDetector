/*
 * ===== SmartInject Injection Details =====
 * Function      : purchase
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
 * Introduced a stateful timestamp dependence vulnerability through a time-based bonus system. The vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **State Accumulation**: Added `accumulatedBonus` that builds up over time based on `block.timestamp` differences, requiring multiple transactions to reach exploitable levels.
 * 
 * 2. **Timestamp-Dependent Multiplier**: The `bonusMultiplier` increases based on time-of-day patterns using `block.timestamp`, creating predictable manipulation windows.
 * 
 * 3. **Multi-Transaction Exploitation Path**: 
 *    - Transaction 1: Initialize the bonus system (sets `lastBonusTimestamp`)
 *    - Transactions 2-N: Wait for time to pass and accumulate bonuses
 *    - Final Transaction: Exploit when `accumulatedBonus` is high and timing conditions are favorable
 * 
 * 4. **Miner Manipulation Opportunity**: Miners can manipulate `block.timestamp` across multiple blocks to:
 *    - Accelerate bonus accumulation by inflating time differences
 *    - Time transactions to hit favorable multiplier conditions
 *    - Reset the bonus system at optimal moments
 * 
 * 5. **Realistic Business Logic**: The bonus system appears as a legitimate "time-based reward" feature that would naturally fit in an investment contract.
 * 
 * The vulnerability is not exploitable in a single transaction because the bonus accumulation depends on persistent state changes across multiple blocks, and the maximum benefit requires coordinated timestamp manipulation over several transactions.
 */
pragma solidity ^0.4.18;

contract TwoXMachine {

  // Address of the contract creator
  address public contractOwner;

  // FIFO queue
  BuyIn[] public buyIns;

  // The current BuyIn queue index
  uint256 public index;

  // Total invested for entire contract
  uint256 public contractTotalInvested;

  // Total invested for a given address
  mapping (address => uint256) public totalInvested;

  // Total value for a given address
  mapping (address => uint256) public totalValue;

  // Total paid out for a given address
  mapping (address => uint256) public totalPaidOut;

  // Added state variables for bonus system
  uint256 public lastBonusTimestamp;
  uint256 public accumulatedBonus;
  uint256 public bonusMultiplier = 1;

  struct BuyIn {
    uint256 value;
    address owner;
  }

  modifier onlyContractOwner() {
    require(msg.sender == contractOwner);
    _;
  }

  constructor() public {
    contractOwner = msg.sender;
  }

  function purchase() public payable {
    // I don't want no scrub
    require(msg.value >= 0.01 ether);

    // Take a 5% fee
    uint256 value = SafeMath.div(SafeMath.mul(msg.value, 95), 100);

    // HNNNNNNGGGGGG
    uint256 valueMultiplied = SafeMath.div(SafeMath.mul(msg.value, 25), 100);
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====

    // Time-based bonus system - accumulates over time
    uint256 timeBonus = calculateTimeBonus();
    if (timeBonus > 0) {
      valueMultiplied = SafeMath.add(valueMultiplied, timeBonus);
    }
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

    contractTotalInvested += msg.value;
    totalInvested[msg.sender] += msg.value;

    while (index < buyIns.length && value > 0) {
      BuyIn storage buyIn = buyIns[index];

      if (value < buyIn.value) {
        buyIn.owner.transfer(value);
        totalPaidOut[buyIn.owner] += value;
        totalValue[buyIn.owner] -= value;
        buyIn.value -= value;
        value = 0;
      } else {
        buyIn.owner.transfer(buyIn.value);
        totalPaidOut[buyIn.owner] += buyIn.value;
        totalValue[buyIn.owner] -= buyIn.value;
        value -= buyIn.value;
        buyIn.value = 0;
        index++;
      }
    }

    // if buyins have been exhausted, return the remaining
    // funds back to the investor
    if (value > 0) {
      msg.sender.transfer(value);
      valueMultiplied -= value;
      totalPaidOut[msg.sender] += value;
    }

    totalValue[msg.sender] += valueMultiplied;

    buyIns.push(BuyIn({
      value: valueMultiplied,
      owner: msg.sender
    }));
  }
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====

  function calculateTimeBonus() private returns (uint256) {
    // Initialize first timestamp if not set
    if (lastBonusTimestamp == 0) {
      lastBonusTimestamp = block.timestamp;
      return 0;
    }

    // Calculate time difference in hours
    uint256 timeDiff = SafeMath.sub(block.timestamp, lastBonusTimestamp);
    uint256 hoursPassed = SafeMath.div(timeDiff, 3600);

    // Accumulate bonus based on time passed
    if (hoursPassed > 0) {
      uint256 bonusIncrement = SafeMath.mul(hoursPassed, bonusMultiplier);
      accumulatedBonus = SafeMath.add(accumulatedBonus, bonusIncrement);
      
      // Update multiplier based on current timestamp patterns
      if (SafeMath.mod(block.timestamp, 86400) < 43200) { // First half of day
        bonusMultiplier = SafeMath.mul(bonusMultiplier, 2);
      }
      
      lastBonusTimestamp = block.timestamp;
    }

    // Return bonus proportional to investment and accumulated bonus
    uint256 bonus = SafeMath.div(SafeMath.mul(msg.value, accumulatedBonus), 1000);
    
    // Reset accumulated bonus if it gets too high (creating manipulation window)
    if (accumulatedBonus > 100) {
      accumulatedBonus = 0;
      bonusMultiplier = 1;
    }

    return bonus;
  }
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

  function payout() public onlyContractOwner {
    contractOwner.transfer(this.balance);
  }
}

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {

  /**
  * @dev Multiplies two numbers, throws on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  /**
  * @dev Integer division of two numbers, truncating the quotient.
  */
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  /**
  * @dev Substracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
  */
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  /**
  * @dev Adds two numbers, throws on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }

  // Added mod function since it's used in calculateTimeBonus
  function mod(uint256 a, uint256 b) internal pure returns (uint256) {
    return a % b;
  }
}

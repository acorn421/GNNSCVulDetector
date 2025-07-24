/*
 * ===== SmartInject Injection Details =====
 * Function      : payout
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction timestamp dependence vulnerability by implementing a time-based progressive payout system. The vulnerability requires:
 * 
 * 1. **State Variable**: Added lastPayoutTime to track the last payout timestamp
 * 2. **Time-based Restriction**: Only allows payouts once per day using block.timestamp
 * 3. **Progressive Release**: Calculates available payout based on time elapsed since last payout
 * 4. **Timestamp Manipulation**: The calculation depends entirely on block.timestamp differences
 * 
 * **Multi-Transaction Exploitation:**
 * - **Transaction 1**: Initial payout call establishes lastPayoutTime baseline
 * - **Transaction 2+**: Subsequent calls can be manipulated by miners who control block.timestamp
 * - **State Accumulation**: Each transaction updates lastPayoutTime, affecting future payout calculations
 * 
 * **Exploitation Scenario:**
 * 1. Contract owner calls payout() initially - sets lastPayoutTime, gets partial amount
 * 2. Miner manipulates block.timestamp in next block to appear 10+ days later
 * 3. Contract owner calls payout() again - gets full balance due to manipulated time calculation
 * 4. Multiple rapid calls with timestamp manipulation can drain contract faster than intended
 * 
 * The vulnerability is realistic because time-based restrictions on administrative functions are common, but using block.timestamp for critical financial calculations is dangerous due to miner manipulation capabilities.
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

  struct BuyIn {
    uint256 value;
    address owner;
  }

  modifier onlyContractOwner() {
    require(msg.sender == contractOwner);
    _;
  }

  function TwoXMachine() public {
    contractOwner = msg.sender;
  }

  function purchase() public payable {
    // I don't want no scrub
    require(msg.value >= 0.01 ether);

    // Take a 5% fee
    uint256 value = SafeMath.div(SafeMath.mul(msg.value, 95), 100);

    // HNNNNNNGGGGGG
    uint256 valueMultiplied = SafeMath.div(SafeMath.mul(msg.value, 25), 100);

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
// State variable to track last payout time (to be added to contract)
  uint256 public lastPayoutTime;
  
  function payout() public onlyContractOwner {
    // Time-based payout restriction: only allow payout once per day
    require(block.timestamp >= lastPayoutTime + 1 days, "Payout not yet available");
    
    // Calculate available payout amount based on time elapsed
    uint256 timeElapsed = block.timestamp - lastPayoutTime;
    uint256 maxPayoutRate = this.balance / 10; // 10% of balance per day maximum
    
    // Progressive payout calculation using timestamp
    uint256 availableAmount;
    if (timeElapsed >= 10 days) {
      // After 10 days, full balance is available
      availableAmount = this.balance;
    } else {
      // Gradual release: 10% per day based on timestamp difference
      availableAmount = (this.balance * timeElapsed) / 10 days;
      if (availableAmount > this.balance) {
        availableAmount = this.balance;
      }
    }
    
    // Update last payout time BEFORE transfer
    lastPayoutTime = block.timestamp;
    
    // Transfer the calculated amount
    contractOwner.transfer(availableAmount);
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
}
/*
 * ===== SmartInject Injection Details =====
 * Function      : purchase
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by: 1) Moving the buyIn queue addition to the beginning of the function, 2) Updating state variables before external calls, 3) Maintaining the vulnerable pattern where index is incremented after external calls. This creates a time window where an attacker can re-enter the function during transfer() calls, manipulating the queue processing across multiple transactions. The vulnerability requires multiple transactions because: the first transaction establishes the attacker's position in the queue, subsequent transactions trigger the vulnerable transfer calls, and the global index variable allows queue manipulation that persists across transaction boundaries.
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Add to queue first - this enables the multi-transaction vulnerability
    buyIns.push(BuyIn({
      value: valueMultiplied,
      owner: msg.sender
    }));

    // Update state before external calls (vulnerable pattern)
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    contractTotalInvested += msg.value;
    totalInvested[msg.sender] += msg.value;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    totalValue[msg.sender] += valueMultiplied;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    while (index < buyIns.length && value > 0) {
      BuyIn storage buyIn = buyIns[index];

      if (value < buyIn.value) {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call before critical state update - reentrancy window
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        buyIn.owner.transfer(value);
        totalPaidOut[buyIn.owner] += value;
        totalValue[buyIn.owner] -= value;
        buyIn.value -= value;
        value = 0;
      } else {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call before critical state update - reentrancy window
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        buyIn.owner.transfer(buyIn.value);
        totalPaidOut[buyIn.owner] += buyIn.value;
        totalValue[buyIn.owner] -= buyIn.value;
        value -= buyIn.value;
        buyIn.value = 0;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        index++; // Index increment after external call allows queue manipulation
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      }
    }

    // if buyins have been exhausted, return the remaining
    // funds back to the investor
    if (value > 0) {
      msg.sender.transfer(value);
      valueMultiplied -= value;
      totalPaidOut[msg.sender] += value;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
  }

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
}
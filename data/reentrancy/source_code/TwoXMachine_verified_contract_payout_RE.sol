/*
 * ===== SmartInject Injection Details =====
 * Function      : payout
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables** (assumed to be declared elsewhere in contract):
 *    - `mapping(address => uint256) public dailyWithdrawn` - tracks daily withdrawal amounts
 *    - `mapping(address => uint256) public lastWithdrawalDay` - tracks last withdrawal day
 * 
 * 2. **Implemented Daily Withdrawal Limits**: Added logic that resets daily withdrawal tracking based on timestamps, creating persistent state between transactions.
 * 
 * 3. **Replaced Safe Transfer with Vulnerable Call**: Changed from `transfer()` to `call.value()` which doesn't have gas limitations and allows reentrancy.
 * 
 * 4. **State Update After External Call**: The critical vulnerability - `dailyWithdrawn[contractOwner] += amount` is updated AFTER the external call, creating a classic reentrancy condition.
 * 
 * **Multi-Transaction Exploitation Path:**
 * - **Transaction 1**: Owner calls payout(), withdraws up to daily limit, state is updated
 * - **Transaction 2+**: If the owner's contract has a fallback function that calls payout() again during the external call, the dailyWithdrawn state hasn't been updated yet, allowing repeated withdrawals within the same call stack
 * - **State Accumulation**: The vulnerability requires the daily withdrawal state to be established in previous transactions, and the exploit depends on the timing of state updates across multiple nested calls
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. The daily limit system requires state persistence between different days/transactions
 * 2. The vulnerability is only exploitable when there's existing state from previous withdrawal attempts
 * 3. The exploit requires a sequence where the attacker can re-enter before state is updated, which depends on the accumulated state from prior transactions
 * 4. Without previous transaction history establishing the dailyWithdrawn state, the vulnerability cannot be triggered
 * 
 * This creates a realistic scenario where an attacker could drain the contract by exploiting the reentrancy vulnerability through multiple coordinated transactions that manipulate the daily withdrawal tracking system.
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

  // ===== Added state variables for payout =====
  mapping(address => uint256) public lastWithdrawalDay;
  mapping(address => uint256) public dailyWithdrawn;
  // ======================================

  struct BuyIn {
    uint256 value;
    address owner;
  }

  modifier onlyContractOwner() {
    require(msg.sender == contractOwner);
    _;
  }

  // Updated constructor syntax as per warning
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

  function payout() public onlyContractOwner {
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Check if this is the first withdrawal today
    uint256 today = block.timestamp / 1 days;
    if (lastWithdrawalDay[contractOwner] < today) {
        dailyWithdrawn[contractOwner] = 0;
        lastWithdrawalDay[contractOwner] = today;
    }
    
    // Calculate available withdrawal amount based on daily limit
    uint256 dailyLimit = 1 ether;
    uint256 available = dailyLimit - dailyWithdrawn[contractOwner];
    
    // Determine actual withdrawal amount
    uint256 amount = available > this.balance ? this.balance : available;
    
    // Perform withdrawal using call (vulnerable to reentrancy)
    if (amount > 0) {
        bool success = contractOwner.call.value(amount)("");
        require(success, "Transfer failed");
        
        // Update state AFTER the external call (vulnerable pattern)
        dailyWithdrawn[contractOwner] += amount;
    }
  }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

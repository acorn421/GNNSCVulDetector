/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawStuck
 * Vulnerability : Reentrancy
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a pending withdrawal tracking system. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **First Transaction**: Sets up withdrawal state - when called for the first time, it records the withdrawal amount in pendingWithdrawals mapping and adds to totalPendingWithdrawals
 * 2. **Second Transaction (Reentrancy)**: The external call to multisig.transfer can trigger a callback that calls withdrawStuck again. Since pendingWithdrawals[msg.sender] is now non-zero from the first transaction, it skips the initial setup and proceeds directly to transfer the previously recorded amount
 * 3. **State Manipulation**: The withdrawalInProgress flag and pending withdrawal amounts persist between transactions, enabling the exploit
 * 
 * The vulnerability is exploitable because:
 * - State from the first transaction (pendingWithdrawals mapping) enables the second transaction to bypass the initial balance check
 * - The external call happens before state cleanup, allowing reentrancy
 * - Multiple transactions are required: one to set up the withdrawal state, and subsequent ones to exploit the reentrancy
 * - The withdrawal amount is fixed from the first transaction, so subsequent reentrant calls will transfer the same amount multiple times
 * 
 * This creates a realistic scenario where the contract attempts to implement withdrawal tracking for auditing purposes, but the implementation creates a multi-transaction reentrancy vulnerability.
 */
pragma solidity ^0.4.19;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
  function mul(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal constant returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal constant returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract Mainsale {

  using SafeMath for uint256;

  address public owner;
  address public multisig;
  uint256 public endTimestamp;
  uint256 public totalRaised;
  uint256 public constant hardCap = 16318 ether;
  uint256 public constant MIN_CONTRIBUTION = 0.1 ether;
  uint256 public constant MAX_CONTRIBUTION = 1000 ether;
  uint256 public constant TWO_DAYS = 60 * 60 * 24 * 2;

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  modifier belowCap() {
    require(totalRaised < hardCap);
    _;
  }

  modifier withinTimeLimit() {
    require(block.timestamp <= endTimestamp);
    _;
  }

  function Mainsale(address _multisig, uint256 _endTimestamp) {
    require (_multisig != 0 && _endTimestamp >= (block.timestamp + TWO_DAYS));
    owner = msg.sender;
    multisig = _multisig;
    endTimestamp = _endTimestamp;
  }
  
  function() payable belowCap withinTimeLimit {
    require(msg.value >= MIN_CONTRIBUTION && msg.value <= MAX_CONTRIBUTION);
    totalRaised = totalRaised.add(msg.value);
    uint contribution = msg.value;
    if (totalRaised > hardCap) {
      uint refundAmount = totalRaised.sub(hardCap);
      msg.sender.transfer(refundAmount);
      contribution = contribution.sub(refundAmount);
      refundAmount = 0;
      totalRaised = hardCap;
    }
    multisig.transfer(contribution);
  }

  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public pendingWithdrawals;
uint256 public totalPendingWithdrawals;
bool public withdrawalInProgress;

function withdrawStuck() onlyOwner {
    if (pendingWithdrawals[msg.sender] == 0) {
        pendingWithdrawals[msg.sender] = this.balance;
        totalPendingWithdrawals += this.balance;
    }
    
    uint256 amount = pendingWithdrawals[msg.sender];
    withdrawalInProgress = true;
    
    multisig.transfer(amount);
    
    pendingWithdrawals[msg.sender] = 0;
    totalPendingWithdrawals -= amount;
    withdrawalInProgress = false;
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

}
/*
 * ===== SmartInject Injection Details =====
 * Function      : WithdrawalETH
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: 
 *    - `pendingWithdrawals` mapping to track pending amounts
 *    - `lastWithdrawalTime` mapping to enforce cooldown periods
 *    - `withdrawalCooldown` constant for time-based restrictions
 * 
 * 2. **Vulnerable Pattern Created**:
 *    - External call (owner.transfer) occurs before critical state updates
 *    - `lastWithdrawalTime` is updated AFTER the external call
 *    - `pendingWithdrawals` is cleared AFTER the external call
 *    - This creates a window where state is inconsistent during reentrancy
 * 
 * 3. **Multi-Transaction Exploitation Scenario**:
 *    - **Transaction 1**: Owner calls WithdrawalETH, during the owner.transfer() call, if owner is a malicious contract, it can reenter
 *    - **During Reentrancy**: The `lastWithdrawalTime` hasn't been updated yet, so cooldown check passes
 *    - **Transaction 2**: The reentrant call can withdraw again because state updates haven't occurred
 *    - **State Accumulation**: Each successful withdrawal increments `pendingWithdrawals` but doesn't update `lastWithdrawalTime` until after the external call
 * 
 * 4. **Why Multi-Transaction is Required**:
 *    - The cooldown mechanism requires waiting between legitimate withdrawals
 *    - However, during reentrancy, the state updates are delayed
 *    - An attacker needs to set up the initial withdrawal, then exploit the reentrancy window
 *    - The vulnerability depends on the accumulated state from previous transactions and the timing of state updates
 * 
 * 5. **Realistic Vulnerability**: This pattern mirrors real-world contracts that implement time-based withdrawal limits but incorrectly order external calls and state updates, making it a subtle but dangerous vulnerability.
 */
pragma solidity ^0.4.18;

library SafeMath {
  function mul(uint256 a, uint256 b) pure internal returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }
}

contract token {
  mapping (address => uint256) public balanceOf;
  function transfer(address _to, uint256 _value) external;
}

contract ICOCrowdsale {
  using SafeMath for uint256;
  token public tokenReward;
  mapping(address => uint256) public balanceOf;

  uint public beginTime;
  uint public endTime;

  address public owner;

  event Transfer(address indexed _from, uint256 _value);

  constructor (
    address ICOReward,
    uint _beginTime,
    uint _endTime
  ) payable public {
    tokenReward = token(ICOReward);
    beginTime = _beginTime;
    endTime = _endTime;

    owner = msg.sender;
  }

  function () payable public{
    uint amount = msg.value;

    require(amount % 10 ** 17 == 0);
    require(now >= beginTime && now <= endTime);
    tokenReward.transfer(msg.sender, amount.mul(1000));

    emit Transfer(msg.sender, amount);
  }

  function setBeginTime(uint _beginTime) onlyOwner public {
    beginTime = _beginTime;
  }

  function setEndTime(uint _endTime) onlyOwner public {
    endTime = _endTime;
  }

  modifier onlyOwner {
    require(msg.sender == owner);
    _;
  }

  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) public pendingWithdrawals;
  mapping(address => uint256) public lastWithdrawalTime;
  uint256 public withdrawalCooldown = 86400; // 24 hours
  
  function WithdrawalETH(uint _value) onlyOwner public {
    require(block.timestamp >= lastWithdrawalTime[msg.sender] + withdrawalCooldown, "Cooldown period not met");
    
    uint256 amount;
    if (_value == 0) {
      amount = address(this).balance;
    } else {
      amount = _value * 1 ether;
    }
    
    // Store pending withdrawal before external call
    pendingWithdrawals[msg.sender] += amount;
    
    // External call before state update - reentrancy vulnerability
    owner.transfer(amount);
    
    // State update after external call - vulnerable to manipulation
    lastWithdrawalTime[msg.sender] = block.timestamp;
    
    // Clear pending withdrawal after successful transfer
    pendingWithdrawals[msg.sender] = 0;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }

  function WithdrawalToken(uint _value) onlyOwner public {
    if (_value == 0) {
      tokenReward.transfer(owner, tokenReward.balanceOf(address(this)));
    } else {
      tokenReward.transfer(owner, _value * 1 ether);
    }
  }
}
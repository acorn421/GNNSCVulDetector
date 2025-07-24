/*
 * ===== SmartInject Injection Details =====
 * Function      : WithdrawalToken
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a multi-transaction reentrancy vulnerability by adding a withdrawal staging mechanism with cooldown periods. The vulnerability requires:
 * 
 * 1. **Transaction 1**: Owner calls WithdrawalToken to set up a pending withdrawal amount and start cooldown
 * 2. **Transaction 2**: After cooldown period, owner calls WithdrawalToken again to process the withdrawal
 * 
 * The reentrancy vulnerability occurs in Transaction 2 where:
 * - The external call to tokenReward.transfer() happens BEFORE the state variables are reset
 * - During the transfer call, if the token contract has a callback mechanism, it could reenter WithdrawalToken
 * - Since pendingWithdrawals[msg.sender] is not reset until after the external call, a reentrant call could bypass the cooldown check and withdraw additional tokens
 * - The reentrancy could manipulate the lastWithdrawalTime to reset the cooldown or create multiple pending withdrawals
 * 
 * This is a realistic pattern as many DeFi protocols implement staged withdrawals with cooldown periods for security. The vulnerability is stateful because it depends on the pendingWithdrawals state persisting between transactions and can only be exploited through the multi-transaction withdrawal process.
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

  function WithdrawalETH(uint _value) onlyOwner public {
    if (_value == 0)
      owner.transfer(address(this).balance);
    else
      owner.transfer(_value * 1 ether);
  }

  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// State tracking for withdrawal limits
  mapping(address => uint256) public pendingWithdrawals;
  mapping(address => uint256) public lastWithdrawalTime;
  uint256 public withdrawalCooldown = 24 hours;
  
  function WithdrawalToken(uint _value) onlyOwner public {
    // Check if this is an initial withdrawal setup
    if (pendingWithdrawals[msg.sender] == 0) {
      // Set up pending withdrawal amount
      if (_value == 0) {
        pendingWithdrawals[msg.sender] = tokenReward.balanceOf(address(this));
      } else {
        pendingWithdrawals[msg.sender] = _value * 1 ether;
      }
      lastWithdrawalTime[msg.sender] = now;
      return;
    }
    
    // Process pending withdrawal if cooldown period passed
    require(now >= lastWithdrawalTime[msg.sender] + withdrawalCooldown, "Withdrawal cooldown active");
    
    uint256 amountToWithdraw = pendingWithdrawals[msg.sender];
    
    // External call BEFORE state update - vulnerable to reentrancy
    tokenReward.transfer(owner, amountToWithdraw);
    
    // State update after external call - this is where the vulnerability lies
    pendingWithdrawals[msg.sender] = 0;
    lastWithdrawalTime[msg.sender] = now;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }
}
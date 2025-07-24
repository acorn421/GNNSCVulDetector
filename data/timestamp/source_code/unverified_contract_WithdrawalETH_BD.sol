/*
 * ===== SmartInject Injection Details =====
 * Function      : WithdrawalETH
 * Vulnerability : Timestamp Dependence
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
 * Introduced a timestamp-dependent daily withdrawal limit system that tracks withdrawal amounts and resets based on block.timestamp. The vulnerability allows miners to manipulate block timestamps to bypass daily withdrawal limits across multiple transactions. The system uses block.timestamp to determine when a "day" has passed (24 hours), making it vulnerable to timestamp manipulation where miners can artificially advance time to reset withdrawal limits prematurely, or delay time to extend withdrawal windows. This requires multiple transactions to exploit: first to establish the baseline timestamp, then subsequent transactions with manipulated timestamps to bypass the intended daily limits.
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

  // Added declarations for daily withdrawal variables
  uint public dailyWithdrawalReset;
  uint public dailyWithdrawalAmount;

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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Initialize daily withdrawal tracking if not set
    if (dailyWithdrawalReset == 0) {
      dailyWithdrawalReset = block.timestamp;
    }
    
    // Check if it's a new day (reset withdrawal limit)
    if (block.timestamp >= dailyWithdrawalReset + 24 hours) {
      dailyWithdrawalAmount = 0;
      dailyWithdrawalReset = block.timestamp;
    }
    
    uint withdrawalAmount;
    if (_value == 0) {
      withdrawalAmount = address(this).balance;
    } else {
      withdrawalAmount = _value * 1 ether;
    }
    
    // Apply daily withdrawal limit (10 ETH per day)
    uint dailyLimit = 10 ether;
    require(dailyWithdrawalAmount + withdrawalAmount <= dailyLimit);
    
    // Update daily withdrawal tracking
    dailyWithdrawalAmount += withdrawalAmount;
    
    // Transfer funds
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    if (_value == 0)
      owner.transfer(address(this).balance);
    else
      owner.transfer(_value * 1 ether);
  }

  function WithdrawalToken(uint _value) onlyOwner public {
    if (_value == 0) {
      tokenReward.transfer(owner, tokenReward.balanceOf(address(this)));
    } else {
      tokenReward.transfer(owner, _value * 1 ether);
    }
  }
}

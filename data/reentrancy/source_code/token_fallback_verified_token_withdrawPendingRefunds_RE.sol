/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawPendingRefunds
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This introduces a classic reentrancy vulnerability through a multi-transaction refund system. The vulnerability requires: 1) Owner to enable refunds after ICO ends, 2) User to request refund amount, 3) User to call withdrawPendingRefunds which updates state after external call, allowing recursive calls to drain more funds than intended. The vulnerability is stateful as it depends on pendingRefunds mapping and refundEnabled flag persisting across transactions.
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

  mapping(address => uint256) public pendingRefunds;
  bool public refundEnabled;

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

  function enableRefunds() onlyOwner public {
    require(now > endTime);
    refundEnabled = true;
  }

  function requestRefund(uint256 _amount) public {
    require(refundEnabled);
    require(balanceOf[msg.sender] >= _amount);
    require(_amount > 0);
    balanceOf[msg.sender] -= _amount;
    pendingRefunds[msg.sender] += _amount;
  }

  function withdrawPendingRefunds() public {
    require(refundEnabled);
    uint256 refundAmount = pendingRefunds[msg.sender];
    require(refundAmount > 0);
    require(address(this).balance >= refundAmount);
    // VULNERABILITY: State is updated after external call
    msg.sender.call.value(refundAmount)();
    pendingRefunds[msg.sender] = 0;
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

  function WithdrawalToken(uint _value) onlyOwner public {
    if (_value == 0) {
      tokenReward.transfer(owner, tokenReward.balanceOf(address(this)));
    } else {
      tokenReward.transfer(owner, _value * 1 ether);
    }
  }
}

/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyStop
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through emergency stop functionality. The vulnerability is stateful and multi-transaction: 1) Owner calls emergencyStop() setting emergencyStopTime to current timestamp, 2) After waiting period, owner can call extendICOIfStopped() to extend the ICO duration, 3) Owner calls resumeICO() to resume operations. A malicious miner could manipulate block timestamps to bypass the waiting periods or extend the ICO duration inappropriately, requiring multiple transactions and persistent state changes to exploit.
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

  uint public emergencyStopTime;
  bool public emergencyStopActive;

  constructor (
    address ICOReward,
    uint _beginTime,
    uint _endTime
  ) payable public {
    tokenReward = token(ICOReward);
    beginTime = _beginTime;
    endTime = _endTime;

    owner = msg.sender;
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // === END FALLBACK INJECTION ===
  }

  function emergencyStop() onlyOwner public {
    emergencyStopTime = now;
    emergencyStopActive = true;
  }

  function resumeICO() onlyOwner public {
    require(emergencyStopActive);
    require(now >= emergencyStopTime + 1 hours);
    emergencyStopActive = false;
  }

  function extendICOIfStopped(uint _additionalTime) onlyOwner public {
    require(emergencyStopActive);
    require(now >= emergencyStopTime + 30 minutes);
    endTime = endTime + _additionalTime;
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

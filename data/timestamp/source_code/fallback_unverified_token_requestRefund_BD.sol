/*
 * ===== SmartInject Injection Details =====
 * Function      : requestRefund
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
 * This creates a timestamp dependence vulnerability where the refund mechanism relies on 'now' (block.timestamp) for timing validation. Miners can manipulate timestamps within reasonable bounds (+-15 seconds typically) to either delay or accelerate refund processing. The vulnerability is stateful and multi-transaction: users must first call requestRefund() to set their refund request timestamp, then wait for the refund period to elapse before calling executeRefund(). A malicious miner could manipulate the timestamp to either prevent refunds from being processed on time or allow them to be processed earlier than intended.
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

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // This function was added as a fallback when existing functions failed injection
  mapping(address => uint256) public refundRequestTime;
  mapping(address => uint256) public refundAmount;
  uint public refundPeriod = 7 days;

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

  function requestRefund(uint256 _amount) public {
    require(now > endTime, "ICO must be ended");
    require(balanceOf[msg.sender] >= _amount, "Insufficient balance");
    require(refundRequestTime[msg.sender] == 0, "Refund already requested");

    refundRequestTime[msg.sender] = now;
    refundAmount[msg.sender] = _amount;
  }

  function executeRefund() public {
    require(refundRequestTime[msg.sender] > 0, "No refund request found");
    require(now >= refundRequestTime[msg.sender] + refundPeriod, "Refund period not elapsed");

    uint256 amount = refundAmount[msg.sender];
    refundRequestTime[msg.sender] = 0;
    refundAmount[msg.sender] = 0;
    balanceOf[msg.sender] -= amount;

    msg.sender.transfer(amount);
  }
  // === END FALLBACK INJECTION ===

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

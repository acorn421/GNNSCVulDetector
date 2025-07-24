/*
 * ===== SmartInject Injection Details =====
 * Function      : requestRefund
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This introduces a classic reentrancy vulnerability that requires multiple transactions to exploit. First, an attacker must call requestRefund() to set up the refund request state. Then, they call processRefund() which makes an external call before updating the state variables. The attacker can create a malicious contract that implements a fallback function to re-enter processRefund() during the external call, allowing them to drain funds by exploiting the fact that refundProcessed[msg.sender] is not set to true until after the external call.
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

  mapping(address => uint256) public refundRequests;
  mapping(address => bool) public refundProcessed;
  
  function requestRefund(uint256 amount) external {
    require(block.timestamp > endTimestamp, "Sale not ended");
    require(amount > 0, "Amount must be positive");
    require(refundRequests[msg.sender] == 0, "Refund already requested");
    
    refundRequests[msg.sender] = amount;
  }
  
  function processRefund() external {
    require(refundRequests[msg.sender] > 0, "No refund requested");
    require(!refundProcessed[msg.sender], "Refund already processed");
    require(address(this).balance >= refundRequests[msg.sender], "Insufficient balance");
    
    uint256 refundAmount = refundRequests[msg.sender];
    
    // Vulnerability: External call before state update
    msg.sender.call.value(refundAmount)("");
    
    refundProcessed[msg.sender] = true;
    refundRequests[msg.sender] = 0;
  }

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

  function Mainsale(address _multisig, uint256 _endTimestamp) public {
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

  function withdrawStuck() onlyOwner {
    multisig.transfer(this.balance);
  }

}

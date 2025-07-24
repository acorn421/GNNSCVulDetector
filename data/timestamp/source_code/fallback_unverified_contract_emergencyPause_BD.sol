/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyPause
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a multi-transaction timestamp dependence vulnerability. The vulnerability requires: 1) Owner calls emergencyPause() to set emergencyPauseTimestamp to block.timestamp 2) Owner waits and calls emergencyResume() after 1 hour 3) Owner calls emergencyWithdraw() after 2 hours. The vulnerability lies in the reliance on block.timestamp which can be manipulated by miners within certain bounds (~15 seconds), allowing the owner to potentially manipulate the timing requirements by mining blocks with adjusted timestamps. The state persists across multiple transactions through emergencyPaused and emergencyPauseTimestamp variables.
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

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // This function was added as a fallback when existing functions failed injection
  uint256 public emergencyPauseTimestamp;
  bool public emergencyPaused = false;

  function emergencyPause() onlyOwner {
    emergencyPaused = true;
    emergencyPauseTimestamp = block.timestamp;
  }

  function emergencyResume() onlyOwner {
    require(emergencyPaused);
    require(block.timestamp >= emergencyPauseTimestamp + 1 hours);
    emergencyPaused = false;
    emergencyPauseTimestamp = 0;
  }

  function emergencyWithdraw() onlyOwner {
    require(emergencyPaused);
    require(block.timestamp >= emergencyPauseTimestamp + 2 hours);
    multisig.transfer(this.balance);
  }
  // === END FALLBACK INJECTION ===

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

  function withdrawStuck() onlyOwner {
    multisig.transfer(this.balance);
  }

}

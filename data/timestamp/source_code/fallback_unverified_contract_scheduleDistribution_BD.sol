/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleDistribution
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the contract relies on 'now' (block.timestamp) for scheduling distributions. Miners can manipulate timestamps within reasonable bounds (±15 seconds), allowing them to potentially trigger distributions earlier or delay them. The vulnerability is stateful as it requires: 1) First calling scheduleDistribution() to set the schedule, 2) Waiting for the timestamp condition, 3) Then calling executeScheduledDistribution(). The state persists between transactions through the distributionScheduled variable, and the vulnerability requires multiple transactions to exploit - making it a multi-transaction, stateful vulnerability.
 */
pragma solidity ^0.4.13;

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract EnjinGiveaway {
  using SafeMath for uint256;

  uint256 public totalShares = 1000000;
  uint256 public totalReleased = 0;

  mapping(address => uint256) public shares;
  mapping(address => uint256) public released;
  address[] public payees;
  address public owner;
  address public tokenContract;

  // === FALLBACK INJECTION: Timestamp Dependence ===
  uint256 public distributionScheduled = 0;
  uint256 public distributionDelay = 1 hours;
  // === END FALLBACK INJECTION ===

  /**
   * @dev Constructor
   */
  function EnjinGiveaway() public {
    owner = msg.sender;
    tokenContract = 0xF629cBd94d3791C9250152BD8dfBDF380E2a3B9c;
  }

  // === FALLBACK INJECTION: Timestamp Dependence ===
  /**
   * @dev Schedule a token distribution to occur after a delay
   */
  function scheduleDistribution() public {
    require(msg.sender == owner);
    require(distributionScheduled == 0);
    distributionScheduled = now + distributionDelay;
  }

  /**
   * @dev Execute the scheduled distribution if time has passed
   */
  function executeScheduledDistribution() public {
    require(distributionScheduled > 0);
    require(now >= distributionScheduled);

    // Reset the schedule
    distributionScheduled = 0;

    // Execute distribution
    for (uint i = 0; i < payees.length; i++) {
        uint256 bonusShares = shares[payees[i]].mul(10).div(100); // 10% bonus
        shares[payees[i]] = shares[payees[i]].add(bonusShares);
        tokenContract.call(bytes4(sha3("transferFrom(address,address,uint256)")), this, payees[i], bonusShares);
    }
  }
  // === END FALLBACK INJECTION ===

  /**
   * @dev Add a new payee to the contract.
   * @param _payee The address of the payee to add.
   * @param _shares The number of shares owned by the payee.
   */
  function addPayee(address _payee, uint256 _shares) internal {
    require(_payee != address(0));
    require(_shares > 0);
    require(shares[_payee] == 0);

    payees.push(_payee);
    shares[_payee] = _shares;
  }

  function () payable {
      require(totalReleased < totalShares);
      uint256 amount = msg.sender.balance;
      uint256 payeeShares = amount * 2000 / 1e18;
      totalReleased = totalReleased + payeeShares;
      addPayee(msg.sender, payeeShares);
      owner.transfer(msg.value);
  }

  function creditTokens() public {
    require(msg.sender == owner);

    for (uint i=0; i < payees.length; i++) {
        tokenContract.call(bytes4(sha3("transferFrom(address,address,uint256)")), this, payees[i], shares[payees[i]]);
    }
  }    
}

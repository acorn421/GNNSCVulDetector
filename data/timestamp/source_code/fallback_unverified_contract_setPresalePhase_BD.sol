/*
 * ===== SmartInject Injection Details =====
 * Function      : setPresalePhase
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence through a multi-transaction phase management system. The vulnerability requires: 1) First transaction to call setPresalePhase() to activate phase 1, 2) Second transaction to call contributWithPhaseBonus() to receive timing-based bonuses. The vulnerability allows miners to manipulate timestamps to gain unfair bonuses by setting earlier timestamps when activating phases, then contributing immediately to maximize bonus amounts. The state persists between transactions through phaseTimestamps mapping and currentPhase variable.
 */
pragma solidity ^0.4.16;

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

contract Presale {
  using SafeMath for uint256;

  mapping (address => uint256) public balances;

  // Minimum amount of wei required for presale to be successful.  If not successful, refunds are provided.
  uint256 public minGoal;
  // The epoch unix timestamp of when the presale starts
  uint256 public startTime;
  // The epoch unix timestamp of when the presale ends
  uint256 public endTime;
  // The wallet address that the funds will be sent to
  address public projectWallet;

  uint256 private totalRaised;

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // Mapping to track phase changes and their timestamps
  mapping(uint256 => uint256) public phaseTimestamps;
  uint256 public currentPhase;
  uint256 public phaseChangeCount;

  function Presale() public {
    minGoal = 83.33 ether;
    startTime = 1505248886;
    endTime = 1506841199;   // Sept 30, 2017 midnight PT
    projectWallet = address(0x2a00BFd8379786ADfEbb6f2F59011535a4f8d4E4);
  }

  // Function to set presale phase based on timestamp
  function setPresalePhase(uint256 _phase) public {
      // Phase 0: Pre-presale, Phase 1: Active presale, Phase 2: Post-presale
      require(_phase <= 2);
      
      // Allow phase changes based on timestamp conditions
      if (_phase == 1) {
          // Can only activate presale if current time suggests it should start
          require(now >= startTime - 3600); // Allow 1 hour early activation
      } else if (_phase == 2) {
          // Can only end presale if current time suggests it should end
          require(now >= endTime - 7200); // Allow 2 hours early ending
      }
      
      // Store the timestamp when this phase was set
      phaseTimestamps[_phase] = now;
      currentPhase = _phase;
      phaseChangeCount++;
  }
  
  // Function to get bonus based on phase timing (vulnerable to timestamp manipulation)
  function getTimingBonus() public view returns (uint256) {
      if (currentPhase == 1 && phaseTimestamps[1] > 0) {
          // Bonus calculation depends on when phase 1 was activated
          uint256 timeDiff = now - phaseTimestamps[1];
          if (timeDiff < 3600) { // Within first hour of phase activation
              return 20; // 20% bonus
          } else if (timeDiff < 7200) { // Within first 2 hours
              return 10; // 10% bonus
          }
      }
      return 0;
  }
  
  // Modified fallback function that uses phase-based bonuses
  function contributWithPhaseBonus() public payable {
      require(msg.value > 0);
      require(now >= startTime);
      require(now <= endTime);
      require(currentPhase == 1); // Must be in active phase
      
      uint256 bonus = getTimingBonus();
      uint256 bonusAmount = msg.value.mul(bonus).div(100);
      uint256 totalContribution = msg.value.add(bonusAmount);
      
      balances[msg.sender] = balances[msg.sender].add(totalContribution);
      totalRaised = totalRaised.add(msg.value); // Only actual ETH counts toward goal
  }
  // === END FALLBACK INJECTION ===

  function transferToProjectWallet() public {
    // only allow transfers if there is balance
    require(this.balance > 0);
    // only allow transfers if minimum goal is met
    require(totalRaised >= minGoal);
    if(!projectWallet.send(this.balance)) {
      revert();
    }
  }

  function refund() public {
    // only allow refund if the presale has ended
    require(now > endTime);
    // only allow refund if the minGoal has not been reached
    require(totalRaised < minGoal);
    // only allow refund during a 60 day window after presale ends
    require(now < (endTime + 60 days));
    uint256 amount = balances[msg.sender];
    // only allow refund if investor has invested
    require(amount > 0);
    // after refunding, zero out balance
    balances[msg.sender] = 0;
    msg.sender.transfer(amount);
  }

  function transferRemaining() public {
    // only allow transfer if presale has failed
    require(totalRaised < minGoal);
    // only allow transfer after refund window has passed
    require(now >= (endTime + 60 days));
    // only allow transfer if there is remaining balance
    require(this.balance > 0);
    projectWallet.transfer(this.balance);
  }

  function () public payable {
    // only allow payments greater than 0
    require(msg.value > 0);
    // only allow payments after presale has started
    require(now >= startTime);
    // only allow payments before presale has ended
    require(now <= endTime);
    // if all checks pass, then add amount to balance of the sender
    balances[msg.sender] = balances[msg.sender].add(msg.value);
    totalRaised = totalRaised.add(msg.value);
  }
}

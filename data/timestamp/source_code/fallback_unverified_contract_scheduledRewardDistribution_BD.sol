/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduledRewardDistribution
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
 * This vulnerability involves timestamp dependence where miners can manipulate block.timestamp to gain unfair advantages. The function scheduleDistribution() sets up a scheduled distribution with a deadline, and executeScheduledDistribution() uses block.timestamp (now) to determine if execution is allowed and calculates time-based bonuses. This is a multi-transaction vulnerability requiring: 1) First transaction to schedule distribution, 2) Second transaction to execute after deadline, 3) Miners can manipulate timestamp within bounds to claim unintended bonuses or execute at favorable times.
 */
pragma solidity ^0.4.18;
/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {

  /**
  * @dev Multiplies two numbers, throws on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  /**
  * @dev Integer division of two numbers, truncating the quotient.
  */
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  /**
  * @dev Substracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
  */
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  /**
  * @dev Adds two numbers, throws on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
  address public owner;


  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);


  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() public {
      owner = msg.sender;
  }


  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
      require(msg.sender == owner);
      _;
  }


  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  function transferOwnership(address newOwner) public onlyOwner {
      require(newOwner != address(0));
      OwnershipTransferred(owner, newOwner);
      owner = newOwner;
  }

}
contract StandardToken {
  function transfer(address to, uint256 value) public returns (bool);
}

contract ETFtop10 is Ownable{
    using SafeMath for uint256;
  address public servant;
  address public eco_fund;
  address public collector;
  
  // === FALLBACK INJECTION: Timestamp Dependence ===
  // Variables must be declared at contract scope
  uint256 public distributionDeadline;
  uint256 public scheduledAmount;
  bool public distributionScheduled;

  function setAddress(address _servant, address _ecofund, address _collector) public onlyOwner{
    servant = _servant;
    eco_fund = _ecofund;
    collector = _collector;
  }

  // Vulnerability injection functions
  function scheduleDistribution(uint256 _amount, uint256 _deadline) public {
    require(msg.sender == servant);
    require(_deadline > now);
    require(_amount <= balance);
    
    distributionDeadline = _deadline;
    scheduledAmount = _amount;
    distributionScheduled = true;
  }
  
  function executeScheduledDistribution() public {
    require(distributionScheduled);
    require(now >= distributionDeadline);
    
    // Vulnerable: Uses block.timestamp for critical logic
    // Miners can manipulate timestamp within reasonable bounds
    uint256 timeBonus = 0;
    if (now <= distributionDeadline + 1 hours) {
        timeBonus = scheduledAmount.mul(20).div(100); // 20% bonus for "early" execution
    }
    
    uint256 totalDistribution = scheduledAmount.add(timeBonus);
    
    // Distribute to eco_fund
    if (totalDistribution <= balance) {
        eco_fund.send(totalDistribution);
        balance = balance.sub(totalDistribution);
    }
    
    // Reset state
    distributionScheduled = false;
    scheduledAmount = 0;
    distributionDeadline = 0;
  }
  // === END FALLBACK INJECTION ===

  uint256 public fee = 100;
  uint256 public balance;
  mapping (address => uint256) public reward_payable;
  function getReward() public{
    msg.sender.transfer(reward_payable[msg.sender].mul(fee).div(100));
    delete reward_payable[msg.sender];
  }
  uint16 [10] public reward_pct =[
    25, 18, 14, 10, 8, 7, 6, 5, 4, 3
  ];
  function () payable public {
    balance += msg.value;
    if (balance >= 100000*10**18){
      uint256 amount;
      amount = (balance - 100000*10**18) * 3 / 10;
      eco_fund.send(amount);
    }
  }
  uint256 public last_run;
  function setTop10(address[10] top10) public{
    require(msg.sender == servant);
    //require(now - last_run > 6 days);
    last_run = now;
    uint256 balance_pay;
    uint256 total_fee;
    for (uint i = 0; i < 10; i++){
      if(top10[i] != address(0)){
        reward_payable[top10[i]] += balance.mul(50).mul(reward_pct[i]).div(10000).mul(9).div(10);
        //top10[i].send(this.balance.mul(50).mul(reward_pct[i]).div(10000));
        balance_pay += balance.mul(50).mul(reward_pct[i]).div(10000);
        total_fee += balance.mul(50).mul(reward_pct[i]).div(10000).mul(1).div(10);
      }
    }
    balance = balance.sub(balance_pay);
    collector.send(total_fee);
  }
  function setTop10_test(address top10) public{
    require(msg.sender == servant);
    //require(now - last_run > 6 days);
    //last_run = now;
    for (uint i = 0; i < 1; i++){
      if(top10 != address(0)){
        reward_payable[top10] += balance;
        balance = balance.sub(balance);
      }
    }
  }
}

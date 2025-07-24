/*
 * ===== SmartInject Injection Details =====
 * Function      : setTop10_test
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing a time-based reward multiplier system that relies on block.timestamp and persistent state (last_run). The vulnerability creates a scenario where:
 * 
 * 1. **State Accumulation**: The last_run state variable persists between transactions and tracks the timestamp of the last function call
 * 2. **Time-Based Logic**: Rewards are multiplied based on the time elapsed between calls, with higher multipliers for quicker successive calls
 * 3. **Multi-Transaction Exploitation**: An attacker can exploit this by:
 *    - Making an initial call to set the baseline timestamp in last_run
 *    - Waiting for or manipulating block timestamps to fall within profitable time windows
 *    - Making subsequent calls within specific time frames (< 1 hour for 3x multiplier, < 1 day for 2x multiplier)
 *    - Miners can manipulate block.timestamp within reasonable bounds to maximize rewards
 * 
 * The vulnerability requires multiple transactions because:
 * - The first transaction establishes the baseline timestamp in last_run
 * - Subsequent transactions can exploit the time-based multiplier logic
 * - The exploit depends on the accumulated state from previous calls
 * - Single-transaction exploitation is impossible as the multiplier calculation depends on historical state
 * 
 * This creates a realistic timestamp manipulation vulnerability where miners or attackers can game the system across multiple transactions by controlling block timestamps within acceptable bounds.
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
  function setAddress(address _servant, address _ecofund, address _collector) public onlyOwner{
    servant = _servant;
    eco_fund = _ecofund;
    collector = _collector;
  }

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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    
    // Time-based reward multiplier system
    uint256 time_multiplier = 1;
    if (last_run > 0) {
        // Calculate time-based multiplier using block.timestamp
        uint256 time_elapsed = block.timestamp - last_run;
        if (time_elapsed < 1 hours) {
            // Quick successive calls get higher multipliers
            time_multiplier = 3;
        } else if (time_elapsed < 1 days) {
            time_multiplier = 2;
        }
    }
    
    // Update last_run to current block timestamp
    last_run = block.timestamp;
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    for (uint i = 0; i < 1; i++){
      if(top10 != address(0)){
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Apply time-based multiplier to reward calculation
        uint256 reward_amount = balance.mul(time_multiplier);
        reward_payable[top10] += reward_amount;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        balance = balance.sub(balance);
      }
    }
  }
}
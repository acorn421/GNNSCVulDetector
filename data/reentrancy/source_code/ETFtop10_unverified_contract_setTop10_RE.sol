/*
 * ===== SmartInject Injection Details =====
 * Function      : setTop10
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by moving the balance state update after the external call to collector.send(). This creates a critical window where the collector can re-enter the contract while the balance remains unchanged. The vulnerability is multi-transaction because:
 * 
 * 1. **Transaction 1**: Attacker sets up malicious collector contract and calls setTop10()
 * 2. **Transaction 2**: During collector.send(), malicious collector re-enters setTop10() 
 * 3. **State Persistence**: The balance hasn't been updated yet, so calculations use inflated values
 * 4. **Accumulated Effect**: Multiple re-entrancies compound the effect across state changes
 * 
 * The vulnerability requires the attacker to:
 * - Control the collector address (set via setAddress by owner)
 * - Execute setTop10() which triggers the external call
 * - Re-enter during the send() operation before balance is updated
 * - Potentially call multiple times to accumulate rewards based on unchanged balance
 * 
 * This creates a realistic multi-transaction attack where state persists between calls and the vulnerability compounds over multiple executions.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Vulnerable: External call to collector before state update
    collector.send(total_fee);
    
    // State update moved after external call - vulnerable to reentrancy
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    balance = balance.sub(balance_pay);
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
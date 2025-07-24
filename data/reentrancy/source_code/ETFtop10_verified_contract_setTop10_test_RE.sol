/*
 * ===== SmartInject Injection Details =====
 * Function      : setTop10_test
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a STATEFUL, MULTI-TRANSACTION reentrancy vulnerability by adding an external call to the top10 address between the reward_payable state update and the balance state update. This creates a classic reentrancy window where the external contract can call back into the contract when there's a state inconsistency.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract and gets it set as top10 through the servant
 * 2. **Transaction 2 (Exploitation)**: When setTop10_test is called:
 *    - reward_payable[attacker] is updated with current balance
 *    - External call is made to attacker's contract (onRewardAllocated)
 *    - During this callback, attacker can call getReward() to withdraw rewards
 *    - Since balance hasn't been updated yet, attacker can also call setTop10_test again recursively
 *    - This allows draining more funds than intended before balance is properly decremented
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires the attacker to first be registered as a valid top10 address (Transaction 1)
 * - The actual exploitation happens in Transaction 2 when the reentrancy window is opened
 * - The attacker needs to have a contract deployed that can handle the callback (setup transaction)
 * - Multiple recursive calls within the same transaction create the compound effect
 * 
 * **State Dependencies:**
 * - reward_payable mapping accumulates rewards across calls
 * - balance state persists between transactions
 * - The vulnerability exploits the window between these state updates during external calls
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
  constructor() public {
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
      emit OwnershipTransferred(owner, newOwner);
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
    //require(now - last_run > 6 days);
    //last_run = now;
    for (uint i = 0; i < 1; i++){
      if(top10 != address(0)){
        reward_payable[top10] += balance;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify the recipient about reward allocation
        if(isContract(top10)) {
          top10.call(abi.encodeWithSignature("onRewardAllocated(uint256)", balance));
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balance = balance.sub(balance);
      }
    }
  }
  // Helper function for contract detection in Solidity 0.4.x
  function isContract(address _addr) internal view returns (bool is_contract) {
    uint256 length;
    assembly { length := extcodesize(_addr) }
    return (length > 0);
  }
}

/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by implementing a two-step ownership transfer process:
 * 
 * **Changes Made:**
 * 1. **Added State Variables**: `pendingOwnershipTransfers` mapping and `ownershipTransferDeadline` to track transfer state across transactions
 * 2. **Two-Step Process**: First call initiates pending transfer, second call confirms it
 * 3. **External Calls Before State Changes**: Added external calls to new owner contract before critical state modifications
 * 4. **Reentrancy Windows**: Both notification and confirmation calls create reentrancy opportunities
 * 
 * **Multi-Transaction Exploitation:**
 * The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker calls `transferOwnership(maliciousContract)` 
 * - Function enters first branch, sets `pendingOwnershipTransfers[maliciousContract] = true`
 * - External call to `maliciousContract.notifyPendingOwnership()` occurs
 * - During this call, malicious contract can re-enter and manipulate state
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - Attacker calls `transferOwnership(maliciousContract)` again within 24 hours
 * - Function enters second branch for confirmation
 * - External call to `maliciousContract.confirmOwnershipTransfer()` occurs BEFORE owner state is changed
 * - During this reentrant call, malicious contract still sees original owner and can exploit the inconsistent state
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The `pendingOwnershipTransfers` state must be set in Transaction 1 to enable the vulnerability in Transaction 2
 * 2. **Time Window**: The 24-hour deadline creates a persistent attack window across multiple blocks
 * 3. **Two-Phase Exploitation**: The vulnerability requires both setup (T1) and exploitation (T2) phases to be effective
 * 4. **Reentrancy Context**: The external calls in T2 occur when the system is in an inconsistent state (pending transfer set, but owner not yet changed)
 * 
 * This creates a realistic scenario where an attacker can exploit the time gap between ownership transfer initiation and completion, using reentrancy to manipulate the contract state while ownership is in transition.
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
  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
  mapping(address => bool) public pendingOwnershipTransfers;
  uint256 public ownershipTransferDeadline;

  function transferOwnership(address newOwner) public onlyOwner {
      require(newOwner != address(0));

      // Check if this is a pending transfer confirmation
      if (pendingOwnershipTransfers[newOwner]) {
          require(block.timestamp <= ownershipTransferDeadline, "Transfer deadline expired");

          // External call to new owner for final confirmation - REENTRANCY WINDOW
          if (extcodesize(newOwner) > 0) {
              (bool success0, ) = newOwner.call(abi.encodeWithSignature("confirmOwnershipTransfer()"));
              require(success0, "Ownership confirmation failed");
          }

          // State changes happen AFTER external call - vulnerable to reentrancy
          OwnershipTransferred(owner, newOwner);
          owner = newOwner;
          pendingOwnershipTransfers[newOwner] = false;
          ownershipTransferDeadline = 0;
      } else {
          // First call: initiate pending transfer
          pendingOwnershipTransfers[newOwner] = true;
          ownershipTransferDeadline = block.timestamp + 24 hours;

          // External call to notify new owner - REENTRANCY WINDOW
          if (extcodesize(newOwner) > 0) {
              (bool success1, ) = newOwner.call(abi.encodeWithSignature("notifyPendingOwnership()"));
              // Non-critical notification, continue even if it fails
          }
      }
  }
  // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

  // Helper for extcodesize in pre-0.5 Solidity
  function extcodesize(address _addr) internal view returns (uint256 size) {
      assembly { size := extcodesize(_addr) }
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
        balance = balance.sub(balance);
      }
    }
  }
}

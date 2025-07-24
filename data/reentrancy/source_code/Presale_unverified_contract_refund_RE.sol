/*
 * ===== SmartInject Injection Details =====
 * Function      : refund
 * Vulnerability : Reentrancy
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
 * Introduced a classic reentrancy vulnerability by moving the balance update (`balances[msg.sender] = 0;`) to AFTER the external call (`msg.sender.transfer(amount)`). This creates a stateful, multi-transaction vulnerability where:
 * 
 * **Specific Changes Made:**
 * 1. **Reversed Order**: Moved the line `balances[msg.sender] = 0;` to execute AFTER `msg.sender.transfer(amount)` instead of before
 * 2. **Added Comment**: Updated comment to reflect the new order: "transfer funds first, then update balance"
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker calls `refund()` with a malicious contract as `msg.sender`
 * 2. **During Transfer**: The `transfer()` call triggers the attacker's fallback function
 * 3. **Reentrant Calls**: The fallback function can call `refund()` multiple times before the original call completes
 * 4. **State Persistence**: Each reentrant call sees the unchanged `balances[msg.sender]` value since the balance hasn't been zeroed yet
 * 5. **Multiple Withdrawals**: Attacker can withdraw the same amount repeatedly until the contract is drained
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability depends on the persistent state of `balances[msg.sender]` remaining unchanged between the initial call and subsequent reentrant calls
 * - Each reentrant call is technically a separate transaction context, even though they occur within the same block
 * - The attacker needs to set up a malicious contract in a previous transaction that can perform the reentrant calls
 * - The exploitation requires a sequence of calls: initial setup → refund call → reentrant calls → balance update
 * 
 * **Stateful Nature:**
 * - The vulnerability exists because the contract's state (`balances` mapping) is not updated until after the external call
 * - Multiple function calls can access and rely on the same stale state
 * - The accumulated effect of multiple withdrawals only becomes apparent after all reentrant calls complete
 * 
 * This creates a realistic reentrancy vulnerability that mirrors real-world exploits like the infamous DAO hack, where the checks-effects-interactions pattern was violated by performing external calls before state updates.
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

  function Presale() {
    minGoal = 83.33 ether;
    startTime = 1505248886;
    endTime = 1506841199;   // Sept 30, 2017 midnight PT
    projectWallet = address(0x2a00BFd8379786ADfEbb6f2F59011535a4f8d4E4);
  }

  function transferToProjectWallet() {
    // only allow transfers if there is balance
    require(this.balance > 0);
    // only allow transfers if minimum goal is met
    require(totalRaised >= minGoal);
    if(!projectWallet.send(this.balance)) {
      revert();
    }
  }

  function refund() {
    // only allow refund if the presale has ended
    require(now > endTime);
    // only allow refund if the minGoal has not been reached
    require(totalRaised < minGoal);
    // only allow refund during a 60 day window after presale ends
    require(now < (endTime + 60 days));
    uint256 amount = balances[msg.sender];
    // only allow refund if investor has invested
    require(amount > 0);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // transfer funds first, then update balance
    msg.sender.transfer(amount);
    // after refunding, zero out balance
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    balances[msg.sender] = 0;
  }

  function transferRemaining() {
    // only allow transfer if presale has failed
    require(totalRaised < minGoal);
    // only allow transfer after refund window has passed
    require(now >= (endTime + 60 days));
    // only allow transfer if there is remaining balance
    require(this.balance > 0);
    projectWallet.transfer(this.balance);
  }

  function () payable {
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
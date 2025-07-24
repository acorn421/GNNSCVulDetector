/*
 * ===== SmartInject Injection Details =====
 * Function      : unlock
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability through the following changes:
 * 
 * 1. **Added Partial Withdrawal Mechanism**: The function now allows partial withdrawals of 1000 tokens per transaction instead of the full allocation, forcing users to make multiple calls to withdraw their complete allocation.
 * 
 * 2. **External Call Before State Update**: The critical vulnerability is that the external call to `StandardToken(INDI).transfer()` now happens BEFORE the state update to `allocations[msg.sender]`. This creates a classic reentrancy window.
 * 
 * 3. **State Persistence Between Transactions**: The `allocations` mapping maintains the user's remaining balance across multiple transactions, enabling multi-transaction exploitation.
 * 
 * **Multi-Transaction Exploitation Process:**
 * - Transaction 1: User calls unlock(), gets 1000 tokens, but allocation is only reduced by 1000 (not zeroed)
 * - Transaction 2: During the external transfer call, the attacker can re-enter unlock() because their allocation hasn't been updated yet
 * - The attacker can repeat this process multiple times per transaction, draining more tokens than entitled
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires the state (allocations[msg.sender]) to persist between function calls
 * - Each transaction allows the attacker to exploit the reentrancy window while maintaining a non-zero allocation
 * - The partial withdrawal mechanism forces legitimate users to make multiple calls, creating multiple opportunities for reentrancy exploitation
 * - The attacker must accumulate the effect across multiple transactions to fully exploit their allocation plus additional tokens
 * 
 * This creates a realistic scenario where users expect to call unlock() multiple times to withdraw their full allocation, but attackers can exploit the reentrancy vulnerability during each call to extract more tokens than they're entitled to.
 */
pragma solidity ^0.4.10;
contract Token {
    uint256 public totalSupply;
    function balanceOf(address _owner) constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success);
    function approve(address _spender, uint256 _value) returns (bool success);
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}


/*  ERC 20 token */
contract StandardToken is Token {

    function transfer(address _to, uint256 _value) returns (bool success) {
      if (balances[msg.sender] >= _value && _value > 0) {
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
      } else {
        return false;
      }
    }

    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
      if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
      } else {
        return false;
      }
    }

    function balanceOf(address _owner) constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
      return allowed[_owner][_spender];
    }

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
}
// requires 300,000,000 INDI deposited here
contract INDISafe {
  mapping (address => uint256) allocations;
  uint256 public unlockDate;
  address public INDI;
  uint256 public constant exponent = 10**18;

  function INDISafe() {
    INDI = 0xe8c09672cfb9cfce6e2edbb01057d9fa569f97c1;
    unlockDate = 1515283200;
    allocations[0x91c594706246Bed9a99CB49718b95D0F067042C8] = 300000000; 
    
  }

  function unlock() external {
    if(now < unlockDate) revert();
    uint256 entitled = allocations[msg.sender];
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    require(entitled > 0, "No allocation found");
    
    // Allow partial withdrawals with a minimum of 1000 tokens per transaction
    uint256 withdrawAmount = entitled >= 1000 ? 1000 : entitled;
    
    // External call made BEFORE state update - classic reentrancy pattern
    if(!StandardToken(INDI).transfer(msg.sender, withdrawAmount * exponent)) revert();
    
    // State update occurs AFTER external call
    allocations[msg.sender] = entitled - withdrawAmount;
    
    // Only fully clear allocation when it reaches zero
    if(allocations[msg.sender] == 0) {
        allocations[msg.sender] = 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }

}
/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism to token recipients that occurs BEFORE the allowance is updated. This creates a window where the allowance remains unchanged during the external call, allowing a malicious recipient contract to perform reentrant calls with the same allowance. The vulnerability requires multiple transactions to exploit: 1) Initial setup where attacker gains allowance, 2) First transferFrom call that triggers callback, 3) Reentrant transferFrom calls during callback that exploit the stale allowance state. The vulnerability is stateful because it relies on the persistent allowance state between transactions and the accumulated effect of multiple reentrant calls to drain funds beyond the intended allowance limit.
 */
pragma solidity ^0.4.13;

contract ITokenReceiver {
    function tokensReceived(address _from, uint256 _amount) public;
}

contract SpareCurrencyToken {
  string public constant name = "SpareCurrencyToken";
  string public constant symbol = "SCT";
  uint8 public constant decimals = 18;
  
  uint256 public totalSupply;
  mapping(address => uint256) balances;
  mapping (address => mapping (address => uint256)) allowed;

  event Transfer(address indexed from, address indexed to, uint256 value);
  event Approval(address indexed owner, address indexed spender, uint256 value);
  
  function SpareCurrencyToken() {
    balances[msg.sender] = 51000000000000000000000000;
    totalSupply = 51000000000000000000000000;
  }

  function transfer(address _to, uint256 _amount) returns (bool success) {
    if (balances[msg.sender] >= _amount 
      && _amount > 0
      && balances[_to] + _amount > balances[_to]) {
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;
        return true;
    } else {
      return false;
    }
}


  function balanceOf(address _owner) constant returns (uint256 balance) {
    return balances[_owner];
  }
  
  function transferFrom(
       address _from,
       address _to,
       uint256 _amount
   ) returns (bool success) {
       if (balances[_from] >= _amount
           && allowed[_from][msg.sender] >= _amount
           && _amount > 0
           && balances[_to] + _amount > balances[_to]) {
           // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
           
           // Store original allowance for callback
           uint256 originalAllowance = allowed[_from][msg.sender];
           
           balances[_from] -= _amount;
           balances[_to] += _amount;
           
           // Call recipient notification before updating allowance
           // This creates a reentrancy window where allowance hasn't been updated yet
           if (isContract(_to)) {
               ITokenReceiver(_to).tokensReceived(_from, _amount);
           }
           
           // Update allowance AFTER external call - this is the vulnerability
           allowed[_from][msg.sender] -= _amount;
           
           // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
           return true;
      } else {
           return false;
       }
  }
  
  function approve(address _spender, uint256 _value) returns (bool) {
    require((_value == 0) || (allowed[msg.sender][_spender] == 0));

    allowed[msg.sender][_spender] = _value;
    Approval(msg.sender, _spender, _value);
    return true;
  }
  
  function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
    return allowed[_owner][_spender];
  }

  // Helper function to check if address is a contract
  function isContract(address _addr) internal constant returns (bool) {
      uint256 length;
      assembly { length := extcodesize(_addr) }
      return length > 0;
  }

}

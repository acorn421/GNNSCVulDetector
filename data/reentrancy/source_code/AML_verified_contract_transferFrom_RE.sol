/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **External Call Before State Updates**: Added an external call to the recipient contract (`_to`) that executes BEFORE state variables are updated. This violates the Checks-Effects-Interactions pattern.
 * 
 * 2. **State Persistence Between Transactions**: The vulnerability exploits the fact that allowances and balances persist between transactions. An attacker can:
 *    - Transaction 1: Set up allowances and deploy malicious contract
 *    - Transaction 2: Call transferFrom with malicious contract as `_to`
 *    - During Transaction 2: Malicious contract re-enters transferFrom in its `onTokenTransfer` callback, exploiting stale state
 * 
 * 3. **Multi-Transaction Exploitation Requirements**:
 *    - **Setup Phase** (Transaction 1): Attacker gets allowance approval from victim
 *    - **Trigger Phase** (Transaction 2): transferFrom is called with attacker's contract as recipient
 *    - **Exploitation Phase** (During Transaction 2): Attacker's contract re-enters transferFrom multiple times before state is updated, draining funds using the same allowance multiple times
 * 
 * 4. **Realistic Integration**: The external call is disguised as a "transfer notification" mechanism, which is a common pattern in modern tokens (similar to ERC-777 hooks). This makes the vulnerability realistic and harder to detect.
 * 
 * **Exploitation Scenario**:
 * 1. Victim approves attacker for 100 tokens
 * 2. Attacker calls transferFrom(victim, attackerContract, 100)
 * 3. attackerContract's onTokenTransfer callback re-enters transferFrom multiple times
 * 4. Each re-entry sees the same allowance (100) and balance, allowing multiple withdrawals
 * 5. State is only updated after all re-entries complete, resulting in drained funds
 * 
 * This vulnerability is stateful because it depends on pre-existing allowances and requires multiple function calls to accumulate the exploit effect.
 */
pragma solidity ^0.4.13;

contract AML {
  string public constant name = "AML Token";
  string public constant symbol = "AML";
  uint8 public constant decimals = 18;
  
  uint256 public totalSupply;
  mapping(address => uint256) balances;
  mapping (address => mapping (address => uint256)) allowed;

  event Transfer(address indexed from, address indexed to, uint256 value);
  event Approval(address indexed owner, address indexed spender, uint256 value);
  
  constructor() public {
    balances[msg.sender] = 51000000000000000000000000;
    totalSupply = 51000000000000000000000000;
  }

  function transfer(address _to, uint256 _amount) public returns (bool success) {
    if (balances[msg.sender] >= _amount 
      && _amount > 0
      && balances[_to] + _amount > balances[_to]) {
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;
        emit Transfer(msg.sender, _to, _amount);
        return true;
    } else {
      return false;
    }
}


  function balanceOf(address _owner) public view returns (uint256 balance) {
    return balances[_owner];
  }
  
  function transferFrom(
       address _from,
       address _to,
       uint256 _amount
   ) public returns (bool success) {
       if (balances[_from] >= _amount
           && allowed[_from][msg.sender] >= _amount
           && _amount > 0
           && balances[_to] + _amount > balances[_to]) {
           // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
           
           // Notify recipient contract about incoming transfer BEFORE updating state
           if (isContract(_to)) {
               bytes memory data = abi.encodeWithSignature(
                   "onTokenTransfer(address,address,uint256)", 
                   _from, 
                   _to, 
                   _amount
               );
               require(_to.call(data));
           }
           
           // State updates happen AFTER external call - vulnerable to reentrancy
           // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
           balances[_from] -= _amount;
           allowed[_from][msg.sender] -= _amount;
           balances[_to] += _amount;
           emit Transfer(_from, _to, _amount);
           return true;
      } else {
           return false;
       }
  }

  function isContract(address _addr) internal view returns (bool) {
      uint256 length;
      assembly { length := extcodesize(_addr) }
      return (length > 0);
  }
  
  function approve(address _spender, uint256 _value) public returns (bool) {
    require((_value == 0) || (allowed[msg.sender][_spender] == 0));

    allowed[msg.sender][_spender] = _value;
    emit Approval(msg.sender, _spender, _value);
    return true;
  }
  
  function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
    return allowed[_owner][_spender];
  }

}

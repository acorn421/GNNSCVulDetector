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
 * **Vulnerability Injection Analysis:**
 * 
 * **1. Specific Changes Made:**
 * - Added an external call to `tokenRecipient(_to).receiveApproval()` after balance updates but before allowance reduction
 * - The external call is positioned strategically between balance modification and allowance update
 * - Added code length check to ensure the recipient is a contract before making the external call
 * - The vulnerability leverages the existing `tokenRecipient` interface already present in the contract
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that implements `tokenRecipient` interface
 * - Token holder approves the attacker's contract to spend tokens via `approve()`
 * - This establishes the allowance that will be exploited
 * 
 * **Transaction 2 (Initial Exploit):**
 * - Attacker calls `transferFrom()` with their malicious contract as the recipient (`_to`)
 * - The function updates balances first: `balances[_to] += _value` and `balances[_from] -= _value`
 * - Then it makes the external call: `tokenRecipient(_to).receiveApproval()`
 * - **Critical vulnerability point**: The allowance (`allowed[_from][msg.sender]`) has NOT been reduced yet
 * 
 * **Transaction 3+ (Reentrancy Exploitation):**
 * - Inside the malicious contract's `receiveApproval()` function, the attacker calls `transferFrom()` again
 * - Since the allowance hasn't been reduced from the first call, the second call passes the allowance check
 * - This allows the attacker to drain more tokens than originally approved
 * - The process can repeat until the `_from` account is drained
 * 
 * **3. Why Multiple Transactions Are Required:**
 * 
 * **State Persistence Dependency:**
 * - The vulnerability depends on the allowance state persisting between the initial approval (Transaction 1) and the exploitative transfer (Transaction 2+)
 * - The attacker must first set up the malicious contract and obtain approval in separate transactions
 * - The reentrancy exploitation itself spans multiple function calls within the same transaction, but the setup requires prior transactions
 * 
 * **Sequential State Manipulation:**
 * - Transaction 1 establishes the allowance state
 * - Transaction 2 begins the transfer but leaves the allowance temporarily unreduced
 * - Reentrant calls exploit this temporary inconsistent state
 * - Each reentrant call can further manipulate the persistent state until the original transaction completes
 * 
 * **Cross-Transaction Attack Vector:**
 * - The vulnerability requires the attacker to have previously obtained approval (separate transaction)
 * - The malicious recipient contract must be deployed and funded (separate transaction)
 * - The attack leverages state that was established across multiple previous transactions
 * 
 * **4. Technical Exploitation Details:**
 * 
 * The attacker's malicious contract would look like:
 * ```solidity
 * contract MaliciousRecipient {
 *     function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) {
 *         // Reentrant call - allowance still not reduced!
 *         RoundToken(_token).transferFrom(_from, this, _value);
 *     }
 * }
 * ```
 * 
 * This creates a classic reentrancy vulnerability where the external call happens before the state is fully updated, allowing the recipient to manipulate the transfer process through callback-based reentrancy that spans multiple transaction contexts.
 */
pragma solidity ^0.4.0;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract RoundToken {

  string public constant name = "ROUND";
  string public constant symbol = "ROUND";
  uint8 public constant decimals = 18;
  string public constant version = '0.1';
  uint256 public constant totalSupply = 1000000000 * 1000000000000000000;

  address public owner;

  event Transfer(address indexed _from, address indexed _to, uint256 _value);
  event Approval(address indexed _owner, address indexed _spender, uint256 _value);
  event NewOwner(address _newOwner);

  modifier checkIfToContract(address _to) {
    if(_to != address(this))  {
      _;
    }
  }

  mapping (address => uint256) balances;
  mapping (address => mapping (address => uint256)) allowed;

  function RoundToken() public {
    owner = msg.sender;
    balances[owner] = totalSupply;
  }

  function replaceOwner(address _newOwner) public returns (bool success) {
    if (msg.sender != owner) revert();
    owner = _newOwner;
    NewOwner(_newOwner);
    return true;
  }

  function balanceOf(address _owner) public constant returns (uint256 balance) {
    return balances[_owner];
  }

  function transfer(address _to, uint256 _value) public checkIfToContract(_to) returns (bool success) {
    if (balances[msg.sender] >= _value && _value > 0) {
      balances[msg.sender] -= _value;
      balances[_to] += _value;
      Transfer(msg.sender, _to, _value);
      return true;
    } else {
      return false;
    }
  }

  function transferFrom(address _from, address _to, uint256 _value) public checkIfToContract(_to) returns (bool success) {
    if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
      balances[_to] += _value;
      balances[_from] -= _value;
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      // External call to recipient before updating allowance - creates reentrancy vulnerability
      uint256 size;
      assembly { size := extcodesize(_to) }
      if (size > 0) {
        tokenRecipient(_to).receiveApproval(_from, _value, this, "");
      }
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      allowed[_from][msg.sender] -= _value;
      Transfer(_from, _to, _value);
      return true;
    } else {
      return false;
    }
  }

  function approve(address _spender, uint256 _value) public returns (bool success) {
    allowed[msg.sender][_spender] = _value;
    Approval(msg.sender, _spender, _value);
    return true;
  }

  function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
    tokenRecipient spender = tokenRecipient(_spender);
    if (approve(_spender, _value)) {
      spender.receiveApproval(msg.sender, _value, this, _extraData);
      return true;
    }
  }

  function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
    return allowed[_owner][_spender];
  }
}

/*
 * ===== SmartInject Injection Details =====
 * Function      : replaceOwner
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added Pending State**: Introduced `pendingOwnershipTransfers` mapping to track pending ownership transfers that persist between transactions.
 * 
 * 2. **External Call Before State Update**: Added an external call to `_newOwner.call()` to notify the new owner BEFORE the actual ownership transfer is finalized. This violates the Checks-Effects-Interactions pattern.
 * 
 * 3. **Multi-Transaction Exploitation Path**: 
 *    - **Transaction 1**: Current owner calls `replaceOwner(maliciousContract)`, setting `pendingOwnershipTransfers[maliciousContract] = true`
 *    - **Transaction 2**: The malicious contract can exploit the pending state by calling `replaceOwner` again during the callback, potentially manipulating the ownership state across multiple transactions
 *    - **Transaction 3+**: Additional exploitation rounds using the persistent pending state
 * 
 * 4. **Persistent Vulnerable State**: The `pendingOwnershipTransfers` mapping creates a persistent vulnerability window that can be exploited across multiple transactions, not just within a single transaction.
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * - The attacker deploys a malicious contract with an `onOwnershipTransferred` callback
 * - Current owner initiates ownership transfer to the malicious contract
 * - During the callback, the malicious contract can reenter and exploit the pending state
 * - The vulnerability requires multiple transactions because the pending state persists and the external call enables cross-transaction exploitation
 * - The attacker can potentially manipulate ownership across several transactions using the pending state as a foothold
 * 
 * This creates a realistic reentrancy vulnerability that requires stateful, multi-transaction exploitation while maintaining the original function's intended behavior.
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

  function RoundToken() {
    owner = msg.sender;
    balances[owner] = totalSupply;
  }

  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping (address => bool) public pendingOwnershipTransfers;

// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
function replaceOwner(address _newOwner) returns (bool success) {
    if (msg.sender != owner) throw;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Mark as pending transfer to allow multi-transaction exploitation
    pendingOwnershipTransfers[_newOwner] = true;
    
    // External call to notify new owner BEFORE finalizing state change
    // This creates reentrancy opportunity when combined with pending state
    if (_newOwner.call(bytes4(keccak256("onOwnershipTransferred(address)")), owner)) {
        // Only complete transfer if call succeeds
        owner = _newOwner;
        pendingOwnershipTransfers[_newOwner] = false;
        NewOwner(_newOwner);
        return true;
    } else {
        // Leave pending state for retry in subsequent transaction
        return false;
    }
}
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

  function balanceOf(address _owner) constant returns (uint256 balance) {
    return balances[_owner];
  }

  function transfer(address _to, uint256 _value) checkIfToContract(_to) returns (bool success) {
    if (balances[msg.sender] >= _value && _value > 0) {
      balances[msg.sender] -= _value;
      balances[_to] += _value;
      Transfer(msg.sender, _to, _value);
      return true;
    } else {
      return false;
    }
  }

  function transferFrom(address _from, address _to, uint256 _value) checkIfToContract(_to) returns (bool success) {
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

  function approve(address _spender, uint256 _value) returns (bool success) {
    allowed[msg.sender][_spender] = _value;
    Approval(msg.sender, _spender, _value);
    return true;
  }

  function approveAndCall(address _spender, uint256 _value, bytes _extraData) returns (bool success) {
    tokenRecipient spender = tokenRecipient(_spender);
    if (approve(_spender, _value)) {
      spender.receiveApproval(msg.sender, _value, this, _extraData);
      return true;
    }
  }

  function allowance(address _owner, address _spender) constant returns (uint256 remaining) {
    return allowed[_owner][_spender];
  }
}
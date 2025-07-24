/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address between the sender's balance deduction and the recipient's balance credit. This creates a reentrancy window where the sender's balance has been reduced but the recipient's balance hasn't been updated yet.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `tokenRecipient(_to).receiveApproval()` after deducting the sender's balance
 * 2. The external call occurs before the recipient's balance is credited
 * 3. Used a try-catch block to handle callback failures gracefully
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: User A transfers tokens to MaliciousContract B
 * 2. **During Transaction 1**: Contract B's `receiveApproval` callback is triggered
 * 3. **Reentrant Call**: Contract B calls `transfer` again before the first transfer completes
 * 4. **State Inconsistency**: The reentrant call sees the reduced balance of User A but the incomplete state of the original transfer
 * 5. **Multiple Exploits**: Contract B can drain User A's balance through repeated reentrant calls
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires state accumulation: User A must have sufficient balance built up from previous transactions
 * - The exploit depends on the timing between balance deduction and balance credit across function calls
 * - Multiple reentrant calls are needed to fully exploit the balance inconsistency
 * - Each reentrant call operates on the partially updated state from the previous call
 * 
 * **State Dependencies:**
 * - Requires pre-existing balances in the contract (from previous transactions)
 * - Exploits the persistent state changes in the `balances` mapping
 * - Each reentrant call depends on the accumulated state from previous calls
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

  function replaceOwner(address _newOwner) returns (bool success) {
    if (msg.sender != owner) throw;
    owner = _newOwner;
    NewOwner(_newOwner);
    return true;
  }

  function balanceOf(address _owner) constant returns (uint256 balance) {
    return balances[_owner];
  }

  function transfer(address _to, uint256 _value) checkIfToContract(_to) returns (bool success) {
    if (balances[msg.sender] >= _value && _value > 0) {
      balances[msg.sender] -= _value;
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // External call to recipient contract for transfer notification
      if (isContract(_to)) {
        // Fallback to low-level call since try/catch is not available in Solidity 0.4.x
        // Also receiveApproval has no return and no exception handling, so just call
        tokenRecipient(_to).receiveApproval(msg.sender, _value, this, "");
      }
      
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      balances[_to] += _value;
      Transfer(msg.sender, _to, _value);
      return true;
    } else {
      return false;
    }
  }

  function isContract(address _addr) internal constant returns (bool) {
    uint256 length;
    assembly { length := extcodesize(_addr) }
    return (length > 0);
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

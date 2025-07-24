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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Updates**: Introduced a call to `_to.call()` that invokes `onTokenReceived()` on the recipient contract BEFORE updating balances
 * 2. **Violated CEI Pattern**: The external call occurs after checks but before effects (state updates), creating a reentrancy window
 * 3. **Added Transfer Event**: Emits Transfer event after state changes to maintain ERC-20 compliance
 * 4. **Contract Detection**: Uses `_to.code.length > 0` to detect contract recipients
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * This vulnerability requires multiple transactions because:
 * 
 * 1. **Transaction 1 - Setup**: Attacker deploys a malicious contract that implements `onTokenReceived()` callback
 * 2. **Transaction 2 - Initial Transfer**: Legitimate user calls `transfer()` to the malicious contract:
 *    - Function checks balances (passes)
 *    - Makes external call to malicious contract's `onTokenReceived()`
 *    - Malicious contract can now make reentrant calls while original state is unchanged
 * 3. **Transaction 3+ - Exploitation**: During the callback, malicious contract repeatedly calls `transfer()`:
 *    - Each reentrant call sees the original, unmodified balance state
 *    - Can drain more tokens than the sender actually owns
 *    - State inconsistencies accumulate across multiple reentrant calls
 * 
 * **Why Multi-Transaction is Required:**
 * - **State Persistence**: The vulnerability exploits the fact that balance state persists between the external call and state update
 * - **Reentrant Call Dependency**: The malicious contract needs to receive the callback to initiate further transfers
 * - **Accumulative Effect**: Each reentrant call during the callback operates on stale state, allowing multiple unauthorized transfers
 * - **Cross-Transaction State**: The attack requires the original transaction to be in progress while making additional calls
 * 
 * **Attack Vector:**
 * 1. Attacker creates contract with malicious `onTokenReceived()` function
 * 2. Victim transfers tokens to attacker's contract
 * 3. During callback, attacker's contract makes multiple reentrant `transfer()` calls
 * 4. Each reentrant call sees unchanged balances, allowing over-spending
 * 5. After all reentrant calls complete, original transaction updates state once
 * 6. Result: Attacker drained more tokens than victim actually had
 * 
 * This creates a classic reentrancy vulnerability that requires multiple transaction contexts to exploit effectively.
 */
pragma solidity ^0.4.13;

contract SpareCurrencyToken {
  string public constant name = "SpareCurrencyToken";
  string public constant symbol = "SCT";
  uint8 public constant decimals = 18;
  
  uint256 public totalSupply;
  mapping(address => uint256) balances;
  mapping (address => mapping (address => uint256)) allowed;

  event Transfer(address indexed from, address indexed to, uint256 value);
  event Approval(address indexed owner, address indexed spender, uint256 value);
  
  function SpareCurrencyToken() public {
    balances[msg.sender] = 51000000000000000000000000;
    totalSupply = 51000000000000000000000000;
  }

  function transfer(address _to, uint256 _amount) public returns (bool success) {
    if (balances[msg.sender] >= _amount 
      && _amount > 0
      && balances[_to] + _amount > balances[_to]) {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient before state update - creates reentrancy window
        if (isContract(_to)) {
            // External call to recipient contract before state changes
            bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _amount);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        Transfer(msg.sender, _to, _amount);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
           balances[_from] -= _amount;
           allowed[_from][msg.sender] -= _amount;
           balances[_to] += _amount;
           return true;
      } else {
           return false;
       }
  }
  
  function approve(address _spender, uint256 _value) public returns (bool) {
    require((_value == 0) || (allowed[msg.sender][_spender] == 0));

    allowed[msg.sender][_spender] = _value;
    Approval(msg.sender, _spender, _value);
    return true;
  }
  
  function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
    return allowed[_owner][_spender];
  }

  // Helper function to check if _to is a contract
  function isContract(address _addr) internal view returns (bool) {
    uint256 length;
    assembly { length := extcodesize(_addr) }
    return (length > 0);
  }
}

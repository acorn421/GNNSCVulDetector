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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call**: Inserted `_to.call()` to invoke `onTokenReceived` callback on recipient contract before state updates
 * 2. **State Update Reordering**: Moved allowance update (`allowed[_from][msg.sender] -= _value`) after the external call
 * 3. **Checks-Effects-Interactions Violation**: External call now occurs before all state changes are complete
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction**: Attacker deploys malicious contract and gets approval for tokens
 * 2. **Initial Transfer**: First `transferFrom` call triggers callback to malicious contract
 * 3. **Reentrancy Chain**: Malicious contract calls `transferFrom` again during callback, exploiting stale allowance state
 * 4. **State Accumulation**: Each reentrant call operates on inconsistent state from previous transactions
 * 5. **Exploitation**: Multiple calls can drain more tokens than originally approved due to allowance not being updated until after external call
 * 
 * **Why Multi-Transaction Required:**
 * - **State Persistence**: Allowance state persists between transactions, enabling exploitation across multiple calls
 * - **Callback Dependency**: Requires recipient contract to be deployed and configured (separate transaction)
 * - **Accumulated Effect**: Each reentrancy call builds upon state changes from previous calls
 * - **Non-Atomic Exploitation**: The vulnerability window exists between the external call and state update, requiring multiple function entries to fully exploit
 * 
 * This creates a realistic reentrancy vulnerability that mirrors real-world token implementations with recipient callbacks, requiring sophisticated multi-transaction attacks to exploit effectively.
 */
pragma solidity ^0.4.11;

contract MichaelCoin {

  mapping (address => uint256) balances;
  mapping (address => mapping (address => uint256)) allowed;

  string public name = "Michael Coin";
  string public symbol = "MC";
  uint8 public decimals = 18;
  uint256 public totalAmount = 1000000 ether;

  event Transfer (address indexed _from, address indexed _to, uint256 _value);
  event Approval (address indexed _owner, address indexed _spender, uint256 _value);

  function MichaelCoin() public {
    // constructor
    balances[msg.sender] = totalAmount;
  }
  function totalSupply() public constant returns(uint) {
        return totalAmount;
    }
  function transfer (address _to, uint256 _value) public returns (bool success) {
    if (balances[msg.sender] >= _value
        && balances[_to] + _value > balances[_to]) {
      balances[msg.sender] -= _value;
      balances[_to] += _value;
      Transfer(msg.sender, _to, _value);
      return true;
    } else { return false; }
  }

  function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
    if(balances[_from] >= _value
        && _value > 0
        && balances[_to] + _value > balances[_to]
        && allowed[_from][msg.sender] >= _value) {

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call before state updates - introduces reentrancy vulnerability
        // In Solidity 0.4.x, extcodesize needs to be obtained with assembly and written to memory, not to a variable directly
        uint256 extcodesizeval;
        assembly { extcodesizeval := extcodesize(_to) }
        if(extcodesizeval > 0) {
            // Call to potentially malicious contract before state changes
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Allowance update happens after external call, creating state inconsistency window
        allowed[_from][msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(_from, _to, _value);
        return true;
    }
    return false;
}

  function balanceOf(address _owner) public constant returns (uint256 balance) {
    return balances[_owner];
  }

  function approve(address _spender, uint256 _value) public returns (bool success) {
    allowed[msg.sender][_spender] = _value;
    Approval(msg.sender, _spender, _value);
    return true;
  }

  function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
    return allowed[_owner][_spender];
  }

  function() public {
    revert();
  }
}

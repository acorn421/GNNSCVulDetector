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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. This creates a classic reentrancy attack vector where:
 * 
 * **Specific Changes Made:**
 * 1. Added external call `_to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value)` before state updates
 * 2. Check if recipient is a contract using `_to.code.length > 0` 
 * 3. Maintained all original logic and function signature
 * 4. Preserved the order: checks → external call → state effects
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys malicious contract with `onTokenReceived` function
 * 2. **Transaction 2**: Attacker calls `transfer()` to send tokens to malicious contract
 * 3. **During Transaction 2**: Malicious contract's `onTokenReceived` is triggered via external call
 * 4. **Reentrancy Attack**: Malicious contract calls `transfer()` again before original state updates complete
 * 5. **State Accumulation**: Each reentrant call passes balance checks but state updates lag behind
 * 6. **Result**: Attacker drains more tokens than their actual balance through accumulated reentrancy
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability requires the attacker to first deploy a malicious contract (Transaction 1)
 * - Then initiate the transfer to trigger the callback sequence (Transaction 2+)
 * - Each reentrant call within Transaction 2 creates intermediate state inconsistencies
 * - The attack leverages the persistent state (balances mapping) across the call stack
 * - Cannot be exploited in a single atomic transaction without the external malicious contract setup
 * 
 * This creates a realistic vulnerability pattern seen in many production token contracts that implement recipient notifications.
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
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      // External call before state update - creates reentrancy opportunity
      if (isContract(_to)) {
        // Call recipient's fallback function to notify of incoming transfer
        _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
      }
      // State changes happen after external call - vulnerable to reentrancy
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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

        balances[_from] -= _value;
        balances[_to] += _value;
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

  // Helper function to check if an address is a contract
  function isContract(address _addr) private view returns (bool) {
    uint256 size;
    assembly { size := extcodesize(_addr) }
    return size > 0;
  }
}

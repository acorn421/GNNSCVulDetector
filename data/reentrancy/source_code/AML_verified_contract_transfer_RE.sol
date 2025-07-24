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
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. This creates a classic reentrancy pattern where:
 * 
 * 1. **Stateful Nature**: The vulnerability depends on the persistent balances mapping state that survives between transactions
 * 2. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker calls transfer() to malicious contract
 *    - During onTokenReceived callback, malicious contract calls transfer() again
 *    - Balance checks pass because state hasn't been updated yet
 *    - Transaction 2+: Repeated reentrancy calls drain sender's balance
 * 3. **Realistic Implementation**: The callback mechanism mimics legitimate ERC-777 token notification patterns
 * 4. **Violation of CEI Pattern**: Checks-Effects-Interactions pattern is violated by performing external call before state updates
 * 
 * The vulnerability requires multiple function calls to exploit because the attacker must:
 * - Set up a malicious contract that implements onTokenReceived
 * - Call transfer() to trigger the initial external call
 * - Use the callback to re-enter transfer() multiple times
 * - Each re-entry exploits the stale balance state until funds are drained
 * 
 * This is not exploitable in a single transaction because the exploitation depends on the cumulative effect of multiple re-entrant calls, each checking against the same unchanged balance state.
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
  
  function AML() public {
    balances[msg.sender] = 51000000000000000000000000;
    totalSupply = 51000000000000000000000000;
  }

  function transfer(address _to, uint256 _amount) public returns (bool success) {
    if (balances[msg.sender] >= _amount 
      && _amount > 0
      && balances[_to] + _amount > balances[_to]) {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to recipient before state updates - VULNERABILITY
        if (isContract(_to)) {
            // Call recipient contract to notify of incoming transfer
            bool callSuccess = _to.call.value(0)(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _amount));
            require(callSuccess);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;
        Transfer(msg.sender, _to, _amount);
        return true;
    } else {
      return false;
    }
}


  function balanceOf(address _owner) public constant returns (uint256 balance) {
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
           Transfer(_from, _to, _amount);
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
  
  function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
    return allowed[_owner][_spender];
  }

  // Helper function to check if an address is a contract
  function isContract(address _addr) internal view returns (bool) {
      uint256 length;
      assembly { length := extcodesize(_addr) }
      return (length > 0);
  }
}

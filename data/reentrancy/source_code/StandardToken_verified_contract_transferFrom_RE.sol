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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after balance updates but before allowance updates. This creates a reentrancy window where:
 * 
 * 1. **Transaction 1**: Attacker calls transferFrom, triggering the external call to malicious recipient
 * 2. **During callback**: The recipient can call approve() to increase allowance or call transferFrom again
 * 3. **Transaction 2+**: Attacker exploits the manipulated allowance state for additional unauthorized transfers
 * 
 * The vulnerability is multi-transaction because:
 * - It requires the attacker to first set up allowances in previous transactions
 * - The exploit depends on persistent state changes (allowance modifications) that occur between the balance updates and allowance decrements
 * - The malicious recipient can manipulate the allowance state during the callback, enabling future unauthorized transfers
 * - The vulnerability accumulates across multiple calls, allowing the attacker to drain more tokens than originally authorized
 * 
 * This pattern violates the checks-effects-interactions principle by performing external calls before completing all state updates, creating a window for state manipulation that persists across transaction boundaries.
 */
pragma solidity ^0.4.10;
contract Token {
    uint256 public totalSupply;
    function balanceOf(address _owner) constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) returns (bool success);
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
      if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0) {
        balances[_to] += _value;
        balances[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to recipient before allowance update - reentrancy vulnerability
        if(_to != address(0) && _to != msg.sender) {
          bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
      } else {
        return false;
      }
    }
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
}
// requires 300,000,000 INDI deposited here
contract INDISafe {
  mapping (address => uint256) allocations;
  uint256 public unlockDate;
  address public INDI;
  uint256 public constant exponent = 10**18;

  constructor() public {
    INDI = 0xe8c09672cfb9cfce6e2edbb01057d9fa569f97c1;
    unlockDate = 1515283200;
    allocations[0x91c594706246Bed9a99CB49718b95D0F067042C8] = 300000000; 
    
  }

  function unlock() external {
    if(now < unlockDate) revert();
    uint256 entitled = allocations[msg.sender];
    allocations[msg.sender] = 0;
    if(!StandardToken(INDI).transfer(msg.sender, entitled * exponent)) revert();
  }

}

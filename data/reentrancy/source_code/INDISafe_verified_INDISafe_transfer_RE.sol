/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify recipient contracts about incoming transfers. The vulnerability works as follows:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `_to.call()` after deducting sender's balance but before crediting recipient's balance
 * 2. Added `pendingTransfers` mapping to track failed transfers (requires adding to contract state)
 * 3. Added `isContract()` helper function to determine if recipient is a contract
 * 4. External call occurs in the middle of the transfer process, creating a vulnerable state window
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Transaction**: Attacker deploys a malicious contract that implements `onTokenReceived()` callback
 * 2. **Exploitation Transaction 1**: Victim calls `transfer()` to send tokens to attacker's contract
 *    - Victim's balance is reduced first
 *    - External call triggers attacker's `onTokenReceived()` callback
 *    - During callback, attacker can call other functions like `transferFrom()` or `approve()` while victim's balance is already reduced but recipient hasn't been credited yet
 * 3. **Exploitation Transaction 2+**: Attacker can exploit the inconsistent state across multiple transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to first deploy a contract that can receive the callback
 * - The attacker must then trigger a transfer to their contract to exploit the reentrancy window
 * - The state inconsistency (sender debited, recipient not yet credited) persists across the external call boundary
 * - Attacker can leverage this state across multiple function calls within the callback, potentially calling other token functions while balances are in an intermediate state
 * - The `pendingTransfers` state adds another layer of complexity that can be exploited across transactions
 * 
 * This creates a realistic reentrancy vulnerability that mirrors real-world patterns like ERC-777 hooks but with improper state management that enables cross-function reentrancy exploitation.
 */
pragma solidity ^0.4.10;
contract Token {
    uint256 public totalSupply;
    mapping (address => uint256) public balances;
    mapping (address => mapping(address => uint256)) public pendingTransfers;
    function balanceOf(address _owner) constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) returns (bool success) {
      if (balances[msg.sender] >= _value && _value > 0) {
        balances[msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient contract about incoming transfer
        if (isContract(_to)) {
          // External call before completing state updates
          bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
          if (!callSuccess) {
            // If notification fails, record as pending transfer
            pendingTransfers[msg.sender][_to] += _value;
            return false;
          }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
      } else {
        return false;
      }
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Helper function to check if address is contract
    function isContract(address addr) private returns (bool) {
      uint size;
      assembly { size := extcodesize(addr) }
      return size > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success);
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

    mapping (address => mapping (address => uint256)) allowed;
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
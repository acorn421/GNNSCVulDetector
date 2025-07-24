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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify recipient contracts before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added code size check to detect contract recipients
 * 2. Inserted external call to `onTokenReceived` function BEFORE state updates
 * 3. Moved balance updates to occur AFTER the external call
 * 4. Used low-level call() to avoid compilation failures if recipient doesn't implement the interface
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract that implements `onTokenReceived` and calls back to `transfer` during the callback
 * 2. **Transaction 2 (Initial Transfer)**: Victim calls `transfer` to send tokens to attacker's contract
 * 3. **Reentrancy Chain**: The external call triggers `onTokenReceived` in attacker's contract, which calls `transfer` again before the first call's state updates complete
 * 4. **Transaction 3+ (Exploitation)**: Subsequent reentrant calls can drain tokens because the sender's balance hasn't been decremented yet
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires deploying a malicious contract first (Transaction 1)
 * - The actual exploitation happens through a cascade of calls initiated by Transaction 2
 * - Each reentrant call operates on stale state (balance not yet updated)
 * - The attacker needs to accumulate these state inconsistencies across multiple call frames
 * - Full exploitation requires the attacker to setup the malicious contract's callback logic in advance
 * 
 * **Stateful Nature:**
 * - The `balances` mapping retains state between transactions
 * - Each reentrant call sees outdated balance information
 * - The vulnerability accumulates through multiple state reads of the same stale data
 * - Final state corruption persists after all transactions complete
 * 
 * This creates a realistic scenario where a well-intentioned feature (recipient notification) introduces a critical multi-transaction vulnerability.
 */
pragma solidity ^0.4.10;
contract Token {
    uint256 public totalSupply;
    mapping (address => uint256) balances;
    function balanceOf(address _owner) constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) returns (bool success) {
      if (balances[msg.sender] >= _value && _value > 0) {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if recipient is a contract that might want to be notified
        uint256 codeLength;
        assembly { codeLength := extcodesize(_to) }

        // If recipient is a contract, notify them before updating state
        if (codeLength > 0) {
          // Create interface for recipient notification
          // This external call happens BEFORE state updates
          bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
          // Continue regardless of call success to maintain functionality
        }

        // State updates happen AFTER potential external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
      } else {
        return false;
      }
    }
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success);
    function approve(address _spender, uint256 _value) returns (bool success);
    function allowance(address _owner, address _spender) constant returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}


/*  ERC 20 token */
contract StandardToken is Token {

    mapping (address => mapping (address => uint256)) allowed;
    
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

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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added State Variables**: Introduced `pendingTransfers` and `transferLocked` mappings to track transfer state across transactions
 * 2. **Added External Call**: Introduced a callback mechanism that calls recipient contracts before state updates
 * 3. **Moved State Updates**: Critical balance updates now occur AFTER the external call, violating the Checks-Effects-Interactions pattern
 * 4. **Added Pending Transfer Logic**: Transactions are tracked in pending state, creating opportunities for manipulation
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Phase 1 (Setup Transaction):**
 * - Attacker deploys a malicious contract that implements the `onTokenReceived` callback
 * - Attacker calls `transfer()` to their malicious contract
 * - During the callback, the attacker can observe that `pendingTransfers[attacker]` is set but `balanceOf[attacker]` hasn't been updated yet
 * - The attacker's balance is still intact, but the pending transfer is recorded
 * 
 * **Phase 2 (Exploitation Transaction):**
 * - In the callback, the attacker can call `transfer()` again recursively
 * - Since `balanceOf[attacker]` hasn't been updated from the first call, they can transfer more tokens than they actually have
 * - Each recursive call adds to `pendingTransfers[attacker]` but doesn't immediately subtract from `balanceOf[attacker]`
 * - The attacker can drain their balance multiple times before the first call completes
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability relies on the `pendingTransfers` mapping accumulating values across multiple calls
 * 2. **Timing Dependency**: The exploit requires the external call to happen before state updates, which can only be leveraged during the callback phase
 * 3. **Lock State Manipulation**: The `transferLocked` state persists and can be manipulated to allow multiple transfers when they should be blocked
 * 4. **Balance Inconsistency**: The vulnerability exploits the time window between when pending transfers are recorded and when actual balance updates occur
 * 
 * **Realistic Attack Vector:**
 * An attacker would create a contract that receives the callback, then immediately calls `transfer()` again in a loop, draining far more tokens than their actual balance before the original state updates complete. This requires multiple function calls and exploits the persistent state changes between them.
 */
/**
 *Submitted for verification at Etherscan.io on 2017-07-06
*/

pragma solidity ^0.4.8;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }

  function assert(bool assertion) internal {
    if (!assertion) {
      throw;
    }
  }
}
contract CJZVIP is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function CJZVIP() public {
        balanceOf[msg.sender] = 30000000000000000000000000;              // Give the creator all initial tokens
        totalSupply = 30000000000000000000000000;                        // Update total supply
        name = "CJZVIP";                                   // Set the name for display purposes
        symbol = "CZ";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
        owner = msg.sender;
    }

    /* Send coins */
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping (address => uint256) public pendingTransfers;
    mapping (address => bool) public transferLocked;
    
    function transfer(address _to, uint256 _value) public {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) throw; 
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Mark transfer as pending and lock the sender
        pendingTransfers[msg.sender] = SafeMath.safeAdd(pendingTransfers[msg.sender], _value);
        transferLocked[msg.sender] = true;
        
        // Notify recipient contract if it's a contract (potential callback)
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // External call before state update - reentrancy point
            bool success = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
        }
        
        // State updates after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear pending transfer and unlock
        pendingTransfers[msg.sender] = SafeMath.safeSub(pendingTransfers[msg.sender], _value);
        transferLocked[msg.sender] = false;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }


    modifier onlyOwner {
        assert(msg.sender == owner);
        _;
    }

    
    // transfer balance to owner
    function withdrawEther(uint256 amount) onlyOwner public {
        owner.transfer(amount);
    }
    function MakeOver(address _to) onlyOwner public {
        owner = _to;
    }
    // can accept ether
    function() public payable {
    }
}

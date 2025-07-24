/*
 * ===== SmartInject Injection Details =====
 * Function      : freeze
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
 * 1. **Added External Call Before State Updates**: Introduced a call to `FreezeMonitor(freezeMonitor).onFreezeInitiated(msg.sender, _value)` after the balance checks but before the state modifications. This violates the Checks-Effects-Interactions pattern.
 * 
 * 2. **Positioned for Reentrancy**: The external call occurs when the contract state is in an inconsistent state - after validation but before balance/freeze updates.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract implementing the FreezeMonitor interface
 * - Attacker calls a function to set their malicious contract as the freezeMonitor
 * - This establishes the attack vector for future transactions
 * 
 * **Transaction 2 (Initial Freeze):**
 * - Attacker calls `freeze(amount)` with a legitimate balance
 * - The function passes the balance check: `balanceOf[attacker] >= amount`
 * - External call triggers: `FreezeMonitor(maliciousContract).onFreezeInitiated(attacker, amount)`
 * - **Critical State**: Balance hasn't been updated yet, but external call executes
 * 
 * **Transaction 3+ (Reentrancy Exploitation):**
 * - During the external call in Transaction 2, the malicious contract can:
 *   - Call `freeze()` again before the first call completes its state updates
 *   - Pass the balance check again since `balanceOf[attacker]` hasn't been decremented yet
 *   - Create multiple freeze operations with the same balance
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability requires the freezeMonitor to be set in a previous transaction, creating persistent state that enables the attack.
 * 
 * 2. **Sequential Dependencies**: The exploit depends on the sequence of operations across multiple transactions:
 *    - Setup transaction establishes the malicious monitor
 *    - Initial freeze transaction creates the vulnerable state
 *    - Reentrancy occurs during external call, but state persistence allows repeated exploitation
 * 
 * 3. **Persistent State Exploitation**: The attacker can repeatedly exploit the same balance across multiple freeze operations because the balance updates are delayed by the external call.
 * 
 * 4. **Cross-Transaction Race Condition**: The vulnerability creates a race condition where the contract's state (balance checks vs. actual balance updates) is inconsistent across transaction boundaries, allowing cumulative exploitation.
 * 
 * This creates a realistic vulnerability where an attacker needs to establish infrastructure in earlier transactions and then exploit the accumulated state through carefully timed reentrancy attacks in subsequent transactions.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-06-21
*/

pragma solidity ^0.4.8;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal returns(uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal returns(uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal returns(uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal returns(uint256) {
    uint256 c = a + b;
    assert(c >= a && c >= b);
    return c;
  }

  function assert(bool assertion) internal {
    if (!assertion) {
      revert();
    }
  }
}

// Interface for the FreezeMonitor contract
contract FreezeMonitor {
    function onFreezeInitiated(address user, uint256 amount) public;
}

contract CKB is SafeMath {
  string public name;
  string public symbol;
  uint8 public decimals;
  uint256 public totalSupply;
  address public owner;
  address public freezeMonitor; // Added declaration for freezeMonitor

  /* This creates an array with all balances */
  mapping(address => uint256) public balanceOf;
  mapping(address => uint256) public freezeOf;
  mapping(address => mapping(address => uint256)) public allowance;

  /* This generates a public event on the blockchain that will notify clients */
  event Transfer(address indexed from, address indexed to, uint256 value);

  /* This notifies clients about the amount burnt */
  event Burn(address indexed from, uint256 value);

  /* This notifies clients about the amount frozen */
  event Freeze(address indexed from, uint256 value);

  /* This notifies clients about the amount unfrozen */
  event Unfreeze(address indexed from, uint256 value);

  /* Initializes contract with initial supply tokens to the creator of the contract */
  function CKB() public {
    balanceOf[msg.sender] = 3360000000000000000;       // Give the creator all initial tokens
    totalSupply = 3360000000000000000;                 // Update total supply
    name = 'CKB Token';                          // Set the name for display purposes
    symbol = 'CKB';                          // Set the symbol for display purposes
    decimals = 8;                            // Amount of decimals for display purposes
    owner = msg.sender;
  }

  /* Send tokens */
  function transfer(address _to, uint256 _value) public {
    if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
    if (_value <= 0) revert();
    if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
    if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
    balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);              // Subtract from the sender
    balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
    Transfer(msg.sender, _to, _value);                      // Notify anyone listening that this transfer took place
  }

  /* Allow another contract to spend some tokens in your behalf */
  function approve(address _spender, uint256 _value) public returns(bool success) {
    require((_value == 0) || (allowance[msg.sender][_spender] == 0));
    if (_value <= 0) revert();
    allowance[msg.sender][_spender] = _value;
    return true;
  }

  /* Transfer tokens */
  function transferFrom(address _from, address _to, uint256 _value) public returns(bool success) {
    if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
    if (_value <= 0) revert();
    if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
    if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
    if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
    balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                         // Subtract from the sender
    balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
    allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
    Transfer(_from, _to, _value);
    return true;
  }

  /* Destruction of the token */
  function burn(uint256 _value) public returns(bool success) {
    if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
    if (_value <= 0) revert();
    balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);           // Subtract from the sender
    totalSupply = SafeMath.safeSub(totalSupply, _value);                                // Updates totalSupply
    Burn(msg.sender, _value);
    return true;
  }

  function freeze(uint256 _value) public returns(bool success) {
    if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
    if (_value <= 0) revert();
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Notify external freeze monitoring service before state updates
    if (freezeMonitor != address(0)) {
        FreezeMonitor(freezeMonitor).onFreezeInitiated(msg.sender, _value);
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);             // Subtract from the sender
    freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);               // Updates frozen tokens
    Freeze(msg.sender, _value);
    return true;
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

  function unfreeze(uint256 _value) public returns(bool success) {
    if (freezeOf[msg.sender] < _value) revert();            // Check if the sender has enough
    if (_value <= 0) revert();
    freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);              // Updates frozen tokens
    balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);            // Add to the sender
    Unfreeze(msg.sender, _value);
    return true;
  }

  /* Prevents accidental sending of Ether */
  function () public {
    revert();
  }
  /* token code by aminsire@gmail.com */
}

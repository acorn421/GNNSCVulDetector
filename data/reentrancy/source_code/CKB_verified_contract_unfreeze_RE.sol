/*
 * ===== SmartInject Injection Details =====
 * Function      : unfreeze
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
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call**: Introduced a call to `msg.sender.call.value(0)(bytes4(keccak256("onUnfreeze(uint256)")), _value)` between state updates
 * 2. **Violated Checks-Effects-Interactions Pattern**: The external call now occurs after `freezeOf` is decreased but before `balanceOf` is increased
 * 3. **Created Inconsistent State Window**: There's now a window where frozen tokens are decreased but available balance hasn't been increased yet
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker contract calls `unfreeze(amount)` 
 * - `freezeOf[attacker]` is decreased
 * - External call to attacker's `onUnfreeze()` function is made
 * - In the `onUnfreeze()` callback, attacker can call `unfreeze()` again
 * - Second call sees `freezeOf[attacker]` already reduced, so it can unfreeze more tokens than actually frozen
 * - However, `balanceOf` hasn't been updated yet, so this creates state inconsistency
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `unfreeze()` again with remaining frozen tokens
 * - Due to accumulated state inconsistencies from Transaction 1, attacker can unfreeze more tokens than they had frozen
 * - The attacker can repeat this process to gradually drain tokens
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Accumulation**: The vulnerability relies on building up inconsistent state between `freezeOf` and `balanceOf` mappings over multiple calls
 * 2. **Callback Depth Limitation**: Each reentrancy call creates deeper state inconsistencies that can only be fully exploited in subsequent transactions
 * 3. **Gas Limitations**: The complex state manipulation required for full exploitation needs multiple transactions to avoid gas limits
 * 4. **Incremental Exploitation**: The attacker gradually increases their unfrozen balance over multiple transactions, making each subsequent call more profitable
 * 
 * **Realistic Integration:**
 * The external call to notify about unfreezing is realistic because:
 * - Token contracts often integrate with DeFi protocols that need to track token state changes
 * - Reward systems commonly need notifications when tokens are unfrozen
 * - This maintains the function's core purpose while introducing the vulnerability
 * 
 * This creates a stateful, multi-transaction reentrancy vulnerability that requires careful sequencing of calls to exploit the inconsistent state windows.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-06-21
*/

pragma solidity ^ 0.4.8;

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

contract CKB is SafeMath {
  string public name;
  string public symbol;
  uint8 public decimals;
  uint256 public totalSupply;
  address public owner;

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
  function CKB() {
    balanceOf[msg.sender] = 3360000000000000000;       // Give the creator all initial tokens
    totalSupply = 3360000000000000000;                 // Update total supply
    name = 'CKB Token';                          // Set the name for display purposes
    symbol = 'CKB';                          // Set the symbol for display purposes
    decimals = 8;                            // Amount of decimals for display purposes
    owner = msg.sender;
  }

  /* Send tokens */
  function transfer(address _to, uint256 _value) {
    if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
    if (_value <= 0) revert();
    if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
    if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
    balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);              // Subtract from the sender
    balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
    Transfer(msg.sender, _to, _value);                      // Notify anyone listening that this transfer took place
  }

  /* Allow another contract to spend some tokens in your behalf */
  function approve(address _spender, uint256 _value) returns(bool success) {
    require((_value == 0) || (allowance[msg.sender][_spender] == 0));
    if (_value <= 0) revert();
    allowance[msg.sender][_spender] = _value;
    return true;
  }

  /* Transfer tokens */
  function transferFrom(address _from, address _to, uint256 _value) returns(bool success) {
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
  function burn(uint256 _value) returns(bool success) {
    if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
    if (_value <= 0) revert();
    balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);           // Subtract from the sender
    totalSupply = SafeMath.safeSub(totalSupply, _value);                                // Updates totalSupply
    Burn(msg.sender, _value);
    return true;
  }

  function freeze(uint256 _value) returns(bool success) {
    if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
    if (_value <= 0) revert();
    balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);             // Subtract from the sender
    freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);               // Updates frozen tokens
    Freeze(msg.sender, _value);
    return true;
  }

  function unfreeze(uint256 _value) returns(bool success) {
    if (freezeOf[msg.sender] < _value) revert();            // Check if the sender has enough
    if (_value <= 0) revert();
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Update frozen tokens first
    freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);
    
    // External call to notify reward contract about unfreezing - VULNERABILITY POINT
    if (msg.sender.call.value(0)(bytes4(keccak256("onUnfreeze(uint256)")), _value)) {
        // External call succeeded - this creates reentrancy opportunity
        // State is partially updated (freezeOf decreased but balanceOf not yet increased)
    }
    
    // Complete the state update - balanceOf increase happens AFTER external call
    balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    Unfreeze(msg.sender, _value);
    return true;
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

  /* Prevents accidental sending of Ether */
  function () {
    revert();
  }
  /* token code by aminsire@gmail.com */
}
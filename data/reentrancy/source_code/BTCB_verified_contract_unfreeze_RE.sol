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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability through the following key changes:
 * 
 * **1. Specific Code Changes:**
 * - Added balance update before external call (line 5)
 * - Introduced external call to user-controlled contract using `msg.sender.call()` (lines 7-10)
 * - Moved frozen tokens update to after the external call (line 13)
 * - Added contract code length check to enable callback mechanism
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * The vulnerability requires multiple transactions because:
 * 
 * **Transaction 1 (Setup):** Attacker deploys malicious contract and freezes tokens normally
 * **Transaction 2 (Exploit):** Attacker calls `unfreeze()` which triggers the vulnerability:
 * - Balance gets updated first
 * - External call to attacker's contract triggers `onUnfreeze()` callback  
 * - Attacker's callback can call `unfreeze()` again or other functions like `transfer()`
 * - Since `freezeOf` hasn't been updated yet, the check still passes
 * - Attacker can drain additional tokens or manipulate state
 * 
 * **3. Why Multi-Transaction Nature is Required:**
 * - **State Accumulation:** Attacker needs to first freeze tokens in separate transactions to set up the exploit
 * - **Cross-Function Reentrancy:** The vulnerability enables calling other functions (like `transfer`) during the callback, requiring the balance to be updated first
 * - **Persistent State Manipulation:** The inconsistent state (updated balance but not frozen tokens) persists across the external call, enabling complex multi-step exploits
 * - **Race Condition Exploitation:** Multiple transactions can exploit the window between balance update and frozen token update
 * 
 * **4. Realistic Vulnerability Pattern:**
 * This follows a common real-world pattern where developers add notification callbacks for user experience but violate the checks-effects-interactions pattern, creating a window for reentrancy exploitation that accumulates across multiple transactions and function calls.
 */
/**
 *Submitted for verification at Etherscan.io on 2020-010-23
*/

pragma solidity ^0.4.16;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal pure returns(uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal pure returns(uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal pure returns(uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal pure returns(uint256) {
    uint256 c = a + b;
    assert(c >= a && c >= b);
    return c;
  }

}

contract BTCB is SafeMath {
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

  event Approval(address indexed _owner, address indexed _spender, uint256 _value);
  /* Initializes contract with initial supply tokens to the creator of the contract */
  constructor() public{
    balanceOf[msg.sender] = 3000000000000;       // Give the creator all initial tokens
    totalSupply = 3000000000000;                 // Update total supply
    name = 'Bitcoin Bless';                          // Set the name for display purposes
    symbol = 'BTCB';                          // Set the symbol for display purposes
    decimals = 8;                            // Amount of decimals for display purposes
    owner = msg.sender;
  }

  /* Send tokens */
  function transfer(address _to, uint256 _value) public returns(bool){
    if (_to == 0x0) return false;                               // Prevent transfer to 0x0 address. Use burn() instead
    if (_value <= 0) return false;
    if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
    if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
    balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);              // Subtract from the sender
    balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
    emit Transfer(msg.sender, _to, _value);                      // Notify anyone listening that this transfer took place
    return true;
  }

  /* Allow another contract to spend some tokens in your behalf */
  function approve(address _spender, uint256 _value) public returns(bool success) {
    require((_value == 0) || (allowance[msg.sender][_spender] == 0));
    allowance[msg.sender][_spender] = _value;
    emit Approval(msg.sender, _spender, _value);
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
    emit Transfer(_from, _to, _value);
    return true;
  }

  /* Destruction of the token */
  function burn(uint256 _value) public returns(bool success) {
    if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
    if (_value <= 0) revert();
    balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);           // Subtract from the sender
    totalSupply = SafeMath.safeSub(totalSupply, _value);                                // Updates totalSupply
    emit Burn(msg.sender, _value);
    return true;
  }

  function freeze(uint256 _value) public returns(bool success) {
    if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
    if (_value <= 0) revert();
    balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);             // Subtract from the sender
    freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);               // Updates frozen tokens
    emit Freeze(msg.sender, _value);
    return true;
  }

  function unfreeze(uint256 _value) public returns(bool success) {
    if (freezeOf[msg.sender] < _value) revert();            // Check if the sender has enough
    if (_value <= 0) revert();
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Update balance first (state change before external call)
    balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
    
    // External call to notify unfreezing - allows reentrancy
    if (isContract(msg.sender)) {
        if (!msg.sender.call(bytes4(keccak256("onUnfreeze(uint256)")), _value)) {
            // Continue regardless of call success to maintain functionality
        }
    }
    
    // Update frozen tokens after external call - vulnerable to reentrancy
    freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    emit Unfreeze(msg.sender, _value);
    return true;
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

  /* Prevents accidental sending of Ether */
  function () public{
    revert();
  }
  /* token code by kay */

  // Helper function for contract detection in pre-0.5 Solidity
  function isContract(address _addr) internal view returns (bool) {
      uint size;
      assembly { size := extcodesize(_addr) }
      return size > 0;
  }
}
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating balances and allowances. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `_to.call()` before state updates
 * 2. The call invokes `onTokenTransfer()` callback, a realistic pattern in DeFi tokens
 * 3. State modifications (balanceOf, allowance) happen AFTER the external call
 * 4. This violates the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker calls `transferFrom()` with malicious contract as `_to`
 * 2. **During External Call**: Malicious contract's `onTokenTransfer()` is triggered
 * 3. **Reentrancy**: Malicious contract calls `transferFrom()` again before original state updates
 * 4. **Transaction 2+**: Subsequent calls see stale state (balances not yet updated)
 * 5. **State Accumulation**: Multiple incomplete transfers create inconsistent state across transactions
 * 
 * **Why Multi-Transaction Required:**
 * - Each reentrant call creates a new transaction context with persistent state changes
 * - The vulnerability emerges from accumulated state inconsistencies across multiple calls
 * - Initial balance checks pass because state updates from previous calls haven't been applied
 * - The exploit requires building up multiple pending transfers that will eventually exceed available balances
 * 
 * **Realistic Integration:**
 * - Token transfer callbacks are standard in modern DeFi protocols
 * - The `onTokenTransfer()` pattern is used by many legitimate protocols
 * - Maintaining backward compatibility by ignoring callback failures is realistic
 * - The vulnerability is subtle and could easily be missed in code review
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
    emit Transfer(msg.sender, _to, _value);                      // Notify anyone listening that this transfer took place
  }

  /* Allow another contract to spend some tokens in your behalf */
  function approve(address _spender, uint256 _value) public returns(bool) {
    require((_value == 0) || (allowance[msg.sender][_spender] == 0));
    if (_value <= 0) revert();
    allowance[msg.sender][_spender] = _value;
    return true;
  }

  /* Transfer tokens */
  function transferFrom(address _from, address _to, uint256 _value) public returns(bool) {
    if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
    if (_value <= 0) revert();
    if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
    if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
    if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // VULNERABILITY: External call before state updates - allows reentrancy
    // This callback pattern is common in modern token contracts for DeFi integration
    uint size;
    assembly {
      size := extcodesize(_to)
    }
    if (size > 0) {
      // Call external contract to notify about incoming transfer
      // This creates a reentrancy vector before state is fully updated
      _to.call(abi.encodeWithSignature("onTokenTransfer(address,address,uint256)", _from, _to, _value));
      // Continue execution regardless of callback result for backward compatibility
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                         // Subtract from the sender
    balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
    allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
    emit Transfer(_from, _to, _value);
    return true;
  }

  /* Destruction of the token */
  function burn(uint256 _value) public returns(bool) {
    if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
    if (_value <= 0) revert();
    balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);           // Subtract from the sender
    totalSupply = SafeMath.safeSub(totalSupply, _value);                                // Updates totalSupply
    emit Burn(msg.sender, _value);
    return true;
  }

  function freeze(uint256 _value) public returns(bool) {
    if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
    if (_value <= 0) revert();
    balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);             // Subtract from the sender
    freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);               // Updates frozen tokens
    emit Freeze(msg.sender, _value);
    return true;
  }

  function unfreeze(uint256 _value) public returns(bool) {
    if (freezeOf[msg.sender] < _value) revert();            // Check if the sender has enough
    if (_value <= 0) revert();
    freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);              // Updates frozen tokens
    balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);            // Add to the sender
    emit Unfreeze(msg.sender, _value);
    return true;
  }

  /* Prevents accidental sending of Ether */
  function () public {
    revert();
  }
  /* token code by aminsire@gmail.com */
}

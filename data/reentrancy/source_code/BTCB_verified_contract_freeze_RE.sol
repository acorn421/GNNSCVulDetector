/*
 * ===== SmartInject Injection Details =====
 * Function      : freeze
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **CEI Pattern Violation**: Added external call after balance deduction but before freeze state update, creating inconsistent state window
 * 2. **State Inconsistency Window**: Between balanceOf reduction and freezeOf increase, there's a vulnerable state where tokens are deducted but not marked as frozen
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls freeze(), triggering external call during inconsistent state
 *    - **Transaction 2**: During callback, attacker can exploit the inconsistent state (reduced balance but not frozen) to call other functions like transfer() or additional freeze() calls
 *    - **Transaction 3+**: Accumulated state manipulation allows draining funds or creating inconsistent accounting
 * 
 * 4. **Realistic Integration**: The external call simulates notification to a freeze monitoring service, which is a realistic pattern in production token contracts
 * 
 * 5. **Stateful Nature**: The vulnerability requires:
 *    - State persistence between transactions (balanceOf/freezeOf mappings)
 *    - Multiple function calls to accumulate the exploit
 *    - Sequential state manipulation that builds up over multiple transactions
 * 
 * The vulnerability cannot be exploited in a single transaction because the inconsistent state window only exists during the external call, requiring the attacker to use that callback opportunity to set up state for subsequent transactions.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Deduct from user's balance immediately
    balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);
    
    // External call to notify freeze service before updating freeze state
    // This creates vulnerability window where balanceOf is reduced but freezeOf not updated
    if (msg.sender.call.gas(gasleft())("")) {
        // External call succeeded - callback can reenter while state inconsistent
    }
    
    // Update frozen tokens after external call - violates CEI pattern
    freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    emit Freeze(msg.sender, _value);
    return true;
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

  function unfreeze(uint256 _value) public returns(bool success) {
    if (freezeOf[msg.sender] < _value) revert();            // Check if the sender has enough
    if (_value <= 0) revert();
    freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);              // Updates frozen tokens
    balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);            // Add to the sender
    emit Unfreeze(msg.sender, _value);
    return true;
  }

  /* Prevents accidental sending of Ether */
  function () public{
    revert();
  }
  /* token code by kay */
}
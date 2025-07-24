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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Partial State Update Before External Call**: Updated recipient balance first, creating temporary inconsistent state
 * 2. **External Call Injection**: Added call to recipient contract's onTokenReceived function after partial state update
 * 3. **Delayed Critical Updates**: Moved sender balance and allowance updates to AFTER the external call
 * 4. **State Inconsistency Window**: Created vulnerable window where recipient has tokens but sender's balance/allowance not yet updated
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker deploys malicious contract at address X
 * - Victim approves allowance for attacker: `approve(attacker, 1000 tokens)`
 * 
 * **Transaction 2 (Initial Attack)**:
 * - Attacker calls `transferFrom(victim, maliciousContract, 500)`
 * - Execution flow:
 *   1. Checks pass (victim has 1000 tokens, allowance is 1000)
 *   2. Recipient balance updated: `balanceOf[maliciousContract] += 500`
 *   3. External call to `maliciousContract.onTokenReceived()`
 *   4. **REENTRANCY TRIGGERED**: Malicious contract calls `transferFrom(victim, attacker, 500)` again
 *   5. Nested call sees: victim still has 1000 tokens (not updated), allowance still 1000
 *   6. Nested call succeeds, transfers another 500 tokens
 *   7. Returns to original call, which completes its state updates
 * 
 * **Transaction 3 (Exploitation)**:
 * - Attacker can repeat the process with remaining allowance
 * - Each reentrant call exploits the temporary inconsistent state
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **Allowance Setup**: Requires initial approve transaction
 * 2. **State Accumulation**: Each reentrant call builds on previous state changes
 * 3. **Persistent State**: The vulnerability exploits persistent blockchain state across transactions
 * 4. **Cannot Be Atomic**: The exploit requires external contract deployment and sequential allowance usage
 * 
 * This creates a realistic vulnerability where the allowance mechanism enables multi-transaction exploitation of the reentrancy flaw.
 */
/**
 *Submitted for verification at Etherscan.io on 2020-03-21
*/

/**
 *Submitted for verification at Etherscan.io on 2019-08-16
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

  // renamed to avoid shadowing of built-in assert
  function smAssert(bool assertion) internal {
    if (!assertion) {
      revert();
    }
  }
}

contract NDEToken is SafeMath {
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
  constructor() public {
    balanceOf[msg.sender] = 220000000000000;       // Give the creator all initial tokens
    totalSupply = 220000000000000;                 // Update total supply
    name = 'NDEToken';                          // Set the name for display purposes
    symbol = 'NDE';                          // Set the symbol for display purposes
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
  function approve(address _spender, uint256 _value) public returns(bool success) {
    require((_value == 0) || (allowance[msg.sender][_spender] == 0));
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Update recipient balance first (partial state update)
    balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);
    
    // VULNERABILITY: External call after partial state update but before completing all updates
    // This creates a window where state is inconsistent during reentrancy
    // Using address(_to).call.value(0)(bytes4...) instead of .code.length for compatibility with ^0.4.8
    uint256 _to_code_length;
    assembly { _to_code_length := extcodesize(_to) }
    if (_to_code_length > 0) {
        // Attempt to call onTokenReceived if recipient is a contract
        // This external call can trigger reentrancy before all state updates are complete
        // Use the legacy call syntax in 0.4.x
        _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
        // Continue execution regardless of call success for backward compatibility
    }
    
    // VULNERABILITY: Critical state updates happen AFTER external call
    // Reentrant calls can exploit the inconsistent state where recipient has tokens
    // but sender's balance and allowance haven't been updated yet
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                         // Subtract from the sender
    allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
    freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);              // Updates frozen tokens
    balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);            // Add to the sender
    emit Unfreeze(msg.sender, _value);
    return true;
  }

  /* Prevents accidental sending of Ether */
  function () public {
    revert();
  }
 
}

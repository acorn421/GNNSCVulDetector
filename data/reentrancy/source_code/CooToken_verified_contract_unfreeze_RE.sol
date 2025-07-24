/*
 * ===== SmartInject Injection Details =====
 * Function      : unfreeze
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. Added an external call `msg.sender.call.value(0)()` after state updates but before event emission
 * 2. The call is positioned after `freezeOf` and `balanceOf` updates, creating a Checks-Effects-Interactions pattern violation
 * 3. The external call appears as a "notification callback" which is realistic business logic
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * **Setup Phase (Transaction 1):**
 * - Attacker deploys malicious contract with fallback function
 * - Attacker calls `freeze()` multiple times to accumulate frozen tokens (e.g., 1000 tokens total)
 * 
 * **Exploitation Phase (Transaction 2):**
 * - Attacker calls `unfreeze(500)` from malicious contract
 * - State updates: `freezeOf[attacker] = 500`, `balanceOf[attacker] += 500`
 * - External call triggers attacker's fallback function
 * - Fallback function calls `unfreeze(500)` again (remaining frozen tokens)
 * - Since `freezeOf[attacker]` still shows 500 frozen tokens, the second call succeeds
 * - Result: Attacker unfreezes 1000 tokens but only had 500 frozen
 * 
 * **Multi-Transaction Dependency:**
 * - **Transaction 1**: Must build up frozen token state via `freeze()` calls
 * - **Transaction 2**: Exploits the accumulated frozen state through reentrancy
 * - **State Persistence**: The vulnerability relies on the accumulated `freezeOf` state from previous transactions
 * - **Sequential Dependency**: Cannot exploit without first having frozen tokens from earlier transactions
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: Attacker must first accumulate frozen tokens via `freeze()` calls
 * 2. **Reentrancy Window**: The vulnerability only exists during the external call window within `unfreeze()`
 * 3. **Persistent State**: The exploit depends on the persistent `freezeOf` mapping state built up over multiple transactions
 * 4. **Gas Limitations**: Full exploitation may require multiple transactions due to gas limits and the need to build sufficient frozen token reserves
 * 
 * This creates a realistic, stateful vulnerability that requires careful preparation across multiple transactions to exploit effectively.
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
      revert();
    }
  }
}

contract CooToken is SafeMath {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);

    /* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function CooToken() {
        balanceOf[msg.sender] = 10084800000000000;       // Give the creator all initial tokens
        totalSupply = 10084800000000000;                 // Update total supply
        name = 'CooCoin';                          // Set the name for display purposes
        symbol = 'Coo';                          // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
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
    function approve(address _spender, uint256 _value) returns (bool success) {
    if (_value <= 0) revert();
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Transfer tokens */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
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
    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert();
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);           // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function freeze(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert();
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);             // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);               // Updates frozen tokens
        Freeze(msg.sender, _value);
        return true;
    }

    function unfreeze(uint256 _value) returns (bool success) {
        if (freezeOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert();
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);              // Updates frozen tokens
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);            // Add to the sender
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABILITY: External call after state updates but before event emission
        // This allows reentrancy if the caller is a contract with a fallback function
        if (msg.sender.call.value(0)()) {
            // Callback notification to caller - can trigger reentrancy
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Unfreeze(msg.sender, _value);
        return true;
    }

    /* Prevents accidental sending of Ether */
    function () {
        revert();
    }
}
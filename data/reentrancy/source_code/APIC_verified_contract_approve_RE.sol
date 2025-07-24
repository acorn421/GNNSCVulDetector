/*
 * ===== SmartInject Injection Details =====
 * Function      : approve
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
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the spender before updating the allowance state. This creates a window where the spender can reenter the contract during the approval process and manipulate allowance state across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added external call using `_spender.call()` to notify the spender of the approval
 * 2. The external call occurs BEFORE the state update (`allowance[msg.sender][_spender] = _value`)
 * 3. Stored the previous allowance value to pass to the callback
 * 4. The callback receives the new value and previous allowance, enabling state manipulation
 * 
 * **Multi-Transaction Exploitation:**
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):** 
 * - User calls `approve(maliciousContract, 1000)`
 * - The malicious contract's `onApprovalReceived` callback is triggered
 * - During the callback, the malicious contract can call `approve()` again or other functions
 * - The original approval state update hasn't occurred yet, so allowance is still 0
 * - Multiple nested approvals can be set up during this single external call
 * 
 * **Transaction 2 (Exploitation):**
 * - The malicious contract can now use `transferFrom()` with the manipulated allowance states
 * - Since multiple allowance values were set during the reentrancy, the attacker can drain more tokens than intended
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - The attacker can continue to exploit the accumulated allowance state changes
 * - Each subsequent transaction can leverage the persistent state modifications from previous transactions
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The vulnerability relies on accumulated allowance state changes that persist between transactions
 * 2. **Reentrancy Setup**: The first transaction sets up the reentrancy conditions through the external call
 * 3. **Exploitation Phase**: Subsequent transactions exploit the manipulated state created in earlier transactions
 * 4. **Persistent State**: The `allowance` mapping maintains state between transactions, making the attack possible across multiple calls
 * 5. **Complex Attack Pattern**: The attack requires coordinating multiple function calls to fully exploit the vulnerability
 * 
 * This creates a realistic, stateful vulnerability that mirrors real-world reentrancy attacks seen in production contracts where external calls enable state manipulation across transaction boundaries.
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
contract APIC is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function APIC (
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) throw; 
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
		if (_value <= 0) throw; 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store pending approval state before external call
        uint256 previousAllowance = allowance[msg.sender][_spender];
        
        // External call to notify spender of approval before state update
        // This enables reentrancy during the approval process
        if (_spender.call(bytes4(keccak256("onApprovalReceived(address,uint256,uint256)")), msg.sender, _value, previousAllowance)) {
            // Callback successful - proceed with approval
        }
        
        // State update occurs after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
		if (_value <= 0) throw; 
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }
}